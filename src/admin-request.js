// The Nordea admin request state machine, deliberately free of the DOM.
//
// Four review rounds found four blockers in this flow, and every one was an ORDERING or OWNERSHIP
// defect rather than a cryptographic one: the display rendered before the meaning was derived; two
// refreshes paired one request with another's action; and — in the first version of this very
// module — validation ran against an internal snapshot while the object stored, displayed and later
// signed was still the caller's, free to change underneath both.
//
// So the rules live here, with fetching and validation injected, and the module OWNS what it holds.
// Everything below serves one property:
//
//     the holder signs exactly the request whose derived meaning they were shown, or nothing.

// Object.freeze is shallow; a frozen parent says nothing about its children, and a renderer could
// still rewrite a nested authorizer_id after derivation.
function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  Object.freeze(value);
  for (const key of Object.getOwnPropertyNames(value)) {
    deepFreeze(value[key]);
  }
  return value;
}

// Take ownership BEFORE anything is validated. structuredClone throws on functions and symbols,
// which is the right direction: an input carrying either is refused rather than half-copied.
function own(input) {
  return deepFreeze(structuredClone(input));
}

// Identity is the VALIDATED SIGNING STRING — the exact bytes that would be signed. Deriving it from
// request_id, or even request_id + body, would let a request with the same body but a different
// originating host or date inherit an earlier dismissal, though its signed bytes differ.
function identityFor(signingString, ownedInput) {
  if (typeof signingString === "string" && signingString.length > 0) {
    return `signed:${signingString}`;
  }
  // Underivable requests never become approvable, so a structural fallback is only used to tell one
  // unapprovable request from another.
  return `unverified:${ownedInput?.request_id ?? ""}|${ownedInput?.method ?? ""}|${ownedInput?.path ?? ""}`;
}

export function createAdminRequestController({ fetchPendingAdminRequest, validateAdminInput }) {
  if (typeof fetchPendingAdminRequest !== "function" || typeof validateAdminInput !== "function") {
    throw new TypeError("createAdminRequestController requires fetchPendingAdminRequest and validateAdminInput");
  }

  // TWO counters, because "a newer result exists" and "the context is gone" are different events and
  // conflating them breaks one of the two rules:
  //   generation — bumped by refresh AND clear; decides whether a fetch/validation may still COMMIT.
  //   epoch      — bumped ONLY by clear; decides whether an approval already in flight may still
  //                SUBMIT. A routine poll must not abort a holder's approval mid-signature; a lock,
  //                reset or backend change must.
  let generation = 0;
  let epoch = 0;
  let current = null; // frozen, OWNED { input, action, identity }
  let error = "";
  let dismissedIdentity = "";
  let approving = false;

  return {
    async refresh() {
      const startedAt = ++generation;
      let fetched;
      try {
        fetched = await fetchPendingAdminRequest();
      } catch {
        if (startedAt === generation) { current = null; error = ""; }
        return;
      }
      if (!fetched) {
        if (startedAt === generation) { current = null; error = ""; }
        return;
      }

      // OWN IT FIRST. Everything after this point — validation, display, signing — uses this copy,
      // so the caller mutating its object mid-validation cannot make the shown action describe
      // different bytes than the ones eventually signed.
      let owned;
      try {
        owned = own(fetched);
      } catch {
        if (startedAt === generation) {
          current = null;
          error = "This request could not be read and cannot be approved.";
        }
        return;
      }

      try {
        const { visibleAdminAction, signingString } = await validateAdminInput(owned);
        if (startedAt !== generation) return;
        current = deepFreeze({ input: owned, action: visibleAdminAction, identity: identityFor(signingString, owned) });
        error = "";
      } catch (validationError) {
        if (startedAt !== generation) return;
        // Keep it visible with its reason: silently hiding an underivable request leaves an operator
        // waiting on an approval that will never come, with no clue why.
        current = deepFreeze({ input: owned, action: null, identity: identityFor(null, owned) });
        error = validationError.message;
      }
    },

    snapshot() {
      if (!current || current.identity === dismissedIdentity) {
        return { visible: false, action: null, error: "", canApprove: false };
      }
      return {
        visible: true,
        action: current.action,
        error,
        // Never approvable without a derived meaning, and never while an approval is already running.
        canApprove: Boolean(current.action) && !approving
      };
    },

    /**
     * Approve the tuple that is currently displayed.
     *
     * `context` is captured HERE, at invocation, and handed to sign/submit — the caller must not read
     * live application state after an await, or a request fetched from one backend could be
     * submitted to another after the origin changed mid-signature.
     */
    async approve({ sign, submit, context }) {
      const approved = current;
      if (!approved?.action) return { ok: false, reason: "not_approvable" };
      // A dismissed request is not "currently displayed"; visibility and approvability must agree,
      // or the button state becomes the only guard and a programmatic path bypasses it.
      if (approved.identity === dismissedIdentity) return { ok: false, reason: "dismissed" };
      if (approving) return { ok: false, reason: "already_approving" };

      approving = true;
      const startedAt = epoch;
      try {
        const signed = await sign(approved.input, approved.action, context);
        // Lock, reset or a backend change during signing invalidates the context this share was
        // produced for. Refuse to submit rather than send it somewhere it was never meant for.
        if (startedAt !== epoch) return { ok: false, reason: "context_changed" };

        // Checking only here is not enough: submit() itself does real work before the request
        // leaves — hashing, fetching a nonce, signing the backend-auth envelope — and an
        // invalidation during THAT window would still let the POST go out. So submit is handed a
        // predicate to re-check at the last moment it controls. Once the request is actually on the
        // wire the outcome is uncertain by nature; the goal is to shrink that window, not pretend
        // it closes.
        const isStillValid = () => startedAt === epoch;
        const result = await submit(approved.input, signed, { ...context, isStillValid });
        if (!isStillValid()) return { ok: false, reason: "context_changed" };

        // Retire by CONTENT, not object identity: a poll that recommitted the same pending request
        // builds a new tuple, and clearing only on `===` would leave an already-approved request on
        // screen inviting a duplicate approval.
        if (current?.identity === approved.identity) { current = null; error = ""; }
        return { ok: true, result };
      } finally {
        approving = false;
      }
    },

    dismiss() {
      if (current) dismissedIdentity = current.identity;
    },

    clear() {
      generation += 1; // disowns any refresh already in flight
      epoch += 1;      // and any approval already in flight
      current = null;
      error = "";
      dismissedIdentity = "";
    }
  };
}
