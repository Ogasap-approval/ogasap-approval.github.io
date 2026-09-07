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
//
// THAT PROPERTY IS NOW SATISFIED VACUOUSLY FOR THE BANK-SETUP ACTIONS, and it is worth being precise
// about why rather than quietly dropping it. The six admin requests are signed without being shown,
// because none of them takes effect without an explicit approval in the Nordea ID app — a gate
// outside this stack that this code can neither fake nor bypass. The holder's tap here was never
// the control for them. What the tap did control was ATTENTION, and spending it on six near-
// identical prompts, plus one an hour forever, is the approval-fatigue failure this module was
// written to prevent, arriving by the other door.
//
// The invariant that replaces it is narrower and still load-bearing:
//
//     nothing outside ADMIN_AUTO_SIGN_ACTIONS is ever signed without being shown.

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

// Progress is CONTEXT, not consent — it describes where the sequence has got to, never what is
// being signed. It is owned like everything else this module holds (a renderer must not be able to
// rewrite it after display), but a malformed one degrades to "no progress shown" rather than
// failing the refresh: losing a step counter must never cost the holder a request they could act on.
function ownProgress(value) {
  if (!value || typeof value !== "object") return null;
  try {
    return own(value);
  } catch {
    return null;
  }
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

// WHAT MAY BE SIGNED WITHOUT BEING SHOWN. The service holds the same table (adminAuthority.js) and
// argues the rule there; this is the phone's own copy, because the phone must not need the service
// to tell it what it is allowed to do unattended — a backend that could widen this set by saying so
// would be a backend that could walk a holder past their own consent.
//
// Keyed by the DERIVED action: the value computed from the bytes that will actually be signed,
// never a route or a label the response asserted. Everything absent from it — an action this build
// does not know, a protocol addition, anything payment-shaped — falls back to the panel and a human.
export const ADMIN_AUTO_SIGN_ACTIONS = Object.freeze([
  // Grants nothing on its own; opens the Corporate Access request.
  "corporate_access_start",
  // GRANTS bank authority — and the bank will not grant it until the nominated human approves in
  // the Nordea ID app. That approval is the control, and it is not ours to give.
  "corporate_access_authorize",
  // Reads whether they have approved yet.
  "corporate_access_status",
  // Spends the code, or the refresh token, for an access token. Authorizes nothing new.
  "corporate_access_token",
  // GRANTS a signing key — which the bank issues in AUTHENTICATION_PENDING and which signs nothing
  // until its SCA completes in the Nordea ID app.
  "signing_key_create",
  // Reads whether that SCA completed.
  "signing_key_status"
]);

const AUTO_SIGN_SET = new Set(ADMIN_AUTO_SIGN_ACTIONS);

/**
 * May this action be signed without a person looking at it?
 *
 * Takes the DERIVED action object, and reads only its `action`. Anything unrecognised, absent or
 * malformed is false — the fallback is a human, in every direction.
 */
export function mayAutoSignAdminAction(action) {
  return typeof action?.action === "string" && AUTO_SIGN_SET.has(action.action);
}

// Does a panel state actually ask the holder to DO something?
//
// Kept here rather than in the renderer because it is a rule, not a layout: it decides whether the
// bank panel takes the whole approval view to itself, hiding the payment queue underneath it.
//
// The rule changed with auto-signing, and it had to. It used to be "there is a derived action" —
// i.e. a bank request waiting for a tap. Those are signed in the background now and flash past in a
// second or two, so keying the takeover on them would blank the payment queue at random on behalf
// of a process that wants nothing. Two states are left that genuinely want a person:
//
//   - the bank is waiting for them in the Nordea ID app. The only real request in the flow, and it
//     is reported only when the bank itself has said so.
//   - a request arrived that this build cannot verify, or is not allowed to sign unattended. That
//     is an anomaly, and a human reading it is exactly what the fallback panel is for.
//
// Everything else — a step being signed, a backoff, a finished setup — is a progress note, and a
// progress note does not get to suspend a payment that is genuinely waiting.
export function adminRequestNeedsAHuman(snapshot) {
  if (!snapshot?.visible) return false;
  if (snapshot.suppression) return snapshot.suppression === "awaiting_bank_approval";
  // `canApprove` is deliberately NOT consulted: it goes false for the duration of a chain, which is
  // precisely when a panel a human is needed for must stay in front of everything else.
  return !snapshot.autoSignable;
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
  // WHY there is nothing to approve, when the service declined to mint a step. Kept OUT of `current`
  // on purpose: `current` is the owned request tuple that approve() reads and dismiss() binds to, and
  // a suppression is not a request — it has no input, no action, and nothing signable.
  let suppression = null;
  // Held OUTSIDE `current` for the same reason `suppression` is, and one more: this is the only
  // field that must survive `current === null`, because the screen that most needs a step counter
  // is the one with nothing to approve.
  let flowProgress = null;
  let dismissedIdentity = "";
  let approving = false;

  const controller = {
    async refresh() {
      const startedAt = ++generation;
      let fetched;
      try {
        fetched = await fetchPendingAdminRequest();
      } catch {
        if (startedAt === generation) { current = null; error = ""; suppression = null; flowProgress = null; }
        return;
      }
      // An ENVELOPE — { adminInput, suppression } — destructured explicitly rather than sniffed, so a
      // fetcher returning the wrong shape reads as "nothing pending" loudly rather than silently.
      const input = fetched?.adminInput ?? null;
      const why = typeof fetched?.suppression === "string" ? fetched.suppression : null;
      const progress = ownProgress(fetched?.flowProgress);
      if (!input) {
        // A suppression is only meaningful as the NEWEST answer, so it is written under the same
        // generation guard as everything else.
        if (startedAt === generation) { current = null; error = ""; suppression = why; flowProgress = progress; }
        return;
      }

      // OWN IT FIRST. Everything after this point — validation, display, signing — uses this copy,
      // so the caller mutating its object mid-validation cannot make the shown action describe
      // different bytes than the ones eventually signed.
      let owned;
      try {
        owned = own(input);
      } catch {
        if (startedAt === generation) {
          current = null;
          error = "This request could not be read and cannot be approved.";
          suppression = null;
          flowProgress = progress;
        }
        return;
      }

      try {
        const { visibleAdminAction, signingString } = await validateAdminInput(owned);
        if (startedAt !== generation) return;
        current = deepFreeze({ input: owned, action: visibleAdminAction, identity: identityFor(signingString, owned) });
        error = "";
        suppression = null;
        flowProgress = progress;
      } catch (validationError) {
        if (startedAt !== generation) return;
        // Keep it visible with its reason: silently hiding an underivable request leaves an operator
        // waiting on an approval that will never come, with no clue why.
        current = deepFreeze({ input: owned, action: null, identity: identityFor(null, owned) });
        error = validationError.message;
        suppression = null;
        flowProgress = progress;
      }
    },

    snapshot() {
      // Visible, with its reason, never approvable — the same shape as an underivable request above,
      // and for the same reason: silently showing nothing leaves the one person who can act on this
      // unable to tell "no work" from "the flow gave up", which is exactly how it deadlocked.
      if (!current && suppression) {
        const identity = `suppressed:${suppression}`;
        if (identity !== dismissedIdentity) {
          return { visible: true, action: null, error: "", canApprove: false, suppression, identity, autoSignable: false, flowProgress };
        }
      }
      if (!current || current.identity === dismissedIdentity) {
        return { visible: false, action: null, error: "", canApprove: false, suppression: null, autoSignable: false, flowProgress };
      }
      return {
        visible: true,
        action: current.action,
        error,
        // Never approvable without a derived meaning, and never while an approval is already running.
        canApprove: Boolean(current.action) && !approving,
        // Whether the caller may sign this in the background. Derived from the SAME action object
        // the panel would render, so "what is shown" and "what may go unshown" cannot disagree. An
        // unverifiable request is never auto-signable, because it has no derived action at all.
        autoSignable: mayAutoSignAdminAction(current.action),
        suppression: null,
        flowProgress
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
      if (current) { dismissedIdentity = current.identity; return; }
      // `suppressed:<reason>` cannot collide with a request identity, which is always `signed:` or
      // `unverified:` prefixed.
      if (suppression) dismissedIdentity = `suppressed:${suppression}`;
    },

    clear() {
      generation += 1; // disowns any refresh already in flight
      epoch += 1;      // and any approval already in flight
      current = null;
      error = "";
      suppression = null;
      flowProgress = null;
      dismissedIdentity = "";
    },

    /**
     * Approve a PRE-AUTHORIZED SEQUENCE of steps from a single gesture.
     *
     * Obtaining Corporate Access is six bank requests and they cannot be bundled into one signature:
     * each signs its own HTTP request, and steps 2+ sign a URL containing an access_id that only the
     * previous response produces. Six identical-looking prompts is itself the approval-fatigue failure
     * this module exists to prevent, so the consent moves up a level: the holder authorizes a
     * described SEQUENCE, and the chain signs each step as its predecessor returns.
     *
     * That relaxes the module's invariant from "signed exactly the request they were shown" to
     * "signed exactly the requests in the set they accepted, each rendered as it was signed". Keeping
     * it honest is `accept` and `onStep`, and they are not optional:
     *   accept(action) — built from what was enumerated at the tap. Anything outside it STOPS the
     *                    chain and falls back to the manual panel. This is what stops a compromised
     *                    or confused backend walking a holder through a step they never saw.
     *   onStep(action) — renders the derived meaning BEFORE the signature is produced.
     *
     * The chain halts by itself where a human is genuinely required: once the bank tells the service
     * it is waiting on somebody in the Nordea ID app, the service stops minting and answers with a
     * suppression instead, which ends the chain as a SUCCESS rather than a failure.
     *
     * This is also the path taken when nobody tapped anything at all. `accept` is what keeps that
     * honest: an unattended chain is bounded by the same enumerated set as a tapped one, so a
     * backend cannot use the absence of a gesture to walk a phone somewhere new.
     */
    async approveChain({ sign, submit, context, accept, onStep, maxSteps = 6, deadlineMs = 5 * 60 * 1000 }) {
      if (typeof accept !== "function") {
        throw new TypeError("approveChain requires an accept predicate: an unbounded chain is not consent");
      }
      // Captured ONCE for the whole chain, not per step. A lock, reset or backend-origin change
      // partway through must abandon the remainder, not just the step in flight.
      const chainEpoch = epoch;
      const startedAtMs = Date.now();
      const steps = [];
      for (let index = 0; index < maxSteps; index += 1) {
        if (chainEpoch !== epoch) return { ok: false, reason: "context_changed", steps };
        // Drafts carry a signed originating date and the bank refuses a stale one, so a chain that
        // has been running longer than a date-box is worth must stop rather than sign into a refusal.
        if (Date.now() - startedAtMs > deadlineMs) return { ok: false, reason: "deadline", steps };

        await controller.refresh();
        if (chainEpoch !== epoch) return { ok: false, reason: "context_changed", steps };

        const snap = controller.snapshot();
        // Nothing left to sign. Either the sequence is complete or it is waiting on the human in the
        // Nordea ID app — both are successful ends to THIS gesture.
        if (!snap.visible || snap.suppression) {
          return { ok: true, reason: "chain_paused", suppression: snap.suppression ?? null, steps };
        }
        if (!snap.canApprove) return { ok: false, reason: "not_approvable", error: snap.error, steps };
        if (!accept(snap.action)) {
          return { ok: false, reason: "outside_authorized_set", action: snap.action, steps };
        }

        onStep?.(snap.action, index);
        const outcome = await controller.approve({ sign, submit, context });
        if (!outcome.ok) return { ...outcome, steps };
        steps.push(snap.action);
      }
      return { ok: false, reason: "step_limit", steps };
    }
  };

  return controller;
}
