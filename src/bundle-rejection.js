// Rejecting a pending bundle from the app (nofipa-backend docs/plans/2026-09-30-pwa-bundle-reject-and-payout-sms.md §2).
//
// The kernel freezes the bundle the holder is looking at the moment they tap "Afvis bundle"; the shell asks
// for confirmation and posts THAT, never whatever the poll has put on screen since. The server only rejects
// a bundle that is still pending, has never been attempted at the bank and still has the hash that was
// shown, so a stale or changed bundle is refused rather than rejected.
//
// No WebAuthn gesture: rejecting cannot move money, it sends the payments back to second approval in
// Nofipa. And it is safe to repeat: a bundle that is already rejected answers the same success.
import { buildBundleRowModel } from "./payment-grouping.js";
import { amountMinorToDecimal } from "./payment-view.js";

export const REJECTION_UNKNOWN_TEXT = "Ukendt om afvist - prøv igen";

// The whole send (nonce round-trip, signing, POST, verification) gives up after this, as unknown: the
// holder must never be left behind a modal that cannot be closed. Asking again is safe.
export const REJECTION_DEADLINE_MS = 20_000;

const REFUSAL_TEXT = Object.freeze({
  bundle_not_found: "Bundlen findes ikke længere.",
  bundle_not_pending: "Bundlen afventer ikke længere godkendelse og kan ikke afvises.",
  bundle_hash_mismatch: "Bundlen er ændret siden den blev vist. Luk og se den igen.",
  bundle_not_rejectable: "Denne bundle kan ikke afvises fra appen.",
  bundle_attempted: "Bundlen er allerede sendt til banken og kan ikke afvises.",
  share_not_permitted_for_payments: "Denne telefon må ikke afvise betalinger.",
  bundle_rejection_contract_unavailable: "Afvisning er ikke slået til på serveren endnu.",
  backend_auth_body_mismatch: "Serveren kunne ikke bekræfte forespørgslen. Prøv igen."
});

export function rejectionRefusalText(code) {
  return REFUSAL_TEXT[code] ?? `Serveren afviste afvisningen (${code || "ukendt fejl"}).`;
}

/**
 * What the holder saw, read once. Frozen so nothing that happens while the modal is open (a poll, a new
 * bundle selected) can change what is posted.
 */
export function freezeRejection(bundle) {
  const model = buildBundleRowModel(bundle.payment_inputs);
  return Object.freeze({
    bundle_id: bundle.bundle_id,
    bundle_hash: bundle.bundle_hash_sha256,
    count: model.paymentCount,
    total: (bundle.totals ?? []).map((total) => amountMinorToDecimal(total.amount_minor, total.currency)).join(", ")
  });
}

export function rejectionPromptText(frozen) {
  const payments = frozen.count === 1 ? "1 betaling" : `${frozen.count} betalinger`;
  return `Afvis bundle med ${payments}, i alt ${frozen.total || "-"}? De sendes tilbage til 2. godkendelse i Nofipa.`;
}

/**
 * Post one rejection and say what happened:
 *   { kind: "rejected", alreadyRejected }  the server confirmed it (first time or a repeat)
 *   { kind: "refused", code, text }        the server said no, in a company-signed answer: final
 *   { kind: "unknown", text }              no answer this phone can trust: asking again is safe
 *
 * `send(body, { signal, assertStillValid })` is submitBundleRejection bound to the share and backend. At
 * the deadline, or when `isCancelled()` turns true (the modal was dismissed by a lock), the attempt stops
 * for good rather than only being stopped waiting for: `assertStillValid` turns false, so nothing unsent
 * is signed or sent, and `signal` aborts what is in flight.
 */
export async function rejectFrozenBundle(frozen, send, { deadlineMs = REJECTION_DEADLINE_MS, isCancelled = () => false, signal } = {}) {
  const controller = new AbortController();
  let expired = false;
  let timer;
  let onAbort;
  let result;
  try {
    // The deadline, or the caller's `signal` (a dismissal), ends the attempt at once: the fetch is aborted
    // and the outcome is unknown.
    const deadline = new Promise((_resolve, reject) => {
      const stop = (reason) => {
        expired = true;
        controller.abort();
        reject(new Error(reason));
      };
      timer = setTimeout(() => stop("bundle rejection timed out"), deadlineMs);
      if (signal) {
        onAbort = () => stop("bundle rejection cancelled");
        if (signal.aborted) {
          onAbort();
        } else {
          signal.addEventListener("abort", onAbort, { once: true });
        }
      }
    });
    result = await Promise.race([
      send(
        { bundle_id: frozen.bundle_id, bundle_hash: frozen.bundle_hash },
        { signal: controller.signal, assertStillValid: () => !expired && !isCancelled() }
      ),
      deadline
    ]);
  } catch (error) {
    if (error?.companySigned && error.code) {
      return { kind: "refused", code: error.code, text: rejectionRefusalText(error.code) };
    }
    return { kind: "unknown", text: REJECTION_UNKNOWN_TEXT };
  } finally {
    clearTimeout(timer);
    if (onAbort) {
      signal.removeEventListener("abort", onAbort);
    }
  }
  // A verified success about some other bundle is not a confirmation of this one.
  if (result?.bundle_id !== frozen.bundle_id) {
    return { kind: "unknown", text: REJECTION_UNKNOWN_TEXT };
  }
  return { kind: "rejected", alreadyRejected: Boolean(result.already_rejected) };
}

/**
 * The confirmation modal. "Annuller" takes focus when it opens, so a stray Enter cancels. While a
 * rejection is posting both buttons are disabled; afterwards a refusal or an unknown outcome is shown in
 * the modal, and the confirm button (now "Prøv igen" for an unknown one) posts the SAME frozen bundle.
 *
 * `els`: { modal, text, error, cancel, confirm }. `setInert(on)` takes the rest of the app out of reach.
 * `send(body, options)` posts; `onRejected(frozen, outcome)` runs once the server has confirmed, BEFORE the
 * modal lets go, so the rejected bundle has left the list by the time anything can act on it again.
 *
 * `isPending()` is true while ANY attempt is out, a dismissed one included, and `onSettled()` runs when
 * one finishes: approving must stay off until then, not merely until the modal is gone.
 */
export function createRejectionModal({ els, setInert, send, onRejected, onSettled = () => {}, deadlineMs }) {
  let frozen = null;
  let posting = false;
  let pending = 0;
  // Bumped by dismiss(): an attempt from an earlier opening stops sending, and no longer owns the modal.
  let generation = 0;
  let attempt = null;

  function render({ error = "", confirmLabel = "Afvis bundle" } = {}) {
    els.error.textContent = error;
    els.error.classList.toggle("hidden", !error);
    els.confirm.textContent = posting ? "Afviser…" : confirmLabel;
    els.confirm.disabled = posting;
    els.cancel.disabled = posting;
  }

  function hide() {
    frozen = null;
    els.modal.classList.add("hidden");
    setInert(false);
  }

  function open(request) {
    if (frozen) {
      return;
    }
    frozen = request;
    els.text.textContent = rejectionPromptText(frozen);
    render();
    els.modal.classList.remove("hidden");
    setInert(true);
    els.cancel.focus();
  }

  // The holder's way out: not while this opening's rejection is posting.
  function close() {
    if (posting || !frozen) {
      return;
    }
    hide();
  }

  // The app's way out (a lock): always, a POST in flight included, which is aborted on the spot. Whether
  // it reached the server is then unknown; the next pending-bundles poll settles it.
  function dismiss() {
    if (!frozen) {
      return;
    }
    attempt?.abort();
    attempt = null;
    generation += 1;
    posting = false;
    hide();
  }

  async function confirm() {
    if (posting || !frozen) {
      return null;
    }
    const request = frozen;
    const mine = generation;
    const controller = new AbortController();
    attempt = controller;
    posting = true;
    pending += 1;
    render();
    let outcome;
    try {
      outcome = await rejectFrozenBundle(request, send, {
        ...(deadlineMs === undefined ? {} : { deadlineMs }),
        isCancelled: () => mine !== generation,
        signal: controller.signal
      });
    } finally {
      pending -= 1;
      if (attempt === controller) {
        attempt = null;
      }
    }
    if (mine !== generation) {
      if (outcome.kind === "rejected") {
        onRejected(request, outcome);
      }
      onSettled();
      return outcome;
    }
    posting = false;
    if (outcome.kind === "rejected") {
      onRejected(request, outcome);
      hide();
    } else {
      render({ error: outcome.text, confirmLabel: outcome.kind === "unknown" ? "Prøv igen" : "Afvis bundle" });
      if (outcome.kind === "refused") {
        els.confirm.disabled = true;
      }
      els.cancel.focus();
    }
    onSettled();
    return outcome;
  }

  return {
    open,
    close,
    dismiss,
    confirm,
    isOpen: () => Boolean(frozen),
    isPosting: () => posting,
    isPending: () => pending > 0
  };
}
