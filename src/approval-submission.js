// What happens to an approval once it has been SENT, kept free of the DOM so the app-lock cases are tested as
// behaviour.
//
// THE LINE THIS DRAWS. Before the approval POST leaves the phone, an app lock cancels it and nothing reaches
// the server. After, the lock can no longer undo anything: the request carries only signed data, the server
// verifies and records it whether or not the phone is still listening, and its answer is company-signed. So
// from that moment the lock does its security job — the phone share and every secret leave memory at once —
// but it does NOT abort the request or throw its result away. The outcome is settled here, after unlock:
//
//   - the answer arrived (even while locked): verify it with the share once the share is back;
//   - the answer was lost (iOS may kill a fetch in the background), cannot be verified, or has not come:
//     ask the server, through the existing pending-bundles and recent-approvals reads, what it recorded.
//
// Nothing in this module holds the share. `currentShare()` is read at the moment of use and `sent.verify`
// takes it as an argument, so a lock while the server is still verifying leaves no reference behind.

// How long after sending an approval the server might still be working on it. The 2026-09-15 approval took
// 25.7s to answer, and the server carries on when a client disconnects. Until this has passed, a bundle that
// is still listed as pending means "not recorded YET", never "not recorded". It is also how long the phone
// waits for an answer before it starts asking instead.
//
// Approving again inside the window would still not pay twice — the server locks the bundle row and refuses
// a second approval of an approved bundle — but it would be the wrong thing to tell a holder while the first
// one may be about to land.
export const LOOKUP_WINDOW_MS = 120_000;
// Each lookup is two signed reads, which the server answers on the same loop that is doing the verification,
// so they are spaced out rather than hammered.
export const LOOKUP_INTERVAL_MS = 10_000;

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function defaultAnswerTimeout(ms) {
  let handle;
  const promise = new Promise((resolve) => {
    handle = setTimeout(resolve, ms);
  });
  return { promise, cancel: () => clearTimeout(handle) };
}

/**
 * Where a bundle stands, from the two lists the server already publishes.
 *
 * Pending wins over a recent approval on purpose: a bundle whose date box expired before it could be sent is
 * put back to pending and keeps its old approval in history, and that old approval is not this one.
 */
export function classifyApprovalLookup({ bundleId, approverId, shareIndex, pendingBundles = [], recentApprovals = [] } = {}) {
  if ((pendingBundles ?? []).some((bundle) => bundle?.bundle_id === bundleId)) {
    return { kind: "pending" };
  }
  const approval = (recentApprovals ?? []).find((item) => item?.bundle_id === bundleId);
  if (approval) {
    const self = approval.approver_id === approverId && Number(approval.share_index) === Number(shareIndex);
    return { kind: "recorded", by: self ? "self" : "other", approval };
  }
  return { kind: "absent" };
}

/**
 * Settle an approval that has left the phone. Safe to call again for the same `sent` (a later "check again"):
 * an answer that has arrived since is used, and a lookup made after the window is conclusive at once.
 *
 * @param {object} args
 * @param {{ response: Promise<object>, verify: (captured: object, share: object) => Promise<object> }} args.sent
 * @param {string} args.bundleId
 * @param {string} args.approverId
 * @param {number} args.shareIndex
 * @param {number} args.sentAt            ms timestamp taken as the request was handed to the network
 * @param {() => object|null} args.currentShare   the share, or null while the app is locked
 * @param {() => Promise<void>} args.waitForShare resolves once the app is unlocked again
 * @param {(share: object) => Promise<{ pendingBundles: object[], recentApprovals: object[] }>} args.lookup
 * @returns {Promise<
 *   { kind: "approved", result: object }
 * | { kind: "rejected", error: Error }
 * | { kind: "recorded", by: "self"|"other", approval: object, interruption: string }
 * | { kind: "not_recorded", elapsedMs: number, interruption: string }
 * | { kind: "unknown", reason: string, error?: Error, interruption: string }>}
 *   `interruption` says why the answer was not used: "lost", "unverifiable" or "no_answer".
 */
export async function settleSentApproval({
  sent,
  bundleId,
  approverId,
  shareIndex,
  sentAt,
  currentShare,
  waitForShare,
  lookup,
  onPhase = () => {},
  now = () => Date.now(),
  sleep = defaultSleep,
  answerTimeout = defaultAnswerTimeout,
  windowMs = LOOKUP_WINDOW_MS,
  intervalMs = LOOKUP_INTERVAL_MS
}) {
  // open -> arrived -> used, or open -> lost. Tracked rather than awaited once, so an answer that turns up
  // after the phone has stopped waiting for it is still the first thing consulted.
  const answer = { state: "open", captured: null };
  const answered = sent.response.then(
    (captured) => {
      answer.state = "arrived";
      answer.captured = captured;
    },
    () => {
      answer.state = "lost";
    }
  );
  let interruption = "lost";

  async function share() {
    let value = currentShare();
    while (!value) {
      onPhase({ phase: "locked" });
      await waitForShare();
      value = currentShare();
    }
    return value;
  }

  async function useAnswer() {
    if (answer.state !== "arrived") {
      return null;
    }
    answer.state = "used";
    try {
      const result = await sent.verify(answer.captured, await share());
      return { kind: "approved", result };
    } catch (error) {
      // An answer the company shares signed is the server's word, success or not.
      if (error?.companySigned === true) {
        return { kind: "rejected", error };
      }
      // Anything else — no signature, a bad one, a body that fails its schema — is not evidence of what the
      // server did, so it gets the same treatment as an answer that never arrived.
      interruption = "unverifiable";
      return null;
    }
  }

  onPhase({ phase: "verifying" });
  const timer = answerTimeout(Math.max(0, sentAt + windowMs - now()));
  try {
    await Promise.race([answered, timer.promise]);
  } finally {
    timer.cancel();
  }
  const direct = await useAnswer();
  if (direct) {
    return direct;
  }

  let lastError = null;
  for (;;) {
    const unlockedShare = await share();
    const late = await useAnswer();
    if (late) {
      return late;
    }
    if (answer.state === "open") {
      interruption = "no_answer";
    }
    onPhase({ phase: "checking" });
    let verdict = null;
    try {
      verdict = classifyApprovalLookup({ bundleId, approverId, shareIndex, ...(await lookup(unlockedShare)) });
      lastError = null;
    } catch (error) {
      lastError = error;
    }
    if (verdict?.kind === "recorded") {
      return { ...verdict, interruption };
    }
    const elapsedMs = now() - sentAt;
    if (elapsedMs >= windowMs) {
      // A request that is still open may still be being processed, however long it has been.
      if (answer.state === "open") {
        return { kind: "unknown", reason: "no_answer", interruption };
      }
      if (verdict?.kind === "pending") {
        return { kind: "not_recorded", elapsedMs, interruption };
      }
      return {
        kind: "unknown",
        reason: verdict ? "bundle_not_listed" : "lookup_failed",
        ...(lastError ? { error: lastError } : {}),
        interruption
      };
    }
    // Still inside the window: wait, but never past its end, so the concluding look happens as soon as a
    // conclusion is allowed.
    await sleep(Math.max(0, Math.min(intervalMs, sentAt + windowMs - now())));
  }
}
