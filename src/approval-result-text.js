// Plain-text lines the approval kernel shows around an approval, kept free of the DOM so they are tested as
// behaviour rather than matched as source text. Both live here because the screen said something untrue at
// the two moments a holder is most likely to be reading it: while waiting for the server, and on success.

/**
 * The bank-submission half of "Bundle approved successfully · ...".
 *
 * DISABLED ONLY WHEN THE BACKEND SAYS SO. nofipa-payments' approve response carried no `enabled` at all, and
 * reading that silence as `!submission.enabled` printed "Bank submission disabled" under every successful
 * approval while the payments were in fact being sent. Silence is also the one reading that cannot be
 * right: the backend refuses an approval outright (503 `nordea_disabled`) while submission is switched off,
 * so a body that got this far came from a service that submits. An explicit `enabled: false`, or a
 * `disabled` status, is still reported as disabled — those are the backend's own words, not an inference
 * from a key that was never sent.
 */
export function bankSubmissionText(submission) {
  if (!submission) {
    return "";
  }
  if (submission.enabled === false || submission.status === "disabled") {
    return "Bank submission disabled";
  }
  const total = submission.total_payment_count ?? submission.payment_count ?? 0;
  const done = submission.payment_count ?? 0;
  if (submission.status === "queued") {
    return "queued for bank submission by backend";
  }
  if (submission.status === "submitting") {
    return `submitting to bank ${done}/${total}`;
  }
  if (submission.status === "executed") {
    return "executed by bank";
  }
  if (submission.status === "submitted") {
    return "submitted to bank";
  }
  if (submission.status === "auth_expired") {
    return "bank auth expired";
  }
  if (submission.status === "key_refreshing") {
    return "renewing bank signing key";
  }
  if (submission.status === "key_inactive") {
    return "bank signing key inactive";
  }
  if (submission.status === "date_invalid") {
    return "bank date expired";
  }
  if (submission.status === "failed") {
    return `Bank submission failed${submission.error ? `: ${submission.error}` : ""}`;
  }
  return `Bank ${submission.status}`;
}

// Elapsed time as a holder reads it: whole seconds, counted up, never negative and never "NaNs".
export function elapsedText(elapsedMs) {
  const seconds = Math.floor(Number(elapsedMs) / 1000);
  if (!Number.isFinite(seconds) || seconds < 0) {
    return "0s";
  }
  const minutes = Math.floor(seconds / 60);
  return minutes ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
}

function knownCount(signatureCount) {
  return Number.isInteger(signatureCount) && signatureCount > 0 ? signatureCount : null;
}

/**
 * The approve button while the phone waits on the server.
 *
 * WHY THIS IS A CLOCK AND NOT A PERCENTAGE. By the time this shows, the phone's part is finished and the
 * server's has not reported anything. Before it answers, the server combines its two company shares with
 * EVERY signature the phone sent — each payment, plus one pre-signed status read per hour of the 72h polling
 * horizon — checks each combined signature, and records the approval. Nothing goes to the bank until that
 * answer has been sent. For the two-payment bundle approved on 2026-09-15 that was 74 combines and a 25.7s
 * POST, longer than all of the phone-side signing put together.
 *
 * The old label, "Submitting approval · 100%" over a full bar, read as "done" for that entire wait, which is
 * exactly when a holder wonders whether it has hung. The server sends no progress to base a percentage on,
 * so any percentage would be invented; an elapsed clock is true however long it takes.
 */
export function serverVerificationText({ signatureCount, elapsedMs } = {}, { multiline = false } = {}) {
  const top = "Server verifying";
  const bottom = serverVerificationClock({ signatureCount, elapsedMs });
  return multiline ? `${top}\n${bottom}` : `${top} · ${bottom}`;
}

function serverVerificationClock({ signatureCount, elapsedMs } = {}) {
  const count = knownCount(signatureCount);
  return `${count ? `${count} signatures · ` : ""}${elapsedText(elapsedMs)}`;
}

export const SUBMISSION_SCREEN_TITLE = "Submitting — do not close the app or lock your phone";

/**
 * The full-screen "do not close" screen, phase by phase.
 *
 * The screen cannot keep anyone in the app, so every `leave` line says what REALLY happens if the holder
 * leaves anyway at that point — and they differ, because the app lock means something different before and
 * after the approval has been sent (approval-submission.js):
 *
 *   signing      nothing has left the phone; leaving cancels the approval, and nothing reaches the server.
 *   verifying    the approval has been sent; the server finishes it regardless and the result is shown after
 *                unlock, but the payment authorization that follows needs the share, which the lock wipes.
 *   checking     the answer was lost; the check pauses while locked and resumes after unlock.
 *   authorizing  approved; the bank authorization is signed with the share in memory right now, so leaving
 *                leaves the payments waiting at the bank until the app is next open and unlocked.
 */
export function submissionScreenText({ phase, progressText = "", signatureCount, elapsedMs } = {}) {
  const title = SUBMISSION_SCREEN_TITLE;
  const count = knownCount(signatureCount);
  if (phase === "signing") {
    return {
      title,
      phase: "Signing on this phone",
      clock: progressText,
      leave: "Nothing has been sent yet. If you leave now, the approval is cancelled and nothing reaches the server."
    };
  }
  if (phase === "verifying") {
    return {
      title,
      phase: `Sent. The server is checking ${count ? `all ${count} signatures` : "the signatures"} before it records the approval.`,
      clock: serverVerificationClock({ signatureCount, elapsedMs }),
      leave: "If you leave now, the server still finishes and this app shows the result when you unlock it, but the payments cannot be authorized with the bank until you do."
    };
  }
  if (phase === "checking") {
    return {
      title,
      phase: "The server's answer did not reach this phone. Checking whether it recorded the approval.",
      clock: `${elapsedText(elapsedMs)} since sent`,
      leave: "If you leave now, the check pauses and carries on when you unlock the app. Do not approve again until it has finished."
    };
  }
  if (phase === "authorizing") {
    return {
      title,
      phase: "Approved. Authorizing the payments with the bank from this phone.",
      clock: "",
      leave: "If you leave now, the payments wait at the bank until you next open and unlock this app."
    };
  }
  return {
    title,
    phase: "The app locked after the approval was sent.",
    clock: "",
    leave: "Unlock to see whether the server recorded it."
  };
}

// The shell's status line while the app is locked with an approval already sent: the one moment the
// submission screen itself is out of sight, behind the unlock gate.
export function approvalLockedStatus() {
  return "The app locked after the approval was sent. Unlock to see whether the server recorded it.";
}

export function cancelledBeforeSendResult() {
  return {
    status: "warning",
    title: "Approval cancelled",
    detail: "The app locked before the approval was sent. Nothing reached the server; approve again when you are ready."
  };
}

/**
 * The result panel for an approval whose answer this phone did not get to verify, once the server has been
 * asked what it recorded (approval-submission.js). "Safe to approve again" is said in exactly one case: the
 * bundle is still pending AND long enough has passed that the server cannot still be working on it.
 */
export function interruptedApprovalResult(outcome, { summary = "" } = {}) {
  const lead = summary ? `${summary} · ` : "";
  const why = outcome?.interruption === "unverifiable"
    ? "its answer could not be verified"
    : outcome?.interruption === "no_answer"
      ? "it had not answered in time"
      : "its answer did not reach this phone";
  if (outcome?.kind === "recorded" && outcome.by === "self") {
    return {
      status: "approved",
      title: "Bundle approved successfully",
      detail: `${lead}the server recorded this approval (${why}, so it was confirmed separately)`
    };
  }
  if (outcome?.kind === "recorded") {
    const share = Number.isInteger(outcome.approval?.share_index) ? `share ${outcome.approval.share_index}` : "another share";
    return {
      status: "warning",
      title: "Bundle already approved",
      detail: `The server recorded an approval of this bundle by ${share}, not by this phone.`
    };
  }
  if (outcome?.kind === "not_recorded") {
    return {
      status: "warning",
      title: "Approval not recorded",
      detail: `The server still lists this bundle as pending ${elapsedText(outcome.elapsedMs)} after the approval was sent, so it did not record it and is no longer processing it. It is safe to approve again.`
    };
  }
  return {
    status: "warning",
    title: "Approval outcome unknown",
    detail: outcome?.reason === "bundle_not_listed"
      ? "The server lists this bundle neither as pending nor as recently approved. Do not approve again yet; check History, or tap Check again."
      : "The server could not be reached to confirm whether it recorded this approval. Do not approve again yet; tap Check again."
  };
}

// The status line for the same wait, posted once rather than every tick. It says what is being waited on and
// that the bank has not been contacted yet, because "is it already sending the payments?" is the question a
// long pause raises.
export function serverVerificationStatus(signatureCount) {
  const count = knownCount(signatureCount);
  const what = count ? `all ${count} signatures` : "the signatures";
  return `Signed on this phone. The server is checking ${what} before it records the approval and hands the payments to the bank; this usually takes under a minute. Keep the app open.`;
}
