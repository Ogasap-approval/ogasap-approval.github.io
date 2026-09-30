import { approveReviewedBundle, authorizePendingPayments } from "./approval-kernel.js";
import { freezeRejection } from "./bundle-rejection.js";
import {
  approvalLockedStatus,
  bankSubmissionText,
  cancelledBeforeSendResult,
  elapsedText,
  interruptedApprovalResult,
  serverVerificationStatus,
  serverVerificationText,
  submissionScreenText
} from "./approval-result-text.js";
import { settleSentApproval } from "./approval-submission.js";
import { fetchPendingBundles, fetchRecentApprovals } from "./api-client.js";
import { createLatestOnly, isTrustedFrameMessage } from "./frame-messaging.js";
import { loadIntegrityManifest } from "./integrity.js";
import { buildBundleRowModel, paymentCountMetricText } from "./payment-grouping.js";
import { amountMinorToDecimal } from "./payment-view.js";
import { validateBundleForApprovalV1 } from "./core/protocol/envelopes.js";

// The approval shell embeds this kernel from the same origin, so outbound
// messages are posted to that exact origin (never "*") and inbound messages are
// only accepted from the parent window at that origin (issue #25).
const PARENT_ORIGIN = window.location.origin;

const ids = [
  "bundleSummary",
  "bundleCountValue",
  "totalsStrip",
  "paymentRows",
  "approveButton",
  "rejectButton",
  "resultPanel",
  "resultTitle",
  "resultDetail",
  "recheckPanel",
  "recheckText",
  "recheckButton"
];
const els = Object.fromEntries(ids.map((id) => [id, document.querySelector(`#${id}`)]));
const state = {
  phoneSharePackage: null,
  webauthnCredential: null,
  backendOrigin: "",
  integrityManifest: null,
  bundle: null,
  bundleError: "",
  lastApprovalResult: null,
  approvedBundleIds: new Set(),
  busy: false,
  approvalProgress: null,
  serverWaitStartedAt: 0,
  serverWaitTicker: 0,
  lockEpoch: 0,
  approvalAbortController: null,
  // What the shell's "do not close" screen shows: "" when no approval is in flight, else
  // signing | verifying | checking | authorizing.
  submissionPhase: "",
  submissionSignatureCount: 0,
  // Set the moment the approval POST has been handed to the network, and cleared when the approval settles.
  // Non-zero is what turns an app lock from "cancel" into "wipe the share and settle the outcome after unlock".
  sentAt: 0,
  shareWaiters: [],
  // A sent approval whose outcome could not be confirmed: its bundle stays un-approvable here until checked.
  unresolvedApproval: null,
  // The shell's rejection modal is open or its POST is in flight (sent in "state"). Approving is off
  // meanwhile, as rejecting is while an approval runs: the two must never race over one bundle.
  rejectionActive: false
};
// Validating a bundle is async, so an older "state" can finish after a newer one; only the latest may set
// the bundle, or a bundle the shell has just removed (rejected) could come back.
const stateUpdates = createLatestOnly();

function post(type, fields = {}) {
  window.parent.postMessage({ source: "approval-kernel", type, ...fields }, PARENT_ORIGIN);
}

function reportHeight() {
  post("height", {
    height: Math.ceil(document.documentElement.scrollHeight)
  });
}

function setStatus(message, level = "normal") {
  post("status", { message, level });
}

function totalText(totals = []) {
  return totals.map((total) => amountMinorToDecimal(total.amount_minor, total.currency)).join(", ");
}

function setResult(result) {
  if (!result) {
    els.resultPanel.classList.add("hidden");
    els.resultTitle.textContent = "-";
    els.resultDetail.textContent = "-";
    els.resultPanel.className = "result-panel hidden";
    return;
  }
  els.resultPanel.className = `result-panel result-${result.status ?? "normal"}`;
  els.resultTitle.textContent = result.title ?? "Approval result";
  els.resultDetail.textContent = result.detail ?? "";
}

function cell(text, className = "") {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) {
    td.className = className;
  }
  return td;
}

function span(text, className = "") {
  const value = document.createElement("span");
  value.textContent = text;
  if (className) {
    value.className = className;
  }
  return value;
}

function currentBundleApproved() {
  return Boolean(state.bundle && state.approvedBundleIds.has(state.bundle.bundle_id));
}

function currentBundleUnresolved() {
  return Boolean(state.bundle && state.unresolvedApproval?.bundleId === state.bundle.bundle_id);
}

function shareReady() {
  return Boolean(state.phoneSharePackage && state.backendOrigin);
}

// Resolved by applyState when an unlock brings the share back. Only a promise waits here — nothing that
// holds the share — so a sent approval can sit out a lock of any length.
function waitForShare() {
  return new Promise((resolve) => {
    state.shareWaiters.push(resolve);
  });
}

function releaseShareWaiters() {
  if (!shareReady() || state.shareWaiters.length === 0) {
    return;
  }
  const waiters = state.shareWaiters;
  state.shareWaiters = [];
  for (const resolve of waiters) {
    resolve();
  }
}

function boundedPercent(progress) {
  const value = Number(progress?.phase_percent ?? progress?.percent ?? progress?.overall_percent ?? 0);
  return Math.max(0, Math.min(100, Number.isFinite(value) ? Math.round(value) : 0));
}

function formatEta(seconds) {
  const value = Math.max(0, Math.ceil(Number(seconds)));
  if (!Number.isFinite(value)) {
    return "";
  }
  if (value < 1) {
    return "<1s";
  }
  if (value < 60) {
    return `${value}s`;
  }
  if (value < 3600) {
    const minutes = Math.floor(value / 60);
    const rest = value % 60;
    return rest ? `${minutes}m ${rest}s` : `${minutes}m`;
  }
  const hours = Math.floor(value / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  return minutes ? `${hours}h ${minutes}m` : `${hours}h`;
}

function etaValue(progress) {
  return Number.isFinite(Number(progress?.eta_seconds))
    ? formatEta(progress.eta_seconds)
    : "";
}

function signingProgressParts(progress) {
  const percent = boundedPercent(progress);
  const total = progress.phase_total ?? progress.total ?? 1;
  const done = Math.max(0, Math.min(total, progress.phase_completed ?? progress.completed ?? 0));
  const workers = Number(progress.worker_count ?? 1);
  const workerCount = Number.isFinite(workers) && workers > 0 ? workers : 1;
  const label = progress.stage === "polling" ? "Status" : "Pay";
  const eta = etaValue(progress);
  return {
    top: `${label} ${done}/${total}`,
    bottom: `${workerCount}w · ${percent}%${eta ? ` · ETA ${eta}` : ""}`
  };
}

function approvalProgressText(progress, { multiline = false } = {}) {
  if (!progress) {
    return "Approve";
  }
  // Ahead of `message` on purpose: this stage is rendered here, as a clock, and a fixed label passed in by
  // a caller must not be able to put "100%" back over a wait the server has not reported on.
  if (progress.stage === "submitting") {
    return serverVerificationText({
      signatureCount: progress.signature_count ?? progress.total,
      elapsedMs: state.serverWaitStartedAt ? Date.now() - state.serverWaitStartedAt : 0
    }, { multiline });
  }
  if (progress.stage === "checking") {
    const elapsed = elapsedText(state.sentAt ? Date.now() - state.sentAt : 0);
    return multiline ? `Checking result\n${elapsed}` : `Checking result · ${elapsed}`;
  }
  if (progress.message) {
    return progress.message;
  }
  if (progress.stage === "payments" || progress.stage === "polling") {
    const parts = signingProgressParts(progress);
    return multiline ? `${parts.top}\n${parts.bottom}` : `${parts.top} · ${parts.bottom}`;
  }
  const percent = boundedPercent(progress);
  return `Signing · ${percent}%`;
}

// The shell draws the "do not close" screen over the whole app; this kernel owns what it says, because this
// is where the approval's real state lives. Posted on every change and once a second while a clock runs.
function publishSubmission() {
  if (!state.submissionPhase) {
    return;
  }
  const locked = Boolean(state.sentAt && !state.phoneSharePackage);
  const phase = locked ? "locked" : state.submissionPhase;
  const screen = submissionScreenText({
    phase,
    progressText: state.approvalProgress ? approvalProgressText(state.approvalProgress) : "",
    signatureCount: state.submissionSignatureCount,
    elapsedMs: phase === "checking"
      ? Date.now() - state.sentAt
      : state.serverWaitStartedAt ? Date.now() - state.serverWaitStartedAt : 0
  });
  post("submission", { screen });
}

function tickClock() {
  setButtonState();
  publishSubmission();
}

// The server wait is the one stage with nothing to report but time, so the button re-renders once a second
// while it lasts. Started on entering the stage and stopped on leaving it by ANY route — a result, an error,
// the app lock — because a ticker left running would keep rewriting a button nobody is waiting on.
function syncServerWaitClock() {
  const stage = state.approvalProgress?.stage;
  const waiting = state.busy && (stage === "submitting" || stage === "checking");
  if (waiting && !state.serverWaitTicker) {
    state.serverWaitStartedAt = Date.now();
    state.serverWaitTicker = setInterval(tickClock, 1000);
  } else if (!waiting && state.serverWaitTicker) {
    clearInterval(state.serverWaitTicker);
    state.serverWaitTicker = 0;
    state.serverWaitStartedAt = 0;
  }
}

function setApprovalProgress(progress) {
  state.approvalProgress = progress;
  if (progress?.stage === "submitting") {
    state.submissionPhase = "verifying";
    state.submissionSignatureCount = progress.signature_count ?? progress.total ?? 0;
  } else if (progress && progress.stage !== "checking") {
    state.submissionPhase = "signing";
  }
  syncServerWaitClock();
  setButtonState();
  publishSubmission();
  if (!progress) {
    return;
  }
  // One explanatory line for the whole server wait, rather than the ticking button label copied into the
  // status bar every second.
  setStatus(progress.stage === "submitting"
    ? serverVerificationStatus(progress.signature_count ?? progress.total)
    : approvalProgressText(progress));
}

function setButtonState() {
  const approved = currentBundleApproved();
  const showProgress = state.busy && !approved && state.approvalProgress;
  const waiting = Boolean(showProgress && (state.approvalProgress.stage === "submitting" || state.approvalProgress.stage === "checking"));
  els.approveButton.classList.toggle("approve-button-progress", Boolean(showProgress));
  els.approveButton.classList.toggle("approve-button-waiting", waiting);
  if (showProgress) {
    els.approveButton.style.setProperty("--approval-progress", `${boundedPercent(state.approvalProgress)}%`);
    els.approveButton.title = approvalProgressText(state.approvalProgress);
  } else {
    els.approveButton.style.removeProperty("--approval-progress");
    els.approveButton.title = "";
  }
  els.approveButton.disabled = state.busy || state.rejectionActive || approved || currentBundleUnresolved() || !state.phoneSharePackage || !state.webauthnCredential || !state.backendOrigin || !state.bundle;
  els.rejectButton.disabled = !canRequestRejection();
  els.approveButton.textContent = approved ? "Approved" : showProgress ? approvalProgressText(state.approvalProgress, { multiline: true }) : "Approve";
}

// Rejection needs no WebAuthn credential (it cannot move money), only the share to sign the request. Not
// for a bundle this phone approved or whose approval is unconfirmed: the server would refuse it anyway,
// and offering it would suggest the approval could be undone.
function canRequestRejection() {
  return Boolean(state.bundle && shareReady() && !state.busy && !state.rejectionActive
    && !currentBundleApproved() && !currentBundleUnresolved());
}

function requestRejection() {
  if (!canRequestRejection()) {
    return;
  }
  // Frozen HERE, before anything async, as approveBundle captures its bundle: the shell posts exactly
  // what was on screen when the holder tapped, whatever the poll shows by the time they confirm.
  let request;
  try {
    request = freezeRejection(state.bundle);
  } catch (error) {
    setStatus(`Bundlen kan ikke afvises: ${error.message}`, "error");
    return;
  }
  state.rejectionActive = true;
  setButtonState();
  post("reject-requested", { request });
}

function renderRecheck() {
  const record = state.unresolvedApproval;
  els.recheckPanel.classList.toggle("hidden", !record);
  if (!record) {
    return;
  }
  els.recheckText.textContent = `Not yet confirmed whether the server recorded the approval of ${record.bundleId}. Do not approve it again until this has been checked.`;
  els.recheckButton.disabled = state.busy || !shareReady();
}

function emptyRow(text = "-") {
  const row = document.createElement("tr");
  const value = cell(text);
  value.colSpan = 3;
  value.className = "empty-state";
  row.append(value);
  return row;
}

function appendPaymentRows(target, payments) {
  target.replaceChildren();
  if (payments.length === 0) {
    target.append(emptyRow("Payment details unavailable"));
    return;
  }

  for (const payment of payments) {
    const row = document.createElement("tr");
    row.append(
      // The funding account, masked by the protocol (reg code + last four, e.g. "2000...9922").
      // deriveVisiblePaymentFromBankBodyV1 derives it from the SIGNED body, so what is shown here is
      // the account the bank will actually debit -- not a field the server asserted alongside it.
      cell(payment.debtor_account_masked || "-"),
      cell(payment.creditor_account || "-"),
      cell(payment.remittance_text || "-"),
      cell(amountMinorToDecimal(payment.amount_minor, payment.currency), "numeric")
    );
    target.append(row);
  }
}

function renderBundle() {
  const { bundle } = state;
  els.totalsStrip.replaceChildren();
  els.paymentRows.replaceChildren();
  renderRecheck();

  if (state.bundleError) {
    els.bundleSummary.textContent = "Bundle rejected";
    els.bundleCountValue.textContent = "-";
    els.paymentRows.append(emptyRow(state.bundleError));
    setButtonState();
    reportHeight();
    return;
  }

  if (!bundle) {
    els.bundleSummary.textContent = "Nothing to approve";
    els.bundleCountValue.textContent = "-";
    els.paymentRows.append(emptyRow());
    setButtonState();
    reportHeight();
    return;
  }

  els.bundleSummary.textContent = bundle.bundle_id;
  // Split payouts collapse into one row, so this counts PAYMENTS and names the bank instructions
  // separately -- "2 (3 transfers)" -- rather than silently disagreeing with the rows on screen.
  const model = buildBundleRowModel(bundle.payment_inputs);
  els.bundleCountValue.textContent = paymentCountMetricText(model);
  for (const total of bundle.totals) {
    const item = document.createElement("div");
    item.className = "total-pill";
    item.append(span(total.currency, "total-currency"), span(amountMinorToDecimal(total.amount_minor, total.currency), "numeric"));
    els.totalsStrip.append(item);
  }

  appendPaymentRows(els.paymentRows, model.rows);

  setButtonState();
  reportHeight();
}

async function applyState(message) {
  const update = stateUpdates.begin();
  const nextPhoneSharePackage = message.phoneSharePackage ?? null;
  const locking = Boolean(state.phoneSharePackage && !nextPhoneSharePackage);
  if (locking) {
    state.lockEpoch += 1;
    // Cancels an approval that has NOT been sent. Once it has, approveBundle has already detached this
    // controller: the lock still takes the share out of memory (just below), but the approval is left to
    // finish on the server and its outcome is settled after unlock.
    state.approvalAbortController?.abort();
  }
  state.phoneSharePackage = nextPhoneSharePackage;
  state.webauthnCredential = message.webauthnCredential ?? null;
  state.backendOrigin = message.backendOrigin ?? "";
  state.lastApprovalResult = Object.hasOwn(message, "lastApprovalResult") ? message.lastApprovalResult : state.lastApprovalResult;
  state.approvedBundleIds = new Set(message.approvedBundleIds ?? []);
  state.rejectionActive = Boolean(message.rejectionActive);
  if (locking && state.sentAt) {
    setStatus(approvalLockedStatus(), "warning");
  }
  publishSubmission();
  releaseShareWaiters();

  if (message.bundle) {
    try {
      await validateBundleForApprovalV1(message.bundle);
    } catch (error) {
      if (!stateUpdates.isCurrent(update)) {
        return;
      }
      throw error;
    }
  }
  if (!stateUpdates.isCurrent(update)) {
    return;
  }
  state.bundleError = "";
  state.bundle = message.bundle ?? null;
  setResult(state.lastApprovalResult);
  renderBundle();
}

// How long to keep asking the backend for something to authorize after an approval.
//
// The submit is a fire-and-forget drain, so the bank payment ids do not exist the instant the approval
// returns. A few seconds covers the round-trip; past that the round is left to the recovery path rather
// than holding the holder's screen. Retrying is safe by construction — signing authorizes payments the
// bank has already created and cannot bring a second one into being.
const PAYMENT_AUTHORIZATION_ATTEMPTS = 5;
const PAYMENT_AUTHORIZATION_RETRY_MS = 1200;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const AUTHORIZATION_LEFT_FOR_LATER = "Bundle approved. The app locked before the bank authorization was finished; it finishes by itself the next time the app is open and unlocked.";

async function runPaymentAuthorizationRound({ lockEpoch }) {
  const cancelled = () => lockEpoch !== state.lockEpoch || !state.phoneSharePackage;
  for (let attempt = 0; attempt < PAYMENT_AUTHORIZATION_ATTEMPTS; attempt += 1) {
    if (cancelled()) {
      setStatus(AUTHORIZATION_LEFT_FOR_LATER, "warning");
      return;
    }
    let outcome;
    try {
      outcome = await authorizePendingPayments({
        phoneSharePackage: state.phoneSharePackage,
        backendOrigin: state.backendOrigin,
        integrityManifest: state.integrityManifest,
        // The bundle this holder just approved is in the set by definition — the shell adds it before
        // this runs and syncs it here. Anything else offered in this window belongs to somebody else's
        // decision and is left to them; the shell's background round is what eventually finishes those.
        recognizeBundle: (bundleId) => state.approvedBundleIds.has(bundleId),
        isCancelled: cancelled,
        onStatus: setStatus
      });
    } catch (error) {
      if (cancelled()) {
        setStatus(AUTHORIZATION_LEFT_FOR_LATER, "warning");
        return;
      }
      // Never downgrade the approval. The money is approved and submitted; what failed is the
      // follow-on, and the backend alerts on a payment left waiting.
      setStatus(`Bundle approved. Payment authorization could not be completed: ${error.message}`, "warning");
      return;
    }
    if (!outcome.authorized) {
      // Nothing to authorize YET is the ordinary case in the first second or two after a submit.
      // `bundle_not_recognised` joins them: the backend offered a bundle this holder did not approve,
      // which is not this phone's to finish and not worth a warning.
      if (outcome.reason === "nothing_to_sign" || outcome.reason === "nothing_pending"
          || outcome.reason === "bundle_not_recognised") {
        if (attempt < PAYMENT_AUTHORIZATION_ATTEMPTS - 1) {
          await sleep(PAYMENT_AUTHORIZATION_RETRY_MS);
          continue;
        }
        return;
      }
      setStatus(`Bundle approved. Payment authorization not requested (${outcome.reason})`, "warning");
      return;
    }
    const stillPartial = outcome.result?.still_partial ?? [];
    if (stillPartial.length > 0) {
      // The bank accepted OUR authorization and still wants another one — a two-together mandate. No
      // further signature from this holder can change that, so it is said plainly rather than retried.
      setStatus(
        `Authorized ${outcome.visibleAuthorization?.payment_count ?? 0} payments; ${stillPartial.length} still need a second approver`,
        "warning"
      );
      return;
    }
    setStatus(`Bundle approved and ${outcome.visibleAuthorization?.payment_count ?? 0} payments authorized with the bank`);
    return;
  }
}

// The payment-authorization round needs the phone share IN MEMORY: every signature over the bank's
// authorization request is this phone's threshold share combined with the company's, and the server holds
// no share that can stand in for it. A lock wipes the share, so leaving during the round leaves the payments
// at AUTHORIZATION_PARTIAL until the app is next open and unlocked (the shell's background round). That is
// why the submission screen stays up through this, and comes down as soon as it is over.
async function authorizeApprovedBundle() {
  state.submissionPhase = "authorizing";
  publishSubmission();
  await runPaymentAuthorizationRound({ lockEpoch: state.lockEpoch });
}

function approvalSummary(record, result) {
  return [totalText(record.totals) || result?.bundle_id || record.bundleId, bankSubmissionText(result?.bank_submission)]
    .filter(Boolean)
    .join(" · ");
}

function showApprovalResult(bundleId, approvalResult, { approved = false, message = "", level = "normal" } = {}) {
  if (approved) {
    state.approvedBundleIds.add(bundleId);
  }
  // The server has answered, so its clock stops now rather than running on under "Approved" through the
  // payment-authorization round. After the add above, so the button goes straight to "Approved".
  setApprovalProgress(null);
  state.lastApprovalResult = approvalResult;
  setResult(approvalResult);
  if (message) {
    setStatus(message, level);
  }
  if (approved) {
    post("approved", { bundle_id: bundleId, result: approvalResult });
  } else {
    post("error", { message: approvalResult.detail, result: approvalResult });
  }
}

async function settleApproval(record) {
  const outcome = await settleSentApproval({
    sent: record.sent,
    bundleId: record.bundleId,
    approverId: record.approverId,
    shareIndex: record.shareIndex,
    sentAt: record.sentAt,
    // Read at the moment of use, never kept: null while locked.
    currentShare: () => (shareReady() ? state.phoneSharePackage : null),
    waitForShare,
    lookup: async (share) => {
      const [pendingBundles, recentApprovals] = await Promise.all([
        fetchPendingBundles(share, record.backendOrigin),
        fetchRecentApprovals(share, record.backendOrigin)
      ]);
      return { pendingBundles, recentApprovals };
    },
    onPhase: ({ phase }) => {
      if (phase === "locked") {
        setStatus(approvalLockedStatus(), "warning");
        publishSubmission();
      } else if (phase === "checking" && state.approvalProgress?.stage !== "checking") {
        state.submissionPhase = "checking";
        setApprovalProgress({ stage: "checking" });
        setStatus("Checking whether the server recorded the approval", "warning");
      }
    }
  });

  // The outcome is known (or known to be unknown): a lock from here on no longer means "sent, not yet settled".
  state.sentAt = 0;
  if (outcome.kind !== "unknown" && state.unresolvedApproval?.bundleId === record.bundleId) {
    state.unresolvedApproval = null;
  }

  if (outcome.kind === "approved") {
    const result = outcome.result;
    const approvalResult = {
      status: "approved",
      title: "Bundle approved successfully",
      detail: `${record.paymentCount} transactions · ${approvalSummary(record, result)}`
    };
    showApprovalResult(record.bundleId, approvalResult, {
      approved: true,
      message: result?.bank_submission?.status === "queued" ? "Bundle approved; backend will submit to bank" : "Bundle approved"
    });
    // SECOND ROUND, NO SECOND GESTURE. The approval above only gets the payments CREATED at Nordea; the
    // bank will not execute them until it has a payment authorization, and that request names them by
    // bank-assigned ids, so it could not have been signed a moment ago. The holder is not asked again —
    // they answered when they approved this bundle, and this finishes that same answer while the share
    // is still in hand.
    //
    // Deliberately after `post("approved")` and deliberately unable to fail the approval: the bundle IS
    // approved, and an authorization that does not land is a separate, recoverable state — not a reason
    // to tell the holder their approval failed.
    await authorizeApprovedBundle();
    return;
  }

  if (outcome.kind === "rejected") {
    const error = outcome.error;
    if (error.code === "bundle_already_approved") {
      const alreadyResult = {
        status: "warning",
        title: "Bundle already approved",
        detail: error.body?.received_at ? `Approved at ${new Date(error.body.received_at).toLocaleString()}` : "This bundle was already recorded by the backend."
      };
      showApprovalResult(record.bundleId, alreadyResult, { approved: true, message: "Bundle already approved", level: "warning" });
      return;
    }
    const failedResult = {
      status: "failed",
      title: "Approval failed",
      detail: error.message
    };
    showApprovalResult(record.bundleId, failedResult, { message: error.message, level: "error" });
    return;
  }

  const interrupted = interruptedApprovalResult(outcome, {
    summary: `${record.paymentCount} transactions · ${totalText(record.totals) || record.bundleId}`
  });
  if (outcome.kind === "recorded") {
    showApprovalResult(record.bundleId, interrupted, {
      approved: true,
      message: interrupted.title,
      level: outcome.by === "self" ? "normal" : "warning"
    });
    if (outcome.by === "self") {
      await authorizeApprovedBundle();
    }
    return;
  }
  if (outcome.kind === "unknown") {
    state.unresolvedApproval = record;
  }
  showApprovalResult(record.bundleId, interrupted, { message: interrupted.title, level: "warning" });
}

async function approveBundle() {
  if (state.rejectionActive || !state.phoneSharePackage || !state.webauthnCredential || !state.backendOrigin || !state.bundle || currentBundleApproved() || currentBundleUnresolved()) {
    return;
  }

  // Captured ONCE. The shell can push a different bundle while this runs, and the result, the approved set
  // and the lookup must all describe the bundle that was actually signed.
  const bundle = state.bundle;
  const backendOrigin = state.backendOrigin;
  const identity = { approverId: state.phoneSharePackage.approver_id, shareIndex: state.phoneSharePackage.share_index };

  state.busy = true;
  state.approvalProgress = null;
  const lockEpoch = state.lockEpoch;
  const approvalAbortController = new AbortController();
  state.approvalAbortController = approvalAbortController;
  state.lastApprovalResult = null;
  state.submissionPhase = "signing";
  setButtonState();
  setResult(null);
  post("started");
  setApprovalProgress({ stage: "webauthn", message: "Confirm WebAuthn", percent: 0 });

  try {
    let sent;
    try {
      sent = await approveReviewedBundle({
        phoneSharePackage: state.phoneSharePackage,
        webauthnCredential: state.webauthnCredential,
        backendOrigin,
        bundle,
        integrityManifest: state.integrityManifest,
        signal: approvalAbortController.signal,
        isCancelled: () => lockEpoch !== state.lockEpoch || !state.phoneSharePackage,
        onStatus: setStatus,
        onProgress: setApprovalProgress
      });
    } catch (error) {
      // Everything thrown here happened BEFORE the request left the phone, so it is final: nothing reached
      // the server.
      if (error.name === "ApprovalNotSentError" || error.message === "Approval cancelled by app lock" || error.name === "AbortError") {
        showApprovalResult(bundle.bundle_id, cancelledBeforeSendResult(), {
          message: "Approval cancelled by app lock. Nothing was sent.",
          level: "warning"
        });
        return;
      }
      const failedResult = {
        status: "failed",
        title: "Approval failed",
        detail: error.message
      };
      showApprovalResult(bundle.bundle_id, failedResult, { message: error.message, level: "error" });
      return;
    }

    // SENT. From here a lock cannot, and must not, undo the approval: detach the controller so it aborts
    // nothing, and settle the outcome — after unlock if need be.
    if (state.approvalAbortController === approvalAbortController) {
      state.approvalAbortController = null;
    }
    state.sentAt = sent.sentAt;
    await settleApproval({
      sent,
      sentAt: sent.sentAt,
      bundleId: bundle.bundle_id,
      totals: bundle.totals,
      paymentCount: bundle.payment_inputs.length,
      backendOrigin,
      ...identity
    });
  } catch (error) {
    setStatus(`Approval could not be completed: ${error.message}`, "error");
  } finally {
    if (state.approvalAbortController === approvalAbortController) {
      state.approvalAbortController = null;
    }
    state.busy = false;
    state.approvalProgress = null;
    syncServerWaitClock();
    state.submissionPhase = "";
    state.sentAt = 0;
    setButtonState();
    renderRecheck();
    reportHeight();
    // The one message that lets the shell take the submission screen down and poll again.
    post("settled");
  }
}

// "Check again" for an approval whose outcome could not be confirmed. Never re-sends: it uses an answer that
// has arrived since, and otherwise asks the server, which is conclusive now that the window has passed.
async function recheckApproval() {
  const record = state.unresolvedApproval;
  if (!record || state.busy || !shareReady()) {
    return;
  }
  state.busy = true;
  state.sentAt = record.sentAt;
  state.submissionPhase = "checking";
  setResult(null);
  post("started");
  setApprovalProgress({ stage: "checking" });
  renderRecheck();
  try {
    await settleApproval(record);
  } catch (error) {
    setStatus(`Could not check the approval: ${error.message}`, "error");
  } finally {
    state.busy = false;
    state.approvalProgress = null;
    syncServerWaitClock();
    state.submissionPhase = "";
    state.sentAt = 0;
    setButtonState();
    renderRecheck();
    reportHeight();
    post("settled");
  }
}

window.addEventListener("message", (event) => {
  if (!isTrustedFrameMessage(event, { source: window.parent, origin: PARENT_ORIGIN, kind: "approval-shell" })) {
    return;
  }
  if (event.data.type === "state") {
    applyState(event.data).catch((error) => {
      state.bundleError = error.message;
      state.bundle = null;
      renderBundle();
      setStatus(`Approval bundle rejected: ${error.message}`, "error");
      post("error", {
        message: error.message
      });
    });
  }
});

els.approveButton.addEventListener("click", () => {
  approveBundle();
});

els.rejectButton.addEventListener("click", () => {
  requestRejection();
});

els.recheckButton.addEventListener("click", () => {
  recheckApproval();
});

if ("ResizeObserver" in window) {
  new ResizeObserver(reportHeight).observe(document.documentElement);
} else {
  window.addEventListener("load", reportHeight);
}

state.integrityManifest = await loadIntegrityManifest().catch((error) => {
  setStatus(`App integrity unavailable: ${error.message}`, "error");
  return null;
});
renderBundle();
setResult(null);
post("ready");
