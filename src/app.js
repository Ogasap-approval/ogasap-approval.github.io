import {
  attestMigration,
  enrollApprovalCredential,
  fetchPendingBundles,
  fetchRecentApprovals,
  pollMigration,
  requestMigration
} from "./api-client.js";
import { decodeEncryptedBackupQrV1, encryptBackupQrV1, validateEncryptedBackupQrV1 } from "./backup-recovery.js";
import { utf8Decode, utf8Encode } from "./core/crypto/bytes.js";
import { webauthnEnrollmentStepUpChallengeV1 } from "./core/protocol/envelopes.js";
import { decodePhoneSharePackageV1 } from "./core/protocol/signing.js";
import {
  createMultipartReassembler,
  encodeQrMatrix,
  frameMultipartPayload,
  MULTIPART_PREFIX,
  renderQrToCanvas
} from "./qr-encode.js";
import { assertAppIntegrity, loadIntegrityManifest } from "./integrity.js";
import { amountMinorToDecimal } from "./payment-view.js";
import {
  backendOriginRequiresPrfUnlock,
  clearEnrollment,
  isStoragePersisted,
  loadBackendOrigin,
  loadPhoneSharePackage,
  loadPhoneSharePrfSalt,
  loadWebAuthnCredential,
  phoneSharePackageRequiresPrfUnlock,
  requestPersistentStorage,
  saveBackendOrigin,
  savePhoneSharePackage,
  saveWebAuthnCredential,
  setLocalShareUnlockVerifier
} from "./storage.js";
import {
  createApprovalCredential,
  isWebAuthnAvailable,
  prfWrapKeyFromCreationResult,
  randomPrfSaltBase64url,
  requestApprovalAssertion,
  requestPrfWrapKey
} from "./webauthn.js";

const POLL_INTERVAL_MS = 3000;
const RESET_CONFIRM_MS = 10000;
const QR_SCAN_INTERVAL_MS = 250;
const QR_ANIM_INTERVAL_MS = 500;
const MIGRATION_POLL_INTERVAL_MS = 3000;
const RECOVERY_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ids = [
  "runtimeStatus",
  "homeButton",
  "statusModal",
  "statusModalText",
  "statusModalClose",
  "approvalView",
  "historyView",
  "settingsView",
  "historyButton",
  "settingsButton",
  "bundleQueue",
  "bundleQueueTitle",
  "bundleQueueMeta",
  "bundleTabs",
  "kernelFrame",
  "historyShell",
  "unlockGate",
  "unlockGateButton",
  "historyUnlockGate",
  "historyUnlockGateButton",
  "deviceBadge",
  "approverValue",
  "deviceValue",
  "shareValue",
  "keyValue",
  "webauthnValue",
  "storageValue",
  "appHashValue",
  "backendOriginInput",
  "saveBackendButton",
  "unlockShareButton",
  "enablePrfButton",
  "scanEnrollmentButton",
  "finishQrEnrollmentButton",
  "createBackupButton",
  "startMigrationButton",
  "confirmDeviceButton",
  "enrollmentFile",
  "qrScanner",
  "qrVideo",
  "cancelQrScanButton",
  "qrModal",
  "qrModalTitle",
  "qrModalClose",
  "qrModalText",
  "qrModalSecret",
  "qrModalSecretValue",
  "qrModalSecretCopy",
  "qrCanvas",
  "qrModalFrame",
  "resetButton",
  "recentCount",
  "recentApprovals",
  "activityDetail",
  "activityDetailTitle",
  "activityDetailApprover",
  "activityDetailSummary",
  "activityDetailRows",
  "activityDetailTableWrap",
  "activityDetailClose"
];
const els = Object.fromEntries(ids.map((id) => [id, document.querySelector(`#${id}`)]));
const state = {
  phoneSharePackage: null,
  webauthnCredential: null,
  storagePersistent: null,
  integrityManifest: null,
  integrityError: null,
  backendOrigin: "",
  backendOriginRequiresPrfUnlock: false,
  shareStorageRequiresPrfUnlock: false,
  prfWrapKey: null,
  prfSaltBase64url: "",
  pendingBundles: [],
  selectedBundleId: "",
  bundle: null,
  lastApprovalResult: null,
  recentApprovals: [],
  selectedApprovalId: "",
  approvedBundleIds: new Set(),
  activeView: "approval",
  resetArmed: false,
  resetTimer: 0,
  qrStream: null,
  qrScanTimer: 0,
  qrScanMode: "enroll",
  backupReassembler: null,
  pendingQrPackage: null,
  qrFrames: [],
  qrFrameIndex: 0,
  qrAnimTimer: 0,
  migrationRequired: false,
  pendingMigrationId: "",
  migrationPollActive: false,
  migrationPollTimer: 0,
  kernelReady: false,
  pollTimer: 0,
  pollInFlight: false,
  pollQueued: false,
  lockGeneration: 0,
  autoUnlockInFlight: false,
  autoUnlockAttemptedGeneration: -1
};

function setStatus(message, level = "normal") {
  els.runtimeStatus.textContent = message;
  els.runtimeStatus.className = level === "error" ? "status-line error" : level === "warning" ? "status-line warning" : "status-line";
  els.runtimeStatus.classList.add("status-button");
  els.runtimeStatus.title = message;
  els.runtimeStatus.setAttribute("aria-label", `Status: ${message}`);
  els.statusModalText.textContent = message;
}

function showStatusModal() {
  els.statusModal.classList.remove("hidden");
  els.runtimeStatus.setAttribute("aria-expanded", "true");
  els.statusModalClose.focus();
}

function hideStatusModal() {
  els.statusModal.classList.add("hidden");
  els.runtimeStatus.setAttribute("aria-expanded", "false");
  els.runtimeStatus.focus();
}

function prfErrorMessage(error) {
  const message = error?.message || String(error);
  return error?.name && error.name !== "Error" ? `${error.name}: ${message}` : message;
}

function isNoPrfKeyError(error) {
  return /WebAuthn PRF returned no key/u.test(error?.message || String(error));
}

function prfReenrollMessage() {
  return "Credential does not support WebAuthn PRF. Reset and re-enroll with a PRF-capable passkey provider.";
}

function initialPrfReason(credential) {
  if (credential.prf_creation_result_available) {
    return credential.prf_creation_error || "PRF result could not be used";
  }
  if (credential.prf_creation_enabled) {
    return "No PRF result returned at registration";
  }
  return "PRF extension not enabled at registration";
}

function needsShareUnlock() {
  return Boolean(state.webauthnCredential && state.shareStorageRequiresPrfUnlock && !state.phoneSharePackage);
}

function publicCredentialForLockedState() {
  if (!state.webauthnCredential?.credential_id) {
    return null;
  }
  return {
    credential_id: state.webauthnCredential.credential_id,
    type: state.webauthnCredential.type ?? "public-key",
    prf_enabled: state.webauthnCredential.prf_enabled === true,
    prf_salt_base64url: state.webauthnCredential.prf_salt_base64url ?? ""
  };
}

function storagePersistenceText() {
  if (state.storagePersistent === null) {
    return "Checking";
  }
  return state.storagePersistent ? "Persistent" : "Not persistent";
}

function prfStorageText() {
  const pkg = state.phoneSharePackage;
  const credential = state.webauthnCredential;
  const locked = needsShareUnlock();
  if (locked) {
    return "PRF active, locked";
  }
  if (credential?.prf_enabled) {
    return "PRF active";
  }
  if (credential?.prf_needs_reenroll) {
    return `Local AES, ${credential.prf_last_error || prfReenrollMessage()}`;
  }
  if (pkg && credential) {
    return credential.prf_last_error ? `Local AES, PRF unavailable: ${credential.prf_last_error}` : "Local AES, PRF not enabled";
  }
  return "No share";
}

function renderStorage() {
  const text = `${storagePersistenceText()} · ${prfStorageText()}`;
  els.storageValue.textContent = text;
  els.storageValue.title = text;
}

function renderUnlockGate() {
  const locked = needsShareUnlock();
  els.unlockGate.classList.toggle("hidden", !locked);
  els.kernelFrame.classList.toggle("hidden", locked);
  els.bundleQueue.classList.toggle("hidden", locked || state.pendingBundles.length <= 1);
  els.historyUnlockGate.classList.toggle("hidden", !locked);
  els.historyShell.classList.toggle("hidden", locked);
  queueAutoUnlock();
}

function lockPrfSession(message = "App locked") {
  if (!state.shareStorageRequiresPrfUnlock || !state.phoneSharePackage) {
    return false;
  }

  clearPollTimer();
  state.pollQueued = false;
  state.lockGeneration += 1;
  state.autoUnlockInFlight = false;
  state.phoneSharePackage = null;
  state.webauthnCredential = publicCredentialForLockedState();
  state.prfWrapKey = null;
  state.prfSaltBase64url = "";
  if (state.backendOriginRequiresPrfUnlock) {
    state.backendOrigin = "";
  }
  state.pendingBundles = [];
  state.selectedBundleId = "";
  state.bundle = null;
  state.lastApprovalResult = null;
  state.recentApprovals = [];
  state.selectedApprovalId = "";
  stopQrScanner();
  renderEnrollment();
  renderRecentApprovals();
  renderBundleQueue();
  sendKernelState();
  setStatus(message, "warning");
  return true;
}

function clearTransientApprovalResult() {
  if (!state.lastApprovalResult) {
    return false;
  }
  state.lastApprovalResult = null;
  sendKernelState();
  return true;
}

function handleAppHidden() {
  if (state.qrStream) {
    stopQrScanner();
  }
  if (!lockPrfSession("App locked")) {
    clearTransientApprovalResult();
  }
}

function routeFromLocation() {
  const route = window.location.hash.slice(1);
  return ["approval", "history", "settings"].includes(route) ? route : "approval";
}

function routeHash(view) {
  return `#${view}`;
}

function setRoute(view, mode = "push") {
  const nextState = { view };
  const nextHash = routeHash(view);
  if (mode === "replace") {
    window.history.replaceState(nextState, "", nextHash);
  } else if (window.history.state?.view !== view || window.location.hash !== nextHash) {
    window.history.pushState(nextState, "", nextHash);
  }
}

function showView(view, options = {}) {
  state.activeView = view;
  els.approvalView.classList.toggle("hidden", view !== "approval");
  els.historyView.classList.toggle("hidden", view !== "history");
  els.settingsView.classList.toggle("hidden", view !== "settings");
  els.historyButton.classList.toggle("active", view === "history");
  els.historyButton.setAttribute("aria-pressed", String(view === "history"));
  els.settingsButton.classList.toggle("active", view === "settings");
  els.settingsButton.setAttribute("aria-pressed", String(view === "settings"));
  if (view === "history") {
    renderRecentApprovals();
  }
  renderUnlockGate();
  if (options.history === "push" || options.history === "replace") {
    setRoute(view, options.history);
  }
}

function toggleView(view) {
  showView(state.activeView === view ? "approval" : view, { history: "push" });
}

function kernelFrameUrl() {
  return "./kernel.html";
}

function kernelTargetOrigin() {
  return new URL(els.kernelFrame.src, window.location.href).origin;
}

function normalizeBackendOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
    throw new Error("Backend URL must use HTTPS");
  }
  url.pathname = "";
  url.search = "";
  url.hash = "";
  return url.origin;
}

async function backendOriginChangeChallengeBytes(nextOrigin) {
  if (!state.phoneSharePackage || !state.webauthnCredential) {
    throw new Error("Enroll device before saving backend URL");
  }

  const context = [
    "APPROVAL_BACKEND_ORIGIN_CHANGE_V1",
    `page_origin:${window.location.origin}`,
    `approver_id:${state.phoneSharePackage.approver_id}`,
    `device_id:${state.phoneSharePackage.device_id}`,
    `share_index:${state.phoneSharePackage.share_index}`,
    `key_id:${state.phoneSharePackage.key_id}`,
    `credential_id:${state.webauthnCredential.credential_id}`,
    `current_backend_origin:${state.backendOrigin || "-"}`,
    `next_backend_origin:${nextOrigin}`
  ].join("\n");
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${context}\n`)));
}

async function authorizeBackendOriginChange(nextOrigin) {
  const challengeBytes = await backendOriginChangeChallengeBytes(nextOrigin);
  setStatus("Confirm backend change with WebAuthn");
  await requestApprovalAssertion({
    credentialId: state.webauthnCredential.credential_id,
    challengeBytes
  }).catch((error) => {
    throw new Error(`Backend change approval failed: ${error.message}`);
  });
}

function backendOriginStorageOptions() {
  if (!state.webauthnCredential?.prf_enabled) {
    return {};
  }
  if (!state.prfWrapKey || !state.prfSaltBase64url) {
    throw new Error("Unlock share before saving backend URL");
  }
  return {
    prfWrapKey: state.prfWrapKey,
    prfSaltBase64url: state.prfSaltBase64url
  };
}

function clearResetArming() {
  if (state.resetTimer) {
    clearTimeout(state.resetTimer);
    state.resetTimer = 0;
  }
  state.resetArmed = false;
  els.resetButton.textContent = "Reset";
}

function armReset() {
  state.resetArmed = true;
  els.resetButton.textContent = "Confirm Reset";
  setStatus("Click Confirm Reset to clear this device, then confirm with WebAuthn.", "warning");
  if (state.resetTimer) {
    clearTimeout(state.resetTimer);
  }
  state.resetTimer = setTimeout(() => {
    clearResetArming();
    setStatus("Reset cancelled");
  }, RESET_CONFIRM_MS);
}

async function resetEnrollmentChallengeBytes() {
  const context = [
    "APPROVAL_ENROLLMENT_RESET_V1",
    `page_origin:${window.location.origin}`,
    `approver_id:${state.phoneSharePackage?.approver_id ?? "-"}`,
    `device_id:${state.phoneSharePackage?.device_id ?? "-"}`,
    `share_index:${state.phoneSharePackage?.share_index ?? "-"}`,
    `key_id:${state.phoneSharePackage?.key_id ?? "-"}`,
    `credential_id:${state.webauthnCredential?.credential_id ?? "-"}`
  ].join("\n");
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${context}\n`)));
}

async function authorizeEnrollmentReset() {
  if (!state.webauthnCredential) {
    return;
  }

  const challengeBytes = await resetEnrollmentChallengeBytes();
  setStatus("Confirm reset with WebAuthn");
  await requestApprovalAssertion({
    credentialId: state.webauthnCredential.credential_id,
    challengeBytes
  }).catch((error) => {
    throw new Error(`Reset approval failed: ${error.message}`);
  });
}

async function localShareUnlockChallengeBytes() {
  const context = [
    "APPROVAL_LOCAL_SHARE_UNLOCK_V1",
    `page_origin:${window.location.origin}`,
    `credential_id:${state.webauthnCredential?.credential_id ?? "-"}`
  ].join("\n");
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${context}\n`)));
}

// Issue #26: user-verification gate the storage layer runs before unwrapping a
// local-AES (non-PRF) phone share. Returns without a ceremony when no credential
// is registered yet (nothing to verify against).
async function verifyLocalShareUnlock() {
  if (!state.webauthnCredential?.credential_id) {
    return;
  }
  setStatus("Confirm with WebAuthn to unlock the local share");
  await requestApprovalAssertion({
    credentialId: state.webauthnCredential.credential_id,
    challengeBytes: await localShareUnlockChallengeBytes()
  });
}

function totalText(totals = []) {
  return totals.map((total) => amountMinorToDecimal(total.amount_minor, total.currency)).join(", ");
}

function bankPaymentSummaryText(payments = []) {
  const counts = {
    executed: 0,
    pending: 0,
    failed: 0
  };
  for (const payment of payments) {
    const bankStatus = String(payment.bank_status ?? "").toLowerCase();
    const paymentStatus = String(payment.bank_payment_status ?? "").toUpperCase();
    if (paymentStatus === "PAYMENT_EXECUTED" || bankStatus === "executed") {
      counts.executed += 1;
    } else if (
      ["PAYMENT_REJECTED", "PAYMENT_CANCELLED", "AUTHORIZATION_FAILED"].includes(paymentStatus) ||
      ["failed", "auth_expired", "key_inactive", "date_invalid"].includes(bankStatus) ||
      payment.bank_error
    ) {
      counts.failed += 1;
    } else if (paymentStatus || bankStatus) {
      counts.pending += 1;
    }
  }

  const total = counts.executed + counts.pending + counts.failed;
  if (total === 0) {
    return "";
  }
  if (counts.executed === total) {
    return "Bank executed";
  }
  if (counts.failed === total) {
    return "Bank failed";
  }
  if (counts.pending === total) {
    return "";
  }
  const parts = [
    counts.executed ? `${counts.executed} executed` : "",
    counts.pending ? `${counts.pending} pending` : "",
    counts.failed ? `${counts.failed} failed` : ""
  ].filter(Boolean);
  return `Bank mixed: ${parts.join(", ")}`;
}

function bankSubmissionText(submission, payments = []) {
  if (submission?.status === "date_invalid") {
    return "Bank date expired";
  }
  const paymentSummary = bankPaymentSummaryText(payments);
  if (paymentSummary) {
    return paymentSummary;
  }
  if (!submission) {
    return "";
  }
  if (!submission.enabled) {
    return "Bank disabled";
  }
  const total = submission.total_payment_count ?? submission.payment_count ?? 0;
  const done = submission.payment_count ?? 0;
  if (submission.status === "queued") {
    return "Bank queued";
  }
  if (submission.status === "submitting") {
    return `Bank ${done}/${total}`;
  }
  if (submission.status === "executed") {
    return "Bank executed";
  }
  if (submission.status === "submitted") {
    return "Bank submitted";
  }
  if (submission.status === "auth_expired") {
    return "Bank auth expired";
  }
  if (submission.status === "key_refreshing") {
    return "Bank key renewal";
  }
  if (submission.status === "key_inactive") {
    return "Bank key inactive";
  }
  if (submission.status === "date_invalid") {
    return "Bank date expired";
  }
  if (submission.status === "failed") {
    return "Bank failed";
  }
  return `Bank ${submission.status}`;
}

function bankPaymentStatusText(payment) {
  if (payment.bank_status === "auth_expired" || payment.bank_error === "bank_access_token_expired") {
    return "Bank auth expired";
  }
  if (payment.bank_status === "key_refreshing" || payment.bank_error === "bank_signing_key_inactive_refreshing") {
    return "Bank key renewal";
  }
  if (payment.bank_status === "key_inactive" || payment.bank_error === "bank_signing_key_inactive") {
    return "Bank key inactive";
  }
  if (payment.bank_status === "date_invalid" || payment.bank_error === "bank_originating_date_expired") {
    return "Bank date expired";
  }
  if (payment.bank_error) {
    return `Bank failed: ${payment.bank_error}`;
  }
  const status = payment.bank_payment_status ?? payment.bank_status;
  if (!status) {
    return "";
  }
  const reason = payment.bank_payment_status_reason ? ` · ${payment.bank_payment_status_reason}` : "";
  return `Bank ${status}${reason}`;
}

function shortBundleId(bundleId = "") {
  return bundleId.length > 18 ? `${bundleId.slice(0, 10)}...${bundleId.slice(-6)}` : bundleId;
}

function pendingBundleTotalText(bundle) {
  return totalText(bundle?.totals ?? []) || "-";
}

function pendingBundleTitle(bundle, index) {
  const count = bundle?.payment_inputs?.length ?? 0;
  return `Bundle ${index + 1} · ${count} tx`;
}

function renderBundleQueue() {
  const bundles = state.pendingBundles;
  const multiple = bundles.length > 1 && !needsShareUnlock();
  els.bundleQueue.classList.toggle("hidden", !multiple);
  els.bundleTabs.replaceChildren();
  if (!multiple) {
    els.bundleQueueTitle.textContent = bundles.length === 1 ? "1 bundle pending" : "No bundles pending";
    els.bundleQueueMeta.textContent = "";
    return;
  }

  const selectedIndex = Math.max(0, bundles.findIndex((bundle) => bundle.bundle_id === state.selectedBundleId));
  els.bundleQueueTitle.textContent = `${bundles.length} bundles pending`;
  els.bundleQueueMeta.textContent = `Reviewing ${selectedIndex + 1} of ${bundles.length}`;

  bundles.forEach((bundle, index) => {
    const selected = bundle.bundle_id === state.selectedBundleId;
    const tab = document.createElement("button");
    tab.type = "button";
    tab.className = `bundle-tab${selected ? " selected" : ""}`;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-selected", String(selected));
    tab.title = bundle.bundle_id;
    tab.addEventListener("click", () => selectPendingBundle(bundle.bundle_id, { userSelected: true }));

    const label = document.createElement("strong");
    label.textContent = pendingBundleTitle(bundle, index);
    const meta = document.createElement("span");
    meta.textContent = `${pendingBundleTotalText(bundle)} · ${shortBundleId(bundle.bundle_id)}`;
    tab.append(label, meta);
    els.bundleTabs.append(tab);
  });
}

function selectPendingBundle(bundleId, options = {}) {
  const bundle = state.pendingBundles.find((item) => item.bundle_id === bundleId) ?? null;
  state.selectedBundleId = bundle?.bundle_id ?? "";
  state.bundle = bundle;
  renderBundleQueue();
  sendKernelState();
  if (options.userSelected && bundle) {
    setStatus(`Reviewing ${shortBundleId(bundle.bundle_id)}`);
  }
}

function timeText(iso) {
  const time = Date.parse(iso);
  if (!Number.isFinite(time)) {
    return "-";
  }
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(time));
}

function approvalTimeText(approval) {
  return timeText(approval?.approved_at || approval?.received_at);
}

function cell(text, className = "") {
  const value = document.createElement("td");
  value.textContent = text;
  if (className) {
    value.className = className;
  }
  return value;
}

function span(text, className = "") {
  const value = document.createElement("span");
  value.textContent = text;
  if (className) {
    value.className = className;
  }
  return value;
}

function emptyRow(text = "-") {
  const row = document.createElement("tr");
  const value = cell(text);
  value.colSpan = 3;
  value.className = "empty-state";
  row.append(value);
  return row;
}

function paymentTextCell(payment) {
  const td = cell(payment.remittance_text || "-");
  const status = bankPaymentStatusText(payment);
  if (status) {
    const detail = document.createElement("span");
    detail.className = "payment-status-line";
    detail.textContent = status;
    td.append(document.createElement("br"), detail);
  }
  return td;
}

function renderPaymentRows(target, payments) {
  target.replaceChildren();
  if (payments.length === 0) {
    target.append(emptyRow("Payment details unavailable"));
    return;
  }

  for (const payment of payments) {
    const row = document.createElement("tr");
    row.append(
      cell(payment.creditor_account || "-"),
      paymentTextCell(payment),
      cell(amountMinorToDecimal(payment.amount_minor ?? "0", payment.currency ?? ""), "numeric")
    );
    target.append(row);
  }
}

function visiblePaymentsFromApproval(approval) {
  if (!Array.isArray(approval?.visible_payments)) {
    return [];
  }
  return approval.visible_payments.map((payment) => ({
    creditor_account: payment?.creditor_account ?? "",
    remittance_text: payment?.remittance_text ?? "",
    amount_minor: payment?.amount_minor ?? "0",
    currency: payment?.currency ?? "",
    bank_status: payment?.bank_status ?? "",
    bank_payment_status: payment?.bank_payment_status ?? "",
    bank_payment_status_reason: payment?.bank_payment_status_reason ?? "",
    bank_payment_id: payment?.bank_payment_id ?? "",
    bank_error: payment?.bank_error ?? ""
  }));
}

function approvalShareText(approval) {
  const shareIndex = Number(approval?.share_index);
  if (!Number.isInteger(shareIndex)) {
    return "Share unknown";
  }
  return shareIndex === state.phoneSharePackage?.share_index ? `You, share ${shareIndex}` : `Share ${shareIndex}`;
}

function approvalApproverText(approval) {
  return `Approved by ${approvalShareText(approval)}`;
}

function renderRecentApprovals() {
  if (state.selectedApprovalId && !state.recentApprovals.some((approval) => approval.bundle_id === state.selectedApprovalId)) {
    state.selectedApprovalId = "";
  }
  els.historyView.classList.toggle("history-detail-open", Boolean(state.selectedApprovalId));

  const approvals = state.recentApprovals.slice(0, 20);
  els.recentCount.textContent = String(state.recentApprovals.length);
  els.recentApprovals.replaceChildren();

  if (approvals.length === 0) {
    const empty = document.createElement("div");
    empty.className = "activity-empty";
    empty.textContent = "No approvals in the last 24 hours";
    els.recentApprovals.append(empty);
    renderActivityDetail();
    return;
  }

  for (const approval of approvals) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = `activity-row${approval.bundle_id === state.selectedApprovalId ? " selected" : ""}`;
    row.addEventListener("click", () => {
      state.selectedApprovalId = approval.bundle_id;
      renderRecentApprovals();
    });

    const main = document.createElement("div");
    main.className = "activity-main";
    const bundle = document.createElement("strong");
    bundle.textContent = `${approval.payment_count ?? "-"} transactions`;
    const detail = document.createElement("span");
    detail.textContent = `Approved ${approvalTimeText(approval)} · ${shortBundleId(approval.bundle_id)}`;
    main.append(bundle, detail);

    const meta = document.createElement("div");
    meta.className = "activity-meta";
    const bankStatus = bankSubmissionText(approval.bank_submission, visiblePaymentsFromApproval(approval));
    meta.append(
      span(approvalApproverText(approval), "activity-approver"),
      ...(bankStatus ? [span(bankStatus, "activity-status")] : []),
      span(totalText(approval.totals) || "-", "activity-total")
    );
    row.append(main, meta);
    els.recentApprovals.append(row);
  }
  renderActivityDetail();
}

function renderActivityDetail() {
  const approval = state.recentApprovals.find((item) => item.bundle_id === state.selectedApprovalId);
  if (!approval) {
    els.activityDetail.classList.add("activity-detail-empty");
    els.activityDetailTitle.textContent = "No bundle selected";
    els.activityDetailApprover.textContent = "-";
    els.activityDetailApprover.classList.add("hidden");
    els.activityDetailSummary.textContent = "Approved last 24h";
    els.activityDetailTableWrap.classList.add("hidden");
    els.activityDetailClose.classList.add("hidden");
    els.activityDetailRows.replaceChildren(emptyRow());
    return;
  }

  els.activityDetail.classList.remove("activity-detail-empty");
  els.activityDetailTitle.textContent = `${approval.payment_count ?? "-"} transactions`;
  els.activityDetailApprover.textContent = approvalApproverText(approval);
  els.activityDetailApprover.classList.remove("hidden");
  els.activityDetailSummary.textContent = [
    totalText(approval.totals) || "-",
    `Approved ${approvalTimeText(approval)}`,
    bankSubmissionText(approval.bank_submission, visiblePaymentsFromApproval(approval)),
    shortBundleId(approval.bundle_id)
  ].filter(Boolean).join(" · ");
  els.activityDetailTableWrap.classList.remove("hidden");
  els.activityDetailClose.classList.remove("hidden");
  renderPaymentRows(els.activityDetailRows, visiblePaymentsFromApproval(approval));
}

function sendKernelState() {
  if (!state.kernelReady || !els.kernelFrame.contentWindow) {
    return;
  }
  els.kernelFrame.contentWindow.postMessage({
    source: "approval-shell",
    type: "state",
    phoneSharePackage: state.phoneSharePackage,
    webauthnCredential: state.webauthnCredential,
    backendOrigin: state.backendOrigin,
    bundle: state.bundle,
    lastApprovalResult: state.lastApprovalResult,
    approvedBundleIds: [...state.approvedBundleIds]
  }, kernelTargetOrigin());
}

function handleKernelMessage(event) {
  if (event.source !== els.kernelFrame.contentWindow || event.data?.source !== "approval-kernel") {
    return;
  }
  if (event.origin !== kernelTargetOrigin()) {
    return;
  }

  if (event.data.type === "ready") {
    state.kernelReady = true;
    sendKernelState();
  } else if (event.data.type === "status") {
    setStatus(event.data.message, event.data.level ?? "normal");
  } else if (event.data.type === "started") {
    clearPollTimer();
    state.pollQueued = false;
    state.lastApprovalResult = null;
    sendKernelState();
  } else if (event.data.type === "approved") {
    state.approvedBundleIds.add(event.data.bundle_id);
    state.lastApprovalResult = event.data.result ?? null;
    state.pendingBundles = state.pendingBundles.filter((bundle) => bundle.bundle_id !== event.data.bundle_id);
    selectPendingBundle(state.pendingBundles[0]?.bundle_id ?? "");
    sendKernelState();
    schedulePendingBundlePoll(1000);
  } else if (event.data.type === "error") {
    state.lastApprovalResult = event.data.result ?? {
      status: "failed",
      title: "Approval failed",
      detail: event.data.message ?? "The approval could not be submitted."
    };
    sendKernelState();
    schedulePendingBundlePoll();
  }
}

function renderIntegrity() {
  if (state.integrityManifest?.manifest_sha256) {
    els.appHashValue.textContent = state.integrityManifest.manifest_sha256;
    els.appHashValue.title = state.integrityManifest.manifest_sha256;
    return;
  }
  els.appHashValue.textContent = state.integrityError ? "Unavailable" : "Checking";
  els.appHashValue.title = state.integrityError?.message ?? "";
}

function renderQrEnrollment() {
  const scanning = Boolean(state.qrStream);
  els.qrScanner.classList.toggle("hidden", !scanning);
  els.scanEnrollmentButton.disabled = scanning;
  els.finishQrEnrollmentButton.classList.toggle("hidden", !state.pendingQrPackage);
}

function canEnablePrfStorage() {
  return Boolean(
    state.webauthnCredential &&
    !state.webauthnCredential.prf_enabled &&
    !state.shareStorageRequiresPrfUnlock
  );
}

function renderEnrollment() {
  const pkg = state.phoneSharePackage;
  const credential = state.webauthnCredential;
  const enrolled = Boolean(pkg && credential);
  const locked = needsShareUnlock();
  const backendOriginLocked = locked || Boolean(state.backendOriginRequiresPrfUnlock && !state.prfWrapKey);
  els.deviceBadge.textContent = enrolled ? "Enrolled" : locked ? "Locked" : "Not enrolled";
  els.deviceBadge.className = `badge ${enrolled ? "badge-ok" : locked ? "badge-warn" : "badge-muted"}`;
  els.approverValue.textContent = pkg?.approver_id ?? "-";
  els.deviceValue.textContent = pkg?.device_id ?? "-";
  els.shareValue.textContent = pkg ? `${pkg.share_index} of ${pkg.players}, threshold ${pkg.threshold}` : locked ? "Locked by WebAuthn PRF" : "-";
  els.keyValue.textContent = pkg?.key_id ?? "-";
  els.webauthnValue.textContent = credential ? credential.prf_enabled ? "Registered + PRF" : "Registered" : "-";
  renderStorage();
  els.backendOriginInput.value = backendOriginLocked ? "" : state.backendOrigin;
  els.backendOriginInput.placeholder = backendOriginLocked ? "Unlock to view backend" : "https://example.com";
  els.backendOriginInput.disabled = backendOriginLocked;
  els.saveBackendButton.disabled = backendOriginLocked;
  els.unlockShareButton.classList.toggle("hidden", !locked);
  els.enablePrfButton.classList.toggle("hidden", !canEnablePrfStorage());
  els.createBackupButton.classList.toggle("hidden", !enrolled);
  els.startMigrationButton.classList.toggle("hidden", !(enrolled && state.migrationRequired));
  els.confirmDeviceButton.classList.toggle("hidden", !enrolled);
  renderUnlockGate();
  renderIntegrity();
  renderQrEnrollment();
  sendKernelState();
}

function packageFromQrUrl(value) {
  try {
    const url = new URL(value);
    for (const key of ["package", "enrollment", "data"]) {
      const item = url.searchParams.get(key);
      if (item) {
        return item;
      }
    }
    return url.hash.length > 1 ? decodeURIComponent(url.hash.slice(1)) : value;
  } catch {
    return value;
  }
}

function base64urlToText(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), "=");
  const binary = atob(padded);
  return new TextDecoder().decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
}

function validateEnrollmentPackage(pkg) {
  if (pkg?.version === "encrypted_backup_qr_v1") {
    // Recovery path (issue #40): accept the encrypted backup shape here; the
    // passphrase decrypt + share import happens in enrollFromParsedPackage.
    validateEncryptedBackupQrV1(pkg);
    return pkg;
  }
  decodePhoneSharePackageV1(pkg);
  return pkg;
}

async function recoverShareFromBackupQr(payload) {
  const passphrase = window.prompt("Enter the backup passphrase to decrypt this share:");
  if (!passphrase) {
    throw new Error("Backup recovery cancelled");
  }
  setStatus("Decrypting encrypted backup (Argon2id, this can take a few seconds)");
  return decodeEncryptedBackupQrV1(payload, passphrase);
}

async function enrollFromParsedPackage(parsed) {
  if (parsed?.version === "encrypted_backup_qr_v1") {
    const share = await recoverShareFromBackupQr(parsed);
    await enrollFromPackage(share);
    setStatus("Recovered share from encrypted backup; device enrolled");
    return;
  }
  await enrollFromPackage(parsed);
}

function parseEnrollmentPackageText(text) {
  let payload = packageFromQrUrl(text.trim());
  for (const prefix of ["approval-enrollment:", "approval-enrollment-v1:"]) {
    if (payload.startsWith(prefix)) {
      payload = payload.slice(prefix.length);
    }
  }

  let lastError = new Error("empty enrollment package");
  const candidates = [payload];
  if (!payload.startsWith("{")) {
    try {
      candidates.push(base64urlToText(payload));
    } catch (error) {
      lastError = error;
    }
  }

  for (const candidate of candidates) {
    try {
      return validateEnrollmentPackage(JSON.parse(candidate));
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

// Enrollment (#4/#35 PWA side): register the WebAuthn credential PUBLIC KEY with
// the backend registry so server-side assertion verification (and the
// fail-closed bundle-approval path) can validate this device's assertions. The
// backend binds the approver/device/share/key from the threshold backend-auth
// signature; we only supply the credential public key, its algorithm, RP ID and
// allowed origin. Best-effort: needs a configured backend origin and an exported
// public key (older records / public-only locked records may lack it).
async function enrollCredentialWithBackend(credential = state.webauthnCredential) {
  const pkg = state.phoneSharePackage;
  if (!state.backendOrigin || !pkg || !credential?.credential_id) {
    return false;
  }
  if (!credential.public_key_spki_base64url || !Number.isInteger(credential.public_key_alg) || !credential.rp_id) {
    return false;
  }
  await enrollApprovalCredential({
    version: "enroll_credential_v1",
    approver_id: pkg.approver_id,
    device_id: pkg.device_id,
    share_index: pkg.share_index,
    key_id: pkg.key_id,
    credential_id: credential.credential_id,
    public_key_spki_base64url: credential.public_key_spki_base64url,
    alg: credential.public_key_alg,
    rp_id: credential.rp_id,
    allowed_origins: [window.location.origin]
  }, pkg, state.backendOrigin);
  return true;
}

async function enrollFromPackage(pkg) {
  if (!isWebAuthnAvailable()) {
    throw new Error("WebAuthn is required on this browser");
  }

  validateEnrollmentPackage(pkg);
  const credential = await createApprovalCredential({
    approverId: pkg.approver_id,
    deviceId: pkg.device_id
  });
  const prfWrap = await createPrfStorageWrap(credential);
  await savePhoneSharePackage(pkg, prfWrap ? {
    prfWrapKey: prfWrap.wrapKey,
    prfSaltBase64url: prfWrap.saltBase64url
  } : {});
  const storedCredential = storableCredentialRecord(credential, prfWrap);
  await saveWebAuthnCredential(storedCredential);
  state.phoneSharePackage = pkg;
  state.webauthnCredential = storedCredential;
  state.shareStorageRequiresPrfUnlock = Boolean(prfWrap);
  state.prfWrapKey = prfWrap?.wrapKey ?? null;
  state.prfSaltBase64url = prfWrap?.saltBase64url ?? "";
  if (state.backendOrigin && prfWrap) {
    await saveBackendOrigin(state.backendOrigin, {
      prfWrapKey: prfWrap.wrapKey,
      prfSaltBase64url: prfWrap.saltBase64url
    });
    state.backendOriginRequiresPrfUnlock = true;
  }
  state.pendingQrPackage = null;
  renderEnrollment();
  sendKernelState();
  setStatus(prfWrap ? "Device enrolled with WebAuthn PRF storage" : "Device enrolled. Tap Enable PRF in Settings to test PRF storage.", prfWrap ? "normal" : "warning");
  if (state.backendOrigin) {
    await enrollCredentialWithBackend(credential).catch((error) => {
      if (error.code === "context_already_enrolled") {
        // New-phone case: the approver context already has a passkey, so this
        // device cannot self-enroll. It must go through operator-approved
        // migration instead (Request Migration → confirm on old phone → approve).
        state.migrationRequired = true;
        renderEnrollment();
        setStatus("This approver already has a device. Tap Request Migration to move approval to this phone.", "warning");
        return;
      }
      setStatus(`Device enrolled locally; backend credential enrollment failed: ${error.message}`, "warning");
    });
  }
  pollPendingBundles();
}

function storableCredentialRecord(credential, prfWrap) {
  return {
    credential_id: credential.credential_id,
    type: credential.type,
    created_at: credential.created_at,
    // Non-secret enrollment material so the credential can be (re-)enrolled with
    // the backend registry whenever a backend origin is configured.
    rp_id: typeof credential.rp_id === "string" ? credential.rp_id : "",
    public_key_spki_base64url: typeof credential.public_key_spki_base64url === "string" ? credential.public_key_spki_base64url : "",
    public_key_alg: Number.isInteger(credential.public_key_alg) ? credential.public_key_alg : null,
    resident_key: credential.resident_key === true,
    webauthn_capabilities: credential.webauthn_capabilities ?? {},
    prf_creation_enabled: credential.prf_creation_enabled === true,
    prf_creation_result_available: credential.prf_creation_result_available === true,
    prf_enabled: Boolean(prfWrap),
    prf_salt_base64url: prfWrap?.saltBase64url ?? "",
    prf_last_checked_at: prfWrap ? new Date().toISOString() : "",
    prf_last_error: prfWrap ? "" : initialPrfReason(credential),
    prf_needs_reenroll: false
  };
}

async function createPrfStorageWrap(credential) {
  const creationWrapKey = await prfWrapKeyFromCreationResult(credential).catch((error) => {
    credential.prf_creation_error = prfErrorMessage(error);
    return null;
  });
  if (creationWrapKey && credential.prf_creation_salt_base64url) {
    return {
      wrapKey: creationWrapKey,
      saltBase64url: credential.prf_creation_salt_base64url
    };
  }

  return null;
}

async function unlockPrfShare() {
  if (!state.webauthnCredential) {
    throw new Error("WebAuthn credential is not registered");
  }
  const saltBase64url = state.webauthnCredential.prf_salt_base64url || await loadPhoneSharePrfSalt();
  if (!saltBase64url) {
    throw new Error("Missing WebAuthn PRF salt");
  }

  setStatus("Unlock share with WebAuthn");
  const prfWrapKey = await requestPrfWrapKey({
    credentialId: state.webauthnCredential.credential_id,
    saltBase64url
  });
  state.prfWrapKey = prfWrapKey;
  state.prfSaltBase64url = saltBase64url;
  state.phoneSharePackage = await loadPhoneSharePackage({ prfWrapKey });
  if (!state.phoneSharePackage) {
    throw new Error("Share unlock failed");
  }
  state.backendOriginRequiresPrfUnlock = await backendOriginRequiresPrfUnlock().catch(() => false);
  state.backendOrigin = await loadBackendOrigin({ prfWrapKey }).catch(() => "");
  if (state.backendOrigin && !state.backendOriginRequiresPrfUnlock) {
    await saveBackendOrigin(state.backendOrigin, { prfWrapKey, prfSaltBase64url: saltBase64url });
    state.backendOriginRequiresPrfUnlock = true;
  }
  state.shareStorageRequiresPrfUnlock = true;
  const storedCredential = await loadWebAuthnCredential().catch(() => null);
  state.webauthnCredential = {
    ...(storedCredential ?? state.webauthnCredential),
    prf_enabled: true,
    prf_salt_base64url: saltBase64url,
    prf_last_checked_at: new Date().toISOString(),
    prf_last_error: ""
  };
  await saveWebAuthnCredential(state.webauthnCredential);
  renderEnrollment();
  sendKernelState();
  setStatus("Share unlocked");
  pollPendingBundles({ queueIfBusy: true });
}

async function unlockFromLockedView() {
  const targetView = state.activeView === "history" ? "history" : "approval";
  try {
    await unlockPrfShare();
    showView(targetView);
  } catch (error) {
    setStatus(`Unlock failed: ${error.message}`, "error");
    showView(targetView);
  }
}

function queueAutoUnlock() {
  if (
    state.autoUnlockInFlight ||
    !needsShareUnlock() ||
    state.activeView === "settings" ||
    document.visibilityState !== "visible" ||
    state.autoUnlockAttemptedGeneration === state.lockGeneration
  ) {
    return;
  }

  state.autoUnlockInFlight = true;
  state.autoUnlockAttemptedGeneration = state.lockGeneration;
  setTimeout(() => {
    if (!needsShareUnlock() || state.activeView === "settings" || document.visibilityState !== "visible") {
      state.autoUnlockInFlight = false;
      return;
    }
    const targetView = state.activeView === "history" ? "history" : "approval";
    unlockPrfShare()
      .then(() => showView(targetView))
      .catch((error) => {
        setStatus(`Unlock cancelled: ${error.message}`, "warning");
      })
      .finally(() => {
        state.autoUnlockInFlight = false;
      });
  }, 150);
}

async function enablePrfStorage() {
  if (!state.phoneSharePackage || !state.webauthnCredential) {
    throw new Error("Enroll device before enabling PRF storage");
  }
  if (state.webauthnCredential.prf_enabled) {
    setStatus("PRF storage is already active");
    return;
  }

  const saltBase64url = randomPrfSaltBase64url();
  setStatus("Confirm PRF storage with WebAuthn");
  try {
    const prfWrapKey = await requestPrfWrapKey({
      credentialId: state.webauthnCredential.credential_id,
      saltBase64url
    });
    state.prfWrapKey = prfWrapKey;
    state.prfSaltBase64url = saltBase64url;
    await savePhoneSharePackage(state.phoneSharePackage, {
      prfWrapKey,
      prfSaltBase64url: saltBase64url
    });
    if (state.backendOrigin) {
      await saveBackendOrigin(state.backendOrigin, { prfWrapKey, prfSaltBase64url: saltBase64url });
      state.backendOriginRequiresPrfUnlock = true;
    }
    state.webauthnCredential = {
      ...state.webauthnCredential,
      prf_enabled: true,
      prf_salt_base64url: saltBase64url,
      prf_last_checked_at: new Date().toISOString(),
      prf_last_error: ""
    };
    await saveWebAuthnCredential(state.webauthnCredential);
    state.shareStorageRequiresPrfUnlock = true;
    renderEnrollment();
    sendKernelState();
    setStatus("Share storage upgraded to WebAuthn PRF");
  } catch (error) {
    const needsReenroll = isNoPrfKeyError(error);
    state.webauthnCredential = {
      ...state.webauthnCredential,
      prf_enabled: false,
      prf_last_checked_at: new Date().toISOString(),
      prf_last_error: needsReenroll ? prfReenrollMessage() : prfErrorMessage(error),
      prf_needs_reenroll: needsReenroll
    };
    await saveWebAuthnCredential(state.webauthnCredential);
    renderEnrollment();
    throw new Error(`PRF unavailable: ${state.webauthnCredential.prf_last_error}`);
  }
}

async function saveBackendFromSettings() {
  const origin = normalizeBackendOrigin(els.backendOriginInput.value.trim());
  await authorizeBackendOriginChange(origin);
  const storageOptions = backendOriginStorageOptions();
  await saveBackendOrigin(origin, storageOptions);
  state.backendOrigin = origin;
  state.backendOriginRequiresPrfUnlock = Boolean(storageOptions.prfWrapKey);
  renderEnrollment();
  setStatus("Backend saved");
  if (state.phoneSharePackage && state.webauthnCredential) {
    await enrollCredentialWithBackend().catch((error) => {
      setStatus(`Backend saved; credential enrollment failed: ${error.message}`, "warning");
    });
  }
  pollPendingBundles();
}

async function enrollFromPackageFile(file) {
  if (!file) {
    return;
  }
  await enrollFromParsedPackage(parseEnrollmentPackageText(await file.text()));
  els.enrollmentFile.value = "";
}

async function createQrDetector() {
  if (!("BarcodeDetector" in window)) {
    throw new Error("QR scanning is unavailable in this browser. Use Enroll Package.");
  }
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("Camera access is unavailable in this browser. Use Enroll Package.");
  }
  const supported = await window.BarcodeDetector.getSupportedFormats?.();
  if (supported && !supported.includes("qr_code")) {
    throw new Error("QR scanning is unavailable in this browser. Use Enroll Package.");
  }
  return new window.BarcodeDetector({ formats: ["qr_code"] });
}

function stopQrScanner(message = "") {
  if (state.qrScanTimer) {
    clearTimeout(state.qrScanTimer);
    state.qrScanTimer = 0;
  }
  if (state.qrStream) {
    for (const track of state.qrStream.getTracks()) {
      track.stop();
    }
    state.qrStream = null;
  }
  state.backupReassembler = null;
  state.qrScanMode = "enroll";
  els.qrVideo.pause();
  els.qrVideo.srcObject = null;
  renderQrEnrollment();
  if (message) {
    setStatus(message);
  }
}

async function scanQrFrame(detector) {
  if (!state.qrStream) {
    return;
  }

  try {
    const codes = await detector.detect(els.qrVideo);
    const rawValue = codes.find((code) => code.rawValue?.trim())?.rawValue;
    if (rawValue && await handleScannedValue(rawValue.trim())) {
      return;
    }
  } catch (error) {
    stopQrScanner();
    setStatus(`QR scan failed: ${error.message}`, "error");
    return;
  }

  state.qrScanTimer = setTimeout(() => {
    scanQrFrame(detector);
  }, QR_SCAN_INTERVAL_MS);
}

// Routes a decoded QR value by scan mode. Returns true when scanning is complete
// (camera stopped); false to keep scanning (e.g. waiting for more backup frames).
async function handleScannedValue(rawValue) {
  if (state.qrScanMode === "migration-confirm") {
    const payload = parseMigrationStepUpPayload(rawValue);
    if (!payload) {
      return false;
    }
    stopQrScanner();
    await confirmDeviceFromPayload(payload);
    return true;
  }

  // enroll / recovery scan: a single enrollment package, or a multi-part backup.
  if (rawValue.startsWith(MULTIPART_PREFIX)) {
    const result = await state.backupReassembler.accept(rawValue);
    if (result.status === "progress") {
      setStatus(`Scanning backup… frame ${result.received}/${result.total}`);
      return false;
    }
    if (result.status === "error") {
      setStatus(`Backup QR error: ${result.error}. Keep aiming at the frames.`, "warning");
      state.backupReassembler = createMultipartReassembler();
      return false;
    }
    if (result.status === "complete") {
      state.pendingQrPackage = validateEnrollmentPackage(JSON.parse(utf8Decode(result.bytes)));
      stopQrScanner();
      setStatus("Backup scanned. Tap Enroll QR to finish with WebAuthn.");
      return true;
    }
    return false;
  }

  state.pendingQrPackage = parseEnrollmentPackageText(rawValue);
  stopQrScanner();
  setStatus("QR scanned. Tap Enroll QR to finish with WebAuthn.");
  return true;
}

function parseMigrationStepUpPayload(rawValue) {
  let parsed;
  try {
    parsed = JSON.parse(rawValue);
  } catch {
    return null;
  }
  if (parsed?.v !== "migration_step_up_v1") {
    return null;
  }
  const required = [
    "migration_id", "approver_id", "device_id", "share_index", "key_id",
    "new_credential_id", "new_public_key_spki_base64url", "challenge_nonce", "challenge_nonce_expires_at"
  ];
  for (const field of required) {
    if (parsed[field] === undefined || parsed[field] === null || parsed[field] === "") {
      return null;
    }
  }
  return parsed;
}

async function openScanner(mode) {
  state.qrScanMode = mode;
  state.pendingQrPackage = null;
  state.backupReassembler = createMultipartReassembler();
  renderQrEnrollment();
  const detector = await createQrDetector();
  state.qrStream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: { facingMode: { ideal: "environment" } }
  });
  // Reveal the viewfinder BEFORE attaching the stream and calling play():
  // mobile browsers stall or reject play() on a still-hidden (display:none)
  // <video>, which previously left the camera live with no visible preview.
  renderQrEnrollment();
  els.qrVideo.srcObject = state.qrStream;
  try {
    await els.qrVideo.play();
  } catch {
    // autoplay + muted + playsinline restart playback on their own; a rejected
    // play() (common right after the element is revealed) must not abort scanning.
  }
  setStatus(mode === "migration-confirm"
    ? "Scan the new device's migration code"
    : "Scanning enrollment QR");
  scanQrFrame(detector);
}

async function startQrEnrollment() {
  await openScanner("enroll");
}

async function startConfirmDeviceScan() {
  if (!state.phoneSharePackage || !state.webauthnCredential?.credential_id) {
    throw new Error("Enroll this device before confirming another");
  }
  await openScanner("migration-confirm");
}

async function finishQrEnrollment() {
  if (!state.pendingQrPackage) {
    throw new Error("Scan enrollment QR first");
  }
  await enrollFromParsedPackage(state.pendingQrPackage);
}

// A high-entropy (160-bit) recovery code in Crockford base32 (no I/L/O/U) — the
// secret that protects the encrypted backup QR. A backup QR is photographable,
// so a weak user passphrase would be brute-forceable offline despite Argon2id;
// a generated code removes that risk. Shown once for the user to store.
function generateRecoveryCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += RECOVERY_CODE_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out;
}

function showQrModal({ title, text, secret = "" }) {
  els.qrModalTitle.textContent = title;
  els.qrModalText.textContent = text;
  if (secret) {
    els.qrModalSecretValue.textContent = secret;
    els.qrModalSecret.classList.remove("hidden");
  } else {
    els.qrModalSecretValue.textContent = "-";
    els.qrModalSecret.classList.add("hidden");
  }
  els.qrModal.classList.remove("hidden");
}

function hideQrModal() {
  stopQrAnimation();
  els.qrModal.classList.add("hidden");
}

function stopQrAnimation() {
  if (state.qrAnimTimer) {
    clearInterval(state.qrAnimTimer);
    state.qrAnimTimer = 0;
  }
  state.qrFrames = [];
  state.qrFrameIndex = 0;
}

// Renders one or more QR frames into the modal canvas. Multi-part backups cycle
// (animate) so a phone-to-phone scan can collect every frame; a single frame
// (the migration step-up) just renders once.
function startQrAnimation(frames) {
  stopQrAnimation();
  state.qrFrames = frames;
  state.qrFrameIndex = 0;
  const draw = () => {
    const frame = state.qrFrames[state.qrFrameIndex];
    const matrix = encodeQrMatrix(utf8Encode(frame), { ecLevel: "M" });
    renderQrToCanvas(matrix, els.qrCanvas, { moduleSize: 4 });
    els.qrModalFrame.textContent = `Frame ${state.qrFrameIndex + 1} / ${state.qrFrames.length}`;
    els.qrModalFrame.classList.toggle("hidden", state.qrFrames.length <= 1);
    state.qrFrameIndex = (state.qrFrameIndex + 1) % state.qrFrames.length;
  };
  draw();
  if (frames.length > 1) {
    state.qrAnimTimer = setInterval(draw, QR_ANIM_INTERVAL_MS);
  }
}

async function copyRecoveryCode() {
  const code = els.qrModalSecretValue.textContent ?? "";
  try {
    await navigator.clipboard.writeText(code);
    setStatus("Recovery code copied");
  } catch {
    setStatus("Copy failed — select and copy the code manually", "warning");
  }
}

// Feature A: create an encrypted backup of this device's phone share and render
// it as a multi-part (animated) QR for a second device to scan. The share must
// be unlocked in memory first (PRF/UV ceremony) before it can be re-encrypted.
async function createAndExportBackup() {
  if (needsShareUnlock()) {
    await unlockPrfShare();
  }
  if (!state.phoneSharePackage) {
    throw new Error("Unlock your share before creating a backup");
  }
  const recoveryCode = generateRecoveryCode();
  setStatus("Encrypting backup (Argon2id, this can take a few seconds)…");
  const payload = await encryptBackupQrV1({
    share: state.phoneSharePackage,
    passphrase: recoveryCode,
    createdAt: new Date().toISOString()
  });
  const frames = await frameMultipartPayload(utf8Encode(JSON.stringify(payload)));
  showQrModal({
    title: "Encrypted backup",
    text: `On the other device tap "Scan QR" and hold it over this screen until all ${frames.length} frames are captured. Store the recovery code below — it is required to restore and is shown only once.`,
    secret: recoveryCode
  });
  startQrAnimation(frames);
  setStatus("Backup ready — scan all frames on the other device");
}

// Feature B (new phone): ask the backend to register this device's freshly minted
// passkey for the already-enrolled context. The backend stores it as PENDING and
// returns a step-up nonce; this device shows a step-up QR for the OLD phone to
// confirm, then polls until an operator approves.
async function startMigration() {
  const pkg = state.phoneSharePackage;
  const credential = state.webauthnCredential;
  if (!pkg || !credential?.credential_id) {
    throw new Error("Enroll this device before requesting migration");
  }
  if (!credential.public_key_spki_base64url || !Number.isInteger(credential.public_key_alg) || !credential.rp_id) {
    throw new Error("This device's passkey is missing its public key; reset and re-enroll");
  }
  if (!state.backendOrigin) {
    throw new Error("Configure the backend before requesting migration");
  }
  setStatus("Requesting device migration…");
  const result = await requestMigration({
    version: "migration_request_v1",
    new_credential_id: credential.credential_id,
    new_public_key_spki_base64url: credential.public_key_spki_base64url,
    alg: credential.public_key_alg,
    rp_id: credential.rp_id,
    allowed_origins: [window.location.origin]
  }, pkg, state.backendOrigin);
  state.pendingMigrationId = result.migration_id;
  const stepUpPayload = {
    v: "migration_step_up_v1",
    migration_id: result.migration_id,
    approver_id: pkg.approver_id,
    device_id: pkg.device_id,
    share_index: pkg.share_index,
    key_id: pkg.key_id,
    new_credential_id: credential.credential_id,
    new_public_key_spki_base64url: credential.public_key_spki_base64url,
    challenge_nonce: result.challenge_nonce,
    challenge_nonce_expires_at: result.challenge_nonce_expires_at
  };
  showQrModal({
    title: "Confirm on your old device",
    text: "On your OLD phone open Settings → Confirm New Device and scan this code. Then an operator must approve the migration on the backend."
  });
  startQrAnimation([JSON.stringify(stepUpPayload)]);
  pollMigrationUntilResolved(result.migration_id);
}

function stopMigrationPoll() {
  state.migrationPollActive = false;
  if (state.migrationPollTimer) {
    clearTimeout(state.migrationPollTimer);
    state.migrationPollTimer = 0;
  }
}

function pollMigrationUntilResolved(migrationId) {
  stopMigrationPoll();
  state.migrationPollActive = true;
  const tick = async () => {
    if (!state.migrationPollActive || state.pendingMigrationId !== migrationId) {
      return;
    }
    try {
      const status = await pollMigration(migrationId, state.phoneSharePackage, state.backendOrigin);
      if (status.status === "approved") {
        stopMigrationPoll();
        state.migrationRequired = false;
        state.pendingMigrationId = "";
        hideQrModal();
        setStatus("Migration approved — this device is now active.");
        renderEnrollment();
        pollPendingBundles({ queueIfBusy: true });
        return;
      }
      if (status.status === "rejected" || status.status === "not_found") {
        stopMigrationPoll();
        setStatus(`Migration ${status.status}.`, "warning");
        renderEnrollment();
        return;
      }
      els.qrModalText.textContent = status.status === "awaiting_approval"
        ? "Old device confirmed. Waiting for operator approval on the backend…"
        : "Waiting for your old device to confirm…";
    } catch {
      // Transient (offline / nonce churn) — keep polling.
    }
    if (state.migrationPollActive && state.pendingMigrationId === migrationId) {
      state.migrationPollTimer = setTimeout(tick, MIGRATION_POLL_INTERVAL_MS);
    }
  };
  tick();
}

// Feature B (old phone): confirm a new device by signing the step-up challenge
// with THIS device's existing passkey, proving the second factor. The backend
// recomputes the same challenge from its stored record and verifies it.
async function confirmDeviceFromPayload(payload) {
  const pkg = state.phoneSharePackage;
  const credential = state.webauthnCredential;
  if (!pkg || !credential?.credential_id) {
    throw new Error("This device is not enrolled");
  }
  if (!state.backendOrigin) {
    throw new Error("Configure the backend before confirming a device");
  }
  // Validate the scanned request locally BEFORE prompting WebAuthn: a tampered or
  // foreign QR would otherwise burn the single-use step-up nonce on a doomed
  // assertion (leaving the real request stuck) and pop a confusing passkey prompt.
  if (!/^mig-[A-Za-z0-9_-]+$/u.test(payload.migration_id)) {
    throw new Error("Scanned code is not a valid migration request");
  }
  if (
    payload.approver_id !== pkg.approver_id ||
    payload.device_id !== pkg.device_id ||
    payload.share_index !== pkg.share_index ||
    payload.key_id !== pkg.key_id
  ) {
    throw new Error("Scanned code is for a different approver context");
  }
  setStatus("Confirming the new device with your passkey…");
  const challengeBytes = await webauthnEnrollmentStepUpChallengeV1({
    approver_id: payload.approver_id,
    device_id: payload.device_id,
    share_index: payload.share_index,
    key_id: payload.key_id,
    new_credential_id: payload.new_credential_id,
    new_public_key_spki_base64url: payload.new_public_key_spki_base64url,
    challenge_nonce: payload.challenge_nonce,
    challenge_nonce_expires_at: payload.challenge_nonce_expires_at
  });
  const assertion = await requestApprovalAssertion({
    credentialId: credential.credential_id,
    challengeBytes
  });
  await attestMigration(payload.migration_id, {
    version: "migration_attest_v1",
    step_up_assertion: assertion
  }, pkg, state.backendOrigin);
  setStatus("New device confirmed. An operator must now approve the migration on the backend.");
}

async function resetEnrollment() {
  if (!state.resetArmed) {
    armReset();
    return;
  }

  clearResetArming();
  await authorizeEnrollmentReset();
  clearPollTimer();
  await clearEnrollment();
  state.phoneSharePackage = null;
  state.webauthnCredential = null;
  state.backendOrigin = "";
  state.pendingBundles = [];
  state.selectedBundleId = "";
  state.bundle = null;
  state.lastApprovalResult = null;
  state.recentApprovals = [];
  state.selectedApprovalId = "";
  state.pendingQrPackage = null;
  state.shareStorageRequiresPrfUnlock = false;
  state.backendOriginRequiresPrfUnlock = false;
  state.prfWrapKey = null;
  state.prfSaltBase64url = "";
  state.approvedBundleIds.clear();
  stopMigrationPoll();
  state.migrationRequired = false;
  state.pendingMigrationId = "";
  stopQrScanner();
  renderEnrollment();
  renderRecentApprovals();
  renderBundleQueue();
  sendKernelState();
  setStatus("Enrollment reset");
}

function clearPollTimer() {
  if (state.pollTimer) {
    clearTimeout(state.pollTimer);
    state.pollTimer = 0;
  }
}

function schedulePendingBundlePoll(delay = POLL_INTERVAL_MS) {
  clearPollTimer();
  if (!state.phoneSharePackage || !state.backendOrigin) {
    return;
  }
  state.pollTimer = setTimeout(() => {
    pollPendingBundles();
  }, delay);
}

async function pollPendingBundles(options = {}) {
  if (state.pollInFlight) {
    if (options.queueIfBusy) {
      state.pollQueued = true;
    }
    return;
  }
  clearPollTimer();
  if (!state.phoneSharePackage) {
    state.pendingBundles = [];
    state.selectedBundleId = "";
    state.bundle = null;
    state.recentApprovals = [];
    state.selectedApprovalId = "";
    renderRecentApprovals();
    renderBundleQueue();
    sendKernelState();
    if (needsShareUnlock()) {
      if (state.activeView !== "history") {
        showView("approval");
      }
      setStatus("Unlock share to check approvals", "warning");
    } else {
      setStatus("Enroll device in Settings to check approvals", "warning");
    }
    return;
  }
  if (!state.backendOrigin) {
    state.pendingBundles = [];
    state.selectedBundleId = "";
    state.bundle = null;
    state.recentApprovals = [];
    state.selectedApprovalId = "";
    renderRecentApprovals();
    renderBundleQueue();
    sendKernelState();
    setStatus("Set backend URL in Settings to check approvals", "warning");
    return;
  }

  state.pollInFlight = true;
  const pollShare = state.phoneSharePackage;
  const pollBackendOrigin = state.backendOrigin;
  try {
    if (!state.bundle) {
      setStatus("Checking for approvals");
    }
    const [bundles, recentApprovals] = await Promise.all([
      fetchPendingBundles(pollShare, pollBackendOrigin),
      fetchRecentApprovals(pollShare, pollBackendOrigin)
    ]);
    if (state.phoneSharePackage !== pollShare || state.backendOrigin !== pollBackendOrigin) {
      return;
    }
    state.recentApprovals = recentApprovals;
    renderRecentApprovals();
    const pendingBundles = bundles.filter((bundle) => !state.approvedBundleIds.has(bundle.bundle_id));
    state.pendingBundles = pendingBundles;
    const selectedStillPending = pendingBundles.some((bundle) => bundle.bundle_id === state.selectedBundleId);
    const nextBundle = selectedStillPending
      ? pendingBundles.find((bundle) => bundle.bundle_id === state.selectedBundleId)
      : pendingBundles[0];

    if (!nextBundle) {
      state.pendingBundles = [];
      state.selectedBundleId = "";
      state.bundle = null;
      renderBundleQueue();
      sendKernelState();
      setStatus("No pending approvals");
      return;
    }

    selectPendingBundle(nextBundle.bundle_id);
    setStatus(pendingBundles.length > 1 ? `${pendingBundles.length} bundles ready for review` : "Bundle ready for review");
  } catch (error) {
    setStatus(`Approval polling failed: ${error.message}`, "error");
  } finally {
    state.pollInFlight = false;
    if (state.pollQueued) {
      state.pollQueued = false;
      pollPendingBundles();
    } else {
      schedulePendingBundlePoll();
    }
  }
}

async function init() {
  window.addEventListener("message", handleKernelMessage);
  window.addEventListener("popstate", () => showView(routeFromLocation()));
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      handleAppHidden();
    } else if (document.visibilityState === "visible") {
      queueAutoUnlock();
    }
  });
  window.addEventListener("pagehide", handleAppHidden);
  els.kernelFrame.src = kernelFrameUrl();
  els.homeButton.addEventListener("click", () => showView("approval", { history: "push" }));
  els.historyButton.addEventListener("click", () => toggleView("history"));
  els.settingsButton.addEventListener("click", () => toggleView("settings"));
  els.enrollmentFile.addEventListener("change", () => enrollFromPackageFile(els.enrollmentFile.files[0]).catch((error) => {
    setStatus(error.message, "error");
  }));
  els.scanEnrollmentButton.addEventListener("click", () => startQrEnrollment().catch((error) => {
    stopQrScanner();
    setStatus(error.message, "error");
  }));
  els.finishQrEnrollmentButton.addEventListener("click", () => finishQrEnrollment().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.cancelQrScanButton.addEventListener("click", () => stopQrScanner("QR scan cancelled"));
  els.createBackupButton.addEventListener("click", () => createAndExportBackup().catch((error) => {
    hideQrModal();
    setStatus(error.message, "error");
  }));
  els.startMigrationButton.addEventListener("click", () => startMigration().catch((error) => {
    hideQrModal();
    setStatus(error.message, "error");
  }));
  els.confirmDeviceButton.addEventListener("click", () => startConfirmDeviceScan().catch((error) => {
    stopQrScanner();
    setStatus(error.message, "error");
  }));
  els.qrModalClose.addEventListener("click", () => hideQrModal());
  els.qrModalSecretCopy.addEventListener("click", () => copyRecoveryCode());
  els.unlockShareButton.addEventListener("click", () => unlockPrfShare().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.unlockGateButton.addEventListener("click", () => unlockFromLockedView());
  els.historyUnlockGateButton.addEventListener("click", () => unlockFromLockedView());
  els.enablePrfButton.addEventListener("click", () => enablePrfStorage().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.resetButton.addEventListener("click", () => resetEnrollment().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.saveBackendButton.addEventListener("click", () => saveBackendFromSettings().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.activityDetailClose.addEventListener("click", () => {
    state.selectedApprovalId = "";
    renderRecentApprovals();
  });
  els.runtimeStatus.addEventListener("click", showStatusModal);
  els.statusModalClose.addEventListener("click", hideStatusModal);
  els.statusModal.addEventListener("click", (event) => {
    if (event.target === els.statusModal) {
      hideStatusModal();
    }
  });
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !els.statusModal.classList.contains("hidden")) {
      hideStatusModal();
    }
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./service-worker.js", { type: "module" }).catch(() => {});
  }

  // Issue #26: gate every local-AES share unwrap behind a WebAuthn UV ceremony.
  setLocalShareUnlockVerifier(verifyLocalShareUnlock);

  let persistent = await isStoragePersisted().catch(() => false);
  if (!persistent) {
    persistent = await requestPersistentStorage().catch(() => false);
  }
  state.storagePersistent = persistent;

  // Issue #10: verify the full app-controlled graph (HTML + renderer/controller
  // + crypto), not only the signing sub-graph, before trusting the app. This
  // FAILS CLOSED: on any integrity failure we abort init before loading key
  // material, polling, or signing. (The SRI-pinned bootstrap.js is the primary
  // verify-before-import gate; this is the same enforcement if app.js is ever
  // reached without it.)
  try {
    state.integrityManifest = await loadIntegrityManifest();
    await assertAppIntegrity(state.integrityManifest);
  } catch (error) {
    state.integrityError = error;
    state.integrityManifest = null;
    renderEnrollment();
    setStatus(`App integrity check failed: ${error.message}`, "error");
    throw error; // fail closed: do not load key material, poll, or sign
  }
  state.shareStorageRequiresPrfUnlock = await phoneSharePackageRequiresPrfUnlock().catch(() => false);
  state.webauthnCredential = await loadWebAuthnCredential({
    publicOnly: state.shareStorageRequiresPrfUnlock
  }).catch(() => null);
  state.backendOriginRequiresPrfUnlock = await backendOriginRequiresPrfUnlock().catch(() => false);
  state.phoneSharePackage = state.shareStorageRequiresPrfUnlock ? null : await loadPhoneSharePackage().catch(() => null);
  state.backendOrigin = state.shareStorageRequiresPrfUnlock || state.backendOriginRequiresPrfUnlock ? "" : await loadBackendOrigin().catch(() => "");
  renderEnrollment();
  renderRecentApprovals();
  sendKernelState();
  showView(routeFromLocation(), { history: "replace" });
  await pollPendingBundles();
}

init().catch((error) => {
  setStatus(error.message, "error");
});
