import { fetchPendingBundles, fetchRecentApprovals } from "./api-client.js";
import { decodePhoneSharePackageV1 } from "./core/protocol/signing.js";
import { loadIntegrityManifest } from "./integrity.js";
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
  saveWebAuthnCredential
} from "./storage.js";
import {
  createApprovalCredential,
  isWebAuthnAvailable,
  prfWrapKeyFromCreationResult,
  randomPrfSaltBase64url,
  requestApprovalAssertion,
  requestPrfWrapKey
} from "./webauthn.js?v=status-modal-v40";

const POLL_INTERVAL_MS = 3000;
const RESET_CONFIRM_MS = 10000;
const QR_SCAN_INTERVAL_MS = 250;
const ids = [
  "runtimeStatus",
  "statusModal",
  "statusModalText",
  "statusModalClose",
  "approvalView",
  "historyView",
  "settingsView",
  "historyButton",
  "settingsButton",
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
  "enrollmentFile",
  "qrScanner",
  "qrVideo",
  "cancelQrScanButton",
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
  pendingQrPackage: null,
  kernelReady: false,
  pollTimer: 0,
  pollInFlight: false,
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
  els.historyUnlockGate.classList.toggle("hidden", !locked);
  els.historyShell.classList.toggle("hidden", locked);
  queueAutoUnlock();
}

function lockPrfSession(message = "App locked") {
  if (!state.shareStorageRequiresPrfUnlock || !state.phoneSharePackage) {
    return false;
  }

  clearPollTimer();
  state.lockGeneration += 1;
  state.autoUnlockInFlight = false;
  state.phoneSharePackage = null;
  state.webauthnCredential = publicCredentialForLockedState();
  state.prfWrapKey = null;
  state.prfSaltBase64url = "";
  if (state.backendOriginRequiresPrfUnlock) {
    state.backendOrigin = "";
  }
  state.bundle = null;
  state.lastApprovalResult = null;
  state.recentApprovals = [];
  state.selectedApprovalId = "";
  stopQrScanner();
  renderEnrollment();
  renderRecentApprovals();
  sendKernelState();
  setStatus(message, "warning");
  return true;
}

function handleAppHidden() {
  if (state.qrStream) {
    stopQrScanner();
  }
  lockPrfSession("App locked");
}

function showView(view) {
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
}

function toggleView(view) {
  showView(state.activeView === view ? "approval" : view);
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

function totalText(totals = []) {
  return totals.map((total) => amountMinorToDecimal(total.amount_minor, total.currency)).join(", ");
}

function shortBundleId(bundleId = "") {
  return bundleId.length > 18 ? `${bundleId.slice(0, 10)}...${bundleId.slice(-6)}` : bundleId;
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
      cell(payment.remittance_text || "-"),
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
    currency: payment?.currency ?? ""
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
    detail.textContent = `${shortBundleId(approval.bundle_id)} · ${timeText(approval.received_at)}`;
    main.append(bundle, detail);

    const meta = document.createElement("div");
    meta.className = "activity-meta";
    meta.append(
      span(approvalApproverText(approval), "activity-approver"),
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
  els.activityDetailSummary.textContent = `${totalText(approval.totals) || "-"} · ${timeText(approval.received_at)} · ${shortBundleId(approval.bundle_id)}`;
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
  } else if (event.data.type === "approved") {
    state.approvedBundleIds.add(event.data.bundle_id);
    state.lastApprovalResult = event.data.result ?? null;
    state.bundle = null;
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
    throw new Error("Encrypted backup QR must be decrypted before enrollment");
  }
  decodePhoneSharePackageV1(pkg);
  return pkg;
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
  pollPendingBundles();
}

function storableCredentialRecord(credential, prfWrap) {
  return {
    credential_id: credential.credential_id,
    type: credential.type,
    created_at: credential.created_at,
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
  pollPendingBundles();
}

async function unlockFromLockedView() {
  const targetView = state.activeView === "history" ? "history" : "approval";
  try {
    await unlockPrfShare();
    showView(targetView);
  } catch (error) {
    setStatus(`Unlock failed: ${error.message}`, "error");
    showView("settings");
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
  pollPendingBundles();
}

async function enrollFromPackageFile(file) {
  if (!file) {
    return;
  }
  await enrollFromPackage(parseEnrollmentPackageText(await file.text()));
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
    if (rawValue) {
      state.pendingQrPackage = parseEnrollmentPackageText(rawValue);
      stopQrScanner();
      renderQrEnrollment();
      setStatus("QR scanned. Tap Enroll QR to finish with WebAuthn.");
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

async function startQrEnrollment() {
  state.pendingQrPackage = null;
  renderQrEnrollment();
  const detector = await createQrDetector();
  state.qrStream = await navigator.mediaDevices.getUserMedia({
    audio: false,
    video: { facingMode: { ideal: "environment" } }
  });
  els.qrVideo.srcObject = state.qrStream;
  await els.qrVideo.play();
  renderQrEnrollment();
  setStatus("Scanning enrollment QR");
  scanQrFrame(detector);
}

async function finishQrEnrollment() {
  if (!state.pendingQrPackage) {
    throw new Error("Scan enrollment QR first");
  }
  await enrollFromPackage(state.pendingQrPackage);
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
  stopQrScanner();
  renderEnrollment();
  renderRecentApprovals();
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

async function pollPendingBundles() {
  if (state.pollInFlight) {
    return;
  }
  clearPollTimer();
  if (!state.phoneSharePackage) {
    state.bundle = null;
    state.recentApprovals = [];
    state.selectedApprovalId = "";
    renderRecentApprovals();
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
    state.bundle = null;
    state.recentApprovals = [];
    state.selectedApprovalId = "";
    renderRecentApprovals();
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
    const nextBundle = bundles.find((bundle) => !state.approvedBundleIds.has(bundle.bundle_id));

    if (!nextBundle) {
      state.bundle = null;
      sendKernelState();
      setStatus("No pending approvals");
      return;
    }

    if (state.bundle?.bundle_id !== nextBundle.bundle_id) {
      state.bundle = nextBundle;
      sendKernelState();
    }
    setStatus("Bundle ready for review");
  } catch (error) {
    setStatus(`Approval polling failed: ${error.message}`, "error");
  } finally {
    state.pollInFlight = false;
    schedulePendingBundlePoll();
  }
}

async function init() {
  window.addEventListener("message", handleKernelMessage);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      handleAppHidden();
    } else if (document.visibilityState === "visible") {
      queueAutoUnlock();
    }
  });
  window.addEventListener("pagehide", handleAppHidden);
  els.kernelFrame.src = kernelFrameUrl();
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
    navigator.serviceWorker.register("./service-worker.js").catch(() => {});
  }

  let persistent = await isStoragePersisted().catch(() => false);
  if (!persistent) {
    persistent = await requestPersistentStorage().catch(() => false);
  }
  state.storagePersistent = persistent;

  state.integrityManifest = await loadIntegrityManifest().catch((error) => {
    state.integrityError = error;
    return null;
  });
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
  showView("approval");
  await pollPendingBundles();
}

init().catch((error) => {
  setStatus(error.message, "error");
});
