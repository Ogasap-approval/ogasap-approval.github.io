import { fetchPendingBundles, fetchRecentApprovals } from "./api-client.js";
import { loadIntegrityManifest } from "./integrity.js";
import { amountMinorToDecimal } from "./payment-view.js";
import {
  clearEnrollment,
  loadBackendOrigin,
  loadPhoneSharePackage,
  loadWebAuthnCredential,
  requestPersistentStorage,
  saveBackendOrigin,
  savePhoneSharePackage,
  saveWebAuthnCredential
} from "./storage.js";
import { createApprovalCredential, isWebAuthnAvailable, requestApprovalAssertion } from "./webauthn.js";

const POLL_INTERVAL_MS = 3000;
const RESET_CONFIRM_MS = 10000;
const ids = [
  "runtimeStatus",
  "approvalView",
  "historyView",
  "settingsView",
  "historyButton",
  "settingsButton",
  "kernelFrame",
  "deviceBadge",
  "approverValue",
  "deviceValue",
  "shareValue",
  "keyValue",
  "webauthnValue",
  "appHashValue",
  "backendOriginInput",
  "saveBackendButton",
  "enrollmentFile",
  "resetButton",
  "recentCount",
  "recentApprovals",
  "activityDetail",
  "activityDetailTitle",
  "activityDetailSummary",
  "activityDetailRows",
  "activityDetailTableWrap",
  "activityDetailClose"
];
const els = Object.fromEntries(ids.map((id) => [id, document.querySelector(`#${id}`)]));
const state = {
  phoneSharePackage: null,
  webauthnCredential: null,
  integrityManifest: null,
  integrityError: null,
  backendOrigin: "",
  bundle: null,
  lastApprovalResult: null,
  recentApprovals: [],
  selectedApprovalId: "",
  approvedBundleIds: new Set(),
  activeView: "approval",
  resetArmed: false,
  resetTimer: 0,
  kernelReady: false,
  pollTimer: 0,
  pollInFlight: false
};

function setStatus(message, level = "normal") {
  els.runtimeStatus.textContent = message;
  els.runtimeStatus.className = level === "error" ? "status-line error" : level === "warning" ? "status-line warning" : "status-line";
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
    meta.append(span(totalText(approval.totals) || "-", "activity-total"));
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
    els.activityDetailSummary.textContent = "Approved last 24h";
    els.activityDetailTableWrap.classList.add("hidden");
    els.activityDetailClose.classList.add("hidden");
    els.activityDetailRows.replaceChildren(emptyRow());
    return;
  }

  els.activityDetail.classList.remove("activity-detail-empty");
  els.activityDetailTitle.textContent = `${approval.payment_count ?? "-"} transactions`;
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

function renderEnrollment() {
  const pkg = state.phoneSharePackage;
  const credential = state.webauthnCredential;
  const enrolled = Boolean(pkg && credential);
  els.deviceBadge.textContent = enrolled ? "Enrolled" : "Not enrolled";
  els.deviceBadge.className = `badge ${enrolled ? "badge-ok" : "badge-muted"}`;
  els.approverValue.textContent = pkg?.approver_id ?? "-";
  els.deviceValue.textContent = pkg?.device_id ?? "-";
  els.shareValue.textContent = pkg ? `${pkg.share_index} of ${pkg.players}, threshold ${pkg.threshold}` : "-";
  els.keyValue.textContent = pkg?.key_id ?? "-";
  els.webauthnValue.textContent = credential ? "Registered" : "-";
  els.backendOriginInput.value = state.backendOrigin;
  renderIntegrity();
  sendKernelState();
}

async function saveBackendFromSettings() {
  const origin = normalizeBackendOrigin(els.backendOriginInput.value.trim());
  await authorizeBackendOriginChange(origin);
  await saveBackendOrigin(origin);
  state.backendOrigin = origin;
  renderEnrollment();
  setStatus("Backend saved");
  pollPendingBundles();
}

async function enrollFromPackageFile(file) {
  if (!file) {
    return;
  }
  if (!isWebAuthnAvailable()) {
    throw new Error("WebAuthn is required on this browser");
  }

  const pkg = JSON.parse(await file.text());
  const credential = await createApprovalCredential({
    approverId: pkg.approver_id,
    deviceId: pkg.device_id
  });
  await savePhoneSharePackage(pkg);
  await saveWebAuthnCredential(credential);
  state.phoneSharePackage = pkg;
  state.webauthnCredential = credential;
  renderEnrollment();
  sendKernelState();
  setStatus("Device enrolled");
  pollPendingBundles();
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
  state.approvedBundleIds.clear();
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
    setStatus("Enroll device in Settings to check approvals", "warning");
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
  try {
    if (!state.bundle) {
      setStatus("Checking for approvals");
    }
    const [bundles, recentApprovals] = await Promise.all([
      fetchPendingBundles(state.phoneSharePackage, state.backendOrigin),
      fetchRecentApprovals(state.phoneSharePackage, state.backendOrigin)
    ]);
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
  els.kernelFrame.src = kernelFrameUrl();
  els.historyButton.addEventListener("click", () => toggleView("history"));
  els.settingsButton.addEventListener("click", () => toggleView("settings"));
  els.enrollmentFile.addEventListener("change", () => enrollFromPackageFile(els.enrollmentFile.files[0]).catch((error) => {
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

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./service-worker.js").catch(() => {});
  }

  await requestPersistentStorage().catch(() => false);

  state.integrityManifest = await loadIntegrityManifest().catch((error) => {
    state.integrityError = error;
    return null;
  });
  state.phoneSharePackage = await loadPhoneSharePackage().catch(() => null);
  state.webauthnCredential = await loadWebAuthnCredential().catch(() => null);
  state.backendOrigin = await loadBackendOrigin().catch(() => "");
  renderEnrollment();
  renderRecentApprovals();
  sendKernelState();
  showView("approval");
  await pollPendingBundles();
}

init().catch((error) => {
  setStatus(error.message, "error");
});
