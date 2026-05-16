import { fetchDemoBundle, fetchTestPhoneSharePackage, submitDemoApproval } from "./api-client.js";
import { amountMinorToDecimal, deriveVisiblePaymentFromInput } from "../../prod/src/payment-view.js";
import {
  clearEnrollment,
  isStoragePersisted,
  loadPhoneSharePackage,
  loadWebAuthnCredential,
  requestPersistentStorage,
  savePhoneSharePackage,
  saveWebAuthnCredential
} from "../../prod/src/storage.js";
import { createApprovalCredential, isWebAuthnAvailable, requestApprovalAssertion } from "../../prod/src/webauthn.js";
import { validateBundleForApprovalV1, webauthnApprovalChallengeV1 } from "../../prod/src/core/protocol/envelopes.js";

const RESET_CONFIRM_MS = 10000;

const els = {
  runtimeStatus: document.querySelector("#runtimeStatus"),
  approvalView: document.querySelector("#approvalView"),
  historyView: document.querySelector("#historyView"),
  settingsView: document.querySelector("#settingsView"),
  historyButton: document.querySelector("#historyButton"),
  settingsButton: document.querySelector("#settingsButton"),
  deviceBadge: document.querySelector("#deviceBadge"),
  approverValue: document.querySelector("#approverValue"),
  deviceValue: document.querySelector("#deviceValue"),
  shareValue: document.querySelector("#shareValue"),
  keyValue: document.querySelector("#keyValue"),
  webauthnValue: document.querySelector("#webauthnValue"),
  storageValue: document.querySelector("#storageValue"),
  enrollDemoButton: document.querySelector("#enrollDemoButton"),
  resetButton: document.querySelector("#resetButton"),
  paymentCountInput: document.querySelector("#paymentCountInput"),
  loadBundleButton: document.querySelector("#loadBundleButton"),
  approveButton: document.querySelector("#approveButton"),
  bundleSummary: document.querySelector("#bundleSummary"),
  bundleCountValue: document.querySelector("#bundleCountValue"),
  totalsStrip: document.querySelector("#totalsStrip"),
  paymentRows: document.querySelector("#paymentRows"),
  signProgress: document.querySelector("#signProgress"),
  resultPanel: document.querySelector("#resultPanel"),
  resultTitle: document.querySelector("#resultTitle"),
  resultDetail: document.querySelector("#resultDetail"),
  recentCount: document.querySelector("#recentCount"),
  recentApprovals: document.querySelector("#recentApprovals"),
  activityDetail: document.querySelector("#activityDetail"),
  activityDetailTitle: document.querySelector("#activityDetailTitle"),
  activityDetailApprover: document.querySelector("#activityDetailApprover"),
  activityDetailSummary: document.querySelector("#activityDetailSummary"),
  activityDetailRows: document.querySelector("#activityDetailRows"),
  activityDetailTableWrap: document.querySelector("#activityDetailTableWrap"),
  activityDetailClose: document.querySelector("#activityDetailClose"),
  approvalOutput: document.querySelector("#approvalOutput")
};

const state = {
  phoneSharePackage: null,
  webauthnCredential: null,
  storagePersistent: null,
  bundle: null,
  lastApprovalResult: null,
  recentApprovals: [],
  selectedApprovalId: "",
  approvedBundleIds: new Set(),
  activeView: "approval",
  resetArmed: false,
  resetTimer: 0,
  signatures: []
};

function setStatus(message, level = "normal") {
  els.runtimeStatus.textContent = message;
  els.runtimeStatus.className = level === "error" ? "status-line error" : level === "warning" ? "status-line warning" : "status-line";
}

function setStatusWithRetry(message, onRetry, level = "warning") {
  els.runtimeStatus.replaceChildren(document.createTextNode(`${message} `));
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Try again";
  button.style.cssText = "background:transparent;border:1px solid currentColor;color:inherit;border-radius:4px;padding:0 0.5em;margin-left:0.25em;font:inherit;cursor:pointer;";
  button.addEventListener("click", () => {
    onRetry().catch((error) => setStatus(error.message, "error"));
  });
  els.runtimeStatus.append(button);
  els.runtimeStatus.className = level === "error" ? "status-line error" : level === "warning" ? "status-line warning" : "status-line";
}

async function retryPersistence() {
  const persistent = await requestPersistentStorage();
  state.storagePersistent = persistent;
  renderStorage();
  if (persistent) {
    setStatus("Ready. Storage marked durable.");
    return;
  }
  setStatusWithRetry(
    "Ready. Browser still won't mark storage as durable — data is unlikely to be lost but may be evicted under low storage. For stronger durability install via Chrome.",
    retryPersistence
  );
}

function renderStorage() {
  els.storageValue.textContent = state.storagePersistent === null
    ? "Checking"
    : state.storagePersistent
      ? "Persistent"
      : "Not persistent";
}

function writeOutput(value) {
  els.approvalOutput.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
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

function setResult(result) {
  state.lastApprovalResult = result;
  if (!result) {
    els.resultPanel.className = "result-panel hidden";
    els.resultTitle.textContent = "-";
    els.resultDetail.textContent = "-";
    return;
  }
  els.resultPanel.className = `result-panel result-${result.status ?? "normal"}`;
  els.resultTitle.textContent = result.title ?? "Approval result";
  els.resultDetail.textContent = result.detail ?? "";
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

function outputBundleContext(extra = {}) {
  if (!state.bundle) {
    return extra;
  }

  return {
    bundle: state.bundle,
    ...extra
  };
}

function renderEnrollment() {
  const pkg = state.phoneSharePackage;
  const credential = state.webauthnCredential;
  const enrolled = Boolean(pkg);

  els.deviceBadge.textContent = enrolled ? "Enrolled" : "Not enrolled";
  els.deviceBadge.className = `badge ${enrolled ? "badge-ok" : "badge-muted"}`;
  els.approverValue.textContent = pkg?.approver_id ?? "-";
  els.deviceValue.textContent = pkg?.device_id ?? "-";
  els.shareValue.textContent = pkg ? `${pkg.share_index} of ${pkg.players}, threshold ${pkg.threshold}` : "-";
  els.keyValue.textContent = pkg?.key_id ?? "-";
  els.webauthnValue.textContent = credential ? "Registered" : enrolled ? "Pending" : "-";
  renderStorage();
  renderApprovalState();
}

function renderBundle() {
  const bundle = state.bundle;
  els.paymentRows.replaceChildren();
  els.totalsStrip.replaceChildren();

  if (!bundle) {
    els.bundleSummary.textContent = "No bundle loaded";
    els.bundleCountValue.textContent = "-";
    els.paymentRows.append(emptyRow());
    els.signProgress.max = 1;
    els.signProgress.value = 0;
    renderApprovalState();
    return;
  }

  els.bundleSummary.textContent = `${bundle.payment_inputs.length} transactions ready for review`;
  els.bundleCountValue.textContent = String(bundle.payment_inputs.length);
  for (const total of bundle.totals) {
    const pill = document.createElement("div");
    pill.className = "total-pill";
    const label = document.createElement("span");
    label.className = "total-currency";
    label.textContent = total.currency;
    const amount = document.createElement("strong");
    amount.textContent = amountMinorToDecimal(total.amount_minor, total.currency).replace(` ${total.currency}`, "");
    pill.append(label, amount);
    els.totalsStrip.append(pill);
  }

  for (const input of bundle.payment_inputs) {
    const payment = deriveVisiblePaymentFromInput(input);
    const row = document.createElement("tr");
    row.append(
      cell(payment.creditor_account),
      cell(payment.remittance_text || "-"),
      cell(amountMinorToDecimal(payment.amount_minor, payment.currency), "numeric")
    );
    els.paymentRows.append(row);
  }

  els.signProgress.max = bundle.payment_inputs.length;
  els.signProgress.value = 0;
  renderApprovalState();
}

function renderRecentApprovals() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  state.recentApprovals = state.recentApprovals
    .filter((approval) => Date.parse(approval.received_at) >= cutoff)
    .sort((left, right) => Date.parse(right.received_at) - Date.parse(left.received_at));
  if (state.selectedApprovalId && !state.recentApprovals.some((approval) => approval.bundle_id === state.selectedApprovalId)) {
    state.selectedApprovalId = "";
  }
  els.historyView.classList.toggle("history-detail-open", Boolean(state.selectedApprovalId));
  els.recentCount.textContent = String(state.recentApprovals.length);
  els.recentApprovals.replaceChildren();

  if (state.recentApprovals.length === 0) {
    const empty = document.createElement("div");
    empty.className = "activity-empty";
    empty.textContent = "No approvals in the last 24 hours";
    els.recentApprovals.append(empty);
    renderActivityDetail();
    return;
  }

  for (const approval of state.recentApprovals.slice(0, 20)) {
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
      cellSpan(approvalApproverText(approval), "activity-approver"),
      cellSpan(totalText(approval.totals) || "-", "activity-total")
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
  renderPaymentRows(els.activityDetailRows, visiblePaymentsFromApproval(approval), "Payment details unavailable");
}

function renderApprovalState() {
  const approved = currentBundleApproved();
  const canApprove = Boolean(state.phoneSharePackage && state.webauthnCredential && state.bundle);
  els.approveButton.disabled = approved || !canApprove;
  els.approveButton.textContent = approved ? "Approved" : "Approve";
}

function currentBundleApproved() {
  return Boolean(state.bundle && state.approvedBundleIds.has(state.bundle.bundle_id));
}

function emptyRow() {
  const row = document.createElement("tr");
  const value = document.createElement("td");
  value.colSpan = 3;
  value.className = "empty-state";
  value.textContent = "-";
  row.append(value);
  return row;
}

function renderPaymentRows(target, payments, emptyText = "-") {
  target.replaceChildren();
  if (payments.length === 0) {
    const row = emptyRow();
    row.firstElementChild.textContent = emptyText;
    target.append(row);
    return;
  }

  for (const payment of payments) {
    const row = document.createElement("tr");
    row.append(
      cell(payment.creditor_account || "-"),
      cell(payment.remittance_text || "-"),
      cell(amountMinorToDecimal(payment.amount_minor, payment.currency), "numeric")
    );
    target.append(row);
  }
}

function visiblePaymentsFromBundle(bundle) {
  return bundle.payment_inputs.map((input) => {
    const payment = deriveVisiblePaymentFromInput(input);
    return {
      creditor_account: payment.creditor_account,
      remittance_text: payment.remittance_text ?? "",
      amount_minor: payment.amount_minor,
      currency: payment.currency
    };
  });
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

function cell(text, className = "") {
  const value = document.createElement("td");
  value.textContent = text;
  if (className) {
    value.className = className;
  }
  return value;
}

function cellSpan(text, className = "") {
  const value = document.createElement("span");
  value.textContent = text;
  if (className) {
    value.className = className;
  }
  return value;
}

async function enrollDemoDevice() {
  const pkg = await fetchTestPhoneSharePackage();
  await savePhoneSharePackage(pkg);
  state.phoneSharePackage = pkg;
  renderEnrollment();
  setStatus("Test PKI share enrolled");

  if (!isWebAuthnAvailable()) {
    state.webauthnCredential = null;
    renderEnrollment();
    setStatus("Test PKI share enrolled. WebAuthn is unavailable in this browser.", "warning");
    return;
  }

  try {
    const credential = await createApprovalCredential({
      approverId: pkg.approver_id,
      deviceId: pkg.device_id
    });
    await saveWebAuthnCredential(credential);
    state.webauthnCredential = credential;
    renderEnrollment();
    setStatus("Test PKI device enrolled");
  } catch (error) {
    state.webauthnCredential = null;
    renderEnrollment();
    setStatus(`Test PKI share enrolled. WebAuthn registration failed: ${error.message}`, "warning");
  }
}

async function resetDevice() {
  if (!state.resetArmed) {
    armReset();
    return;
  }

  clearResetArming();
  await authorizeEnrollmentReset();
  await clearEnrollment();
  state.phoneSharePackage = null;
  state.webauthnCredential = null;
  state.signatures = [];
  writeOutput("");
  setResult(null);
  renderEnrollment();
  renderRecentApprovals();
  setStatus("Enrollment reset");
}

async function loadDemoBundle() {
  const count = Number.parseInt(els.paymentCountInput.value, 10);
  state.bundle = await fetchDemoBundle(count);
  await validateBundleForApprovalV1(state.bundle);
  state.signatures = [];
  writeOutput(outputBundleContext({
    note: "Full bundle JSON. Every payment_input below is included in the signing set."
  }));
  renderBundle();
  setStatus("Demo bundle loaded");
}

async function approveBundle() {
  if (!state.phoneSharePackage || !state.webauthnCredential || !state.bundle || currentBundleApproved()) {
    return;
  }

  els.approveButton.disabled = true;
  els.signProgress.value = 0;
  setStatus("Waiting for biometric approval");
  writeOutput("");

  const challengeBytes = await webauthnApprovalChallengeV1({
    bundle_id: state.bundle.bundle_id,
    bundle_hash_sha256: state.bundle.bundle_hash_sha256,
    payment_count: state.bundle.payment_inputs.length,
    approver_id: state.phoneSharePackage.approver_id,
    device_id: state.phoneSharePackage.device_id,
    share_index: state.phoneSharePackage.share_index,
    key_id: state.phoneSharePackage.key_id,
    credential_id: state.webauthnCredential.credential_id
  });
  const assertion = await requestApprovalAssertion({
    credentialId: state.webauthnCredential.credential_id,
    challengeBytes
  }).catch((error) => {
    throw new Error(`WebAuthn approval failed: ${error.message}`);
  });

  setStatus("Signing payment inputs");
  const signatures = await signInWorker({
    phoneSharePackage: state.phoneSharePackage,
    paymentInputs: state.bundle.payment_inputs
  });

  state.signatures = signatures;
  const approval = {
    version: "bundle_approval_v1",
    bundle_id: state.bundle.bundle_id,
    bundle_hash_sha256: state.bundle.bundle_hash_sha256,
    approver_id: state.phoneSharePackage.approver_id,
    device_id: state.phoneSharePackage.device_id,
    share_index: state.phoneSharePackage.share_index,
    key_id: state.phoneSharePackage.key_id,
    payment_count: state.bundle.payment_inputs.length,
    totals: state.bundle.totals,
    bank_request_hashes: state.bundle.bank_request_hashes,
    visible_line_item_hashes: state.bundle.visible_line_item_hashes,
    webauthn_assertion: assertion,
    phone_sign_shares: signatures.map((signature) => signature.sign_share_base64url),
    approved_at: new Date().toISOString()
  };
  let backendResult;
  try {
    backendResult = await submitDemoApproval(approval);
  } catch (error) {
    if (error.status === 409 || error.code === "bundle_already_approved") {
      state.approvedBundleIds.add(state.bundle.bundle_id);
      setResult({
        status: "warning",
        title: "Bundle already approved",
        detail: "This demo bundle was already recorded."
      });
      writeOutput(outputBundleContext({
        error: "bundle_already_approved",
        note: "This bundle was already approved."
      }));
      setStatus("Bundle already approved", "warning");
      renderApprovalState();
      return;
    }
    setResult({
      status: "failed",
      title: "Approval failed",
      detail: error.message
    });
    throw error;
  }
  state.approvedBundleIds.add(state.bundle.bundle_id);
  const activity = {
    bundle_id: state.bundle.bundle_id,
    status: "approved",
    payment_count: state.bundle.payment_inputs.length,
    totals: state.bundle.totals,
    visible_payments: visiblePaymentsFromBundle(state.bundle),
    approver_id: state.phoneSharePackage.approver_id,
    device_id: state.phoneSharePackage.device_id,
    share_index: state.phoneSharePackage.share_index,
    key_id: state.phoneSharePackage.key_id,
    received_at: backendResult.received_at ?? new Date().toISOString()
  };
  state.recentApprovals.unshift(activity);
  setResult({
    status: "approved",
    title: "Bundle approved successfully",
    detail: `${activity.payment_count} transactions · ${totalText(activity.totals)}`
  });
  renderRecentApprovals();
  writeOutput(outputBundleContext({
    approval,
    backend_result: backendResult,
    timing: summarizeDurations(signatures)
  }));
  setStatus("Bundle approved");
  renderApprovalState();
}

function summarizeDurations(signatures) {
  const durations = signatures
    .map((signature) => signature.duration_ms)
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);
  const sum = durations.reduce((total, value) => total + value, 0);
  return {
    count: durations.length,
    total_ms: Math.round(sum),
    average_ms: durations.length ? Math.round(sum / durations.length) : 0,
    p50_ms: percentile(durations, 0.5),
    p95_ms: percentile(durations, 0.95),
    max_ms: durations.at(-1) ?? 0
  };
}

function percentile(values, p) {
  if (values.length === 0) {
    return 0;
  }
  const index = Math.min(values.length - 1, Math.ceil(values.length * p) - 1);
  return Math.round(values[index]);
}

function signInWorker({ phoneSharePackage, paymentInputs }) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("../../prod/src/sign-worker.js", import.meta.url), { type: "module" });
    worker.addEventListener("message", (event) => {
      const message = event.data;
      if (message.type === "progress") {
        els.signProgress.max = message.total;
        els.signProgress.value = message.completed;
        setStatus(`Signed ${message.completed} of ${message.total}`);
      }
      if (message.type === "done") {
        worker.terminate();
        resolve(message.signatures);
      }
      if (message.type === "error") {
        worker.terminate();
        reject(new Error(message.message));
      }
    });
    worker.addEventListener("error", (event) => {
      worker.terminate();
      reject(new Error(event.message));
    });
    worker.postMessage({ phoneSharePackage, paymentInputs });
  });
}

async function init() {
  els.historyButton.addEventListener("click", () => toggleView("history"));
  els.settingsButton.addEventListener("click", () => toggleView("settings"));
  els.enrollDemoButton.addEventListener("click", () => enrollDemoDevice().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.resetButton.addEventListener("click", () => resetDevice().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.loadBundleButton.addEventListener("click", () => loadDemoBundle().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.approveButton.addEventListener("click", () => approveBundle().catch((error) => {
    setStatus(error.message, "error");
    renderApprovalState();
  }));
  els.activityDetailClose.addEventListener("click", () => {
    state.selectedApprovalId = "";
    renderRecentApprovals();
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./service-worker.js").catch(() => {});
  }

  let persistent = await isStoragePersisted().catch(() => false);
  if (!persistent) {
    persistent = await requestPersistentStorage().catch(() => false);
  }
  state.storagePersistent = persistent;
  state.phoneSharePackage = await loadPhoneSharePackage().catch(() => null);
  state.webauthnCredential = await loadWebAuthnCredential().catch(() => null);
  renderEnrollment();
  renderBundle();
  renderRecentApprovals();
  setResult(null);
  showView("approval");
  if (persistent) {
    setStatus("Ready");
  } else {
    setStatusWithRetry(
      "Ready. Browser hasn't marked storage as durable — data is unlikely to be lost but may be evicted under low storage. For stronger durability install via Chrome.",
      retryPersistence
    );
  }
}

init().catch((error) => {
  setStatus(error.message, "error");
});
