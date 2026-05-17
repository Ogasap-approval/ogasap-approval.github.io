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
  homeButton: document.querySelector("#homeButton"),
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
  approvalBusy: false,
  approvalProgress: null,
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

function initialPrfReason(credential) {
  if (credential.prf_creation_result_available) {
    return "PRF creation result ignored by demo";
  }
  if (credential.prf_creation_enabled) {
    return "No PRF result returned at registration";
  }
  return "PRF extension not enabled at registration";
}

function writeOutput(value) {
  els.approvalOutput.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function totalText(totals = []) {
  return totals.map((total) => amountMinorToDecimal(total.amount_minor, total.currency)).join(", ");
}

function bankSubmissionText(submission) {
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
  if (submission.status === "failed") {
    return "Bank failed";
  }
  return `Bank ${submission.status}`;
}

function bankPaymentStatusText(payment) {
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
  if (options.history === "push" || options.history === "replace") {
    setRoute(view, options.history);
  }
}

function toggleView(view) {
  showView(state.activeView === view ? "approval" : view, { history: "push" });
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
    detail.textContent = `Approved ${approvalTimeText(approval)} · ${shortBundleId(approval.bundle_id)}`;
    main.append(bundle, detail);

    const meta = document.createElement("div");
    meta.className = "activity-meta";
    const bankStatus = bankSubmissionText(approval.bank_submission);
    meta.append(
      cellSpan(approvalApproverText(approval), "activity-approver"),
      ...(bankStatus ? [cellSpan(bankStatus, "activity-status")] : []),
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
  els.activityDetailSummary.textContent = [
    totalText(approval.totals) || "-",
    `Approved ${approvalTimeText(approval)}`,
    bankSubmissionText(approval.bank_submission),
    shortBundleId(approval.bundle_id)
  ].filter(Boolean).join(" · ");
  els.activityDetailTableWrap.classList.remove("hidden");
  els.activityDetailClose.classList.remove("hidden");
  renderPaymentRows(els.activityDetailRows, visiblePaymentsFromApproval(approval), "Payment details unavailable");
}

function renderApprovalState() {
  const approved = currentBundleApproved();
  const canApprove = Boolean(state.phoneSharePackage && state.webauthnCredential && state.bundle);
  const showProgress = state.approvalBusy && !approved && state.approvalProgress;
  els.approveButton.classList.toggle("approve-button-progress", Boolean(showProgress));
  if (showProgress) {
    els.approveButton.style.setProperty("--approval-progress", `${boundedPercent(state.approvalProgress)}%`);
    els.approveButton.title = approvalProgressText(state.approvalProgress);
  } else {
    els.approveButton.style.removeProperty("--approval-progress");
    els.approveButton.title = "";
  }
  els.approveButton.disabled = state.approvalBusy || approved || !canApprove;
  els.approveButton.textContent = approved ? "Approved" : showProgress ? approvalProgressText(state.approvalProgress) : "Approve";
}

function currentBundleApproved() {
  return Boolean(state.bundle && state.approvedBundleIds.has(state.bundle.bundle_id));
}

function boundedPercent(progress) {
  const value = Number(progress?.phase_percent ?? progress?.percent ?? progress?.overall_percent ?? 0);
  return Math.max(0, Math.min(100, Number.isFinite(value) ? Math.round(value) : 0));
}

function approvalProgressText(progress) {
  if (!progress) {
    return "Approve";
  }
  if (progress.message) {
    return progress.message;
  }
  const percent = boundedPercent(progress);
  const current = Math.max(1, Math.min(progress.phase_total ?? progress.total ?? 1, progress.current ?? progress.phase_completed ?? 1));
  if (progress.stage === "payments") {
    return `Signing payment ${current}/${progress.phase_total} · ${percent}%`;
  }
  if (progress.stage === "polling") {
    return `Signing later requests ${current}/${progress.phase_total} · ${percent}%`;
  }
  if (progress.stage === "submitting") {
    return "Submitting approval · 100%";
  }
  return `Signing · ${percent}%`;
}

function setApprovalProgress(progress) {
  state.approvalProgress = progress;
  renderApprovalState();
  if (progress) {
    setStatus(approvalProgressText(progress));
  }
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
      paymentTextCell(payment),
      cell(amountMinorToDecimal(payment.amount_minor, payment.currency), "numeric")
    );
    target.append(row);
  }
}

function paymentTextCell(payment) {
  const value = cell(payment.remittance_text || "-");
  const status = bankPaymentStatusText(payment);
  if (status) {
    const detail = document.createElement("span");
    detail.className = "payment-status-line";
    detail.textContent = status;
    value.append(document.createElement("br"), detail);
  }
  return value;
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
    const storedCredential = {
      credential_id: credential.credential_id,
      type: credential.type,
      created_at: credential.created_at,
      resident_key: credential.resident_key === true,
      webauthn_capabilities: credential.webauthn_capabilities ?? {},
      prf_creation_enabled: credential.prf_creation_enabled === true,
      prf_creation_result_available: credential.prf_creation_result_available === true,
      prf_enabled: false,
      prf_salt_base64url: "",
      prf_last_checked_at: "",
      prf_last_error: initialPrfReason(credential)
    };
    await saveWebAuthnCredential(storedCredential);
    state.webauthnCredential = storedCredential;
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

  state.approvalBusy = true;
  state.approvalProgress = null;
  els.approveButton.disabled = true;
  setApprovalProgress({ stage: "webauthn", message: "Confirm WebAuthn", percent: 0 });
  setResult(null);
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
  setApprovalProgress({ stage: "preparing", message: "Preparing signatures", percent: 0 });
  const signatures = await signInWorker({
    phoneSharePackage: state.phoneSharePackage,
    paymentInputs: state.bundle.payment_inputs,
    onProgress: setApprovalProgress
  });

  state.signatures = signatures;
  setApprovalProgress({ stage: "submitting", message: "Submitting approval", percent: 100 });
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
      state.approvalBusy = false;
      state.approvalProgress = null;
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
    received_at: backendResult.received_at ?? new Date().toISOString(),
    bank_submission: backendResult.bank_submission ?? {
      enabled: false,
      status: "disabled",
      payment_count: 0,
      total_payment_count: state.bundle.payment_inputs.length,
      payments: []
    }
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
  state.approvalBusy = false;
  state.approvalProgress = null;
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

function signInWorker({ phoneSharePackage, paymentInputs, onProgress }) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("../../prod/src/sign-worker.js", import.meta.url), { type: "module" });
    worker.addEventListener("message", (event) => {
      const message = event.data;
      if (message.type === "done") {
        worker.terminate();
        resolve(message.signatures);
      }
      if (message.type === "progress") {
        onProgress?.(message.progress);
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
  window.addEventListener("popstate", () => showView(routeFromLocation()));
  els.homeButton.addEventListener("click", () => showView("approval", { history: "push" }));
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
    state.approvalBusy = false;
    state.approvalProgress = null;
    setStatus(error.message, "error");
    renderApprovalState();
  }));
  els.activityDetailClose.addEventListener("click", () => {
    state.selectedApprovalId = "";
    renderRecentApprovals();
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./service-worker.js?v=hourly-polling-v37").catch(() => {});
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
  showView(routeFromLocation(), { history: "replace" });
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
