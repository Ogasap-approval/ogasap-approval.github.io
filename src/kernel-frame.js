import { approveReviewedBundle } from "./approval-kernel.js";
import { loadIntegrityManifest } from "./integrity.js";
import { amountMinorToDecimal, deriveVisiblePaymentFromInput } from "./payment-view.js";
import { validateBundleForApprovalV1 } from "./core/protocol/envelopes.js";

const ids = [
  "bundleSummary",
  "bundleCountValue",
  "totalsStrip",
  "paymentRows",
  "approveButton",
  "resultPanel",
  "resultTitle",
  "resultDetail"
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
  lockEpoch: 0,
  approvalAbortController: null
};

function post(type, fields = {}) {
  window.parent.postMessage({ source: "approval-kernel", type, ...fields }, "*");
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

function setButtonState() {
  const approved = currentBundleApproved();
  els.approveButton.disabled = state.busy || approved || !state.phoneSharePackage || !state.webauthnCredential || !state.backendOrigin || !state.bundle;
  els.approveButton.textContent = approved ? "Approved" : "Approve";
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
  els.bundleCountValue.textContent = String(bundle.payment_inputs.length);
  for (const total of bundle.totals) {
    const item = document.createElement("div");
    item.className = "total-pill";
    item.append(span(total.currency, "total-currency"), span(amountMinorToDecimal(total.amount_minor, total.currency), "numeric"));
    els.totalsStrip.append(item);
  }

  appendPaymentRows(els.paymentRows, bundle.payment_inputs.map((input) => deriveVisiblePaymentFromInput(input)));

  setButtonState();
  reportHeight();
}

async function applyState(message) {
  const nextPhoneSharePackage = message.phoneSharePackage ?? null;
  if (state.phoneSharePackage && !nextPhoneSharePackage) {
    state.lockEpoch += 1;
    state.approvalAbortController?.abort();
  }
  state.phoneSharePackage = nextPhoneSharePackage;
  state.webauthnCredential = message.webauthnCredential ?? null;
  state.backendOrigin = message.backendOrigin ?? "";
  state.lastApprovalResult = message.lastApprovalResult ?? state.lastApprovalResult;
  state.approvedBundleIds = new Set(message.approvedBundleIds ?? []);

  if (message.bundle) {
    await validateBundleForApprovalV1(message.bundle);
  }
  state.bundleError = "";
  state.bundle = message.bundle ?? null;
  setResult(state.lastApprovalResult);
  renderBundle();
}

async function approveBundle() {
  if (!state.phoneSharePackage || !state.webauthnCredential || !state.backendOrigin || !state.bundle || currentBundleApproved()) {
    return;
  }

  state.busy = true;
  const lockEpoch = state.lockEpoch;
  const approvalAbortController = new AbortController();
  state.approvalAbortController = approvalAbortController;
  state.lastApprovalResult = null;
  setButtonState();
  setResult(null);
  post("started");

  try {
    const result = await approveReviewedBundle({
      phoneSharePackage: state.phoneSharePackage,
      webauthnCredential: state.webauthnCredential,
      backendOrigin: state.backendOrigin,
      bundle: state.bundle,
      integrityManifest: state.integrityManifest,
      signal: approvalAbortController.signal,
      isCancelled: () => lockEpoch !== state.lockEpoch || !state.phoneSharePackage,
      onStatus: setStatus
    });
    const approvalDetail = totalText(state.bundle.totals) || result?.bundle_id || state.bundle.bundle_id;
    const approvalResult = {
      status: "approved",
      title: "Bundle approved successfully",
      detail: `${state.bundle.payment_inputs.length} transactions · ${approvalDetail}`
    };
    state.approvedBundleIds.add(state.bundle.bundle_id);
    state.lastApprovalResult = approvalResult;
    setResult(approvalResult);
    setStatus("Bundle approved");
    post("approved", {
      bundle_id: state.bundle.bundle_id,
      result: approvalResult
    });
  } catch (error) {
    if (error.message === "Approval cancelled by app lock" || error.name === "AbortError") {
      setResult(null);
      setStatus("Approval cancelled by app lock", "warning");
      return;
    }
    if (error.status === 409 || error.code === "bundle_already_approved") {
      const alreadyResult = {
        status: "warning",
        title: "Bundle already approved",
        detail: error.body?.received_at ? `Approved at ${new Date(error.body.received_at).toLocaleString()}` : "This bundle was already recorded by the backend."
      };
      state.approvedBundleIds.add(state.bundle.bundle_id);
      state.lastApprovalResult = alreadyResult;
      setResult(alreadyResult);
      setStatus("Bundle already approved", "warning");
      post("approved", {
        bundle_id: state.bundle.bundle_id,
        result: alreadyResult
      });
      return;
    }
    const failedResult = {
      status: "failed",
      title: "Approval failed",
      detail: error.message
    };
    state.lastApprovalResult = failedResult;
    setResult(failedResult);
    setStatus(error.message, "error");
    post("error", {
      message: error.message,
      result: failedResult
    });
  } finally {
    if (state.approvalAbortController === approvalAbortController) {
      state.approvalAbortController = null;
    }
    state.busy = false;
    setButtonState();
    reportHeight();
  }
}

window.addEventListener("message", (event) => {
  if (event.source !== window.parent || event.data?.source !== "approval-shell") {
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
