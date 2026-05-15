import { approveReviewedBundle } from "./approval-kernel.js";
import { loadIntegrityManifest } from "./integrity.js";
import { amountMinorToDecimal, deriveVisiblePaymentFromInput } from "./payment-view.js";
import { validateBundleForApprovalV1 } from "./core/protocol/envelopes.js";

const ids = [
  "bundleSummary",
  "bundleCountValue",
  "totalsStrip",
  "paymentRows",
  "signProgress",
  "approveButton",
  "resultValue"
];
const els = Object.fromEntries(ids.map((id) => [id, document.querySelector(`#${id}`)]));
const state = {
  phoneSharePackage: null,
  webauthnCredential: null,
  backendOrigin: "",
  integrityManifest: null,
  bundle: null,
  approvedBundleIds: new Set(),
  busy: false
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

function setResult(message) {
  els.resultValue.textContent = message;
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

function renderBundle() {
  const { bundle } = state;
  els.totalsStrip.replaceChildren();
  els.paymentRows.replaceChildren();

  if (!bundle) {
    els.bundleSummary.textContent = "Nothing to approve";
    els.bundleCountValue.textContent = "-";
    els.paymentRows.append(emptyRow());
    els.signProgress.max = 1;
    els.signProgress.value = 0;
    setResult("-");
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
  setResult("-");
  setButtonState();
  reportHeight();
}

async function applyState(message) {
  state.phoneSharePackage = message.phoneSharePackage ?? null;
  state.webauthnCredential = message.webauthnCredential ?? null;
  state.backendOrigin = message.backendOrigin ?? "";
  state.approvedBundleIds = new Set(message.approvedBundleIds ?? []);

  if (message.bundle) {
    await validateBundleForApprovalV1(message.bundle);
  }
  state.bundle = message.bundle ?? null;
  renderBundle();
}

async function approveBundle() {
  if (!state.phoneSharePackage || !state.webauthnCredential || !state.backendOrigin || !state.bundle || currentBundleApproved()) {
    return;
  }

  state.busy = true;
  setButtonState();
  els.signProgress.value = 0;
  setResult("-");

  try {
    const result = await approveReviewedBundle({
      phoneSharePackage: state.phoneSharePackage,
      webauthnCredential: state.webauthnCredential,
      backendOrigin: state.backendOrigin,
      bundle: state.bundle,
      integrityManifest: state.integrityManifest,
      onStatus: setStatus,
      onProgress(progress) {
        els.signProgress.max = progress.total;
        els.signProgress.value = progress.completed;
        setStatus(`Signed ${progress.completed} of ${progress.total}`);
      }
    });
    state.approvedBundleIds.add(state.bundle.bundle_id);
    setResult(result?.approval_id ?? result?.bundle_id ?? "Submitted");
    setStatus("Approval submitted");
    post("approved", {
      bundle_id: state.bundle.bundle_id
    });
  } catch (error) {
    if (error.status === 409 || error.code === "bundle_already_approved") {
      state.approvedBundleIds.add(state.bundle.bundle_id);
      setResult("Already approved");
      setStatus("Bundle already approved", "warning");
      post("approved", {
        bundle_id: state.bundle.bundle_id
      });
      return;
    }
    setStatus(error.message, "error");
    post("error", {
      message: error.message
    });
  } finally {
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
post("ready");
