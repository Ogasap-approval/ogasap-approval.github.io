import { fetchPendingBundles, fetchRecentApprovals } from "./api-client.js";
import { loadIntegrityManifest } from "./integrity.js";
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
const ids = [
  "runtimeStatus",
  "approvalView",
  "settingsView",
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
  "resetButton"
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
  approvedBundleIds: new Set(),
  kernelReady: false,
  pollTimer: 0,
  pollInFlight: false
};

function setStatus(message, level = "normal") {
  els.runtimeStatus.textContent = message;
  els.runtimeStatus.className = level === "error" ? "status-line error" : level === "warning" ? "status-line warning" : "status-line";
}

function showSettings(show) {
  els.settingsView.classList.toggle("hidden", !show);
  els.approvalView.classList.toggle("hidden", show);
  els.settingsButton.classList.toggle("active", show);
  els.settingsButton.setAttribute("aria-pressed", String(show));
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
    recentApprovals: state.recentApprovals,
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
  clearPollTimer();
  await clearEnrollment();
  state.phoneSharePackage = null;
  state.webauthnCredential = null;
  state.bundle = null;
  renderEnrollment();
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
    sendKernelState();
    setStatus("Enroll device in Settings to check approvals", "warning");
    return;
  }
  if (!state.backendOrigin) {
    state.bundle = null;
    state.recentApprovals = [];
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
  els.settingsButton.addEventListener("click", () => showSettings(els.settingsView.classList.contains("hidden")));
  els.enrollmentFile.addEventListener("change", () => enrollFromPackageFile(els.enrollmentFile.files[0]).catch((error) => {
    setStatus(error.message, "error");
  }));
  els.resetButton.addEventListener("click", () => resetEnrollment().catch((error) => {
    setStatus(error.message, "error");
  }));
  els.saveBackendButton.addEventListener("click", () => saveBackendFromSettings().catch((error) => {
    setStatus(error.message, "error");
  }));

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
  sendKernelState();
  showSettings(false);
  await pollPendingBundles();
}

init().catch((error) => {
  setStatus(error.message, "error");
});
