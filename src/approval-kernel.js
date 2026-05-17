import { submitBundleApproval } from "./api-client.js";
import { assertResourcesIntegrity } from "./integrity.js";
import { validateBundleForApprovalV1, webauthnApprovalChallengeV1 } from "./core/protocol/envelopes.js";
import { requestApprovalAssertion } from "./webauthn.js";

const SIGN_WORKER_GRAPH = [
  "src/sign-worker.js",
  "src/sign-task-worker.js",
  "src/bank-signing-batch.js",
  "src/signing-worker-pool.js",
  "src/signing-session.js",
  "src/polling-capabilities.js",
  "src/core/crypto/bigint.js",
  "src/core/crypto/bytes.js",
  "src/core/crypto/circl-signshare.js",
  "src/core/crypto/pkcs1v15.js",
  "src/core/crypto/threshold-rsa.js",
  "src/core/protocol/canonical.js",
  "src/core/protocol/envelopes.js",
  "src/core/protocol/signing.js"
];

function approvalMetadata({ bundle, phoneSharePackage, webauthnCredential }) {
  return {
    bundle_id: bundle.bundle_id,
    bundle_hash_sha256: bundle.bundle_hash_sha256,
    payment_count: bundle.payment_inputs.length,
    approver_id: phoneSharePackage.approver_id,
    device_id: phoneSharePackage.device_id,
    share_index: phoneSharePackage.share_index,
    key_id: phoneSharePackage.key_id,
    credential_id: webauthnCredential.credential_id
  };
}

async function signInVerifiedWorker({ integrityManifest, phoneSharePackage, bundle, approvedAt, onProgress }) {
  await assertResourcesIntegrity(integrityManifest, SIGN_WORKER_GRAPH);

  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./sign-worker.js", import.meta.url), { type: "module" });
    worker.addEventListener("message", (event) => {
      const message = event.data;
      if (message.type === "done") {
        worker.terminate();
        resolve({
          paymentSignatures: message.paymentSignatures,
          pollingCapabilityPackage: message.pollingCapabilityPackage
        });
      } else if (message.type === "progress") {
        onProgress?.(message.progress);
      } else if (message.type === "error") {
        worker.terminate();
        reject(new Error(message.message));
      }
    });
    worker.addEventListener("error", (event) => {
      worker.terminate();
      reject(new Error(event.message));
    });
    worker.postMessage({ phoneSharePackage, bundle, approvedAt });
  });
}

export async function approveReviewedBundle({
  phoneSharePackage,
  webauthnCredential,
  backendOrigin,
  bundle,
  integrityManifest,
  signal,
  isCancelled = () => false,
  onStatus = () => {},
  onProgress = () => {}
}) {
  if (!phoneSharePackage || !webauthnCredential || !backendOrigin || !bundle) {
    throw new Error("approval kernel requires enrollment and a bundle");
  }
  const assertActive = () => {
    if (signal?.aborted || isCancelled()) {
      throw new Error("Approval cancelled by app lock");
    }
  };

  await validateBundleForApprovalV1(bundle);
  const metadata = approvalMetadata({ bundle, phoneSharePackage, webauthnCredential });
  onStatus("Waiting for biometric approval");
  onProgress({ stage: "webauthn", message: "Confirm WebAuthn", percent: 0 });
  const assertion = await requestApprovalAssertion({
    credentialId: webauthnCredential.credential_id,
    challengeBytes: await webauthnApprovalChallengeV1(metadata)
  });
  assertActive();

  const approvedAt = new Date().toISOString();
  onStatus("Signing payment inputs and status polling requests");
  onProgress({ stage: "preparing", message: "Preparing signatures", percent: 0 });
  const { paymentSignatures, pollingCapabilityPackage } = await signInVerifiedWorker({
    integrityManifest,
    phoneSharePackage,
    bundle,
    approvedAt,
    onProgress
  });
  assertActive();

  onProgress({ stage: "submitting", message: "Submitting approval", percent: 100 });
  return submitBundleApproval({
    version: "bundle_approval_v1",
    ...metadata,
    totals: bundle.totals,
    bank_request_hashes: bundle.bank_request_hashes,
    visible_line_item_hashes: bundle.visible_line_item_hashes,
    webauthn_assertion: assertion,
    phone_sign_shares: paymentSignatures.map((signature) => signature.sign_share_base64url),
    polling_capability_package: pollingCapabilityPackage,
    approved_at: approvedAt
  }, phoneSharePackage, backendOrigin, { signal });
}
