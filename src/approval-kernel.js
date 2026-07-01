import { fetchWebauthnChallengeNonce, submitBundleApproval } from "./api-client.js";
import { APP_INTEGRITY_GRAPH, assertResourcesIntegrity } from "./integrity.js";
import { signBundleBankInputs } from "./bank-signing-batch.js";
import { validateBundleForApprovalV1, webauthnApprovalChallengeV1 } from "./core/protocol/envelopes.js";
import { PROTOCOL_RELEASE_ID } from "./core/protocol/release.js";
import { requestApprovalAssertion } from "./webauthn.js";

// Issue #10: verify the full app-controlled graph (renderer/controller/HTML +
// crypto), not just the signing sub-graph, before producing any signature.
const SIGN_WORKER_GRAPH = APP_INTEGRITY_GRAPH;

function approvalMetadata({ bundle, phoneSharePackage, webauthnCredential }) {
  return {
    protocol_release_id: PROTOCOL_RELEASE_ID,
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

  return signBundleBankInputs({
    phoneSharePackage,
    bundle,
    approvedAt,
    onProgress
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
  // #19: a fresh, server-issued, single-use, expiring challenge nonce is folded
  // into the challenge so the assertion cannot be replayed (even for this bundle).
  const { challengeNonce, challengeNonceExpiresAt } = await fetchWebauthnChallengeNonce(phoneSharePackage, backendOrigin);
  assertActive();
  const assertion = await requestApprovalAssertion({
    credentialId: webauthnCredential.credential_id,
    challengeBytes: await webauthnApprovalChallengeV1({
      ...metadata,
      challenge_nonce: challengeNonce,
      challenge_nonce_expires_at: challengeNonceExpiresAt
    })
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
    webauthn_assertion: {
      ...assertion,
      challenge_nonce: challengeNonce,
      challenge_nonce_expires_at: challengeNonceExpiresAt
    },
    phone_sign_shares: paymentSignatures.map((signature) => signature.sign_share_base64url),
    polling_capability_package: pollingCapabilityPackage,
    approved_at: approvedAt
  }, phoneSharePackage, backendOrigin, { signal });
}
