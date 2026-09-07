import {
  fetchPendingPaymentSign,
  fetchWebauthnChallengeNonce,
  submitBundleApproval,
  submitPaymentSign
} from "./api-client.js";
import { APP_INTEGRITY_GRAPH, assertResourcesIntegrity } from "./integrity.js";
import { signBundleBankInputs } from "./bank-signing-batch.js";
import { validateBundleForApprovalV1, webauthnApprovalChallengeV1 } from "./core/protocol/envelopes.js";
import { signNordeaPaymentSignInputV1 } from "./core/protocol/signing.js";
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


/**
 * The SECOND signing round: authorizing the payments the bank has now created.
 *
 * `POST /corporate/premium/v2/payments` only creates payments at Nordea — the bank waits for a payment
 * authorization before executing them. That request names payments by BANK-assigned ids, so its bytes
 * do not exist until the submit has returned, and it cannot be folded into the approval above.
 *
 * ONE gesture, several signatures, the shape the admin chain already uses: the holder is still here and
 * still holds their share, so the round runs straight after the approval rather than asking them to
 * come back. A bundle of up to 200 payments is at most ten requests (20 ids each), all signed in one
 * pass.
 *
 * It is equally the CRASH-RECOVERY path, and that is not a bonus — it is the requirement. If the phone
 * goes away between the submit and this round (app closed, network dropped, tab killed), the result is
 * a created-but-unsigned payment sitting at the bank, which is exactly the live production state this
 * was written for. So this is also safe to call on app open with no approval in progress: it asks what
 * is outstanding and authorizes that.
 *
 * Signing is safe to repeat — it authorizes payments the bank has already created and cannot bring a
 * second one into being — so a retry here can never double-pay. The dangerous direction is the other
 * one: not signing at all.
 */
export async function authorizePendingPayments({
  phoneSharePackage,
  backendOrigin,
  integrityManifest,
  signal,
  isCancelled = () => false,
  onStatus = () => {}
}) {
  if (!phoneSharePackage || !backendOrigin) {
    throw new Error("payment authorization requires enrollment");
  }
  const assertActive = () => {
    if (signal?.aborted || isCancelled()) {
      throw new Error("Payment authorization cancelled by app lock");
    }
  };

  const { paymentSignInput, suppression } = await fetchPendingPaymentSign(phoneSharePackage, backendOrigin);
  if (!paymentSignInput) {
    return { authorized: false, reason: suppression ?? "nothing_pending" };
  }
  assertActive();

  // The same integrity gate the payment signatures pass through: never produce a signature from a
  // resource graph that has not just been verified.
  await assertResourcesIntegrity(integrityManifest, SIGN_WORKER_GRAPH);
  onStatus("Authorizing payments with the bank");

  // validateNordeaPaymentSignInputV1 runs inside this call and returns the visible action derived from
  // the SIGNED bodies — so what is reported below describes the bytes, not the server's claim.
  const { signatures, visible_payment_authorization: visibleAuthorization } =
    await signNordeaPaymentSignInputV1(paymentSignInput, phoneSharePackage);
  assertActive();

  const result = await submitPaymentSign(
    {
      request_id: paymentSignInput.request_id,
      phone_sign_shares: signatures.map((signature) => signature.sign_share_base64url),
      share_index: phoneSharePackage.share_index
    },
    phoneSharePackage,
    backendOrigin,
    { assertStillValid: () => !(signal?.aborted || isCancelled()) }
  );
  return { authorized: true, result, visibleAuthorization };
}
