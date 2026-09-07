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
 * THE HOLDER IS NOT ASKED. This runs by itself, in the background, on the ordinary poll. They already
 * decided: they read the line items, produced a WebAuthn assertion over the bundle metadata, and signed
 * `bank_request_hashes` — the exact bytes of the POST that created these payments. This round adds
 * nothing they could weigh. It names payments by bank ids they have never seen and can do nothing but
 * finish authorizing payments that already exist. A panel here would be a question with no answer to
 * give, and the only thing it could teach is to tap through approval panels.
 *
 * It is equally the CRASH-RECOVERY path, and that is not a bonus — it is the requirement. If the phone
 * goes away between the submit and this round (app closed, network dropped, tab killed), the result is
 * a created-but-unsigned payment sitting at the bank, which is exactly the live production state this
 * was written for.
 *
 * Signing is safe to repeat — it authorizes payments the bank has already created and cannot bring a
 * second one into being — so a retry here can never double-pay. The dangerous direction is the other
 * one: not signing at all.
 *
 * ---------------------------------------------------------------------------------------------------
 * WHAT THE PHONE CHECKS BEFORE SIGNING SOMETHING IT WAS NOT ASKED ABOUT
 * ---------------------------------------------------------------------------------------------------
 * The load-bearing check is the one signNordeaPaymentSignInputV1 already makes, and it is structural
 * rather than contextual: `nordea_payment_sign_input_v1` admits exactly one method, one path, and a
 * body that is nothing but `{"payment_id_list":[...]}` of well-formed bank ids, each request's digest
 * verified against its own bytes. A signature produced here CANNOT create a payment, alter an amount,
 * or reach any other endpoint. That is what makes signing without a gesture safe at all, and no amount
 * of context-checking would substitute for it.
 *
 * `recognizeBundle` is the second, weaker check, and it is honestly weaker: the phone has never seen a
 * bank-assigned payment id (they are minted after the submit), so it cannot relate these bytes to a
 * bundle on its own. What it CAN do is refuse a bundle it has no record of the holder approving. The
 * caller supplies that record; the backend supplies both the offer and the history, so this bounds a
 * BUG or a mix-up between the two holders, not a compromised backend. Say that plainly rather than
 * dressing it up — the anti-compromise argument is the paragraph above, plus the fact that a payment
 * can only be sitting at AUTHORIZATION_PARTIAL because a WebAuthn-attested approval put it there.
 *
 * It is required, not optional: a caller that cannot say which bundles are the holder's gets no
 * signature. Fail closed.
 */
export async function authorizePendingPayments({
  phoneSharePackage,
  backendOrigin,
  integrityManifest,
  // (bundleId) => boolean — "this holder approved this bundle, and I can show you where I know it from".
  recognizeBundle,
  signal,
  isCancelled = () => false,
  onStatus = () => {},
  // Seams, for tests only. Production passes none of these and gets the real modules.
  fetchPending = fetchPendingPaymentSign,
  signInput = signNordeaPaymentSignInputV1,
  submitSigned = submitPaymentSign,
  assertIntegrity = assertResourcesIntegrity
} = {}) {
  if (!phoneSharePackage || !backendOrigin) {
    throw new Error("payment authorization requires enrollment");
  }
  if (typeof recognizeBundle !== "function") {
    throw new Error("payment authorization requires a way to recognize the holder's own bundles");
  }
  const assertActive = () => {
    if (signal?.aborted || isCancelled()) {
      throw new Error("Payment authorization cancelled by app lock");
    }
  };

  const { paymentSignInput, suppression } = await fetchPending(phoneSharePackage, backendOrigin);
  if (!paymentSignInput) {
    return { authorized: false, reason: suppression ?? "nothing_pending" };
  }
  assertActive();

  // Read ONCE, before anything else touches the object, and carried by value from here. The validator
  // takes its own snapshot for the bytes; this is the routing field, and reading it twice is how a
  // check and a signature come to disagree.
  const bundleId = paymentSignInput.bundle_id;
  if (typeof bundleId !== "string" || bundleId.length === 0) {
    return { authorized: false, reason: "bundle_not_named" };
  }
  if (!recognizeBundle(bundleId)) {
    // Not an error and not retried differently: the ordinary cause is an authorization waiting on the
    // OTHER holder, which this phone should neither sign nor complain about.
    return { authorized: false, reason: "bundle_not_recognised", bundleId };
  }

  // The same integrity gate the payment signatures pass through: never produce a signature from a
  // resource graph that has not just been verified.
  await assertIntegrity(integrityManifest, SIGN_WORKER_GRAPH);
  onStatus("Finishing the payment authorization with the bank");

  // validateNordeaPaymentSignInputV1 runs inside this call and returns the visible action derived from
  // the SIGNED bodies — so what is reported below describes the bytes, not the server's claim.
  const { signatures, visible_payment_authorization: visibleAuthorization } =
    await signInput(paymentSignInput, phoneSharePackage);
  assertActive();

  const result = await submitSigned(
    {
      request_id: paymentSignInput.request_id,
      phone_sign_shares: signatures.map((signature) => signature.sign_share_base64url),
      share_index: phoneSharePackage.share_index
    },
    phoneSharePackage,
    backendOrigin,
    { assertStillValid: () => !(signal?.aborted || isCancelled()) }
  );
  return { authorized: true, result, visibleAuthorization, bundleId };
}
