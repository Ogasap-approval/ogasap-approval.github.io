import { base64urlToBytes, bytesToBase64url, utf8Decode, utf8Encode } from "./core/crypto/bytes.js";
import { unmarshalSignShare } from "./core/crypto/circl-signshare.js";
import { pkcs1v15PaddedMessageForModulus } from "./core/crypto/pkcs1v15.js";
import { combineSignShares } from "./core/crypto/threshold-rsa.js";
import { sha256Hex } from "./core/protocol/canonical.js";
import { PROTOCOL_RELEASE_ID } from "./core/protocol/release.js";
import {
  decodePhoneSharePackageV1,
  signBackendAuthEnvelopeV1,
  signBackendResponseEnvelopeV1
} from "./core/protocol/signing.js";
import { assertMatchesSchema } from "./json-schema-validate.js";
import { responseSchema } from "./response-schemas.js";

const PENDING_BUNDLES_PATH = "/api/approval/pending-bundles";
const RECENT_APPROVALS_PATH = "/api/approval/recent-approvals";
const BACKEND_AUTH_NONCE_PATH = "/api/approval/backend-auth-nonce";
const BUNDLE_APPROVAL_PATH = "/api/approval/bundle-approval";
const BUNDLE_REJECTION_PATH = "/api/approval/bundle-rejection";
const WEBAUTHN_CHALLENGE_NONCE_PATH = "/api/approval/webauthn-challenge-nonce";
const ENROLL_CREDENTIAL_PATH = "/api/approval/enroll-credential";
const MIGRATION_REQUEST_PATH = "/api/approval/migration-request";
const PENDING_ADMIN_REQUEST_PATH = "/api/approval/pending-admin-request";
const ADMIN_APPROVAL_PATH = "/api/approval/admin-approval";
// The payment-authorization round. NEW paths rather than new fields on the bundle endpoints: a phone
// on a cached build validates responses with additionalProperties:false, so an added field breaks every
// poll from an un-updated PWA while an added endpoint is simply never called by one.
const PENDING_PAYMENT_SIGN_PATH = "/api/approval/pending-payment-sign";
const PAYMENT_SIGN_PATH = "/api/approval/payment-sign";
const BACKEND_RESPONSE_HEADER = "X-Approval-Backend-Response";
const EMPTY_BODY = new Uint8Array();

// #6: validate a backend response body against its versioned schema, failing
// closed (the caller's surrounding try/catch surfaces it as a backend error).
function validateResponseBody(name, body) {
  return assertMatchesSchema(body, responseSchema(name));
}

function apiOrigin(backendOrigin) {
  if (!backendOrigin) {
    throw new Error("backend URL is not configured");
  }
  return backendOrigin;
}

function apiUrl(path, params = {}, backendOrigin) {
  const url = new URL(path, apiOrigin(backendOrigin));
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      url.searchParams.set(key, value);
    }
  }
  return url;
}

// Only ever reached AFTER the company-share attestation has verified, so `companySigned` says this refusal is
// the server's own word rather than something on the wire claiming to be it.
function throwBackendError(response, body) {
  const error = new Error(body.message ?? body.error ?? `approval backend returned ${response.status}`);
  error.status = response.status;
  error.code = body.error;
  error.body = body;
  error.companySigned = true;
  throw error;
}

/**
 * Thrown when an approval was stopped BEFORE its request left the phone, so the server never saw it.
 * The message is the one the kernel has always shown for an app lock during signing.
 */
export class ApprovalNotSentError extends Error {
  constructor() {
    super("Approval cancelled by app lock");
    this.name = "ApprovalNotSentError";
    this.sent = false;
  }
}

function parseJsonBody(response, bodyText) {
  if (bodyText.trim() === "") {
    return {};
  }
  try {
    return JSON.parse(bodyText);
  } catch (cause) {
    const error = new Error(`approval backend returned invalid JSON for ${response.status}`);
    error.status = response.status;
    error.cause = cause;
    throw error;
  }
}

function decodeBackendResponseHeader(response) {
  const raw = response.attestation;
  if (!raw) {
    throw new Error("approval backend response was not signed by company shares");
  }
  try {
    return JSON.parse(utf8Decode(base64urlToBytes(raw)));
  } catch (cause) {
    const error = new Error("approval backend response signature header is invalid");
    error.cause = cause;
    throw error;
  }
}

function assertBackendResponseAttestation(attestation, expected) {
  if (attestation.version !== "backend_response_envelope_v1") {
    throw new Error("approval backend response signature version is unsupported");
  }
  // #6: the signed response-envelope header has a versioned schema too.
  validateResponseBody("backend_response_envelope_v1", attestation);
  for (const [name, value] of Object.entries(expected)) {
    if (attestation[name] !== value) {
      throw new Error(`approval backend response signature ${name} mismatch`);
    }
  }
  if (!Array.isArray(attestation.company_sign_shares_base64url)) {
    throw new Error("approval backend response did not include company sign shares");
  }
}

// `assertStillValid` (optional) throws to stop: it runs after every await here and inside the phone
// signature, so a lock at any point leaves the answer unverified and the share unused from then on.
async function verifyBackendResponseAttestation({ response, bodyBytes, phoneSharePackage, method, path, requestServerNonce, requestClientNonce, assertStillValid }) {
  const bodySha256 = await sha256Hex(bodyBytes);
  if (typeof assertStillValid === "function") {
    assertStillValid();
  }
  const attestation = decodeBackendResponseHeader(response);
  const upperMethod = method.toUpperCase();
  const expected = {
    method: upperMethod,
    path,
    status: response.status,
    body_sha256: bodySha256,
    approver_id: phoneSharePackage.approver_id,
    device_id: phoneSharePackage.device_id,
    share_index: phoneSharePackage.share_index,
    key_id: phoneSharePackage.key_id,
    request_server_nonce: requestServerNonce ?? "-",
    request_client_nonce: requestClientNonce ?? "-"
  };
  assertBackendResponseAttestation(attestation, expected);

  const envelope = {
    ...expected,
    bodyBytes,
    response_timestamp: attestation.response_timestamp
  };
  const phoneShare = decodePhoneSharePackageV1(phoneSharePackage);
  const phoneSigned = await signBackendResponseEnvelopeV1(envelope, phoneSharePackage, guardedSigningOptions(assertStillValid));
  const companyShares = attestation.company_sign_shares_base64url.map((share) => {
    const parsed = unmarshalSignShare(base64urlToBytes(share));
    if (parsed.trailingBytes.length !== 0) {
      throw new Error("approval backend response company sign share has trailing bytes");
    }
    return parsed;
  });
  const companyShareIndexes = companyShares.map((share) => share.index).sort((left, right) => left - right);
  if (companyShareIndexes.length !== 2 || companyShareIndexes[0] !== 1 || companyShareIndexes[1] !== 2) {
    throw new Error("approval backend response was not signed by company shares 1 and 2");
  }
  if (JSON.stringify(attestation.company_share_indexes ?? []) !== JSON.stringify(companyShareIndexes)) {
    throw new Error("approval backend response company share indexes mismatch");
  }

  const paddedDigest = await pkcs1v15PaddedMessageForModulus(phoneSigned.canonical_envelope, phoneShare.modulus);
  if (typeof assertStillValid === "function") {
    assertStillValid();
  }
  combineSignShares({
    modulus: phoneShare.modulus,
    publicExponent: phoneShare.publicExponent,
    shares: [...companyShares, unmarshalSignShare(phoneSigned.sign_share)],
    paddedDigest
  });
}

// Everything verification needs from a response, read off the wire and held as plain data. Capturing is
// separate from verifying because verifying needs the phone share (the phone's half of the response
// signature) and capturing does not: an approval's answer can be taken in while the app is locked and the
// share is out of memory, and checked once it is back.
async function captureResponse(response) {
  return {
    status: response.status,
    ok: response.ok,
    attestation: response.headers.get(BACKEND_RESPONSE_HEADER),
    bodyText: await response.text()
  };
}

async function verifyCapturedResponse(captured, {
  method,
  path,
  phoneSharePackage,
  requestServerNonce = "-",
  requestClientNonce = "-",
  assertStillValid
}) {
  const bodyBytes = utf8Encode(captured.bodyText);
  const body = parseJsonBody(captured, captured.bodyText);
  await verifyBackendResponseAttestation({
    response: captured,
    bodyBytes,
    phoneSharePackage,
    method,
    path,
    requestServerNonce,
    requestClientNonce,
    assertStillValid
  });
  if (!captured.ok) {
    throwBackendError(captured, body);
  }
  return body;
}

async function verifiedJsonResponse(response, options) {
  return verifyCapturedResponse(await captureResponse(response), options);
}

function randomNonce() {
  return bytesToBase64url(crypto.getRandomValues(new Uint8Array(18)));
}

function backendAuthHeaderValue(envelope) {
  return bytesToBase64url(utf8Encode(JSON.stringify(envelope)));
}

// `signal` and `assertStillValid` are optional (the rejection uses them): the first stops the fetch, the
// second is checked after every await of the answer's verification, before the share is read or signs, so
// a lock during the round-trip or the crypto ends it without the share being touched again.
async function fetchBackendAuthNonce({ method, path, phoneSharePackage, backendOrigin, signal, assertStillValid }) {
  const guard = notSentGuard(assertStillValid);
  const response = await fetch(apiUrl(BACKEND_AUTH_NONCE_PATH, {
    method,
    path,
    approver_id: phoneSharePackage.approver_id,
    device_id: phoneSharePackage.device_id,
    share_index: phoneSharePackage.share_index,
    key_id: phoneSharePackage.key_id
  }, backendOrigin), {
    method: "GET",
    headers: {
      "Accept": "application/json"
    },
    cache: "no-store",
    ...(signal ? { signal } : {})
  });
  const captured = await captureResponse(response);
  const body = await verifyCapturedResponse(captured, {
    method: "GET",
    path: BACKEND_AUTH_NONCE_PATH,
    phoneSharePackage,
    assertStillValid: guard
  });
  validateResponseBody("backend_auth_nonce_response_v1", body);
  return body.server_nonce;
}

export async function fetchWebauthnChallengeNonce(phoneSharePackage, backendOrigin) {
  const auth = await signedApprovalHeaders({
    method: "GET",
    path: WEBAUTHN_CHALLENGE_NONCE_PATH,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(WEBAUTHN_CHALLENGE_NONCE_PATH, {}, backendOrigin), {
    method: "GET",
    headers: auth.headers,
    cache: "no-store"
  });
  const body = await verifiedJsonResponse(response, {
    method: "GET",
    path: WEBAUTHN_CHALLENGE_NONCE_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  validateResponseBody("webauthn_challenge_nonce_response_v1", body);
  return { challengeNonce: body.challenge_nonce, challengeNonceExpiresAt: body.expires_at };
}

// Nordea ADMIN approval (nordea_admin_input_v1). Operator-created drafts are fetched and approved
// over the PHONE-authenticated channel, exactly like payment bundles: creating a draft needs the
// operator's admin token, but AUTHORIZING one needs a share holder. Neither can do it alone.
export async function fetchPendingAdminRequest(phoneSharePackage, backendOrigin) {
  const auth = await signedApprovalHeaders({
    method: "GET",
    path: PENDING_ADMIN_REQUEST_PATH,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(PENDING_ADMIN_REQUEST_PATH, {}, backendOrigin), {
    method: "GET",
    headers: auth.headers,
    cache: "no-store"
  });
  const body = await verifiedJsonResponse(response, {
    method: "GET",
    path: PENDING_ADMIN_REQUEST_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  validateResponseBody("pending_admin_request_response_v1", body);
  // An ENVELOPE, not the bare input. `admin_input: null` alone cannot tell a holder apart from
  // "nothing to do" and "the service refused to mint one, and here is why" — and the second is the
  // state this flow deadlocked in: an empty screen with nothing to act on and no way to find out.
  // Explicit destructuring at the consumer rather than shape-sniffing: this module refuses ambiguity.
  return {
    adminInput: body.admin_input ?? null,
    suppression: body.suppression ?? null,
    // Context, NOT consent: where the multi-step setup has got to. Carried alongside the input
    // rather than inside it because it describes the sequence, not the bytes being signed — and it
    // is the one field that must survive `admin_input: null`, since the screen that most needs it
    // is the one with nothing to approve.
    flowProgress: body.flow_progress ?? null
  };
}

export class AdminApprovalAbandonedError extends Error {
  constructor() {
    super("the signing context changed before the approval was sent");
    this.name = "AdminApprovalAbandonedError";
  }
}

/**
 * `assertStillValid` is re-checked immediately before the request goes out. Preparing an approval
 * involves a nonce round-trip and a backend-auth signature, and a lock or backend change during
 * that window must not still result in a POST.
 */
export async function submitAdminApproval(approval, phoneSharePackage, backendOrigin, { assertStillValid } = {}) {
  const body = JSON.stringify(approval);
  const bodyBytes = utf8Encode(body);
  const auth = await signedApprovalHeaders({
    method: "POST",
    path: ADMIN_APPROVAL_PATH,
    bodyBytes,
    phoneSharePackage,
    backendOrigin
  });
  // LAST controllable moment: everything above (hashing, the nonce, the backend-auth signature) is
  // preparation, and an invalidation during it must stop the send.
  if (typeof assertStillValid === "function" && !assertStillValid()) {
    throw new AdminApprovalAbandonedError();
  }
  const response = await fetch(apiUrl(ADMIN_APPROVAL_PATH, {}, backendOrigin), {
    method: "POST",
    headers: { ...auth.headers, "Content-Type": "application/json" },
    body,
    cache: "no-store"
  });
  const result = await verifiedJsonResponse(response, {
    method: "POST",
    path: ADMIN_APPROVAL_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  return validateResponseBody("admin_approval_result_v1", result);
}

// ---------------------------------------------------------------------------------------------------
// The payment-authorization round (nordea_payment_sign_input_v1).
//
// POST /corporate/premium/v2/payments only CREATES payments at Nordea; the bank waits for a payment
// authorization before executing them. That request names payments by bank-assigned ids, so it cannot
// be signed until the POST has returned — hence a second round rather than part of the bundle approval.
// ---------------------------------------------------------------------------------------------------
export async function fetchPendingPaymentSign(phoneSharePackage, backendOrigin) {
  const auth = await signedApprovalHeaders({
    method: "GET",
    path: PENDING_PAYMENT_SIGN_PATH,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(PENDING_PAYMENT_SIGN_PATH, {}, backendOrigin), {
    method: "GET",
    headers: auth.headers,
    cache: "no-store"
  });
  const body = await verifiedJsonResponse(response, {
    method: "GET",
    path: PENDING_PAYMENT_SIGN_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  validateResponseBody("pending_payment_sign_response_v1", body);
  return {
    paymentSignInput: body.payment_sign_input ?? null,
    suppression: body.suppression ?? null
  };
}

/**
 * Send the holder's shares for every request of one authorization.
 *
 * `assertStillValid` is re-checked immediately before the send, for the same reason it is on the admin
 * path: preparing this involves a nonce round-trip and a backend-auth signature, and a lock or context
 * change during that window must stop the POST rather than merely be noticed afterwards.
 */
export async function submitPaymentSign(approval, phoneSharePackage, backendOrigin, { assertStillValid } = {}) {
  const body = JSON.stringify(approval);
  const bodyBytes = utf8Encode(body);
  const auth = await signedApprovalHeaders({
    method: "POST",
    path: PAYMENT_SIGN_PATH,
    bodyBytes,
    phoneSharePackage,
    backendOrigin
  });
  if (typeof assertStillValid === "function" && !assertStillValid()) {
    throw new AdminApprovalAbandonedError();
  }
  const response = await fetch(apiUrl(PAYMENT_SIGN_PATH, {}, backendOrigin), {
    method: "POST",
    headers: { ...auth.headers, "Content-Type": "application/json" },
    body,
    cache: "no-store"
  });
  const result = await verifiedJsonResponse(response, {
    method: "POST",
    path: PAYMENT_SIGN_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  return validateResponseBody("payment_sign_result_v1", result);
}

export async function enrollApprovalCredential(enrollment, phoneSharePackage, backendOrigin) {
  const body = JSON.stringify(enrollment);
  const bodyBytes = utf8Encode(body);
  const auth = await signedApprovalHeaders({
    method: "POST",
    path: ENROLL_CREDENTIAL_PATH,
    bodyBytes,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(ENROLL_CREDENTIAL_PATH, {}, backendOrigin), {
    method: "POST",
    headers: {
      ...auth.headers,
      "Content-Type": "application/json"
    },
    body
  });
  const result = await verifiedJsonResponse(response, {
    method: "POST",
    path: ENROLL_CREDENTIAL_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  return validateResponseBody("enroll_credential_result_v1", result);
}

// New-phone migration (server-approved): the new phone proves share-possession
// (the signed backend-auth header) and asks the backend to register its freshly
// minted passkey. The backend stores it as PENDING (awaiting_approval) and does
// NOT register anything until an operator approves. Both calls reuse the same
// signed auth + signed-response verification as the rest of the API.
export async function requestMigration(request, phoneSharePackage, backendOrigin) {
  const body = JSON.stringify(request);
  const bodyBytes = utf8Encode(body);
  const auth = await signedApprovalHeaders({
    method: "POST",
    path: MIGRATION_REQUEST_PATH,
    bodyBytes,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(MIGRATION_REQUEST_PATH, {}, backendOrigin), {
    method: "POST",
    headers: {
      ...auth.headers,
      "Content-Type": "application/json"
    },
    body
  });
  const result = await verifiedJsonResponse(response, {
    method: "POST",
    path: MIGRATION_REQUEST_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  return validateResponseBody("migration_request_response_v1", result);
}

// NEW phone: poll a pending migration's status until an operator approves/rejects.
export async function pollMigration(migrationId, phoneSharePackage, backendOrigin) {
  const path = `${MIGRATION_REQUEST_PATH}/${migrationId}`;
  const auth = await signedApprovalHeaders({
    method: "GET",
    path,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(path, {}, backendOrigin), {
    method: "GET",
    headers: auth.headers,
    cache: "no-store"
  });
  const result = await verifiedJsonResponse(response, {
    method: "GET",
    path,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  return validateResponseBody("migration_status_response_v1", result);
}

// Signing options for a share that must stop the moment the app locks, without touching the core (whose
// hash is the protocol release id). `guard()` throws; it runs at the blinding draw, the last step before
// the share's exponentiation and after every await inside the signature, so a locked share never signs.
function guardedSigningOptions(guard) {
  if (typeof guard !== "function") {
    return {};
  }
  const base = globalThis.crypto;
  return {
    cryptoProvider: {
      subtle: base.subtle,
      getRandomValues(array) {
        guard();
        return base.getRandomValues(array);
      }
    }
  };
}

// A false `assertStillValid()` throws ApprovalNotSentError: it is checked after every await, up to and
// inside the backend-auth signature.
function notSentGuard(assertStillValid) {
  if (typeof assertStillValid !== "function") {
    return undefined;
  }
  return () => {
    if (!assertStillValid()) {
      throw new ApprovalNotSentError();
    }
  };
}

async function signedApprovalHeaders({ method, path, bodyBytes = EMPTY_BODY, phoneSharePackage, backendOrigin, signal, assertStillValid }) {
  const guard = notSentGuard(assertStillValid);
  const upperMethod = method.toUpperCase();
  const bodySha256 = await sha256Hex(bodyBytes);
  guard?.();
  const serverNonce = await fetchBackendAuthNonce({
    method: upperMethod,
    path,
    phoneSharePackage,
    backendOrigin,
    signal,
    assertStillValid
  });
  guard?.();
  const clientNonce = randomNonce();
  const envelope = {
    method: upperMethod,
    protocol_release_id: PROTOCOL_RELEASE_ID,
    path,
    body_sha256: bodySha256,
    bodyBytes,
    approver_id: phoneSharePackage.approver_id,
    device_id: phoneSharePackage.device_id,
    share_index: phoneSharePackage.share_index,
    key_id: phoneSharePackage.key_id,
    timestamp: new Date().toISOString(),
    server_nonce: serverNonce,
    client_nonce: clientNonce
  };
  const signed = await signBackendAuthEnvelopeV1(envelope, phoneSharePackage, guardedSigningOptions(guard));

  return {
    serverNonce,
    clientNonce,
    headers: {
      "Accept": "application/json",
      "X-Approval-Backend-Auth": backendAuthHeaderValue({
        version: "backend_auth_envelope_v1",
        protocol_release_id: envelope.protocol_release_id,
        method: envelope.method,
        path: envelope.path,
        body_sha256: envelope.body_sha256,
        approver_id: envelope.approver_id,
        device_id: envelope.device_id,
        share_index: envelope.share_index,
        key_id: envelope.key_id,
        timestamp: envelope.timestamp,
        server_nonce: envelope.server_nonce,
        client_nonce: envelope.client_nonce,
        sign_share_base64url: signed.sign_share_base64url
      })
    }
  };
}

function normalizePendingBundles(body) {
  if (Array.isArray(body)) {
    return body;
  }
  if (Array.isArray(body?.bundles)) {
    return body.bundles;
  }
  if (body?.bundle) {
    return [body.bundle];
  }
  return [];
}

export async function fetchPendingBundles(phoneSharePackage, backendOrigin) {
  const auth = await signedApprovalHeaders({
    method: "GET",
    path: PENDING_BUNDLES_PATH,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(PENDING_BUNDLES_PATH, {}, backendOrigin), {
    method: "GET",
    headers: auth.headers,
    cache: "no-store"
  });
  const body = await verifiedJsonResponse(response, {
    method: "GET",
    path: PENDING_BUNDLES_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  validateResponseBody("pending_bundles_response_v1", body);
  return normalizePendingBundles(body);
}

function normalizeRecentApprovals(body) {
  if (Array.isArray(body)) {
    return body;
  }
  if (Array.isArray(body?.approvals)) {
    return body.approvals;
  }
  return [];
}

export async function fetchRecentApprovals(phoneSharePackage, backendOrigin) {
  const auth = await signedApprovalHeaders({
    method: "GET",
    path: RECENT_APPROVALS_PATH,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(RECENT_APPROVALS_PATH, {}, backendOrigin), {
    method: "GET",
    headers: auth.headers,
    cache: "no-store"
  });
  const body = await verifiedJsonResponse(response, {
    method: "GET",
    path: RECENT_APPROVALS_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  validateResponseBody("recent_approvals_response_v1", body);
  return normalizeRecentApprovals(body);
}

/**
 * Send a bundle approval and hand back its answer UNVERIFIED, without waiting for it.
 *
 * Resolves the moment the request has been handed to the network, with:
 *   sentAt    when that happened (ms)
 *   response  a promise of the captured answer; rejects if the answer never arrives
 *   verify    (captured, phoneSharePackage) => the verified, schema-checked result
 *
 * `assertStillValid` is re-checked after the nonce round-trip and the backend-auth signature, immediately
 * before the send, so an app lock during that preparation throws ApprovalNotSentError and nothing leaves.
 *
 * After the send there is deliberately NO abort signal on the request. It carries only signed data, the
 * server records the approval whether or not anyone is still listening, and its answer is company-signed —
 * so a lock has nothing to gain by cancelling it and a holder has everything to lose by never learning what
 * happened. The share is not needed again until `verify`, which takes it as an argument: nothing returned
 * from here keeps a reference to it (see sentBundleApproval).
 */
export async function dispatchBundleApproval(approval, phoneSharePackage, backendOrigin, { assertStillValid } = {}) {
  const body = JSON.stringify(approval);
  const bodyBytes = utf8Encode(body);
  const auth = await signedApprovalHeaders({
    method: "POST",
    path: BUNDLE_APPROVAL_PATH,
    bodyBytes,
    phoneSharePackage,
    backendOrigin
  });
  // LAST controllable moment. Nothing between this check and fetch() awaits, so a lock cannot slip between.
  if (typeof assertStillValid === "function" && !assertStillValid()) {
    throw new ApprovalNotSentError();
  }
  const sentAt = Date.now();
  const response = fetch(apiUrl(BUNDLE_APPROVAL_PATH, {}, backendOrigin), {
    method: "POST",
    headers: {
      ...auth.headers,
      "Content-Type": "application/json"
    },
    body
  }).then(captureResponse);
  return sentBundleApproval(response, {
    sentAt,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
}

// A separate function on purpose: its scope has no phone share in it, so the closures it returns cannot keep
// one alive while the server is still verifying and the app has been locked.
function sentBundleApproval(response, { sentAt, requestServerNonce, requestClientNonce }) {
  // Handled here so a lost answer is never an unhandled rejection; whoever awaits `response` still sees it.
  response.catch(() => {});
  return {
    sentAt,
    response,
    async verify(captured, phoneSharePackage) {
      const result = await verifyCapturedResponse(captured, {
        method: "POST",
        path: BUNDLE_APPROVAL_PATH,
        phoneSharePackage,
        requestServerNonce,
        requestClientNonce
      });
      return validateResponseBody("bundle_approval_result_v1", result);
    }
  };
}

// Send and wait for the verified answer in one step, with the same share throughout. For callers that do not
// need to survive an app lock between the two (the conformance tests).
export async function submitBundleApproval(approval, phoneSharePackage, backendOrigin, options = {}) {
  const sent = await dispatchBundleApproval(approval, phoneSharePackage, backendOrigin, options);
  return sent.verify(await sent.response, phoneSharePackage);
}

/**
 * Reject a pending bundle: `{ bundle_id, bundle_hash }`, where bundle_hash is the bundle's
 * bundle_hash_sha256 as it was shown, so the server refuses (bundle_hash_mismatch) a bundle that changed
 * underneath the holder. Resolves with the verified bundle_rejection_result_v1.
 *
 * Needs no WebAuthn gesture: rejecting cannot move money. Safe to repeat: a bundle already rejected
 * answers the same success with already_rejected: true. A refusal throws with `companySigned` set, as
 * every verified error does; anything else thrown (network, an unverifiable answer) leaves the outcome
 * unknown.
 *
 * Options, all for an app that can lock underneath it:
 *   assertStillValid  checked after every await before the POST (nonce verification and signing included,
 *                     right up to the share signature) and right before the POST; false throws
 *                     ApprovalNotSentError and nothing is sent
 *   signal            aborts the nonce fetch and the POST
 *   currentShare      () => the share to verify the answer with, read when it arrives (null while locked,
 *                     which leaves the outcome unknown), and re-read after every await of the verification.
 *                     When given, this call lets go of the share it was handed the moment the POST is sent.
 */
export async function submitBundleRejection(rejection, phoneSharePackage, backendOrigin, { assertStillValid, signal, currentShare } = {}) {
  const stillValid = () => typeof assertStillValid !== "function" || assertStillValid();
  const body = JSON.stringify({ bundle_id: rejection.bundle_id, bundle_hash: rejection.bundle_hash });
  const auth = await signedApprovalHeaders({
    method: "POST",
    path: BUNDLE_REJECTION_PATH,
    bodyBytes: utf8Encode(body),
    phoneSharePackage,
    backendOrigin,
    signal,
    assertStillValid: stillValid
  });
  // LAST controllable moment: nothing between this check and fetch() awaits.
  if (!stillValid()) {
    throw new ApprovalNotSentError();
  }
  const shareToVerify = typeof currentShare === "function" ? currentShare : () => phoneSharePackage;
  if (typeof currentShare === "function") {
    phoneSharePackage = null;
  }
  const captured = await captureResponse(await fetch(apiUrl(BUNDLE_REJECTION_PATH, {}, backendOrigin), {
    method: "POST",
    headers: { ...auth.headers, "Content-Type": "application/json" },
    body,
    cache: "no-store",
    ...(signal ? { signal } : {})
  }));
  // Sent: a lock from here on leaves the outcome unknown (a plain Error), and it is re-read after every
  // await of the verification, so a lock during the crypto stops the share being used.
  const share = shareToVerify();
  const shareStillCurrent = () => {
    if (!share || shareToVerify() !== share) {
      throw new Error("the app locked before the answer could be verified");
    }
  };
  shareStillCurrent();
  const result = await verifyCapturedResponse(captured, {
    method: "POST",
    path: BUNDLE_REJECTION_PATH,
    phoneSharePackage: share,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce,
    assertStillValid: shareStillCurrent
  });
  return validateResponseBody("bundle_rejection_result_v1", result);
}
