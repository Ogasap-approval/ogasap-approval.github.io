import { base64urlToBytes, bytesToBase64url, utf8Decode, utf8Encode } from "./core/crypto/bytes.js";
import { unmarshalSignShare } from "./core/crypto/circl-signshare.js";
import { pkcs1v15PaddedMessageForModulus } from "./core/crypto/pkcs1v15.js";
import { combineSignShares } from "./core/crypto/threshold-rsa.js";
import { sha256Hex } from "./core/protocol/canonical.js";
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
const WEBAUTHN_CHALLENGE_NONCE_PATH = "/api/approval/webauthn-challenge-nonce";
const ENROLL_CREDENTIAL_PATH = "/api/approval/enroll-credential";
const MIGRATION_REQUEST_PATH = "/api/approval/migration-request";
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

function throwBackendError(response, body) {
  const error = new Error(body.message ?? body.error ?? `approval backend returned ${response.status}`);
  error.status = response.status;
  error.code = body.error;
  error.body = body;
  throw error;
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
  const raw = response.headers.get(BACKEND_RESPONSE_HEADER);
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

async function verifyBackendResponseAttestation({ response, bodyBytes, phoneSharePackage, method, path, requestServerNonce, requestClientNonce }) {
  const bodySha256 = await sha256Hex(bodyBytes);
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
  const phoneSigned = await signBackendResponseEnvelopeV1(envelope, phoneSharePackage);
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
  combineSignShares({
    modulus: phoneShare.modulus,
    publicExponent: phoneShare.publicExponent,
    shares: [...companyShares, unmarshalSignShare(phoneSigned.sign_share)],
    paddedDigest
  });
}

async function verifiedJsonResponse(response, {
  method,
  path,
  phoneSharePackage,
  requestServerNonce = "-",
  requestClientNonce = "-"
}) {
  const bodyText = await response.text();
  const bodyBytes = utf8Encode(bodyText);
  const body = parseJsonBody(response, bodyText);
  await verifyBackendResponseAttestation({
    response,
    bodyBytes,
    phoneSharePackage,
    method,
    path,
    requestServerNonce,
    requestClientNonce
  });
  if (!response.ok) {
    throwBackendError(response, body);
  }
  return body;
}

function randomNonce() {
  return bytesToBase64url(crypto.getRandomValues(new Uint8Array(18)));
}

function backendAuthHeaderValue(envelope) {
  return bytesToBase64url(utf8Encode(JSON.stringify(envelope)));
}

async function fetchBackendAuthNonce({ method, path, phoneSharePackage, backendOrigin }) {
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
    cache: "no-store"
  });
  const body = await verifiedJsonResponse(response, {
    method: "GET",
    path: BACKEND_AUTH_NONCE_PATH,
    phoneSharePackage
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

async function signedApprovalHeaders({ method, path, bodyBytes = EMPTY_BODY, phoneSharePackage, backendOrigin }) {
  const upperMethod = method.toUpperCase();
  const bodySha256 = await sha256Hex(bodyBytes);
  const serverNonce = await fetchBackendAuthNonce({
    method: upperMethod,
    path,
    phoneSharePackage,
    backendOrigin
  });
  const clientNonce = randomNonce();
  const envelope = {
    method: upperMethod,
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
  const signed = await signBackendAuthEnvelopeV1(envelope, phoneSharePackage);

  return {
    serverNonce,
    clientNonce,
    headers: {
      "Accept": "application/json",
      "X-Approval-Backend-Auth": backendAuthHeaderValue({
        version: "backend_auth_envelope_v1",
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

export async function submitBundleApproval(approval, phoneSharePackage, backendOrigin, { signal } = {}) {
  const body = JSON.stringify(approval);
  const bodyBytes = utf8Encode(body);
  const auth = await signedApprovalHeaders({
    method: "POST",
    path: BUNDLE_APPROVAL_PATH,
    bodyBytes,
    phoneSharePackage,
    backendOrigin
  });
  const response = await fetch(apiUrl(BUNDLE_APPROVAL_PATH, {}, backendOrigin), {
    method: "POST",
    headers: {
      ...auth.headers,
      "Content-Type": "application/json"
    },
    body,
    signal
  });
  const result = await verifiedJsonResponse(response, {
    method: "POST",
    path: BUNDLE_APPROVAL_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
  return validateResponseBody("bundle_approval_result_v1", result);
}
