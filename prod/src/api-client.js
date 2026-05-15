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

const PENDING_BUNDLES_PATH = "/api/approval/pending-bundles";
const BACKEND_AUTH_NONCE_PATH = "/api/approval/backend-auth-nonce";
const BUNDLE_APPROVAL_PATH = "/api/approval/bundle-approval";
const BACKEND_RESPONSE_HEADER = "X-Approval-Backend-Response";
const EMPTY_BODY = new Uint8Array();

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
  if (typeof body.server_nonce !== "string") {
    throw new Error("approval backend did not return a server nonce");
  }
  return body.server_nonce;
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
  return normalizePendingBundles(await verifiedJsonResponse(response, {
    method: "GET",
    path: PENDING_BUNDLES_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  }));
}

export async function submitBundleApproval(approval, phoneSharePackage, backendOrigin) {
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
    body
  });
  return verifiedJsonResponse(response, {
    method: "POST",
    path: BUNDLE_APPROVAL_PATH,
    phoneSharePackage,
    requestServerNonce: auth.serverNonce,
    requestClientNonce: auth.clientNonce
  });
}
