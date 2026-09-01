import { base64urlToBytes, bytesToHex, utf8Encode } from "../crypto/bytes.js";
import { emsaPkcs1v15Encode, sha256 } from "../crypto/pkcs1v15.js";
import { canonicalJsonBytes, canonicalText, sha256Hex, stableStringify } from "./canonical.js";
import { PROTOCOL_RELEASE_ID } from "./release.js";

const BACKEND_PATH = /^\/api\/approval(\/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$/u;
const HEX_64 = /^[a-f0-9]{64}$/u;
const ID_8_128 = /^[A-Za-z0-9._:-]{8,128}$/u;
const APPROVER_ID = /^[A-Za-z0-9._:-]{3,128}$/u;
const DEVICE_ID = /^[A-Za-z0-9._:-]{16,128}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const CURRENCY = /^[A-Z]{3}$/u;
const AMOUNT_MINOR = /^[0-9]+$/u;
const AMOUNT_DECIMAL = /^(0|[1-9][0-9]*)(\.[0-9]{1,2})?$/u;
const BBAN_VALUE = /^[0-9]{14}$/u;
const DISPLAY_UNSAFE = /[\p{Cc}\p{Cf}\p{Cs}\p{Noncharacter_Code_Point}]/u;
const MAX_BANK_BODY_FIELD = 256;
const MAX_AMOUNT_MINOR = 10n ** 15n;
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/u;
const NO_LINE_BREAKS = /^[^\r\n]*$/u;
const MAX_BUNDLE_PAYMENTS = 200;
const MAX_BODY_BASE64URL_LENGTH = 350000;
const BANK_SIGNED_HEADER_COUNT = 5;
const BANK_READ_SIGNED_HEADER_COUNT = 3;
const MAX_POLLING_CAPABILITY_REQUESTS = 2500;
const MAX_POLLING_EXTERNAL_IDS = 20;
const ORIGINATING_HOST_HEADER = /^x-[a-z0-9-]+-originating-host$/u;
const ORIGINATING_DATE_HEADER = /^x-[a-z0-9-]+-originating-date$/u;
const PROTOCOL_RELEASE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{7,127}$/u;

// Protocol release-id binding (issue #71). PROTOCOL_RELEASE_ID is derived from
// this build's canonical core (tools/generate-protocol-release.mjs) and bound
// into the signed bytes of the auth + bundle-approval envelopes. The verifier
// rejects an envelope whose id is not on its allowlist with a DISTINCT error, so
// deploy skew between the phone and the backend fails closed and attributably
// instead of as an opaque signature mismatch at payment time.
export { PROTOCOL_RELEASE_ID };
export const ACCEPTED_PROTOCOL_RELEASE_IDS = Object.freeze([PROTOCOL_RELEASE_ID]);

export class ProtocolReleaseError extends Error {
  constructor(message, releaseId) {
    super(message);
    this.name = "ProtocolReleaseError";
    this.code = "protocol_release_rejected";
    this.releaseId = releaseId;
  }
}

// Verifier-side gate: throws ProtocolReleaseError (NOT a generic signature
// failure) when the carried protocol_release_id is missing, malformed, or not on
// the allowlist. `accepted` lets a deployment widen the set during a rolling
// protocol bump.
export function assertAcceptedProtocolReleaseId(releaseId, accepted = ACCEPTED_PROTOCOL_RELEASE_IDS) {
  if (typeof releaseId !== "string" || !PROTOCOL_RELEASE_ID_PATTERN.test(releaseId)) {
    throw new ProtocolReleaseError("protocol_release_id is missing or malformed", releaseId);
  }
  if (!accepted.includes(releaseId)) {
    throw new ProtocolReleaseError(`protocol_release_id "${releaseId}" is not an accepted protocol release`, releaseId);
  }
  return releaseId;
}

// Signer-side: every signed envelope carries protocol_release_id in its canonical
// bytes. Verification re-derives the exact bytes from the wire envelope, so the
// canonical builders read the carried value; signers that omit it default to this
// build's id.
function resolveProtocolReleaseId(value) {
  const releaseId = value ?? PROTOCOL_RELEASE_ID;
  if (typeof releaseId !== "string" || !PROTOCOL_RELEASE_ID_PATTERN.test(releaseId)) {
    throw new RangeError("protocol_release_id is invalid");
  }
  return releaseId;
}

function assertPattern(name, value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new RangeError(`${name} is invalid`);
  }
}

function assertHex64(name, value) {
  assertPattern(name, value, HEX_64);
}

// RFC 3339 date-time: a date, a 'T' separator, a time, and a 'Z' or numeric
// offset. This matches the JSON Schemas' "format": "date-time" and rejects
// date-only strings (e.g. "2026-05-15") that Date.parse would otherwise accept.
const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/u;

function assertDateTime(name, value) {
  if (typeof value !== "string" || !ISO_DATE_TIME.test(value) || Number.isNaN(Date.parse(value))) {
    throw new RangeError(`${name} must be an ISO date-time`);
  }
}

function assertPaymentCount(value) {
  if (!Number.isInteger(value) || value < 1 || value > MAX_BUNDLE_PAYMENTS) {
    throw new RangeError(`payment_count must be in range 1..${MAX_BUNDLE_PAYMENTS}`);
  }
}

function assertNoLineBreaks(name, value, maxLength) {
  if (typeof value !== "string" || value.length > maxLength || !NO_LINE_BREAKS.test(value)) {
    throw new RangeError(`${name} must not contain line breaks and must be at most ${maxLength} characters`);
  }
}

function assertPrintableHeaderValue(name, value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 512 || !PRINTABLE_ASCII.test(value)) {
    throw new RangeError(`${name} must be 1..512 printable ASCII characters`);
  }
}

function sameJSON(a, b) {
  return stableStringify(a) === stableStringify(b);
}

function bytesToBase64(bytes) {
  if (typeof btoa !== "function") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}

function hexToBase64(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytesToBase64(bytes);
}

function decimalAmountToMinor(value) {
  // Amounts MUST arrive as their canonical decimal string. A JS number could
  // already have lost precision in JSON.parse (any integer minor unit > 2^53
  // rounds), so accepting one here would let the displayed/derived amount_minor
  // silently diverge from the signed bytes. Parse the digits with BigInt only.
  if (typeof value !== "string") {
    throw new TypeError("amount must be a decimal string, not a JS number");
  }
  const match = /^([0-9]+)(?:\.([0-9]{1,2}))?$/u.exec(value);
  if (!match) {
    return "";
  }
  const [, whole, fractional = ""] = match;
  return (BigInt(whole) * 100n + BigInt(fractional.padEnd(2, "0"))).toString();
}

function maskAccount(value) {
  const text = String(value ?? "");
  if (text.length <= 8) {
    return text;
  }
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

export async function canonicalBackendAuthEnvelopeV1(input, cryptoProvider = globalThis.crypto) {
  const method = input.method?.toUpperCase();
  if (!["GET", "POST"].includes(method)) {
    throw new RangeError("backend auth method must be GET or POST");
  }
  if (!BACKEND_PATH.test(input.path)) {
    throw new RangeError("backend auth path is not allowlisted");
  }

  const bodyBytes = input.bodyBytes ?? new Uint8Array();
  const bodySha256 = input.body_sha256 ?? await sha256Hex(bodyBytes, cryptoProvider);
  if (!HEX_64.test(bodySha256)) {
    throw new RangeError("body_sha256 must be lowercase SHA-256 hex");
  }

  return canonicalText("APPROVAL_BACKEND_API_AUTH_V1", [
    ["protocol_release_id", resolveProtocolReleaseId(input.protocol_release_id), "string"],
    ["method", method, "string"],
    ["path", input.path, "string"],
    ["body_sha256", bodySha256, "string"],
    ["approver_id", input.approver_id, "string"],
    ["device_id", input.device_id, "string"],
    ["share_index", input.share_index, "integer"],
    ["key_id", input.key_id, "string"],
    ["timestamp", input.timestamp, "string"],
    ["server_nonce", input.server_nonce, "string"],
    ["client_nonce", input.client_nonce, "string"]
  ]);
}

export async function canonicalBackendResponseEnvelopeV1(input, cryptoProvider = globalThis.crypto) {
  const method = input.method?.toUpperCase();
  if (!["GET", "POST"].includes(method)) {
    throw new RangeError("backend response method must be GET or POST");
  }
  if (!BACKEND_PATH.test(input.path)) {
    throw new RangeError("backend response path is not allowlisted");
  }
  if (!Number.isInteger(input.status) || input.status < 100 || input.status > 599) {
    throw new RangeError("backend response status must be an HTTP status code");
  }

  const bodyBytes = input.bodyBytes ?? new Uint8Array();
  const bodySha256 = input.body_sha256 ?? await sha256Hex(bodyBytes, cryptoProvider);
  if (!HEX_64.test(bodySha256)) {
    throw new RangeError("body_sha256 must be lowercase SHA-256 hex");
  }
  assertPattern("approver_id", input.approver_id, APPROVER_ID);
  assertPattern("device_id", input.device_id, DEVICE_ID);
  if (![3, 4].includes(input.share_index)) {
    throw new RangeError("share_index must be 3 or 4");
  }
  assertPattern("key_id", input.key_id, ID_8_128);
  assertDateTime("response_timestamp", input.response_timestamp);

  return canonicalText("APPROVAL_BACKEND_RESPONSE_V1", [
    ["method", method, "string"],
    ["path", input.path, "string"],
    ["status", input.status, "integer"],
    ["body_sha256", bodySha256, "string"],
    ["approver_id", input.approver_id, "string"],
    ["device_id", input.device_id, "string"],
    ["share_index", input.share_index, "integer"],
    ["key_id", input.key_id, "string"],
    ["request_server_nonce", input.request_server_nonce ?? "-", "string"],
    ["request_client_nonce", input.request_client_nonce ?? "-", "string"],
    ["response_timestamp", input.response_timestamp, "string"]
  ]);
}

// The eight scalar fields that are actually emitted into (and signed as) the
// APPROVAL_BUNDLE_APPROVAL_V1 canonical text. Kept separate from the full
// wire-object validator (validateBundleApprovalEnvelopeInputV1) so the canonical
// signer does not require the authorization fields (totals, webauthn_assertion,
// phone_sign_shares) it never serializes.
function assertBundleApprovalCanonicalFieldsV1(input) {
  assertPattern("bundle_id", input.bundle_id, ID_8_128);
  assertHex64("bundle_hash_sha256", input.bundle_hash_sha256);
  assertPaymentCount(input.payment_count);
  assertPattern("approver_id", input.approver_id, APPROVER_ID);
  assertPattern("device_id", input.device_id, DEVICE_ID);
  if (![3, 4].includes(input.share_index)) {
    throw new RangeError("share_index must be 3 or 4");
  }
  assertPattern("key_id", input.key_id, ID_8_128);
  assertDateTime("approved_at", input.approved_at);
}

export function canonicalBundleApprovalEnvelopeV1(input) {
  if (input?.version !== undefined && input.version !== "bundle_approval_v1") {
    throw new RangeError("bundle approval version must be bundle_approval_v1");
  }
  assertBundleApprovalCanonicalFieldsV1(input);

  return canonicalText("APPROVAL_BUNDLE_APPROVAL_V1", [
    ["protocol_release_id", resolveProtocolReleaseId(input.protocol_release_id), "string"],
    ["bundle_id", input.bundle_id, "string"],
    ["bundle_hash_sha256", input.bundle_hash_sha256, "string"],
    ["payment_count", input.payment_count, "integer"],
    ["approver_id", input.approver_id, "string"],
    ["device_id", input.device_id, "string"],
    ["share_index", input.share_index, "integer"],
    ["key_id", input.key_id, "string"],
    ["approved_at", input.approved_at, "string"]
  ]);
}

export async function webauthnApprovalChallengeV1(input, cryptoProvider = globalThis.crypto) {
  assertPattern("bundle_id", input.bundle_id, ID_8_128);
  assertHex64("bundle_hash_sha256", input.bundle_hash_sha256);
  assertPaymentCount(input.payment_count);
  assertPattern("approver_id", input.approver_id, APPROVER_ID);
  assertPattern("device_id", input.device_id, DEVICE_ID);
  if (![3, 4].includes(input.share_index)) {
    throw new RangeError("share_index must be 3 or 4");
  }
  assertPattern("key_id", input.key_id, ID_8_128);
  assertPattern("credential_id", input.credential_id, BASE64URL);
  // #19: fold a server-issued, single-use, expiring nonce (and its
  // server-authoritative expiry) into the challenge so the WebAuthn assertion is
  // FRESH. Without this the challenge is fully client-derived and deterministic
  // for a given bundle, so an assertion for that bundle could be REPLAYED. The
  // backend issues challenge_nonce from /api/approval/webauthn-challenge-nonce,
  // recomputes this exact challenge with the stored nonce + expiry, verifies the
  // assertion against it, and consumes the nonce (single-use) — rejecting replays.
  assertPattern("challenge_nonce", input.challenge_nonce, BASE64URL);
  assertDateTime("challenge_nonce_expires_at", input.challenge_nonce_expires_at);

  const challengeContext = canonicalText("APPROVAL_WEBAUTHN_BUNDLE_APPROVAL_V1", [
    ["protocol_release_id", resolveProtocolReleaseId(input.protocol_release_id), "string"],
    ["bundle_id", input.bundle_id, "string"],
    ["bundle_hash_sha256", input.bundle_hash_sha256, "string"],
    ["payment_count", input.payment_count, "integer"],
    ["approver_id", input.approver_id, "string"],
    ["device_id", input.device_id, "string"],
    ["share_index", input.share_index, "integer"],
    ["key_id", input.key_id, "string"],
    ["credential_id", input.credential_id, "string"],
    ["challenge_nonce", input.challenge_nonce, "string"],
    ["challenge_nonce_expires_at", input.challenge_nonce_expires_at, "string"]
  ]);
  return sha256(challengeContext, cryptoProvider);
}

// Step-up challenge for ADDING a new WebAuthn credential once an approver/device
// context is ALREADY enrolled. It must be signed by an EXISTING enrolled
// credential for that context, proving possession of the current passkey — so a
// holder of a stolen phone share alone cannot graft an attacker passkey onto a
// victim's context (the credential is a true second factor). A fresh, single-use,
// expiring nonce makes it non-replayable, and the NEW credential id + public key
// are bound in so a captured step-up assertion cannot authorize a different key.
export async function webauthnEnrollmentStepUpChallengeV1(input, cryptoProvider = globalThis.crypto) {
  assertPattern("approver_id", input.approver_id, APPROVER_ID);
  assertPattern("device_id", input.device_id, DEVICE_ID);
  if (![3, 4].includes(input.share_index)) {
    throw new RangeError("share_index must be 3 or 4");
  }
  assertPattern("key_id", input.key_id, ID_8_128);
  assertPattern("new_credential_id", input.new_credential_id, BASE64URL);
  assertPattern("new_public_key_spki_base64url", input.new_public_key_spki_base64url, BASE64URL);
  assertPattern("challenge_nonce", input.challenge_nonce, BASE64URL);
  assertDateTime("challenge_nonce_expires_at", input.challenge_nonce_expires_at);

  const challengeContext = canonicalText("APPROVAL_WEBAUTHN_ENROLLMENT_STEP_UP_V1", [
    ["approver_id", input.approver_id, "string"],
    ["device_id", input.device_id, "string"],
    ["share_index", input.share_index, "integer"],
    ["key_id", input.key_id, "string"],
    ["new_credential_id", input.new_credential_id, "string"],
    ["new_public_key_spki_base64url", input.new_public_key_spki_base64url, "string"],
    ["challenge_nonce", input.challenge_nonce, "string"],
    ["challenge_nonce_expires_at", input.challenge_nonce_expires_at, "string"]
  ]);
  return sha256(challengeContext, cryptoProvider);
}

function assertBankSigningInputShapeV1(input) {
  if (input?.version !== "bank_signing_input_v1") {
    throw new RangeError("Bank signing input version must be bank_signing_input_v1");
  }
  assertPattern("request_id", input.request_id, ID_8_128);
  if (input.method !== "POST") {
    throw new RangeError("Bank v1 signing input supports POST only");
  }
  if (!input.path?.startsWith("/corporate/premium/v2/")) {
    throw new RangeError("Bank path must be a Corporate Payout v2 path");
  }
  if (
    typeof input.body_base64url !== "string" ||
    input.body_base64url.length < 2 ||
    input.body_base64url.length > MAX_BODY_BASE64URL_LENGTH ||
    !BASE64URL.test(input.body_base64url)
  ) {
    throw new RangeError("body_base64url must be bounded unpadded base64url");
  }
  assertHex64("body_sha256", input.body_sha256);
  normalizeVisiblePaymentV1(input.visible_payment);
}

function assertBankReadSigningInputShapeV1(input) {
  // Allow-list matching bank_read_signing_input_v1.schema.json (required +
  // optional), so unmodeled fields are rejected like the schema's
  // additionalProperties:false. A bare read carries only the required keys; the
  // polling-capability extras (scope/slot_index/.../phone_sign_share_base64url)
  // are optional here and are further validated by validatePollingCapabilityPackageV1.
  assertModeledObject(
    "bank read signing input",
    input,
    ["version", "request_id", "method", "path", "signed_headers"],
    ["scope", "slot_index", "deterministic_index", "chunk_index", "external_ids", "phone_sign_share_base64url"]
  );
  if (input.version !== "bank_read_signing_input_v1") {
    throw new RangeError("Bank read signing input version must be bank_read_signing_input_v1");
  }
  assertPattern("request_id", input.request_id, ID_8_128);
  if (input.method !== "GET") {
    throw new RangeError("Bank read v1 signing input supports GET only");
  }
  if (!input.path?.startsWith("/corporate/")) {
    throw new RangeError("Bank read path must be a corporate API path");
  }
  assertNoLineBreaks("Bank read path", input.path, 2048);
}

function validateBankSignedHeadersV1(headers, bodySha256) {
  if (!Array.isArray(headers) || headers.length !== BANK_SIGNED_HEADER_COUNT) {
    throw new RangeError(`signed_headers must contain exactly ${BANK_SIGNED_HEADER_COUNT} headers`);
  }

  const expectedDigest = `SHA-256=${hexToBase64(bodySha256)}`;
  const seen = new Set();
  return headers.map((header, index) => {
    if (!header || typeof header !== "object") {
      throw new RangeError("signed_headers entries must be objects");
    }
    const { name, value } = header;
    if (seen.has(name)) {
      throw new RangeError(`duplicate signed header ${name}`);
    }
    seen.add(name);
    if (!PRINTABLE_ASCII.test(name)) {
      throw new RangeError("signed header names must be printable ASCII");
    }
    if (index === 0 && name !== "(request-target)") {
      throw new RangeError("signed header 1 must be (request-target)");
    }
    if (index === 1 && !ORIGINATING_HOST_HEADER.test(name)) {
      throw new RangeError("signed header 2 must be an originating host header");
    }
    if (index === 2 && !ORIGINATING_DATE_HEADER.test(name)) {
      throw new RangeError("signed header 3 must be an originating date header");
    }
    if (index === 3 && name !== "content-type") {
      throw new RangeError("signed header 4 must be content-type");
    }
    if (index === 4 && name !== "digest") {
      throw new RangeError("signed header 5 must be digest");
    }
    if (name === "(request-target)") {
      if (value !== "") {
        throw new RangeError("(request-target) signed header value must be empty");
      }
    } else {
      assertPrintableHeaderValue(`signed header ${name}`, value);
    }
    if (name === "content-type" && value !== "application/json") {
      throw new RangeError("content-type signed header must be application/json");
    }
    if (name === "digest" && value !== expectedDigest) {
      throw new RangeError("digest signed header must match body_sha256");
    }
    return { name, value };
  });
}

function validateBankReadSignedHeadersV1(headers) {
  if (!Array.isArray(headers) || headers.length !== BANK_READ_SIGNED_HEADER_COUNT) {
    throw new RangeError(`read signed_headers must contain exactly ${BANK_READ_SIGNED_HEADER_COUNT} headers`);
  }

  const seen = new Set();
  return headers.map((header, index) => {
    if (!header || typeof header !== "object") {
      throw new RangeError("read signed_headers entries must be objects");
    }
    const { name, value } = header;
    if (seen.has(name)) {
      throw new RangeError(`duplicate read signed header ${name}`);
    }
    seen.add(name);
    if (!PRINTABLE_ASCII.test(name)) {
      throw new RangeError("read signed header names must be printable ASCII");
    }
    if (index === 0 && name !== "(request-target)") {
      throw new RangeError("read signed header 1 must be (request-target)");
    }
    if (index === 1 && !ORIGINATING_HOST_HEADER.test(name)) {
      throw new RangeError("read signed header 2 must be an originating host header");
    }
    if (index === 2 && !ORIGINATING_DATE_HEADER.test(name)) {
      throw new RangeError("read signed header 3 must be an originating date header");
    }
    if (name === "(request-target)") {
      if (value !== "") {
        throw new RangeError("(request-target) read signed header value must be empty");
      }
    } else {
      assertPrintableHeaderValue(`read signed header ${name}`, value);
    }
    return { name, value };
  });
}

export function bankHttpSigningStringV1(input) {
  assertBankSigningInputShapeV1(input);
  const headers = validateBankSignedHeadersV1(input.signed_headers, input.body_sha256);

  const lines = headers.map(({ name, value }) => {
    if (name === "(request-target)") {
      return `(request-target): ${input.method.toLowerCase()} ${input.path}`;
    }
    return `${name}: ${value}`;
  });
  return lines.join("\n");
}

export function bankReadHttpSigningStringV1(input) {
  assertBankReadSigningInputShapeV1(input);
  const headers = validateBankReadSignedHeadersV1(input.signed_headers);

  return headers.map(({ name, value }) => {
    if (name === "(request-target)") {
      return `(request-target): ${input.method.toLowerCase()} ${input.path}`;
    }
    return `${name}: ${value}`;
  }).join("\n");
}

export function normalizeVisiblePaymentV1(payment) {
  if (!payment || typeof payment !== "object") {
    throw new RangeError("visible_payment is required");
  }

  assertNoLineBreaks("creditor_name", payment.creditor_name, 140);
  if (payment.creditor_name.length < 1) {
    throw new RangeError("creditor_name is required");
  }
  assertNoLineBreaks("creditor_account", payment.creditor_account, 64);
  if (payment.creditor_account.length < 4) {
    throw new RangeError("creditor_account must be at least 4 characters");
  }
  const debtorAccountMasked = payment.debtor_account_masked ?? "";
  assertNoLineBreaks("debtor_account_masked", debtorAccountMasked, 64);
  assertPattern("amount_minor", payment.amount_minor, AMOUNT_MINOR);
  assertPattern("currency", payment.currency, CURRENCY);
  const remittanceText = payment.remittance_text ?? "";
  assertNoLineBreaks("remittance_text", remittanceText, 140);

  return {
    creditor_name: payment.creditor_name,
    creditor_account: payment.creditor_account,
    debtor_account_masked: debtorAccountMasked,
    amount_minor: payment.amount_minor,
    currency: payment.currency,
    remittance_text: remittanceText
  };
}

// Strict JSON parse for the bank request body. Standard JSON, but it rejects duplicate object
// member names — an "ambiguous encoding": JSON.parse silently keeps last-wins while the bank's
// parser may keep first, so identical signed bytes could be displayed one way and executed
// another. Member assignment uses defineProperty (never `object[key] = ...`) so a "__proto__"
// member cannot poison the prototype chain.
function parseStrictJson(text) {
  let i = 0;
  const length = text.length;
  const fail = (message) => {
    throw new Error(`bank request body is not strict JSON: ${message}`);
  };
  const skipWhitespace = () => {
    while (i < length) {
      const char = text[i];
      if (char === " " || char === "\t" || char === "\n" || char === "\r") {
        i += 1;
      } else {
        break;
      }
    }
  };

  function parseString() {
    i += 1;
    let out = "";
    while (i < length) {
      const char = text[i];
      if (char === "\"") {
        i += 1;
        return out;
      }
      if (char === "\\") {
        const escape = text[i + 1];
        if (escape === "\"" || escape === "\\" || escape === "/") { out += escape; i += 2; continue; }
        if (escape === "b") { out += "\b"; i += 2; continue; }
        if (escape === "f") { out += "\f"; i += 2; continue; }
        if (escape === "n") { out += "\n"; i += 2; continue; }
        if (escape === "r") { out += "\r"; i += 2; continue; }
        if (escape === "t") { out += "\t"; i += 2; continue; }
        if (escape === "u") {
          const hex = text.slice(i + 2, i + 6);
          if (!/^[0-9a-fA-F]{4}$/u.test(hex)) { fail("invalid unicode escape"); }
          out += String.fromCharCode(Number.parseInt(hex, 16));
          i += 6;
          continue;
        }
        fail("invalid string escape");
      }
      if (char < " ") { fail("unescaped control character in string"); }
      out += char;
      i += 1;
    }
    fail("unterminated string");
  }

  function parseNumber() {
    const start = i;
    if (text[i] === "-") { i += 1; }
    while (i < length && text[i] >= "0" && text[i] <= "9") { i += 1; }
    if (text[i] === ".") {
      i += 1;
      while (i < length && text[i] >= "0" && text[i] <= "9") { i += 1; }
    }
    if (text[i] === "e" || text[i] === "E") {
      i += 1;
      if (text[i] === "+" || text[i] === "-") { i += 1; }
      while (i < length && text[i] >= "0" && text[i] <= "9") { i += 1; }
    }
    const token = text.slice(start, i);
    if (!/^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$/u.test(token)) { fail("invalid number"); }
    return Number(token);
  }

  function parseValue() {
    skipWhitespace();
    if (i >= length) { fail("unexpected end of input"); }
    const char = text[i];
    if (char === "{") { return parseObject(); }
    if (char === "[") { return parseArray(); }
    if (char === "\"") { return parseString(); }
    if (char === "-" || (char >= "0" && char <= "9")) { return parseNumber(); }
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    fail("unexpected token");
  }

  function parseArray() {
    i += 1;
    const array = [];
    skipWhitespace();
    if (text[i] === "]") { i += 1; return array; }
    for (;;) {
      array.push(parseValue());
      skipWhitespace();
      if (text[i] === ",") { i += 1; continue; }
      if (text[i] === "]") { i += 1; return array; }
      fail("expected ',' or ']'");
    }
  }

  function parseObject() {
    i += 1;
    const object = {};
    const seen = new Set();
    skipWhitespace();
    if (text[i] === "}") { i += 1; return object; }
    for (;;) {
      skipWhitespace();
      if (text[i] !== "\"") { fail("expected object member name"); }
      const key = parseString();
      if (seen.has(key)) { fail(`duplicate object member name ${JSON.stringify(key)}`); }
      seen.add(key);
      skipWhitespace();
      if (text[i] !== ":") { fail("expected ':'"); }
      i += 1;
      const value = parseValue();
      Object.defineProperty(object, key, { value, writable: true, enumerable: true, configurable: true });
      skipWhitespace();
      if (text[i] === ",") { i += 1; continue; }
      if (text[i] === "}") { i += 1; return object; }
      fail("expected ',' or '}'");
    }
  }

  const result = parseValue();
  skipWhitespace();
  if (i !== length) { fail("unexpected trailing content"); }
  return result;
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function assertModeledObject(name, value, requiredKeys, optionalKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RangeError(`${name} must be an object`);
  }
  const allowed = new Set([...requiredKeys, ...optionalKeys]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new RangeError(`${name} has unmodeled field "${key}"`);
    }
  }
  for (const key of requiredKeys) {
    if (!hasOwn(value, key)) {
      throw new RangeError(`${name} is missing required field "${key}"`);
    }
  }
}

function assertDisplaySafeText(name, value, maxLength) {
  assertNoLineBreaks(name, value, maxLength);
  if (DISPLAY_UNSAFE.test(value)) {
    throw new RangeError(`${name} must not contain unsafe display characters`);
  }
}

function assertOptionalDisplaySafeText(name, object, key, maxLength) {
  if (hasOwn(object, key)) {
    assertDisplaySafeText(`${name}.${key}`, object[key], maxLength);
  }
}

function assertModeledBbanAccount(name, account, optionalKeys) {
  assertModeledObject(name, account, ["type", "value"], optionalKeys);
  // `type` selects the account-numbering rail and is bank-honored; an unmodeled rail could route
  // the same digit string to a different recipient, so pin it to the only sandbox-confirmed value.
  if (account.type !== "BBAN") {
    throw new RangeError(`${name}.type must be "BBAN"`);
  }
  assertPattern(`${name}.value`, account.value, BBAN_VALUE);
}

// Pinned Nordea Corporate Payout v2 request body schema — the sandbox-confirmed DK shape produced
// by the demo fixtures. This is an allow-list: every modeled key is validated and ANY unmodeled key,
// at any nesting level, is rejected (fail closed). A WYSIWYS signer must provably model 100% of
// bank-honored content, so the production system must extend this allow-list to every field the real
// Nordea request sends — reflecting any recipient/amount-determining field in the visible payment and
// rejecting anything it does not model.
function parseBankBodyV1(bodyBytes) {
  let body;
  try {
    // Fatal UTF-8 decode: reject (rather than silently U+FFFD-replace) non-UTF-8 bytes, so what the
    // approver sees cannot diverge from the signed bytes the bank parses.
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
    body = parseStrictJson(text);
  } catch (error) {
    throw new Error(`Bank request body must be JSON for visible payment derivation: ${error.message}`);
  }

  // end_to_end_id / external_id are execution-neutral references (passed through to statements and
  // used for backend idempotency/matching); neither determines recipient or amount, so they are
  // allow-listed but not displayed.
  assertModeledObject(
    "bank body",
    body,
    ["template_id", "amount", "currency", "debtor", "creditor"],
    ["end_to_end_id", "external_id"]
  );
  if (body.template_id !== "INSTANT_CREDIT_TRANSFER_DK") {
    throw new RangeError("template_id must be \"INSTANT_CREDIT_TRANSFER_DK\"");
  }
  assertPattern("amount", body.amount, AMOUNT_DECIMAL);
  if (body.currency !== "DKK") {
    throw new RangeError("currency must be \"DKK\"");
  }
  assertOptionalDisplaySafeText("bank body", body, "end_to_end_id", MAX_BANK_BODY_FIELD);
  assertOptionalDisplaySafeText("bank body", body, "external_id", MAX_BANK_BODY_FIELD);

  // own_reference is the debtor's own statement text; debtor.account.currency is the funding-account
  // currency (equal to the payment currency in the confirmed DK scope) — both execution-neutral here.
  assertModeledObject("debtor", body.debtor, ["account"], ["own_reference"]);
  assertOptionalDisplaySafeText("debtor", body.debtor, "own_reference", MAX_BANK_BODY_FIELD);
  assertModeledBbanAccount("debtor.account", body.debtor.account, ["currency"]);
  if (hasOwn(body.debtor.account, "currency") && body.debtor.account.currency !== "DKK") {
    throw new RangeError("debtor.account.currency must be \"DKK\"");
  }

  assertModeledObject("creditor", body.creditor, ["name", "account"], ["bank", "message"]);
  assertDisplaySafeText("creditor.name", body.creditor.name, 140);
  if (body.creditor.name.length < 1) {
    throw new RangeError("creditor.name is required");
  }
  assertOptionalDisplaySafeText("creditor", body.creditor, "message", 140);
  assertModeledBbanAccount("creditor.account", body.creditor.account, []);
  if (hasOwn(body.creditor, "bank")) {
    // bank.bank_code is bound to the signed BBAN (validated against the registration prefix in
    // domesticAccountDisplay); bank.country is a display hint.
    assertModeledObject("creditor.bank", body.creditor.bank, [], ["country", "bank_code"]);
    if (hasOwn(body.creditor.bank, "country") && body.creditor.bank.country !== "DK") {
      throw new RangeError("creditor.bank.country must be \"DK\"");
    }
    assertOptionalDisplaySafeText("creditor.bank", body.creditor.bank, "bank_code", 16);
  }

  return body;
}

function domesticAccountDisplay(account, bank, body) {
  // `account` is already validated as a BBAN with a 14-digit value by parseBankBodyV1.
  const value = account.value;
  const templateId = body.template_id;
  if (bank?.country === "DK" || bank?.bank_code || templateId.endsWith("_DK") || body.currency === "DKK") {
    const regCode = value.slice(0, 4);
    if (typeof bank?.bank_code === "string" && bank.bank_code && bank.bank_code !== regCode) {
      throw new Error("creditor bank_code does not match BBAN registration number");
    }
    return `${regCode} ${value.slice(4)}`;
  }
  return value;
}

export function deriveVisiblePaymentFromBankBodyV1(bodyBytes) {
  const body = parseBankBodyV1(bodyBytes);

  const amountMinor = decimalAmountToMinor(body.amount);
  const minor = BigInt(amountMinor);
  if (minor <= 0n) {
    throw new RangeError("amount must be greater than zero");
  }
  if (minor > MAX_AMOUNT_MINOR) {
    throw new RangeError("amount exceeds the maximum supported value");
  }

  return normalizeVisiblePaymentV1({
    creditor_name: body.creditor.name,
    creditor_account: domesticAccountDisplay(body.creditor.account, body.creditor.bank, body),
    debtor_account_masked: maskAccount(body.debtor.account.value),
    amount_minor: amountMinor,
    currency: body.currency,
    remittance_text: hasOwn(body.creditor, "message") ? body.creditor.message : ""
  });
}

export function calculateTotalsFromVisiblePaymentsV1(visiblePayments) {
  const totals = new Map();
  for (const payment of visiblePayments) {
    const normalized = normalizeVisiblePaymentV1(payment);
    const current = totals.get(normalized.currency) ?? 0n;
    totals.set(normalized.currency, current + BigInt(normalized.amount_minor));
  }

  return [...totals.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([currency, amount]) => ({
      currency,
      amount_minor: amount.toString()
    }));
}

export async function visibleLineItemHashV1(payment, cryptoProvider = globalThis.crypto) {
  return sha256Hex(canonicalJsonBytes(normalizeVisiblePaymentV1(payment)), cryptoProvider);
}

export async function validateBankSigningInputV1(input, cryptoProvider = globalThis.crypto) {
  assertBankSigningInputShapeV1(input);
  const bodyBytes = base64urlToBytes(input.body_base64url);
  const actualBodyHash = bytesToHex(await sha256(bodyBytes, cryptoProvider));
  if (actualBodyHash !== input.body_sha256) {
    throw new Error("Bank body hash mismatch");
  }

  const visiblePayment = deriveVisiblePaymentFromBankBodyV1(bodyBytes);
  const suppliedVisiblePayment = normalizeVisiblePaymentV1(input.visible_payment);
  if (!sameJSON(visiblePayment, suppliedVisiblePayment)) {
    throw new Error("visible payment mismatch");
  }

  const signingString = bankHttpSigningStringV1(input);
  const signingStringBytes = utf8Encode(signingString);
  return {
    bodyBytes,
    bodySha256: actualBodyHash,
    visiblePayment,
    signingString,
    signingStringBytes
  };
}

export async function bankSigningInputCommitmentV1(input, cryptoProvider = globalThis.crypto) {
  const validation = await validateBankSigningInputV1(input, cryptoProvider);
  const bankRequestHash = await sha256Hex(canonicalJsonBytes({
    version: input.version,
    request_id: input.request_id,
    method: input.method,
    path: input.path,
    signed_headers: validateBankSignedHeadersV1(input.signed_headers, validation.bodySha256),
    body_sha256: validation.bodySha256
  }), cryptoProvider);
  const visibleLineItemHash = await visibleLineItemHashV1(validation.visiblePayment, cryptoProvider);

  return {
    request_id: input.request_id,
    bank_request_hash: bankRequestHash,
    visible_line_item_hash: visibleLineItemHash,
    visible_payment: validation.visiblePayment,
    body_sha256: validation.bodySha256,
    signing_string: validation.signingString
  };
}

function validateBundleHashPartsV1(parts) {
  assertPattern("bundle_id", parts.bundle_id, ID_8_128);
  assertPattern("bundle_version", parts.bundle_version, /^[A-Za-z0-9._:-]{3,128}$/u);
  assertPaymentCount(parts.payment_count);
  if (!Array.isArray(parts.totals) || parts.totals.length < 1 || parts.totals.length > 10) {
    throw new RangeError("totals must contain 1..10 currency totals");
  }
  for (const total of parts.totals) {
    assertPattern("total currency", total.currency, CURRENCY);
    assertPattern("total amount_minor", total.amount_minor, AMOUNT_MINOR);
  }
  if (!Array.isArray(parts.bank_request_hashes) || parts.bank_request_hashes.length !== parts.payment_count) {
    throw new RangeError("bank_request_hashes length must equal payment_count");
  }
  if (!Array.isArray(parts.visible_line_item_hashes) || parts.visible_line_item_hashes.length !== parts.payment_count) {
    throw new RangeError("visible_line_item_hashes length must equal payment_count");
  }
  for (const hash of [...parts.bank_request_hashes, ...parts.visible_line_item_hashes]) {
    assertHex64("commitment hash", hash);
  }
}

export async function bundleHashV1(parts, cryptoProvider = globalThis.crypto) {
  validateBundleHashPartsV1(parts);
  return sha256Hex(canonicalJsonBytes({
    version: "bundle_hash_v1",
    bundle_id: parts.bundle_id,
    bundle_version: parts.bundle_version,
    payment_count: parts.payment_count,
    totals: parts.totals,
    bank_request_hashes: parts.bank_request_hashes,
    visible_line_item_hashes: parts.visible_line_item_hashes
  }), cryptoProvider);
}

export async function bundleCommitmentsForInputsV1({
  bundleId,
  bundleVersion,
  paymentInputs
}, cryptoProvider = globalThis.crypto) {
  assertPattern("bundle_id", bundleId, ID_8_128);
  assertPattern("bundle_version", bundleVersion, /^[A-Za-z0-9._:-]{3,128}$/u);
  if (!Array.isArray(paymentInputs) || paymentInputs.length < 1 || paymentInputs.length > MAX_BUNDLE_PAYMENTS) {
    throw new RangeError(`paymentInputs must contain 1..${MAX_BUNDLE_PAYMENTS} payments`);
  }

  const bankRequestHashes = [];
  const visibleLineItemHashes = [];
  const visiblePayments = [];
  for (const input of paymentInputs) {
    const commitment = await bankSigningInputCommitmentV1(input, cryptoProvider);
    bankRequestHashes.push(commitment.bank_request_hash);
    visibleLineItemHashes.push(commitment.visible_line_item_hash);
    visiblePayments.push(commitment.visible_payment);
  }

  const totals = calculateTotalsFromVisiblePaymentsV1(visiblePayments);
  const paymentCount = paymentInputs.length;
  const bundleHash = await bundleHashV1({
    bundle_id: bundleId,
    bundle_version: bundleVersion,
    payment_count: paymentCount,
    totals,
    bank_request_hashes: bankRequestHashes,
    visible_line_item_hashes: visibleLineItemHashes
  }, cryptoProvider);

  return {
    payment_count: paymentCount,
    totals,
    bank_request_hashes: bankRequestHashes,
    visible_line_item_hashes: visibleLineItemHashes,
    bundle_hash_sha256: bundleHash
  };
}

export async function validateBundleForApprovalV1(bundle, cryptoProvider = globalThis.crypto) {
  if (!bundle || typeof bundle !== "object") {
    throw new RangeError("bundle is required");
  }
  const commitments = await bundleCommitmentsForInputsV1({
    bundleId: bundle.bundle_id,
    bundleVersion: bundle.version,
    paymentInputs: bundle.payment_inputs
  }, cryptoProvider);

  if (!sameJSON(bundle.totals, commitments.totals)) {
    throw new Error("bundle totals do not match visible payments");
  }
  if (!sameJSON(bundle.bank_request_hashes, commitments.bank_request_hashes)) {
    throw new Error("bundle Bank request hashes do not match payment inputs");
  }
  if (!sameJSON(bundle.visible_line_item_hashes, commitments.visible_line_item_hashes)) {
    throw new Error("bundle visible line item hashes do not match payment inputs");
  }
  if (bundle.bundle_hash_sha256 !== commitments.bundle_hash_sha256) {
    throw new Error("bundle hash does not match payment commitments");
  }

  return commitments;
}

function assertBundleApprovalHashArray(name, value, paymentCount) {
  if (!Array.isArray(value) || value.length !== paymentCount) {
    throw new RangeError(`${name} length must equal payment_count`);
  }
  for (const hash of value) {
    assertHex64(name, hash);
  }
}

function assertBundleApprovalWebauthnAssertionV1(assertion) {
  assertModeledObject(
    "webauthn_assertion",
    assertion,
    [
      "credential_id",
      "client_data_json_base64url",
      "authenticator_data_base64url",
      "signature_base64url",
      "user_verification",
      // #19: the fresh, single-use challenge nonce + its server-authoritative
      // expiry the assertion was bound to, carried so the backend can recompute
      // the challenge and consume the nonce (rejecting replays).
      "challenge_nonce",
      "challenge_nonce_expires_at"
    ],
    []
  );
  const boundedBase64url = (name, candidate, min, max) => {
    if (typeof candidate !== "string" || candidate.length < min || candidate.length > max || !BASE64URL.test(candidate)) {
      throw new RangeError(`${name} must be ${min}..${max} base64url characters`);
    }
  };
  boundedBase64url("webauthn_assertion.credential_id", assertion.credential_id, 16, 1024);
  boundedBase64url("webauthn_assertion.client_data_json_base64url", assertion.client_data_json_base64url, 16, 8192);
  boundedBase64url("webauthn_assertion.authenticator_data_base64url", assertion.authenticator_data_base64url, 16, 4096);
  boundedBase64url("webauthn_assertion.signature_base64url", assertion.signature_base64url, 16, 2048);
  if (assertion.user_verification !== "required") {
    throw new RangeError("webauthn_assertion.user_verification must be \"required\"");
  }
  boundedBase64url("webauthn_assertion.challenge_nonce", assertion.challenge_nonce, 16, 256);
  assertDateTime("webauthn_assertion.challenge_nonce_expires_at", assertion.challenge_nonce_expires_at);
}

// Authoritative runtime validator for a full bundle_approval_v1 wire object.
// It is kept provably in lock-step with schemas/bundle_approval_v1.schema.json:
// the same allow-listed property set, the same required set, and the same per-
// field constraints (see test/schemas.test.mjs "bundle approval validator
// matches its schema"). JSON Schema cannot express the cross-field rule that
// the per-payment arrays have exactly payment_count entries, so the validator
// is strictly tighter on that one point. The eight scalar fields that are
// actually signed are validated via assertBundleApprovalCanonicalFieldsV1, the
// same helper the canonical text encoder uses.
export function validateBundleApprovalEnvelopeInputV1(input) {
  assertModeledObject(
    "bundle approval",
    input,
    [
      "version",
      "protocol_release_id",
      "bundle_id",
      "bundle_hash_sha256",
      "approver_id",
      "device_id",
      "share_index",
      "key_id",
      "payment_count",
      "totals",
      "bank_request_hashes",
      "visible_line_item_hashes",
      "webauthn_assertion",
      "phone_sign_shares",
      "approved_at"
    ],
    ["polling_capability_package"]
  );
  if (input.version !== "bundle_approval_v1") {
    throw new RangeError("bundle approval version must be bundle_approval_v1");
  }
  assertPattern("protocol_release_id", input.protocol_release_id, PROTOCOL_RELEASE_ID_PATTERN);
  assertBundleApprovalCanonicalFieldsV1(input);

  if (!Array.isArray(input.totals) || input.totals.length < 1 || input.totals.length > 10) {
    throw new RangeError("totals must contain 1..10 currency totals");
  }
  const seenTotals = new Set();
  for (const total of input.totals) {
    assertModeledObject("total", total, ["currency", "amount_minor"], []);
    assertPattern("total currency", total.currency, CURRENCY);
    if (typeof total.amount_minor !== "string" || total.amount_minor.length > 32 || !AMOUNT_MINOR.test(total.amount_minor)) {
      throw new RangeError("total amount_minor must be a numeric string of at most 32 digits");
    }
    // Matches the schema's uniqueItems: a total object only has currency and
    // amount_minor, so identical (currency, amount_minor) pairs are duplicates.
    const totalKey = `${total.currency} ${total.amount_minor}`;
    if (seenTotals.has(totalKey)) {
      throw new RangeError("totals must not contain duplicate entries");
    }
    seenTotals.add(totalKey);
  }

  assertBundleApprovalHashArray("bank_request_hashes", input.bank_request_hashes, input.payment_count);
  assertBundleApprovalHashArray("visible_line_item_hashes", input.visible_line_item_hashes, input.payment_count);

  if (
    !Array.isArray(input.phone_sign_shares) ||
    input.phone_sign_shares.length !== input.payment_count ||
    input.phone_sign_shares.some((share) =>
      typeof share !== "string" || share.length < 12 || share.length > 1024 || !BASE64URL.test(share))
  ) {
    throw new RangeError("phone_sign_shares must contain payment_count base64url shares of 12..1024 characters");
  }

  assertBundleApprovalWebauthnAssertionV1(input.webauthn_assertion);

  if (input.polling_capability_package !== undefined) {
    validatePollingCapabilityPackageV1(input.polling_capability_package);
  }
}

export async function paddedBankSigningDigestV1(input, modulusByteLength, cryptoProvider = globalThis.crypto) {
  const { signingStringBytes } = await validateBankSigningInputV1(input, cryptoProvider);
  return emsaPkcs1v15Encode(signingStringBytes, modulusByteLength, cryptoProvider);
}

export function validateBankReadSigningInputV1(input) {
  assertBankReadSigningInputShapeV1(input);
  const signingString = bankReadHttpSigningStringV1(input);
  return {
    signingString,
    signingStringBytes: utf8Encode(signingString)
  };
}

export async function paddedBankReadSigningDigestV1(input, modulusByteLength, cryptoProvider = globalThis.crypto) {
  const { signingStringBytes } = validateBankReadSigningInputV1(input);
  return emsaPkcs1v15Encode(signingStringBytes, modulusByteLength, cryptoProvider);
}

// --- Nordea admin drafts (Corporate Access + signing-key lifecycle) ---------
//
// These are the ONLY non-payment requests the threshold key ever signs. Before
// this envelope existed the drafts could only be signed by feeding a raw phone
// share to a CLI tool — i.e. by exporting share 3 or 4 off a phone, which
// defeats the ceremony. They are modeled exactly like bank_signing_input_v1
// (body + digest header) or bank_read_signing_input_v1 (body-less read),
// restricted to the admin routes, and they carry their own VISIBLE ACTION
// derived from the signed body so the holder sees what they are authorizing.
//
// The highest-blast-radius field here is `authorizer_id`: it nominates the human
// who receives the approval in the Nordea app. Nominating the wrong id (e.g. a
// sandbox id in production) hands the decision to the wrong person, so it is
// surfaced for the holder to check rather than trusted from the caller.
//
// Two constraints are pinned here and NOWHERE ELSE in this module, because the
// payment envelope's validators are shared and must not learn them:
//   1. WHERE the signature is valid. The signed bytes name an originating host;
//      a Nordea-looking path signed for an attacker's host is a request this
//      protocol never makes, so the host value is an allowlist (below), not a
//      shape test.
//   2. WHICH authorization variant is being asked for. DECOUPLED and REDIRECT
//      are different requests carrying different fields; they are modeled
//      separately so a draft can never be half of each.

// Every admin request shape, keyed by METHOD + PATH. Kept as an explicit table rather than a
// prefix test: "/corporate/" alone would also match the payment API, so an admin envelope could be
// used to sign a payment. An id segment is bounded, never a free path.
//
// `body` is the WIRE SHAPE the route demands — "json", "form" (Nordea takes the OAuth token
// exchange as application/x-www-form-urlencoded, not JSON) or "none". It decides how the signed
// bytes are parsed AND which content-type may be signed beside them; if those two disagree, the
// parse the holder was shown is not the parse the bank performs.
const NORDEA_ADMIN_EXACT_ROUTES = Object.freeze([
  Object.freeze({ action: "corporate_access_start", method: "POST", path: "/corporate/v3/authorize", body: "json" }),
  Object.freeze({ action: "corporate_access_token", method: "POST", path: "/corporate/v3/authorize/token", body: "form" }),
  Object.freeze({ action: "signing_key_create", method: "POST", path: "/corporate/v2/keys/sign", body: "json" })
]);

// The parameterised routes: `${prefix}${id}`, where the id is a bank-issued resource id.
const NORDEA_ADMIN_ID_ROUTES = Object.freeze([
  // The step that NOMINATES the human who approves in the Nordea app.
  Object.freeze({ action: "corporate_access_authorize", method: "PUT", prefix: "/corporate/v3/authorize/", body: "json" }),
  Object.freeze({ action: "corporate_access_status", method: "GET", prefix: "/corporate/v3/authorize/", body: "none" }),
  Object.freeze({ action: "signing_key_status", method: "GET", prefix: "/corporate/v2/keys/", body: "none" })
]);

// Unreserved characters only: no "/" and no "%", so no path segment and no percent-encoded
// traversal is expressible inside an id.
const ADMIN_ID_SEGMENT = /^[A-Za-z0-9._~-]{1,128}$/u;

// The id segments that URL machinery REWRITES in transit. "/corporate/v3/authorize/.." normalises
// to "/corporate/v3" in any conforming URL parser between here and Nordea, so the path that was
// signed and the path that arrives are different requests — the signature would cover a request
// nobody saw. The character class above happens to admit both, so exclude them by value.
function isAdminIdSegmentV1(value) {
  return typeof value === "string" && value !== "." && value !== ".." && ADMIN_ID_SEGMENT.test(value);
}

// "token" and "sign" are EXACT routes sitting under the same prefixes as the {id} routes. Treating
// them as ids would let "GET /corporate/v3/authorize/token" be signed as a status read of a
// resource named "token" — a different request from the POST token exchange that path really is.
function isReservedAdminIdSegmentV1(prefix, id) {
  return NORDEA_ADMIN_EXACT_ROUTES.some((route) => route.path === `${prefix}${id}`);
}

// Resolution is PATH FIRST, method second. Filtering by method first is the bug this ordering
// exists to prevent: a GET or PUT on "/corporate/v3/authorize/token" would skip the (POST) exact
// route and fall through to the parameterised routes, resolving as an {id} request. A path that IS
// an exact route is only ever that route, and only for that route's method.
function resolveNordeaAdminRoute(method, path) {
  if (typeof method !== "string" || typeof path !== "string" || path.length > 512) {
    return null;
  }
  const exact = NORDEA_ADMIN_EXACT_ROUTES.find((route) => route.path === path);
  if (exact) {
    return exact.method === method ? exact : null;
  }
  for (const route of NORDEA_ADMIN_ID_ROUTES) {
    if (route.method !== method || !path.startsWith(route.prefix)) {
      continue;
    }
    const id = path.slice(route.prefix.length);
    if (!isAdminIdSegmentV1(id) || isReservedAdminIdSegmentV1(route.prefix, id)) {
      // Defense in depth: the exact-route match above already claimed the reserved literals.
      return null;
    }
    return route;
  }
  return null;
}

// The exact Nordea authority this system is built to ask for — nothing wider. These are
// ALLOWLISTS, not shape patterns: a broad regex would let a compromised backend draft a request for
// authority nobody ever reviewed (a different scope, a role that signs something else, an
// authentication type that skips the human) and ask a holder to sign it, where the display looks
// unremarkable because the display is derived from those same bytes. Extending any of these lists
// is a deliberate code change, reviewed like any other — that is the point of them.
const ADMIN_SCOPES = Object.freeze(["PAYMENTS_BROADBAND"]);
const ADMIN_ROLES = Object.freeze(["SIGNING_PAYMENTS"]);
const ADMIN_AUTH_TYPES = Object.freeze(["DECOUPLED", "REDIRECT"]);
const ADMIN_AUTH_METHODS = Object.freeze(["MTA"]);

// WHERE the signature is valid. The signed bytes carry an originating-host header, and the
// signature is computed over it: whoever holds a signature for host H holds an authorization to
// speak to H. Accepting any syntactically valid host would let a compromised backend obtain a
// threshold signature over a Nordea-shaped path addressed to a host it controls — the holder would
// read a familiar admin action and never see the destination. So the value is pinned to the two
// Nordea-operated hosts this protocol talks to.
//
// ADDING A HOST HERE IS A DELIBERATE CODE CHANGE, reviewed like any other. It is the one place that
// decides which party a threshold signature can be aimed at; it must never become configuration,
// and it must never be derived from the draft being signed.
export const NORDEA_ADMIN_ORIGINATING_HOSTS = Object.freeze([
  // Nordea's Open Banking production gateway.
  "open.nordea.com",
  // The host server/nordea-client.mjs defaults to (NORDEA_ORIGINATING_HOST / the base URL host);
  // Nordea serves the sandbox and the live Corporate APIs from it.
  "api.nordeaopenbanking.com"
]);

// The admin signed-header block, by NAME and POSITION. validateBankSignedHeadersV1 accepts any
// `x-<vendor>-originating-*` spelling because it guards the shared payment path; the admin routes
// are only ever spoken to Nordea, so here the names are literals. A header the recipient reads
// under a different name is a header the holder was shown under the wrong one.
const NORDEA_ADMIN_HOST_HEADER = "x-nordea-originating-host";
const NORDEA_ADMIN_DATE_HEADER = "x-nordea-originating-date";
const NORDEA_ADMIN_READ_HEADER_NAMES = Object.freeze([
  "(request-target)",
  NORDEA_ADMIN_HOST_HEADER,
  NORDEA_ADMIN_DATE_HEADER
]);
const NORDEA_ADMIN_BODY_HEADER_NAMES = Object.freeze([
  ...NORDEA_ADMIN_READ_HEADER_NAMES,
  "content-type",
  "digest"
]);

// The originating-date WIRE FORMAT: the IMF-fixdate that `new Date().toUTCString()` emits in
// server/nordea-client.mjs, e.g. "Mon, 31 Aug 2026 12:00:00 GMT". This is deliberately narrower
// than "a date": Date.parse also accepts ISO 8601, informal spellings and non-GMT offsets, none of
// which the draft builder can produce, so a value that parses but is not this shape means the
// signer and the sender disagree about the request being signed.
const NORDEA_ADMIN_IMF_FIXDATE =
  /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/u;

// Shape AND instant. The regex fixes the format; Date.parse then rejects the impossible component
// values the shape alone admits (day 00, hour 99). The weekday is not cross-checked against the
// date — no HTTP-date consumer routes on it, and the numeric date is what is bound either way.
function isNordeaAdminHttpDate(value) {
  if (typeof value !== "string" || !NORDEA_ADMIN_IMF_FIXDATE.test(value)) {
    return false;
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    return false;
  }
  // Round-trip against the exact spelling toUTCString() produces. The regex alone still admits
  // dates the builder can never emit — "31 Feb", hour 24, a weekday that does not match the date —
  // because Date.parse normalises them. If the signer would accept a date the sender cannot
  // produce, the two disagree about the request.
  return new Date(parsed).toUTCString() === value;
}


const ADMIN_ID = /^[A-Za-z0-9._:-]{1,64}$/u;
// The unit is SECONDS (tools/test-nordea-sandbox-payment-poll.mjs --duration <seconds>). What Nordea
// actually GRANTS is its own decision, read back from the response; this only bounds what can be asked
// for, so a nonsense value cannot be signed unnoticed.
// MINUTES. Nordea's `duration` is minutes, so this bound must be too. It was 315360000,
// chosen as ten years of SECONDS, which against a minutes value is a ceiling of six
// hundred years — which is why it did not catch the request for a hundred and twenty.
const MAX_ADMIN_DURATION_MINUTES = 5256000; // 10 years, in minutes
const MAX_ADMIN_LIST_ENTRIES = 16;
const MAX_ADMIN_REDIRECT_URI_LENGTH = 512;
// The DISPLAYED redirect target is the parsed origin, which is bounded separately (and matches
// nordea_admin_input_v1.schema.json's 255-char bound on visible_admin_action.redirect_uri).
const MAX_ADMIN_REDIRECT_ORIGIN_LENGTH = 255;
const MAX_ADMIN_STATE_LENGTH = 256;
// DEFENSIVE CEILINGS, not Nordea-documented limits: Nordea publishes no OAS for these routes, so
// there is nothing to check them against. They exist to stop an absurd body being signed unread,
// not to model the bank. A bound that is too TIGHT is the dangerous direction — it fails closed in
// the middle of a live flow, on an opaque credential whose length the bank chose — so they are set
// well above anything Nordea has been observed to issue rather than snugly around it.
const MAX_ADMIN_FORM_BODY_LENGTH = 32768;
const MAX_ADMIN_FORM_VALUE_LENGTH = 8192;
const ADMIN_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";
const ADMIN_JSON_CONTENT_TYPE = "application/json";

// The two token exchanges Nordea defines, by their COMPLETE key set (sorted). Neither extra keys
// nor missing ones are accepted: an unmodeled key in a form body is a parameter the holder was
// never shown, and the recipient would honor it.
const ADMIN_TOKEN_GRANTS = Object.freeze({
  authorization_code: Object.freeze(["code", "grant_type"]),
  refresh_token: Object.freeze(["grant_type", "refresh_token"])
});

function assertAdminAllowedValue(name, value, allowed) {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new RangeError(`${name} must be one of: ${allowed.join(", ")}`);
  }
  return value;
}

// scope/roles are arrays in the Nordea bodies; a lone string is normalised so the holder always
// sees a list. Duplicates are refused: they cannot mean anything beyond the single entry, and the
// visible action is compared byte-for-byte against a caller-supplied one.
function assertAdminAllowedList(name, raw, allowed) {
  const entries = Array.isArray(raw) ? raw : [raw];
  if (entries.length < 1 || entries.length > MAX_ADMIN_LIST_ENTRIES) {
    throw new RangeError(`${name} must contain 1..${MAX_ADMIN_LIST_ENTRIES} entries`);
  }
  for (const entry of entries) {
    assertAdminAllowedValue(`${name} entry`, entry, allowed);
  }
  if (new Set(entries).size !== entries.length) {
    throw new RangeError(`${name} must not repeat an entry`);
  }
  return entries;
}

function assertAdminDuration(value) {
  if (!Number.isInteger(value) || value <= 0 || value > MAX_ADMIN_DURATION_MINUTES) {
    throw new RangeError("Nordea admin duration must be a positive integer number of minutes within bounds");
  }
  return value;
}

function assertAdminIdValue(name, value) {
  assertPattern(name, value, ADMIN_ID);
  return value;
}

// An IPv4 host, in the ONE spelling that survives URL parsing: the WHATWG parser normalises every
// legal IPv4 form ("0x7f.1", "2130706433", "127.1") to dotted decimal, so this single test covers
// all of them. IPv6 arrives bracketed ("[::1]").
const ADMIN_IPV4_HOSTNAME = /^\d{1,3}(?:\.\d{1,3}){3}$/u;
// A plain ASCII domain with at least two labels — the same host shape
// nordea_admin_input_v1.schema.json pins for the displayed redirect origin.
const ADMIN_REDIRECT_HOSTNAME = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;

// A redirect_uri is DISPLAYED to the holder and then followed by a browser, so it has to be safe to
// read as much as safe to visit. Returns the PARSED ORIGIN — what a URL parser resolved, not what
// the caller typed — because that string, and only that string, decides who receives the
// authorization. A path or query would only add screen for the holder to read past.
function assertAdminRedirectUri(value) {
  // Checked before new URL(): the URL parser silently STRIPS tab/CR/LF and tolerates leading and
  // trailing whitespace, so a parsed URL that looks clean can still have been signed with control
  // characters in it. Bidi overrides (U+202A-U+202E, U+2066-U+2069) are the other half — they can
  // make an attacker's host render right-to-left as the bank's. DISPLAY_UNSAFE covers both, plus
  // the rest of Cc/Cf/surrogates/noncharacters.
  assertDisplaySafeText("redirect_uri", value, MAX_ADMIN_REDIRECT_URI_LENGTH);
  // Surrounding whitespace is stripped by the same parser, for the same reason: the value that was
  // signed and displayed would not be the value that is fetched.
  if (value.length < 1 || value.trim() !== value) {
    throw new RangeError("redirect_uri must not be empty or padded with whitespace");
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new RangeError("redirect_uri must be an absolute URL");
  }
  if (url.protocol !== "https:") {
    throw new RangeError("redirect_uri must use https");
  }
  // "https://login.nordea.com@attacker.example/" reads as the bank and resolves to the attacker;
  // userinfo has no legitimate use in a bank redirect.
  if (url.username !== "" || url.password !== "") {
    throw new RangeError("redirect_uri must not carry credentials");
  }
  // A fragment is never sent to the server, so it can only ever be display bait: everything after
  // "#" is invisible to the recipient and fully visible to the holder.
  if (url.hash !== "") {
    throw new RangeError("redirect_uri must not carry a fragment");
  }
  const hostname = url.hostname;
  // An IP literal names no organisation. A holder cannot tell "https://13.53.1.2" from the bank's
  // own address, and no legitimate Nordea callback is addressed to a bare address.
  if (hostname.startsWith("[") || ADMIN_IPV4_HOSTNAME.test(hostname)) {
    throw new RangeError("redirect_uri host must be a domain name, not an IP address");
  }
  // Homograph defence. new URL() IDNA-encodes a Unicode host, so "nordeа.com" (Cyrillic а) arrives
  // here as "xn--norde-6cd.com" — it would pass every ASCII check while rendering, in the holder's
  // browser and in most fonts, as the bank's own domain. Refuse both the encoded and (defensively)
  // the raw non-ASCII form rather than trying to decide which lookalikes are acceptable.
  if (hostname.includes("xn--") || !PRINTABLE_ASCII.test(hostname)) {
    throw new RangeError("redirect_uri host must be a plain ASCII domain (no internationalised or punycode labels)");
  }
  if (!ADMIN_REDIRECT_HOSTNAME.test(hostname)) {
    throw new RangeError("redirect_uri host must be a dotted ASCII domain name");
  }
  // url.origin, not the raw string: scheme + host + non-default port, normalised by the parser. What
  // the holder reads is then exactly what a URL parser resolved out of the signed bytes.
  const origin = url.origin;
  if (origin.length < 1 || origin.length > MAX_ADMIN_REDIRECT_ORIGIN_LENGTH) {
    throw new RangeError(`redirect_uri origin must be at most ${MAX_ADMIN_REDIRECT_ORIGIN_LENGTH} characters`);
  }
  return origin;
}

// The opaque value the bank echoes back on the callback. Never interpreted here — only bounded and
// constrained to characters that render, since it goes on the holder's screen.
function assertAdminState(value) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_ADMIN_STATE_LENGTH ||
    !PRINTABLE_ASCII.test(value)
  ) {
    throw new RangeError(`state must be 1..${MAX_ADMIN_STATE_LENGTH} printable ASCII characters`);
  }
  return value;
}

// The two authorization VARIANTS, modeled separately because they are two different requests that
// happen to share a JSON object.
//
//   DECOUPLED — the decision is pushed to a NAMED human's Nordea app. It must name that human
//               (authorizer_id) and how to reach them (authentication_method). No browser is
//               involved, so redirect_uri/state would be signed and never used — and would show the
//               holder a callback that never fires. Refused rather than ignored.
//   REDIRECT  — a browser is sent to redirect_uri and returns with state. This repo's own drafts
//               (demo/backend/server.mjs, tools/test-nordea-sandbox-payment-poll.mjs) carry exactly
//               { authentication_type, redirect_uri, state } and NO authentication_method: an
//               earlier revision closed authentication_method to a required MTA, which made every
//               legitimate redirect draft in this repo unsignable. Both authentication_method and
//               authorizer_id stay permitted-but-optional for a bank that sends them; each is
//               surfaced when present.
//
// Anything else — a mixed body, an unmodeled key, a DECOUPLED with no nominee — is refused. Shared
// by corporate_access_authorize and signing_key_create, whose authorization objects are identical.
function deriveVisibleAdminAuthorizationV1(name, details) {
  if (details === null || typeof details !== "object" || Array.isArray(details)) {
    throw new RangeError(`${name} must be an object`);
  }
  // Read the variant FIRST: which keys are even legal depends on it.
  const authenticationType = assertAdminAllowedValue(
    `${name}.authentication_type`,
    details.authentication_type,
    ADMIN_AUTH_TYPES
  );

  if (authenticationType === "DECOUPLED") {
    assertModeledObject(name, details, ["authentication_type", "authentication_method", "authorizer_id"], []);
    return {
      authentication_type: authenticationType,
      authentication_method: assertAdminAllowedValue(
        `${name}.authentication_method`,
        details.authentication_method,
        ADMIN_AUTH_METHODS
      ),
      authorizer_id: assertAdminIdValue("authorizer_id", details.authorizer_id)
    };
  }

  // REDIRECT refuses authorizer_id. In a redirect authorization the approval comes from whoever
  // follows the link — nothing consults a nominated id — so displaying one to the holder would
  // assert a control that does not exist: they would read "approver: <person>" and believe that
  // person gates it. Showing an inert field is the same failure as showing an unverified one, and
  // no flow in this repository sends it. A bank that genuinely does is a deliberate code change.
  assertModeledObject(
    name,
    details,
    ["authentication_type", "redirect_uri"],
    ["authentication_method", "state"]
  );
  return {
    authentication_type: authenticationType,
    ...(details.authentication_method === undefined
      ? {}
      : {
        authentication_method: assertAdminAllowedValue(
          `${name}.authentication_method`,
          details.authentication_method,
          ADMIN_AUTH_METHODS
        )
      }),
    ...(details.authorizer_id === undefined
      ? {}
      : { authorizer_id: assertAdminIdValue("authorizer_id", details.authorizer_id) }),
    redirect_uri: assertAdminRedirectUri(details.redirect_uri),
    ...(details.state === undefined ? {} : { state: assertAdminState(details.state) })
  };
}

// Same fatal UTF-8 + strict JSON discipline as parseBankBodyV1: reject non-UTF-8 rather than
// silently U+FFFD-replacing it, so what the holder is shown cannot diverge from the bytes Nordea
// parses.
function parseAdminJsonBodyV1(bodyBytes) {
  let body;
  try {
    body = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes));
  } catch (error) {
    throw new RangeError(`Nordea admin body must be JSON: ${error.message}`);
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new RangeError("Nordea admin body must be a JSON object");
  }
  return body;
}

// The canonical form serialization: URLSearchParams, keys sorted — byte-for-byte what
// server/nordea-client.mjs formUrlEncodedSorted() emits (and what tools/test-nordea-sandbox-payment-poll.mjs
// builds). Sorting by code unit rather than locale: the modeled keys are ASCII, and a locale-dependent
// order in a signature check would be a machine-dependent one.
function canonicalAdminFormTextV1(entries) {
  const canonical = new URLSearchParams();
  for (const [key, value] of [...entries].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))) {
    canonical.append(key, value);
  }
  return canonical.toString();
}

// The token exchange is the ONE admin route whose body is a form, and the one whose body is a
// bearer secret. Both facts are load-bearing: parsing it as JSON (as this envelope originally did)
// means the real draft can never be signed at all, and surfacing its values would put an
// access-granting credential on a screen and into every comparison and log that touches the
// visible action.
function parseAdminFormBodyV1(bodyBytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bodyBytes);
  } catch (error) {
    throw new RangeError(`Nordea admin form body must be UTF-8: ${error.message}`);
  }
  if (text.length < 1 || text.length > MAX_ADMIN_FORM_BODY_LENGTH) {
    throw new RangeError("Nordea admin form body must be bounded and non-empty");
  }
  // URLSearchParams DROPS a leading "?" (it parses a query string, not a body). A recipient reading
  // the same bytes as a form body sees a parameter literally named "?grant_type" instead — so the
  // two parses disagree, which is exactly what must never happen between the display and the bank.
  // (The canonicality rule below also catches this; it is kept for the specific error.)
  if (text.startsWith("?")) {
    throw new RangeError("Nordea admin form body must not begin with \"?\"");
  }
  const entries = [...new URLSearchParams(text).entries()];
  // PARSE-AND-RESERIALIZE EQUALITY. One rule in place of a list of them: the signed bytes must be
  // exactly the canonical encoding of the parameters this code just read out of them. Every way a
  // form body can be read two ways — ";" as a separator, "+" versus "%20", empty pairs, a stray
  // trailing "&", a noncanonical percent-encoding of an unreserved character, key order — produces
  // a reserialization that differs from the original, and is refused here. What the holder is shown
  // is then derived from a parse that has no second reading left in it.
  if (canonicalAdminFormTextV1(entries) !== text) {
    throw new RangeError(
      "Nordea admin form body must be the canonical sorted url-encoded serialization of its parameters"
    );
  }
  const params = new URLSearchParams(entries);
  const grantType = params.get("grant_type");
  const expectedKeys = typeof grantType === "string" && hasOwn(ADMIN_TOKEN_GRANTS, grantType)
    ? ADMIN_TOKEN_GRANTS[grantType]
    : null;
  if (expectedKeys === null) {
    throw new RangeError(`Nordea admin grant_type must be one of: ${Object.keys(ADMIN_TOKEN_GRANTS).join(", ")}`);
  }
  // Sorted comparison of the FULL key list (not a Set) also rejects a repeated key, which would
  // leave the recipient free to pick a different occurrence than the one read here.
  const keys = entries.map(([key]) => key).sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    throw new RangeError(`a ${grantType} exchange must carry exactly: ${expectedKeys.join(", ")}`);
  }
  const secretKey = grantType === "refresh_token" ? "refresh_token" : "code";
  const secret = params.get(secretKey);
  if (typeof secret !== "string" || secret.length < 1 || secret.length > MAX_ADMIN_FORM_VALUE_LENGTH) {
    throw new RangeError(`Nordea admin ${secretKey} must be a bounded non-empty value`);
  }
  // Deliberately returns only the grant type. The code / refresh_token IS signed (it is part of the
  // body bytes) but is never returned, displayed or compared.
  return { grant_type: grantType };
}

// Strictly derives what an admin request actually asks for, from the SIGNED bytes — never from
// caller-supplied display fields (the discipline of deriveVisiblePaymentFromBankBodyV1). Body-less
// status reads carry the id being queried, which is all there is to show.
export function deriveVisibleAdminActionFromBodyV1(bodyBytes, path, method = "POST") {
  const route = resolveNordeaAdminRoute(method, path);
  if (!route) {
    throw new RangeError("Nordea admin path is not a modeled admin endpoint");
  }
  if (route.body === "none") {
    // A read. Nothing is authorized by it, so the visible action is the query itself.
    if (bodyBytes?.length) {
      throw new RangeError("a body-less Nordea admin request must not carry a body");
    }
    return { action: route.action, resource_path: path };
  }

  if (route.body === "form") {
    // The exchange authorizes no new decision of its own — that decision was made when the access
    // request was approved — but WHICH exchange it is stays visible: redeeming a one-time code is
    // not the same as refreshing a session that was approved long ago.
    const { grant_type: grantType } = parseAdminFormBodyV1(bodyBytes);
    return { action: route.action, grant_type: grantType };
  }

  const body = parseAdminJsonBodyV1(bodyBytes);

  if (route.action === "corporate_access_start") {
    assertModeledObject("corporate access body", body, ["scope", "duration"], ["agreement_number"]);
    return {
      action: route.action,
      scope: assertAdminAllowedList("scope", body.scope, ADMIN_SCOPES),
      duration_minutes: assertAdminDuration(body.duration),
      ...(body.agreement_number === undefined
        ? {}
        : { agreement_number: assertAdminIdValue("agreement_number", body.agreement_number) })
    };
  }

  if (route.action === "corporate_access_authorize") {
    // THE nomination step: this is where the approver is decided — either a named human (DECOUPLED)
    // or whoever completes the browser round-trip to redirect_uri (REDIRECT). Both are surfaced, and
    // authentication_type is always shown, so the holder can see WHICH of the two they are approving
    // rather than inferring it from which fields happen to be present.
    return {
      action: route.action,
      resource_path: path,
      ...deriveVisibleAdminAuthorizationV1("authorize body", body)
    };
  }

  // signing_key_create.
  assertModeledObject("signing key body", body, ["key_details", "authorization_details"], []);
  assertModeledObject("key_details", body.key_details, ["roles", "duration"], []);
  return {
    action: route.action,
    roles: assertAdminAllowedList("roles", body.key_details.roles, ADMIN_ROLES),
    duration_minutes: assertAdminDuration(body.key_details.duration),
    ...deriveVisibleAdminAuthorizationV1("authorization_details", body.authorization_details)
  };
}

// The admin signed-header block. Deliberately NOT validateBankSignedHeadersV1 /
// validateBankReadSignedHeadersV1: those guard the shared payment path and must keep accepting any
// vendor's originating-header spelling and any host, because they are the generic bank envelope.
// The admin routes are spoken to Nordea and to nobody else, so here everything is pinned —
//
//   * the header NAMES, by position: (request-target), x-nordea-originating-host,
//     x-nordea-originating-date, and for a body route content-type, digest. No duplicate check is
//     needed: five distinct literals in five fixed positions cannot repeat.
//   * the HOST VALUE, to NORDEA_ADMIN_ORIGINATING_HOSTS. This is the fix for the real hole: without
//     it, a Nordea-looking path signed for "attacker.example" produced a valid threshold signature
//     scoped to the attacker's host, and the holder's screen — derived from the body, which is
//     genuine — showed nothing unusual.
//   * the DATE VALUE, to the exact IMF-fixdate the draft builder emits
//     (new Date().toUTCString() in server/nordea-client.mjs). Date.parse alone was too weak: it
//     accepts ISO 8601 and informal dates, so a value the sender could never transmit could ride
//     along inside the signature.
//   * the CONTENT-TYPE, to the one the resolved route's body kind demands — the cross-check that
//     stops a form body being signed as JSON (or the reverse), i.e. a request whose derived display
//     came from a parse the recipient will not perform.
function validateNordeaAdminSignedHeadersV1(headers, route, bodySha256) {
  const bodyless = route.body === "none";
  const expectedNames = bodyless ? NORDEA_ADMIN_READ_HEADER_NAMES : NORDEA_ADMIN_BODY_HEADER_NAMES;
  if (!Array.isArray(headers) || headers.length !== expectedNames.length) {
    throw new RangeError(`Nordea admin signed_headers must contain exactly ${expectedNames.length} headers`);
  }
  const expectedContentType = route.body === "form" ? ADMIN_FORM_CONTENT_TYPE : ADMIN_JSON_CONTENT_TYPE;
  const expectedDigest = bodyless ? null : `SHA-256=${hexToBase64(bodySha256)}`;

  return headers.map((header, index) => {
    assertModeledObject("Nordea admin signed header", header, ["name", "value"], []);
    const { name, value } = header;
    const expectedName = expectedNames[index];
    if (name !== expectedName) {
      throw new RangeError(`Nordea admin signed header ${index + 1} must be ${expectedName}`);
    }
    if (name === "(request-target)") {
      if (value !== "") {
        throw new RangeError("(request-target) signed header value must be empty");
      }
      return { name, value };
    }
    assertPrintableHeaderValue(`signed header ${name}`, value);
    if (name === NORDEA_ADMIN_HOST_HEADER && !NORDEA_ADMIN_ORIGINATING_HOSTS.includes(value)) {
      throw new RangeError(
        `${NORDEA_ADMIN_HOST_HEADER} must be one of: ${NORDEA_ADMIN_ORIGINATING_HOSTS.join(", ")}`
      );
    }
    if (name === NORDEA_ADMIN_DATE_HEADER && !isNordeaAdminHttpDate(value)) {
      throw new RangeError(
        `${NORDEA_ADMIN_DATE_HEADER} must be an IMF-fixdate, e.g. "Mon, 31 Aug 2026 12:00:00 GMT"`
      );
    }
    if (name === "content-type" && value !== expectedContentType) {
      throw new RangeError(`content-type signed header must be ${expectedContentType}`);
    }
    if (name === "digest" && value !== expectedDigest) {
      throw new RangeError("digest signed header must match body_sha256");
    }
    return { name, value };
  });
}

function assertNordeaAdminInputShapeV1(input) {
  assertModeledObject(
    "Nordea admin signing input",
    input,
    ["version", "request_id", "method", "path", "signed_headers"],
    ["body_sha256", "body_base64url", "visible_admin_action"]
  );
  if (input.version !== "nordea_admin_input_v1") {
    throw new RangeError("Nordea admin signing input version must be nordea_admin_input_v1");
  }
  assertPattern("request_id", input.request_id, ID_8_128);
  const route = resolveNordeaAdminRoute(input.method, input.path);
  if (!route) {
    throw new RangeError("Nordea admin path is not a modeled admin endpoint");
  }
  assertNoLineBreaks("Nordea admin path", input.path, 512);

  if (route.body === "none") {
    // A body on a read would be signed but never sent — a silent divergence between the signed
    // bytes and the request. Refuse it rather than ignore it.
    if (input.body_base64url !== undefined || input.body_sha256 !== undefined) {
      throw new RangeError("a body-less Nordea admin request must not carry a body");
    }
  } else {
    if (
      typeof input.body_base64url !== "string" ||
      input.body_base64url.length < 2 ||
      input.body_base64url.length > MAX_BODY_BASE64URL_LENGTH ||
      !BASE64URL.test(input.body_base64url)
    ) {
      throw new RangeError("body_base64url must be bounded unpadded base64url");
    }
    assertHex64("body_sha256", input.body_sha256);
  }
  return route;
}

// An IMMUTABLE PICTURE of the draft, taken once, before anything is validated or awaited.
//
// Validation and signing read the same draft many times: the route comes from method + path, the
// signing string from method + path + headers, and the visible action from the body and the path
// again — with an `await` on the body hash in between. Reading the caller's object across that await
// means a caller (or a getter) can change it mid-flight and hand out a signature over one request
// with a display describing another. Everything downstream reads this copy instead, so there is
// exactly one draft in play no matter what happens to the original.
//
// Plain JSON values only: getters are invoked exactly once here and never again, and
// functions/symbols/BigInt — none of which this envelope models — are refused rather than carried.
//
// Object copies are given a NULL PROTOTYPE. That is not cosmetic: assigning to `copy["__proto__"]`
// on an ordinary object runs Object.prototype's __proto__ SETTER, which re-parents the copy and
// erases the key, so an input carrying an own enumerable "__proto__" field used to be silently
// swallowed instead of rejected as unmodeled. On a null-prototype target there is no inherited
// setter, so the key is copied as an own DATA property and the ordinary unmodeled-field checks
// (assertModeledObject downstream, stableStringify for visible_admin_action) see it and refuse it.
// Both of those work on null-prototype objects: they read own keys via Object.keys /
// Object.prototype.hasOwnProperty.call, and stableStringify accepts a null prototype explicitly.
const MAX_ADMIN_SNAPSHOT_DEPTH = 8;
// Canonical array index, i.e. exactly what JSON can express as an array position.
const ADMIN_ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/u;

function snapshotAdminValueV1(value, depth) {
  if (depth > MAX_ADMIN_SNAPSHOT_DEPTH) {
    // Also the cycle guard: a self-referencing draft cannot recurse forever.
    throw new RangeError("Nordea admin signing input is nested too deeply");
  }
  if (value === null) {
    return null;
  }
  const type = typeof value;
  if (type === "function" || type === "symbol" || type === "bigint") {
    throw new RangeError(`Nordea admin signing input must not contain a ${type}`);
  }
  if (type !== "object") {
    return value;
  }
  // Symbol-keyed properties are invisible to Object.keys and to every JSON serializer: they would
  // ride through the copy unexamined and unmodeled. Refuse them wherever they appear.
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new RangeError("Nordea admin signing input must not carry symbol-keyed properties");
  }
  if (Array.isArray(value)) {
    // An array is its indices and nothing else. Own enumerable properties beyond them are dropped
    // by every array serializer (so they would never reach the recipient) and holes are not JSON
    // at all — and a hole in signed_headers would skip that header's name check, because .map
    // skips holes. Requiring exactly `length` own enumerable index keys rejects both.
    const keys = Object.keys(value);
    for (const key of keys) {
      if (!ADMIN_ARRAY_INDEX.test(key) || Number(key) >= value.length) {
        throw new RangeError(`Nordea admin signing input array has unmodeled property "${key}"`);
      }
    }
    if (keys.length !== value.length) {
      throw new RangeError("Nordea admin signing input array must not be sparse");
    }
    const copy = [];
    for (let index = 0; index < value.length; index += 1) {
      copy.push(snapshotAdminValueV1(value[index], depth + 1));
    }
    return copy;
  }
  const copy = Object.create(null);
  for (const key of Object.keys(value)) {
    // defineProperty, not assignment: a plain data property, never a setter invocation, whatever
    // the key is named.
    Object.defineProperty(copy, key, {
      value: snapshotAdminValueV1(value[key], depth + 1),
      writable: true,
      enumerable: true,
      configurable: true
    });
  }
  return copy;
}

function snapshotNordeaAdminInputV1(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new RangeError("Nordea admin signing input must be an object");
  }
  return snapshotAdminValueV1(input, 0);
}

function buildNordeaAdminSigningStringV1(method, path, headers) {
  return headers.map(({ name, value }) => {
    if (name === "(request-target)") {
      return `(request-target): ${method.toLowerCase()} ${path}`;
    }
    return `${name}: ${value}`;
  }).join("\n");
}

export function nordeaAdminHttpSigningStringV1(input) {
  // Snapshot first, even here: this function is synchronous, but a getter on the caller's object
  // could still return one path to the route resolver and another to the signing string.
  const draft = snapshotNordeaAdminInputV1(input);
  const route = assertNordeaAdminInputShapeV1(draft);
  const headers = validateNordeaAdminSignedHeadersV1(draft.signed_headers, route, draft.body_sha256);
  return buildNordeaAdminSigningStringV1(draft.method, draft.path, headers);
}

// Full validation: any body must hash to body_sha256, and any visible_admin_action the caller
// supplied must EQUAL the one derived from those same signed bytes. A display that disagrees with
// the bytes is refused, never preferred.
export async function validateNordeaAdminSigningInputV1(input, cryptoProvider = globalThis.crypto) {
  // FIRST statement, before any validation and before any await: from here on the caller's object is
  // never read again, so the signing string and the visible action describe the same request even if
  // the original is mutated while the body hash is in flight.
  const draft = snapshotNordeaAdminInputV1(input);
  const route = assertNordeaAdminInputShapeV1(draft);
  const headers = validateNordeaAdminSignedHeadersV1(draft.signed_headers, route, draft.body_sha256);
  const signingString = buildNordeaAdminSigningStringV1(draft.method, draft.path, headers);
  let bodyBytes = new Uint8Array(0);
  if (route.body !== "none") {
    bodyBytes = base64urlToBytes(draft.body_base64url);
    const actualBodySha256 = await sha256Hex(bodyBytes, cryptoProvider);
    if (actualBodySha256 !== draft.body_sha256) {
      throw new RangeError("body_sha256 does not match body_base64url");
    }
  }
  const derived = deriveVisibleAdminActionFromBodyV1(bodyBytes, draft.path, draft.method);
  if (draft.visible_admin_action !== undefined) {
    if (stableStringify(draft.visible_admin_action) !== stableStringify(derived)) {
      throw new RangeError("visible_admin_action does not match the signed body");
    }
  }
  return {
    signingString,
    signingStringBytes: utf8Encode(signingString),
    visibleAdminAction: derived
  };
}

export async function paddedNordeaAdminDigestV1(input, modulusByteLength, cryptoProvider = globalThis.crypto) {
  const { signingStringBytes } = await validateNordeaAdminSigningInputV1(input, cryptoProvider);
  return emsaPkcs1v15Encode(signingStringBytes, modulusByteLength, cryptoProvider);
}

export function validatePollingCapabilityPackageV1(pkg) {
  if (pkg === undefined || pkg === null) {
    return null;
  }
  // Allow-list matching polling_capability_package_v1.schema.json
  // (additionalProperties:false); the runtime is additionally stricter than the
  // bank_read schema in requiring scope/slot_index/phone_sign_share_base64url on
  // every polling request, so any package it accepts is also schema-valid.
  assertModeledObject(
    "polling capability package",
    pkg,
    ["version", "bundle_id", "created_at", "valid_until", "horizon_hours", "slot_interval_minutes", "requests"],
    []
  );
  if (pkg.version !== "polling_capability_package_v1") {
    throw new RangeError("polling capability package version must be polling_capability_package_v1");
  }
  assertPattern("polling bundle_id", pkg.bundle_id, ID_8_128);
  assertDateTime("polling created_at", pkg.created_at);
  assertDateTime("polling valid_until", pkg.valid_until);
  if (pkg.slot_interval_minutes !== 60) {
    throw new RangeError("polling slot_interval_minutes must be 60");
  }
  if (pkg.horizon_hours !== 72) {
    throw new RangeError("polling horizon_hours must be 72");
  }
  if (!Array.isArray(pkg.requests) || pkg.requests.length > MAX_POLLING_CAPABILITY_REQUESTS) {
    throw new RangeError(`polling requests must contain at most ${MAX_POLLING_CAPABILITY_REQUESTS} entries`);
  }
  for (const request of pkg.requests) {
    validateBankReadSigningInputV1(request);
    if (!["deterministic", "bundle_payment_status"].includes(request.scope)) {
      throw new RangeError("polling request scope is invalid");
    }
    if (!Number.isInteger(request.slot_index) || request.slot_index < 0 || request.slot_index > 96) {
      throw new RangeError("polling request slot_index is invalid");
    }
    if (
      request.deterministic_index !== undefined &&
      (!Number.isInteger(request.deterministic_index) || request.deterministic_index < 0)
    ) {
      throw new RangeError("polling request deterministic_index is invalid");
    }
    if (
      typeof request.phone_sign_share_base64url !== "string" ||
      request.phone_sign_share_base64url.length < 12 ||
      request.phone_sign_share_base64url.length > 1024 ||
      !BASE64URL.test(request.phone_sign_share_base64url)
    ) {
      throw new RangeError("polling request phone_sign_share_base64url is invalid");
    }
    if (request.scope === "bundle_payment_status") {
      if (!Number.isInteger(request.chunk_index) || request.chunk_index < 0) {
        throw new RangeError("polling payment chunk_index is invalid");
      }
      if (
        !Array.isArray(request.external_ids) ||
        request.external_ids.length < 1 ||
        request.external_ids.length > MAX_POLLING_EXTERNAL_IDS
      ) {
        throw new RangeError("polling payment external_ids must contain 1..20 entries");
      }
      for (const externalId of request.external_ids) {
        assertNoLineBreaks("polling external_id", externalId, 128);
      }
    }
  }
  return pkg;
}
