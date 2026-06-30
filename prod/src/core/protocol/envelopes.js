import { base64urlToBytes, bytesToHex, utf8Encode } from "../crypto/bytes.js";
import { emsaPkcs1v15Encode, sha256 } from "../crypto/pkcs1v15.js";
import { canonicalJsonBytes, canonicalText, sha256Hex, stableStringify } from "./canonical.js";

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
