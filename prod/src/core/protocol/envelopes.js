import { base64urlToBytes, bytesToHex, utf8Decode, utf8Encode } from "../crypto/bytes.js";
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
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/u;
const NO_LINE_BREAKS = /^[^\r\n]*$/u;
const MAX_BUNDLE_PAYMENTS = 200;
const MAX_BODY_BASE64URL_LENGTH = 350000;
const BANK_SIGNED_HEADER_COUNT = 5;
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

function assertDateTime(name, value) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
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
  const text = String(value ?? "");
  const match = /^([0-9]+)(?:\.([0-9]{1,2}))?$/u.exec(text);
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
    ["method", method],
    ["path", input.path],
    ["body_sha256", bodySha256],
    ["approver_id", input.approver_id],
    ["device_id", input.device_id],
    ["share_index", input.share_index],
    ["key_id", input.key_id],
    ["timestamp", input.timestamp],
    ["server_nonce", input.server_nonce],
    ["client_nonce", input.client_nonce]
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
    ["method", method],
    ["path", input.path],
    ["status", input.status],
    ["body_sha256", bodySha256],
    ["approver_id", input.approver_id],
    ["device_id", input.device_id],
    ["share_index", input.share_index],
    ["key_id", input.key_id],
    ["request_server_nonce", input.request_server_nonce ?? "-"],
    ["request_client_nonce", input.request_client_nonce ?? "-"],
    ["response_timestamp", input.response_timestamp]
  ]);
}

export function canonicalBundleApprovalEnvelopeV1(input) {
  validateBundleApprovalEnvelopeInputV1(input);

  return canonicalText("APPROVAL_BUNDLE_APPROVAL_V1", [
    ["bundle_id", input.bundle_id],
    ["bundle_hash_sha256", input.bundle_hash_sha256],
    ["payment_count", input.payment_count],
    ["approver_id", input.approver_id],
    ["device_id", input.device_id],
    ["share_index", input.share_index],
    ["key_id", input.key_id],
    ["approved_at", input.approved_at]
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

  const challengeContext = canonicalText("APPROVAL_WEBAUTHN_BUNDLE_APPROVAL_V1", [
    ["bundle_id", input.bundle_id],
    ["bundle_hash_sha256", input.bundle_hash_sha256],
    ["payment_count", input.payment_count],
    ["approver_id", input.approver_id],
    ["device_id", input.device_id],
    ["share_index", input.share_index],
    ["key_id", input.key_id],
    ["credential_id", input.credential_id]
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

function domesticAccountDisplay(account, bank) {
  const value = account?.value ?? account;
  if (
    account?.type === "BBAN" &&
    typeof value === "string" &&
    /^[0-9]{14}$/u.test(value) &&
    (bank?.country === "DK" || bank?.bank_code)
  ) {
    const bankCode = typeof bank?.bank_code === "string" && bank.bank_code ? bank.bank_code : value.slice(0, 4);
    const accountNumber = value.startsWith(bankCode) ? value.slice(bankCode.length) : value.slice(4);
    return `${bankCode} ${accountNumber}`;
  }
  return value;
}

export function deriveVisiblePaymentFromBankBodyV1(bodyBytes) {
  let body;
  try {
    body = JSON.parse(utf8Decode(bodyBytes));
  } catch {
    throw new Error("Bank request body must be JSON for visible payment derivation");
  }

  return normalizeVisiblePaymentV1({
    creditor_name: body.creditor?.name,
    creditor_account: domesticAccountDisplay(body.creditor?.account, body.creditor?.bank),
    debtor_account_masked: body.debtor?.account_masked ?? maskAccount(body.debtor?.account?.value),
    amount_minor: body.amount?.minor !== undefined ? String(body.amount.minor) : decimalAmountToMinor(body.amount),
    currency: body.amount?.currency ?? body.currency,
    remittance_text: body.remittance_text ?? body.creditor?.message ?? body.creditor?.reference?.value ?? body.end_to_end_id ?? ""
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

export function validateBundleApprovalEnvelopeInputV1(input) {
  if (input?.version !== undefined && input.version !== "bundle_approval_v1") {
    throw new RangeError("bundle approval version must be bundle_approval_v1");
  }
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

  if (input.bank_request_hashes !== undefined) {
    if (!Array.isArray(input.bank_request_hashes) || input.bank_request_hashes.length !== input.payment_count) {
      throw new RangeError("bank_request_hashes length must equal payment_count");
    }
    for (const hash of input.bank_request_hashes) {
      assertHex64("bank_request_hash", hash);
    }
  }
  if (input.visible_line_item_hashes !== undefined) {
    if (!Array.isArray(input.visible_line_item_hashes) || input.visible_line_item_hashes.length !== input.payment_count) {
      throw new RangeError("visible_line_item_hashes length must equal payment_count");
    }
    for (const hash of input.visible_line_item_hashes) {
      assertHex64("visible_line_item_hash", hash);
    }
  }
  if (input.phone_sign_shares !== undefined && (
    !Array.isArray(input.phone_sign_shares) ||
    input.phone_sign_shares.length !== input.payment_count ||
    input.phone_sign_shares.some((share) => typeof share !== "string" || !BASE64URL.test(share))
  )) {
    throw new RangeError("phone_sign_shares length must equal payment_count and contain base64url values");
  }
}

export async function paddedBankSigningDigestV1(input, modulusByteLength, cryptoProvider = globalThis.crypto) {
  const { signingStringBytes } = await validateBankSigningInputV1(input, cryptoProvider);
  return emsaPkcs1v15Encode(signingStringBytes, modulusByteLength, cryptoProvider);
}
