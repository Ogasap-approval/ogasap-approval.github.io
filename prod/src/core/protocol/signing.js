import { base64urlToBytes, bytesToBase64url } from "../crypto/bytes.js";
import { bytesToBigInt, modulusByteLength } from "../crypto/bigint.js";
import {
  signShareForMessagePkcs1v15,
  signShareForPaddedDigest
} from "../crypto/threshold-rsa.js";
import {
  canonicalBackendAuthEnvelopeV1,
  canonicalBackendResponseEnvelopeV1,
  canonicalBundleApprovalEnvelopeV1,
  paddedBankReadSigningDigestV1,
  paddedBankSigningDigestV1
} from "./envelopes.js";

const ID_8_128 = /^[A-Za-z0-9._:-]{8,128}$/u;
const APPROVER_ID = /^[A-Za-z0-9._:-]{3,128}$/u;
const DEVICE_ID = /^[A-Za-z0-9._:-]{16,128}$/u;
const HEX_64 = /^[a-f0-9]{64}$/u;
const SUPPORTED_MODULUS_BYTES = new Set([256, 384, 512]);
const PUBLIC_EXPONENT = 65537;

function assertPattern(name, value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new RangeError(`${name} is invalid`);
  }
}

export function decodePhoneSharePackageV1(pkg) {
  if (pkg?.version !== "phone_share_package_v1") {
    throw new Error("unsupported phone share package version");
  }
  assertPattern("key_id", pkg.key_id, ID_8_128);
  assertPattern("certificate_fingerprint_sha256", pkg.certificate_fingerprint_sha256, HEX_64);
  assertPattern("approver_id", pkg.approver_id, APPROVER_ID);
  assertPattern("device_id", pkg.device_id, DEVICE_ID);
  if (pkg.players !== 4 || pkg.threshold !== 3) {
    throw new Error("phone share package must be 3-of-4");
  }
  if (![3, 4].includes(pkg.share_index)) {
    throw new Error("phone share index must be 3 or 4");
  }
  if (pkg.circl_version !== "v1.6.3") {
    throw new Error("phone share package must target CIRCL v1.6.3");
  }
  if (pkg.rsa_public_exponent !== PUBLIC_EXPONENT) {
    throw new Error("phone share package must use RSA public exponent 65537");
  }

  const modulusBytes = base64urlToBytes(pkg.rsa_modulus_base64url);
  if (!SUPPORTED_MODULUS_BYTES.has(modulusBytes.length)) {
    throw new Error("unsupported RSA modulus size");
  }
  const shareSiBytes = base64urlToBytes(pkg.share_si_base64url);
  if (shareSiBytes.length === 0 || shareSiBytes.every((byte) => byte === 0)) {
    throw new Error("phone share secret must be non-empty");
  }
  const modulus = bytesToBigInt(modulusBytes);
  const shareSi = bytesToBigInt(shareSiBytes);
  if (shareSi <= 0n || shareSi >= modulus) {
    throw new Error("phone share secret is out of RSA range");
  }

  return {
    keyId: pkg.key_id,
    certificateFingerprintSha256: pkg.certificate_fingerprint_sha256,
    approverId: pkg.approver_id,
    deviceId: pkg.device_id,
    shareIndex: pkg.share_index,
    players: pkg.players,
    threshold: pkg.threshold,
    publicExponent: PUBLIC_EXPONENT,
    modulus,
    shareSi
  };
}

function assertShareMetadataMatchesInput(share, input) {
  if (input.approver_id !== share.approverId) {
    throw new Error("approver_id does not match phone share package");
  }
  if (input.device_id !== share.deviceId) {
    throw new Error("device_id does not match phone share package");
  }
  if (input.share_index !== share.shareIndex) {
    throw new Error("share_index does not match phone share package");
  }
  if (input.key_id !== share.keyId) {
    throw new Error("key_id does not match phone share package");
  }
  if (
    input.certificate_fingerprint_sha256 !== undefined &&
    input.certificate_fingerprint_sha256 !== share.certificateFingerprintSha256
  ) {
    throw new Error("certificate_fingerprint_sha256 does not match phone share package");
  }
}

function assertNoProductionBlindingOverride(options) {
  if (Object.hasOwn(options, "blinded")) {
    throw new Error("public typed signing APIs always use blinding");
  }
}

export async function signBackendAuthEnvelopeV1(envelopeInput, phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  assertShareMetadataMatchesInput(share, envelopeInput);
  const message = await canonicalBackendAuthEnvelopeV1(envelopeInput, options.cryptoProvider);
  const signShare = await signShareForMessagePkcs1v15({
    message,
    modulus: share.modulus,
    shareSi: share.shareSi,
    shareIndex: share.shareIndex,
    players: share.players,
    threshold: share.threshold,
    blinded: true,
    cryptoProvider: options.cryptoProvider
  });

  return {
    canonical_envelope: message,
    sign_share: signShare,
    sign_share_base64url: bytesToBase64url(signShare)
  };
}

export async function signBackendResponseEnvelopeV1(envelopeInput, phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  assertShareMetadataMatchesInput(share, envelopeInput);
  const message = await canonicalBackendResponseEnvelopeV1(envelopeInput, options.cryptoProvider);
  const signShare = await signShareForMessagePkcs1v15({
    message,
    modulus: share.modulus,
    shareSi: share.shareSi,
    shareIndex: share.shareIndex,
    players: share.players,
    threshold: share.threshold,
    blinded: true,
    cryptoProvider: options.cryptoProvider
  });

  return {
    canonical_envelope: message,
    sign_share: signShare,
    sign_share_base64url: bytesToBase64url(signShare)
  };
}

export async function signBundleApprovalV1(approvalInput, phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  assertShareMetadataMatchesInput(share, approvalInput);
  const message = canonicalBundleApprovalEnvelopeV1(approvalInput);
  const signShare = await signShareForMessagePkcs1v15({
    message,
    modulus: share.modulus,
    shareSi: share.shareSi,
    shareIndex: share.shareIndex,
    players: share.players,
    threshold: share.threshold,
    blinded: true,
    cryptoProvider: options.cryptoProvider
  });

  return {
    canonical_envelope: message,
    sign_share: signShare,
    sign_share_base64url: bytesToBase64url(signShare)
  };
}

export async function signBankPaymentInputV1(bankInput, phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  const paddedDigest = await paddedBankSigningDigestV1(
    bankInput,
    modulusByteLength(share.modulus),
    options.cryptoProvider
  );
  const signShare = signShareForPaddedDigest({
    paddedDigest,
    modulus: share.modulus,
    shareSi: share.shareSi,
    shareIndex: share.shareIndex,
    players: share.players,
    threshold: share.threshold,
    blinded: true,
    cryptoProvider: options.cryptoProvider
  });

  return {
    padded_digest: paddedDigest,
    sign_share: signShare,
    sign_share_base64url: bytesToBase64url(signShare)
  };
}

export async function signBankReadInputV1(bankInput, phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  const paddedDigest = await paddedBankReadSigningDigestV1(
    bankInput,
    modulusByteLength(share.modulus),
    options.cryptoProvider
  );
  const signShare = signShareForPaddedDigest({
    paddedDigest,
    modulus: share.modulus,
    shareSi: share.shareSi,
    shareIndex: share.shareIndex,
    players: share.players,
    threshold: share.threshold,
    blinded: true,
    cryptoProvider: options.cryptoProvider
  });

  return {
    padded_digest: paddedDigest,
    sign_share: signShare,
    sign_share_base64url: bytesToBase64url(signShare)
  };
}
