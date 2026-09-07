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
  paddedBankSigningDigestV1,
  validateNordeaAdminSigningInputV1,
  validateNordeaPaymentSignInputV1
} from "./envelopes.js";
import { emsaPkcs1v15Encode } from "../crypto/pkcs1v15.js";

const ID_8_128 = /^[A-Za-z0-9._:-]{8,128}$/u;
const APPROVER_ID = /^[A-Za-z0-9._:-]{3,128}$/u;
const DEVICE_ID = /^[A-Za-z0-9._:-]{16,128}$/u;
const HEX_64 = /^[a-f0-9]{64}$/u;
const SUPPORTED_MODULUS_BYTES = new Set([256, 384, 512]);
const PUBLIC_EXPONENT = 65537;

// The exact property set of schemas/phone_share_package_v1.schema.json
// (additionalProperties:false). Used to reject attacker-injected fields, mirroring
// assertExactKeys in backup-recovery.js (Codex MED #3).
const PHONE_SHARE_PACKAGE_KEYS = [
  "version",
  "key_id",
  "certificate_fingerprint_sha256",
  "approver_id",
  "device_id",
  "share_index",
  "threshold",
  "players",
  "circl_version",
  "rsa_modulus_base64url",
  "rsa_public_exponent",
  "share_si_base64url",
  "created_at"
];

function assertPattern(name, value, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new RangeError(`${name} is invalid`);
  }
}

// Rejects any property outside the schema's allowed set (additionalProperties:false),
// the way assertExactKeys does in backup-recovery.js (Codex MED #3).
function assertNoUnexpectedKeys(object, allowedKeys, label) {
  for (const key of Object.keys(object)) {
    if (!allowedKeys.includes(key)) {
      throw new Error(`${label} has unexpected field ${key}`);
    }
  }
}

export function decodePhoneSharePackageV1(pkg) {
  if (pkg?.version !== "phone_share_package_v1") {
    throw new Error("unsupported phone share package version");
  }
  assertNoUnexpectedKeys(pkg, PHONE_SHARE_PACKAGE_KEYS, "phone share package");
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

export function createBankInputSignerV1(phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  const modulusBytes = modulusByteLength(share.modulus);
  const signPaddedDigest = (paddedDigest) => signShareForPaddedDigest({
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
    async signPaymentInput(bankInput) {
      const paddedDigest = await paddedBankSigningDigestV1(
        bankInput,
        modulusBytes,
        options.cryptoProvider
      );
      const signShare = signPaddedDigest(paddedDigest);
      return {
        padded_digest: paddedDigest,
        sign_share: signShare,
        sign_share_base64url: bytesToBase64url(signShare)
      };
    },

    async signReadInput(bankInput) {
      const paddedDigest = await paddedBankReadSigningDigestV1(
        bankInput,
        modulusBytes,
        options.cryptoProvider
      );
      const signShare = signPaddedDigest(paddedDigest);
      return {
        padded_digest: paddedDigest,
        sign_share: signShare,
        sign_share_base64url: bytesToBase64url(signShare)
      };
    }
  };
}

export async function signBankPaymentInputV1(bankInput, phoneSharePackage, options = {}) {
  return createBankInputSignerV1(phoneSharePackage, options).signPaymentInput(bankInput);
}

export async function signBankReadInputV1(bankInput, phoneSharePackage, options = {}) {
  return createBankInputSignerV1(phoneSharePackage, options).signReadInput(bankInput);
}

/**
 * Signs a Nordea ADMIN draft (Corporate Access or signing-key creation).
 *
 * This is the only non-payment request the threshold key signs. It stays a TYPED
 * envelope for the same reason every other path is: the device must never expose
 * a generic "sign these bytes" route. The returned visible_admin_action is derived
 * from the SIGNED body, so the caller displays what was actually signed rather
 * than what it hoped was signed.
 */
export async function signNordeaAdminInputV1(adminInput, phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  // ONE validation pass, and the digest is computed from the bytes THAT pass returned. Validating a
  // second time (via paddedNordeaAdminDigestV1) would re-read a caller-held object that can change
  // between awaits, so the action shown to the holder could describe different bytes than the ones
  // signed. The returned signingStringBytes are the single source of truth here.
  const { visibleAdminAction, signingStringBytes } = await validateNordeaAdminSigningInputV1(
    adminInput,
    options.cryptoProvider
  );
  const paddedDigest = await emsaPkcs1v15Encode(
    signingStringBytes,
    modulusByteLength(share.modulus),
    options.cryptoProvider ?? globalThis.crypto
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
    visible_admin_action: visibleAdminAction,
    sign_share: signShare,
    sign_share_base64url: bytesToBase64url(signShare)
  };
}


/**
 * Signs the payment-authorization round: the SECOND signature a submitted bundle needs.
 *
 * `POST /corporate/premium/v2/payments` only CREATES payments at Nordea; the bank waits for a payment
 * authorization before executing them. That request names payments by the ids the BANK assigns, so its
 * bytes cannot exist until the POST has returned — which is why this is a separate round rather than
 * part of the bundle approval the holder has already given.
 *
 * One gesture, several signatures, exactly as the admin chain does it: a bundle of up to 200 payments
 * is at most ten requests (the endpoint takes 20 ids each), and all of them are signed here in one
 * pass while the share is in hand. The holder is never asked to come back per payment.
 *
 * The returned visible_payment_authorization is derived from the SIGNED bodies, so the caller displays
 * what was actually authorized rather than what it was told.
 */
export async function signNordeaPaymentSignInputV1(paymentSignInput, phoneSharePackage, options = {}) {
  assertNoProductionBlindingOverride(options);
  const share = decodePhoneSharePackageV1(phoneSharePackage);
  // ONE validation pass, and every digest is computed from the bytes THAT pass returned — never by
  // re-reading the caller's object, which could change between awaits and leave the holder shown one
  // set of payments while a different set was signed.
  const { visiblePaymentAuthorization, signingStringBytes } = await validateNordeaPaymentSignInputV1(
    paymentSignInput,
    options.cryptoProvider
  );
  const signatures = [];
  for (const [chunkIndex, bytes] of signingStringBytes.entries()) {
    const paddedDigest = await emsaPkcs1v15Encode(
      bytes,
      modulusByteLength(share.modulus),
      options.cryptoProvider ?? globalThis.crypto
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
    signatures.push({
      chunk_index: chunkIndex,
      padded_digest: paddedDigest,
      sign_share: signShare,
      sign_share_base64url: bytesToBase64url(signShare)
    });
  }
  return {
    visible_payment_authorization: visiblePaymentAuthorization,
    signatures
  };
}
