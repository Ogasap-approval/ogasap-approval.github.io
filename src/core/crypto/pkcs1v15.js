import { concatBytes, hexToBytes } from "./bytes.js";
import { modulusByteLength } from "./bigint.js";

export const SHA256_DIGEST_INFO_PREFIX = hexToBytes("3031300d060960864801650304020105000420");

export async function sha256(bytes, cryptoProvider = globalThis.crypto) {
  if (!cryptoProvider?.subtle?.digest) {
    throw new Error("crypto.subtle.digest is required");
  }

  const digest = await cryptoProvider.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

export function emsaPkcs1v15EncodeHash(hash, encodedLength) {
  if (!(hash instanceof Uint8Array) || hash.length !== 32) {
    throw new TypeError("hash must be a 32-byte SHA-256 digest");
  }
  if (!Number.isInteger(encodedLength) || encodedLength < SHA256_DIGEST_INFO_PREFIX.length + hash.length + 11) {
    throw new RangeError("encodedLength is too short for SHA-256 PKCS#1 v1.5 encoding");
  }

  const digestInfo = concatBytes(SHA256_DIGEST_INFO_PREFIX, hash);
  const psLength = encodedLength - digestInfo.length - 3;
  const padding = new Uint8Array(psLength).fill(0xff);
  return concatBytes(new Uint8Array([0x00, 0x01]), padding, new Uint8Array([0x00]), digestInfo);
}

export async function emsaPkcs1v15Encode(message, encodedLength, cryptoProvider = globalThis.crypto) {
  const hash = await sha256(message, cryptoProvider);
  return emsaPkcs1v15EncodeHash(hash, encodedLength);
}

export async function pkcs1v15PaddedMessageForModulus(message, modulus, cryptoProvider = globalThis.crypto) {
  return emsaPkcs1v15Encode(message, modulusByteLength(modulus), cryptoProvider);
}
