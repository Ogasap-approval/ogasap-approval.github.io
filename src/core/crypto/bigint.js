import { assertUint8Array } from "./bytes.js";

export function bytesToBigInt(bytes) {
  assertUint8Array(bytes, "bytes");
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) + BigInt(byte);
  }
  return value;
}

export function bigIntToBytes(value, length = undefined) {
  if (typeof value !== "bigint") {
    throw new TypeError("value must be a bigint");
  }
  if (value < 0n) {
    throw new RangeError("value must be non-negative");
  }

  let hex = value.toString(16);
  if (hex.length % 2 === 1) {
    hex = `0${hex}`;
  }

  let bytes;
  if (value === 0n) {
    bytes = new Uint8Array([0]);
  } else {
    bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i += 1) {
      bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
  }

  if (length === undefined) {
    return bytes;
  }
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError("length must be a non-negative integer");
  }
  if (bytes.length > length) {
    throw new RangeError("value does not fit in requested length");
  }

  const out = new Uint8Array(length);
  out.set(bytes, length - bytes.length);
  return out;
}

export function bitLength(value) {
  if (typeof value !== "bigint") {
    throw new TypeError("value must be a bigint");
  }
  if (value < 0n) {
    throw new RangeError("value must be non-negative");
  }
  return value === 0n ? 0 : value.toString(2).length;
}

export function modulusByteLength(modulus) {
  return Math.ceil(bitLength(modulus) / 8);
}

export function mod(value, modulus) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function exponentWindowBits(exponent) {
  const bits = bitLength(exponent);
  if (bits <= 64) {
    return 1;
  }
  if (bits <= 256) {
    return 4;
  }
  if (bits <= 1024) {
    return 5;
  }
  return 6;
}

export function modPow(base, exponent, modulus) {
  if (typeof base !== "bigint" || typeof exponent !== "bigint" || typeof modulus !== "bigint") {
    throw new TypeError("base, exponent, and modulus must be bigint values");
  }
  if (exponent < 0n) {
    throw new RangeError("exponent must be non-negative");
  }
  if (modulus <= 0n) {
    throw new RangeError("modulus must be positive");
  }

  // Identical results to naive square-and-multiply (preserved for signing,
  // verification, and CIRCL conformance) but using fixed-window (k-ary)
  // exponentiation to cut the number of multiplications on large exponents.
  if (exponent === 0n) {
    return 1n;
  }
  if (modulus === 1n) {
    return 0n;
  }

  const reducedBase = mod(base, modulus);
  const windowBits = exponentWindowBits(exponent);
  const tableSize = 1 << windowBits;
  const powers = new Array(tableSize);
  powers[0] = 1n;
  for (let i = 1; i < tableSize; i += 1) {
    powers[i] = mod(powers[i - 1] * reducedBase, modulus);
  }

  const bits = exponent.toString(2);
  const padding = (windowBits - (bits.length % windowBits)) % windowBits;
  const padded = padding === 0 ? bits : `${"0".repeat(padding)}${bits}`;

  let result = 1n;
  for (let offset = 0; offset < padded.length; offset += windowBits) {
    for (let square = 0; square < windowBits; square += 1) {
      result = mod(result * result, modulus);
    }
    const window = Number.parseInt(padded.slice(offset, offset + windowBits), 2);
    if (window !== 0) {
      result = mod(result * powers[window], modulus);
    }
  }
  return result;
}

export function modInverse(value, modulus) {
  if (modulus <= 0n) {
    throw new RangeError("modulus must be positive");
  }

  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = mod(value, modulus);

  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }

  if (r !== 1n) {
    throw new RangeError("value is not invertible modulo modulus");
  }
  return t < 0n ? t + modulus : t;
}

export function factorial(value) {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError("value must be a non-negative integer");
  }

  let result = 1n;
  for (let i = 2; i <= value; i += 1) {
    result *= BigInt(i);
  }
  return result;
}

export function randomBigIntWithBitLength(bitCount, cryptoProvider = globalThis.crypto) {
  if (!Number.isInteger(bitCount) || bitCount <= 0) {
    throw new RangeError("bitCount must be a positive integer");
  }
  if (!cryptoProvider?.getRandomValues) {
    throw new Error("crypto.getRandomValues is required");
  }

  const byteCount = Math.ceil(bitCount / 8);
  const excessBits = byteCount * 8 - bitCount;
  const bytes = new Uint8Array(byteCount);
  cryptoProvider.getRandomValues(bytes);

  bytes[0] &= 0xff >>> excessBits;
  bytes[0] |= 1 << (7 - excessBits);

  return bytesToBigInt(bytes);
}
