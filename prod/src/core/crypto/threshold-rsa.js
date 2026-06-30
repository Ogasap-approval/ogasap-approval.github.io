import {
  bitLength,
  bigIntToBytes,
  bytesToBigInt,
  factorial,
  mod,
  modInverse,
  modPow,
  modulusByteLength,
  randomBigIntWithBitLength
} from "./bigint.js";
import { marshalSignShare } from "./circl-signshare.js";
import { pkcs1v15PaddedMessageForModulus } from "./pkcs1v15.js";

// Capability token that unlocks the unblinded (`blinded: false`) partial-
// signature path. The raw unblinded path raises the secret share directly to a
// variable-time exponentiation and so must never run in production; gating it
// behind a Symbol means production callers cannot reach it even by accident,
// while tests that need deterministic math import and pass this exact value.
export const UNSAFE_ALLOW_UNBLINDED = Symbol("UNSAFE_ALLOW_UNBLINDED");

export function thresholdRsaExponent(shareSi, players) {
  if (typeof shareSi !== "bigint") {
    throw new TypeError("shareSi must be a bigint");
  }
  return 2n * factorial(players) * shareSi;
}

function sameNumber(values, name) {
  const [first, ...rest] = values;
  for (const value of rest) {
    if (value !== first) {
      throw new Error(`${name} mismatch`);
    }
  }
  return first;
}

function extendedGcd(a, b) {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;

  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
    [oldT, t] = [t, oldT - quotient * t];
  }

  return {
    gcd: oldR,
    a: oldS,
    b: oldT
  };
}

function signedModPow(base, exponent, modulus) {
  if (exponent >= 0n) {
    return modPow(base, exponent, modulus);
  }
  return modInverse(modPow(base, -exponent, modulus), modulus);
}

function modPowPairSameBase(base, leftExponent, rightExponent, modulus) {
  let left = 1n;
  let right = 1n;
  let b = mod(base, modulus);
  let l = leftExponent;
  let r = rightExponent;
  while (l > 0n || r > 0n) {
    if ((l & 1n) === 1n) {
      left = mod(left * b, modulus);
    }
    if ((r & 1n) === 1n) {
      right = mod(right * b, modulus);
    }
    l >>= 1n;
    r >>= 1n;
    b = mod(b * b, modulus);
  }
  return [left, right];
}

function computeLambda(delta, shares, i, j) {
  if (i === j) {
    throw new Error("lambda interpolation points must differ");
  }

  let foundJ = false;
  let num = 1n;
  let den = 1n;
  for (const share of shares) {
    const jPrime = BigInt(share.index);
    if (jPrime === j) {
      foundJ = true;
      continue;
    }
    if (jPrime === i) {
      throw new Error("lambda interpolation target must not be in share set");
    }
    num *= i - jPrime;
    den *= j - jPrime;
  }

  if (!foundJ) {
    throw new Error("lambda interpolation share missing from set");
  }
  const scaledNum = delta * num;
  if (scaledNum % den !== 0n) {
    throw new Error("lambda interpolation division was not exact");
  }
  return scaledNum / den;
}

// TRUST BOUNDARY (#36): `combineSignShares` self-verifies the reconstructed
// signature against the CALLER-SUPPLIED `paddedDigest` (`modPow(y, e, N) === x`,
// where `x = bytesToBigInt(paddedDigest)`). It therefore only proves the
// combined signature is valid for *that* digest — it has no notion of which
// message the digest represents. Binding the digest to the intended,
// authenticated message is the CALLER's responsibility: every caller must
// locally re-encode the canonical authenticated message into `paddedDigest` and
// must never accept a digest received from the network. A wrong-but-in-range
// digest will still combine successfully; combine cannot detect it.
//
// SEMI-HONEST / NON-ROBUST ASSUMPTION (#37): this is Shoup "Protocol 1"
// combination WITHOUT robustness — there are NO per-share validity proofs. The
// scheme assumes the share holders (the four mutually-known operators) are
// honest-but-curious. A malicious or buggy share holder cannot forge a
// signature, but it can submit a bad partial that makes combination abort with
// no attribution of which player misbehaved (a denial-of-service, not a forgery).
export function combineSignShares({ modulus, publicExponent, shares, paddedDigest }) {
  if (!Array.isArray(shares) || shares.length === 0) {
    throw new Error("at least one sign share is required");
  }
  const exponent = BigInt(publicExponent);

  const players = sameNumber(shares.map((share) => share.players), "share players");
  const threshold = sameNumber(shares.map((share) => share.threshold), "share threshold");
  if (shares.length < threshold) {
    throw new Error("insufficient sign shares for threshold");
  }
  const shareIndexes = new Set(shares.map((share) => share.index));
  if (shareIndexes.size !== shares.length) {
    throw new Error("duplicate sign share index");
  }

  const x = bytesToBigInt(paddedDigest);
  if (x <= 0n || x >= modulus) {
    throw new Error("padded digest integer is out of RSA range");
  }

  const delta = factorial(players);
  let w = 1n;
  for (const share of shares) {
    if (share.xi <= 0n || share.xi >= modulus) {
      throw new Error(`sign share ${share.index} is out of RSA range`);
    }

    const lambda = computeLambda(delta, shares, 0n, BigInt(share.index));
    const exp = 2n * lambda;
    const powered = signedModPow(share.xi, exp, modulus);
    w = mod(w * powered, modulus);
  }

  const ePrime = 4n * delta * delta;
  const bezout = extendedGcd(ePrime, exponent);
  if (bezout.gcd !== 1n) {
    throw new Error("public exponent is not coprime with threshold exponent");
  }

  const y = mod(
    signedModPow(w, bezout.a, modulus) * signedModPow(x, bezout.b, modulus),
    modulus
  );
  if (modPow(y, exponent, modulus) !== x) {
    throw new Error("combined RSA signature verification failed");
  }

  return bigIntToBytes(y, modulusByteLength(modulus));
}

export function partialSignatureXi({
  paddedDigest,
  modulus,
  shareSi,
  players = 4,
  blinded = true,
  allowUnblinded,
  cryptoProvider = globalThis.crypto
}) {
  if (!(paddedDigest instanceof Uint8Array)) {
    throw new TypeError("paddedDigest must be a Uint8Array");
  }
  if (typeof modulus !== "bigint" || modulus <= 1n) {
    throw new RangeError("modulus must be a bigint greater than 1");
  }
  if (paddedDigest.length !== modulusByteLength(modulus)) {
    throw new RangeError("paddedDigest length must match RSA modulus length");
  }
  if (!blinded && allowUnblinded !== UNSAFE_ALLOW_UNBLINDED) {
    throw new Error("unblinded partial signatures are disabled outside tests; pass UNSAFE_ALLOW_UNBLINDED to opt in");
  }

  const x = bytesToBigInt(paddedDigest);
  if (x <= 0n || x >= modulus) {
    throw new RangeError("paddedDigest integer must be in range 1..N-1");
  }

  const exponent = thresholdRsaExponent(shareSi, players);
  if (!blinded) {
    return modPow(x, exponent, modulus);
  }

  const randomBits = Math.max(bitLength(exponent), bitLength(modulus));
  const r = randomBigIntWithBitLength(randomBits, cryptoProvider);
  const [blindedPower, unblindPower] = modPowPairSameBase(x, exponent + r, r, modulus);
  return mod(blindedPower * modInverse(unblindPower, modulus), modulus);
}

export function signShareForPaddedDigest({
  paddedDigest,
  modulus,
  shareSi,
  shareIndex,
  players = 4,
  threshold = 3,
  blinded = true,
  allowUnblinded,
  cryptoProvider = globalThis.crypto
}) {
  const xi = partialSignatureXi({
    paddedDigest,
    modulus,
    shareSi,
    players,
    blinded,
    allowUnblinded,
    cryptoProvider
  });

  return marshalSignShare({
    players,
    threshold,
    index: shareIndex,
    xi
  });
}

export async function signShareForMessagePkcs1v15({
  message,
  modulus,
  shareSi,
  shareIndex,
  players = 4,
  threshold = 3,
  blinded = true,
  allowUnblinded,
  cryptoProvider = globalThis.crypto
}) {
  const paddedDigest = await pkcs1v15PaddedMessageForModulus(message, modulus, cryptoProvider);
  return signShareForPaddedDigest({
    paddedDigest,
    modulus,
    shareSi,
    shareIndex,
    players,
    threshold,
    blinded,
    allowUnblinded,
    cryptoProvider
  });
}
