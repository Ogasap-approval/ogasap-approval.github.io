// Encrypted-backup-QR recovery (issue #40).
//
// Implements decode + decrypt for `encrypted_backup_qr_v1`
// (schemas/encrypted_backup_qr_v1.schema.json): Argon2id (RFC 9106) key
// derivation from a user passphrase + AES-256-GCM. The whole thing is pure,
// no-build ESM with no external dependencies, so the Argon2id primitive is
// implemented here and pinned against the RFC 9106 known-answer test in
// test/backup-recovery.test.mjs.
//
// The recovered plaintext is the same `phone_share_package_v1` produced at
// enrollment, so callers import it through the normal (issue #26-hardened)
// storage path.
import { base64urlToBytes, concatBytes, utf8Decode, utf8Encode } from "./core/crypto/bytes.js";
import { canonicalJsonBytes } from "./core/protocol/canonical.js";
import { decodePhoneSharePackageV1 } from "./core/protocol/signing.js";

// ---------------------------------------------------------------------------
// BLAKE2b (RFC 7693) — used by Argon2 for H0, the variable-length hash H', and
// the final tag. Not on the hot path, so a clear BigInt implementation is fine.
// ---------------------------------------------------------------------------
const MASK64 = (1n << 64n) - 1n;
const BLAKE2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
];
const BLAKE2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
];

function rotr64Big(x, n) {
  return ((x >> n) | (x << (64n - n))) & MASK64;
}

function blake2bMix(v, a, b, c, d, x, y) {
  v[a] = (v[a] + v[b] + x) & MASK64;
  v[d] = rotr64Big(v[d] ^ v[a], 32n);
  v[c] = (v[c] + v[d]) & MASK64;
  v[b] = rotr64Big(v[b] ^ v[c], 24n);
  v[a] = (v[a] + v[b] + y) & MASK64;
  v[d] = rotr64Big(v[d] ^ v[a], 16n);
  v[c] = (v[c] + v[d]) & MASK64;
  v[b] = rotr64Big(v[b] ^ v[c], 63n);
}

function blake2bWords(bytes, offset) {
  const m = new Array(16);
  for (let w = 0; w < 16; w += 1) {
    let value = 0n;
    for (let byte = 7; byte >= 0; byte -= 1) {
      value = (value << 8n) | BigInt(bytes[offset + w * 8 + byte]);
    }
    m[w] = value;
  }
  return m;
}

function blake2bCompress(h, m, counter, last) {
  const v = [...h, ...BLAKE2B_IV];
  v[12] ^= counter & MASK64;
  v[13] ^= (counter >> 64n) & MASK64;
  if (last) {
    v[14] ^= MASK64;
  }
  for (let round = 0; round < 12; round += 1) {
    const s = BLAKE2B_SIGMA[round % 10];
    blake2bMix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    blake2bMix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    blake2bMix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    blake2bMix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    blake2bMix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    blake2bMix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    blake2bMix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    blake2bMix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (let i = 0; i < 8; i += 1) {
    h[i] = (h[i] ^ v[i] ^ v[i + 8]) & MASK64;
  }
}

function blake2b(outLen, input) {
  if (outLen < 1 || outLen > 64) {
    throw new Error("blake2b output length out of range");
  }
  const h = BLAKE2B_IV.slice();
  h[0] = (h[0] ^ 0x01010000n ^ BigInt(outLen)) & MASK64;
  const len = input.length;
  let offset = 0;
  let counter = 0n;
  while (len - offset > 128) {
    counter += 128n;
    blake2bCompress(h, blake2bWords(input, offset), counter, false);
    offset += 128;
  }
  const remaining = len - offset;
  counter += BigInt(remaining);
  const finalBlock = new Uint8Array(128);
  finalBlock.set(input.subarray(offset, offset + remaining));
  blake2bCompress(h, blake2bWords(finalBlock, 0), counter, true);
  const out = new Uint8Array(outLen);
  for (let i = 0; i < outLen; i += 1) {
    out[i] = Number((h[i >> 3] >> BigInt((i & 7) * 8)) & 0xffn);
  }
  return out;
}

function le32(value) {
  const out = new Uint8Array(4);
  out[0] = value & 0xff;
  out[1] = (value >>> 8) & 0xff;
  out[2] = (value >>> 16) & 0xff;
  out[3] = (value >>> 24) & 0xff;
  return out;
}

// Variable-length hash H' (RFC 9106 section 3.3).
function hprime(outLen, input) {
  const prefix = le32(outLen);
  if (outLen <= 64) {
    return blake2b(outLen, concatBytes(prefix, input));
  }
  const out = new Uint8Array(outLen);
  let v = blake2b(64, concatBytes(prefix, input));
  out.set(v.subarray(0, 32), 0);
  let pos = 32;
  const r = Math.ceil(outLen / 32) - 2;
  for (let i = 2; i <= r; i += 1) {
    v = blake2b(64, v);
    out.set(v.subarray(0, 32), pos);
    pos += 32;
  }
  out.set(blake2b(outLen - 32 * r, v), pos);
  return out;
}

// ---------------------------------------------------------------------------
// Argon2 compression function G — hot path, so 64-bit words are kept as pairs
// of 32-bit lanes in a Uint32Array (word k -> [2k]=low, [2k+1]=high).
// ---------------------------------------------------------------------------
function mul32(a, b) {
  const aL = a & 0xffff;
  const aH = a >>> 16;
  const bL = b & 0xffff;
  const bH = b >>> 16;
  const ll = aL * bL;
  const lh = aL * bH;
  const hl = aH * bL;
  const hh = aH * bH;
  const cross = lh + hl;
  let lo = ll + (cross & 0xffff) * 0x10000;
  const carry = Math.floor(lo / 0x100000000);
  lo %= 0x100000000;
  let hi = hh + Math.floor(cross / 0x10000) + carry;
  hi %= 0x100000000;
  return [lo >>> 0, hi >>> 0];
}

function rotr64Pair(lo, hi, n) {
  if (n === 32) {
    return [hi, lo];
  }
  if (n < 32) {
    return [
      ((lo >>> n) | (hi << (32 - n))) >>> 0,
      ((hi >>> n) | (lo << (32 - n))) >>> 0
    ];
  }
  const m = n - 32;
  return [
    ((hi >>> m) | (lo << (32 - m))) >>> 0,
    ((lo >>> m) | (hi << (32 - m))) >>> 0
  ];
}

// fBlaMka: a + b + 2 * lower32(a) * lower32(b)  (mod 2^64)
function blamka(aLo, aHi, bLo, bHi) {
  const [mLo, mHi] = mul32(aLo, bLo);
  const m2Lo = (mLo << 1) >>> 0;
  const m2Hi = ((mHi << 1) | (mLo >>> 31)) >>> 0;
  let lo = aLo + bLo;
  let hi = (aHi + bHi + (lo > 0xffffffff ? 1 : 0)) >>> 0;
  lo >>>= 0;
  const lo2 = lo + m2Lo;
  const hi2 = (hi + m2Hi + (lo2 > 0xffffffff ? 1 : 0)) >>> 0;
  return [lo2 >>> 0, hi2];
}

function gb(v, a, b, c, d) {
  let aLo = v[2 * a];
  let aHi = v[2 * a + 1];
  let bLo = v[2 * b];
  let bHi = v[2 * b + 1];
  let cLo = v[2 * c];
  let cHi = v[2 * c + 1];
  let dLo = v[2 * d];
  let dHi = v[2 * d + 1];
  [aLo, aHi] = blamka(aLo, aHi, bLo, bHi);
  [dLo, dHi] = rotr64Pair((dLo ^ aLo) >>> 0, (dHi ^ aHi) >>> 0, 32);
  [cLo, cHi] = blamka(cLo, cHi, dLo, dHi);
  [bLo, bHi] = rotr64Pair((bLo ^ cLo) >>> 0, (bHi ^ cHi) >>> 0, 24);
  [aLo, aHi] = blamka(aLo, aHi, bLo, bHi);
  [dLo, dHi] = rotr64Pair((dLo ^ aLo) >>> 0, (dHi ^ aHi) >>> 0, 16);
  [cLo, cHi] = blamka(cLo, cHi, dLo, dHi);
  [bLo, bHi] = rotr64Pair((bLo ^ cLo) >>> 0, (bHi ^ cHi) >>> 0, 63);
  v[2 * a] = aLo;
  v[2 * a + 1] = aHi;
  v[2 * b] = bLo;
  v[2 * b + 1] = bHi;
  v[2 * c] = cLo;
  v[2 * c + 1] = cHi;
  v[2 * d] = dLo;
  v[2 * d + 1] = dHi;
}

const ROW_INDICES = [];
const COL_INDICES = [];
for (let r = 0; r < 8; r += 1) {
  const row = [];
  const col = [];
  for (let k = 0; k < 16; k += 1) {
    row.push(16 * r + k);
  }
  for (let k = 0; k < 8; k += 1) {
    col.push(2 * r + 16 * k, 2 * r + 16 * k + 1);
  }
  ROW_INDICES.push(row);
  COL_INDICES.push(col);
}

function roundP(v, idx) {
  gb(v, idx[0], idx[4], idx[8], idx[12]);
  gb(v, idx[1], idx[5], idx[9], idx[13]);
  gb(v, idx[2], idx[6], idx[10], idx[14]);
  gb(v, idx[3], idx[7], idx[11], idx[15]);
  gb(v, idx[0], idx[5], idx[10], idx[15]);
  gb(v, idx[1], idx[6], idx[11], idx[12]);
  gb(v, idx[2], idx[7], idx[8], idx[13]);
  gb(v, idx[3], idx[4], idx[9], idx[14]);
}

const RBUF = new Uint32Array(256);
const TBUF = new Uint32Array(256);

function compressBlock(prev, ref, out, withXor) {
  for (let i = 0; i < 256; i += 1) {
    const value = (prev[i] ^ ref[i]) >>> 0;
    RBUF[i] = value;
    TBUF[i] = value;
  }
  for (let r = 0; r < 8; r += 1) {
    roundP(RBUF, ROW_INDICES[r]);
  }
  for (let c = 0; c < 8; c += 1) {
    roundP(RBUF, COL_INDICES[c]);
  }
  for (let i = 0; i < 256; i += 1) {
    let value = (RBUF[i] ^ TBUF[i]) >>> 0;
    if (withXor) {
      value = (value ^ out[i]) >>> 0;
    }
    out[i] = value;
  }
}

function loadBlock(mem, blockIndex, bytes) {
  const base = blockIndex * 256;
  for (let w = 0; w < 128; w += 1) {
    const o = w * 8;
    mem[base + 2 * w] = (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
    mem[base + 2 * w + 1] = (bytes[o + 4] | (bytes[o + 5] << 8) | (bytes[o + 6] << 16) | (bytes[o + 7] << 24)) >>> 0;
  }
}

function blockToBytes(block) {
  const out = new Uint8Array(1024);
  for (let w = 0; w < 128; w += 1) {
    const lo = block[2 * w];
    const hi = block[2 * w + 1];
    const o = w * 8;
    out[o] = lo & 0xff;
    out[o + 1] = (lo >>> 8) & 0xff;
    out[o + 2] = (lo >>> 16) & 0xff;
    out[o + 3] = (lo >>> 24) & 0xff;
    out[o + 4] = hi & 0xff;
    out[o + 5] = (hi >>> 8) & 0xff;
    out[o + 6] = (hi >>> 16) & 0xff;
    out[o + 7] = (hi >>> 24) & 0xff;
  }
  return out;
}

function setWord(block, wordIndex, value) {
  block[2 * wordIndex] = value >>> 0;
  block[2 * wordIndex + 1] = Math.floor(value / 0x100000000) >>> 0;
}

function nextAddresses(addressBlock, inputBlock, zeroBlock) {
  const counter = inputBlock[12] + inputBlock[13] * 0x100000000 + 1;
  setWord(inputBlock, 6, counter);
  compressBlock(zeroBlock, inputBlock, addressBlock, false);
  compressBlock(zeroBlock, addressBlock, addressBlock, false);
}

function fillSegment(mem, pass, lane, slice, dataIndependent, ctx) {
  const { lanes, laneLength, segmentLength, memoryBlocks, passes, type, zeroBlock } = ctx;
  let inputBlock = null;
  let addressBlock = null;
  if (dataIndependent) {
    inputBlock = new Uint32Array(256);
    addressBlock = new Uint32Array(256);
    setWord(inputBlock, 0, pass);
    setWord(inputBlock, 1, lane);
    setWord(inputBlock, 2, slice);
    setWord(inputBlock, 3, memoryBlocks);
    setWord(inputBlock, 4, passes);
    setWord(inputBlock, 5, type);
    setWord(inputBlock, 6, 0);
  }

  let startingIndex = 0;
  if (pass === 0 && slice === 0) {
    startingIndex = 2;
    if (dataIndependent) {
      nextAddresses(addressBlock, inputBlock, zeroBlock);
    }
  }

  for (let i = startingIndex; i < segmentLength; i += 1) {
    const column = slice * segmentLength + i;
    const current = lane * laneLength + column;
    const prev = column === 0 ? lane * laneLength + (laneLength - 1) : current - 1;

    let j1;
    let j2;
    if (dataIndependent) {
      if (i % 128 === 0) {
        nextAddresses(addressBlock, inputBlock, zeroBlock);
      }
      const w = i % 128;
      j1 = addressBlock[2 * w] >>> 0;
      j2 = addressBlock[2 * w + 1] >>> 0;
    } else {
      const pbase = prev * 256;
      j1 = mem[pbase] >>> 0;
      j2 = mem[pbase + 1] >>> 0;
    }

    const refLane = pass === 0 && slice === 0 ? lane : j2 % lanes;
    const sameLane = refLane === lane;

    let refAreaSize;
    if (pass === 0) {
      if (slice === 0) {
        refAreaSize = i - 1;
      } else if (sameLane) {
        refAreaSize = slice * segmentLength + i - 1;
      } else {
        refAreaSize = slice * segmentLength + (i === 0 ? -1 : 0);
      }
    } else if (sameLane) {
      refAreaSize = laneLength - segmentLength + i - 1;
    } else {
      refAreaSize = laneLength - segmentLength + (i === 0 ? -1 : 0);
    }

    const x = mul32(j1, j1)[1];
    const y = mul32(refAreaSize >>> 0, x)[1];
    const relative = refAreaSize - 1 - y;

    let start = 0;
    if (pass !== 0) {
      start = slice === 3 ? 0 : (slice + 1) * segmentLength;
    }
    const refIndex = (start + relative) % laneLength;
    const refBlock = refLane * laneLength + refIndex;

    compressBlock(
      mem.subarray(prev * 256, prev * 256 + 256),
      mem.subarray(refBlock * 256, refBlock * 256 + 256),
      mem.subarray(current * 256, current * 256 + 256),
      pass !== 0
    );
  }
}

// Argon2id (RFC 9106). `secret`/`ad` default to empty as in the backup format.
export function argon2id({
  password,
  salt,
  secret = new Uint8Array(0),
  associatedData = new Uint8Array(0),
  parallelism,
  memoryKiB,
  iterations,
  tagLength = 32,
  version = 0x13
}) {
  if (!Number.isInteger(parallelism) || parallelism < 1) {
    throw new Error("argon2id parallelism is invalid");
  }
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("argon2id iterations is invalid");
  }
  if (!Number.isInteger(memoryKiB) || memoryKiB < 8 * parallelism) {
    throw new Error("argon2id memory is too small");
  }
  const lanes = parallelism;
  const memoryBlocks = 4 * lanes * Math.floor(memoryKiB / (4 * lanes));
  const laneLength = memoryBlocks / lanes;
  const segmentLength = laneLength / 4;
  const type = 2;

  const h0 = blake2b(64, concatBytes(
    le32(lanes), le32(tagLength), le32(memoryKiB), le32(iterations), le32(version), le32(type),
    le32(password.length), password,
    le32(salt.length), salt,
    le32(secret.length), secret,
    le32(associatedData.length), associatedData
  ));

  const mem = new Uint32Array(memoryBlocks * 256);
  for (let lane = 0; lane < lanes; lane += 1) {
    loadBlock(mem, lane * laneLength, hprime(1024, concatBytes(h0, le32(0), le32(lane))));
    loadBlock(mem, lane * laneLength + 1, hprime(1024, concatBytes(h0, le32(1), le32(lane))));
  }

  const ctx = { lanes, laneLength, segmentLength, memoryBlocks, passes: iterations, type, zeroBlock: new Uint32Array(256) };
  for (let pass = 0; pass < iterations; pass += 1) {
    for (let slice = 0; slice < 4; slice += 1) {
      const dataIndependent = type === 2 && pass === 0 && slice < 2;
      for (let lane = 0; lane < lanes; lane += 1) {
        fillSegment(mem, pass, lane, slice, dataIndependent, ctx);
      }
    }
  }

  const final = new Uint32Array(256);
  for (let lane = 0; lane < lanes; lane += 1) {
    const base = (lane * laneLength + (laneLength - 1)) * 256;
    for (let i = 0; i < 256; i += 1) {
      final[i] = (final[i] ^ mem[base + i]) >>> 0;
    }
  }
  return hprime(tagLength, blockToBytes(final));
}

// ---------------------------------------------------------------------------
// encrypted_backup_qr_v1 decode / decrypt / import
// ---------------------------------------------------------------------------
const KEY_ID = /^[A-Za-z0-9._:-]+$/u;
const B64URL = /^[A-Za-z0-9_-]+$/u;
const MAX_MEMORY_KIB = 262144; // 256 MiB Argon2id ceiling (DoS hardening)
const MAX_ITERATIONS = 16;
const REQUIRED_KEYS = [
  "version", "key_id", "share_index", "plaintext_schema", "kdf", "encryption",
  "salt_base64url", "nonce_base64url", "ciphertext_base64url", "created_at"
];

// AES-GCM additional authenticated data: the canonical header (every field
// except the ciphertext). Binding it means kdf params, version, created_at,
// salt/nonce etc. cannot be swapped without breaking decryption (issue #40 AAD).
function backupAad(payload) {
  const { ciphertext_base64url, ...header } = payload;
  void ciphertext_base64url;
  return canonicalJsonBytes(header);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertExactKeys(object, keys, label) {
  assert(object !== null && typeof object === "object" && !Array.isArray(object), `${label} must be an object`);
  const actual = Object.keys(object);
  for (const key of keys) {
    assert(actual.includes(key), `${label} is missing ${key}`);
  }
  for (const key of actual) {
    assert(keys.includes(key), `${label} has unexpected field ${key}`);
  }
}

// Strict validation that mirrors schemas/encrypted_backup_qr_v1.schema.json.
export function validateEncryptedBackupQrV1(payload) {
  assertExactKeys(payload, REQUIRED_KEYS, "encrypted backup QR");
  assert(payload.version === "encrypted_backup_qr_v1", "unsupported backup QR version");
  assert(typeof payload.key_id === "string" && payload.key_id.length >= 8 && payload.key_id.length <= 128 && KEY_ID.test(payload.key_id), "backup key_id is invalid");
  assert(Number.isInteger(payload.share_index) && payload.share_index >= 1 && payload.share_index <= 4, "backup share_index is invalid");
  assert(payload.plaintext_schema === "phone_share_package_v1" || payload.plaintext_schema === "company_share_package_v1", "backup plaintext_schema is invalid");

  assertExactKeys(payload.kdf, ["name", "memory_kib", "iterations", "parallelism", "output_len"], "backup kdf");
  assert(payload.kdf.name === "argon2id", "backup kdf must be argon2id");
  // Bounded ranges (DoS hardening): a malicious QR must not be able to request
  // an unbounded Argon2id memory/time cost that freezes or crashes the browser.
  assert(Number.isInteger(payload.kdf.memory_kib) && payload.kdf.memory_kib >= 65536 && payload.kdf.memory_kib <= MAX_MEMORY_KIB, "backup kdf memory_kib is out of range");
  assert(Number.isInteger(payload.kdf.iterations) && payload.kdf.iterations >= 3 && payload.kdf.iterations <= MAX_ITERATIONS, "backup kdf iterations is out of range");
  assert(Number.isInteger(payload.kdf.parallelism) && payload.kdf.parallelism >= 1 && payload.kdf.parallelism <= 8, "backup kdf parallelism is invalid");
  assert(payload.kdf.output_len === 32, "backup kdf output_len must be 32");

  assertExactKeys(payload.encryption, ["name", "tag_len"], "backup encryption");
  assert(payload.encryption.name === "aes-256-gcm", "backup encryption must be aes-256-gcm");
  assert(payload.encryption.tag_len === 16, "backup encryption tag_len must be 16");

  assert(typeof payload.salt_base64url === "string" && payload.salt_base64url.length >= 22 && B64URL.test(payload.salt_base64url), "backup salt is invalid");
  assert(typeof payload.nonce_base64url === "string" && payload.nonce_base64url.length >= 16 && B64URL.test(payload.nonce_base64url), "backup nonce is invalid");
  assert(typeof payload.ciphertext_base64url === "string" && payload.ciphertext_base64url.length >= 32 && payload.ciphertext_base64url.length <= 5000 && B64URL.test(payload.ciphertext_base64url), "backup ciphertext is invalid");
  assert(typeof payload.created_at === "string" && !Number.isNaN(Date.parse(payload.created_at)), "backup created_at is invalid");

  // Decode-then-bound the salt/nonce to exact byte ranges (base64urlToBytes also
  // rejects non-canonical base64url).
  const saltBytes = base64urlToBytes(payload.salt_base64url);
  assert(saltBytes.length >= 16 && saltBytes.length <= 64, "backup salt length is invalid");
  const nonceBytes = base64urlToBytes(payload.nonce_base64url);
  assert(nonceBytes.length === 12, "backup nonce must be 96-bit (12 bytes)");
  return payload;
}

export function deriveBackupKey(passphrase, payload) {
  return argon2id({
    password: utf8Encode(passphrase),
    salt: base64urlToBytes(payload.salt_base64url),
    parallelism: payload.kdf.parallelism,
    memoryKiB: payload.kdf.memory_kib,
    iterations: payload.kdf.iterations,
    tagLength: payload.kdf.output_len
  });
}

// Decodes + decrypts an encrypted_backup_qr_v1 payload with the user's
// passphrase and returns the recovered, strictly-validated share package.
// `deriveKey` is injectable so the wiring can be tested without paying the full
// Argon2id cost (the primitive itself is covered by the RFC 9106 KAT).
export async function decodeEncryptedBackupQrV1(payload, passphrase, { deriveKey = deriveBackupKey } = {}) {
  validateEncryptedBackupQrV1(payload);
  assert(typeof passphrase === "string" && passphrase.length > 0, "backup passphrase is required");
  // The approval app only ever imports phone shares. Refuse company-share
  // backups here rather than returning unvalidated attacker JSON (issue #40).
  assert(payload.plaintext_schema === "phone_share_package_v1", "only phone_share_package_v1 backups can be recovered in the approval app");

  const keyBytes = await deriveKey(passphrase, payload);
  assert(keyBytes instanceof Uint8Array && keyBytes.length === payload.kdf.output_len, "derived backup key has the wrong length");
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);

  let plaintextBytes;
  try {
    plaintextBytes = new Uint8Array(await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64urlToBytes(payload.nonce_base64url),
        additionalData: backupAad(payload),
        tagLength: payload.encryption.tag_len * 8
      },
      key,
      base64urlToBytes(payload.ciphertext_base64url)
    ));
  } catch {
    throw new Error("backup decryption failed (wrong passphrase, tampered header, or corrupt backup)");
  }

  let plaintext;
  try {
    plaintext = JSON.parse(utf8Decode(plaintextBytes));
  } catch {
    throw new Error("backup plaintext is not valid JSON");
  }

  assert(plaintext?.version === payload.plaintext_schema, "backup plaintext schema mismatch");
  decodePhoneSharePackageV1(plaintext);
  assert(plaintext.key_id === payload.key_id, "backup key_id does not match the recovered share");
  assert(plaintext.share_index === payload.share_index, "backup share_index does not match the recovered share");
  return plaintext;
}

// Builds an encrypted_backup_qr_v1 payload. Provided so the decode path has a
// matching producer (there is no other in-repo producer to mirror) and so the
// round-trip can be exercised in tests.
export async function encryptBackupQrV1({ share, passphrase, kdf, saltBytes, nonceBytes, createdAt }, { deriveKey = deriveBackupKey } = {}) {
  assert(typeof passphrase === "string" && passphrase.length > 0, "backup passphrase is required");
  const salt = saltBytes ?? crypto.getRandomValues(new Uint8Array(16));
  const nonce = nonceBytes ?? crypto.getRandomValues(new Uint8Array(12));
  const payloadKdf = kdf ?? { name: "argon2id", memory_kib: 65536, iterations: 3, parallelism: 1, output_len: 32 };
  const draft = {
    version: "encrypted_backup_qr_v1",
    key_id: share.key_id,
    share_index: share.share_index,
    plaintext_schema: share.version,
    kdf: payloadKdf,
    encryption: { name: "aes-256-gcm", tag_len: 16 },
    salt_base64url: bytesToBase64urlLocal(salt),
    nonce_base64url: bytesToBase64urlLocal(nonce),
    ciphertext_base64url: "",
    created_at: createdAt ?? new Date().toISOString()
  };
  const keyBytes = await deriveKey(passphrase, draft);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: backupAad(draft), tagLength: 128 },
    key,
    utf8Encode(JSON.stringify(share))
  ));
  draft.ciphertext_base64url = bytesToBase64urlLocal(ciphertext);
  return validateEncryptedBackupQrV1(draft);
}

function bytesToBase64urlLocal(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = typeof btoa === "function" ? btoa(binary) : Buffer.from(binary, "binary").toString("base64");
  return base64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
