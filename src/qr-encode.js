// Dependency-free, no-build multi-part (animated) QR encoder for the approval
// PWA (issue: phone-to-phone encrypted-backup hand-off).
//
// Why this module exists
// ----------------------
// The encrypted backup payload is ~1.8-2.4 KB and the small migration hand-off
// payloads are a few hundred bytes. A single QR symbol for ~2 KB needs a very
// high version (dense module grid) that is unreliable to scan phone-to-phone.
// So we split the payload into chunks, render each chunk as its OWN low/medium
// version QR frame, and cycle the frames on screen ("animated QR"). The scanner
// side uses the browser's native BarcodeDetector, which yields each QR's decoded
// TEXT, so every frame is a plain ASCII string (see MULTIPART_PREFIX format).
//
// This file is intentionally self-contained: the only imports are the repo's
// existing byte/encoding helpers. It is an APP-LAYER module and deliberately
// does NOT live under pwa/src/core/ (that subtree is under a byte-identity drift
// guard). It pulls in zero third-party code (the repo ships zero runtime deps).
//
// The QR encoder implements BYTE and NUMERIC modes, full Reed-Solomon error
// correction over GF(2^8) with primitive polynomial 0x11D, all function
// patterns (finders, separators, timing, alignment, dark module), BCH format
// information, BCH version information (v >= 7), the 8 data masks, and the 4
// standard penalty rules for automatic mask selection. It is validated in
// test/qr-encode.test.mjs against the ISO/IEC 18004 Annex worked example
// ("01234567", version 1, EC level M) and the Reed-Solomon worked example.

import {
  assertUint8Array,
  base64urlToBytes,
  bytesToBase64url,
  bytesToHex,
  concatBytes,
  utf8Encode
} from "./core/crypto/bytes.js";

// ---------------------------------------------------------------------------
// QR static tables (ISO/IEC 18004). Indexed by EC level then version (1..40);
// index 0 is an unused padding slot so the version number maps directly.
// ---------------------------------------------------------------------------
const EC_LEVELS = ["L", "M", "Q", "H"];
const EC_ORDINAL = { L: 0, M: 1, Q: 2, H: 3 };
// Format-information 2-bit field per EC level (NOT the same order as EC_ORDINAL).
const EC_FORMAT_BITS = { L: 1, M: 0, Q: 3, H: 2 };

const MIN_QR_VERSION = 1;
const MAX_QR_VERSION = 40;

// Number of error-correction codewords per block.
const ECC_CODEWORDS_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // L
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28], // M
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // Q
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30] // H
];

// Number of error-correction blocks the data is split across.
const NUM_ERROR_CORRECTION_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25], // L
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49], // M
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68], // Q
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81] // H
];

// Penalty-rule weights from the standard.
const PENALTY_N1 = 3;
const PENALTY_N2 = 3;
const PENALTY_N3 = 40;
const PENALTY_N4 = 10;

const MODE_NUMERIC = { bits: 0x1, countBits: [10, 12, 14] };
const MODE_BYTE = { bits: 0x4, countBits: [8, 16, 16] };

/**
 * Computes the 15-bit BCH format-information string for an (ecLevel, mask)
 * pair: 5 data bits (2-bit EC field + 3-bit mask) extended with a 10-bit BCH
 * code (generator 0x537) then XOR'd with the standard mask 0x5412.
 *
 * @param {"L"|"M"|"Q"|"H"} ecLevel
 * @param {number} mask 0..7
 * @returns {number} 15-bit value
 */
export function formatInfoBits(ecLevel, mask) {
  const data = (EC_FORMAT_BITS[ecLevel] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i += 1) {
    rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  }
  return ((data << 10) | rem) ^ 0x5412;
}

// ---------------------------------------------------------------------------
// GF(2^8) arithmetic and Reed-Solomon (primitive polynomial 0x11D, generator 2)
// ---------------------------------------------------------------------------

// Multiplies two GF(2^8) elements modulo x^8 + x^4 + x^3 + x^2 + 1 (0x11D).
export function gf256Multiply(x, y) {
  if (x >>> 8 !== 0 || y >>> 8 !== 0) {
    throw new RangeError("gf256Multiply operands must be bytes");
  }
  let z = 0;
  for (let i = 7; i >= 0; i -= 1) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

// Builds the degree-`degree` Reed-Solomon generator polynomial, returned as the
// coefficients from x^(degree-1) down to x^0 (the leading 1 is implicit).
export function reedSolomonGeneratorPolynomial(degree) {
  if (degree < 1 || degree > 254) {
    throw new RangeError("RS degree out of range");
  }
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1; // 2^0
  for (let i = 0; i < degree; i += 1) {
    for (let j = 0; j < degree; j += 1) {
      result[j] = gf256Multiply(result[j], root);
      if (j + 1 < degree) {
        result[j] ^= result[j + 1];
      }
    }
    root = gf256Multiply(root, 0x02);
  }
  return result;
}

// Computes the `degree` error-correction codewords for the given data block.
export function reedSolomonRemainder(data, degree) {
  const divisor = reedSolomonGeneratorPolynomial(degree);
  const result = new Uint8Array(degree);
  for (const b of data) {
    const factor = b ^ result[0];
    result.copyWithin(0, 1);
    result[degree - 1] = 0;
    for (let i = 0; i < degree; i += 1) {
      result[i] ^= gf256Multiply(divisor[i], factor);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Version geometry helpers (closed-form, matching ISO/IEC 18004).
// ---------------------------------------------------------------------------

function numRawDataModules(version) {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) {
      result -= 36;
    }
  }
  return result;
}

function numDataCodewords(version, ecLevel) {
  const ord = EC_ORDINAL[ecLevel];
  return (
    Math.floor(numRawDataModules(version) / 8) -
    ECC_CODEWORDS_PER_BLOCK[ord][version] * NUM_ERROR_CORRECTION_BLOCKS[ord][version]
  );
}

function alignmentPatternPositions(version) {
  if (version === 1) {
    return [];
  }
  const size = version * 4 + 17;
  const numAlign = Math.floor(version / 7) + 2;
  const step = Math.floor((version * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2;
  const result = [6];
  for (let pos = size - 7; result.length < numAlign; pos -= step) {
    result.splice(1, 0, pos);
  }
  return result;
}

function charCountBits(mode, version) {
  return mode.countBits[Math.floor((version + 7) / 17)];
}

// ---------------------------------------------------------------------------
// Bit-buffer assembly (mode indicator, char count, data, terminator, padding).
// ---------------------------------------------------------------------------

function appendBits(bits, value, length) {
  if (length < 0 || length > 31 || value >>> length !== 0) {
    throw new RangeError("appendBits value out of range");
  }
  for (let i = length - 1; i >= 0; i -= 1) {
    bits.push((value >>> i) & 1);
  }
}

// Encodes BYTE-mode segment payload bits (8 bits per byte) for the given bytes.
function byteSegmentBits(bytes) {
  const bits = [];
  for (const b of bytes) {
    appendBits(bits, b, 8);
  }
  return bits;
}

// Encodes NUMERIC-mode segment payload bits: groups of 3/2/1 digits map to
// 10/7/4 bits respectively. `digits` is an array of digit values (0-9).
function numericSegmentBits(digits) {
  const bits = [];
  for (let i = 0; i < digits.length; i += 3) {
    const group = digits.slice(i, i + 3);
    let value = 0;
    for (const d of group) {
      value = value * 10 + d;
    }
    appendBits(bits, value, group.length * 3 + 1);
  }
  return bits;
}

// Builds the final data codewords: prepend mode + char-count, append the
// 4-bit terminator, pad to a byte boundary, then alternate 0xEC / 0x11 pad
// bytes up to the version+EC data capacity. Returns a Uint8Array.
function buildDataCodewords(mode, charCount, segmentBits, version, ecLevel) {
  const capacityBits = numDataCodewords(version, ecLevel) * 8;
  const bits = [];
  appendBits(bits, mode.bits, 4);
  appendBits(bits, charCount, charCountBits(mode, version));
  for (const bit of segmentBits) {
    bits.push(bit);
  }
  // 4-bit terminator (or fewer if near capacity).
  appendBits(bits, 0, Math.min(4, capacityBits - bits.length));
  // Pad to a byte boundary.
  appendBits(bits, 0, (8 - (bits.length % 8)) % 8);
  // Alternating pad bytes.
  for (let padByte = 0xec; bits.length < capacityBits; padByte ^= 0xec ^ 0x11) {
    appendBits(bits, padByte, 8);
  }

  const codewords = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i += 1) {
    codewords[i >>> 3] |= bits[i] << (7 - (i & 7));
  }
  return codewords;
}

// Splits data codewords into EC blocks, appends RS codewords, and interleaves
// data then EC bytes into the final codeword stream placed onto the matrix.
function addEccAndInterleave(dataCodewords, version, ecLevel) {
  const ord = EC_ORDINAL[ecLevel];
  const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ord][version];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[ord][version];
  const rawCodewords = Math.floor(numRawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockDataLen = Math.floor(rawCodewords / numBlocks) - blockEccLen;

  const blocks = [];
  let offset = 0;
  for (let i = 0; i < numBlocks; i += 1) {
    const dataLen = shortBlockDataLen + (i < numShortBlocks ? 0 : 1);
    const dat = dataCodewords.subarray(offset, offset + dataLen);
    offset += dataLen;
    const ecc = reedSolomonRemainder(dat, blockEccLen);
    blocks.push({ data: dat, ecc });
  }

  const result = [];
  // Interleave data codewords (skip the missing column of short blocks).
  for (let i = 0; i < shortBlockDataLen + 1; i += 1) {
    for (let j = 0; j < numBlocks; j += 1) {
      if (i < shortBlockDataLen || j >= numShortBlocks) {
        result.push(blocks[j].data[i]);
      }
    }
  }
  // Interleave EC codewords.
  for (let i = 0; i < blockEccLen; i += 1) {
    for (let j = 0; j < numBlocks; j += 1) {
      result.push(blocks[j].ecc[i]);
    }
  }
  return Uint8Array.from(result);
}

// ---------------------------------------------------------------------------
// Matrix construction.
// ---------------------------------------------------------------------------

function makeGrid(size, value) {
  const grid = new Array(size);
  for (let y = 0; y < size; y += 1) {
    grid[y] = new Array(size).fill(value);
  }
  return grid;
}

function getBit(value, i) {
  return ((value >>> i) & 1) !== 0;
}

class QrMatrix {
  constructor(version, ecLevel) {
    this.version = version;
    this.ecLevel = ecLevel;
    this.size = version * 4 + 17;
    this.modules = makeGrid(this.size, false);
    this.isFunction = makeGrid(this.size, false);
  }

  setFunctionModule(x, y, isDark) {
    this.modules[y][x] = isDark;
    this.isFunction[y][x] = true;
  }

  drawFinderPattern(cx, cy) {
    for (let dy = -4; dy <= 4; dy += 1) {
      for (let dx = -4; dx <= 4; dx += 1) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx;
        const y = cy + dy;
        if (x >= 0 && x < this.size && y >= 0 && y < this.size) {
          this.setFunctionModule(x, y, dist !== 2 && dist !== 4);
        }
      }
    }
  }

  drawAlignmentPattern(cx, cy) {
    for (let dy = -2; dy <= 2; dy += 1) {
      for (let dx = -2; dx <= 2; dx += 1) {
        this.setFunctionModule(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  drawFunctionPatterns() {
    // Timing patterns.
    for (let i = 0; i < this.size; i += 1) {
      this.setFunctionModule(6, i, i % 2 === 0);
      this.setFunctionModule(i, 6, i % 2 === 0);
    }
    // Three finder patterns (with separators implied by the 9x9 footprint).
    this.drawFinderPattern(3, 3);
    this.drawFinderPattern(this.size - 4, 3);
    this.drawFinderPattern(3, this.size - 4);
    // Alignment patterns (skip the three finder corners).
    const positions = alignmentPatternPositions(this.version);
    const n = positions.length;
    for (let i = 0; i < n; i += 1) {
      for (let j = 0; j < n; j += 1) {
        if (!((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0))) {
          this.drawAlignmentPattern(positions[i], positions[j]);
        }
      }
    }
    // Reserve format/version areas (real bits drawn later).
    this.drawFormatBits(0);
    this.drawVersionBits();
  }

  drawFormatBits(mask) {
    const bits = formatInfoBits(this.ecLevel, mask); // 15-bit format string

    for (let i = 0; i <= 5; i += 1) {
      this.setFunctionModule(8, i, getBit(bits, i));
    }
    this.setFunctionModule(8, 7, getBit(bits, 6));
    this.setFunctionModule(8, 8, getBit(bits, 7));
    this.setFunctionModule(7, 8, getBit(bits, 8));
    for (let i = 9; i < 15; i += 1) {
      this.setFunctionModule(14 - i, 8, getBit(bits, i));
    }

    for (let i = 0; i < 8; i += 1) {
      this.setFunctionModule(this.size - 1 - i, 8, getBit(bits, i));
    }
    for (let i = 8; i < 15; i += 1) {
      this.setFunctionModule(8, this.size - 15 + i, getBit(bits, i));
    }
    this.setFunctionModule(8, this.size - 8, true); // dark module
  }

  drawVersionBits() {
    if (this.version < 7) {
      return;
    }
    let rem = this.version;
    for (let i = 0; i < 12; i += 1) {
      rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    }
    const bits = (this.version << 12) | rem; // 18-bit version string
    for (let i = 0; i < 18; i += 1) {
      const color = getBit(bits, i);
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.setFunctionModule(a, b, color);
      this.setFunctionModule(b, a, color);
    }
  }

  drawCodewords(data) {
    let i = 0; // bit index
    for (let right = this.size - 1; right >= 1; right -= 2) {
      // Skip the vertical timing column; the left column pair is 5,4 (not 6,5).
      if (right === 6) {
        right = 5;
      }
      for (let vert = 0; vert < this.size; vert += 1) {
        for (let j = 0; j < 2; j += 1) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
            i += 1;
          }
        }
      }
    }
  }

  applyMask(mask) {
    for (let y = 0; y < this.size; y += 1) {
      for (let x = 0; x < this.size; x += 1) {
        if (this.isFunction[y][x]) {
          continue;
        }
        let invert;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = (((x * y) % 2) + ((x * y) % 3)) === 0; break;
          case 6: invert = ((((x * y) % 2) + ((x * y) % 3)) % 2) === 0; break;
          case 7: invert = ((((x + y) % 2) + ((x * y) % 3)) % 2) === 0; break;
          default: throw new RangeError("mask out of range");
        }
        if (invert) {
          this.modules[y][x] = !this.modules[y][x];
        }
      }
    }
  }

  penaltyScore() {
    return qrPenaltyScore(this.modules);
  }
}

// ---- Penalty scoring (the 4 standard rules), as a pure function over a grid ----

function finderPenaltyCountPatterns(history) {
  const n = history[1];
  const core =
    n > 0 && history[2] === n && history[3] === n * 3 && history[4] === n && history[5] === n;
  return (
    (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0) +
    (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0)
  );
}

function finderPenaltyAddHistory(runLength, history, size) {
  if (history[0] === 0) {
    runLength += size; // light border before the first run
  }
  history.pop();
  history.unshift(runLength);
}

function finderPenaltyTerminateAndCount(runColor, runLength, history, size) {
  if (runColor) {
    finderPenaltyAddHistory(runLength, history, size);
    runLength = 0;
  }
  runLength += size; // light border after the last run
  finderPenaltyAddHistory(runLength, history, size);
  return finderPenaltyCountPatterns(history);
}

/**
 * Computes the QR penalty score (4 standard rules) for a square boolean grid.
 * Exposed so tests can prove the auto mask selection picks a lowest-penalty mask.
 *
 * @param {boolean[][]} modules
 * @returns {number}
 */
export function qrPenaltyScore(modules) {
  const size = modules.length;
  let result = 0;

  // Rule 1 (runs) + rule 3 (finder-like) along each row.
  for (let y = 0; y < size; y += 1) {
    let runColor = false;
    let runLength = 0;
    const history = [0, 0, 0, 0, 0, 0, 0];
    for (let x = 0; x < size; x += 1) {
      if (modules[y][x] === runColor) {
        runLength += 1;
        if (runLength === 5) {
          result += PENALTY_N1;
        } else if (runLength > 5) {
          result += 1;
        }
      } else {
        finderPenaltyAddHistory(runLength, history, size);
        if (!runColor) {
          result += finderPenaltyCountPatterns(history) * PENALTY_N3;
        }
        runColor = modules[y][x];
        runLength = 1;
      }
    }
    result += finderPenaltyTerminateAndCount(runColor, runLength, history, size) * PENALTY_N3;
  }

  // Rule 1 (runs) + rule 3 (finder-like) along each column.
  for (let x = 0; x < size; x += 1) {
    let runColor = false;
    let runLength = 0;
    const history = [0, 0, 0, 0, 0, 0, 0];
    for (let y = 0; y < size; y += 1) {
      if (modules[y][x] === runColor) {
        runLength += 1;
        if (runLength === 5) {
          result += PENALTY_N1;
        } else if (runLength > 5) {
          result += 1;
        }
      } else {
        finderPenaltyAddHistory(runLength, history, size);
        if (!runColor) {
          result += finderPenaltyCountPatterns(history) * PENALTY_N3;
        }
        runColor = modules[y][x];
        runLength = 1;
      }
    }
    result += finderPenaltyTerminateAndCount(runColor, runLength, history, size) * PENALTY_N3;
  }

  // Rule 2: 2x2 blocks of a single color.
  for (let y = 0; y < size - 1; y += 1) {
    for (let x = 0; x < size - 1; x += 1) {
      const color = modules[y][x];
      if (
        color === modules[y][x + 1] &&
        color === modules[y + 1][x] &&
        color === modules[y + 1][x + 1]
      ) {
        result += PENALTY_N2;
      }
    }
  }

  // Rule 4: dark/light balance.
  let dark = 0;
  for (const row of modules) {
    for (const color of row) {
      if (color) {
        dark += 1;
      }
    }
  }
  const total = size * size;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  result += k * PENALTY_N4;
  return result;
}

// ---------------------------------------------------------------------------
// Public: encodeQrMatrix
// ---------------------------------------------------------------------------

function selectVersion(mode, charCount, segmentBitLength, ecLevel, minVersion) {
  for (let version = Math.max(minVersion, MIN_QR_VERSION); version <= MAX_QR_VERSION; version += 1) {
    const capacityBits = numDataCodewords(version, ecLevel) * 8;
    const usedBits = 4 + charCountBits(mode, version) + segmentBitLength;
    // The char-count field must also be wide enough to hold the count.
    if (charCount < 1 << charCountBits(mode, version) && usedBits <= capacityBits) {
      return version;
    }
  }
  throw new Error("payload too large for QR");
}

/**
 * Encodes a payload into a single QR segment + data codewords, choosing the
 * smallest fitting version. Exposed so tests can assert byte-mode bit packing
 * (mode indicator, char count, 0xEC/0x11 padding) and version selection.
 *
 * @param {Uint8Array} bytes
 * @param {object} [options]
 * @param {"L"|"M"|"Q"|"H"} [options.ecLevel="M"]
 * @param {number} [options.minVersion=1]
 * @param {"byte"|"numeric"} [options.mode="byte"]
 * @returns {{version:number,mode:string,dataCodewords:Uint8Array}}
 */
export function encodeDataCodewords(bytes, { ecLevel = "M", minVersion = 1, mode = "byte" } = {}) {
  assertUint8Array(bytes, "bytes");
  if (!EC_LEVELS.includes(ecLevel)) {
    throw new Error(`unknown ecLevel: ${ecLevel}`);
  }

  let segmentMode;
  let segmentBits;
  let charCount;
  if (mode === "numeric") {
    const digits = [];
    for (const b of bytes) {
      if (b < 0x30 || b > 0x39) {
        throw new Error("numeric mode requires ASCII decimal digits");
      }
      digits.push(b - 0x30);
    }
    segmentMode = MODE_NUMERIC;
    segmentBits = numericSegmentBits(digits);
    charCount = digits.length;
  } else if (mode === "byte") {
    segmentMode = MODE_BYTE;
    segmentBits = byteSegmentBits(bytes);
    charCount = bytes.length;
  } else {
    throw new Error(`unknown mode: ${mode}`);
  }

  const version = selectVersion(segmentMode, charCount, segmentBits.length, ecLevel, minVersion);
  const dataCodewords = buildDataCodewords(segmentMode, charCount, segmentBits, version, ecLevel);
  return { version, mode, dataCodewords };
}

/**
 * Encodes `bytes` (Uint8Array) into a QR module matrix.
 *
 * @param {Uint8Array} bytes - payload bytes. In the default "byte" mode these
 *   are encoded directly; in "numeric" mode they must be ASCII decimal digits.
 * @param {object} [options]
 * @param {"L"|"M"|"Q"|"H"} [options.ecLevel="M"] - error-correction level.
 * @param {number} [options.minVersion=1] - smallest QR version to consider.
 * @param {"byte"|"numeric"} [options.mode="byte"] - segment encoding mode.
 *   ("numeric" exists so the module can be validated against the ISO/IEC 18004
 *   Annex worked example; production framing always uses "byte".)
 * @param {number|null} [options.mask=null] - force a data mask 0..7; when null
 *   the lowest-penalty mask is chosen per the standard.
 * @returns {{version:number,size:number,modules:boolean[][],mask:number}}
 *   `modules` is a size x size boolean grid (true = dark). `mask` is the data
 *   mask that was applied (an additive convenience field).
 */
export function encodeQrMatrix(bytes, { ecLevel = "M", minVersion = 1, mode = "byte", mask = null } = {}) {
  if (mask !== null && (!Number.isInteger(mask) || mask < 0 || mask > 7)) {
    throw new Error("mask must be an integer 0..7 or null");
  }

  const { version, dataCodewords } = encodeDataCodewords(bytes, { ecLevel, minVersion, mode });
  const allCodewords = addEccAndInterleave(dataCodewords, version, ecLevel);

  const qr = new QrMatrix(version, ecLevel);
  qr.drawFunctionPatterns();
  qr.drawCodewords(allCodewords);

  let chosenMask = mask;
  if (chosenMask === null) {
    let bestPenalty = Infinity;
    for (let m = 0; m < 8; m += 1) {
      qr.applyMask(m);
      qr.drawFormatBits(m);
      const penalty = qr.penaltyScore();
      if (penalty < bestPenalty) {
        bestPenalty = penalty;
        chosenMask = m;
      }
      qr.applyMask(m); // undo (XOR is its own inverse)
    }
  }

  qr.applyMask(chosenMask);
  qr.drawFormatBits(chosenMask);

  return { version: qr.version, size: qr.size, modules: qr.modules, mask: chosenMask };
}

// ---------------------------------------------------------------------------
// Public: renderQrToCanvas (browser-only; not exercised by node tests)
// ---------------------------------------------------------------------------

/**
 * Draws a matrix (the object returned by encodeQrMatrix) onto a 2D canvas.
 *
 * @param {{size:number,modules:boolean[][]}} matrix
 * @param {HTMLCanvasElement} canvas
 * @param {object} [options]
 */
export function renderQrToCanvas(matrix, canvas, { moduleSize = 6, margin = 4, dark = "#000000", light = "#ffffff" } = {}) {
  const { size, modules } = matrix;
  const pixels = (size + 2 * margin) * moduleSize;
  canvas.width = pixels;
  canvas.height = pixels;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = light;
  ctx.fillRect(0, 0, pixels, pixels);
  ctx.fillStyle = dark;
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (modules[y][x]) {
        ctx.fillRect((x + margin) * moduleSize, (y + margin) * moduleSize, moduleSize, moduleSize);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Multi-part (animated) QR framing.
// ---------------------------------------------------------------------------

export const MULTIPART_PREFIX = "MQR1";

// Default chunk size. Rationale: a frame string is
//   MQR1|<payloadId>|<index>|<total>|<totalLen>|<hashPrefixHex>|<chunkBase64url>
// whose fixed overhead is ~50 ASCII chars (5 for "MQR1|", ~11 for the default
// 8-byte base64url payloadId, the three small decimal fields, and 16 hex chars
// for the hash prefix). base64url inflates the chunk by 4/3, so a 384-byte
// chunk produces ~512 base64url chars, giving a ~560-char ASCII frame. Encoded
// in BYTE mode at EC level M that lands around QR version 18 (size 89x89) --
// comfortably below the ~version 22 ceiling the contract sets for reliable
// phone-to-phone scanning, while keeping a ~2.4 KB backup down to ~7 frames.
// (test/qr-encode.test.mjs asserts a worst-case backup frame stays <= v22-M.)
export const DEFAULT_MAX_CHUNK_BYTES = 384;
// Bounds so a malformed/hostile frame cannot wedge the reassembler in permanent
// "progress" (huge `total`, never completes) or balloon memory (huge `totalLen`).
// The real backup is ~2.4 KB / ~7 frames, so these ceilings are generous.
export const MAX_MULTIPART_FRAMES = 64;
export const MAX_MULTIPART_TOTAL_LEN = 65536;

function randomPayloadId(cryptoProvider) {
  const seed = new Uint8Array(8);
  cryptoProvider.getRandomValues(seed);
  return bytesToBase64url(seed);
}

async function sha256Prefix8Hex(bytes, cryptoProvider) {
  // Copy into a fresh ArrayBuffer so subarray views hash correctly everywhere.
  const digest = await cryptoProvider.subtle.digest("SHA-256", bytes.slice());
  return bytesToHex(new Uint8Array(digest).subarray(0, 8));
}

/**
 * Splits `bytes` into <= maxChunkBytes chunks and returns one frame string per
 * chunk, each independently scannable as its own QR frame.
 *
 * @returns {Promise<string[]>}
 */
export async function frameMultipartPayload(bytes, { maxChunkBytes = DEFAULT_MAX_CHUNK_BYTES, payloadId, cryptoProvider = globalThis.crypto } = {}) {
  assertUint8Array(bytes, "bytes");
  if (!Number.isInteger(maxChunkBytes) || maxChunkBytes < 1) {
    throw new Error("maxChunkBytes must be a positive integer");
  }
  const id = payloadId ?? randomPayloadId(cryptoProvider);
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]+$/u.test(id)) {
    throw new Error("payloadId must be a non-empty base64url string");
  }
  const hashPrefixHex = await sha256Prefix8Hex(bytes, cryptoProvider);
  const total = Math.max(1, Math.ceil(bytes.length / maxChunkBytes));
  const frames = [];
  for (let index = 0; index < total; index += 1) {
    const chunk = bytes.subarray(index * maxChunkBytes, (index + 1) * maxChunkBytes);
    const chunkB64 = bytesToBase64url(chunk);
    frames.push(`${MULTIPART_PREFIX}|${id}|${index}|${total}|${bytes.length}|${hashPrefixHex}|${chunkB64}`);
  }
  return frames;
}

/**
 * Parses a single multi-part frame string.
 *
 * @param {string} text
 * @returns {{payloadId:string,index:number,total:number,totalLen:number,hashPrefixHex:string,chunkBytes:Uint8Array}|null}
 */
export function parseMultipartFrame(text) {
  if (typeof text !== "string" || !text.startsWith(`${MULTIPART_PREFIX}|`)) {
    return null;
  }
  const parts = text.split("|");
  if (parts.length !== 7 || parts[0] !== MULTIPART_PREFIX) {
    return null;
  }
  const [, payloadId, indexStr, totalStr, totalLenStr, hashPrefixHex, chunkB64] = parts;
  if (!/^[A-Za-z0-9_-]+$/u.test(payloadId)) {
    return null;
  }
  if (!/^\d+$/u.test(indexStr) || !/^\d+$/u.test(totalStr) || !/^\d+$/u.test(totalLenStr)) {
    return null;
  }
  if (!/^[0-9a-f]{16}$/u.test(hashPrefixHex)) {
    return null;
  }
  const index = Number(indexStr);
  const total = Number(totalStr);
  const totalLen = Number(totalLenStr);
  if (total < 1 || total > MAX_MULTIPART_FRAMES || index >= total) {
    return null;
  }
  if (totalLen < 1 || totalLen > MAX_MULTIPART_TOTAL_LEN) {
    return null;
  }
  let chunkBytes;
  try {
    chunkBytes = base64urlToBytes(chunkB64);
  } catch {
    return null;
  }
  return { payloadId, index, total, totalLen, hashPrefixHex, chunkBytes };
}

/**
 * Creates a stateful reassembler that collects frames and rebuilds the payload.
 *
 * @returns {{accept: (text:string)=>Promise<{status:string,received:number,total:number,bytes?:Uint8Array,error?:string}>, reset: ()=>void, progress: {received:number,total:number}}}
 */
export function createMultipartReassembler({ cryptoProvider = globalThis.crypto } = {}) {
  let meta = null; // { payloadId, total, totalLen, hashPrefixHex }
  const chunks = new Map(); // index -> Uint8Array

  function currentTotal() {
    return meta ? meta.total : 0;
  }

  function fail(error) {
    return { status: "error", received: chunks.size, total: currentTotal(), error };
  }

  return {
    async accept(text) {
      if (typeof text !== "string" || !text.startsWith(`${MULTIPART_PREFIX}|`)) {
        return { status: "ignored", received: chunks.size, total: currentTotal() };
      }
      const frame = parseMultipartFrame(text);
      if (!frame) {
        return fail("malformed MQR1 frame");
      }

      if (meta === null) {
        meta = {
          payloadId: frame.payloadId,
          total: frame.total,
          totalLen: frame.totalLen,
          hashPrefixHex: frame.hashPrefixHex
        };
      } else if (
        frame.payloadId !== meta.payloadId ||
        frame.total !== meta.total ||
        frame.totalLen !== meta.totalLen ||
        frame.hashPrefixHex !== meta.hashPrefixHex
      ) {
        return fail("inconsistent frame metadata");
      }

      if (!chunks.has(frame.index)) {
        chunks.set(frame.index, frame.chunkBytes);
      }

      if (chunks.size < meta.total) {
        return { status: "progress", received: chunks.size, total: meta.total };
      }

      // All distinct chunks present: concatenate in index order and verify.
      const ordered = [];
      for (let i = 0; i < meta.total; i += 1) {
        const part = chunks.get(i);
        if (!part) {
          return { status: "progress", received: chunks.size, total: meta.total };
        }
        ordered.push(part);
      }
      const assembled = concatBytes(...ordered);
      if (assembled.length !== meta.totalLen) {
        return fail("reassembled length mismatch");
      }
      const digestHex = await sha256Prefix8Hex(assembled, cryptoProvider);
      if (digestHex !== meta.hashPrefixHex) {
        return fail("reassembled hash mismatch");
      }
      return { status: "complete", received: chunks.size, total: meta.total, bytes: assembled };
    },

    reset() {
      meta = null;
      chunks.clear();
    },

    get progress() {
      return { received: chunks.size, total: currentTotal() };
    }
  };
}
