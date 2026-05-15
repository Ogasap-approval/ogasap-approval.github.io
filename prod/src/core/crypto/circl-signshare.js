import { bigIntToBytes, bytesToBigInt } from "./bigint.js";

function readUint16(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

function writeUint16(bytes, offset, value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new RangeError("uint16 value out of range");
  }
  bytes[offset] = value >> 8;
  bytes[offset + 1] = value & 0xff;
}

export function marshalSignShare({ players, threshold, index, xi }) {
  const xiBytes = bigIntToBytes(xi);
  const payloadLength = xiBytes.length === 0 ? 1 : xiBytes.length;
  const out = new Uint8Array(8 + payloadLength);

  writeUint16(out, 0, players);
  writeUint16(out, 2, threshold);
  writeUint16(out, 4, index);
  writeUint16(out, 6, payloadLength);
  out.set(payloadLength === xiBytes.length ? xiBytes : new Uint8Array([0]), 8);
  return out;
}

export function unmarshalSignShare(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 8) {
    throw new TypeError("SignShare bytes must be at least 8 bytes");
  }

  const players = readUint16(bytes, 0);
  const threshold = readUint16(bytes, 2);
  const index = readUint16(bytes, 4);
  const xiLength = readUint16(bytes, 6);

  if (xiLength === 0) {
    throw new RangeError("SignShare xi length must be non-zero");
  }
  if (bytes.length < 8 + xiLength) {
    throw new RangeError("SignShare bytes are truncated");
  }

  return {
    players,
    threshold,
    index,
    xi: bytesToBigInt(bytes.subarray(8, 8 + xiLength)),
    trailingBytes: bytes.subarray(8 + xiLength)
  };
}
