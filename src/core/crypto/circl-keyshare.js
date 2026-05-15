import { bytesToBigInt } from "./bigint.js";

function readUint16(bytes, offset) {
  return (bytes[offset] << 8) | bytes[offset + 1];
}

export function parseCirclKeyShare(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 8) {
    throw new TypeError("KeyShare bytes must be at least 8 bytes");
  }

  const players = readUint16(bytes, 0);
  const threshold = readUint16(bytes, 2);
  const index = readUint16(bytes, 4);
  const siLength = readUint16(bytes, 6);

  if (siLength === 0) {
    throw new RangeError("KeyShare si length must be non-zero");
  }
  if (bytes.length < 8 + siLength) {
    throw new RangeError("KeyShare bytes are truncated");
  }

  return {
    players,
    threshold,
    index,
    si: bytesToBigInt(bytes.subarray(8, 8 + siLength)),
    trailingBytes: bytes.subarray(8 + siLength)
  };
}
