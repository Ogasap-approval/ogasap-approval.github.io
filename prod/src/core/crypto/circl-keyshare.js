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
  // Range-check the metadata so a direct consumer of the wire decoder cannot be
  // handed a nonsensical (players, threshold, index) triple. Unlike a SignShare,
  // a CIRCL KeyShare legitimately carries more material (the RSA public key
  // modulus and exponent) after si, so trailing bytes are NOT rejected here —
  // they are returned as `trailingBytes` for the caller to consume or check.
  // Contract: callers that expect a bare keyshare must assert
  // `trailingBytes.length === 0` themselves (api-client.js enforces exactly this
  // for sign shares); the circl-wire tests pin both the returned trailing-bytes
  // shape and these metadata range checks.
  if (players < 1) {
    throw new RangeError("KeyShare players must be at least 1");
  }
  if (threshold < 1 || threshold > players) {
    throw new RangeError("KeyShare threshold must be in range 1..players");
  }
  if (index < 1 || index > players) {
    throw new RangeError("KeyShare index must be in range 1..players");
  }

  return {
    players,
    threshold,
    index,
    si: bytesToBigInt(bytes.subarray(8, 8 + siLength)),
    trailingBytes: bytes.subarray(8 + siLength)
  };
}
