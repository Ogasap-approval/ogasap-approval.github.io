export function assertUint8Array(value, name = "value") {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`${name} must be a Uint8Array`);
  }
}

export function concatBytes(...parts) {
  const arrays = parts.flat();
  let total = 0;
  for (const part of arrays) {
    assertUint8Array(part, "part");
    total += part.length;
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of arrays) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function utf8Encode(value) {
  return new TextEncoder().encode(value);
}

export function utf8Decode(bytes) {
  assertUint8Array(bytes, "bytes");
  return new TextDecoder().decode(bytes);
}

export function bytesToHex(bytes) {
  assertUint8Array(bytes, "bytes");
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[a-fA-F0-9]*$/.test(hex)) {
    throw new TypeError("hex must be an even-length hexadecimal string");
  }

  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64url(bytes) {
  assertUint8Array(bytes, "bytes");
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }

  const base64 = typeof btoa === "function"
    ? btoa(binary)
    : Buffer.from(binary, "binary").toString("base64");

  return base64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function base64urlToBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) {
    throw new TypeError("value must be canonical unpadded base64url");
  }

  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = typeof atob === "function"
    ? atob(padded)
    : Buffer.from(padded, "base64").toString("binary");

  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  if (bytesToBase64url(out) !== value) {
    throw new TypeError("value must be canonical unpadded base64url");
  }
  return out;
}
