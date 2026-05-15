import { bytesToHex, utf8Encode } from "../crypto/bytes.js";
import { sha256 } from "../crypto/pkcs1v15.js";

const CANONICAL_VALUE = /^[\x20-\x7e]*$/u;

function assertCanonicalValue(name, value) {
  if (typeof value !== "string" || !CANONICAL_VALUE.test(value)) {
    throw new TypeError(`${name} must be printable ASCII without newlines`);
  }
}

export function canonicalText(domain, fields) {
  assertCanonicalValue("domain", domain);
  if (!Array.isArray(fields)) {
    throw new TypeError("fields must be an array");
  }

  const lines = [domain];
  for (const [name, value] of fields) {
    assertCanonicalValue("field name", name);
    assertCanonicalValue(name, String(value));
    lines.push(`${name}:${value}`);
  }
  return utf8Encode(`${lines.join("\n")}\n`);
}

export function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function canonicalJsonBytes(value) {
  return utf8Encode(stableStringify(value));
}

export async function sha256Hex(bytes, cryptoProvider = globalThis.crypto) {
  return bytesToHex(await sha256(bytes, cryptoProvider));
}
