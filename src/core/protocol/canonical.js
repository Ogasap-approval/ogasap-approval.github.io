import { bytesToHex, utf8Encode } from "../crypto/bytes.js";
import { sha256 } from "../crypto/pkcs1v15.js";

const CANONICAL_VALUE = /^[\x20-\x7e]*$/u;
const CANONICAL_FIELD_TYPES = new Set(["string", "integer"]);

function assertCanonicalValue(name, value) {
  if (typeof value !== "string" || !CANONICAL_VALUE.test(value)) {
    throw new TypeError(`${name} must be printable ASCII without newlines`);
  }
}

// Render a single field value. Every field tuple MUST declare its type. A
// protocol field is either a string (ids, hashes, dates) or a JS safe-integer
// (share_index, status, payment_count); the declared type fixes which, so a
// given field can never accept both `1` and `"1"`. A string-typed field rejects
// non-strings and an integer-typed field rejects non-safe-integers, which also
// rules out booleans, floats, non-finite numbers, objects, null and undefined.
// Emitted bytes for currently valid inputs are unchanged: strings are verbatim,
// integers are decimal.
function renderCanonicalField(name, value, declaredType) {
  if (!CANONICAL_FIELD_TYPES.has(declaredType)) {
    throw new TypeError(`${name} must declare a canonical field type ("string" or "integer")`);
  }
  if (declaredType === "string") {
    if (typeof value !== "string") {
      throw new TypeError(`${name} must be a string`);
    }
    assertCanonicalValue(name, value);
    return value;
  }
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new TypeError(`${name} must be a safe integer`);
  }
  return String(value);
}

export function canonicalText(domain, fields) {
  assertCanonicalValue("domain", domain);
  if (!Array.isArray(fields)) {
    throw new TypeError("fields must be an array");
  }

  const lines = [domain];
  for (const field of fields) {
    // The type element is required: an untyped tuple would let number 1 and
    // string "1" collide, defeating injectivity.
    if (!Array.isArray(field) || field.length !== 3) {
      throw new TypeError("each field must be a [name, value, type] tuple");
    }
    const [name, value, declaredType] = field;
    assertCanonicalValue("field name", name);
    lines.push(`${name}:${renderCanonicalField(name, value, declaredType)}`);
  }
  return utf8Encode(`${lines.join("\n")}\n`);
}

export function stableStringify(value) {
  if (Array.isArray(value)) {
    // Reject sparse arrays: a hole would be rendered as an empty slot by join,
    // colliding with an explicit value and breaking injectivity.
    for (let index = 0; index < value.length; index += 1) {
      if (!(index in value)) {
        throw new TypeError("stableStringify cannot encode sparse arrays");
      }
    }
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    // Only plain objects are encodable. Date, Map, Set, RegExp, TypedArray and
    // class instances all have no own enumerable string keys (or carry hidden
    // state), so they would collapse to "{}" or an ambiguous shape and collide.
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("stableStringify only encodes plain objects");
    }
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  // Reject anything JSON.stringify would render ambiguously or non-injectively:
  // NaN/Infinity/-Infinity all become "null" (colliding with real null), and
  // undefined/function/symbol either vanish or emit the bare token "undefined".
  // BigInt would throw inside JSON.stringify; reject it explicitly for a clear
  // message. The encoder stays total and injective over its accepted domain.
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("stableStringify cannot encode non-finite numbers");
  }
  if (value === undefined || typeof value === "function" || typeof value === "symbol" || typeof value === "bigint") {
    throw new TypeError(`stableStringify cannot encode ${typeof value} values`);
  }
  return JSON.stringify(value);
}

export function canonicalJsonBytes(value) {
  return utf8Encode(stableStringify(value));
}

export async function sha256Hex(bytes, cryptoProvider = globalThis.crypto) {
  return bytesToHex(await sha256(bytes, cryptoProvider));
}
