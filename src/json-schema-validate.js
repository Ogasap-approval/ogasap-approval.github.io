// Tiny dependency-free JSON Schema validator (issue #6).
//
// The PWA ingests security-relevant backend JSON responses. This validates them
// against the versioned schemas in response-schemas.js (a byte-faithful copy of
// the canonical schemas/*.json, guarded by test/response-schemas.test.mjs), so
// the client fails CLOSED on any shape it does not recognize instead of trusting
// ad-hoc fields. It intentionally supports only the JSON Schema (draft 2020-12)
// keywords those response schemas actually use — no $ref, no remote schemas, no
// build step — matching the repo's no-build, allow-list style.

const ISO_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/u;

function typeMatches(value, type) {
  switch (type) {
    case "object":
      return value !== null && typeof value === "object" && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    default:
      throw new Error(`unsupported schema type "${type}"`);
  }
}

function fail(path, message) {
  throw new Error(`schema validation failed at ${path || "<root>"}: ${message}`);
}

function checkNode(value, schema, path) {
  if (typeof schema !== "object" || schema === null) {
    fail(path, "schema node must be an object");
  }

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => typeMatches(value, type))) {
      fail(path, `expected type ${types.join("|")}`);
    }
  }

  if (Object.hasOwn(schema, "const") && !deepEqual(value, schema.const)) {
    fail(path, `must equal const ${JSON.stringify(schema.const)}`);
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((candidate) => deepEqual(value, candidate))) {
    fail(path, "is not one of the allowed enum values");
  }

  if (typeof value === "string") {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) {
      fail(path, `is shorter than minLength ${schema.minLength}`);
    }
    if (Number.isInteger(schema.maxLength) && value.length > schema.maxLength) {
      fail(path, `is longer than maxLength ${schema.maxLength}`);
    }
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
      fail(path, `does not match pattern ${schema.pattern}`);
    }
    if (schema.format === "date-time" && !ISO_DATE_TIME.test(value)) {
      fail(path, "is not an RFC 3339 date-time");
    }
  }

  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      fail(path, `is less than minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      fail(path, `is greater than maximum ${schema.maximum}`);
    }
  }

  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems) && value.length < schema.minItems) {
      fail(path, `has fewer than minItems ${schema.minItems}`);
    }
    if (Number.isInteger(schema.maxItems) && value.length > schema.maxItems) {
      fail(path, `has more than maxItems ${schema.maxItems}`);
    }
    if (schema.items) {
      value.forEach((item, index) => checkNode(item, schema.items, `${path}[${index}]`));
    }
  }

  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const properties = schema.properties ?? {};
    for (const required of schema.required ?? []) {
      if (!Object.hasOwn(value, required)) {
        fail(path, `is missing required property "${required}"`);
      }
    }
    for (const key of Object.keys(value)) {
      if (Object.hasOwn(properties, key)) {
        checkNode(value[key], properties[key], path ? `${path}.${key}` : key);
      } else if (schema.additionalProperties === false) {
        fail(path, `has unexpected property "${key}"`);
      } else if (typeof schema.additionalProperties === "object" && schema.additionalProperties !== null) {
        checkNode(value[key], schema.additionalProperties, path ? `${path}.${key}` : key);
      }
    }
  }
}

function deepEqual(a, b) {
  if (a === b) {
    return true;
  }
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") {
    return false;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((item, index) => deepEqual(item, b[index]));
  }
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  return aKeys.length === bKeys.length && aKeys.every((key) => Object.hasOwn(b, key) && deepEqual(a[key], b[key]));
}

// Throws on any mismatch (fail closed). Returns the validated value on success.
export function assertMatchesSchema(value, schema, label = schema?.title ?? "response") {
  try {
    checkNode(value, schema, "");
  } catch (cause) {
    const error = new Error(`${label} does not match its versioned schema: ${cause.message}`);
    error.cause = cause;
    throw error;
  }
  return value;
}
