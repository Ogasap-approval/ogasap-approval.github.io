// Versioned JSON Schemas for the backend API responses the PWA consumes (#6).
//
// These objects are the in-app copy of the canonical contract files under
// schemas/*.schema.json. test/response-schemas.test.mjs asserts each object here
// deep-equals its schemas/*.schema.json file (so they cannot drift) AND that the
// demo backend's real responses validate against them (so server.mjs cannot
// drift from the contract). The PWA (api-client.js) validates every consumed
// response against the matching schema and fails CLOSED on a mismatch.

const BACKEND_PATH_PATTERN = "^/api/approval(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$";
const BASE64URL_PATTERN = "^[A-Za-z0-9_-]+$";
const HEX64_PATTERN = "^[a-f0-9]{64}$";
const APPROVER_ID_PATTERN = "^[A-Za-z0-9._:-]{3,128}$";
const DEVICE_ID_PATTERN = "^[A-Za-z0-9._:-]{16,128}$";
const KEY_ID_PATTERN = "^[A-Za-z0-9._:-]{8,128}$";
const THRESHOLD_PATTERN = "^[0-9]+-of-[0-9]+$";
const PRINTABLE_ASCII_PATTERN = "^[\\x20-\\x7e]+$";

function schema(name, body) {
  return {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: `urn:approval:approval:schemas:${name}`,
    title: name,
    ...body
  };
}

// A bundle/approval/submission object the PWA additionally validates and (for
// bundles) cryptographically re-derives elsewhere. The response schema pins the
// security-relevant top-level shape but tolerates extra descriptive fields
// (additionalProperties) so the contract does not have to enumerate every
// nested bank/polling field.
const PENDING_BUNDLE_ITEM = {
  type: "object",
  additionalProperties: true,
  required: [
    "version",
    "bundle_id",
    "bundle_hash_sha256",
    "payment_inputs",
    "totals",
    "bank_request_hashes",
    "visible_line_item_hashes"
  ],
  properties: {
    version: { type: "string", minLength: 3, maxLength: 128 },
    bundle_id: { type: "string", minLength: 8, maxLength: 128, pattern: "^[A-Za-z0-9._:-]+$" },
    bundle_hash_sha256: { type: "string", pattern: HEX64_PATTERN },
    payment_inputs: { type: "array", minItems: 1, maxItems: 200 },
    totals: { type: "array", minItems: 1, maxItems: 10 },
    bank_request_hashes: { type: "array", minItems: 1, maxItems: 200, items: { type: "string", pattern: HEX64_PATTERN } },
    visible_line_item_hashes: { type: "array", minItems: 1, maxItems: 200, items: { type: "string", pattern: HEX64_PATTERN } }
  }
};

const RECENT_APPROVAL_ITEM = {
  type: "object",
  additionalProperties: true,
  required: ["bundle_id", "status", "approver_id", "device_id", "share_index", "key_id"],
  properties: {
    bundle_id: { type: "string", minLength: 8, maxLength: 128, pattern: "^[A-Za-z0-9._:-]+$" },
    status: { type: "string", minLength: 1, maxLength: 64 },
    approver_id: { type: "string", pattern: APPROVER_ID_PATTERN },
    device_id: { type: "string", pattern: DEVICE_ID_PATTERN },
    share_index: { type: "integer", enum: [3, 4] },
    key_id: { type: "string", pattern: KEY_ID_PATTERN }
  }
};

// The Nordea ADMIN draft carried by GET /api/approval/pending-admin-request.
// Like PENDING_BUNDLE_ITEM this pins the security-relevant top-level shape and
// bounds the sizes, and tolerates the rest (additionalProperties): the FULL
// contract for this object is schemas/nordea_admin_input_v1.schema.json, and it
// is enforced -- route by route, header by header, body byte by body byte --
// by validateNordeaAdminSigningInputV1 in core/protocol/envelopes.js before
// the draft is ever displayed or signed. Restating that envelope here would
// create a second, weaker copy of it that could drift from the canonical one.
const PENDING_ADMIN_INPUT = {
  type: ["object", "null"],
  additionalProperties: true,
  required: ["version", "request_id", "method", "path", "signed_headers"],
  properties: {
    version: { const: "nordea_admin_input_v1" },
    request_id: { type: "string", minLength: 8, maxLength: 128, pattern: "^[A-Za-z0-9._:-]+$" },
    method: { type: "string", enum: ["POST", "PUT", "GET"] },
    path: { type: "string", minLength: 1, maxLength: 512 },
    signed_headers: { type: "array", minItems: 3, maxItems: 5 },
    body_base64url: { type: "string", minLength: 2, maxLength: 350000, pattern: BASE64URL_PATTERN },
    body_sha256: { type: "string", pattern: HEX64_PATTERN }
  }
};

export const RESPONSE_SCHEMAS = {
  backend_auth_nonce_response_v1: schema("backend_auth_nonce_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "method", "path", "server_nonce", "expires_at"],
    properties: {
      version: { const: "backend_auth_nonce_response_v1" },
      method: { type: "string", enum: ["GET", "POST"] },
      path: { type: "string", pattern: BACKEND_PATH_PATTERN },
      server_nonce: { type: "string", minLength: 16, maxLength: 256, pattern: BASE64URL_PATTERN },
      expires_at: { type: "string", format: "date-time" }
    }
  }),
  webauthn_challenge_nonce_response_v1: schema("webauthn_challenge_nonce_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "challenge_nonce", "expires_at"],
    properties: {
      version: { const: "webauthn_challenge_nonce_response_v1" },
      challenge_nonce: { type: "string", minLength: 16, maxLength: 256, pattern: BASE64URL_PATTERN },
      expires_at: { type: "string", format: "date-time" }
    }
  }),
  enroll_credential_result_v1: schema("enroll_credential_result_v1", {
    type: "object",
    additionalProperties: false,
    required: ["ok", "version", "credential_id", "approver_id", "device_id"],
    properties: {
      ok: { const: true },
      version: { const: "enroll_credential_result_v1" },
      credential_id: { type: "string", minLength: 16, maxLength: 1024, pattern: BASE64URL_PATTERN },
      approver_id: { type: "string", pattern: APPROVER_ID_PATTERN },
      device_id: { type: "string", pattern: DEVICE_ID_PATTERN }
    }
  }),
  pending_bundles_response_v1: schema("pending_bundles_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "bundles"],
    properties: {
      version: { const: "pending_bundles_response_v1" },
      bundles: { type: "array", maxItems: 1000, items: PENDING_BUNDLE_ITEM }
    }
  }),
  recent_approvals_response_v1: schema("recent_approvals_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "window_hours", "approvals"],
    properties: {
      version: { const: "recent_approvals_response_v1" },
      window_hours: { type: "integer", minimum: 1, maximum: 168 },
      approvals: { type: "array", maxItems: 1000, items: RECENT_APPROVAL_ITEM }
    }
  }),
  bundle_approval_result_v1: schema("bundle_approval_result_v1", {
    type: "object",
    additionalProperties: false,
    required: [
      "ok",
      "version",
      "stored_approvals",
      "bundle_id",
      "threshold_verification",
      "received_at",
      "polling_capabilities",
      "bank_submission"
    ],
    properties: {
      ok: { const: true },
      version: { const: "bundle_approval_result_v1" },
      stored_approvals: { type: "integer", minimum: 0 },
      bundle_id: { type: "string", minLength: 8, maxLength: 128, pattern: "^[A-Za-z0-9._:-]+$" },
      demo: { type: "boolean" },
      threshold_verification: { type: "object", additionalProperties: true },
      received_at: { type: "string", format: "date-time" },
      polling_capabilities: { type: "object", additionalProperties: true },
      bank_submission: { type: "object", additionalProperties: true }
    }
  }),
  pending_admin_request_response_v1: schema("pending_admin_request_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "admin_input"],
    properties: {
      version: { const: "pending_admin_request_response_v1" },
      // WHY nothing is pending, when the service chose not to mint a step. Optional, so a service
      // still emitting the two-field body stays valid. A shape constraint rather than an enum of
      // today's reason vocabulary on purpose: this body is SIGNED, so an unrecognised reason would
      // fail loudly on the phone, and a service that learns a new reason must not break a holder
      // whose PWA is pinned a version behind.
      suppression: { type: ["string", "null"], maxLength: 64, pattern: "^[a-z_]+$" },
      // null is the "nothing pending" value, and it is REQUIRED to be present:
      // an absent key would let a renamed/typo'd backend field read as "nothing
      // to approve" forever instead of failing loudly.
      admin_input: PENDING_ADMIN_INPUT
    }
  }),
  admin_approval_result_v1: schema("admin_approval_result_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "ok", "status", "nordea_runtime", "persisted"],
    properties: {
      version: { const: "admin_approval_result_v1" },
      // A REAL boolean, never the string "false": the admin outcome is rendered
      // straight from this field, and every non-empty string is truthy.
      ok: { type: "boolean" },
      // The bank's HTTP status, or null when the backend refused before calling it.
      status: { type: ["integer", "null"], minimum: 100, maximum: 599 },
      nordea_runtime: { type: "object", additionalProperties: true },
      persisted: { type: "array", maxItems: 32, items: { type: "string", minLength: 1, maxLength: 256, pattern: PRINTABLE_ASCII_PATTERN } },
      error: { type: "string", minLength: 1, maxLength: 256, pattern: PRINTABLE_ASCII_PATTERN }
    }
  }),
  migration_request_response_v1: schema("migration_request_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "ok", "migration_id", "status"],
    properties: {
      version: { const: "migration_request_response_v1" },
      ok: { const: true },
      migration_id: { type: "string", minLength: 20, maxLength: 128, pattern: "^mig-[A-Za-z0-9_-]+$" },
      status: { const: "awaiting_approval" }
    }
  }),
  migration_status_response_v1: schema("migration_status_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "ok", "migration_id", "status"],
    properties: {
      version: { const: "migration_status_response_v1" },
      ok: { const: true },
      migration_id: { type: "string", minLength: 20, maxLength: 128, pattern: "^mig-[A-Za-z0-9_-]+$" },
      status: { type: "string", enum: ["not_found", "awaiting_approval", "approved", "rejected"] }
    }
  }),
  backend_response_envelope_v1: schema("backend_response_envelope_v1", {
    type: "object",
    additionalProperties: false,
    required: [
      "version",
      "method",
      "path",
      "status",
      "body_sha256",
      "approver_id",
      "device_id",
      "share_index",
      "key_id",
      "request_server_nonce",
      "request_client_nonce",
      "response_timestamp",
      "certificate_fingerprint_sha256",
      "threshold",
      "company_share_indexes",
      "company_sign_shares_base64url"
    ],
    properties: {
      version: { const: "backend_response_envelope_v1" },
      method: { type: "string", enum: ["GET", "POST"] },
      path: { type: "string", pattern: BACKEND_PATH_PATTERN },
      status: { type: "integer", minimum: 100, maximum: 599 },
      body_sha256: { type: "string", pattern: HEX64_PATTERN },
      approver_id: { type: "string", pattern: APPROVER_ID_PATTERN },
      device_id: { type: "string", pattern: DEVICE_ID_PATTERN },
      share_index: { type: "integer", enum: [3, 4] },
      key_id: { type: "string", pattern: KEY_ID_PATTERN },
      request_server_nonce: { type: "string", minLength: 1, maxLength: 256 },
      request_client_nonce: { type: "string", minLength: 1, maxLength: 256 },
      response_timestamp: { type: "string", format: "date-time" },
      certificate_fingerprint_sha256: { type: "string", pattern: HEX64_PATTERN },
      threshold: { type: "string", pattern: THRESHOLD_PATTERN },
      company_share_indexes: { type: "array", minItems: 1, maxItems: 8, items: { type: "integer", minimum: 1, maximum: 8 } },
      company_sign_shares_base64url: { type: "array", minItems: 1, maxItems: 8, items: { type: "string", minLength: 8, maxLength: 4096, pattern: BASE64URL_PATTERN } }
    }
  })
};

export function responseSchema(name) {
  const found = RESPONSE_SCHEMAS[name];
  if (!found) {
    throw new Error(`unknown response schema "${name}"`);
  }
  return found;
}
