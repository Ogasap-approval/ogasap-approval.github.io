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
  migration_request_response_v1: schema("migration_request_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "ok", "migration_id", "challenge_nonce", "challenge_nonce_expires_at", "status"],
    properties: {
      version: { const: "migration_request_response_v1" },
      ok: { const: true },
      migration_id: { type: "string", minLength: 20, maxLength: 128, pattern: "^mig-[A-Za-z0-9_-]+$" },
      challenge_nonce: { type: "string", minLength: 16, maxLength: 256, pattern: BASE64URL_PATTERN },
      challenge_nonce_expires_at: { type: "string", format: "date-time" },
      status: { const: "awaiting_step_up" }
    }
  }),
  migration_attest_response_v1: schema("migration_attest_response_v1", {
    type: "object",
    additionalProperties: false,
    required: ["version", "ok", "migration_id", "status"],
    properties: {
      version: { const: "migration_attest_response_v1" },
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
      status: { type: "string", enum: ["not_found", "awaiting_step_up", "awaiting_approval", "approved", "rejected"] }
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
