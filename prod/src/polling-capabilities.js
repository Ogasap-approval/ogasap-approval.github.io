import { base64urlToBytes, utf8Decode } from "./core/crypto/bytes.js";

export const POLLING_CAPABILITY_HORIZON_HOURS = 72;
export const POLLING_CAPABILITY_SLOT_INTERVAL_MINUTES = 60;
export const POLLING_CAPABILITY_SLOT_OFFSET_MINUTES = 30;
export const POLLING_CAPABILITY_SLOT_COUNT = POLLING_CAPABILITY_HORIZON_HOURS;
export const POLLING_CAPABILITY_EXTERNAL_ID_CHUNK_SIZE = 20;
export const DEFAULT_DETERMINISTIC_POLLING_PATHS = [];

function originatingHeadersFromBundle(bundle) {
  const headers = bundle?.payment_inputs?.[0]?.signed_headers ?? [];
  const hostHeader = headers.find((header) => /^x-[a-z0-9-]+-originating-host$/u.test(header.name));
  const dateHeader = headers.find((header) => /^x-[a-z0-9-]+-originating-date$/u.test(header.name));
  if (!hostHeader?.value || !dateHeader?.name) {
    throw new Error("bundle is missing bank originating host");
  }
  return {
    hostName: hostHeader.name,
    hostValue: hostHeader.value,
    dateName: dateHeader.name
  };
}

function externalIdFromPaymentInput(input) {
  const body = JSON.parse(utf8Decode(base64urlToBytes(input.body_base64url)));
  if (typeof body.external_id !== "string" || body.external_id.length < 1 || body.external_id.length > 64) {
    throw new Error(`payment ${input.request_id} is missing external_id`);
  }
  return body.external_id;
}

function chunks(values, size) {
  const output = [];
  for (let index = 0; index < values.length; index += size) {
    output.push(values.slice(index, index + size));
  }
  return output;
}

function slotDate(startMs, slotIndex) {
  const offsetMs = POLLING_CAPABILITY_SLOT_OFFSET_MINUTES * 60_000;
  const intervalMs = POLLING_CAPABILITY_SLOT_INTERVAL_MINUTES * 60_000;
  return new Date(startMs + offsetMs + slotIndex * intervalMs).toUTCString();
}

function signedHeaders(originatingHeaders, originatingDate) {
  return [
    { name: "(request-target)", value: "" },
    { name: originatingHeaders.hostName, value: originatingHeaders.hostValue },
    { name: originatingHeaders.dateName, value: originatingDate }
  ];
}

function encodeExternalIds(externalIds) {
  return externalIds.map((externalId) => encodeURIComponent(externalId)).join(",");
}

function paymentStatusPath(externalIds) {
  return `/corporate/premium/v2/payments?external_ids=${encodeExternalIds(externalIds)}&page=1&size=20`;
}

function requestId(bundleId, scope, slotIndex, index) {
  const prefix = bundleId.length > 80 ? bundleId.slice(0, 80) : bundleId;
  return `${prefix}:${scope}:${slotIndex}:${index}`;
}

function defaultSlots(startMs) {
  return Array.from({ length: POLLING_CAPABILITY_SLOT_COUNT }, (_, slotIndex) => ({
    slot_index: slotIndex,
    originating_date: slotDate(startMs, slotIndex)
  }));
}

function requirementRequests(requirements) {
  if (!requirements || !Array.isArray(requirements.requests)) {
    return null;
  }
  return requirements.requests.map((request) => ({
    scope: request.scope,
    slot_index: request.slot_index,
    deterministic_index: request.deterministic_index,
    chunk_index: request.chunk_index,
    originating_date: request.originating_date
  }));
}

export function buildPollingCapabilityInputsV1({
  bundle,
  createdAt = new Date(),
  deterministicPaths = DEFAULT_DETERMINISTIC_POLLING_PATHS,
  requirements = bundle?.polling_capability_requirements
}) {
  const createdAtDate = createdAt instanceof Date ? createdAt : new Date(createdAt);
  if (Number.isNaN(createdAtDate.getTime())) {
    throw new Error("polling capability createdAt is invalid");
  }
  const startMs = createdAtDate.getTime();
  const originatingHeaders = originatingHeadersFromBundle(bundle);
  const externalIds = bundle.payment_inputs.map(externalIdFromPaymentInput);
  const externalIdChunks = chunks(externalIds, POLLING_CAPABILITY_EXTERNAL_ID_CHUNK_SIZE);
  const inputs = [];
  const requiredRequests = requirementRequests(requirements);

  if (requiredRequests) {
    for (const required of requiredRequests) {
      if (required.scope !== "bundle_payment_status") {
        continue;
      }
      const chunk = externalIdChunks[required.chunk_index];
      if (!chunk) {
        throw new Error("polling capability requirement chunk_index is invalid");
      }
      inputs.push({
        version: "bank_read_signing_input_v1",
        request_id: requestId(bundle.bundle_id, "pay", required.slot_index, required.chunk_index),
        scope: "bundle_payment_status",
        slot_index: required.slot_index,
        chunk_index: required.chunk_index,
        external_ids: chunk,
        method: "GET",
        path: paymentStatusPath(chunk),
        signed_headers: signedHeaders(originatingHeaders, required.originating_date)
      });
    }
  } else {
    for (const slot of defaultSlots(startMs)) {
      const originatingDate = slot.originating_date;
      const slotIndex = slot.slot_index;
      for (let chunkIndex = 0; chunkIndex < externalIdChunks.length; chunkIndex += 1) {
        const chunk = externalIdChunks[chunkIndex];
        inputs.push({
          version: "bank_read_signing_input_v1",
          request_id: requestId(bundle.bundle_id, "pay", slotIndex, chunkIndex),
          scope: "bundle_payment_status",
          slot_index: slotIndex,
          chunk_index: chunkIndex,
          external_ids: chunk,
          method: "GET",
          path: paymentStatusPath(chunk),
          signed_headers: signedHeaders(originatingHeaders, originatingDate)
        });
      }
    }
  }

  if (!requiredRequests) {
    for (const slot of defaultSlots(startMs)) {
      const originatingDate = slot.originating_date;
      const slotIndex = slot.slot_index;
      for (let index = 0; index < deterministicPaths.length; index += 1) {
        const path = deterministicPaths[index];
        inputs.push({
          version: "bank_read_signing_input_v1",
          request_id: requestId(bundle.bundle_id, "det", slotIndex, index),
          scope: "deterministic",
          slot_index: slotIndex,
          deterministic_index: index,
          method: "GET",
          path,
          signed_headers: signedHeaders(originatingHeaders, originatingDate)
        });
      }
    }
  }

  return {
    version: "polling_capability_package_v1",
    bundle_id: bundle.bundle_id,
    created_at: requirements?.created_at ?? createdAtDate.toISOString(),
    valid_until: requirements?.valid_until ?? new Date(startMs + POLLING_CAPABILITY_HORIZON_HOURS * 60 * 60_000).toISOString(),
    horizon_hours: requirements?.horizon_hours ?? POLLING_CAPABILITY_HORIZON_HOURS,
    slot_interval_minutes: requirements?.slot_interval_minutes ?? POLLING_CAPABILITY_SLOT_INTERVAL_MINUTES,
    requests: inputs
  };
}

export function attachPollingCapabilitySignatures(packageInput, signatures) {
  if (!Array.isArray(signatures) || signatures.length !== packageInput.requests.length) {
    throw new Error("polling capability signature count mismatch");
  }
  return {
    ...packageInput,
    requests: packageInput.requests.map((request, index) => ({
      ...request,
      phone_sign_share_base64url: signatures[index].sign_share_base64url
    }))
  };
}
