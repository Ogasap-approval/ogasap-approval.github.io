import { createFreshDemoBundle } from "./demo-fixtures.js";

export async function fetchDemoBundle(count) {
  return createFreshDemoBundle(count);
}

export async function submitDemoApproval(approval) {
  if (!approval?.bundle_id) {
    throw new Error("approval bundle_id is required");
  }
  return {
    ok: true,
    mode: "local-demo",
    bundle_id: approval.bundle_id,
    payment_count: approval.payment_count,
    received_phone_sign_shares: approval.phone_sign_shares?.length ?? 0
  };
}

export async function fetchTestPhoneSharePackage() {
  const response = await fetch("./src/test-materials/test-phone-share-package.json", {
    method: "GET",
    headers: {
      "Accept": "application/json"
    },
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error("test phone share package has not been generated");
  }
  return response.json();
}
