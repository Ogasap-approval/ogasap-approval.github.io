import { bytesToBase64url, utf8Encode } from "../../prod/src/core/crypto/bytes.js";
import { sha256Hex } from "../../prod/src/core/protocol/canonical.js";
import { bundleCommitmentsForInputsV1 } from "../../prod/src/core/protocol/envelopes.js";

function demoPaymentBody(index) {
  const amountMinor = 125000 + index * 1375;
  return {
    template_id: "DK_INSTANT_CREDIT_TRANSFER",
    debtor: {
      account_masked: "2030 **** **1234"
    },
    creditor: {
      name: `Demo Supplier ${String(index).padStart(3, "0")}`,
      account: `2030${String(1000000000 + index).slice(1)}`
    },
    amount: {
      minor: String(amountMinor),
      currency: "DKK"
    },
    remittance_text: `Invoice ${2026000 + index}`
  };
}

function randomToken() {
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  return bytesToBase64url(bytes);
}

async function createDemoBankSigningInput(index) {
  const body = demoPaymentBody(index);
  const bodyBytes = utf8Encode(JSON.stringify(body));
  const bodySha256 = await sha256Hex(bodyBytes);

  return {
    version: "bank_signing_input_v1",
    request_id: `demo-payment-${String(index).padStart(3, "0")}`,
    method: "POST",
    path: "/corporate/premium/v2/payments",
    signed_headers: [
      { name: "(request-target)", value: "" },
      { name: "x-bank-originating-host", value: "api.bankopenbanking.com" },
      { name: "x-bank-originating-date", value: "Fri, 15 May 2026 10:00:00 GMT" },
      { name: "digest", value: `SHA-256=${bodySha256}` }
    ],
    body_base64url: bytesToBase64url(bodyBytes),
    body_sha256: bodySha256,
    visible_payment: {
      creditor_name: body.creditor.name,
      creditor_account: body.creditor.account,
      debtor_account_masked: body.debtor.account_masked,
      amount_minor: body.amount.minor,
      currency: body.amount.currency,
      remittance_text: body.remittance_text
    }
  };
}

export async function createFreshDemoBundle(count = 3) {
  const boundedCount = Math.max(1, Math.min(200, Number.parseInt(count, 10) || 1));
  const paymentInputs = [];
  for (let index = 1; index <= boundedCount; index += 1) {
    paymentInputs.push(await createDemoBankSigningInput(index));
  }

  const bundleId = `demo-bundle-${boundedCount}-${randomToken()}`;
  const version = "demo_bundle_v1";
  const commitments = await bundleCommitmentsForInputsV1({
    bundleId,
    bundleVersion: version,
    paymentInputs
  });

  return {
    version,
    bundle_id: bundleId,
    payment_inputs: paymentInputs,
    totals: commitments.totals,
    bank_request_hashes: commitments.bank_request_hashes,
    visible_line_item_hashes: commitments.visible_line_item_hashes,
    bundle_hash_sha256: commitments.bundle_hash_sha256,
    created_at: new Date().toISOString()
  };
}
