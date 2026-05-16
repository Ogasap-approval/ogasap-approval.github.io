import { bytesToBase64url, utf8Encode } from "../../prod/src/core/crypto/bytes.js";
import { sha256Hex } from "../../prod/src/core/protocol/canonical.js";
import { bundleCommitmentsForInputsV1 } from "../../prod/src/core/protocol/envelopes.js";

function demoPaymentBody(index) {
  const amountMinor = 12500 + index * 137;
  return {
    template_id: "SEPA_INSTANT_CREDIT_TRANSFER_FI",
    amount: amountMinorToDecimal(amountMinor),
    currency: "EUR",
    end_to_end_id: `demo-${String(index).padStart(3, "0")}`,
    external_id: `demo-local-${String(index).padStart(3, "0")}-${randomToken()}`.slice(0, 64),
    debtor: {
      account: {
        currency: "EUR",
        type: "IBAN",
        value: "FI4616603001014326"
      },
      own_reference: `Demo payout ${String(index).padStart(3, "0")}`
    },
    creditor: {
      name: `Demo Supplier ${String(index).padStart(3, "0")}`,
      account: {
        type: "IBAN",
        value: "FI1350001520000081"
      },
      reference: {
        value: "RF18539007547034",
        type: "RF"
      }
    }
  };
}

function amountMinorToDecimal(amountMinor) {
  const value = BigInt(amountMinor);
  return `${value / 100n}.${(value % 100n).toString().padStart(2, "0")}`;
}

function hexToBase64(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  let binary = "";
  const chunkSize = 0x8000;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
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
  const bodyDigest = hexToBase64(bodySha256);

  return {
    version: "bank_signing_input_v1",
    request_id: `demo-payment-${String(index).padStart(3, "0")}`,
    method: "POST",
    path: "/corporate/premium/v2/payments",
    signed_headers: [
      { name: "(request-target)", value: "" },
      { name: "x-bank-originating-host", value: "api.sandbox-payments.example" },
      { name: "x-bank-originating-date", value: new Date().toUTCString() },
      { name: "content-type", value: "application/json" },
      { name: "digest", value: `SHA-256=${bodyDigest}` }
    ],
    body_base64url: bytesToBase64url(bodyBytes),
    body_sha256: bodySha256,
    visible_payment: {
      creditor_name: body.creditor.name,
      creditor_account: body.creditor.account.value,
      debtor_account_masked: "FI46...4326",
      amount_minor: String(12500 + index * 137),
      currency: body.currency,
      remittance_text: body.creditor.reference.value
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
