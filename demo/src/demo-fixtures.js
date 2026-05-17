import { bytesToBase64url, utf8Encode } from "../../prod/src/core/crypto/bytes.js";
import { sha256Hex } from "../../prod/src/core/protocol/canonical.js";
import { bundleCommitmentsForInputsV1 } from "../../prod/src/core/protocol/envelopes.js";

function demoPaymentBody(index) {
  const amountMinor = 25000 + index * 701;
  const debtorAccount = DK_SANDBOX_ACCOUNTS[0];
  const creditorAccount = DK_SANDBOX_ACCOUNTS[(index % (DK_SANDBOX_ACCOUNTS.length - 1)) + 1];
  return {
    template_id: "INSTANT_CREDIT_TRANSFER_DK",
    amount: amountMinorToDecimal(amountMinor),
    currency: "DKK",
    end_to_end_id: `dk-${String(index).padStart(3, "0")}`,
    external_id: `demo-local-dk-${String(index).padStart(3, "0")}-${randomToken()}`.slice(0, 64),
    debtor: {
      account: {
        currency: "DKK",
        type: "BBAN",
        value: debtorAccount.bban
      },
      own_reference: `DK payout ${String(index).padStart(3, "0")}`
    },
    creditor: {
      name: `DK Supplier ${String(index).padStart(3, "0")}`,
      account: {
        type: "BBAN",
        value: creditorAccount.bban
      },
      bank: {
        bank_code: creditorAccount.bankCode,
        country: "DK"
      },
      message: `Invoice DK-${String(index).padStart(3, "0")}`
    }
  };
}

const DK_SANDBOX_ACCOUNTS = [
  { bban: "20000216144198", bankCode: "2000", accountNumber: "0216144198" },
  { bban: "20000808505894", bankCode: "2000", accountNumber: "0808505894" },
  { bban: "20001544959502", bankCode: "2000", accountNumber: "1544959502" },
  { bban: "20005005538159", bankCode: "2000", accountNumber: "5005538159" }
];

function domesticAccountLabel(account) {
  return `${account.bankCode} ${account.accountNumber}`;
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
      creditor_account: domesticAccountLabel(DK_SANDBOX_ACCOUNTS[(index % (DK_SANDBOX_ACCOUNTS.length - 1)) + 1]),
      debtor_account_masked: "2000...4198",
      amount_minor: String(25000 + index * 701),
      currency: body.currency,
      remittance_text: body.creditor.message
    }
  };
}

export async function createFreshDemoBundle(count = 3) {
  const boundedCount = Math.max(1, Math.min(200, Number.parseInt(count, 10) || 1));
  const paymentInputs = [];
  for (let index = 1; index <= boundedCount; index += 1) {
    paymentInputs.push(await createDemoBankSigningInput(index));
  }

  const bundleId = `demo-bundle-${boundedCount}-dk-${randomToken()}`;
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
