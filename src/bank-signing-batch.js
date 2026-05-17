import { signBankReadInputV1 } from "./core/protocol/signing.js";
import { signPaymentInputsForBundle } from "./signing-session.js";
import {
  attachPollingCapabilitySignatures,
  buildPollingCapabilityInputsV1
} from "./polling-capabilities.js";

export async function signBundleBankInputs({
  phoneSharePackage,
  bundle,
  approvedAt = new Date(),
  cryptoProvider = globalThis.crypto
}) {
  const paymentSignatures = await signPaymentInputsForBundle({
    phoneSharePackage,
    paymentInputs: bundle.payment_inputs,
    cryptoProvider
  });
  const pollingPackageInput = buildPollingCapabilityInputsV1({
    bundle,
    createdAt: approvedAt
  });
  const pollingSignatures = [];
  for (const input of pollingPackageInput.requests) {
    const signed = await signBankReadInputV1(input, phoneSharePackage, {
      cryptoProvider
    });
    pollingSignatures.push({
      request_id: input.request_id,
      sign_share_base64url: signed.sign_share_base64url
    });
  }

  return {
    paymentSignatures,
    pollingCapabilityPackage: attachPollingCapabilitySignatures(pollingPackageInput, pollingSignatures)
  };
}
