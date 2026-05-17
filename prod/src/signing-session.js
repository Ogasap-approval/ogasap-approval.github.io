import { signBankPaymentInputV1 } from "./core/protocol/signing.js";

export async function signPaymentInputsForBundle({
  phoneSharePackage,
  paymentInputs,
  cryptoProvider = globalThis.crypto,
  onProgress = () => {}
}) {
  if (!phoneSharePackage) {
    throw new Error("phone share package is required");
  }
  if (!Array.isArray(paymentInputs) || paymentInputs.length < 1 || paymentInputs.length > 200) {
    throw new RangeError("paymentInputs must contain 1..200 payments");
  }

  const signatures = [];
  for (let index = 0; index < paymentInputs.length; index += 1) {
    const input = paymentInputs[index];
    onProgress({
      stage: "payments",
      current: index + 1,
      completed: index,
      total: paymentInputs.length
    });
    const startedAt = globalThis.performance?.now?.() ?? Date.now();
    const signed = await signBankPaymentInputV1(input, phoneSharePackage, {
      cryptoProvider
    });
    const finishedAt = globalThis.performance?.now?.() ?? Date.now();
    const durationMS = Math.round(finishedAt - startedAt);
    signatures.push({
      request_id: input.request_id,
      sign_share_base64url: signed.sign_share_base64url,
      duration_ms: durationMS
    });
    onProgress({
      stage: "payments",
      current: index + 1,
      completed: index + 1,
      total: paymentInputs.length
    });
  }

  return signatures;
}
