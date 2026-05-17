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
  cryptoProvider = globalThis.crypto,
  onProgress = () => {}
}) {
  const pollingPackageInput = buildPollingCapabilityInputsV1({
    bundle,
    createdAt: approvedAt
  });
  const paymentCount = bundle.payment_inputs.length;
  const pollingCount = pollingPackageInput.requests.length;
  const totalCount = paymentCount + pollingCount;
  const emitProgress = ({ stage, current, completed, total }) => {
    const overallCompleted = stage === "polling" ? paymentCount + completed : completed;
    onProgress({
      stage,
      current,
      phase_completed: completed,
      phase_total: total,
      completed: overallCompleted,
      total: totalCount,
      percent: totalCount ? Math.round((overallCompleted / totalCount) * 100) : 0
    });
  };

  const paymentSignatures = await signPaymentInputsForBundle({
    phoneSharePackage,
    paymentInputs: bundle.payment_inputs,
    cryptoProvider,
    onProgress: emitProgress
  });
  const pollingSignatures = [];
  for (const input of pollingPackageInput.requests) {
    const index = pollingSignatures.length;
    emitProgress({
      stage: "polling",
      current: index + 1,
      completed: index,
      total: pollingCount
    });
    const signed = await signBankReadInputV1(input, phoneSharePackage, {
      cryptoProvider
    });
    pollingSignatures.push({
      request_id: input.request_id,
      sign_share_base64url: signed.sign_share_base64url
    });
    emitProgress({
      stage: "polling",
      current: index + 1,
      completed: index + 1,
      total: pollingCount
    });
  }
  onProgress({
    stage: "submitting",
    current: totalCount,
    phase_completed: totalCount,
    phase_total: totalCount,
    completed: totalCount,
    total: totalCount,
    percent: 100
  });

  return {
    paymentSignatures,
    pollingCapabilityPackage: attachPollingCapabilitySignatures(pollingPackageInput, pollingSignatures)
  };
}
