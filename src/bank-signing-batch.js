import { signBankReadInputV1 } from "./core/protocol/signing.js";
import { signPaymentInputsForBundle } from "./signing-session.js";
import {
  attachPollingCapabilitySignatures,
  buildPollingCapabilityInputsV1
} from "./polling-capabilities.js";

const POLLING_PROGRESS_STEP = 10;

export async function signBundleBankInputs({
  phoneSharePackage,
  bundle,
  approvedAt = new Date(),
  cryptoProvider = globalThis.crypto,
  onProgress = () => {}
}) {
  const paymentCount = bundle.payment_inputs.length;
  let totalCount = paymentCount;
  const emitProgress = ({ stage, current, completed, total }) => {
    const overallCompleted = stage === "polling" ? paymentCount + completed : completed;
    onProgress({
      stage,
      current,
      phase_completed: completed,
      phase_total: total,
      completed: overallCompleted,
      total: totalCount,
      phase_percent: total ? Math.round((completed / total) * 100) : 0,
      overall_percent: totalCount ? Math.round((overallCompleted / totalCount) * 100) : 0
    });
  };

  const paymentSignatures = await signPaymentInputsForBundle({
    phoneSharePackage,
    paymentInputs: bundle.payment_inputs,
    cryptoProvider,
    onProgress: emitProgress
  });
  const pollingPackageInput = buildPollingCapabilityInputsV1({
    bundle,
    createdAt: approvedAt
  });
  const pollingCount = pollingPackageInput.requests.length;
  totalCount = paymentCount + pollingCount;
  const pollingSignatures = [];
  for (const input of pollingPackageInput.requests) {
    const index = pollingSignatures.length;
    if (index === 0 || index % POLLING_PROGRESS_STEP === 0) {
      emitProgress({
        stage: "polling",
        current: index + 1,
        completed: index,
        total: pollingCount
      });
    }
    const signed = await signBankReadInputV1(input, phoneSharePackage, {
      cryptoProvider
    });
    pollingSignatures.push({
      request_id: input.request_id,
      sign_share_base64url: signed.sign_share_base64url
    });
    if (index + 1 === pollingCount || (index + 1) % POLLING_PROGRESS_STEP === 0) {
      emitProgress({
        stage: "polling",
        current: index + 1,
        completed: index + 1,
        total: pollingCount
      });
    }
  }
  onProgress({
    stage: "submitting",
    current: totalCount,
    phase_completed: totalCount,
    phase_total: totalCount,
    completed: totalCount,
    total: totalCount,
    phase_percent: 100,
    overall_percent: 100
  });

  return {
    paymentSignatures,
    pollingCapabilityPackage: attachPollingCapabilitySignatures(pollingPackageInput, pollingSignatures)
  };
}
