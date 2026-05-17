import {
  attachPollingCapabilitySignatures,
  buildPollingCapabilityInputsV1
} from "./polling-capabilities.js";
import {
  signBankReadInputsParallel,
  signPaymentInputsForBundleParallel
} from "./signing-worker-pool.js";

const POLLING_PROGRESS_STEP = 10;

export async function signBundleBankInputs({
  phoneSharePackage,
  bundle,
  approvedAt = new Date(),
  onProgress = () => {}
}) {
  const paymentCount = bundle.payment_inputs.length;
  let totalCount = paymentCount;
  const emitProgress = ({ stage, current, completed, total, worker_count }) => {
    const overallCompleted = stage === "polling" ? paymentCount + completed : completed;
    onProgress({
      stage,
      current,
      phase_completed: completed,
      phase_total: total,
      completed: overallCompleted,
      total: totalCount,
      worker_count,
      phase_percent: total ? Math.round((completed / total) * 100) : 0,
      overall_percent: totalCount ? Math.round((overallCompleted / totalCount) * 100) : 0
    });
  };

  const paymentSignatures = await signPaymentInputsForBundleParallel({
    phoneSharePackage,
    paymentInputs: bundle.payment_inputs,
    onProgress: emitProgress
  });
  const pollingPackageInput = buildPollingCapabilityInputsV1({
    bundle,
    createdAt: approvedAt
  });
  const pollingCount = pollingPackageInput.requests.length;
  totalCount = paymentCount + pollingCount;
  const pollingSignatures = await signBankReadInputsParallel({
    phoneSharePackage,
    inputs: pollingPackageInput.requests,
    progressStep: POLLING_PROGRESS_STEP,
    onProgress: emitProgress
  });
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
