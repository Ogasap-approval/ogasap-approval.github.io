import { signBundleBankInputs } from "./bank-signing-batch.js";
import { signPaymentInputsForBundle } from "./signing-session.js";

self.addEventListener("message", async (event) => {
  const { phoneSharePackage, bundle, approvedAt, paymentInputs } = event.data;
  const onProgress = (progress) => {
    self.postMessage({ type: "progress", progress });
  };
  try {
    if (bundle) {
      const result = await signBundleBankInputs({
        phoneSharePackage,
        bundle,
        approvedAt,
        onProgress
      });

      self.postMessage({ type: "done", signatures: result.paymentSignatures, ...result });
      return;
    }

    const signatures = await signPaymentInputsForBundle({
      phoneSharePackage,
      paymentInputs,
      onProgress
    });
    self.postMessage({ type: "done", signatures, paymentSignatures: signatures });
  } catch (error) {
    self.postMessage({
      type: "error",
      message: error instanceof Error ? error.message : String(error)
    });
  }
});
