import { signPaymentInputsForBundle } from "./signing-session.js";

self.addEventListener("message", async (event) => {
  const { phoneSharePackage, paymentInputs } = event.data;
  try {
    const signatures = await signPaymentInputsForBundle({
      phoneSharePackage,
      paymentInputs,
      onProgress(progress) {
        self.postMessage({ type: "progress", ...progress });
      }
    });

    self.postMessage({ type: "done", signatures });
  } catch (error) {
    self.postMessage({
      type: "error",
      message: error instanceof Error ? error.message : String(error)
    });
  }
});
