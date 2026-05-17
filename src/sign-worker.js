import { signBundleBankInputs } from "./bank-signing-batch.js";

self.addEventListener("message", async (event) => {
  const { phoneSharePackage, bundle, approvedAt } = event.data;
  try {
    const result = await signBundleBankInputs({
      phoneSharePackage,
      bundle,
      approvedAt
    });

    self.postMessage({ type: "done", ...result });
  } catch (error) {
    self.postMessage({
      type: "error",
      message: error instanceof Error ? error.message : String(error)
    });
  }
});
