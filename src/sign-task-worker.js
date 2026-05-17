import { createBankInputSignerV1 } from "./core/protocol/signing.js";

self.addEventListener("message", async (event) => {
  const { taskId, kind, phoneSharePackage, items } = event.data;
  try {
    const signer = createBankInputSignerV1(phoneSharePackage);
    for (const item of items) {
      const startedAt = globalThis.performance?.now?.() ?? Date.now();
      const signed = kind === "payment"
        ? await signer.signPaymentInput(item.input)
        : await signer.signReadInput(item.input);
      const finishedAt = globalThis.performance?.now?.() ?? Date.now();
      self.postMessage({
        type: "result",
        taskId,
        index: item.index,
        signature: {
          request_id: item.input.request_id,
          sign_share_base64url: signed.sign_share_base64url,
          duration_ms: Math.round(finishedAt - startedAt)
        }
      });
    }
    self.postMessage({ type: "done", taskId });
  } catch (error) {
    self.postMessage({
      type: "error",
      taskId,
      message: error instanceof Error ? error.message : String(error)
    });
  }
});
