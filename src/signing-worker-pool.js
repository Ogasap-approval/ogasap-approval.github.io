import { createBankInputSignerV1 } from "./core/protocol/signing.js";

const MAX_SIGNING_WORKERS = 8;

function workerCountFor(total) {
  const reported = Number(globalThis.navigator?.hardwareConcurrency);
  const available = Number.isFinite(reported) && reported > 2 ? reported - 1 : 1;
  return Math.max(1, Math.min(MAX_SIGNING_WORKERS, available, total));
}

function partition(inputs, count) {
  const chunks = Array.from({ length: count }, () => []);
  inputs.forEach((input, index) => {
    chunks[index % count].push({ index, input });
  });
  return chunks.filter((chunk) => chunk.length > 0);
}

function shouldReport(completed, total, step) {
  return completed === 0 || completed === total || completed % step === 0;
}

function progressPayload(stage, completed, total, workerCount) {
  return {
    stage,
    current: Math.min(completed + 1, total),
    completed,
    total,
    worker_count: workerCount
  };
}

async function signSequential({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress }) {
  const signer = createBankInputSignerV1(phoneSharePackage);
  const signatures = [];
  onProgress(progressPayload(stage, 0, inputs.length, 1));
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    const startedAt = globalThis.performance?.now?.() ?? Date.now();
    const signed = kind === "payment"
      ? await signer.signPaymentInput(input)
      : await signer.signReadInput(input);
    const finishedAt = globalThis.performance?.now?.() ?? Date.now();
    signatures.push({
      request_id: input.request_id,
      sign_share_base64url: signed.sign_share_base64url,
      duration_ms: Math.round(finishedAt - startedAt)
    });
    if (shouldReport(index + 1, inputs.length, progressStep)) {
      onProgress(progressPayload(stage, index + 1, inputs.length, 1));
    }
  }
  return signatures;
}

function startWorker({ taskId, kind, phoneSharePackage, items, onResult }) {
  const worker = new Worker(new URL("./sign-task-worker.js", import.meta.url), { type: "module" });
  return {
    worker,
    promise: new Promise((resolve, reject) => {
      worker.addEventListener("message", (event) => {
        const message = event.data;
        if (message.taskId !== taskId) {
          return;
        }
        if (message.type === "result") {
          onResult(message.index, message.signature);
        } else if (message.type === "done") {
          resolve();
        } else if (message.type === "error") {
          reject(new Error(message.message));
        }
      });
      worker.addEventListener("error", (event) => reject(new Error(event.message)));
      worker.postMessage({ taskId, kind, phoneSharePackage, items });
    })
  };
}

async function signWithPool({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress }) {
  if (!Array.isArray(inputs) || inputs.length === 0) {
    return [];
  }
  if (typeof Worker !== "function" || workerCountFor(inputs.length) === 1) {
    return signSequential({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress });
  }

  const workerCount = workerCountFor(inputs.length);
  const results = new Array(inputs.length);
  const workers = [];
  let completed = 0;
  const onResult = (index, signature) => {
    results[index] = signature;
    completed += 1;
    if (shouldReport(completed, inputs.length, progressStep)) {
      onProgress(progressPayload(stage, completed, inputs.length, workerCount));
    }
  };

  try {
    onProgress(progressPayload(stage, 0, inputs.length, workerCount));
    for (const [index, items] of partition(inputs, workerCount).entries()) {
      try {
        workers.push(startWorker({
          taskId: `${stage}:${index}:${Date.now()}`,
          kind,
          phoneSharePackage,
          items,
          onResult
        }));
      } catch (error) {
        if (workers.length === 0) {
          return signSequential({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress });
        }
        throw error;
      }
    }
    await Promise.all(workers.map(({ promise }) => promise));
    for (let index = 0; index < results.length; index += 1) {
      if (results[index] === undefined) {
        throw new Error("signing worker returned incomplete results");
      }
    }
    return results;
  } finally {
    for (const { worker } of workers) {
      worker.terminate();
    }
  }
}

export function signPaymentInputsForBundleParallel({ phoneSharePackage, paymentInputs, onProgress = () => {} }) {
  if (!phoneSharePackage) {
    throw new Error("phone share package is required");
  }
  if (!Array.isArray(paymentInputs) || paymentInputs.length < 1 || paymentInputs.length > 200) {
    throw new RangeError("paymentInputs must contain 1..200 payments");
  }
  return signWithPool({
    kind: "payment",
    phoneSharePackage,
    inputs: paymentInputs,
    stage: "payments",
    progressStep: 1,
    onProgress
  });
}

export function signBankReadInputsParallel({ phoneSharePackage, inputs, progressStep = 10, onProgress = () => {} }) {
  return signWithPool({
    kind: "read",
    phoneSharePackage,
    inputs,
    stage: "polling",
    progressStep,
    onProgress
  });
}
