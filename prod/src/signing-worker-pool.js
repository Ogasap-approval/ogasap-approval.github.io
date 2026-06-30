import { createBankInputSignerV1 } from "./core/protocol/signing.js";

const MAX_SIGNING_WORKERS = 8;
// Secret-share material lives inside each worker's heap. To keep that exposure
// window minimal (see the threat model on SigningWorkerPool) the warm pool is
// torn down as soon as the current signing operation's batches all settle and
// control returns to the event loop. A 0ms macrotask still bridges the two
// back-to-back batches of a single approval (payments then polling), because
// the next batch starts within the microtask continuation and cancels this
// timer before it fires.
const DEFAULT_POOL_IDLE_TEARDOWN_MS = 0;

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

function nowMs() {
  return globalThis.performance?.now?.() ?? Date.now();
}

function progressPayload(stage, completed, total, workerCount, startedAt) {
  const elapsedMs = Math.max(0, Math.round(nowMs() - startedAt));
  const remaining = Math.max(0, total - completed);
  const etaSeconds = completed > 0
    ? Math.ceil((elapsedMs / completed) * remaining / 1000)
    : undefined;
  return {
    stage,
    current: Math.min(completed + 1, total),
    completed,
    total,
    worker_count: workerCount,
    elapsed_ms: elapsedMs,
    eta_seconds: etaSeconds
  };
}

// Raised when no worker could be created (e.g. the platform blocks Workers).
// signWithPool treats it as "fall back to sequential", matching the original
// behaviour. A worker that errors *after* construction is a signing failure and
// is rethrown, not silently downgraded.
class WorkerPoolUnavailableError extends Error {}

// --- Test seam -------------------------------------------------------------
// Production keeps the defaults below untouched: a real DOM Worker factory and
// a macrotask yield. Tests inject a worker shim / observable yield / forced
// worker count / idle delay through `__configureSigningWorkerPoolForTests`
// without changing any production behaviour.

function defaultWorkerFactory() {
  return new Worker(new URL("./sign-task-worker.js", import.meta.url), { type: "module" });
}

function defaultYield() {
  return new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

let workerFactory = null;
let yieldToEventLoop = defaultYield;
let forcedWorkerCount = null;
let idleTeardownMs = DEFAULT_POOL_IDLE_TEARDOWN_MS;
let taskSequence = 0;

function workersAvailable() {
  return workerFactory !== null || typeof Worker === "function";
}

function createWorker() {
  return workerFactory ? workerFactory() : defaultWorkerFactory();
}

function desiredWorkerCount(total) {
  if (forcedWorkerCount !== null) {
    return Math.max(1, Math.min(forcedWorkerCount, total));
  }
  return workerCountFor(total);
}

async function signSequential({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress }) {
  const signer = createBankInputSignerV1(phoneSharePackage);
  const signatures = [];
  const batchStartedAt = nowMs();
  onProgress(progressPayload(stage, 0, inputs.length, 1, batchStartedAt));
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    const startedAt = nowMs();
    const signed = kind === "payment"
      ? await signer.signPaymentInput(input)
      : await signer.signReadInput(input);
    const finishedAt = nowMs();
    signatures.push({
      request_id: input.request_id,
      sign_share_base64url: signed.sign_share_base64url,
      duration_ms: Math.round(finishedAt - startedAt)
    });
    if (shouldReport(index + 1, inputs.length, progressStep)) {
      onProgress(progressPayload(stage, index + 1, inputs.length, 1, batchStartedAt));
    }
    // Yield to the event loop between tasks so the single-core fallback does
    // not freeze the UI thread for the whole batch.
    if (index + 1 < inputs.length) {
      await yieldToEventLoop();
    }
  }
  return signatures;
}

// A pool of long-lived workers reused across signing batches.
//
// Lifecycle / threat model: workers are created lazily, reused across the
// back-to-back batches of an in-flight signing operation, and torn down as soon
// as no batch is active and the event loop turns (`idleTeardownMs`, default 0).
// Because each worker holds decoded secret-share material, that material is only
// resident during active signing plus this minimal window. For defence in depth
// callers should also invoke `terminateSigningWorkerPool()` when the share /
// signing session is cleared, so the heap is wiped immediately on approval
// completion rather than waiting for the next loop turn.
class SigningWorkerPool {
  constructor() {
    this.entries = [];
    this.idleTimer = null;
    this.activeBatches = 0;
    this.workersCreated = 0;
    this.batches = 0;
  }

  cancelIdleTeardown() {
    if (this.idleTimer !== null) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }

  scheduleIdleTeardown() {
    this.cancelIdleTeardown();
    if (this.entries.length === 0) {
      return;
    }
    const timer = setTimeout(() => {
      this.idleTimer = null;
      this.terminate();
    }, idleTeardownMs);
    if (typeof timer?.unref === "function") {
      timer.unref();
    }
    this.idleTimer = timer;
  }

  routeMessage(entry, message) {
    const handler = entry.handlers.get(message.taskId);
    if (!handler) {
      return;
    }
    if (message.type === "result") {
      handler.onResult(message.index, message.signature);
    } else if (message.type === "done") {
      entry.handlers.delete(message.taskId);
      handler.resolve();
    } else if (message.type === "error") {
      entry.handlers.delete(message.taskId);
      handler.reject(new Error(message.message));
    }
  }

  // A worker `error` event means the worker is dead: remove it from the pool so
  // later batches never post to it (which would hang forever) and reject any
  // chunk currently assigned to it.
  handleWorkerError(entry, error) {
    const index = this.entries.indexOf(entry);
    if (index !== -1) {
      this.entries.splice(index, 1);
    }
    const pending = [...entry.handlers.values()];
    entry.handlers.clear();
    try {
      entry.worker.terminate();
    } catch {
      // worker already torn down
    }
    for (const handler of pending) {
      handler.reject(error);
    }
  }

  ensure(count) {
    const created = [];
    try {
      while (this.entries.length < count) {
        const worker = createWorker();
        const entry = { worker, handlers: new Map() };
        worker.addEventListener("message", (event) => this.routeMessage(entry, event.data));
        worker.addEventListener("error", (event) => {
          this.handleWorkerError(entry, new Error(event?.message ?? "signing worker error"));
        });
        this.entries.push(entry);
        created.push(entry);
        this.workersCreated += 1;
      }
    } catch (error) {
      // Roll back the workers created in this call so a partial failure never
      // leaves orphaned (untracked-for-teardown) workers running.
      for (const entry of created) {
        const index = this.entries.indexOf(entry);
        if (index !== -1) {
          this.entries.splice(index, 1);
        }
        try {
          entry.worker.terminate();
        } catch {
          // ignore
        }
      }
      throw error;
    }
  }

  runChunk(entry, payload, onResult) {
    return new Promise((resolve, reject) => {
      entry.handlers.set(payload.taskId, { onResult, resolve, reject });
      try {
        entry.worker.postMessage(payload);
      } catch (error) {
        // postMessage threw synchronously: drop the handler we just registered
        // so it cannot leak, and fail this chunk.
        entry.handlers.delete(payload.taskId);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  async signBatch({ kind, phoneSharePackage, inputs, stage, onResult }) {
    this.cancelIdleTeardown();
    this.activeBatches += 1;
    this.batches += 1;
    let cancelled = false;
    const guardedOnResult = (index, signature) => {
      if (!cancelled) {
        onResult(index, signature);
      }
    };
    try {
      const target = desiredWorkerCount(inputs.length);
      try {
        this.ensure(target);
      } catch (creationError) {
        if (this.entries.length === 0) {
          throw new WorkerPoolUnavailableError(creationError?.message ?? "signing worker pool unavailable");
        }
        // Some warm workers survived: continue with what we have.
      }
      const workerCount = Math.min(target, this.entries.length);
      const promises = partition(inputs, workerCount).map((items, index) => this.runChunk(
        this.entries[index],
        {
          taskId: `${stage}:${index}:${(taskSequence += 1)}`,
          kind,
          phoneSharePackage,
          items
        },
        guardedOnResult
      ));
      try {
        await Promise.all(promises);
      } catch (chunkError) {
        // Cancel further result/progress side effects, drain the remaining
        // in-flight chunks (so none survive into the next batch), then tear the
        // pool down so no poisoned worker state is reused.
        cancelled = true;
        await Promise.allSettled(promises);
        this.terminate();
        throw chunkError;
      }
    } finally {
      this.activeBatches -= 1;
      // Only arm idle teardown once no batch is active, so an early-finishing
      // batch can never terminate workers out from under a concurrent batch.
      if (this.activeBatches === 0) {
        this.scheduleIdleTeardown();
      }
    }
  }

  terminate() {
    this.cancelIdleTeardown();
    const entries = this.entries;
    this.entries = [];
    for (const entry of entries) {
      const pending = [...entry.handlers.values()];
      entry.handlers.clear();
      try {
        entry.worker.terminate();
      } catch {
        // ignore
      }
      for (const handler of pending) {
        handler.reject(new Error("signing worker pool terminated"));
      }
    }
  }
}

let pool = new SigningWorkerPool();

export function terminateSigningWorkerPool() {
  pool.terminate();
}

async function signWithPool({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress }) {
  if (!Array.isArray(inputs) || inputs.length === 0) {
    return [];
  }
  if (!workersAvailable() || desiredWorkerCount(inputs.length) === 1) {
    return signSequential({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress });
  }

  const workerCount = desiredWorkerCount(inputs.length);
  const results = new Array(inputs.length);
  const batchStartedAt = nowMs();
  let completed = 0;
  const onResult = (index, signature) => {
    results[index] = signature;
    completed += 1;
    if (shouldReport(completed, inputs.length, progressStep)) {
      onProgress(progressPayload(stage, completed, inputs.length, workerCount, batchStartedAt));
    }
  };

  onProgress(progressPayload(stage, 0, inputs.length, workerCount, batchStartedAt));
  try {
    await pool.signBatch({ kind, phoneSharePackage, inputs, stage, onResult });
  } catch (error) {
    if (error instanceof WorkerPoolUnavailableError) {
      return signSequential({ kind, phoneSharePackage, inputs, stage, progressStep, onProgress });
    }
    throw error;
  }
  for (let index = 0; index < results.length; index += 1) {
    if (results[index] === undefined) {
      throw new Error("signing worker returned incomplete results");
    }
  }
  return results;
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

// Test-only configuration seam. Production code never calls this; the defaults
// above (real Worker factory, macrotask yield, hardware-derived worker count,
// eager idle teardown) are used unless a test overrides them. Returns restore().
export function __configureSigningWorkerPoolForTests(overrides = {}) {
  const previous = { workerFactory, yieldToEventLoop, forcedWorkerCount, idleTeardownMs };
  pool.terminate();
  pool = new SigningWorkerPool();
  if ("createWorker" in overrides) {
    workerFactory = overrides.createWorker ?? null;
  }
  if ("yieldToEventLoop" in overrides) {
    yieldToEventLoop = overrides.yieldToEventLoop ?? defaultYield;
  }
  if ("workerCount" in overrides) {
    forcedWorkerCount = overrides.workerCount ?? null;
  }
  if ("idleTeardownMs" in overrides) {
    idleTeardownMs = overrides.idleTeardownMs ?? DEFAULT_POOL_IDLE_TEARDOWN_MS;
  }
  return function restore() {
    pool.terminate();
    pool = new SigningWorkerPool();
    workerFactory = previous.workerFactory;
    yieldToEventLoop = previous.yieldToEventLoop;
    forcedWorkerCount = previous.forcedWorkerCount;
    idleTeardownMs = previous.idleTeardownMs;
  };
}

export function __getSigningWorkerPoolStats() {
  return {
    workerCount: pool.entries.length,
    workersCreated: pool.workersCreated,
    batches: pool.batches,
    activeBatches: pool.activeBatches,
    idleScheduled: pool.idleTimer !== null
  };
}
