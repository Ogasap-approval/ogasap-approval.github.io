// SRI-pinned integrity bootstrap (issue #10 — verify BEFORE import).
//
// WHY: browsers enforce Subresource Integrity only on the entry <script> file,
// NOT on the ES modules it statically `import`s. So pinning app.js with an
// `integrity=` attribute does not pin integrity.js/storage.js/etc., which would
// EXECUTE before any "runtime graph" check — a poisoned dependency could no-op
// the checker. This module imports NO app code: the browser enforces SRI on
// THIS file, it then verifies every app/crypto module's bytes against
// manifest-sha256.json, and only then dynamically imports the real entry.
//
// RESIDUAL LIMITATION: the dynamic import re-fetches modules (served from the
// install-verified service-worker cache, or from the network when no service
// worker is active). The binding is: bootstrap-verified bytes == manifest AND
// service-worker cache == manifest (verified at install) => the executed bytes
// equal the manifest. With no service worker, a same-origin network MITM could
// in principle flip bytes between this check and the import — an
// origin-compromise threat the out-of-band manifest cannot defend against on
// its own. The real fix for that is a header-capable host signing the manifest.

// Keep in exact sync with APP_INTEGRITY_GRAPH in integrity.js
// (test/bootstrap.test.mjs asserts equality).
export const BOOTSTRAP_GRAPH = [
  "index.html",
  "kernel.html",
  "src/app.js",
  "src/approval-kernel.js",
  "src/api-client.js",
  "src/backup-recovery.js",
  "src/bank-signing-batch.js",
  "src/bootstrap.js",
  "src/frame-buster.js",
  "src/frame-messaging.js",
  "src/integrity.js",
  "src/json-schema-validate.js",
  "src/kernel-frame.js",
  "src/payment-view.js",
  "src/response-schemas.js",
  "src/polling-capabilities.js",
  "src/sign-task-worker.js",
  "src/signing-session.js",
  "src/signing-worker-pool.js",
  "src/storage.js",
  "src/styles.css",
  "src/sw-integrity.js",
  "src/webauthn.js",
  "src/core/crypto/bigint.js",
  "src/core/crypto/bytes.js",
  "src/core/crypto/circl-keyshare.js",
  "src/core/crypto/circl-signshare.js",
  "src/core/crypto/pkcs1v15.js",
  "src/core/crypto/threshold-rsa.js",
  "src/core/protocol/canonical.js",
  "src/core/protocol/envelopes.js",
  "src/core/protocol/signing.js"
];

const INTEGRITY_BYPASS_PARAM = "integrity_check";
const ENTRY_ALLOWLIST = new Set(["./app.js", "./kernel-frame.js"]);

function rootUrl() {
  return new URL("../", import.meta.url);
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bypassUrl(href) {
  const url = new URL(href);
  url.searchParams.set(INTEGRITY_BYPASS_PARAM, "1");
  return url;
}

export async function verifyGraph(graph = BOOTSTRAP_GRAPH, root = rootUrl()) {
  const response = await fetch(bypassUrl(new URL("manifest-sha256.json", root).href), { cache: "no-store" });
  if (!response.ok) {
    throw new Error("app integrity manifest is unavailable");
  }
  const manifest = JSON.parse(await response.text());
  if (manifest.version !== "pwa_integrity_manifest_v1" || manifest.algorithm !== "SHA-256") {
    throw new Error("app integrity manifest version is unsupported");
  }
  const expected = new Map((manifest.files ?? []).map((entry) => [entry.path, entry.sha256]));
  await Promise.all(graph.map(async (path) => {
    const want = expected.get(path);
    if (!want) {
      throw new Error(`app integrity manifest does not pin ${path}`);
    }
    const fileResponse = await fetch(bypassUrl(new URL(path, root).href), { cache: "no-store" });
    if (!fileResponse.ok) {
      throw new Error(`integrity fetch failed for ${path}`);
    }
    const got = await sha256Hex(new Uint8Array(await fileResponse.arrayBuffer()));
    if (got !== want) {
      throw new Error(`app integrity check failed for ${path}`);
    }
  }));
}

// Decided only AFTER the graph (including both verified HTML files) passes, and
// restricted to a hardcoded allow-list. index.html owns #kernelFrame; the
// kernel page (kernel.html) does not.
function entryModule() {
  const entry = document.getElementById("kernelFrame") ? "./app.js" : "./kernel-frame.js";
  if (!ENTRY_ALLOWLIST.has(entry)) {
    throw new Error("refusing to import a non-allowlisted entry module");
  }
  return entry;
}

async function boot() {
  await verifyGraph();
  await import(entryModule());
}

if (typeof window !== "undefined") {
  boot().catch((error) => {
    // Fail closed: never import the app on an integrity failure.
    try {
      document.body?.replaceChildren?.();
      const message = document.createElement("p");
      message.textContent = `App integrity check failed: ${error.message}`;
      document.body?.append?.(message);
    } catch {
      // ignore rendering failures; the important part is that the app never loads
    }
    // eslint-disable-next-line no-console
    console.error("[approval] integrity bootstrap failed", error);
  });
}
