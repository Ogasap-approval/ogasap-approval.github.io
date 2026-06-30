// Module service worker (registered with { type: "module" } in app.js).
//
// Bump the trailing -v<N> in CACHE_NAME whenever any file listed in PRECACHE_URLS
// changes. The fetch handler is strict cache-first, so without a fresh CACHE_NAME
// installed clients keep serving the previously cached copy indefinitely.
// Enforced by tools/check-service-worker-cache.mjs in CI.
//
// Issue #9: the precache is verified against pwa/manifest-sha256.json at install
// time (assertBytesMatchManifest below). If any precached byte does not match
// its pinned hash the install rejects and the new worker never activates, so the
// cache can never be poisoned with bytes that disagree with the manifest. The
// runtime integrity check (pwa/src/integrity.js) additionally appends
// INTEGRITY_BYPASS_PARAM so its probes are answered network-first rather than
// from this cache.
import {
  INTEGRITY_BYPASS_PARAM,
  assertBytesMatchManifest,
  expectedHashes,
  manifestPathForPrecacheUrl
} from "./src/sw-integrity.js";

const CACHE_NAME = "approval-approve-prod-v77";
const MANIFEST_URL = "./manifest-sha256.json";
const PRECACHE_URLS = [
  "./",
  "./index.html",
  "./kernel.html",
  "./manifest-sha256.json",
  "./manifest.webmanifest",
  "./src/styles.css",
  "./src/api-client.js",
  "./src/app.js",
  "./src/approval-kernel.js",
  "./src/backup-recovery.js",
  "./src/bank-signing-batch.js",
  "./src/bootstrap.js",
  "./src/frame-buster.js",
  "./src/frame-messaging.js",
  "./src/integrity.js",
  "./src/kernel-frame.js",
  "./src/payment-view.js",
  "./src/polling-capabilities.js",
  "./src/qr-encode.js",
  "./src/qr-decode.js",
  "./src/vendor/jsqr.js",
  "./src/sign-task-worker.js",
  "./src/signing-session.js",
  "./src/signing-worker-pool.js",
  "./src/storage.js",
  "./src/sw-integrity.js",
  "./src/webauthn.js",
  "./src/assets/icon.svg",
  "./src/core/crypto/bigint.js",
  "./src/core/crypto/bytes.js",
  "./src/core/crypto/circl-keyshare.js",
  "./src/core/crypto/circl-signshare.js",
  "./src/core/crypto/pkcs1v15.js",
  "./src/core/crypto/threshold-rsa.js",
  "./src/core/protocol/canonical.js",
  "./src/core/protocol/envelopes.js",
  "./src/core/protocol/signing.js"
];
const NETWORK_ONLY_PATHS = new Set([
  "/force-update.html",
  "/src/force-update.js"
]);

async function installPrecache() {
  const cache = await caches.open(CACHE_NAME);
  const manifestResponse = await fetch(new Request(MANIFEST_URL, { cache: "no-store" }));
  if (!manifestResponse.ok) {
    throw new Error("integrity manifest unavailable during service worker install");
  }
  const manifestText = await manifestResponse.clone().text();
  const expected = expectedHashes(JSON.parse(manifestText));

  await Promise.all(PRECACHE_URLS.map(async (url) => {
    const request = new Request(url, { cache: "no-store" });
    const response = await fetch(request);
    if (!response.ok) {
      throw new Error(`precache fetch failed for ${url}`);
    }
    const bytes = new Uint8Array(await response.clone().arrayBuffer());
    await assertBytesMatchManifest(expected, manifestPathForPrecacheUrl(url), bytes);
    await cache.put(request, response);
  }));
}

self.addEventListener("install", (event) => {
  event.waitUntil(installPrecache());
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) => Promise.all(
      names.filter((name) => name !== CACHE_NAME).map((name) => caches.delete(name))
    ))
  );
  self.clients.claim();
});

self.addEventListener("message", (event) => {
  // The Settings panel asks the active worker which build it is serving, so it can
  // show the version alongside the app hash. CACHE_NAME is already public (a literal
  // in this script), so replying with it leaks nothing. Reply on the provided
  // MessageChannel port if present.
  if (event.data?.type === "GET_VERSION") {
    event.ports?.[0]?.postMessage({ type: "VERSION", cacheName: CACHE_NAME });
  }
});

async function networkFirstThenVerifiedCache(request, url) {
  try {
    return await fetch(request);
  } catch (error) {
    const canonical = new URL(url.href);
    canonical.searchParams.delete(INTEGRITY_BYPASS_PARAM);
    const cached = await caches.match(canonical.href);
    if (cached) {
      return cached;
    }
    throw error;
  }
}

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") {
    return;
  }
  const url = new URL(event.request.url);
  if (
    url.origin !== location.origin ||
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/demo/") ||
    url.pathname.startsWith("/prod/")
  ) {
    return;
  }

  if (NETWORK_ONLY_PATHS.has(url.pathname) || url.searchParams.has("force_update")) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Runtime integrity probes must see authentic (network-true) bytes, never the
  // cache they are meant to be checked against. Fall back to the install-verified
  // cache only when offline.
  if (url.searchParams.has(INTEGRITY_BYPASS_PARAM)) {
    event.respondWith(networkFirstThenVerifiedCache(event.request, url));
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => cached ?? fetch(event.request).then((response) => {
      const copy = response.clone();
      caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
      return response;
    }))
  );
});
