// Bump the trailing -v<N> in CACHE_NAME whenever any file listed in PRECACHE_URLS
// changes. The fetch handler is strict cache-first, so without a fresh CACHE_NAME
// installed clients keep serving the previously cached copy indefinitely.
// Enforced by tools/check-service-worker-cache.mjs in CI.
const CACHE_NAME = "approval-approve-prod-v45";
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
  "./src/integrity.js",
  "./src/kernel-frame.js",
  "./src/payment-view.js",
  "./src/sign-worker.js",
  "./src/signing-session.js",
  "./src/storage.js",
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

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS)));
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

  event.respondWith(
    caches.match(event.request).then((cached) => cached ?? fetch(event.request).then((response) => {
      const copy = response.clone();
      caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
      return response;
    }))
  );
});
