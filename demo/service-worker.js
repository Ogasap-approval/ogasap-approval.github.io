// Bump the trailing -v<N> in CACHE_NAME whenever any file listed in PRECACHE_URLS
// changes. The fetch handler is strict cache-first, so without a fresh CACHE_NAME
// installed clients keep serving the previously cached copy indefinitely.
// Enforced by tools/check-service-worker-cache.mjs in CI.
const CACHE_NAME = "approval-approve-demo-pwa-v45";
const PRECACHE_URLS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./src/styles.css",
  "./src/api-client.js",
  "./src/app.js",
  "./src/demo-fixtures.js",
  "./src/assets/icon.svg",
  "./src/test-materials/test-phone-share-package.json",
  "../prod/src/payment-view.js",
  "../prod/src/bank-signing-batch.js",
  "../prod/src/polling-capabilities.js",
  "../prod/src/sign-task-worker.js",
  "../prod/src/signing-session.js",
  "../prod/src/signing-worker-pool.js",
  "../prod/src/storage.js",
  "../prod/src/webauthn.js",
  "../prod/src/core/crypto/bigint.js",
  "../prod/src/core/crypto/bytes.js",
  "../prod/src/core/crypto/circl-keyshare.js",
  "../prod/src/core/crypto/circl-signshare.js",
  "../prod/src/core/crypto/pkcs1v15.js",
  "../prod/src/core/crypto/threshold-rsa.js",
  "../prod/src/core/protocol/canonical.js",
  "../prod/src/core/protocol/envelopes.js",
  "../prod/src/core/protocol/signing.js"
];

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
  if (url.origin !== location.origin || url.pathname.startsWith("/api/")) {
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
