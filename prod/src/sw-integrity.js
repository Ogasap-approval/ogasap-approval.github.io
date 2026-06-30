// Shared integrity helpers used by both the service worker (install-time
// precache verification, issue #9) and the runtime integrity check
// (pwa/src/integrity.js). Keeping the logic here means the verification that
// runs in the service worker is the exact same code exercised by the tests in
// test/sw-integrity.test.mjs.
import { bytesToHex } from "./core/crypto/bytes.js";

// Runtime integrity fetches append this query parameter so the service worker
// serves them network-first (bypassing the cache-first path) and can never
// answer an integrity probe with the very bytes it is supposed to be checked
// against. Static hosts (GitHub Pages, the dev server) ignore the query string
// and return the underlying file, so the parameter is harmless when no service
// worker is installed.
export const INTEGRITY_BYPASS_PARAM = "integrity_check";

function defaultDigest(bytes) {
  return globalThis.crypto.subtle.digest("SHA-256", bytes);
}

export async function sha256Hex(bytes, digest = defaultDigest) {
  return bytesToHex(new Uint8Array(await digest(bytes)));
}

// Maps a service-worker PRECACHE_URLS entry (e.g. "./", "./src/app.js") to the
// path key used in pwa/manifest-sha256.json (e.g. "index.html", "src/app.js").
export function manifestPathForPrecacheUrl(url) {
  if (url === "./" || url === "" || url.endsWith("/")) {
    return "index.html";
  }
  return url.replace(/^\.\//u, "");
}

export function expectedHashes(manifest) {
  if (manifest?.version !== "pwa_integrity_manifest_v1" || manifest?.algorithm !== "SHA-256") {
    throw new Error("integrity manifest version is unsupported");
  }
  return new Map((manifest.files ?? []).map((entry) => [entry.path, entry.sha256]));
}

// Throws when the bytes do not match the manifest-pinned hash for the given
// path. Returns the computed hash on success. Paths the manifest does not pin
// (only manifest-sha256.json itself, which is the out-of-band anchor) are
// skipped because they cannot be self-verified.
export async function assertBytesMatchManifest(expected, path, bytes, digest = defaultDigest) {
  const want = expected.get(path);
  if (want === undefined) {
    return null;
  }
  const got = await sha256Hex(bytes, digest);
  if (got !== want) {
    throw new Error(`integrity mismatch for ${path}`);
  }
  return got;
}
