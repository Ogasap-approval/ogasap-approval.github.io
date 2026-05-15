import { utf8Encode } from "./core/crypto/bytes.js";
import { sha256Hex } from "./core/protocol/canonical.js";

const MANIFEST_URL = new URL("../manifest-sha256.json", import.meta.url);
const PWA_ROOT_URL = new URL("../", import.meta.url);

function resourceUrl(path) {
  if (typeof path !== "string" || path.startsWith("/") || path.includes("..")) {
    throw new Error("integrity resource path is invalid");
  }
  return new URL(path, PWA_ROOT_URL);
}

async function responseBytes(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`integrity fetch failed for ${url.pathname}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

function filesByPath(manifest) {
  return new Map((manifest.files ?? []).map((entry) => [entry.path, entry.sha256]));
}

export async function loadIntegrityManifest() {
  const response = await fetch(MANIFEST_URL, { cache: "no-store" });
  if (!response.ok) {
    throw new Error("app integrity manifest is unavailable");
  }
  const raw = await response.text();
  const manifest = JSON.parse(raw);
  if (manifest.version !== "pwa_integrity_manifest_v1" || manifest.algorithm !== "SHA-256") {
    throw new Error("app integrity manifest version is unsupported");
  }

  return {
    ...manifest,
    manifest_sha256: await sha256Hex(utf8Encode(raw)),
    files_by_path: filesByPath(manifest)
  };
}

export async function assertResourceIntegrity(manifest, path) {
  const expected = manifest?.files_by_path?.get(path);
  if (!expected) {
    throw new Error(`app integrity manifest does not pin ${path}`);
  }

  const actual = await sha256Hex(await responseBytes(resourceUrl(path)));
  if (actual !== expected) {
    throw new Error(`app integrity check failed for ${path}`);
  }
  return actual;
}

export async function assertResourcesIntegrity(manifest, paths) {
  await Promise.all(paths.map((path) => assertResourceIntegrity(manifest, path)));
}
