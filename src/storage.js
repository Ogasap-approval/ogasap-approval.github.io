import { base64urlToBytes, bytesToBase64url, utf8Decode, utf8Encode } from "./core/crypto/bytes.js";

const DB_NAME = "approval-approve";
const DB_VERSION = 1;
const KEY_STORE = "keys";
const STATE_STORE = "state";
const WRAP_KEY_ID = "share-wrap-v1";
const SHARE_RECORD_ID = "phone-share-package";
const WEBAUTHN_RECORD_ID = "webauthn-credential";
const WEBAUTHN_PUBLIC_RECORD_ID = "webauthn-credential-public";
const BACKEND_ORIGIN_RECORD_ID = "backend-origin";
const SHARE_AAD = utf8Encode("APPROVAL_PHONE_SHARE_PACKAGE_V1");
const PRF_SHARE_AAD = utf8Encode("APPROVAL_PHONE_SHARE_PACKAGE_PRF_V1");
const WEBAUTHN_AAD = utf8Encode("APPROVAL_WEBAUTHN_CREDENTIAL_V1");
const PRF_BACKEND_ORIGIN_AAD = utf8Encode("APPROVAL_BACKEND_ORIGIN_PRF_V1");

// Issue #26: in the non-PRF (local AES) fallback the phone share is wrapped by
// a non-extractable AES-GCM CryptoKey kept in IndexedDB. The unwrap is gated
// behind a WebAuthn user-verification ceremony supplied by the app shell via
// setLocalShareUnlockVerifier(): the share is only ever decrypted right after a
// fresh biometric/UV assertion, so a silent same-origin script cannot unwrap it
// through this path.
//
// RESIDUAL RISK: the wrapping key is non-extractable (script cannot read its raw
// bytes) but it still lives in IndexedDB with decrypt usage, so a same-origin
// XSS could in principle open the DB and call crypto.subtle.decrypt() directly,
// bypassing this UV gate. The strong mitigation is the WebAuthn-PRF path, where
// the wrapping key is derived from the UV assertion and never stored at all.
let localShareUnlockVerifier = null;

export function setLocalShareUnlockVerifier(verifier) {
  localShareUnlockVerifier = typeof verifier === "function" ? verifier : null;
}

function requestToPromise(request) {
  return new Promise((resolve, reject) => {
    request.addEventListener("success", () => resolve(request.result), { once: true });
    request.addEventListener("error", () => reject(request.error), { once: true });
  });
}

function txDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.addEventListener("complete", () => resolve(), { once: true });
    transaction.addEventListener("abort", () => reject(transaction.error), { once: true });
    transaction.addEventListener("error", () => reject(transaction.error), { once: true });
  });
}

export function openApprovalDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.addEventListener("upgradeneeded", () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE);
      }
      if (!db.objectStoreNames.contains(STATE_STORE)) {
        db.createObjectStore(STATE_STORE);
      }
    });
    request.addEventListener("success", () => resolve(request.result), { once: true });
    request.addEventListener("error", () => reject(request.error), { once: true });
  });
}

async function getRecord(db, storeName, id) {
  const tx = db.transaction(storeName, "readonly");
  return requestToPromise(tx.objectStore(storeName).get(id));
}

async function putRecord(db, storeName, id, value) {
  const tx = db.transaction(storeName, "readwrite");
  tx.objectStore(storeName).put(value, id);
  await txDone(tx);
}

// Non-extractable AES-GCM wrap key: crypto.subtle.exportKey() rejects for it, so
// script can never read the raw key material out of IndexedDB.
export function generateLocalWrapKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function ensureWrapKey(db) {
  const existing = await getRecord(db, KEY_STORE, WRAP_KEY_ID);
  if (existing) {
    return existing;
  }

  const key = await generateLocalWrapKey();
  await putRecord(db, KEY_STORE, WRAP_KEY_ID, key);
  return key;
}

// Unwraps a local-AES record only after the supplied user-verification gate
// resolves. Exported so the gate behaviour is testable without IndexedDB.
export async function decryptLocalShareRecord(key, record, aad, { verifyUserPresence = null } = {}) {
  if (typeof verifyUserPresence === "function") {
    await verifyUserPresence();
  }
  return decryptJsonWithKey(key, record, aad);
}

export async function encryptJsonWithKey(key, { version, aad, value, extra = {} }) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = utf8Encode(JSON.stringify(value));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    plaintext
  ));

  return {
    version,
    ...extra,
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(ciphertext),
    saved_at: new Date().toISOString()
  };
}

export async function decryptJsonWithKey(key, record, aad) {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64urlToBytes(record.iv),
      additionalData: aad,
      tagLength: 128
    },
    key,
    base64urlToBytes(record.ciphertext)
  );
  return JSON.parse(utf8Decode(new Uint8Array(plaintext)));
}

async function encryptJsonRecord(db, options) {
  return encryptJsonWithKey(await ensureWrapKey(db), options);
}

async function decryptJsonRecord(db, record, aad) {
  const key = await getRecord(db, KEY_STORE, WRAP_KEY_ID);
  return key ? decryptJsonWithKey(key, record, aad) : null;
}

function publicWebAuthnCredentialRecord(record) {
  if (typeof record?.credential_id !== "string") {
    return null;
  }
  return {
    version: "webauthn_credential_public_v1",
    credential_id: record.credential_id,
    type: typeof record.type === "string" ? record.type : "public-key",
    // Non-secret enrollment material kept in the public record so the credential
    // can be (re-)enrolled with the backend even while the share is PRF-locked.
    rp_id: typeof record.rp_id === "string" ? record.rp_id : "",
    public_key_spki_base64url: typeof record.public_key_spki_base64url === "string" ? record.public_key_spki_base64url : "",
    public_key_alg: Number.isInteger(record.public_key_alg) ? record.public_key_alg : null,
    prf_enabled: record.prf_enabled === true,
    prf_salt_base64url: typeof record.prf_salt_base64url === "string" ? record.prf_salt_base64url : ""
  };
}

function credentialFromPublicRecord(record) {
  return record?.version === "webauthn_credential_public_v1" ? publicWebAuthnCredentialRecord(record) : null;
}

export async function savePhoneSharePackage(pkg, { prfWrapKey = null, prfSaltBase64url = "" } = {}) {
  const db = await openApprovalDb();
  try {
    if (prfWrapKey && prfSaltBase64url) {
      await putRecord(db, STATE_STORE, SHARE_RECORD_ID, await encryptJsonWithKey(prfWrapKey, {
        version: "encrypted_prf_share_v1",
        aad: PRF_SHARE_AAD,
        value: pkg,
        extra: {
          wrapping: "webauthn_prf",
          prf_salt_base64url: prfSaltBase64url
        }
      }));
    } else {
      await putRecord(db, STATE_STORE, SHARE_RECORD_ID, await encryptJsonRecord(db, {
        version: "encrypted_local_share_v1",
        aad: SHARE_AAD,
        value: pkg
      }));
    }
  } finally {
    db.close();
  }
}

export async function loadPhoneSharePackage({ prfWrapKey = null } = {}) {
  const db = await openApprovalDb();
  try {
    const record = await getRecord(db, STATE_STORE, SHARE_RECORD_ID);
    if (!record) {
      return null;
    }
    if (record.version === "encrypted_prf_share_v1") {
      return prfWrapKey ? decryptJsonWithKey(prfWrapKey, record, PRF_SHARE_AAD) : null;
    }
    const key = await getRecord(db, KEY_STORE, WRAP_KEY_ID);
    if (!key) {
      return null;
    }
    return decryptLocalShareRecord(key, record, SHARE_AAD, { verifyUserPresence: localShareUnlockVerifier });
  } finally {
    db.close();
  }
}

export async function phoneSharePackageRequiresPrfUnlock() {
  const db = await openApprovalDb();
  try {
    const record = await getRecord(db, STATE_STORE, SHARE_RECORD_ID);
    return record?.version === "encrypted_prf_share_v1";
  } finally {
    db.close();
  }
}

export async function loadPhoneSharePrfSalt() {
  const db = await openApprovalDb();
  try {
    const record = await getRecord(db, STATE_STORE, SHARE_RECORD_ID);
    return record?.version === "encrypted_prf_share_v1" ? record.prf_salt_base64url ?? "" : "";
  } finally {
    db.close();
  }
}

export async function saveWebAuthnCredential(record) {
  const db = await openApprovalDb();
  try {
    const encryptedRecord = await getRecord(db, STATE_STORE, WEBAUTHN_RECORD_ID);
    const existing = encryptedRecord?.version === "encrypted_webauthn_credential_v1"
      ? await decryptJsonRecord(db, encryptedRecord, WEBAUTHN_AAD)
      : null;
    const value = {
      ...(existing ?? {}),
      ...record,
      saved_at: new Date().toISOString()
    };
    const publicRecord = publicWebAuthnCredentialRecord(value);
    if (publicRecord) {
      await putRecord(db, STATE_STORE, WEBAUTHN_PUBLIC_RECORD_ID, publicRecord);
    }
    await putRecord(db, STATE_STORE, WEBAUTHN_RECORD_ID, await encryptJsonRecord(db, {
      version: "encrypted_webauthn_credential_v1",
      aad: WEBAUTHN_AAD,
      value
    }));
  } finally {
    db.close();
  }
}

async function loadPrivateWebAuthnCredential(db) {
  const record = await getRecord(db, STATE_STORE, WEBAUTHN_RECORD_ID);
  if (!record) {
    return null;
  }
  if (record.version === "encrypted_webauthn_credential_v1") {
    return decryptJsonRecord(db, record, WEBAUTHN_AAD);
  }
  if (typeof record.credential_id === "string") {
    await putRecord(db, STATE_STORE, WEBAUTHN_RECORD_ID, await encryptJsonRecord(db, {
      version: "encrypted_webauthn_credential_v1",
      aad: WEBAUTHN_AAD,
      value: record
    }));
    return record;
  }
  return null;
}

export async function loadWebAuthnCredential({ publicOnly = false } = {}) {
  const db = await openApprovalDb();
  try {
    const publicCredential = credentialFromPublicRecord(await getRecord(db, STATE_STORE, WEBAUTHN_PUBLIC_RECORD_ID));
    if (publicOnly && publicCredential) {
      return publicCredential;
    }
    const privateCredential = await loadPrivateWebAuthnCredential(db);
    if (!privateCredential) {
      return publicCredential;
    }
    const nextPublicCredential = publicWebAuthnCredentialRecord(privateCredential);
    if (nextPublicCredential) {
      await putRecord(db, STATE_STORE, WEBAUTHN_PUBLIC_RECORD_ID, nextPublicCredential);
    }
    return publicOnly ? nextPublicCredential : privateCredential;
  } finally {
    db.close();
  }
}

export async function saveBackendOrigin(origin, { prfWrapKey = null, prfSaltBase64url = "" } = {}) {
  const db = await openApprovalDb();
  try {
    if (prfWrapKey && prfSaltBase64url) {
      await putRecord(db, STATE_STORE, BACKEND_ORIGIN_RECORD_ID, await encryptJsonWithKey(prfWrapKey, {
        version: "encrypted_prf_backend_origin_v1",
        aad: PRF_BACKEND_ORIGIN_AAD,
        value: { origin },
        extra: {
          wrapping: "webauthn_prf",
          prf_salt_base64url: prfSaltBase64url
        }
      }));
    } else {
      await putRecord(db, STATE_STORE, BACKEND_ORIGIN_RECORD_ID, {
        version: "backend_origin_v1",
        origin,
        saved_at: new Date().toISOString()
      });
    }
  } finally {
    db.close();
  }
}

export async function loadBackendOrigin({ prfWrapKey = null } = {}) {
  const db = await openApprovalDb();
  try {
    const record = await getRecord(db, STATE_STORE, BACKEND_ORIGIN_RECORD_ID);
    if (record?.version === "encrypted_prf_backend_origin_v1") {
      if (!prfWrapKey) {
        return "";
      }
      const value = await decryptJsonWithKey(prfWrapKey, record, PRF_BACKEND_ORIGIN_AAD);
      return typeof value?.origin === "string" ? value.origin : "";
    }
    return record?.version === "backend_origin_v1" && typeof record.origin === "string" ? record.origin : "";
  } finally {
    db.close();
  }
}

export async function backendOriginRequiresPrfUnlock() {
  const db = await openApprovalDb();
  try {
    const record = await getRecord(db, STATE_STORE, BACKEND_ORIGIN_RECORD_ID);
    return record?.version === "encrypted_prf_backend_origin_v1";
  } finally {
    db.close();
  }
}

export function clearEnrollment() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DB_NAME);
    request.addEventListener("success", () => resolve(), { once: true });
    request.addEventListener("blocked", () => reject(new Error("database reset is blocked by an open tab")), { once: true });
    request.addEventListener("error", () => reject(request.error), { once: true });
  });
}

export async function isStoragePersisted() {
  if (!navigator.storage?.persisted) {
    return false;
  }
  return navigator.storage.persisted();
}

export async function requestPersistentStorage() {
  if (await isStoragePersisted()) {
    return true;
  }
  if (!navigator.storage?.persist) {
    return false;
  }
  return navigator.storage.persist();
}
