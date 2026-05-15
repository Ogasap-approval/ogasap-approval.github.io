import { base64urlToBytes, bytesToBase64url, utf8Decode, utf8Encode } from "./core/crypto/bytes.js";

const DB_NAME = "approval-approve";
const DB_VERSION = 1;
const KEY_STORE = "keys";
const STATE_STORE = "state";
const WRAP_KEY_ID = "share-wrap-v1";
const SHARE_RECORD_ID = "phone-share-package";
const WEBAUTHN_RECORD_ID = "webauthn-credential";
const BACKEND_ORIGIN_RECORD_ID = "backend-origin";
const SHARE_AAD = utf8Encode("APPROVAL_PHONE_SHARE_PACKAGE_V1");
const WEBAUTHN_AAD = utf8Encode("APPROVAL_WEBAUTHN_CREDENTIAL_V1");

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

async function ensureWrapKey(db) {
  const existing = await getRecord(db, KEY_STORE, WRAP_KEY_ID);
  if (existing) {
    return existing;
  }

  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  await putRecord(db, KEY_STORE, WRAP_KEY_ID, key);
  return key;
}

async function encryptJsonRecord(db, { version, aad, value }) {
  const key = await ensureWrapKey(db);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = utf8Encode(JSON.stringify(value));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
    key,
    plaintext
  ));

  return {
    version,
    iv: bytesToBase64url(iv),
    ciphertext: bytesToBase64url(ciphertext),
    saved_at: new Date().toISOString()
  };
}

async function decryptJsonRecord(db, record, aad) {
  const key = await getRecord(db, KEY_STORE, WRAP_KEY_ID);
  if (!key) {
    return null;
  }

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

export async function savePhoneSharePackage(pkg) {
  const db = await openApprovalDb();
  try {
    await putRecord(db, STATE_STORE, SHARE_RECORD_ID, await encryptJsonRecord(db, {
      version: "encrypted_local_share_v1",
      aad: SHARE_AAD,
      value: pkg
    }));
  } finally {
    db.close();
  }
}

export async function loadPhoneSharePackage() {
  const db = await openApprovalDb();
  try {
    const record = await getRecord(db, STATE_STORE, SHARE_RECORD_ID);
    return record ? await decryptJsonRecord(db, record, SHARE_AAD) : null;
  } finally {
    db.close();
  }
}

export async function saveWebAuthnCredential(record) {
  const db = await openApprovalDb();
  try {
    await putRecord(db, STATE_STORE, WEBAUTHN_RECORD_ID, await encryptJsonRecord(db, {
      version: "encrypted_webauthn_credential_v1",
      aad: WEBAUTHN_AAD,
      value: {
        ...record,
        saved_at: new Date().toISOString()
      }
    }));
  } finally {
    db.close();
  }
}

export async function loadWebAuthnCredential() {
  const db = await openApprovalDb();
  try {
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
  } finally {
    db.close();
  }
}

export async function saveBackendOrigin(origin) {
  const db = await openApprovalDb();
  try {
    await putRecord(db, STATE_STORE, BACKEND_ORIGIN_RECORD_ID, {
      version: "backend_origin_v1",
      origin,
      saved_at: new Date().toISOString()
    });
  } finally {
    db.close();
  }
}

export async function loadBackendOrigin() {
  const db = await openApprovalDb();
  try {
    const record = await getRecord(db, STATE_STORE, BACKEND_ORIGIN_RECORD_ID);
    return record?.version === "backend_origin_v1" && typeof record.origin === "string" ? record.origin : "";
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
