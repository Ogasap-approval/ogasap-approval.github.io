import { base64urlToBytes, bytesToBase64url, utf8Encode } from "./core/crypto/bytes.js";

const LOCAL_RP_IDS = new Set(["localhost", "127.0.0.1"]);
const GITHUB_PAGES_SUFFIX = ".github.io";
const PRF_WRAP_HKDF_SALT = utf8Encode("APPROVAL_WEBAUTHN_PRF_WRAP_SALT_V1");
const PRF_WRAP_HKDF_INFO = utf8Encode("APPROVAL_PHONE_SHARE_PACKAGE_PRF_AES_GCM_V1");

function randomChallenge(length = 32) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function randomPrfSaltBase64url() {
  return bytesToBase64url(randomChallenge());
}

export function isWebAuthnAvailable() {
  return Boolean(window.PublicKeyCredential && navigator.credentials?.create && navigator.credentials?.get);
}

export async function webauthnClientCapabilities() {
  if (typeof window.PublicKeyCredential?.getClientCapabilities !== "function") {
    return {};
  }
  try {
    return await window.PublicKeyCredential.getClientCapabilities();
  } catch {
    return {};
  }
}

export function approvalRpId(hostname = window.location.hostname) {
  const normalized = hostname.toLowerCase();
  if (normalized.endsWith(GITHUB_PAGES_SUFFIX)) {
    return normalized;
  }
  if (LOCAL_RP_IDS.has(normalized)) {
    return normalized;
  }
  throw new Error(`Unsupported WebAuthn RP host: ${normalized}`);
}

export async function createApprovalCredential({ approverId, deviceId }) {
  if (!isWebAuthnAvailable()) {
    throw new Error("WebAuthn is not available");
  }

  const userId = utf8Encode(`${approverId}:${deviceId}`).slice(0, 64);
  const prfCreationSalt = randomChallenge();
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: randomChallenge(),
      rp: {
        id: approvalRpId(),
        name: "Approval"
      },
      user: {
        id: userId,
        name: approverId,
        displayName: approverId
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 }
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required"
      },
      attestation: "none",
      timeout: 120000,
      extensions: {
        credProps: true,
        prf: {
          eval: { first: prfCreationSalt }
        }
      }
    }
  });

  if (!credential?.rawId) {
    throw new Error("WebAuthn credential creation failed");
  }

  const extensionResults = credential.getClientExtensionResults?.() ?? {};
  const prfResult = extensionResults.prf?.results?.first;
  const credProps = extensionResults.credProps ?? {};
  // Enrollment (#4/#35 PWA side): export the credential PUBLIC KEY (SPKI DER) and
  // its COSE algorithm so the PWA can enrol it with the backend registry, which
  // server-side WebAuthn verification needs to validate the assertion signature.
  const attestation = credential.response;
  const publicKeyDer = attestation?.getPublicKey?.() ?? null;
  const publicKeyAlg = attestation?.getPublicKeyAlgorithm?.();
  return {
    credential_id: bytesToBase64url(new Uint8Array(credential.rawId)),
    type: credential.type,
    created_at: new Date().toISOString(),
    rp_id: approvalRpId(),
    public_key_spki_base64url: publicKeyDer ? bytesToBase64url(new Uint8Array(publicKeyDer)) : "",
    public_key_alg: Number.isInteger(publicKeyAlg) ? publicKeyAlg : null,
    resident_key: credProps.rk === true,
    webauthn_capabilities: await webauthnClientCapabilities(),
    prf_creation_enabled: extensionResults.prf?.enabled === true,
    prf_creation_result_available: Boolean(prfResult),
    prf_creation_salt_base64url: prfResult ? bytesToBase64url(prfCreationSalt) : "",
    prf_creation_result_base64url: prfResult ? bytesToBase64url(new Uint8Array(prfResult)) : ""
  };
}

export async function derivePrfWrapKey(prfOutputBytes) {
  const raw = prfOutputBytes instanceof Uint8Array ? prfOutputBytes : new Uint8Array(prfOutputBytes);
  if (raw.byteLength < 32) {
    throw new Error("WebAuthn PRF output is too short");
  }
  const key = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: PRF_WRAP_HKDF_SALT,
      info: PRF_WRAP_HKDF_INFO
    },
    key,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function prfWrapKeyFromCreationResult(credentialRecord) {
  if (!credentialRecord?.prf_creation_result_base64url) {
    return null;
  }
  return derivePrfWrapKey(base64urlToBytes(credentialRecord.prf_creation_result_base64url));
}

export async function requestPrfWrapKey({ credentialId, saltBase64url }) {
  if (!isWebAuthnAvailable()) {
    throw new Error("WebAuthn is not available");
  }

  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: randomChallenge(),
      rpId: approvalRpId(),
      allowCredentials: [
        {
          type: "public-key",
          id: base64urlToBytes(credentialId)
        }
      ],
      userVerification: "required",
      timeout: 120000,
      extensions: {
        prf: {
          evalByCredential: {
            [credentialId]: {
              first: base64urlToBytes(saltBase64url)
            }
          }
        }
      }
    }
  });

  const prfResult = credential?.getClientExtensionResults?.()?.prf?.results?.first;
  if (!prfResult) {
    throw new Error("WebAuthn PRF returned no key for this credential");
  }
  return derivePrfWrapKey(new Uint8Array(prfResult));
}

export async function requestApprovalAssertion({ credentialId, challengeBytes }) {
  if (!isWebAuthnAvailable()) {
    throw new Error("WebAuthn is not available");
  }

  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: challengeBytes,
      rpId: approvalRpId(),
      allowCredentials: [
        {
          type: "public-key",
          id: base64urlToBytes(credentialId)
        }
      ],
      userVerification: "required",
      timeout: 120000
    }
  });

  if (!credential?.response) {
    throw new Error("WebAuthn assertion failed");
  }

  return {
    credential_id: bytesToBase64url(new Uint8Array(credential.rawId)),
    client_data_json_base64url: bytesToBase64url(new Uint8Array(credential.response.clientDataJSON)),
    authenticator_data_base64url: bytesToBase64url(new Uint8Array(credential.response.authenticatorData)),
    signature_base64url: bytesToBase64url(new Uint8Array(credential.response.signature)),
    user_verification: "required"
  };
}
