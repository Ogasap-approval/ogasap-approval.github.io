import { base64urlToBytes, bytesToBase64url, utf8Encode } from "./core/crypto/bytes.js";

const LOCAL_RP_IDS = new Set(["localhost", "127.0.0.1"]);
const GITHUB_PAGES_SUFFIX = ".github.io";

function randomChallenge(length = 32) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function isWebAuthnAvailable() {
  return Boolean(window.PublicKeyCredential && navigator.credentials?.create && navigator.credentials?.get);
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
        residentKey: "discouraged",
        userVerification: "required"
      },
      attestation: "none",
      timeout: 120000
    }
  });

  if (!credential?.rawId) {
    throw new Error("WebAuthn credential creation failed");
  }

  return {
    credential_id: bytesToBase64url(new Uint8Array(credential.rawId)),
    type: credential.type,
    created_at: new Date().toISOString()
  };
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
