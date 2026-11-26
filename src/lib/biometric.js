// Touch ID unlock, the half that runs in the service worker.
//
// The WebAuthn PRF extension gives us 32 bytes that the platform authenticator
// only releases after the user's fingerprint matches. We stretch those with
// HKDF into an AES-GCM key and use it to wrap the vault key. What sits on disk
// is useless without the authenticator: no fingerprint, no PRF output, no key.

import { base64ToBytes, bytesToBase64, utf8ToBytes } from './bytes.js';

const INFO = utf8ToBytes('kupunya/biometric-wrap/v1');
const PRF_BYTES = 32;
const IV_BYTES = 12;

function decodePrf(prfOutput) {
  const bytes = typeof prfOutput === 'string' ? base64ToBytes(prfOutput) : new Uint8Array(prfOutput || []);
  if (bytes.length !== PRF_BYTES) throw new Error('BIOMETRIC_FAILED');
  return bytes;
}

async function wrappingKey(prfBytes, salt) {
  const base = await crypto.subtle.importKey('raw', prfBytes, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: INFO },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Seal the vault key under the PRF output. Returns the record to store. */
export async function wrapVaultKey(keyBytes, prfOutput, { credentialId, prfSalt }) {
  if (!credentialId || !prfSalt) throw new Error('credential details are missing');
  const key = await wrappingKey(decodePrf(prfOutput), base64ToBytes(prfSalt));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const wrapped = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: base64ToBytes(credentialId) },
    key,
    keyBytes,
  );
  return {
    version: 1,
    credentialId,
    prfSalt,
    iv: bytesToBase64(iv),
    wrapped: bytesToBase64(new Uint8Array(wrapped)),
    createdAt: new Date().toISOString(),
  };
}

/** Recover the vault key, or throw BIOMETRIC_FAILED. */
export async function unwrapVaultKey(record, prfOutput) {
  try {
    const key = await wrappingKey(decodePrf(prfOutput), base64ToBytes(record.prfSalt));
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(record.iv), additionalData: base64ToBytes(record.credentialId) },
      key,
      base64ToBytes(record.wrapped),
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error('BIOMETRIC_FAILED');
  }
}
