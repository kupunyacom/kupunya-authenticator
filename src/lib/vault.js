// Vault encryption: PBKDF2-SHA256 for the passphrase, AES-256-GCM for the secrets.
// The plaintext never touches disk; only the envelope below is persisted.

import { base64ToBytes, bytesToBase64, bytesToUtf8, utf8ToBytes } from './bytes.js';

export const VAULT_FORMAT = 'kupunya-vault';
// Backups written before the rename still restore.
const LEGACY_FORMATS = ['keyring-vault'];
export const VAULT_VERSION = 1;
export const DEFAULT_ITERATIONS = 650000;
const KEY_BITS = 256;
const SALT_BYTES = 16;
const IV_BYTES = 12;

/** Derive raw key material. Kept as bytes so it can live in chrome.storage.session. */
export async function deriveKeyBytes(passphrase, salt, iterations = DEFAULT_ITERATIONS) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    utf8ToBytes(passphrase),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    baseKey,
    KEY_BITS,
  );
  return new Uint8Array(bits);
}

async function importAesKey(keyBytes, usages) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, usages);
}

export function randomSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

/** Encrypt a payload object into a self-describing envelope. */
export async function sealVault(payload, keyBytes, kdf) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await importAesKey(keyBytes, ['encrypt']);
  const plaintext = utf8ToBytes(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return {
    format: VAULT_FORMAT,
    version: VAULT_VERSION,
    kdf: {
      name: 'PBKDF2',
      hash: 'SHA-256',
      iterations: kdf.iterations,
      salt: bytesToBase64(kdf.salt),
    },
    cipher: 'AES-GCM',
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(ciphertext)),
    updatedAt: new Date().toISOString(),
  };
}

/** Decrypt an envelope. A wrong passphrase surfaces as an AES-GCM tag failure. */
export async function openVault(envelope, keyBytes) {
  assertEnvelope(envelope);
  const key = await importAesKey(keyBytes, ['decrypt']);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(envelope.iv) },
      key,
      base64ToBytes(envelope.data),
    );
  } catch {
    throw new Error('WRONG_PASSPHRASE');
  }
  return JSON.parse(bytesToUtf8(new Uint8Array(plaintext)));
}

export function assertEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object') throw new Error('vault envelope is missing');
  if (envelope.format !== VAULT_FORMAT && !LEGACY_FORMATS.includes(envelope.format)) {
    throw new Error('not a Kupunya vault file');
  }
  if (envelope.version > VAULT_VERSION) {
    throw new Error('vault was written by a newer version of the extension');
  }
  for (const field of ['iv', 'data', 'kdf']) {
    if (!envelope[field]) throw new Error(`vault envelope is missing "${field}"`);
  }
  if (!envelope.kdf.salt || !envelope.kdf.iterations) throw new Error('vault KDF parameters are incomplete');
}

/** KDF parameters read back out of an envelope, ready for deriveKeyBytes. */
export function kdfFromEnvelope(envelope) {
  return {
    salt: base64ToBytes(envelope.kdf.salt),
    iterations: envelope.kdf.iterations,
  };
}

/** Rough passphrase feedback for the setup screen. Advisory only, never blocking. */
export function passphraseStrength(passphrase) {
  const length = passphrase.length;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(passphrase)).length;
  if (length < 8) return { score: 0, label: 'too short' };
  let score = 1;
  if (length >= 12) score++;
  if (length >= 16) score++;
  if (classes >= 3) score++;
  score = Math.min(4, score);
  return { score, label: ['weak', 'weak', 'fair', 'good', 'strong'][score] };
}
