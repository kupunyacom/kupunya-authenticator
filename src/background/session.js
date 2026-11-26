// Holds the derived vault key for the life of an unlocked session.
//
// MV3 service workers get evicted, so the key cannot live in a module variable
// alone. chrome.storage.session is the right home: it is memory-backed, never
// written to disk, and cleared when the browser closes.

import { bytesToBase64, base64ToBytes } from '../lib/bytes.js';
import {
  deriveKeyBytes,
  kdfFromEnvelope,
  openVault,
  sealVault,
  randomSalt,
  DEFAULT_ITERATIONS,
} from '../lib/vault.js';
import { loadSettings } from '../lib/settings.js';
import { wrapVaultKey, unwrapVaultKey } from '../lib/biometric.js';

const SESSION_KEY = 'sessionKey';
const ALARM_NAME = 'kupunya-auto-lock';
const BIOMETRIC_KEY = 'biometric';

export async function getEnvelope() {
  const { vault } = await chrome.storage.local.get('vault');
  return vault || null;
}

export async function setEnvelope(envelope) {
  await chrome.storage.local.set({ vault: envelope });
}

export async function isInitialized() {
  return (await getEnvelope()) !== null;
}

async function getKeyBytes() {
  const stored = await chrome.storage.session.get(SESSION_KEY);
  const value = stored[SESSION_KEY];
  return value ? base64ToBytes(value) : null;
}

async function rememberKey(keyBytes) {
  await chrome.storage.session.set({ [SESSION_KEY]: bytesToBase64(keyBytes) });
}

export async function isUnlocked() {
  return (await getKeyBytes()) !== null;
}

export async function lock() {
  await chrome.storage.session.remove(SESSION_KEY);
  await chrome.alarms.clear(ALARM_NAME);
}

/** Restart the idle timer. Called on every successful popup interaction. */
export async function scheduleAutoLock() {
  const { autoLockMinutes } = await loadSettings();
  await chrome.alarms.clear(ALARM_NAME);
  if (autoLockMinutes > 0) {
    chrome.alarms.create(ALARM_NAME, { delayInMinutes: autoLockMinutes });
  }
}

export function isAutoLockAlarm(alarm) {
  return alarm?.name === ALARM_NAME;
}

/** Create a brand new empty vault protected by `passphrase`. */
export async function createVault(passphrase) {
  if (await isInitialized()) throw new Error('vault already exists');
  const kdf = { salt: randomSalt(), iterations: DEFAULT_ITERATIONS };
  const keyBytes = await deriveKeyBytes(passphrase, kdf.salt, kdf.iterations);
  const envelope = await sealVault({ accounts: [] }, keyBytes, kdf);
  await setEnvelope(envelope);
  await rememberKey(keyBytes);
  await scheduleAutoLock();
}

/** Verify the passphrase and keep the derived key for this session. */
export async function unlock(passphrase) {
  const envelope = await getEnvelope();
  if (!envelope) throw new Error('NOT_INITIALIZED');
  const kdf = kdfFromEnvelope(envelope);
  const keyBytes = await deriveKeyBytes(passphrase, kdf.salt, kdf.iterations);
  await openVault(envelope, keyBytes); // throws WRONG_PASSPHRASE
  await rememberKey(keyBytes);
  await scheduleAutoLock();
}

/** Read the decrypted payload. Requires an unlocked session. */
export async function readPayload() {
  const keyBytes = await getKeyBytes();
  if (!keyBytes) throw new Error('LOCKED');
  const envelope = await getEnvelope();
  if (!envelope) throw new Error('NOT_INITIALIZED');
  return openVault(envelope, keyBytes);
}

// Every write is read-modify-write over the whole vault, so two commands
// arriving close together could otherwise read the same snapshot and the second
// seal would silently discard the first one's change. Serialise them.
let writeQueue = Promise.resolve();

/** Apply `mutator` to the payload and re-seal it. Returns the new payload. */
export async function writePayload(mutator) {
  const run = async () => {
    const keyBytes = await getKeyBytes();
    if (!keyBytes) throw new Error('LOCKED');
    const envelope = await getEnvelope();
    const payload = await openVault(envelope, keyBytes);
    const next = (await mutator(payload)) ?? payload;
    await setEnvelope(await sealVault(next, keyBytes, kdfFromEnvelope(envelope)));
    return next;
  };
  const result = writeQueue.then(run, run);
  // Keep the chain alive even when a mutator throws.
  writeQueue = result.catch(() => {});
  return result;
}

/** Re-derive under a new passphrase and rewrite the envelope. */
export async function changePassphrase(currentPassphrase, nextPassphrase) {
  const envelope = await getEnvelope();
  if (!envelope) throw new Error('NOT_INITIALIZED');
  const currentKdf = kdfFromEnvelope(envelope);
  const currentKey = await deriveKeyBytes(currentPassphrase, currentKdf.salt, currentKdf.iterations);
  const payload = await openVault(envelope, currentKey);

  const kdf = { salt: randomSalt(), iterations: DEFAULT_ITERATIONS };
  const keyBytes = await deriveKeyBytes(nextPassphrase, kdf.salt, kdf.iterations);
  await setEnvelope(await sealVault(payload, keyBytes, kdf));
  await rememberKey(keyBytes);
  await disableBiometric(); // it wrapped the old key
  await scheduleAutoLock();
}

/** Replace the whole vault from a backup file, unlocking with its own passphrase. */
export async function restoreFromEnvelope(backup, passphrase) {
  const kdf = kdfFromEnvelope(backup);
  const keyBytes = await deriveKeyBytes(passphrase, kdf.salt, kdf.iterations);
  const payload = await openVault(backup, keyBytes); // validates the passphrase
  await setEnvelope(backup);
  await rememberKey(keyBytes);
  await disableBiometric(); // it wrapped the old key
  await scheduleAutoLock();
  return payload;
}

// --- Touch ID ---------------------------------------------------------------

export async function getBiometric() {
  const stored = await chrome.storage.local.get(BIOMETRIC_KEY);
  return stored[BIOMETRIC_KEY] || null;
}

/** Wrap the current session key under a PRF output. Requires an unlocked vault. */
export async function enableBiometric({ credentialId, prfSalt, prfOutput }) {
  const keyBytes = await getKeyBytes();
  if (!keyBytes) throw new Error('LOCKED');
  const record = await wrapVaultKey(keyBytes, prfOutput, { credentialId, prfSalt });
  // Prove the round trip before trusting it with an unlock.
  await unwrapVaultKey(record, prfOutput);
  await chrome.storage.local.set({ [BIOMETRIC_KEY]: record });
  await scheduleAutoLock();
}

export async function disableBiometric() {
  await chrome.storage.local.remove(BIOMETRIC_KEY);
}

export async function unlockWithBiometric(prfOutput) {
  const record = await getBiometric();
  if (!record) throw new Error('BIOMETRIC_NOT_SET_UP');
  const envelope = await getEnvelope();
  if (!envelope) throw new Error('NOT_INITIALIZED');
  const keyBytes = await unwrapVaultKey(record, prfOutput);
  try {
    await openVault(envelope, keyBytes);
  } catch {
    // The vault was re-keyed without us noticing; this record is dead.
    await disableBiometric();
    throw new Error('BIOMETRIC_STALE');
  }
  await rememberKey(keyBytes);
  await scheduleAutoLock();
}

export async function wipeEverything() {
  await lock();
  await chrome.storage.local.clear();
}
