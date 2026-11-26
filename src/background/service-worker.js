// Single owner of the vault. The popup and options page never touch storage or
// crypto directly; they send commands here and get plain data back.

import {
  createVault,
  unlock,
  lock,
  isUnlocked,
  isInitialized,
  readPayload,
  writePayload,
  changePassphrase,
  restoreFromEnvelope,
  scheduleAutoLock,
  isAutoLockAlarm,
  getEnvelope,
  wipeEverything,
  getBiometric,
  enableBiometric,
  disableBiometric,
  unlockWithBiometric,
} from './session.js';
import { otpFieldScript, issuerMatchesHost, FILL_THRESHOLD } from '../lib/autofill.js';
import { loadSettings, saveSettings } from '../lib/settings.js';
import { parseOtpauthUri, buildOtpauthUri, extractUris } from '../lib/uri.js';
import { parseMigrationUri, buildMigrationUris } from '../lib/migration.js';
import { importForeignJson } from '../lib/foreign.js';
import { payloadCapacity } from '../lib/qr.js';
import { generate, secondsRemaining, normalizeAlgorithm } from '../lib/otp.js';
import { isValidBase32 } from '../lib/base32.js';
import { assertEnvelope, deriveKeyBytes, kdfFromEnvelope, openVault } from '../lib/vault.js';

const handlers = {
  state: cmdState,
  create: cmdCreate,
  unlock: cmdUnlock,
  lock: cmdLock,
  touch: cmdTouch,
  list: cmdList,
  codes: cmdCodes,
  add: cmdAdd,
  update: cmdUpdate,
  remove: cmdRemove,
  reorder: cmdReorder,
  advanceCounter: cmdAdvanceCounter,
  importText: cmdImportText,
  exportUris: cmdExportUris,
  exportMigration: cmdExportMigration,
  exportEncrypted: cmdExportEncrypted,
  importEncrypted: cmdImportEncrypted,
  changePassphrase: cmdChangePassphrase,
  settings: cmdSettings,
  captureTab: cmdCaptureTab,
  fill: cmdFill,
  biometricEnable: cmdBiometricEnable,
  biometricDisable: cmdBiometricDisable,
  biometricUnlock: cmdBiometricUnlock,
  wipe: cmdWipe,
};

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const handler = handlers[message?.cmd];
  if (!handler) {
    sendResponse({ ok: false, error: `unknown command: ${message?.cmd}` });
    return false;
  }
  Promise.resolve(handler(message))
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => sendResponse({ ok: false, error: err?.message || String(err) }));
  return true; // keep the message channel open for the async reply
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (isAutoLockAlarm(alarm)) await lock();
});

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  if (reason === 'install' && !(await isInitialized())) {
    await chrome.tabs.create({ url: chrome.runtime.getURL('src/options/options.html#setup') });
  }
});

// --- commands ---------------------------------------------------------------

async function cmdState() {
  const biometric = await getBiometric();
  return {
    initialized: await isInitialized(),
    unlocked: await isUnlocked(),
    // Only the public half: the credential to ask for and the PRF salt.
    biometric: biometric
      ? { enabled: true, credentialId: biometric.credentialId, prfSalt: biometric.prfSalt }
      : { enabled: false },
    settings: await loadSettings(),
    version: chrome.runtime.getManifest().version,
  };
}

async function cmdCreate({ passphrase }) {
  assertPassphrase(passphrase);
  await createVault(passphrase);
  return cmdState();
}

async function cmdUnlock({ passphrase }) {
  await unlock(String(passphrase || ''));
  return cmdState();
}

async function cmdLock() {
  await lock();
  return cmdState();
}

async function cmdTouch() {
  if (await isUnlocked()) await scheduleAutoLock();
  return { ok: true };
}

async function cmdList() {
  const { accounts } = await readPayload();
  await scheduleAutoLock();
  // Secrets stay in the background; the UI only needs metadata.
  return accounts.map(redact);
}

/** Codes for every account (or a subset), plus the time left in the window. */
async function cmdCodes({ ids, at }) {
  const { accounts } = await readPayload();
  const now = at || Date.now();
  const wanted = ids ? accounts.filter((a) => ids.includes(a.id)) : accounts;
  return Promise.all(
    wanted.map(async (account) => ({
      id: account.id,
      code: await generate(account, now),
      remaining: account.type === 'hotp' ? null : secondsRemaining(account, now),
      period: account.period || 30,
    })),
  );
}

async function cmdAdd({ account }) {
  const clean = sanitizeAccount(account);
  const payload = await writePayload((current) => {
    if (current.accounts.some((a) => sameAccount(a, clean))) {
      throw new Error('an identical account already exists');
    }
    current.accounts.push({ ...clean, order: current.accounts.length });
    return current;
  });
  return payload.accounts.map(redact);
}

async function cmdUpdate({ id, patch }) {
  const payload = await writePayload((current) => {
    const account = current.accounts.find((a) => a.id === id);
    if (!account) throw new Error('account not found');
    // Only editable metadata; the secret and type are immutable after creation.
    if (patch.name !== undefined) account.name = String(patch.name).trim() || account.name;
    if (patch.issuer !== undefined) account.issuer = String(patch.issuer).trim();
    if (patch.digits !== undefined) account.digits = clamp(patch.digits, 4, 10, account.digits);
    if (patch.period !== undefined) account.period = clamp(patch.period, 1, 300, account.period);
    if (patch.algorithm !== undefined) account.algorithm = normalizeAlgorithm(patch.algorithm);
    if (patch.counter !== undefined && account.type === 'hotp') {
      account.counter = Math.max(0, Number(patch.counter) || 0);
    }
    return current;
  });
  return payload.accounts.map(redact);
}

async function cmdRemove({ id }) {
  const payload = await writePayload((current) => {
    const before = current.accounts.length;
    current.accounts = current.accounts.filter((a) => a.id !== id);
    if (current.accounts.length === before) throw new Error('account not found');
    current.accounts.forEach((a, i) => { a.order = i; });
    return current;
  });
  return payload.accounts.map(redact);
}

async function cmdReorder({ ids }) {
  const payload = await writePayload((current) => {
    const rank = new Map(ids.map((id, i) => [id, i]));
    current.accounts.sort((a, b) => (rank.get(a.id) ?? 1e9) - (rank.get(b.id) ?? 1e9));
    current.accounts.forEach((a, i) => { a.order = i; });
    return current;
  });
  return payload.accounts.map(redact);
}

/** HOTP only: burn the current counter so the next code is fresh. */
async function cmdAdvanceCounter({ id }) {
  let code = null;
  await writePayload(async (current) => {
    const account = current.accounts.find((a) => a.id === id);
    if (!account) throw new Error('account not found');
    if (account.type !== 'hotp') throw new Error('only HOTP accounts have a counter');
    account.counter = (account.counter ?? 0) + 1;
    code = await generate(account);
    return current;
  });
  return { code };
}

/**
 * Import from pasted text, a scanned QR payload, or a file: accepts otpauth://
 * URIs, otpauth-migration:// batches, and our own plain JSON export.
 */
async function cmdImportText({ text }) {
  const candidates = extractUris(text);
  const parsed = [];
  const errors = [];

  if (candidates.length === 0) {
    // No URIs: treat it as a JSON backup, ours or another app's.
    const foreign = importForeignJson(text, (reason) => {
      throw new Error(`no otpauth:// URI here, and it is not a JSON backup either (${reason})`);
    });
    errors.push(...foreign.errors);
    for (const entry of foreign.accounts) {
      try {
        parsed.push(sanitizeAccount(entry));
      } catch (err) {
        errors.push(err.message);
      }
    }
  }

  for (const uri of candidates) {
    try {
      if (/^otpauth-migration:/i.test(uri)) {
        const result = parseMigrationUri(uri);
        errors.push(...result.errors);
        for (const account of result.accounts) parsed.push(sanitizeAccount(account));
      } else {
        parsed.push(sanitizeAccount(parseOtpauthUri(uri)));
      }
    } catch (err) {
      errors.push(err.message);
    }
  }

  let added = 0;
  let skipped = 0;
  const payload = await writePayload((current) => {
    for (const account of parsed) {
      if (current.accounts.some((a) => sameAccount(a, account))) {
        skipped++;
        continue;
      }
      current.accounts.push({ ...account, order: current.accounts.length });
      added++;
    }
    return current;
  });

  return { added, skipped, errors, accounts: payload.accounts.map(redact) };
}

async function cmdExportUris() {
  const { accounts } = await readPayload();
  return accounts.map((account) => ({ id: account.id, uri: buildOtpauthUri(account) }));
}

// Cap each batch at what a version-25 symbol holds: large enough to be useful,
// small enough that the modules stay chunky on a phone camera.
const QR_BATCH_BYTES = payloadCapacity(25, 'M');

async function cmdExportMigration({ perBatch } = {}) {
  const { accounts } = await readPayload();
  if (accounts.length === 0) throw new Error('there are no accounts to export');
  return buildMigrationUris(accounts, {
    perBatch: perBatch || 10,
    maxUriBytes: QR_BATCH_BYTES,
  });
}

async function cmdExportEncrypted() {
  const envelope = await getEnvelope();
  if (!envelope) throw new Error('NOT_INITIALIZED');
  if (!(await isUnlocked())) throw new Error('LOCKED');
  return envelope;
}

async function cmdImportEncrypted({ envelope, passphrase, mode }) {
  assertEnvelope(envelope);
  if (mode === 'merge') {
    if (!(await isUnlocked())) throw new Error('LOCKED');
    // Statically imported: dynamic import() is not allowed in a service worker.
    const kdf = kdfFromEnvelope(envelope);
    const keyBytes = await deriveKeyBytes(passphrase, kdf.salt, kdf.iterations);
    const incoming = await openVault(envelope, keyBytes);
    let added = 0;
    let skipped = 0;
    const payload = await writePayload((current) => {
      for (const raw of incoming.accounts || []) {
        const account = sanitizeAccount(raw);
        if (current.accounts.some((a) => sameAccount(a, account))) {
          skipped++;
          continue;
        }
        current.accounts.push({ ...account, order: current.accounts.length });
        added++;
      }
      return current;
    });
    return { added, skipped, accounts: payload.accounts.map(redact) };
  }

  const payload = await restoreFromEnvelope(envelope, passphrase);
  return { added: (payload.accounts || []).length, skipped: 0, accounts: (payload.accounts || []).map(redact) };
}

async function cmdChangePassphrase({ current, next }) {
  assertPassphrase(next);
  await changePassphrase(String(current || ''), next);
  return { ok: true };
}

async function cmdSettings({ patch }) {
  const settings = patch ? await saveSettings(patch) : await loadSettings();
  if (patch && 'autoLockMinutes' in patch && (await isUnlocked())) await scheduleAutoLock();
  return settings;
}

/**
 * Screenshot the active tab so the popup can look for a QR code in it.
 * Requires <all_urls>-free `activeTab`, granted by the user's click on our action.
 */
async function cmdCaptureTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab) throw new Error('no active tab to capture');
  const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
  return { dataUrl, title: tab.title || '' };
}

/**
 * Type the account's current code into the active tab. Probes every frame first
 * without sending the code, then fills only the best-matching one. When the
 * account's issuer does not look like the site, stops and asks the popup to
 * confirm (`force`) — the cheapest anti-phishing check there is.
 */
async function cmdFill({ id, force }) {
  const { accounts } = await readPayload();
  const account = accounts.find((a) => a.id === id);
  if (!account) throw new Error('account not found');

  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.id) return { status: 'unavailable' };
  let host = '';
  try {
    host = new URL(tab.url || '').hostname;
  } catch {
    // no URL visible to us: the page is not one we were granted
  }
  if (!host) return { status: 'unavailable' };

  const length = account.type === 'steam' ? 5 : account.digits || 6;
  let probes;
  try {
    probes = await runInTab(tab.id, { allFrames: true }, [null, 'probe', length]);
  } catch {
    return { status: 'unavailable', host }; // chrome://, the Web Store, PDFs…
  }
  const best = probes
    .filter((p) => (p.result?.score ?? 0) >= FILL_THRESHOLD)
    .sort((a, b) => b.result.score - a.result.score)[0];
  if (!best) return { status: 'no-field', host };

  if (!force && issuerMatchesHost(account.issuer, host) === false) {
    return { status: 'mismatch', host, issuer: account.issuer };
  }

  const code = await generate(account, Date.now());
  const [filled] = await runInTab(tab.id, { frameIds: [best.frameId] }, [code, 'fill', length]);
  await scheduleAutoLock();
  return filled?.result?.filled ? { status: 'filled', host } : { status: 'no-field', host };
}

async function runInTab(tabId, frames, args) {
  return chrome.scripting.executeScript({
    target: { tabId, ...frames },
    func: otpFieldScript,
    args,
  });
}

async function cmdBiometricEnable({ credentialId, prfSalt, prfOutput }) {
  await enableBiometric({ credentialId, prfSalt, prfOutput });
  return cmdState();
}

async function cmdBiometricDisable() {
  await disableBiometric();
  return cmdState();
}

async function cmdBiometricUnlock({ prfOutput }) {
  await unlockWithBiometric(prfOutput);
  return cmdState();
}

async function cmdWipe({ confirm }) {
  if (confirm !== 'DELETE') throw new Error('wipe not confirmed');
  await wipeEverything();
  return { ok: true };
}

// --- helpers ----------------------------------------------------------------

function assertPassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 8) {
    throw new Error('passphrase must be at least 8 characters');
  }
}

function clamp(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function sanitizeAccount(input) {
  if (!input || typeof input !== 'object') throw new Error('account payload is not an object');
  if (input.uri) return sanitizeAccount(parseOtpauthUri(input.uri));

  const secret = String(input.secret || '').replace(/\s/g, '').toUpperCase().replace(/=+$/, '');
  const encoding = input.encoding === 'hex' ? 'hex' : 'base32';
  if (encoding === 'base32' && !isValidBase32(secret)) throw new Error('secret is not valid base32');

  const type = ['totp', 'hotp', 'steam'].includes(input.type) ? input.type : 'totp';
  const account = {
    id: input.id || crypto.randomUUID(),
    type,
    name: String(input.name || '').trim() || String(input.issuer || '').trim() || 'Unnamed',
    issuer: String(input.issuer || '').trim(),
    secret,
    encoding,
    algorithm: normalizeAlgorithm(input.algorithm),
    digits: type === 'steam' ? 5 : clamp(input.digits, 4, 10, 6),
    period: clamp(input.period, 1, 300, 30),
    createdAt: input.createdAt || new Date().toISOString(),
  };
  if (type === 'hotp') account.counter = Math.max(0, Number(input.counter) || 0);
  return account;
}

function sameAccount(a, b) {
  return (
    a.secret === b.secret &&
    a.type === b.type &&
    a.issuer.toLowerCase() === b.issuer.toLowerCase() &&
    a.name.toLowerCase() === b.name.toLowerCase()
  );
}

/** Strip the secret before anything leaves the service worker. */
function redact(account) {
  const { secret, ...rest } = account;
  return { ...rest, secretLength: secret.length };
}
