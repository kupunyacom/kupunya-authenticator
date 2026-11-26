// Importers for the JSON backups other authenticator apps write.
//
// Every app invented its own field names, so rather than hard-code one schema we
// recognise the handful of shapes in the wild and map them onto ours. Anything
// that does not yield a usable secret is reported, never silently dropped.

import { isValidBase32 } from './base32.js';
import { parseOtpauthUri } from './uri.js';

const SECRET_KEYS = ['secret', 'secretKey', 'key', 'seed'];
const NAME_KEYS = ['account', 'name', 'label', 'username', 'email', 'accountName'];
const ISSUER_KEYS = ['issuer', 'service', 'provider', 'title'];

function pick(entry, keys) {
  for (const key of keys) {
    const value = entry[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function normalizeType(raw, entry) {
  const type = String(raw || entry.otpType || 'totp').toLowerCase();
  if (type.includes('steam')) return 'steam';
  if (type.includes('hotp')) return 'hotp';
  return 'totp';
}

function normalizeAlgorithm(raw) {
  const algorithm = String(raw || 'SHA1').toUpperCase().replace(/[-_\s]/g, '');
  return ['SHA1', 'SHA256', 'SHA512'].includes(algorithm) ? algorithm : 'SHA1';
}

function toNumber(value, fallback) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

/** Map one foreign entry onto our account shape, or throw with the reason. */
function convert(entry, index) {
  if (typeof entry === 'string') return parseOtpauthUri(entry);
  if (!entry || typeof entry !== 'object') throw new Error(`entry ${index + 1}: not an object`);

  // Aegis and 2FAS nest the interesting parts one level down.
  const info = entry.info && typeof entry.info === 'object' ? entry.info : {};
  const otp = entry.otp && typeof entry.otp === 'object' ? entry.otp : {};
  const flat = { ...otp, ...info, ...entry };

  if (typeof flat.uri === 'string' && flat.uri.startsWith('otpauth://')) {
    return parseOtpauthUri(flat.uri);
  }
  if (typeof flat.url === 'string' && flat.url.startsWith('otpauth://')) {
    return parseOtpauthUri(flat.url);
  }

  const secret = pick(flat, SECRET_KEYS).replace(/\s/g, '').toUpperCase().replace(/=+$/, '');
  if (!secret) throw new Error(`entry ${index + 1}: no secret field found`);
  if (!isValidBase32(secret)) {
    throw new Error(`entry ${index + 1}: secret is not base32 (encrypted backup?)`);
  }

  // 2FAS-style files name the *service* at the top level and keep the account
  // in a nested otp object, so a top-level name there means the issuer.
  const nestedAccount = pick({ ...otp, ...info }, NAME_KEYS);
  const topLevelName = typeof entry.name === 'string' ? entry.name.trim() : '';
  const impliedIssuer = nestedAccount && topLevelName && topLevelName !== nestedAccount ? topLevelName : '';

  const type = normalizeType(flat.type ?? otp.tokenType, flat);
  const account = {
    type,
    name: nestedAccount || pick(flat, NAME_KEYS) || pick(flat, ISSUER_KEYS) || `Imported ${index + 1}`,
    issuer: pick(flat, ISSUER_KEYS) || impliedIssuer,
    secret,
    encoding: 'base32',
    algorithm: normalizeAlgorithm(flat.algorithm ?? flat.algo),
    digits: type === 'steam' ? 5 : toNumber(flat.digits, 6),
    period: toNumber(flat.period, 30),
  };
  // Some apps put "Issuer:account" in the label and leave issuer empty.
  if (!account.issuer && account.name.includes(':')) {
    const idx = account.name.indexOf(':');
    account.issuer = account.name.slice(0, idx).trim();
    account.name = account.name.slice(idx + 1).trim();
  }
  if (account.issuer.toLowerCase() === 'steam') {
    account.type = 'steam';
    account.digits = 5;
  }
  if (account.type === 'hotp') account.counter = Math.max(0, toNumber(flat.counter, 0));
  return account;
}

/**
 * Find the list of entries inside a foreign backup. Apps variously use a bare
 * array, a wrapper object, or an object keyed by id.
 */
function findEntries(json) {
  if (Array.isArray(json)) return json;
  if (!json || typeof json !== 'object') return null;

  for (const key of ['accounts', 'entries', 'services', 'tokens', 'data', 'items', 'db']) {
    const value = json[key];
    if (Array.isArray(value)) return value;
    // Aegis wraps its list one level deeper, in { db: { entries: [...] } }.
    if (value && typeof value === 'object' && Array.isArray(value.entries)) return value.entries;
  }

  // An object keyed by account id, where every value looks like an entry.
  const values = Object.values(json);
  if (values.length > 0 && values.every((v) => v && typeof v === 'object' && !Array.isArray(v))) {
    return values;
  }
  return null;
}

/**
 * Convert a foreign JSON backup into accounts.
 * Returns { accounts, errors } — partial success is normal and useful.
 */
export function importForeignJson(text, onUnparseable) {
  let json;
  try {
    json = typeof text === 'string' ? JSON.parse(text) : text;
  } catch {
    // The caller usually has more context about what the user pasted.
    if (onUnparseable) onUnparseable('not valid JSON');
    throw new Error('not valid JSON');
  }

  if (json && typeof json === 'object' && !Array.isArray(json)) {
    const encrypted = ['cipher', 'encrypted', 'ciphertext', 'kdf', 'salt'].filter((k) => k in json);
    if (encrypted.length >= 2 && !findEntries(json)) {
      throw new Error(
        'this backup is encrypted by the app that wrote it — export an unencrypted ' +
          'backup, or its otpauth:// URIs, and import that instead',
      );
    }
  }

  const entries = findEntries(json);
  if (!entries) throw new Error('could not find a list of accounts in this file');

  const accounts = [];
  const errors = [];
  entries.forEach((entry, index) => {
    try {
      accounts.push(convert(entry, index));
    } catch (err) {
      errors.push(err.message);
    }
  });

  if (accounts.length === 0) {
    throw new Error(errors[0] || 'no accounts found in this file');
  }
  return { accounts, errors };
}
