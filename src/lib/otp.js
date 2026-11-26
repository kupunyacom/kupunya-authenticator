// HOTP (RFC 4226) and TOTP (RFC 6238) on top of WebCrypto HMAC.
// Also handles Steam's 5-character alphabet, which is a TOTP variant.

import { base32Decode } from './base32.js';
import { hexToBytes } from './bytes.js';

const HASH_NAMES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';

export const DEFAULTS = { algorithm: 'SHA1', digits: 6, period: 30 };

export function normalizeAlgorithm(algorithm) {
  const key = String(algorithm || DEFAULTS.algorithm).toUpperCase().replace(/[-_]/g, '');
  if (!HASH_NAMES[key]) throw new Error(`unsupported algorithm: ${algorithm}`);
  return key;
}

export function decodeSecret(secret, encoding = 'base32') {
  if (secret instanceof Uint8Array) return secret;
  return encoding === 'hex' ? hexToBytes(secret) : base32Decode(secret);
}

async function hmac(keyBytes, messageBytes, algorithm) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: HASH_NAMES[normalizeAlgorithm(algorithm)] },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, messageBytes);
  return new Uint8Array(sig);
}

function counterToBytes(counter) {
  // 8-byte big-endian counter. BigInt keeps us correct past 2^53.
  const buf = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return buf;
}

function dynamicTruncate(digest) {
  const offset = digest[digest.length - 1] & 0x0f;
  return (
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3]
  );
}

function toSteamCode(binary) {
  let value = binary;
  let code = '';
  for (let i = 0; i < 5; i++) {
    code += STEAM_ALPHABET[value % STEAM_ALPHABET.length];
    value = Math.floor(value / STEAM_ALPHABET.length);
  }
  return code;
}

/** Raw HOTP over an already-decoded secret. */
export async function hotp(secretBytes, counter, { algorithm = DEFAULTS.algorithm, digits = DEFAULTS.digits, steam = false } = {}) {
  const digest = await hmac(secretBytes, counterToBytes(counter), algorithm);
  const binary = dynamicTruncate(digest);
  if (steam) return toSteamCode(binary);
  if (digits < 1 || digits > 10) throw new Error('digits must be between 1 and 10');
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/**
 * Generate a code for a stored account.
 * `at` is epoch milliseconds so callers can preview past/future windows.
 */
export async function generate(account, at = Date.now()) {
  const secretBytes = decodeSecret(account.secret, account.encoding);
  const steam = account.type === 'steam';
  const opts = {
    algorithm: account.algorithm || DEFAULTS.algorithm,
    digits: steam ? 5 : account.digits || DEFAULTS.digits,
    steam,
  };
  if (account.type === 'hotp') {
    return hotp(secretBytes, account.counter ?? 0, opts);
  }
  const period = account.period || DEFAULTS.period;
  return hotp(secretBytes, Math.floor(at / 1000 / period), opts);
}

/** Seconds left in the current time step, for the countdown ring. */
export function secondsRemaining(account, at = Date.now()) {
  const period = account.period || DEFAULTS.period;
  return period - (Math.floor(at / 1000) % period);
}

/** Generates a fresh random secret, e.g. for seeding a new account by hand. */
export function randomSecretBytes(length = 20) {
  return crypto.getRandomValues(new Uint8Array(length));
}
