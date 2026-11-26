// Parse and build otpauth:// URIs (the de-facto Key Uri Format).

import { isValidBase32, base32Encode } from './base32.js';
import { normalizeAlgorithm, DEFAULTS } from './otp.js';

const SUPPORTED_TYPES = new Set(['totp', 'hotp', 'steam']);

function splitLabel(rawLabel) {
  // "Issuer:account" or "Issuer: account"; the colon is optional.
  const label = decodeURIComponent(rawLabel.replace(/^\//, ''));
  const idx = label.indexOf(':');
  if (idx === -1) return { issuer: '', name: label.trim() };
  return { issuer: label.slice(0, idx).trim(), name: label.slice(idx + 1).trim() };
}

/** Parse one otpauth:// URI into an account object. Throws on anything unusable. */
export function parseOtpauthUri(uri) {
  const trimmed = String(uri).trim();
  if (!/^otpauth:\/\//i.test(trimmed)) throw new Error('not an otpauth:// URI');

  const url = new URL(trimmed);
  const type = url.host.toLowerCase();
  if (!SUPPORTED_TYPES.has(type)) throw new Error(`unsupported OTP type: ${type}`);

  const params = url.searchParams;
  const secret = (params.get('secret') || '').replace(/\s/g, '');
  if (!secret) throw new Error('URI has no secret');
  if (!isValidBase32(secret)) throw new Error('secret is not valid base32');

  const { issuer: labelIssuer, name } = splitLabel(url.pathname);
  const issuer = (params.get('issuer') || labelIssuer || '').trim();

  const account = {
    type: type === 'steam' || issuer.toLowerCase() === 'steam' ? 'steam' : type,
    name: name || issuer || 'Unnamed',
    issuer,
    secret: secret.toUpperCase().replace(/=+$/, ''),
    encoding: 'base32',
    algorithm: normalizeAlgorithm(params.get('algorithm') || DEFAULTS.algorithm),
    digits: clampDigits(params.get('digits')),
    period: clampPeriod(params.get('period')),
  };
  if (account.type === 'steam') account.digits = 5;
  if (account.type === 'hotp') {
    account.counter = Number.parseInt(params.get('counter') ?? '0', 10) || 0;
  }
  return account;
}

function clampDigits(raw) {
  const digits = Number.parseInt(raw ?? '', 10);
  if (!Number.isFinite(digits)) return DEFAULTS.digits;
  return Math.min(10, Math.max(4, digits));
}

function clampPeriod(raw) {
  const period = Number.parseInt(raw ?? '', 10);
  if (!Number.isFinite(period) || period <= 0) return DEFAULTS.period;
  return Math.min(300, period);
}

/** Inverse of parseOtpauthUri; used for exports and QR regeneration. */
export function buildOtpauthUri(account) {
  const type = account.type === 'steam' ? 'totp' : account.type || 'totp';
  const label = account.issuer
    ? `${account.issuer}:${account.name}`
    : account.name || 'Unnamed';
  const params = new URLSearchParams();
  params.set('secret', account.secret);
  if (account.issuer) params.set('issuer', account.issuer);
  if (account.algorithm && account.algorithm !== DEFAULTS.algorithm) {
    params.set('algorithm', account.algorithm);
  }
  if (account.type === 'steam') {
    params.set('digits', '5');
  } else if (account.digits && account.digits !== DEFAULTS.digits) {
    params.set('digits', String(account.digits));
  }
  if (type === 'hotp') {
    params.set('counter', String(account.counter ?? 0));
  } else if (account.period && account.period !== DEFAULTS.period) {
    params.set('period', String(account.period));
  }
  return `otpauth://${type}/${encodeURIComponent(label)}?${params.toString()}`;
}

/** Pull every otpauth URI out of a blob of text (a pasted backup, a page body). */
export function extractUris(text) {
  const matches = String(text).match(/otpauth(?:-migration)?:\/\/[^\s"'<>]+/gi);
  return matches ? Array.from(new Set(matches)) : [];
}

export { base32Encode };
