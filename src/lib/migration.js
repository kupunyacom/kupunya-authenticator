// Google Authenticator's export format: otpauth-migration://offline?data=<base64 protobuf>.
// Rather than pull in a protobuf runtime we decode the handful of fields by hand.
//
// MigrationPayload { repeated OtpParameters otp_parameters = 1; int32 version = 2;
//                    int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5 }
// OtpParameters    { bytes secret = 1; string name = 2; string issuer = 3;
//                    Algorithm algorithm = 4; DigitCount digits = 5;
//                    OtpType type = 6; int64 counter = 7 }

import { base32Encode, base32Decode } from './base32.js';
import { base64ToBytes, bytesToBase64, bytesToUtf8, utf8ToBytes } from './bytes.js';

const ALGORITHMS = { 0: 'SHA1', 1: 'SHA1', 2: 'SHA256', 3: 'SHA512', 4: 'MD5' };
const ALGORITHM_IDS = { SHA1: 1, SHA256: 2, SHA512: 3 };
const DIGIT_COUNTS = { 0: 6, 1: 6, 2: 8 };
const OTP_TYPES = { 0: 'totp', 1: 'hotp', 2: 'totp' };

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  get done() {
    return this.pos >= this.bytes.length;
  }

  varint() {
    let result = 0n;
    let shift = 0n;
    while (true) {
      if (this.done) throw new Error('truncated varint');
      const byte = this.bytes[this.pos++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7n;
      if (shift > 70n) throw new Error('varint too long');
    }
    return result;
  }

  bytesField() {
    const length = Number(this.varint());
    if (this.pos + length > this.bytes.length) throw new Error('truncated length-delimited field');
    const slice = this.bytes.subarray(this.pos, this.pos + length);
    this.pos += length;
    return slice;
  }

  skip(wireType) {
    if (wireType === 0) this.varint();
    else if (wireType === 1) this.pos += 8;
    else if (wireType === 2) this.bytesField();
    else if (wireType === 5) this.pos += 4;
    else throw new Error(`unsupported wire type: ${wireType}`);
  }
}

function decodeOtpParameters(bytes) {
  const reader = new Reader(bytes);
  const account = { encoding: 'base32', algorithm: 'SHA1', digits: 6, period: 30, type: 'totp' };
  let secret = null;
  let name = '';
  let issuer = '';
  let counter = 0;

  while (!reader.done) {
    const tag = Number(reader.varint());
    const field = tag >>> 3;
    const wireType = tag & 7;
    switch (field) {
      case 1:
        secret = reader.bytesField();
        break;
      case 2:
        name = bytesToUtf8(reader.bytesField());
        break;
      case 3:
        issuer = bytesToUtf8(reader.bytesField());
        break;
      case 4:
        account.algorithm = ALGORITHMS[Number(reader.varint())] || 'SHA1';
        break;
      case 5:
        account.digits = DIGIT_COUNTS[Number(reader.varint())] || 6;
        break;
      case 6:
        account.type = OTP_TYPES[Number(reader.varint())] || 'totp';
        break;
      case 7:
        counter = Number(reader.varint());
        break;
      default:
        reader.skip(wireType);
    }
  }

  if (!secret || secret.length === 0) throw new Error('entry has no secret');
  if (account.algorithm === 'MD5') throw new Error('MD5 accounts are not supported');

  // Google writes the label as "Issuer:account" even when the issuer field is
  // also set, so strip a matching prefix; otherwise split to recover the issuer.
  let label = name;
  const colon = label.indexOf(':');
  if (colon !== -1) {
    const prefix = label.slice(0, colon).trim();
    if (issuer && prefix.toLowerCase() === issuer.trim().toLowerCase()) {
      label = label.slice(colon + 1).trim();
    } else if (!issuer) {
      issuer = prefix;
      label = label.slice(colon + 1).trim();
    }
  }

  account.secret = base32Encode(secret);
  account.name = label.trim() || issuer || 'Unnamed';
  account.issuer = issuer.trim();
  if (account.issuer.toLowerCase() === 'steam') {
    account.type = 'steam';
    account.digits = 5;
  }
  if (account.type === 'hotp') account.counter = counter;
  return account;
}

/** Decode an otpauth-migration:// URI into accounts. Returns { accounts, errors, batch }. */
export function parseMigrationUri(uri) {
  const trimmed = String(uri).trim();
  if (!/^otpauth-migration:\/\//i.test(trimmed)) throw new Error('not an otpauth-migration:// URI');
  const data = new URL(trimmed).searchParams.get('data');
  if (!data) throw new Error('migration URI has no data parameter');

  const reader = new Reader(base64ToBytes(data));
  const accounts = [];
  const errors = [];
  const batch = { index: 0, size: 1, id: 0, version: 0 };

  while (!reader.done) {
    const tag = Number(reader.varint());
    const field = tag >>> 3;
    const wireType = tag & 7;
    if (field === 1 && wireType === 2) {
      const chunk = reader.bytesField();
      try {
        accounts.push(decodeOtpParameters(chunk));
      } catch (err) {
        errors.push(err.message);
      }
    } else if (field === 2) batch.version = Number(reader.varint());
    else if (field === 3) batch.size = Number(reader.varint());
    else if (field === 4) batch.index = Number(reader.varint());
    else if (field === 5) batch.id = Number(reader.varint());
    else reader.skip(wireType);
  }

  return { accounts, errors, batch };
}

function varintBytes(value) {
  let remaining = BigInt(value);
  const out = [];
  do {
    let byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    if (remaining > 0n) byte |= 0x80;
    out.push(byte);
  } while (remaining > 0n);
  return out;
}

function lengthDelimited(field, payload) {
  return [...varintBytes((field << 3) | 2), ...varintBytes(payload.length), ...payload];
}

function varintField(field, value) {
  return [...varintBytes(field << 3), ...varintBytes(value)];
}

function encodeOtpParameters(account) {
  const bytes = [
    ...lengthDelimited(1, base32Decode(account.secret)),
    ...lengthDelimited(2, utf8ToBytes(account.name || '')),
  ];
  if (account.issuer) bytes.push(...lengthDelimited(3, utf8ToBytes(account.issuer)));
  bytes.push(...varintField(4, ALGORITHM_IDS[account.algorithm] ?? 1));
  bytes.push(...varintField(5, account.digits === 8 ? 2 : 1));
  bytes.push(...varintField(6, account.type === 'hotp' ? 1 : 2));
  if (account.type === 'hotp') bytes.push(...varintField(7, account.counter ?? 0));
  return bytes;
}

function encodeBatch(batch, { index, total, batchId }) {
  const bytes = [];
  for (const account of batch) bytes.push(...lengthDelimited(1, encodeOtpParameters(account)));
  bytes.push(...varintField(2, 1));
  bytes.push(...varintField(3, total));
  bytes.push(...varintField(4, index));
  bytes.push(...varintField(5, batchId));
  const data = bytesToBase64(new Uint8Array(bytes));
  return `otpauth-migration://offline?data=${encodeURIComponent(data)}`;
}

/**
 * Group accounts into batches that respect both a count limit and, when the
 * result has to fit in a QR code, a byte budget. Long account labels can make a
 * single entry much larger than average, so the byte check measures the real
 * encoded URI rather than assuming an average size.
 */
function partition(accounts, perBatch, maxUriBytes) {
  const batches = [];
  let current = [];
  const fits = (candidate) =>
    maxUriBytes === Infinity ||
    encodeBatch(candidate, { index: 0, total: 1, batchId: 2 ** 31 - 1 }).length <= maxUriBytes;

  for (const account of accounts) {
    const candidate = [...current, account];
    if (current.length > 0 && (candidate.length > perBatch || !fits(candidate))) {
      batches.push(current);
      current = [account];
    } else {
      current = candidate;
    }
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

/**
 * Build otpauth-migration:// URIs from accounts, so the vault stays portable
 * back into Google Authenticator. `maxUriBytes` keeps each batch inside the
 * capacity of the QR code it will be rendered into.
 */
export function buildMigrationUris(accounts, { perBatch = 10, maxUriBytes = Infinity } = {}) {
  if (accounts.length === 0) return [];
  const batches = partition(accounts, perBatch, maxUriBytes);
  const batchId = Math.floor(Math.random() * 2 ** 31);
  return batches.map((batch, index) =>
    encodeBatch(batch, { index, total: batches.length, batchId }),
  );
}
