import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseOtpauthUri, buildOtpauthUri, extractUris } from '../src/lib/uri.js';

test('parses a canonical otpauth URI', () => {
  const account = parseOtpauthUri(
    'otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60',
  );
  assert.deepEqual(account, {
    type: 'totp',
    name: 'alice@example.com',
    issuer: 'GitHub',
    secret: 'JBSWY3DPEHPK3PXP',
    encoding: 'base32',
    algorithm: 'SHA256',
    digits: 8,
    period: 60,
  });
});

test('falls back to the label issuer and to sane defaults', () => {
  const account = parseOtpauthUri('otpauth://totp/ACME%20Co:john.doe%40email.com?secret=JBSWY3DPEHPK3PXP');
  assert.equal(account.issuer, 'ACME Co');
  assert.equal(account.name, 'john.doe@email.com');
  assert.equal(account.algorithm, 'SHA1');
  assert.equal(account.digits, 6);
  assert.equal(account.period, 30);
});

test('HOTP keeps its counter, TOTP does not get one', () => {
  const hotpAccount = parseOtpauthUri('otpauth://hotp/Bank?secret=JBSWY3DPEHPK3PXP&counter=42');
  assert.equal(hotpAccount.type, 'hotp');
  assert.equal(hotpAccount.counter, 42);
  const totpAccount = parseOtpauthUri('otpauth://totp/Bank?secret=JBSWY3DPEHPK3PXP');
  assert.equal(totpAccount.counter, undefined);
});

test('Steam accounts are recognised from either the scheme or the issuer', () => {
  for (const uri of [
    'otpauth://steam/Steam:player?secret=JBSWY3DPEHPK3PXP',
    'otpauth://totp/player?secret=JBSWY3DPEHPK3PXP&issuer=Steam',
  ]) {
    const account = parseOtpauthUri(uri);
    assert.equal(account.type, 'steam', uri);
    assert.equal(account.digits, 5, uri);
  }
});

test('unusable URIs throw instead of producing a broken account', () => {
  assert.throws(() => parseOtpauthUri('https://example.com'), /not an otpauth/);
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?secret='), /no secret/);
  assert.throws(() => parseOtpauthUri('otpauth://totp/x?secret=not-base32!'), /valid base32/);
  assert.throws(() => parseOtpauthUri('otpauth://mtp/x?secret=JBSWY3DPEHPK3PXP'), /unsupported OTP type/);
});

test('out-of-range digits and periods are clamped, not trusted', () => {
  const account = parseOtpauthUri('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99&period=99999');
  assert.equal(account.digits, 10);
  assert.equal(account.period, 300);
});

test('build/parse round-trips every field', () => {
  for (const original of [
    { type: 'totp', name: 'alice@example.com', issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', encoding: 'base32', algorithm: 'SHA512', digits: 8, period: 15 },
    { type: 'hotp', name: 'token', issuer: 'Bank', secret: 'JBSWY3DPEHPK3PXP', encoding: 'base32', algorithm: 'SHA1', digits: 6, period: 30, counter: 7 },
    { type: 'totp', name: 'no-issuer', issuer: '', secret: 'JBSWY3DPEHPK3PXP', encoding: 'base32', algorithm: 'SHA1', digits: 6, period: 30 },
  ]) {
    const reparsed = parseOtpauthUri(buildOtpauthUri(original));
    for (const key of Object.keys(original)) {
      assert.deepEqual(reparsed[key], original[key], `${original.name}.${key}`);
    }
  }
});

test('extractUris finds URIs inside surrounding noise and de-duplicates', () => {
  const text = `
    Scan this: otpauth://totp/A?secret=JBSWY3DPEHPK3PXP
    or this one otpauth://totp/A?secret=JBSWY3DPEHPK3PXP
    and a batch otpauth-migration://offline?data=CjEKCkhlbGxv
  `;
  assert.deepEqual(extractUris(text), [
    'otpauth://totp/A?secret=JBSWY3DPEHPK3PXP',
    'otpauth-migration://offline?data=CjEKCkhlbGxv',
  ]);
});
