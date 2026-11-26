import { test } from 'node:test';
import assert from 'node:assert/strict';

import { importForeignJson } from '../src/lib/foreign.js';

const SECRET = 'JBSWY3DPEHPK3PXP';

test('reads an Authenticator Extension style array export', () => {
  const backup = JSON.stringify([
    { secret: SECRET, account: 'alice@example.com', issuer: 'GitHub', type: 'totp', counter: 0, period: 30, digits: 6, algorithm: 'SHA1', hash: 'abc', index: 0 },
    { secret: SECRET, account: 'token', issuer: 'Bank', type: 'hotp', counter: 9, period: 30, digits: 8, algorithm: 'SHA256', hash: 'def', index: 1 },
  ]);
  const { accounts, errors } = importForeignJson(backup);
  assert.deepEqual(errors, []);
  assert.equal(accounts.length, 2);
  assert.deepEqual(
    { ...accounts[0] },
    { type: 'totp', name: 'alice@example.com', issuer: 'GitHub', secret: SECRET, encoding: 'base32', algorithm: 'SHA1', digits: 6, period: 30 },
  );
  assert.equal(accounts[1].type, 'hotp');
  assert.equal(accounts[1].counter, 9);
  assert.equal(accounts[1].digits, 8);
  assert.equal(accounts[1].algorithm, 'SHA256');
});

test('reads the older shape that keys entries by id', () => {
  const backup = JSON.stringify({
    '9fceb1f2': { secret: SECRET, account: 'alice', issuer: 'GitHub', type: 'totp' },
    'a0b1c2d3': { secret: SECRET, account: 'bob', issuer: 'GitLab', type: 'totp' },
  });
  const { accounts } = importForeignJson(backup);
  assert.deepEqual(accounts.map((a) => a.issuer).sort(), ['GitHub', 'GitLab']);
});

test('reads a 2FAS style wrapper with nested otp fields', () => {
  const backup = JSON.stringify({
    services: [
      { name: 'GitHub', secret: SECRET, otp: { account: 'alice@example.com', digits: 6, period: 30, algorithm: 'SHA1', tokenType: 'TOTP' } },
    ],
    schemaVersion: 4,
  });
  const { accounts } = importForeignJson(backup);
  assert.equal(accounts.length, 1);
  assert.equal(accounts[0].name, 'alice@example.com');
  assert.equal(accounts[0].issuer, 'GitHub');
});

test('reads an Aegis style plain export', () => {
  const backup = JSON.stringify({
    version: 1,
    db: {
      version: 3,
      entries: [
        { type: 'totp', name: 'alice@example.com', issuer: 'GitHub', info: { secret: SECRET, algo: 'SHA1', digits: 6, period: 30 } },
      ],
    },
  });
  const { accounts } = importForeignJson(backup);
  assert.equal(accounts[0].issuer, 'GitHub');
  assert.equal(accounts[0].secret, SECRET);
});

test('accepts entries that carry an otpauth URI instead of loose fields', () => {
  const backup = JSON.stringify([
    { uri: `otpauth://totp/GitHub:alice@example.com?secret=${SECRET}&issuer=GitHub&digits=8` },
    `otpauth://hotp/Bank?secret=${SECRET}&counter=3`,
  ]);
  const { accounts } = importForeignJson(backup);
  assert.equal(accounts[0].digits, 8);
  assert.equal(accounts[1].counter, 3);
});

test('splits an "Issuer:account" label when no issuer field exists', () => {
  const { accounts } = importForeignJson(JSON.stringify([{ secret: SECRET, name: 'GitHub:alice@example.com' }]));
  assert.equal(accounts[0].issuer, 'GitHub');
  assert.equal(accounts[0].name, 'alice@example.com');
});

test('Steam entries keep their five-digit shape', () => {
  const { accounts } = importForeignJson(JSON.stringify([{ secret: SECRET, account: 'player', issuer: 'Steam', type: 'steam' }]));
  assert.equal(accounts[0].type, 'steam');
  assert.equal(accounts[0].digits, 5);
});

test('bad entries are reported while the good ones still import', () => {
  const { accounts, errors } = importForeignJson(JSON.stringify([
    { secret: SECRET, account: 'good' },
    { account: 'no secret here' },
    { secret: '!!!not base32!!!', account: 'bad secret' },
  ]));
  assert.equal(accounts.length, 1);
  assert.equal(accounts[0].name, 'good');
  assert.equal(errors.length, 2);
  assert.match(errors[0], /no secret field/);
  assert.match(errors[1], /not base32/);
});

test('an encrypted foreign backup says so instead of failing obscurely', () => {
  const backup = JSON.stringify({ cipher: 'aes-256-gcm', salt: 'abc123', ciphertext: 'ZGVhZGJlZWY=', kdf: 'pbkdf2' });
  assert.throws(() => importForeignJson(backup), /backup is encrypted/);
});

test('unusable input fails with a readable message', () => {
  assert.throws(() => importForeignJson('not json at all'), /not valid JSON/);
  assert.throws(() => importForeignJson('[]'), /no accounts found/);
  assert.throws(() => importForeignJson('{"unrelated":123}'), /could not find a list of accounts/);
});
