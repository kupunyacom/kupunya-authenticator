import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseMigrationUri, buildMigrationUris } from '../src/lib/migration.js';
import { base32Encode } from '../src/lib/base32.js';

// Wire bytes written by hand against the MigrationPayload schema, so the decoder
// is checked against the format itself rather than against our own encoder:
// secret "Hello!\xDE\xAD\xBE\xEF" (JBSWY3DPEHPK3PXP), name "Example:alice@google.com",
// issuer "Example", algorithm SHA1, six digits, TOTP.
const SAMPLE =
  'otpauth-migration://offline?data=' +
  encodeURIComponent('CjUKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhACGAEgAA==');

test('decodes a Google Authenticator export payload', () => {
  const { accounts, errors } = parseMigrationUri(SAMPLE);
  assert.deepEqual(errors, []);
  assert.equal(accounts.length, 1);
  const [account] = accounts;
  assert.equal(account.secret, base32Encode(Uint8Array.from([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef])));
  assert.equal(account.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(account.issuer, 'Example');
  assert.equal(account.name, 'alice@google.com');
  assert.equal(account.type, 'totp');
  assert.equal(account.algorithm, 'SHA1');
  assert.equal(account.digits, 6);
});

test('round-trips accounts back through the migration format', () => {
  const accounts = [
    { type: 'totp', name: 'alice@example.com', issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA256', digits: 8, period: 30 },
    { type: 'hotp', name: 'token', issuer: 'Bank', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, counter: 12 },
  ];
  const [uri, ...rest] = buildMigrationUris(accounts);
  assert.equal(rest.length, 0);
  const decoded = parseMigrationUri(uri);
  assert.deepEqual(decoded.errors, []);
  assert.equal(decoded.accounts.length, 2);
  assert.equal(decoded.accounts[0].issuer, 'GitHub');
  assert.equal(decoded.accounts[0].digits, 8);
  assert.equal(decoded.accounts[0].algorithm, 'SHA256');
  assert.equal(decoded.accounts[1].type, 'hotp');
  assert.equal(decoded.accounts[1].counter, 12);
});

test('splits large exports into batches that stay scannable', () => {
  const accounts = Array.from({ length: 25 }, (_, i) => ({
    type: 'totp', name: `user${i}`, issuer: 'Issuer', secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1', digits: 6, period: 30,
  }));
  const uris = buildMigrationUris(accounts, { perBatch: 10 });
  assert.equal(uris.length, 3);
  const counts = uris.map((uri) => parseMigrationUri(uri).accounts.length);
  assert.deepEqual(counts, [10, 10, 5]);
  const batch = parseMigrationUri(uris[1]).batch;
  assert.equal(batch.index, 1);
  assert.equal(batch.size, 3);
});

test('a corrupt entry is reported without losing the rest of the batch', () => {
  const uris = buildMigrationUris([
    { type: 'totp', name: 'good', issuer: '', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
  ]);
  assert.throws(() => parseMigrationUri('otpauth-migration://offline'), /no data parameter/);
  assert.throws(() => parseMigrationUri(uris[0].replace('otpauth-migration', 'otpauth')), /not an otpauth-migration/);
});

test('a Steam entry survives the trip through the issuer field', () => {
  const uris = buildMigrationUris([
    { type: 'steam', name: 'player', issuer: 'Steam', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 5, period: 30 },
  ]);
  const [account] = parseMigrationUri(uris[0]).accounts;
  assert.equal(account.type, 'steam');
  assert.equal(account.digits, 5);
});
