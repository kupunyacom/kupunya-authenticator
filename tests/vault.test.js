import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveKeyBytes,
  sealVault,
  openVault,
  randomSalt,
  kdfFromEnvelope,
  assertEnvelope,
  passphraseStrength,
  VAULT_FORMAT,
} from '../src/lib/vault.js';

// A low iteration count keeps the suite fast; production uses 650k.
const KDF = { salt: randomSalt(), iterations: 1000 };
const PAYLOAD = {
  accounts: [
    { id: 'a1', type: 'totp', name: 'alice@example.com', issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' },
  ],
};

async function keyFor(passphrase, kdf = KDF) {
  return deriveKeyBytes(passphrase, kdf.salt, kdf.iterations);
}

test('seal then open returns the original payload', async () => {
  const key = await keyFor('correct horse battery staple');
  const envelope = await sealVault(PAYLOAD, key, KDF);
  assert.equal(envelope.format, VAULT_FORMAT);
  assert.equal(envelope.cipher, 'AES-GCM');
  assert.deepEqual(await openVault(envelope, key), PAYLOAD);
});

test('the envelope leaks no plaintext', async () => {
  const key = await keyFor('correct horse battery staple');
  const serialized = JSON.stringify(await sealVault(PAYLOAD, key, KDF));
  for (const secret of ['JBSWY3DPEHPK3PXP', 'alice@example.com', 'GitHub']) {
    assert.ok(!serialized.includes(secret), `envelope must not contain ${secret}`);
  }
});

test('a wrong passphrase fails the GCM tag rather than returning garbage', async () => {
  const envelope = await sealVault(PAYLOAD, await keyFor('right passphrase'), KDF);
  await assert.rejects(
    openVault(envelope, await keyFor('wrong passphrase')),
    /WRONG_PASSPHRASE/,
  );
});

test('tampering with the ciphertext is detected', async () => {
  const key = await keyFor('right passphrase');
  const envelope = await sealVault(PAYLOAD, key, KDF);
  const flipped = { ...envelope, data: `${envelope.data.slice(0, -2)}${envelope.data.slice(-2) === 'AA' ? 'AB' : 'AA'}` };
  await assert.rejects(openVault(flipped, key), /WRONG_PASSPHRASE/);
});

test('every seal uses a fresh IV', async () => {
  const key = await keyFor('same passphrase');
  const ivs = new Set();
  for (let i = 0; i < 20; i++) ivs.add((await sealVault(PAYLOAD, key, KDF)).iv);
  assert.equal(ivs.size, 20);
});

test('the same passphrase under a different salt yields a different key', async () => {
  const a = await keyFor('same passphrase', { salt: randomSalt(), iterations: 1000 });
  const b = await keyFor('same passphrase', { salt: randomSalt(), iterations: 1000 });
  assert.notDeepEqual(a, b);
  assert.equal(a.length, 32);
});

test('KDF parameters survive the round trip through the envelope', async () => {
  const envelope = await sealVault(PAYLOAD, await keyFor('pass'), KDF);
  const parsed = kdfFromEnvelope(envelope);
  assert.deepEqual(parsed.salt, KDF.salt);
  assert.equal(parsed.iterations, KDF.iterations);
});

test('malformed envelopes are rejected before any crypto runs', () => {
  assert.throws(() => assertEnvelope(null), /missing/);
  assert.throws(() => assertEnvelope({ format: 'something-else' }), /not a Kupunya vault/);
  assert.throws(() => assertEnvelope({ format: VAULT_FORMAT, version: 99 }), /newer version/);
  assert.throws(() => assertEnvelope({ format: VAULT_FORMAT, version: 1, iv: 'x' }), /missing "data"/);
});

test('a vault written before the rename still opens', async () => {
  const key = await keyFor('correct horse battery staple');
  const envelope = { ...(await sealVault(PAYLOAD, key, KDF)), format: 'keyring-vault' };
  assert.doesNotThrow(() => assertEnvelope(envelope));
  assert.deepEqual(await openVault(envelope, key), PAYLOAD);
});

test('passphrase strength is advisory and monotonic', () => {
  assert.equal(passphraseStrength('short').score, 0);
  assert.ok(passphraseStrength('a-longer-passphrase-here').score >= passphraseStrength('abcdefgh').score);
  assert.equal(passphraseStrength('Tr0ub4dor&3xyz!!').label, 'strong');
});
