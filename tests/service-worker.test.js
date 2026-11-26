import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { installChromeStub } from './helpers/chrome-stub.js';
import { buildMigrationUris } from '../src/lib/migration.js';

const PASSPHRASE = 'a-good-enough-passphrase';
const URI = 'otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
// base32("12345678901234567890"), the seed behind the RFC 4226/6238 test vectors.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

let stub;

before(async () => {
  stub = installChromeStub();
  await import('../src/background/service-worker.js');
});

beforeEach(async () => {
  stub.local.clear();
  stub.session.clear();
  stub.alarms.clear();
});

const send = (...args) => stub.send(...args);

test('a fresh profile reports an uninitialised, locked vault', async () => {
  const state = await send('state');
  assert.equal(state.initialized, false);
  assert.equal(state.unlocked, false);
  assert.equal(state.settings.autoLockMinutes, 5);
});

test('creating a vault unlocks it and arms the auto-lock alarm', async () => {
  const state = await send('create', { passphrase: PASSPHRASE });
  assert.equal(state.initialized, true);
  assert.equal(state.unlocked, true);
  assert.equal(stub.alarms.size, 1);
});

test('a short passphrase is refused', async () => {
  await assert.rejects(send('create', { passphrase: 'short' }), /at least 8 characters/);
});

test('locking clears the session key and the alarm; unlocking restores access', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: URI });

  await send('lock');
  assert.equal(stub.session.size, 0);
  assert.equal(stub.alarms.size, 0);
  await assert.rejects(send('list'), /LOCKED/);

  await assert.rejects(send('unlock', { passphrase: 'not it' }), /WRONG_PASSPHRASE/);
  await send('unlock', { passphrase: PASSPHRASE });
  assert.equal((await send('list')).length, 1);
});

test('the stored vault never contains a secret in the clear', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: URI });
  const serialized = JSON.stringify(Object.fromEntries(stub.local));
  assert.ok(!serialized.includes('JBSWY3DPEHPK3PXP'));
  assert.ok(!serialized.includes('alice@example.com'));
});

test('secrets are stripped from everything the UI receives', async () => {
  await send('create', { passphrase: PASSPHRASE });
  const accounts = await send('importText', { text: URI }).then((r) => r.accounts);
  assert.equal(accounts[0].secret, undefined);
  assert.equal(accounts[0].secretLength, 16);
  assert.equal(accounts[0].issuer, 'GitHub');
});

test('codes are generated for stored accounts', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('add', { account: { name: 'rfc', secret: RFC_SECRET } });
  const [entry] = await send('codes', { at: 1111111111 * 1000 });
  assert.equal(entry.code, '050471'); // RFC 6238 SHA1 vector, truncated to 6 digits
  assert.equal(entry.period, 30);
  assert.ok(entry.remaining > 0 && entry.remaining <= 30);
});

test('importing is idempotent: duplicates are skipped, not stacked', async () => {
  await send('create', { passphrase: PASSPHRASE });
  const first = await send('importText', { text: URI });
  const second = await send('importText', { text: URI });
  assert.deepEqual([first.added, first.skipped], [1, 0]);
  assert.deepEqual([second.added, second.skipped], [0, 1]);
  assert.equal((await send('list')).length, 1);
});

test('a Google Authenticator batch imports in one go', async () => {
  await send('create', { passphrase: PASSPHRASE });
  const uris = buildMigrationUris([
    { type: 'totp', name: 'a@example.com', issuer: 'One', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30 },
    { type: 'totp', name: 'b@example.com', issuer: 'Two', secret: 'KRSXG5CTMVRXEZLU', algorithm: 'SHA1', digits: 6, period: 30 },
  ]);
  const result = await send('importText', { text: uris.join('\n') });
  assert.equal(result.added, 2);
  assert.deepEqual((await send('list')).map((a) => a.issuer).sort(), ['One', 'Two']);
});

test('nonsense input is rejected with a useful message', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await assert.rejects(send('importText', { text: 'just some prose' }), /no otpauth/);
  await assert.rejects(
    send('add', { account: { name: 'x', secret: '!!!!' } }),
    /valid base32/,
  );
});

test('HOTP counters advance and persist', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('add', { account: { type: 'hotp', name: 'token', secret: RFC_SECRET, counter: 0 } });
  const [{ code: first }] = await send('codes', {});
  assert.equal(first, '755224'); // RFC 4226 counter 0

  const { code: second } = await send('advanceCounter', { id: (await send('list'))[0].id });
  assert.equal(second, '287082'); // counter 1
  assert.equal((await send('list'))[0].counter, 1);
});

test('rename and reorder persist; secrets and type stay immutable', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: URI });
  await send('add', { account: { name: 'second', secret: 'KRSXG5CTMVRXEZLU' } });
  const ids = (await send('list')).map((a) => a.id);

  await send('reorder', { ids: [ids[1], ids[0]] });
  assert.deepEqual((await send('list')).sort((a, b) => a.order - b.order).map((a) => a.id), [ids[1], ids[0]]);

  await send('update', { id: ids[0], patch: { name: 'renamed', secret: 'HACKED', type: 'hotp' } });
  const account = (await send('list')).find((a) => a.id === ids[0]);
  assert.equal(account.name, 'renamed');
  assert.equal(account.type, 'totp');
  assert.equal(account.secretLength, 16);
});

test('removing an account renumbers the rest', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: URI });
  await send('add', { account: { name: 'second', secret: 'KRSXG5CTMVRXEZLU' } });
  const ids = (await send('list')).map((a) => a.id);
  await send('remove', { id: ids[0] });
  const left = await send('list');
  assert.equal(left.length, 1);
  assert.equal(left[0].order, 0);
  await assert.rejects(send('remove', { id: ids[0] }), /not found/);
});

test('an encrypted backup restores into a different vault', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: URI });
  const backup = await send('exportEncrypted');

  stub.local.clear();
  stub.session.clear();
  await send('create', { passphrase: 'a-completely-different-one' });
  assert.equal((await send('list')).length, 0);

  const result = await send('importEncrypted', { envelope: backup, passphrase: PASSPHRASE, mode: 'merge' });
  assert.equal(result.added, 1);
  assert.equal((await send('list'))[0].issuer, 'GitHub');
});

test('restoring with the wrong passphrase changes nothing', async () => {
  await send('create', { passphrase: PASSPHRASE });
  const backup = await send('exportEncrypted');
  await assert.rejects(
    send('importEncrypted', { envelope: backup, passphrase: 'nope-not-this', mode: 'replace' }),
    /WRONG_PASSPHRASE/,
  );
  assert.equal((await send('state')).unlocked, true);
});

test('changing the passphrase re-encrypts and invalidates the old one', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: URI });
  await assert.rejects(send('changePassphrase', { current: 'wrong', next: 'new-passphrase-here' }), /WRONG_PASSPHRASE/);

  await send('changePassphrase', { current: PASSPHRASE, next: 'new-passphrase-here' });
  await send('lock');
  await assert.rejects(send('unlock', { passphrase: PASSPHRASE }), /WRONG_PASSPHRASE/);
  await send('unlock', { passphrase: 'new-passphrase-here' });
  assert.equal((await send('list')).length, 1);
});

test('the plaintext export round-trips back through import', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: URI });
  const [{ uri }] = await send('exportUris');

  stub.local.clear();
  stub.session.clear();
  await send('create', { passphrase: PASSPHRASE });
  await send('importText', { text: uri });
  const [restored] = await send('list');
  assert.equal(restored.issuer, 'GitHub');
  assert.equal(restored.name, 'alice@example.com');
});

test('the auto-lock alarm locks the vault when it fires', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await stub.listeners.alarm[0]({ name: 'kupunya-auto-lock' });
  assert.equal((await send('state')).unlocked, false);

  await send('unlock', { passphrase: PASSPHRASE });
  await stub.listeners.alarm[0]({ name: 'some-other-alarm' });
  assert.equal((await send('state')).unlocked, true);
});

test('auto-lock can be disabled and the alarm is not armed', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await send('settings', { patch: { autoLockMinutes: 0 } });
  assert.equal(stub.alarms.size, 0);
  assert.equal((await send('settings', {})).autoLockMinutes, 0);
});

test('wiping requires explicit confirmation', async () => {
  await send('create', { passphrase: PASSPHRASE });
  await assert.rejects(send('wipe', { confirm: 'yes' }), /not confirmed/);
  await send('wipe', { confirm: 'DELETE' });
  assert.equal((await send('state')).initialized, false);
});

test('concurrent writes do not overwrite each other', async () => {
  // Each write is a read-modify-write of the whole encrypted vault, so this
  // would silently lose accounts if the writes were not serialised.
  await send('create', { passphrase: PASSPHRASE });
  const secrets = ['JBSWY3DPEHPK3PXP', 'KRSXG5CTMVRXEZLU', 'MFRGGZDFMZTWQ2LK', 'NBSWY3DPEB3W64TM', 'ORSXG5BRGIZQ===='];
  await Promise.all(
    secrets.map((secret, i) => send('add', { account: { name: `parallel-${i}`, secret } })),
  );
  const accounts = await send('list');
  assert.equal(accounts.length, secrets.length);
  assert.deepEqual(accounts.map((a) => a.order).sort((x, y) => x - y), [0, 1, 2, 3, 4]);
});

test('unknown commands are refused rather than ignored', async () => {
  await assert.rejects(send('definitely-not-a-command'), /unknown command/);
});
