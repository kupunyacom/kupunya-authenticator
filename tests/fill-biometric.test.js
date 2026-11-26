import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { installChromeStub } from './helpers/chrome-stub.js';
import { bytesToBase64 } from '../src/lib/bytes.js';

const PASSPHRASE = 'a-good-enough-passphrase';
const GITHUB = 'otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';

let stub;
const send = (...args) => stub.send(...args);
const prf = (fill) => bytesToBase64(new Uint8Array(32).fill(fill));
const credential = { credentialId: bytesToBase64(new Uint8Array([1, 2, 3, 4])), prfSalt: prf(9) };

before(async () => {
  stub = installChromeStub();
  await import('../src/background/service-worker.js');
});

beforeEach(async () => {
  stub.local.clear();
  stub.session.clear();
  stub.alarms.clear();
  stub.scripting.calls.length = 0;
  stub.scripting.frames = [{ frameId: 0, probe: { score: 100, filled: false } }];
  stub.scripting.blocked = false;
  stub.tabState.url = 'https://github.com/sessions/two-factor';
  await send('create', { passphrase: PASSPHRASE });
});

async function githubId() {
  const { accounts } = await send('importText', { text: GITHUB });
  return accounts[0].id;
}

// --- fill -------------------------------------------------------------------

test('fill probes without the code, then fills only the best frame', async () => {
  stub.scripting.frames = [
    { frameId: 0, probe: { score: 10 } },
    { frameId: 7, probe: { score: 100 } },
  ];
  const result = await send('fill', { id: await githubId() });
  assert.equal(result.status, 'filled');

  const [probe, fill] = stub.scripting.calls;
  assert.equal(probe.target.allFrames, true);
  assert.equal(probe.args[0], null, 'the probe must not carry the code');
  assert.deepEqual(fill.target.frameIds, [7]);
  assert.match(fill.args[0], /^\d{6}$/);
  assert.equal(fill.args[1], 'fill');
});

test('no OTP field means the popup falls back to copying', async () => {
  stub.scripting.frames = [{ frameId: 0, probe: { score: 0 } }];
  const result = await send('fill', { id: await githubId() });
  assert.equal(result.status, 'no-field');
  assert.equal(stub.scripting.calls.length, 1);
});

test('a site that does not match the issuer needs confirmation', async () => {
  stub.tabState.url = 'https://github-login.xyz/verify';
  const id = await githubId();
  const result = await send('fill', { id });
  assert.deepEqual(result, { status: 'mismatch', host: 'github-login.xyz', issuer: 'GitHub' });
  assert.equal(stub.scripting.calls.length, 1, 'nothing filled before the user agrees');

  assert.equal((await send('fill', { id, force: true })).status, 'filled');
});

test('pages we cannot script report unavailable instead of failing', async () => {
  stub.scripting.blocked = true;
  assert.equal((await send('fill', { id: await githubId() })).status, 'unavailable');
  stub.tabState.url = undefined;
  assert.equal((await send('fill', { id: await githubId() })).status, 'unavailable');
});

test('fill needs an unlocked vault', async () => {
  const id = await githubId();
  await send('lock');
  await assert.rejects(send('fill', { id }), /LOCKED/);
});

// --- Touch ID ---------------------------------------------------------------

test('Touch ID unlocks with the right PRF output and only that one', async () => {
  await githubId();
  const state = await send('biometricEnable', { ...credential, prfOutput: prf(1) });
  assert.deepEqual(state.biometric, { enabled: true, ...credential });

  await send('lock');
  await assert.rejects(send('biometricUnlock', { prfOutput: prf(2) }), /BIOMETRIC_FAILED/);
  await assert.rejects(send('biometricUnlock', { prfOutput: 'c2hvcnQ=' }), /BIOMETRIC_FAILED/);
  assert.equal((await send('state')).unlocked, false);

  const unlocked = await send('biometricUnlock', { prfOutput: prf(1) });
  assert.equal(unlocked.unlocked, true);
  assert.equal((await send('list')).length, 1);
  assert.equal(stub.alarms.size, 1, 'auto-lock is armed after a Touch ID unlock');
});

test('the stored Touch ID record never holds the vault key in the clear', async () => {
  await send('biometricEnable', { ...credential, prfOutput: prf(1) });
  const sessionKey = [...stub.session.values()][0];
  const stored = JSON.stringify(Object.fromEntries(stub.local));
  assert.ok(!stored.includes(sessionKey));
  assert.ok(!stored.includes(prf(1)));
});

test('enabling Touch ID requires an unlocked vault', async () => {
  await send('lock');
  await assert.rejects(send('biometricEnable', { ...credential, prfOutput: prf(1) }), /LOCKED/);
});

test('changing the passphrase or replacing the vault turns Touch ID off', async () => {
  await send('biometricEnable', { ...credential, prfOutput: prf(1) });
  await send('changePassphrase', { current: PASSPHRASE, next: 'another-passphrase' });
  assert.equal((await send('state')).biometric.enabled, false);

  await send('biometricEnable', { ...credential, prfOutput: prf(1) });
  const backup = await send('exportEncrypted');
  await send('importEncrypted', { envelope: backup, passphrase: 'another-passphrase', mode: 'replace' });
  assert.equal((await send('state')).biometric.enabled, false);
});

test('a record that no longer opens the vault is discarded', async () => {
  await send('biometricEnable', { ...credential, prfOutput: prf(1) });
  // Re-key behind Touch ID's back, keeping its record around.
  const record = stub.local.get('biometric');
  await send('changePassphrase', { current: PASSPHRASE, next: 'another-passphrase' });
  stub.local.set('biometric', record);
  await send('lock');

  await assert.rejects(send('biometricUnlock', { prfOutput: prf(1) }), /BIOMETRIC_STALE/);
  assert.equal((await send('state')).biometric.enabled, false);
});

test('turning Touch ID off removes the record', async () => {
  await send('biometricEnable', { ...credential, prfOutput: prf(1) });
  assert.equal((await send('biometricDisable')).biometric.enabled, false);
  assert.equal(stub.local.has('biometric'), false);
});
