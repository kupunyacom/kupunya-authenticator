import { send, describeError } from '../lib/messaging.js';
import { passphraseStrength } from '../lib/vault.js';
import { encodeQr } from '../lib/qr.js';
import { platformSupport, enrollPlatformCredential, evaluatePrf, describePrfDetails, prfHint } from '../lib/webauthn.js';

const el = (id) => document.getElementById(id);
let settings = null;
let biometric = null;

init();

async function init() {
  el('setup-form').addEventListener('submit', onCreateVault);
  el('setup-pass').addEventListener('input', onStrength);
  el('unlock-form').addEventListener('submit', onUnlock);
  el('passphrase-form').addEventListener('submit', onChangePassphrase);
  el('btn-export-encrypted').addEventListener('click', onExportEncrypted);
  el('btn-export-plain').addEventListener('click', onExportPlain);
  el('btn-restore').addEventListener('click', onRestore);
  el('btn-export-qr').addEventListener('click', onExportQr);
  el('btn-hide-qr').addEventListener('click', hideQr);
  el('btn-lock-now').addEventListener('click', onLockNow);
  el('btn-wipe').addEventListener('click', onWipe);
  el('btn-bio-enable').addEventListener('click', onBiometricEnable);
  el('btn-bio-disable').addEventListener('click', onBiometricDisable);
  el('btn-bio-unlock').addEventListener('click', onBiometricUnlock);
  for (const [id, key, cast] of [
    ['pref-autolock', 'autoLockMinutes', Number],
    ['pref-hide', 'hideCodes', Boolean],
    ['pref-autofill', 'autofill', Boolean],
    ['pref-sort', 'sortMode', String],
    ['pref-theme', 'theme', String],
  ]) {
    el(id).addEventListener('change', (event) => {
      const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
      onSetting(key, cast(value));
    });
  }

  await refresh();
}

async function refresh() {
  const status = await send('state');
  settings = status.settings;
  biometric = status.biometric;
  el('version').textContent = `version ${status.version}`;
  applyTheme(settings.theme);

  const wantsSetup = !status.initialized;
  el('setup').hidden = !wantsSetup;
  el('locked').hidden = wantsSetup || status.unlocked;
  el('main').hidden = wantsSetup || !status.unlocked;

  el('btn-bio-unlock').hidden = !biometric?.enabled;
  if (!wantsSetup && !status.unlocked) el('unlock-pass').focus();
  if (wantsSetup) el('setup-pass').focus();
  if (status.unlocked) {
    fillPreferences();
    await renderBiometric();
    await renderAccounts();
  }
}

function applyTheme(theme) {
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}

function fillPreferences() {
  el('pref-autolock').value = String(settings.autoLockMinutes);
  el('pref-hide').checked = settings.hideCodes;
  el('pref-autofill').checked = settings.autofill !== false;
  el('pref-sort').value = settings.sortMode;
  el('pref-theme').value = settings.theme;
}

// --- setup / unlock ---------------------------------------------------------

function onStrength() {
  const { score, label } = passphraseStrength(el('setup-pass').value);
  const bar = el('strength-bar');
  bar.style.width = `${(score / 4) * 100}%`;
  bar.style.background = ['#f2555a', '#f2555a', '#f5a524', '#3ecf8e', '#3ecf8e'][score];
  el('strength-label').textContent =
    el('setup-pass').value.length === 0
      ? 'At least 8 characters. Longer beats complicated.'
      : `Passphrase strength: ${label}`;
}

async function onCreateVault(event) {
  event.preventDefault();
  const error = el('setup-error');
  error.hidden = true;
  const passphrase = el('setup-pass').value;
  if (passphrase !== el('setup-confirm').value) {
    error.textContent = 'The two passphrases do not match.';
    error.hidden = false;
    return;
  }
  try {
    await send('create', { passphrase });
    el('setup-form').reset();
    toast('Vault created');
    await refresh();
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  }
}

async function onUnlock(event) {
  event.preventDefault();
  const error = el('unlock-error');
  error.hidden = true;
  try {
    await send('unlock', { passphrase: el('unlock-pass').value });
    el('unlock-pass').value = '';
    await refresh();
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  }
}

async function onLockNow() {
  await send('lock');
  await refresh();
  toast('Vault locked');
}

// --- accounts ---------------------------------------------------------------

async function renderAccounts() {
  const accounts = (await send('list')).sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  const list = el('account-list');
  list.replaceChildren(...accounts.map((account, index) => renderRow(account, index, accounts)));
  el('no-accounts').hidden = accounts.length > 0;
  el('account-count').textContent = accounts.length ? `· ${accounts.length}` : '';
}

function renderRow(account, index, accounts) {
  const li = document.createElement('li');
  li.className = 'account-row';

  const info = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'title';
  title.textContent = account.issuer ? `${account.issuer} — ${account.name}` : account.name;
  const sub = document.createElement('div');
  sub.className = 'sub';
  sub.textContent =
    account.type === 'hotp'
      ? `HOTP · ${account.digits} digits · counter ${account.counter ?? 0} · ${account.algorithm}`
      : `${account.type.toUpperCase()} · ${account.digits} digits · ${account.period}s · ${account.algorithm}`;
  info.append(title, sub);

  const tools = document.createElement('div');
  tools.className = 'tools';
  tools.append(
    button('↑', 'Move up', index === 0, () => move(accounts, index, -1)),
    button('↓', 'Move down', index === accounts.length - 1, () => move(accounts, index, 1)),
    button('Rename', 'Rename this account', false, () => rename(account)),
    button('Remove', 'Remove this account', false, () => remove(account), 'danger'),
  );

  li.append(info, tools);
  return li;
}

function button(label, title, disabled, onClick, className = '') {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.textContent = label;
  btn.title = title;
  btn.disabled = disabled;
  if (className) btn.className = className;
  btn.addEventListener('click', onClick);
  return btn;
}

async function move(accounts, index, delta) {
  const ids = accounts.map((a) => a.id);
  const target = index + delta;
  [ids[index], ids[target]] = [ids[target], ids[index]];
  await send('reorder', { ids });
  await renderAccounts();
}

async function rename(account) {
  const name = prompt('Account name', account.name);
  if (name === null) return;
  const issuer = prompt('Issuer', account.issuer);
  if (issuer === null) return;
  await send('update', { id: account.id, patch: { name, issuer } });
  await renderAccounts();
  toast('Account updated');
}

async function remove(account) {
  const label = account.issuer ? `${account.issuer} (${account.name})` : account.name;
  if (!confirm(`Remove ${label}? This cannot be undone.`)) return;
  await send('remove', { id: account.id });
  await renderAccounts();
  toast('Account removed');
}

// --- preferences ------------------------------------------------------------

async function onSetting(key, value) {
  settings = await send('settings', { patch: { [key]: value } });
  applyTheme(settings.theme);
  toast('Saved');
}

// --- backup -----------------------------------------------------------------

function download(filename, text, mime = 'application/json') {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function stamp() {
  return new Date().toISOString().slice(0, 10);
}

async function onExportEncrypted() {
  try {
    const envelope = await send('exportEncrypted');
    download(`kupunya-backup-${stamp()}.json`, JSON.stringify(envelope, null, 2));
    toast('Encrypted backup downloaded');
  } catch (err) {
    toast(describeError(err));
  }
}

async function onExportPlain() {
  const warning =
    'This writes your OTP secrets to disk in plain text. Anyone who reads that ' +
    'file can generate your codes forever.\n\nContinue?';
  if (!confirm(warning)) return;
  try {
    const entries = await send('exportUris');
    const body = entries.map((entry) => entry.uri).join('\n');
    download(`kupunya-plaintext-${stamp()}.txt`, `${body}\n`, 'text/plain');
    toast('Plaintext export downloaded — delete it once imported');
  } catch (err) {
    toast(describeError(err));
  }
}

async function onRestore() {
  const error = el('restore-error');
  error.hidden = true;
  const file = el('restore-file').files?.[0];
  const passphrase = el('restore-pass').value;
  const mode = document.querySelector('input[name="restore-mode"]:checked').value;

  try {
    if (!file) throw new Error('Choose a backup file first.');
    const text = await file.text();

    // A foreign backup or a plain URI list goes through the importer instead.
    if (!isKupunyaBackup(text)) {
      const result = await send('importText', { text });
      el('restore-file').value = '';
      await renderAccounts();
      const skipped = result.skipped ? `, skipped ${result.skipped} duplicate(s)` : '';
      const failed = result.errors.length ? ` — ${result.errors.length} entr(y/ies) could not be read` : '';
      toast(`Imported ${result.added} account(s)${skipped}${failed}`);
      return;
    }

    if (!passphrase) throw new Error('Enter the passphrase for that backup.');
    const envelope = JSON.parse(text);
    if (mode === 'replace') {
      const ok = confirm(
        'Replacing discards every account currently in this vault, and switches ' +
          "to the backup's passphrase.\n\nContinue?",
      );
      if (!ok) return;
    }
    const result = await send('importEncrypted', { envelope, passphrase, mode });
    if (mode === 'replace') {
      biometric = (await send('state')).biometric; // replacing re-keys the vault
      await renderBiometric();
    }
    el('restore-pass').value = '';
    el('restore-file').value = '';
    await renderAccounts();
    toast(
      mode === 'replace'
        ? `Vault replaced — ${result.added} accounts`
        : `Merged ${result.added} account(s), skipped ${result.skipped} duplicate(s)`,
    );
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  }
}

/** Our own envelope, as opposed to another app's export. */
function isKupunyaBackup(text) {
  try {
    const json = JSON.parse(text);
    return json?.format === 'kupunya-vault' || json?.format === 'keyring-vault';
  } catch {
    return false;
  }
}

// --- transfer QR codes -------------------------------------------------------

async function onExportQr() {
  const error = el('qr-error');
  const output = el('qr-output');
  const button = el('btn-export-qr');
  error.hidden = true;
  button.disabled = true;
  try {
    const uris = await send('exportMigration', {});
    const accounts = (await send('list')).sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
    // Batches are built in list order, so walking the list in step labels them.
    let offset = 0;
    const cards = uris.map((uri, index) => {
      const batch = accounts.slice(offset, offset + countEntries(uri));
      offset += batch.length;
      return renderQrCard(uri, index, uris.length, batch);
    });
    output.replaceChildren(...cards);
    output.hidden = false;
    el('btn-hide-qr').hidden = false;
    button.textContent = 'Regenerate';
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

function hideQr() {
  el('qr-output').replaceChildren();
  el('qr-output').hidden = true;
  el('btn-hide-qr').hidden = true;
  el('btn-export-qr').textContent = 'Show transfer QR codes';
}

function renderQrCard(uri, index, total, batch) {
  const card = document.createElement('div');
  card.className = 'qr-card';

  const image = document.createElement('div');
  image.className = 'qr-image';
  try {
    const { matrix, version } = encodeQr(uri, { level: 'M' });
    image.append(buildQrSvg(matrix));
    image.title = `QR version ${version}`;
  } catch (err) {
    image.textContent = describeError(err);
  }

  const meta = document.createElement('div');
  meta.className = 'qr-meta';
  const heading = document.createElement('h4');
  heading.textContent = total > 1 ? `Batch ${index + 1} of ${total}` : 'All accounts';
  const list = document.createElement('ul');
  for (const account of batch) {
    const item = document.createElement('li');
    item.textContent = account.issuer ? `${account.issuer} — ${account.name}` : account.name;
    list.append(item);
  }
  meta.append(heading, list);

  card.append(image, meta);
  return card;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Build the QR as real SVG nodes, so no markup is ever parsed from a string. */
function buildQrSvg(matrix, { moduleSize = 4, quietZone = 4 } = {}) {
  const span = matrix.length + quietZone * 2;
  const dimension = span * moduleSize;
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${dimension} ${dimension}`);
  svg.setAttribute('shape-rendering', 'crispEdges');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Account transfer QR code');

  const background = document.createElementNS(SVG_NS, 'rect');
  background.setAttribute('width', String(dimension));
  background.setAttribute('height', String(dimension));
  background.setAttribute('fill', '#ffffff');
  svg.append(background);

  const commands = [];
  matrix.forEach((row, y) => {
    row.forEach((isDark, x) => {
      if (!isDark) return;
      const px = (x + quietZone) * moduleSize;
      const py = (y + quietZone) * moduleSize;
      commands.push(`M${px} ${py}h${moduleSize}v${moduleSize}h-${moduleSize}z`);
    });
  });
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('fill', '#000000');
  path.setAttribute('d', commands.join(''));
  svg.append(path);
  return svg;
}

/** Count the repeated otp_parameters fields without decoding their contents. */
function countEntries(uri) {
  const data = new URL(uri).searchParams.get('data') || '';
  const binary = atob(data.replace(/-/g, '+').replace(/_/g, '/'));
  let count = 0;
  let i = 0;
  while (i < binary.length) {
    const tag = binary.charCodeAt(i);
    if (tag !== 0x0a) break; // field 1, length-delimited
    i++;
    let length = 0;
    let shift = 0;
    while (i < binary.length) {
      const byte = binary.charCodeAt(i++);
      length |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }
    i += length;
    count++;
  }
  return count;
}

// --- security ---------------------------------------------------------------

async function onChangePassphrase(event) {
  event.preventDefault();
  const error = el('pass-error');
  error.hidden = true;
  const next = el('pass-new').value;
  if (next !== el('pass-confirm').value) {
    error.textContent = 'The two new passphrases do not match.';
    error.hidden = false;
    return;
  }
  try {
    await send('changePassphrase', { current: el('pass-current').value, next });
    el('passphrase-form').reset();
    const hadBiometric = biometric?.enabled;
    await refresh();
    toast(
      hadBiometric
        ? 'Passphrase changed — Touch ID was turned off, enable it again'
        : 'Passphrase changed — back up the new vault file',
    );
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  }
}

// --- Touch ID ---------------------------------------------------------------

async function renderBiometric() {
  const statusEl = el('bio-status');
  el('btn-bio-enable').hidden = true;
  el('btn-bio-disable').hidden = !biometric?.enabled;
  if (biometric?.enabled) {
    statusEl.textContent = 'On. The popup offers Touch ID; your passphrase still works too.';
    return;
  }
  const support = await platformSupport();
  if (!support.available) {
    statusEl.textContent = support.reason;
    return;
  }
  statusEl.textContent =
    'Off. Turning it on saves a passkey for this vault and asks for your fingerprint once or twice.';
  el('btn-bio-enable').hidden = false;
}

async function onBiometricEnable() {
  const error = el('bio-error');
  error.hidden = true;
  el('btn-bio-enable').disabled = true;
  try {
    const enrolled = await enrollPlatformCredential();
    const status = await send('biometricEnable', enrolled);
    biometric = status.biometric;
    await renderBiometric();
    toast('Touch ID unlock is on');
  } catch (err) {
    const details = describePrfDetails(err);
    const hint = prfHint(err);
    error.textContent = describeError(err);
    if (hint) error.append(document.createElement('br'), hint);
    if (details) {
      const line = document.createElement('code');
      line.className = 'details';
      line.textContent = details;
      error.append(document.createElement('br'), line);
      // The passkey exists even though it is no use to us.
      error.append(
        document.createElement('br'),
        'A "Kupunya vault" passkey was still saved; you can delete it from your passwords.',
      );
    }
    error.hidden = false;
  } finally {
    el('btn-bio-enable').disabled = false;
  }
}

async function onBiometricDisable() {
  const status = await send('biometricDisable');
  biometric = status.biometric;
  await renderBiometric();
  toast('Touch ID turned off — you can delete the "Kupunya vault" passkey from your passwords');
}

async function onBiometricUnlock() {
  const error = el('unlock-error');
  error.hidden = true;
  try {
    const prfOutput = await evaluatePrf(biometric);
    await send('biometricUnlock', { prfOutput });
    await refresh();
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
    if (err?.message === 'BIOMETRIC_STALE') el('btn-bio-unlock').hidden = true;
  }
}

async function onWipe() {
  if (!confirm('Delete the vault and every account in it? This cannot be undone.')) return;
  const typed = prompt('Type DELETE to confirm.');
  if (typed !== 'DELETE') {
    toast('Cancelled');
    return;
  }
  await send('wipe', { confirm: 'DELETE' });
  toast('Vault deleted');
  await refresh();
}

// --- misc -------------------------------------------------------------------

let toastTimer = null;
function toast(message) {
  const node = el('toast');
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 2200);
}
