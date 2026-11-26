import { send, describeError } from '../lib/messaging.js';
import { evaluatePrf } from '../lib/webauthn.js';

const views = {
  locked: document.getElementById('view-locked'),
  list: document.getElementById('view-list'),
  add: document.getElementById('view-add'),
};

const state = {
  settings: null,
  biometric: null,
  accounts: [],
  codes: new Map(),   // id -> { code, remaining, period }
  windows: new Map(), // id -> time-step index the cached code belongs to
  filter: '',
};

let ticker = null;

init();

async function init() {
  document.getElementById('unlock-form').addEventListener('submit', onUnlock);
  document.getElementById('unlock-biometric').addEventListener('click', onBiometricUnlock);
  document.getElementById('open-setup').addEventListener('click', openOptions);
  document.getElementById('btn-lock').addEventListener('click', onLock);
  document.getElementById('btn-options').addEventListener('click', openOptions);
  document.getElementById('btn-add').addEventListener('click', () => showView('add'));
  document.getElementById('btn-back').addEventListener('click', () => showView('list'));
  document.getElementById('search').addEventListener('input', (e) => {
    state.filter = e.target.value.trim().toLowerCase();
    renderAccounts();
  });
  document.getElementById('btn-capture').addEventListener('click', onCapture);
  document.getElementById('btn-import-uri').addEventListener('click', onImportUri);
  document.getElementById('manual-form').addEventListener('submit', onManualAdd);
  document.getElementById('m-type').addEventListener('change', onTypeChange);
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => selectTab(tab.dataset.tab));
  }

  const status = await send('state');
  state.settings = status.settings;
  applyTheme(status.settings.theme);

  if (!status.initialized) {
    document.getElementById('lock-title').textContent = 'Welcome to Kupunya';
    document.getElementById('lock-subtitle').textContent =
      'Create a vault to start storing one-time codes.';
    document.getElementById('unlock-form').hidden = true;
    document.getElementById('open-setup').hidden = false;
    showView('locked');
    return;
  }

  if (!status.unlocked) {
    showView('locked');
    state.biometric = status.biometric;
    detectPopupClosedDuringPrompt();
    const bio = document.getElementById('unlock-biometric');
    bio.hidden = !status.biometric?.enabled;
    if (status.biometric?.enabled) bio.focus();
    else document.getElementById('passphrase').focus();
    return;
  }

  await loadAccounts();
  showView('list');
}

function showView(name) {
  for (const [key, el] of Object.entries(views)) el.hidden = key !== name;
  if (name === 'list') {
    startTicker();
    document.getElementById('search').focus();
  } else {
    stopTicker();
  }
}

function applyTheme(theme) {
  if (theme === 'light' || theme === 'dark') {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
}

// --- unlock -----------------------------------------------------------------

async function onUnlock(event) {
  event.preventDefault();
  const input = document.getElementById('passphrase');
  const error = document.getElementById('unlock-error');
  const button = document.getElementById('unlock-submit');
  error.hidden = true;
  button.disabled = true;
  button.textContent = 'Unlocking…';
  try {
    await send('unlock', { passphrase: input.value });
    input.value = '';
    await loadAccounts();
    showView('list');
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
    input.select();
  } finally {
    button.disabled = false;
    button.textContent = 'Unlock';
  }
}

// Touch ID shows a system sheet. If that steals focus, Chrome closes the popup
// and the WebAuthn request dies with it. We cannot catch that from inside, so
// leave a marker before asking and, if we find it on the next open, switch to
// prompting from a small window of our own from then on.
const PENDING = 'kupunya.biometricPending';
const MODE = 'kupunya.biometricMode';

function detectPopupClosedDuringPrompt() {
  const pending = Number(localStorage.getItem(PENDING) || 0);
  localStorage.removeItem(PENDING);
  if (pending && Date.now() - pending < 120000) localStorage.setItem(MODE, 'window');
}

async function onBiometricUnlock() {
  const error = document.getElementById('biometric-error');
  const button = document.getElementById('unlock-biometric');
  error.hidden = true;

  if (localStorage.getItem(MODE) === 'window') {
    await chrome.windows.create({
      url: chrome.runtime.getURL('src/unlock/unlock.html'),
      type: 'popup',
      width: 380,
      height: 320,
      focused: true,
    });
    window.close();
    return;
  }

  button.disabled = true;
  localStorage.setItem(PENDING, String(Date.now()));
  try {
    const prfOutput = await evaluatePrf(state.biometric);
    await send('biometricUnlock', { prfOutput });
    await loadAccounts();
    showView('list');
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
    if (err?.message === 'BIOMETRIC_STALE') button.hidden = true;
  } finally {
    localStorage.removeItem(PENDING);
    button.disabled = false;
  }
}

async function onLock() {
  await send('lock');
  window.close();
}

function openOptions() {
  chrome.runtime.openOptionsPage();
  window.close();
}

// --- account list -----------------------------------------------------------

async function loadAccounts() {
  state.accounts = sortAccounts(await send('list'));
  state.codes.clear();
  state.windows.clear();
  renderAccounts();
  await refreshCodes();
}

function sortAccounts(accounts) {
  const mode = state.settings?.sortMode || 'manual';
  const copy = [...accounts];
  if (mode === 'issuer') {
    copy.sort((a, b) => (a.issuer || a.name).localeCompare(b.issuer || b.name));
  } else if (mode === 'name') {
    copy.sort((a, b) => a.name.localeCompare(b.name));
  } else {
    copy.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  }
  return copy;
}

function visibleAccounts() {
  if (!state.filter) return state.accounts;
  return state.accounts.filter((a) =>
    `${a.issuer} ${a.name}`.toLowerCase().includes(state.filter),
  );
}

function renderAccounts() {
  const list = document.getElementById('accounts');
  const items = visibleAccounts();
  list.replaceChildren(...items.map(renderAccount));
  document.getElementById('empty-state').hidden = state.accounts.length > 0;
  document.getElementById('no-results').hidden = !(state.accounts.length > 0 && items.length === 0);
  paintCodes();
}

function renderAccount(account) {
  const li = document.createElement('li');
  li.className = 'account';
  li.dataset.id = account.id;

  const meta = document.createElement('div');
  meta.className = 'meta';
  const issuer = document.createElement('div');
  issuer.className = 'issuer';
  issuer.textContent = account.issuer || account.name;
  const name = document.createElement('div');
  name.className = 'name';
  name.textContent = account.issuer ? account.name : labelFor(account);
  meta.append(issuer, name);

  const code = document.createElement('button');
  code.type = 'button';
  code.className = 'code';
  if (state.settings?.hideCodes) code.classList.add('blurred');
  code.textContent = '••••••';
  code.title = state.settings?.autofill === false ? 'Click to copy' : 'Click to fill in the page (or copy)';
  code.addEventListener('click', () => useCode(account, code));

  const right = document.createElement('div');
  right.className = 'row-actions';
  if (account.type === 'hotp') {
    const next = document.createElement('button');
    next.type = 'button';
    next.className = 'mini';
    next.textContent = '↻';
    next.title = 'Next counter';
    next.addEventListener('click', () => advanceCounter(account.id));
    right.append(next);
  } else {
    right.append(renderRing(account));
  }
  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'mini danger';
  remove.textContent = '✕';
  remove.title = 'Remove account';
  remove.addEventListener('click', () => removeAccount(account));
  right.append(remove);

  li.append(meta, code, right);
  return li;
}

function labelFor(account) {
  return account.type === 'hotp' ? `HOTP · counter ${account.counter ?? 0}` : `${account.period}s · ${account.algorithm}`;
}

const RING_RADIUS = 8;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

function renderRing(account) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'ring');
  svg.setAttribute('width', '20');
  svg.setAttribute('height', '20');
  svg.setAttribute('viewBox', '0 0 20 20');
  for (const cls of ['track', 'progress']) {
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('class', cls);
    circle.setAttribute('cx', '10');
    circle.setAttribute('cy', '10');
    circle.setAttribute('r', String(RING_RADIUS));
    if (cls === 'progress') {
      circle.setAttribute('stroke-dasharray', String(RING_CIRCUMFERENCE));
      circle.setAttribute('stroke-dashoffset', '0');
    }
    svg.append(circle);
  }
  svg.dataset.id = account.id;
  return svg;
}

async function refreshCodes() {
  if (state.accounts.length === 0) return;
  try {
    const codes = await send('codes', {});
    const now = Date.now();
    for (const entry of codes) {
      state.codes.set(entry.id, entry);
      state.windows.set(entry.id, windowIndex(now, entry.period));
    }
    paintCodes();
  } catch (err) {
    if (describeError(err) === 'The vault is locked.') showView('locked');
  }
}

function windowIndex(now, period) {
  return Math.floor(now / 1000 / (period || 30));
}

function paintCodes() {
  const now = Date.now();
  for (const li of document.querySelectorAll('.account')) {
    const account = state.accounts.find((a) => a.id === li.dataset.id);
    const entry = state.codes.get(li.dataset.id);
    const button = li.querySelector('.code');
    if (!account || !entry) continue;
    if (!button.classList.contains('copied')) button.textContent = groupCode(entry.code);

    const ring = li.querySelector('.ring');
    if (ring && account.type !== 'hotp') {
      const period = entry.period || 30;
      const remaining = period - ((now / 1000) % period);
      const progress = ring.querySelector('.progress');
      progress.setAttribute(
        'stroke-dashoffset',
        String(RING_CIRCUMFERENCE * (1 - remaining / period)),
      );
      ring.classList.toggle('expiring', remaining <= 5);
      ring.setAttribute('aria-label', `${Math.ceil(remaining)} seconds left`);
    }
  }
}

/** 123456 -> "123 456"; easier to read and to type by hand. */
function groupCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function startTicker() {
  stopTicker();
  ticker = setInterval(() => {
    const now = Date.now();
    let stale = false;
    for (const account of state.accounts) {
      if (account.type === 'hotp') continue;
      const cached = state.windows.get(account.id);
      if (cached === undefined || cached !== windowIndex(now, account.period)) stale = true;
    }
    if (stale) refreshCodes();
    else paintCodes();
  }, 250);
}

function stopTicker() {
  if (ticker) clearInterval(ticker);
  ticker = null;
}

/** Fill the code into the page when there is an OTP field, otherwise copy it. */
async function useCode(account, button) {
  if (!state.codes.get(account.id)) return;
  if (state.settings?.autofill === false) return copyCode(account.id, button);

  let result;
  try {
    result = await send('fill', { id: account.id });
    if (result.status === 'mismatch') {
      const ok = confirm(
        `This code is for ${result.issuer}, but the page is ${result.host}.\n\n` +
          'If you did not expect that, it may be a phishing site. Fill it in anyway?',
      );
      if (!ok) return;
      result = await send('fill', { id: account.id, force: true });
    }
  } catch {
    result = { status: 'unavailable' };
  }

  if (result.status === 'filled') {
    flash(button, 'filled');
    setTimeout(() => window.close(), 450); // hand focus back to the page
    return;
  }
  await copyCode(account.id, button);
}

async function copyCode(id, button) {
  const entry = state.codes.get(id);
  if (!entry) return;
  await navigator.clipboard.writeText(entry.code);
  flash(button, 'copied');
  send('touch').catch(() => {});
}

function flash(button, label) {
  button.classList.add('copied');
  button.textContent = label;
  setTimeout(() => {
    button.classList.remove('copied');
    paintCodes();
  }, 900);
}

async function advanceCounter(id) {
  try {
    const { code } = await send('advanceCounter', { id });
    state.codes.set(id, { id, code, remaining: null, period: 0 });
    state.accounts = sortAccounts(await send('list'));
    renderAccounts();
    toast('Counter advanced');
  } catch (err) {
    toast(describeError(err));
  }
}

async function removeAccount(account) {
  const label = account.issuer ? `${account.issuer} (${account.name})` : account.name;
  if (!confirm(`Remove ${label}?\n\nThis cannot be undone — make sure you have another way in.`)) {
    return;
  }
  state.accounts = sortAccounts(await send('remove', { id: account.id }));
  renderAccounts();
  toast('Account removed');
}

// --- add account ------------------------------------------------------------

function selectTab(name) {
  for (const tab of document.querySelectorAll('.tab')) {
    tab.classList.toggle('active', tab.dataset.tab === name);
  }
  for (const panel of document.querySelectorAll('.tab-panel')) {
    panel.hidden = panel.dataset.panel !== name;
  }
}

function onTypeChange(event) {
  const type = event.target.value;
  document.getElementById('m-counter-wrap').hidden = type !== 'hotp';
  document.getElementById('m-period-wrap').hidden = type === 'hotp';
  const digits = document.getElementById('m-digits');
  if (type === 'steam') {
    digits.value = '5';
    digits.disabled = true;
  } else {
    digits.disabled = false;
    if (digits.value === '5') digits.value = '6';
  }
}

async function onCapture() {
  const error = document.getElementById('scan-error');
  const button = document.getElementById('btn-capture');
  error.hidden = true;
  button.disabled = true;
  button.textContent = 'Capturing…';
  try {
    const { dataUrl } = await send('captureTab');
    let text;
    try {
      text = await decodeQrFromDataUrl(dataUrl);
    } finally {
      // The screenshot may show the secret; do not keep it on screen or in the
      // canvas backing store any longer than the decode needs.
      clearScanPreview();
    }
    if (!text) throw new Error('No QR code found in the visible part of the tab.');
    await importText(text, error);
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = 'Capture visible tab';
  }
}

/**
 * Decode a QR code from a screenshot. Tries the full frame first, then a couple
 * of downscales — QR codes rendered small on a hi-dpi page often need them.
 */
async function decodeQrFromDataUrl(dataUrl) {
  const bitmap = await createImageBitmap(dataUrlToBlob(dataUrl));
  const canvas = document.getElementById('scan-canvas');
  const preview = document.getElementById('scan-preview');
  try {
    for (const scale of [1, 0.6, 1.5]) {
      const width = Math.round(bitmap.width * scale);
      const height = Math.round(bitmap.height * scale);
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d', { willReadFrequently: true });
      ctx.drawImage(bitmap, 0, 0, width, height);
      preview.hidden = false;
      const image = ctx.getImageData(0, 0, width, height);
      const result = window.jsQR(image.data, width, height, { inversionAttempts: 'attemptBoth' });
      if (result?.data) return result.data;
    }
    return null;
  } finally {
    bitmap.close();
  }
}

function clearScanPreview() {
  const canvas = document.getElementById('scan-canvas');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  canvas.width = 1;
  canvas.height = 1;
  document.getElementById('scan-preview').hidden = true;
}

/** Decode a data: URL without fetch(), which our CSP blocks with connect-src 'none'. */
function dataUrlToBlob(dataUrl) {
  const [header, payload] = dataUrl.split(',', 2);
  const mime = header.match(/^data:([^;]+)/)?.[1] || 'image/png';
  const binary = atob(payload);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type: mime });
}

async function onImportUri() {
  const input = document.getElementById('uri-input');
  const error = document.getElementById('uri-error');
  await importText(input.value, error, () => { input.value = ''; });
}

async function importText(text, errorEl, onSuccess) {
  errorEl.hidden = true;
  try {
    const result = await send('importText', { text });
    if (result.added === 0 && result.skipped > 0) {
      errorEl.textContent = 'Already in your vault.';
      errorEl.hidden = false;
      return;
    }
    if (result.added === 0) {
      throw new Error(result.errors[0] || 'Nothing importable found.');
    }
    onSuccess?.();
    await loadAccounts();
    showView('list');
    toast(`Added ${result.added} account${result.added === 1 ? '' : 's'}`);
  } catch (err) {
    errorEl.textContent = describeError(err);
    errorEl.hidden = false;
  }
}

async function onManualAdd(event) {
  event.preventDefault();
  const error = document.getElementById('manual-error');
  error.hidden = true;
  const type = document.getElementById('m-type').value;
  const account = {
    type,
    name: document.getElementById('m-name').value,
    issuer: document.getElementById('m-issuer').value,
    secret: document.getElementById('m-secret').value,
    algorithm: document.getElementById('m-algorithm').value,
    digits: Number(document.getElementById('m-digits').value),
    period: Number(document.getElementById('m-period').value),
    counter: Number(document.getElementById('m-counter').value),
  };
  try {
    await send('add', { account });
    event.target.reset();
    onTypeChange({ target: document.getElementById('m-type') });
    await loadAccounts();
    showView('list');
    toast('Account added');
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  }
}

// --- misc -------------------------------------------------------------------

let toastTimer = null;
function toast(message) {
  const el = document.getElementById('toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 1800);
}

window.addEventListener('unload', stopTicker);
