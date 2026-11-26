import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { otpFieldScript, issuerMatchesHost, ownerLabel } from '../src/lib/autofill.js';

// Just enough DOM for the injected function: inputs with a native value setter.
class FakeHTMLInputElement {
  get value() { return this._value; }
  set value(v) { this._value = String(v); }
}
globalThis.HTMLInputElement = FakeHTMLInputElement;
globalThis.InputEvent ??= class InputEvent extends Event {};
globalThis.getComputedStyle = (el) => ({ visibility: el.hiddenStyle ? 'hidden' : 'visible', display: 'block' });

class Input extends FakeHTMLInputElement {
  constructor(props = {}) {
    super();
    Object.assign(this, {
      type: 'text', name: '', id: '', placeholder: '', disabled: false, readOnly: false,
      maxLength: -1, inputMode: '', labels: [], attrs: {}, _value: '', events: [], size: 100,
    }, props);
  }
  getAttribute(name) { return this.attrs[name] ?? null; }
  getBoundingClientRect() { return { width: this.size, height: this.size ? 30 : 0 }; }
  focus() { globalThis.document.activeElement = this; }
  dispatchEvent(event) { this.events.push(event.type); }
}

function page(...inputs) {
  globalThis.document = { activeElement: null, querySelectorAll: () => inputs };
  return inputs;
}

beforeEach(() => page());

test('autocomplete=one-time-code wins over everything', () => {
  const [email, otp] = page(new Input({ name: 'email' }), new Input({ attrs: { autocomplete: 'one-time-code' } }));
  const result = otpFieldScript('123456', 'fill', 6);
  assert.equal(result.filled, true);
  assert.equal(otp.value, '123456');
  assert.equal(email.value, '');
  assert.deepEqual(otp.events, ['input', 'change']);
});

test('a field named like an OTP box is found by its hints', () => {
  const [, code] = page(new Input({ name: 'username' }), new Input({ id: 'app_totp', inputMode: 'numeric' }));
  assert.equal(otpFieldScript('654321', 'fill', 6).filled, true);
  assert.equal(code.value, '654321');
});

test('six one-character boxes receive one digit each', () => {
  const boxes = page(...Array.from({ length: 6 }, () => new Input({ maxLength: 1, inputMode: 'numeric' })));
  const result = otpFieldScript('908172', 'fill', 6);
  assert.equal(result.fields, 6);
  assert.deepEqual(boxes.map((b) => b.value), ['9', '0', '8', '1', '7', '2']);
});

test('probing never writes, and does not need the code', () => {
  const [otp] = page(new Input({ attrs: { autocomplete: 'one-time-code' } }));
  const result = otpFieldScript(null, 'probe', 6);
  assert.ok(result.score >= 45);
  assert.equal(result.filled, false);
  assert.equal(otp.value, '');
});

test('login forms, search boxes and hidden inputs are left alone', () => {
  const inputs = page(
    new Input({ name: 'email' }),
    new Input({ type: 'password', name: 'password' }),
    new Input({ type: 'search', name: 'q' }),
    new Input({ name: 'otp', size: 0 }),
    new Input({ name: 'otp', hiddenStyle: true }),
    new Input({ name: 'otp', disabled: true }),
  );
  assert.equal(otpFieldScript('123456', 'fill', 6).filled, false);
  assert.ok(inputs.every((i) => i.value === ''));
});

test('a plain text field the user already clicked into is filled', () => {
  const [field] = page(new Input({ name: 'answer' }));
  globalThis.document.activeElement = field;
  assert.equal(otpFieldScript('111222', 'fill', 6).filled, true);
  assert.equal(field.value, '111222');
});

test('issuer matching accepts the real site and refuses lookalikes', () => {
  assert.equal(issuerMatchesHost('GitHub', 'github.com'), true);
  assert.equal(issuerMatchesHost('Google', 'accounts.google.com'), true);
  assert.equal(issuerMatchesHost('Amazon Web Services', 'signin.aws.amazon.com'), true);
  assert.equal(issuerMatchesHost('Proton AG', 'account.proton.me'), true);
  assert.equal(issuerMatchesHost('github.com', 'github.com'), true);

  assert.equal(issuerMatchesHost('GitHub', 'github-login.xyz'), false);
  assert.equal(issuerMatchesHost('GitHub', 'githab.com'), false);
  assert.equal(issuerMatchesHost('GitHub', 'login.github.evil.com'), false);
  assert.equal(issuerMatchesHost('Monzo', 'app.monzo.co.uk'), true);
  assert.equal(issuerMatchesHost('PayPal', 'localhost'), false);
  assert.equal(issuerMatchesHost('', 'example.com'), null);
});

test('the owner label skips subdomains and two-part country suffixes', () => {
  assert.equal(ownerLabel('accounts.google.com'), 'google');
  assert.equal(ownerLabel('www.example.co.uk'), 'example');
  assert.equal(ownerLabel('localhost'), '');
});
