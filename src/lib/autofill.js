// Filling a one-time code into the page the user is looking at.
//
// `otpFieldScript` is handed to chrome.scripting.executeScript, which serialises
// it with Function.prototype.toString — so it must stay self-contained: no
// imports, no references to anything else in this module.

/** Below this score a field is not confidently an OTP box, so we copy instead. */
export const FILL_THRESHOLD = 45;

/**
 * Runs inside the page. `mode` is 'probe' (score only, the code is not sent)
 * or 'fill'. Returns { score, filled }.
 */
export function otpFieldScript(code, mode, length) {
  const THRESHOLD = 45;
  const HINT =
    /one[-_ ]?time|\botp|totp|2fa|mfa|two[-_ ]?(factor|step)|verif|security[-_ ]?code|auth\w*[-_ ]?code|passcode|token|\bcode\b|\bpin\b/i;
  const NOT_OTP = /user|e-?mail|login|search|phone|address|zip|postal|promo|coupon|captcha/i;
  const TEXTY = new Set(['text', 'tel', 'number', 'password']);

  const visible = (el) => {
    const rect = el.getBoundingClientRect();
    if (rect.width < 4 || rect.height < 4) return false;
    const style = getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none';
  };
  const usable = (el) => TEXTY.has(el.type) && !el.disabled && !el.readOnly && visible(el);
  const describe = (el) =>
    [el.name, el.id, el.placeholder, el.getAttribute('aria-label'), el.labels?.[0]?.textContent]
      .filter(Boolean)
      .join(' ');

  const inputs = [...document.querySelectorAll('input')].filter(usable);

  const scoreOf = (el) => {
    const autocomplete = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (autocomplete.includes('one-time-code')) return 100 + (el === document.activeElement ? 45 : 0);
    if (/username|email|password|cc-|tel/.test(autocomplete)) return 0;
    const text = describe(el);
    const hinted = HINT.test(text);
    if (el.type === 'password' && !hinted) return 0;
    let score = 0;
    if (hinted) score += 50;
    if (el === document.activeElement) score += 45;
    if (el.inputMode === 'numeric' || el.type === 'tel' || el.type === 'number') score += 10;
    if (el.maxLength >= length && el.maxLength <= 10) score += 10;
    if (!hinted && NOT_OTP.test(`${el.name} ${el.id}`)) score -= 60;
    return score;
  };

  // A row of one-character boxes, one per digit.
  let split = null;
  for (let i = 0; i + length <= inputs.length; i++) {
    const run = inputs.slice(i, i + length);
    if (run.every((el) => el.maxLength === 1)) {
      split = run;
      break;
    }
  }

  let best = null;
  let bestScore = 0;
  for (const el of inputs) {
    if (split?.includes(el)) continue;
    const score = scoreOf(el);
    if (score > bestScore) {
      best = el;
      bestScore = score;
    }
  }
  const splitScore = split ? 90 + (split.includes(document.activeElement) ? 45 : 0) : 0;
  const score = Math.max(bestScore, splitScore);

  if (mode !== 'fill' || score < THRESHOLD || typeof code !== 'string') {
    return { score, filled: false };
  }

  // Frameworks (React, Vue, Angular) watch the native setter and input events,
  // so assigning .value alone would leave their state stale.
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const put = (el, value) => {
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new InputEvent('input', { bubbles: true, data: value, inputType: 'insertText' }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };

  if (splitScore >= bestScore && split) {
    split.forEach((el, i) => put(el, code[i] ?? ''));
    return { score, filled: true, fields: split.length };
  }
  put(best, code);
  return { score, filled: true, fields: 1 };
}

const GENERIC_WORDS = new Set(['inc', 'ltd', 'llc', 'corp', 'the', 'com', 'net', 'org', 'app']);
// Second-level labels under a country TLD that are not anyone's name: co.uk, com.au…
const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'ac', 'gov', 'edu', 'ne', 'or', 'go']);

const squash = (text) => String(text || '').toLowerCase().replace(/[^a-z0-9]/g, '');

/**
 * The label that names who owns `host`: "google" for accounts.google.com,
 * "example" for www.example.co.uk, "evil" for login.github.evil.com. A cheap
 * stand-in for the public suffix list, good enough for a warning.
 */
export function ownerLabel(host) {
  const labels = String(host || '').toLowerCase().split('.').filter(Boolean);
  if (labels.length < 2) return '';
  let index = labels.length - 2;
  const tld = labels[labels.length - 1];
  if (tld.length === 2 && SECOND_LEVEL.has(labels[index]) && index > 0) index--;
  return squash(labels[index]);
}

/**
 * Does the account's issuer plausibly belong to `host`? Returns null when there
 * is no issuer to judge by. Deliberately strict: "github-login.xyz" is not
 * GitHub. A false "no" only costs the user one confirmation.
 */
export function issuerMatchesHost(issuer, host) {
  const key = squash(issuer);
  if (!key) return null;
  const owner = ownerLabel(host);
  if (owner.length < 2) return false;
  const words = String(issuer)
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length >= 3 && !GENERIC_WORDS.has(w));
  if (owner === key || words.includes(owner)) return true;
  // "Amazon Web Services" on amazon.com, "Microsoft 365" on microsoft.com
  return owner.length >= 4 && key.startsWith(owner);
}
