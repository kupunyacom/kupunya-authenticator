// Touch ID unlock, the half that runs in an extension page. WebAuthn needs a
// document, so the popup / options / unlock pages ask the authenticator for the
// PRF output and hand it to the service worker, which does the unwrapping.

import { base64ToBytes, bytesToBase64 } from './bytes.js';

const random = (n) => crypto.getRandomValues(new Uint8Array(n));

// AAGUIDs of the passkey providers a Mac is likely to offer. Lets a PRF failure
// say *where* the passkey landed, which is usually the whole explanation.
const PROVIDERS = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (managed)',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac (profile)',
  'b5397666-4885-aa6b-cebf-e52262a439a2': 'Chromium browser profile (Brave, Arc, Vivaldi…)',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  '00000000-0000-0000-0000-000000000000': 'unknown (AAGUID hidden)',
};

function aaguidOf(credential) {
  const data = credential?.response?.getAuthenticatorData?.();
  if (!data || data.byteLength < 53) return null;
  const hex = [...new Uint8Array(data).slice(37, 53)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** An Error('PRF_UNSUPPORTED') carrying what we learned, for the UI to show. */
function prfError(stage, ext, credential) {
  const err = new Error('PRF_UNSUPPORTED');
  const aaguid = aaguidOf(credential);
  const brand = navigator.userAgentData?.brands?.find((b) => /Chrome|Edge|Brave|Opera/i.test(b.brand));
  err.details = {
    stage,
    aaguid,
    provider: aaguid ? PROVIDERS[aaguid] || `AAGUID ${aaguid}` : null,
    prf: JSON.stringify(ext?.prf ?? null, (_k, v) => (v instanceof ArrayBuffer ? `<${v.byteLength} bytes>` : v)),
    attachment: credential?.authenticatorAttachment ?? null,
    browser: brand ? `${brand.brand} ${brand.version}` : navigator.userAgent,
  };
  return err;
}

// Authenticators known to store the passkey inside the browser profile, with
// no PRF support. Worth a plain-language hint rather than just a GUID.
const PROFILE_AUTHENTICATORS = new Set([
  'adce0002-35bc-c60a-648b-0b25f1f05503',
  'b5397666-4885-aa6b-cebf-e52262a439a2',
]);

/** A sentence on what to do next, when we recognise the cause. */
export function prfHint(err) {
  if (!PROFILE_AUTHENTICATORS.has(err?.details?.aaguid)) return '';
  return 'This browser saved the passkey in its own profile, which cannot derive keys. ' +
    'If it offers iCloud Keychain when saving a passkey, choose that; otherwise use Chrome for Touch ID unlock.';
}

/** One line a person can paste back to whoever is helping them. */
export function describePrfDetails(err) {
  const d = err?.details;
  if (!d) return '';
  return [
    `step: ${d.stage}`,
    d.provider && `saved to: ${d.provider}`,
    `prf: ${d.prf}`,
    d.attachment && `attachment: ${d.attachment}`,
    d.browser,
  ].filter(Boolean).join(' · ');
}

/** Is there a fingerprint/face authenticator, and can the browser do PRF? */
export async function platformSupport() {
  if (!globalThis.PublicKeyCredential) return { available: false, reason: 'WebAuthn is not available in this browser.' };
  const uv = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);
  if (!uv) return { available: false, reason: 'No Touch ID (or other built-in authenticator) is set up on this device.' };
  if (PublicKeyCredential.getClientCapabilities) {
    const caps = await PublicKeyCredential.getClientCapabilities().catch(() => ({}));
    if (caps['extension:prf'] === false) {
      return { available: false, reason: 'This browser does not support the WebAuthn PRF extension yet.' };
    }
  }
  return { available: true };
}

/** Register a passkey for the vault and read its PRF output. May prompt twice. */
export async function enrollPlatformCredential() {
  const prfSalt = random(32);
  const credential = await call(() =>
    navigator.credentials.create({
      publicKey: {
        rp: { name: 'Kupunya Authenticator' },
        user: { id: random(16), name: 'Kupunya vault', displayName: 'Kupunya vault' },
        challenge: random(32),
        pubKeyCredParams: [
          { type: 'public-key', alg: -7 },   // ES256
          { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        attestation: 'none',
        timeout: 60000,
        extensions: { prf: { eval: { first: prfSalt } } },
      },
    }),
  );
  const ext = credential.getClientExtensionResults();
  if (!ext.prf?.enabled) throw prfError('create', ext, credential);
  const credentialId = bytesToBase64(new Uint8Array(credential.rawId));
  const salt = bytesToBase64(prfSalt);
  // Some authenticators only evaluate PRF on get(), not on create().
  const first = ext.prf.results?.first;
  let prfOutput;
  try {
    prfOutput = first ? bytesToBase64(new Uint8Array(first)) : await evaluatePrf({ credentialId, prfSalt: salt });
  } catch (err) {
    if (err.details) err.details.provider ??= prfError('create', ext, credential).details.provider;
    throw err;
  }
  return { credentialId, prfSalt: salt, prfOutput };
}

/** Ask for the fingerprint and return the PRF output as base64. */
export async function evaluatePrf({ credentialId, prfSalt }) {
  const assertion = await call(() =>
    navigator.credentials.get({
      publicKey: {
        challenge: random(32),
        allowCredentials: [{ type: 'public-key', id: base64ToBytes(credentialId) }],
        userVerification: 'required',
        timeout: 60000,
        extensions: { prf: { eval: { first: base64ToBytes(prfSalt) } } },
      },
    }),
  );
  const ext = assertion.getClientExtensionResults();
  const first = ext.prf?.results?.first;
  if (!first) throw prfError('get', ext, assertion);
  return bytesToBase64(new Uint8Array(first));
}

async function call(fn) {
  try {
    const result = await fn();
    if (!result) throw new Error('BIOMETRIC_CANCELLED');
    return result;
  } catch (err) {
    if (err?.name === 'NotAllowedError' || err?.name === 'AbortError') throw new Error('BIOMETRIC_CANCELLED');
    throw err;
  }
}
