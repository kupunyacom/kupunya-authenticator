// Thin wrapper over chrome.runtime.sendMessage that throws on the error path,
// so callers can use plain try/catch instead of inspecting { ok } everywhere.

export async function send(cmd, payload = {}) {
  const response = await chrome.runtime.sendMessage({ cmd, ...payload });
  if (!response) throw new Error('background service worker did not respond');
  if (!response.ok) throw new Error(response.error || 'unknown error');
  return response.data;
}

/** Human-readable text for the error codes the service worker throws. */
export function describeError(err) {
  const message = err?.message || String(err);
  switch (message) {
    case 'WRONG_PASSPHRASE':
      return 'Wrong passphrase.';
    case 'LOCKED':
      return 'The vault is locked.';
    case 'NOT_INITIALIZED':
      return 'No vault exists yet.';
    case 'BIOMETRIC_CANCELLED':
      return 'Touch ID was cancelled.';
    case 'BIOMETRIC_FAILED':
      return 'Touch ID did not unlock the vault. Use your passphrase.';
    case 'BIOMETRIC_STALE':
      return 'The vault key changed, so Touch ID was turned off. Unlock with your passphrase and enable it again.';
    case 'BIOMETRIC_NOT_SET_UP':
      return 'Touch ID unlock is not set up.';
    case 'PRF_UNSUPPORTED':
      return 'This browser or passkey provider cannot derive keys (WebAuthn PRF), so Touch ID unlock is unavailable.';
    default:
      return message;
  }
}
