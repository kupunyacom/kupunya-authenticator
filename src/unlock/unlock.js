import { send, describeError } from '../lib/messaging.js';
import { evaluatePrf } from '../lib/webauthn.js';

const status = document.getElementById('status');
const error = document.getElementById('error');
const retry = document.getElementById('retry');

retry.addEventListener('click', run);
run();

async function run() {
  error.hidden = true;
  retry.disabled = true;
  try {
    const state = await send('state');
    if (state.unlocked) return done();
    if (!state.biometric?.enabled) throw new Error('BIOMETRIC_NOT_SET_UP');
    const prfOutput = await evaluatePrf(state.biometric);
    await send('biometricUnlock', { prfOutput });
    done();
  } catch (err) {
    error.textContent = describeError(err);
    error.hidden = false;
  } finally {
    retry.disabled = false;
  }
}

function done() {
  status.textContent = 'Unlocked. Open Kupunya from the toolbar.';
  retry.hidden = true;
  setTimeout(() => window.close(), 900);
}
