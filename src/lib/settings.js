// Non-secret preferences. These live unencrypted; nothing here identifies an account.

export const DEFAULT_SETTINGS = {
  autoLockMinutes: 5,      // 0 disables the idle lock
  lockOnBrowserClose: true,
  hideCodes: false,        // blur codes until hovered/focused
  copyOnClick: true,
  autofill: true,          // clicking a code fills it into the page when a field is found
  sortMode: 'manual',      // manual | issuer | name
  theme: 'system',         // system | dark | light
};

export async function loadSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

export async function saveSettings(patch) {
  const next = { ...(await loadSettings()), ...patch };
  await chrome.storage.local.set({ settings: next });
  return next;
}
