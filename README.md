# Kupunya Authenticator

A two-factor authenticator that lives in your browser toolbar and belongs to you.
No account, no sync server, no telemetry, no host permissions — the extension
cannot talk to the network at all, and the check script enforces that.

Built because trusting someone else's authenticator extension with your TOTP
secrets is a decision you only get to make once.

```
src/lib        the parts worth trusting: base32, HOTP/TOTP, otpauth URIs,
               Google Authenticator migration, QR encoding, vault encryption
src/background service worker — the only place secrets are ever in the clear
src/popup      toolbar UI: codes, search, QR capture, add account
src/options    vault setup, preferences, backup and restore
tests          91 tests, including the RFC 4226 / 4648 / 6238 vectors
```

## Install

```sh
git clone <your fork> kupunya-authenticator
cd kupunya-authenticator
npm test          # no dependencies; Node 20+
npm run lint      # manifest/permission/no-network checks
```

Then in Chrome (or Edge, Brave, any Chromium 116+):

1. Go to `chrome://extensions`
2. Turn on **Developer mode**
3. **Load unpacked** → pick this folder
4. Pin the key icon to your toolbar

On first install the options page opens so you can create a vault passphrase.
`npm run package` produces `dist/kupunya-authenticator-<version>.zip` if you would
rather upload it to the Web Store under your own developer account.

Firefox is not supported as-is: it needs `browser.*` shims and MV3 event pages.

## Adding accounts

- **Scan QR** — open the page showing the QR code, then press *Capture visible tab*.
  The screenshot is decoded in the popup and thrown away; it never leaves the browser.
- **Paste URI** — accepts `otpauth://totp/…`, `otpauth://hotp/…`, and Google
  Authenticator's `otpauth-migration://offline?data=…` export batches.
- **Manual** — for when a site prints the secret instead of showing a QR code.
- **A file** — *Options → Backup → Restore* takes a `.txt` of `otpauth://` URIs
  (one per line) or an unencrypted JSON export from another app.

TOTP, HOTP and Steam's 5-character codes are all supported, with SHA-1, SHA-256
and SHA-512, 4–10 digits, and any period.

## How the vault works

| | |
|---|---|
| Key derivation | PBKDF2-HMAC-SHA256, 650,000 iterations, 16-byte random salt |
| Encryption | AES-256-GCM, fresh 12-byte IV on every write |
| Where the ciphertext lives | `chrome.storage.local` |
| Where the key lives while unlocked | `chrome.storage.session` — memory only, never written to disk, cleared when the browser closes |
| Auto-lock | `chrome.alarms`, configurable (default 5 minutes idle) |

The passphrase is never stored, so a wrong one simply fails the GCM
authentication tag. **There is no recovery path** — if you forget it, the vault
is gone. Take a backup.

Secrets never leave the service worker: the popup and options page receive
account metadata with the secret stripped, and ask the worker to compute codes.
A test asserts both of those properties, and another asserts that no plaintext
secret ever appears in stored data.

## Backups

*Options → Backup* downloads the encrypted envelope itself — the same bytes on
disk, safe to keep in cloud storage, useless without your passphrase. Restore it
into any install, either merging into the current vault or replacing it.

There is also a plaintext `otpauth://` export for migrating to another app. It
asks for confirmation first, because it writes your secrets to disk unencrypted.
Delete the file once you have used it.

## Moving to another app

*Options → Backup → Show transfer QR codes* renders your accounts as
`otpauth-migration://` QR codes — the format Google Authenticator and most other
apps scan on import. Accounts are split into batches that fit comfortably inside
one symbol, measured against the real encoded length rather than an assumed
average, so long labels cannot produce a code too dense to scan.

The QR encoder is in `src/lib/qr.js` rather than vendored, and the tests pin it
by encoding every version from 1 to 40 at two error-correction levels and
decoding each one with an independent decoder.

## Coming from another authenticator

`src/lib/foreign.js` reads the unencrypted JSON backups other apps write. Field
names vary wildly, so it recognises the common shapes — a bare array, a wrapper
object, an object keyed by id, nested `otp`/`info` blocks — and maps whatever it
finds onto an account. Entries it cannot read are listed rather than dropped in
silence, and an encrypted foreign backup says so instead of failing obscurely.

This is tested against representative fixtures for the Authenticator Extension,
2FAS and Aegis layouts, not against files from every version of every app. If an
import comes back short, the surest route is that app's `otpauth://` URI export.

## Permissions, and why each one is needed

| Permission | Why |
|---|---|
| `storage` | to hold the encrypted vault and your preferences |
| `alarms` | to auto-lock after a period of inactivity |
| `activeTab` | to screenshot the current tab *only* when you press *Capture visible tab*, and to reach that tab when you click a code |
| `scripting` | to type a code into the page's OTP field when you click it |

No `host_permissions`, no content scripts, no `<all_urls>`. Nothing runs in a
page until you click a code in the popup, and then only in the current tab.

## Filling codes into the page

Clicking a code in the popup looks for a one-time-code field in the current tab
(`autocomplete="one-time-code"`, a field labelled like an OTP box, a row of
single-digit boxes, or the field you already clicked into) and types the code
there. Login, email, password and search fields are left alone. When no field is
found, the code is copied to the clipboard as before.

The first pass only scores fields and never carries the code; the code goes
only to the one frame that matched best. If the account's issuer does not look
like the site (a *GitHub* code on `github-login.xyz`), the popup asks before
filling. That check is deliberately strict and errs towards asking. Turn
filling off in *Options → Preferences* to always copy.

## Touch ID unlock

*Options → Security → Touch ID* saves a passkey for the vault on this Mac. It
uses the WebAuthn **PRF** extension: the authenticator gives back a 32-byte
secret only after your fingerprint matches. HKDF stretches that into an
AES-256-GCM key, which wraps the vault key. The wrapped key on disk is useless
without your finger, and Touch ID is never just a gate in front of a stored key.

- Your passphrase always still works, and is still the only way to recover.
- Changing the passphrase or replacing the vault from a backup turns Touch ID
  off, because it wrapped the old key. Enable it again afterwards.
- PRF support depends on the browser and the passkey provider: a recent Chrome,
  and for iCloud Keychain, macOS 15 or later. Where it is missing, the option
  explains why and stays off.
- If the popup closes when the Touch ID sheet opens, it notices on the next open
  and from then on asks for your fingerprint in a small window of its own.

## Threat model

Protects against: someone who gets your machine's disk or your profile directory
while the vault is locked, a cloud backup falling into the wrong hands, and the
extension itself quietly exfiltrating secrets.

Does **not** protect against: malware running as you while the vault is unlocked,
a compromised browser, or someone watching you type the passphrase. Unlocked keys
live in memory because that is the only way to generate codes.

## Tests

```sh
npm test
```

Covers the published RFC vectors for HOTP, TOTP (all three hashes) and base32,
the URI and Google-migration codecs in both directions, the QR encoder against
an independent decoder across all 40 versions, foreign-backup imports, the vault
crypto (round-trip, wrong passphrase, tampering, IV uniqueness) and an end-to-end
pass over every service-worker command against a stubbed `chrome` API.

## Known limitations

- The bundled scanner cannot read QR version 23 at error-correction level L.
  That is a jsQR bug — symbols from an independent encoder fail identically,
  while versions 22 and 24–40 decode fine. Our own transfer codes use level M
  and are unaffected; a QR from another app could in principle hit it.
- The unlocked key lives in `chrome.storage.session`, which is also readable by
  this extension's own pages. Keeping secrets inside the service worker is
  defence in depth against a bug in the UI code, not a hard boundary.
- Turning Touch ID off or deleting the vault leaves the "Kupunya vault" passkey
  in your passwords list; delete it there if you like. It is harmless on its own.
- Firefox is not supported yet.
- The extension has never been through an external security audit.

## Third-party code

`vendor/jsqr.js` — [jsQR](https://github.com/cozmo/jsQR) 1.4.0, Apache-2.0, used
only to *decode* a screenshot. Everything else — all cryptography, both OTP
algorithms, the QR *encoder*, and every import/export codec — is in this
repository.

## License

MIT — see [LICENSE](LICENSE).
