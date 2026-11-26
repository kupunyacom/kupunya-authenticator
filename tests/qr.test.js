import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { encodeQr, qrToSvg, qrToImageData, fittingVersion, maxPayloadBytes } from '../src/lib/qr.js';
import { buildMigrationUris } from '../src/lib/migration.js';
import { buildOtpauthUri } from '../src/lib/uri.js';

// jsQR is an independent implementation; decoding our output with it is the
// real check that the encoder follows the spec rather than merely being
// self-consistent.
const jsQR = createRequire(import.meta.url)('../vendor/jsqr.js');

function roundTrip(text, options) {
  const { matrix, version } = encodeQr(text, options);
  const { data, width, height } = qrToImageData(matrix, { scale: 6 });
  const result = jsQR(data, width, height);
  assert.ok(result, `jsQR could not read the symbol (version ${version}, ${text.length} chars)`);
  return { decoded: result.data, version };
}

test('an otpauth URI survives encode → decode', () => {
  const uri = buildOtpauthUri({
    type: 'totp', name: 'alice@example.com', issuer: 'GitHub',
    secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30,
  });
  assert.equal(roundTrip(uri).decoded, uri);
});

// jsQR (our scanner, and the reference decoder here) cannot read version 23 at
// ECC level L. Verified to be a decoder bug, not an encoder one: symbols produced
// by an independent encoder fail identically, while versions 22 and 24-40 pass.
const DECODER_BLIND_SPOTS = new Set(['L:23']);

test('every version from 1 to 40 encodes and decodes correctly', () => {
  // Sweeping all versions exercises every row of the EC block tables, the
  // alignment-pattern layout and the version-information bits.
  for (const level of ['L', 'M']) {
    for (let version = 1; version <= 40; version++) {
      if (DECODER_BLIND_SPOTS.has(`${level}:${version}`)) continue;
      const capacity = maxPayloadBytesFor(version, level);
      const payload = pseudoText(capacity);
      const { decoded, version: used } = roundTrip(payload, { level, minVersion: version });
      assert.equal(used, version, `level ${level} version ${version}: picked ${used}`);
      assert.equal(decoded, payload, `level ${level} version ${version} payload mismatch`);
    }
  }
});

// Largest payload that still fits in exactly this version.
function maxPayloadBytesFor(version, level) {
  let low = 1;
  for (let size = 1; size <= 3000; size++) {
    if (fittingVersion(size, level) === version) low = size;
  }
  return low;
}

function pseudoText(length) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:/?=&.-_';
  let out = '';
  let seed = 12345;
  for (let i = 0; i < length; i++) {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    out += alphabet[seed % alphabet.length];
  }
  return out;
}

test('boundary payload lengths pick the right version and still decode', () => {
  for (const level of ['L', 'M']) {
    for (let version = 1; version <= 12; version++) {
      const exact = maxPayloadBytesFor(version, level);
      assert.equal(roundTrip(pseudoText(exact), { level }).version, version);
      if (version < 40) {
        assert.equal(roundTrip(pseudoText(exact + 1), { level }).version, version + 1);
      }
    }
  }
});

test('a Google Authenticator migration batch fits in one scannable code', () => {
  const accounts = Array.from({ length: 10 }, (_, i) => ({
    type: 'totp', name: `user${i}@example.com`, issuer: `Service ${i}`,
    secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30,
  }));
  const [uri] = buildMigrationUris(accounts, { perBatch: 10 });
  const { decoded } = roundTrip(uri);
  assert.equal(decoded, uri);
});

test('UTF-8 labels survive the trip', () => {
  const uri = buildOtpauthUri({
    type: 'totp', name: 'péngguna@contoh.id', issuer: 'Café • Köln',
    secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30,
  });
  assert.equal(roundTrip(uri).decoded, uri);
});

test('an oversized payload is refused with a useful message', () => {
  assert.throws(
    () => encodeQr(pseudoText(maxPayloadBytes('M') + 1), { level: 'M' }),
    /a QR code holds at most/,
  );
});

test('the SVG renderer produces a self-contained square image', () => {
  const { matrix, size } = encodeQr('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP');
  const svg = qrToSvg(matrix, { moduleSize: 4, quietZone: 4 });
  const expected = (size + 8) * 4;
  assert.match(svg, new RegExp(`width="${expected}" height="${expected}"`));
  assert.ok(svg.startsWith('<svg xmlns='));
  assert.ok(svg.endsWith('</svg>'));
  assert.ok(!svg.includes('<script'));
});
