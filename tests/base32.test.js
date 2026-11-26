import { test } from 'node:test';
import assert from 'node:assert/strict';

import { base32Encode, base32Decode, isValidBase32 } from '../src/lib/base32.js';
import { utf8ToBytes, bytesToUtf8 } from '../src/lib/bytes.js';

test('RFC 4648 base32 test vectors', () => {
  const vectors = [
    ['', ''],
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======'],
  ];
  for (const [plain, encoded] of vectors) {
    assert.equal(base32Encode(utf8ToBytes(plain), { pad: true }), encoded, `encode ${plain}`);
    if (plain) {
      assert.equal(bytesToUtf8(base32Decode(encoded)), plain, `decode ${encoded}`);
    }
  }
});

test('decoding tolerates what people actually paste', () => {
  const canonical = base32Decode('JBSWY3DPEHPK3PXP');
  for (const messy of [
    'jbswy3dpehpk3pxp',
    'JBSW Y3DP EHPK 3PXP',
    'JBSW-Y3DP-EHPK-3PXP',
    'JBSWY3DPEHPK3PXP======',
  ]) {
    assert.deepEqual(base32Decode(messy), canonical, messy);
  }
});

test('invalid input is rejected rather than silently mangled', () => {
  assert.throws(() => base32Decode('JBSW!Y3DP'), /invalid base32/);
  assert.throws(() => base32Decode('  '), /empty/);
  assert.equal(isValidBase32('01810'), false); // 0, 1 and 8 are not in the alphabet
  assert.equal(isValidBase32('JBSWY3DPEHPK3PXP'), true);
});
