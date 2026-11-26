import { test } from 'node:test';
import assert from 'node:assert/strict';

import { hotp, generate, secondsRemaining, decodeSecret } from '../src/lib/otp.js';
import { base32Encode, base32Decode } from '../src/lib/base32.js';
import { utf8ToBytes } from '../src/lib/bytes.js';

// RFC 4226 Appendix D / RFC 6238 Appendix B use these ASCII seeds.
const SEED_SHA1 = utf8ToBytes('12345678901234567890');
const SEED_SHA256 = utf8ToBytes('12345678901234567890123456789012');
const SEED_SHA512 = utf8ToBytes(
  '1234567890123456789012345678901234567890123456789012345678901234',
);

test('RFC 4226 HOTP test vectors', async () => {
  const expected = [
    '755224', '287082', '359152', '969429', '338314',
    '254676', '287922', '162583', '399871', '520489',
  ];
  for (let counter = 0; counter < expected.length; counter++) {
    assert.equal(await hotp(SEED_SHA1, counter, { digits: 6 }), expected[counter]);
  }
});

test('RFC 6238 TOTP test vectors across all three hashes', async () => {
  const vectors = [
    [59, '94287082', '46119246', '90693936'],
    [1111111109, '07081804', '68084774', '25091201'],
    [1111111111, '14050471', '67062674', '99943326'],
    [1234567890, '89005924', '91819424', '93441116'],
    [2000000000, '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826'],
  ];
  const seeds = { SHA1: SEED_SHA1, SHA256: SEED_SHA256, SHA512: SEED_SHA512 };

  for (const [seconds, ...codes] of vectors) {
    for (const [index, algorithm] of ['SHA1', 'SHA256', 'SHA512'].entries()) {
      const account = {
        type: 'totp',
        secret: base32Encode(seeds[algorithm]),
        algorithm,
        digits: 8,
        period: 30,
      };
      assert.equal(
        await generate(account, seconds * 1000),
        codes[index],
        `${algorithm} @ T=${seconds}`,
      );
    }
  }
});

test('HOTP honours the requested digit count', async () => {
  assert.equal((await hotp(SEED_SHA1, 0, { digits: 8 })).length, 8);
  assert.equal(await hotp(SEED_SHA1, 0, { digits: 8 }), '84755224');
  assert.equal(await hotp(SEED_SHA1, 0, { digits: 4 }), '5224');
});

test('counters above 2^32 do not wrap', async () => {
  // A 64-bit counter must be handled as BigInt; a 32-bit shift would collide here.
  const low = await hotp(SEED_SHA1, 1, { digits: 6 });
  const high = await hotp(SEED_SHA1, 2n ** 32n + 1n, { digits: 6 });
  assert.notEqual(low, high);
});

test('Steam codes are five characters from the Steam alphabet', async () => {
  const account = { type: 'steam', secret: base32Encode(SEED_SHA1), period: 30 };
  const code = await generate(account, 1111111111 * 1000);
  assert.equal(code.length, 5);
  assert.match(code, /^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
});

test('secondsRemaining counts down within the period', () => {
  assert.equal(secondsRemaining({ period: 30 }, 0), 30);
  assert.equal(secondsRemaining({ period: 30 }, 29_000), 1);
  assert.equal(secondsRemaining({ period: 30 }, 30_000), 30);
  assert.equal(secondsRemaining({ period: 60 }, 15_000), 45);
});

test('secrets decode from base32 and hex alike', () => {
  assert.deepEqual(decodeSecret('JBSWY3DPEHPK3PXP'), base32Decode('JBSWY3DPEHPK3PXP'));
  assert.deepEqual(Array.from(decodeSecret('48656c6c6f', 'hex')), [72, 101, 108, 108, 111]);
});
