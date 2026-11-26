// RFC 4648 base32, the encoding every authenticator uses for shared secrets.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes, { pad = false } = {}) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  if (pad) while (out.length % 8 !== 0) out += '=';
  return out;
}

export function base32Decode(input) {
  // Tolerate what users actually paste: spaces, dashes, lowercase, padding.
  const clean = input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (clean.length === 0) throw new Error('secret is empty');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const idx = ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`invalid base32 character: ${char}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function isValidBase32(input) {
  try {
    return base32Decode(input).length > 0;
  } catch {
    return false;
  }
}
