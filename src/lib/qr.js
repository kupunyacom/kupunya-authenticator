// A QR Code encoder (ISO/IEC 18004), byte mode only — enough to hand an account
// back to another authenticator app. Written here rather than pulled in so the
// code that touches your secrets stays in this repository; correctness is pinned
// by round-tripping every version through an independent decoder in the tests.

const ECC_LEVELS = {
  // formatBits are the 2-bit level codes used in the format information.
  L: { formatBits: 1, ecPerBlock: [
    7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
    28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
  ], blocks: [
    1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
    8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
  ] },
  M: { formatBits: 0, ecPerBlock: [
    10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
    26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  ], blocks: [
    1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
    17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
  ] },
};

const MIN_VERSION = 1;
const MAX_VERSION = 40;

// --- Galois field GF(256) with the QR primitive polynomial x^8+x^4+x^3+x^2+1 ---

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

/**
 * Generator polynomial (x-a^0)(x-a^1)...(x-a^(degree-1)), coefficients stored
 * highest power first with the leading 1 left implicit — the form the division
 * loop below consumes.
 */
function generatorPoly(degree) {
  const poly = new Uint8Array(degree);
  poly[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      poly[j] = gfMul(poly[j], root);
      if (j + 1 < degree) poly[j] ^= poly[j + 1];
    }
    root = gfMul(root, 2);
  }
  return poly;
}

/** Reed-Solomon remainder of `data` for the given number of EC codewords. */
function reedSolomon(data, ecLength) {
  const generator = generatorPoly(ecLength);
  const remainder = new Uint8Array(ecLength);
  for (const byte of data) {
    const factor = byte ^ remainder[0];
    remainder.copyWithin(0, 1);
    remainder[ecLength - 1] = 0;
    for (let i = 0; i < ecLength; i++) {
      remainder[i] ^= gfMul(generator[i], factor);
    }
  }
  return remainder;
}

// --- capacity -----------------------------------------------------------------

/** Raw data modules in a symbol, i.e. everything that is not a function pattern. */
function rawDataModules(version) {
  let modules = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const alignCount = Math.floor(version / 7) + 2;
    modules -= (25 * alignCount - 10) * alignCount - 55;
    if (version >= 7) modules -= 36;
  }
  return modules;
}

function totalCodewords(version) {
  return Math.floor(rawDataModules(version) / 8);
}

function ecParams(version, level) {
  const { ecPerBlock, blocks } = ECC_LEVELS[level];
  return { ecPerBlock: ecPerBlock[version - 1], blocks: blocks[version - 1] };
}

function dataCapacityBytes(version, level) {
  const { ecPerBlock, blocks } = ecParams(version, level);
  const dataCodewords = totalCodewords(version) - ecPerBlock * blocks;
  // Byte mode: 4 bits of mode indicator plus an 8- or 16-bit character count.
  const headerBits = 4 + (version < 10 ? 8 : 16);
  return Math.floor((dataCodewords * 8 - headerBits) / 8);
}

/** Smallest version that fits `byteLength`, or null if it does not fit at all. */
export function fittingVersion(byteLength, level = 'M') {
  for (let version = MIN_VERSION; version <= MAX_VERSION; version++) {
    if (dataCapacityBytes(version, level) >= byteLength) return version;
  }
  return null;
}

/** Largest payload a QR code can carry at this level. */
export function maxPayloadBytes(level = 'M') {
  return dataCapacityBytes(MAX_VERSION, level);
}

/** Bytes that fit in one specific version, for callers that cap symbol size. */
export function payloadCapacity(version, level = 'M') {
  if (version < MIN_VERSION || version > MAX_VERSION) throw new Error(`no such version: ${version}`);
  return dataCapacityBytes(version, level);
}

// --- codeword assembly --------------------------------------------------------

class BitBuffer {
  constructor() {
    this.bits = [];
  }

  push(value, length) {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }

  get length() {
    return this.bits.length;
  }

  toBytes() {
    const bytes = new Uint8Array(Math.ceil(this.bits.length / 8));
    this.bits.forEach((bit, i) => {
      if (bit) bytes[i >>> 3] |= 0x80 >>> (i & 7);
    });
    return bytes;
  }
}

function encodeData(bytes, version, level) {
  const { ecPerBlock, blocks } = ecParams(version, level);
  const dataCodewords = totalCodewords(version) - ecPerBlock * blocks;

  const buffer = new BitBuffer();
  buffer.push(0b0100, 4);                              // byte mode
  buffer.push(bytes.length, version < 10 ? 8 : 16);    // character count
  for (const byte of bytes) buffer.push(byte, 8);

  // Terminator, then pad to a byte boundary, then the alternating pad bytes.
  const capacityBits = dataCodewords * 8;
  buffer.push(0, Math.min(4, capacityBits - buffer.length));
  buffer.push(0, (8 - (buffer.length % 8)) % 8);
  const padded = new Uint8Array(dataCodewords);
  padded.set(buffer.toBytes());
  for (let i = buffer.length / 8, pad = 0; i < dataCodewords; i++, pad++) {
    padded[i] = pad % 2 === 0 ? 0xec : 0x11;
  }
  return padded;
}

/** Split into blocks, append EC codewords, then interleave as the spec requires. */
function addErrorCorrection(dataCodewords, version, level) {
  const { ecPerBlock, blocks } = ecParams(version, level);
  const raw = totalCodewords(version);
  const shortBlockLen = Math.floor(raw / blocks) - ecPerBlock;
  const shortBlockCount = blocks - (raw % blocks);

  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let i = 0; i < blocks; i++) {
    const length = shortBlockLen + (i < shortBlockCount ? 0 : 1);
    const block = dataCodewords.subarray(offset, offset + length);
    offset += length;
    dataBlocks.push(block);
    ecBlocks.push(reedSolomon(block, ecPerBlock));
  }

  const result = new Uint8Array(raw);
  let index = 0;
  for (let i = 0; i < shortBlockLen + 1; i++) {
    for (let b = 0; b < blocks; b++) {
      if (i < dataBlocks[b].length) result[index++] = dataBlocks[b][i];
    }
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (let b = 0; b < blocks; b++) result[index++] = ecBlocks[b][i];
  }
  return result;
}

// --- symbol construction ------------------------------------------------------

function alignmentPositions(version) {
  if (version === 1) return [];
  const size = version * 4 + 17;
  const count = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const positions = [6];
  for (let pos = size - 7; positions.length < count; pos -= step) positions.splice(1, 0, pos);
  return positions;
}

class Symbol_ {
  constructor(version) {
    this.version = version;
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Uint8Array(this.size));
    this.reserved = Array.from({ length: this.size }, () => new Uint8Array(this.size));
  }

  set(x, y, dark, functionModule = true) {
    this.modules[y][x] = dark ? 1 : 0;
    if (functionModule) this.reserved[y][x] = 1;
  }

  drawFinder(x, y) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const px = x + dx;
        const py = y + dy;
        if (px < 0 || py < 0 || px >= this.size || py >= this.size) continue;
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        this.set(px, py, distance !== 2 && distance !== 4);
      }
    }
  }

  drawAlignment(x, y) {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        this.set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  drawFunctionPatterns() {
    // Timing patterns.
    for (let i = 0; i < this.size; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }

    this.drawFinder(3, 3);
    this.drawFinder(this.size - 4, 3);
    this.drawFinder(3, this.size - 4);

    const positions = alignmentPositions(this.version);
    for (let i = 0; i < positions.length; i++) {
      for (let j = 0; j < positions.length; j++) {
        // The three finder corners have no alignment pattern.
        const corner =
          (i === 0 && j === 0) ||
          (i === 0 && j === positions.length - 1) ||
          (i === positions.length - 1 && j === 0);
        if (!corner) this.drawAlignment(positions[i], positions[j]);
      }
    }

    this.reserveFormatArea();
    if (this.version >= 7) this.drawVersion();
  }

  reserveFormatArea() {
    for (let i = 0; i <= 8; i++) {
      if (i !== 6) {
        this.set(i, 8, false);
        this.set(8, i, false);
      }
    }
    for (let i = 0; i < 8; i++) {
      this.set(this.size - 1 - i, 8, false);
      this.set(8, this.size - 1 - i, false);
    }
    this.set(8, this.size - 8, true); // the always-dark module
  }

  drawFormat(level, mask) {
    const data = (ECC_LEVELS[level].formatBits << 3) | mask;
    let remainder = data;
    for (let i = 0; i < 10; i++) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
    const bits = ((data << 10) | remainder) ^ 0x5412;

    for (let i = 0; i <= 5; i++) this.set(8, i, bit(bits, i));
    this.set(8, 7, bit(bits, 6));
    this.set(8, 8, bit(bits, 7));
    this.set(7, 8, bit(bits, 8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(bits, i));

    for (let i = 0; i < 8; i++) this.set(this.size - 1 - i, 8, bit(bits, i));
    for (let i = 8; i < 15; i++) this.set(8, this.size - 15 + i, bit(bits, i));
    this.set(8, this.size - 8, true);
  }

  drawVersion() {
    let remainder = this.version;
    for (let i = 0; i < 12; i++) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
    const bits = (this.version << 12) | remainder;
    for (let i = 0; i < 18; i++) {
      const dark = bit(bits, i);
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, dark);
      this.set(b, a, dark);
    }
  }

  drawCodewords(codewords) {
    let bitIndex = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5; // the vertical timing pattern column is skipped
      for (let vertical = 0; vertical < this.size; vertical++) {
        for (let column = 0; column < 2; column++) {
          const x = right - column;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vertical : vertical;
          if (this.reserved[y][x]) continue;
          const dark =
            bitIndex < codewords.length * 8 &&
            ((codewords[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) === 1;
          this.set(x, y, dark, false);
          bitIndex++;
        }
      }
    }
  }

  applyMask(mask) {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (this.reserved[y][x]) continue;
        if (maskAt(mask, x, y)) this.modules[y][x] ^= 1;
      }
    }
  }

  /** The four penalty rules from the spec; lower is better. */
  penalty() {
    const size = this.size;
    let score = 0;

    const runScore = (line) => {
      let total = 0;
      let runLength = 1;
      for (let i = 1; i < line.length; i++) {
        if (line[i] === line[i - 1]) {
          runLength++;
          if (runLength === 5) total += 3;
          else if (runLength > 5) total += 1;
        } else {
          runLength = 1;
        }
      }
      return total;
    };

    for (let y = 0; y < size; y++) score += runScore(Array.from(this.modules[y]));
    for (let x = 0; x < size; x++) {
      score += runScore(Array.from({ length: size }, (_, y) => this.modules[y][x]));
    }

    for (let y = 0; y < size - 1; y++) {
      for (let x = 0; x < size - 1; x++) {
        const a = this.modules[y][x];
        if (a === this.modules[y][x + 1] && a === this.modules[y + 1][x] && a === this.modules[y + 1][x + 1]) {
          score += 3;
        }
      }
    }

    const FINDER = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    const matches = (get, start) => {
      for (let i = 0; i < FINDER.length; i++) if (get(start + i) !== FINDER[i]) return false;
      return true;
    };
    for (let y = 0; y < size; y++) {
      for (let x = 0; x + FINDER.length <= size; x++) {
        if (matches((i) => this.modules[y][i], x)) score += 40;
        if (matches((i) => this.modules[y][size - 1 - i], x)) score += 40;
      }
    }
    for (let x = 0; x < size; x++) {
      for (let y = 0; y + FINDER.length <= size; y++) {
        if (matches((i) => this.modules[i][x], y)) score += 40;
        if (matches((i) => this.modules[size - 1 - i][x], y)) score += 40;
      }
    }

    let dark = 0;
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) dark += this.modules[y][x];
    const percent = (dark * 100) / (size * size);
    score += Math.floor(Math.abs(percent - 50) / 5) * 10;

    return score;
  }

  toMatrix() {
    return this.modules.map((row) => Array.from(row, (v) => v === 1));
  }
}

function bit(value, index) {
  return ((value >>> index) & 1) === 1;
}

function maskAt(mask, x, y) {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: throw new Error(`invalid mask: ${mask}`);
  }
}

// --- public API ---------------------------------------------------------------

/**
 * Encode text as a QR matrix of booleans (true = dark), choosing the smallest
 * version that fits and the mask with the lowest penalty.
 */
export function encodeQr(text, { level = 'M', minVersion = MIN_VERSION, forceMask = null } = {}) {
  const bytes = new TextEncoder().encode(text);
  const needed = fittingVersion(bytes.length, level);
  if (needed === null) {
    throw new Error(
      `payload is ${bytes.length} bytes; a QR code holds at most ${maxPayloadBytes(level)} at level ${level}`,
    );
  }
  const version = Math.max(needed, minVersion);
  const codewords = addErrorCorrection(encodeData(bytes, version, level), version, level);

  let best = null;
  const masks = forceMask === null ? [0, 1, 2, 3, 4, 5, 6, 7] : [forceMask];
  for (const mask of masks) {
    const symbol = new Symbol_(version);
    symbol.drawFunctionPatterns();
    symbol.drawCodewords(codewords);
    symbol.drawFormat(level, mask);
    symbol.applyMask(mask);
    const penalty = symbol.penalty();
    if (best === null || penalty < best.penalty) best = { symbol, penalty, mask };
  }

  return { matrix: best.symbol.toMatrix(), version, level, mask: best.mask, size: best.symbol.size };
}

/** Render a matrix as a standalone SVG string, quiet zone included. */
export function qrToSvg(matrix, { moduleSize = 4, quietZone = 4, dark = '#000000', light = '#ffffff' } = {}) {
  const size = matrix.length + quietZone * 2;
  const dimension = size * moduleSize;
  const path = [];
  matrix.forEach((row, y) => {
    row.forEach((isDark, x) => {
      if (isDark) {
        path.push(`M${(x + quietZone) * moduleSize} ${(y + quietZone) * moduleSize}h${moduleSize}v${moduleSize}h-${moduleSize}z`);
      }
    });
  });
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${dimension}" height="${dimension}"`,
    ` viewBox="0 0 ${dimension} ${dimension}" shape-rendering="crispEdges">`,
    `<rect width="${dimension}" height="${dimension}" fill="${light}"/>`,
    `<path fill="${dark}" d="${path.join('')}"/>`,
    '</svg>',
  ].join('');
}

/** Render a matrix into RGBA pixels — used by the tests and by canvas output. */
export function qrToImageData(matrix, { scale = 4, quietZone = 4 } = {}) {
  const size = (matrix.length + quietZone * 2) * scale;
  const data = new Uint8ClampedArray(size * size * 4).fill(255);
  matrix.forEach((row, y) => {
    row.forEach((isDark, x) => {
      if (!isDark) return;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const px = (x + quietZone) * scale + dx;
          const py = (y + quietZone) * scale + dy;
          const offset = (py * size + px) * 4;
          data[offset] = 0;
          data[offset + 1] = 0;
          data[offset + 2] = 0;
        }
      }
    });
  });
  return { data, width: size, height: size };
}
