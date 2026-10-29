// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Minimal QR code encoder for the tests only (written for OmniVault from ISO/IEC 18004): byte mode, error correction
// level L, versions 1–9 (up to 230 bytes), fixed mask pattern 0. Good enough to put an otpauth:// URI on a test page;
// test/totp-qr.test.js checks the output against the jsQR decoder that the extension uses.

// [error correction codewords per block, number of blocks, data codewords per block] for level L
const LEVEL_L = [null, [7, 1, 19], [10, 1, 34], [15, 1, 55], [20, 1, 80], [26, 1, 108], [18, 2, 68], [20, 2, 78], [24, 2, 97], [30, 2, 116]];
const ALIGN = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46]];

function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

/** Reed–Solomon error correction codewords for one block. */
function reedSolomon(data, degree) {
  // generator polynomial (x − α^0)(x − α^1)…, highest coefficient implicit
  const gen = new Array(degree).fill(0);
  gen[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      gen[j] = gfMul(gen[j], root);
      if (j + 1 < degree) gen[j] ^= gen[j + 1];
    }
    root = gfMul(root, 2);
  }
  const rem = new Array(degree).fill(0);
  for (const b of data) {
    const factor = b ^ rem.shift();
    rem.push(0);
    for (let i = 0; i < degree; i++) rem[i] ^= gfMul(gen[i], factor);
  }
  return rem;
}

/** Data and error correction codewords, interleaved across blocks. */
function codewords(bytes, version) {
  const [ecLen, blocks, dataLen] = LEVEL_L[version];
  const capacity = blocks * dataLen;
  const bits = [];
  const put = (value, n) => { for (let i = n - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
  put(0b0100, 4); // byte mode
  put(bytes.length, 8);
  for (const b of bytes) put(b, 8);
  put(0, Math.min(4, capacity * 8 - bits.length));
  while (bits.length % 8) bits.push(0);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  for (let pad = 0xec; data.length < capacity; pad ^= 0xec ^ 0x11) data.push(pad);
  const dataBlocks = Array.from({ length: blocks }, (_, i) => data.slice(i * dataLen, (i + 1) * dataLen));
  const ecBlocks = dataBlocks.map((b) => reedSolomon(b, ecLen));
  const out = [];
  for (let i = 0; i < dataLen; i++) for (const b of dataBlocks) out.push(b[i]);
  for (let i = 0; i < ecLen; i++) for (const b of ecBlocks) out.push(b[i]);
  return out;
}

/** QR code for `text` (UTF-8) as a square array of rows of booleans (true = dark), without quiet zone. */
export function encodeQr(text) {
  const bytes = [...new TextEncoder().encode(text)];
  const version = LEVEL_L.findIndex((v) => v && v[1] * v[2] >= bytes.length + 2);
  if (version < 1) throw new Error('Text too long for this test encoder');
  const size = 17 + 4 * version;
  const dark = Array.from({ length: size }, () => new Array(size).fill(false));
  const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (row, col, value) => { dark[row][col] = value; fixed[row][col] = true; };

  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); } // timing patterns
  for (const [r0, c0] of [[3, 3], [3, size - 4], [size - 4, 3]]) { // finder patterns with separators
    for (let dr = -4; dr <= 4; dr++) {
      for (let dc = -4; dc <= 4; dc++) {
        const r = r0 + dr, c = c0 + dc;
        if (r < 0 || c < 0 || r >= size || c >= size) continue;
        const d = Math.max(Math.abs(dr), Math.abs(dc));
        set(r, c, d !== 2 && d !== 4);
      }
    }
  }
  const centers = ALIGN[version];
  for (const r0 of centers) {
    for (const c0 of centers) {
      if ((r0 === 6 && c0 === 6) || (r0 === 6 && c0 === size - 7) || (r0 === size - 7 && c0 === 6)) continue; // finder corners
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) set(r0 + dr, c0 + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
    }
  }

  // format information: level L (01), mask 0, BCH(15,5), XOR mask
  const formatData = 0b01 << 3;
  let rem = formatData;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  const format = ((formatData << 10) | rem) ^ 0x5412;
  const bit = (v, i) => ((v >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) set(i, 8, bit(format, i));
  set(7, 8, bit(format, 6));
  set(8, 8, bit(format, 7));
  set(8, 7, bit(format, 8));
  for (let i = 9; i < 15; i++) set(8, 14 - i, bit(format, i));
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, bit(format, i));
  for (let i = 8; i < 15; i++) set(size - 15 + i, 8, bit(format, i));
  set(size - 8, 8, true); // dark module

  if (version >= 7) { // version information, BCH(18,6)
    let v = version;
    for (let i = 0; i < 12; i++) v = (v << 1) ^ ((v >>> 11) * 0x1f25);
    const info = (version << 12) | v;
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(b, a, bit(info, i));
      set(a, b, bit(info, i));
    }
  }

  // data in two-column zigzag from the bottom right, skipping the vertical timing column; mask 0: (row + col) even
  const data = codewords(bytes, version);
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let k = 0; k < size; k++) {
      const row = upward ? size - 1 - k : k;
      for (const col of [right, right - 1]) {
        if (fixed[row][col]) continue;
        const value = i < data.length * 8 ? bit(data[i >>> 3], 7 - (i & 7)) : false;
        i++;
        dark[row][col] = value !== ((row + col) % 2 === 0);
      }
    }
  }
  return dark;
}

/** RGBA pixels (ImageData-like) of a QR code with a 4-module quiet zone, `scale` pixels per module. */
export function renderQr(matrix, scale = 4) {
  const n = matrix.length + 8;
  const width = n * scale;
  const data = new Uint8ClampedArray(width * width * 4).fill(255);
  for (let r = 0; r < matrix.length; r++) {
    for (let c = 0; c < matrix.length; c++) {
      if (!matrix[r][c]) continue;
      for (let y = 0; y < scale; y++) {
        for (let x = 0; x < scale; x++) {
          const p = (((r + 4) * scale + y) * width + (c + 4) * scale + x) * 4;
          data[p] = data[p + 1] = data[p + 2] = 0;
        }
      }
    }
  }
  return { data, width, height: width };
}

/** SVG markup of a QR code (for test pages). */
export function qrSvg(matrix, scale = 6) {
  const n = matrix.length + 8;
  const rects = [];
  for (let r = 0; r < matrix.length; r++) for (let c = 0; c < matrix.length; c++) if (matrix[r][c]) rects.push(`M${c + 4} ${r + 4}h1v1h-1z`);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${n * scale}" height="${n * scale}" viewBox="0 0 ${n} ${n}" shape-rendering="crispEdges">`
    + `<rect width="${n}" height="${n}" fill="#fff"/><path d="${rects.join('')}" fill="#000"/></svg>`;
}
