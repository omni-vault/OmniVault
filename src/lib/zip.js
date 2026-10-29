// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Minimal ZIP reader for import files (1Password .1pux, Proton Pass .zip), in memory only.
// Reads the central directory (APPNOTE.TXT 4.3.12/4.3.16), supports the methods "stored" (0) and "deflate" (8,
// via DecompressionStream('deflate-raw')) and refuses what it does not handle: ZIP64, encrypted entries,
// archives on several disks, other compression methods. Limits against ZIP bombs: number of entries, declared size
// per entry and in total, and while inflating the output may never exceed the declared size (nor the limits);
// each entry's CRC-32 is checked.

import { t } from '../i18n/index.js';

export class ZipError extends Error {
  constructor(message, code = 'zip') { super(message); this.code = code; }
}

export const ZIP_LIMITS = {
  maxEntries: 20_000,
  maxEntryBytes: 128 * 1024 * 1024, // one uncompressed entry
  maxTotalBytes: 512 * 1024 * 1024, // all inflated output of one archive together
};

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_END = 0x06054b50;
const SIG_END64_LOCATOR = 0x07064b50;

let crcTable;
/** CRC-32 (IEEE 802.3, as in ZIP). */
export function crc32(bytes, crc = 0) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = ~crc >>> 0;
  for (let i = 0; i < bytes.length; i++) c = crcTable[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

/** True for data that starts like a ZIP archive (local file header or the end record of an empty archive). */
export function isZip(bytes) {
  return bytes?.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && ((bytes[2] === 3 && bytes[3] === 4) || (bytes[2] === 5 && bytes[3] === 6));
}

const invalid = () => new ZipError(t('Ungültiges ZIP-Archiv.'), 'invalid');
const zip64 = () => new ZipError(t('ZIP64-Archive werden nicht unterstützt. Bitte die Exportdatei kleiner erstellen oder entpacken.'), 'zip64');
const encrypted = () => new ZipError(t('Verschlüsselte ZIP-Archive werden nicht unterstützt. Bitte ohne ZIP-Passwort exportieren.'), 'encrypted');
const tooLarge = () => new ZipError(t('Das ZIP-Archiv ist zu groß oder entpackt sich zu sehr (Schutz vor ZIP-Bomben).'), 'too_large');

function findEnd(bytes, view) {
  // the end record (22 bytes) is followed by a comment of at most 65535 bytes
  const stop = Math.max(0, bytes.length - 22 - 0xffff);
  for (let i = bytes.length - 22; i >= stop; i--) {
    if (view.getUint32(i, true) === SIG_END && i + 22 + view.getUint16(i + 20, true) === bytes.length) return i;
  }
  throw invalid();
}

const decodeName = (raw, utf8Flag) => {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch {
    // not UTF-8 and no UTF-8 flag: code page 437 for the ASCII range, everything else as Latin-1
    if (utf8Flag) throw invalid();
    return String.fromCharCode(...raw);
  }
};

/**
 * Opens a ZIP archive (Uint8Array) → { entries: [{ name, size, compressedSize, method, dir }], find(name), read(entry) }.
 * read() inflates one entry (Promise<Uint8Array>) within the limits. Throws ZipError.
 */
export function openZip(bytes, limits = {}) {
  const L = { ...ZIP_LIMITS, ...limits };
  if (!(bytes instanceof Uint8Array) || bytes.length < 22) throw invalid();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = findEnd(bytes, view);
  if (end >= 20 && view.getUint32(end - 20, true) === SIG_END64_LOCATOR) throw zip64();
  const disk = view.getUint16(end + 4, true);
  const cdDisk = view.getUint16(end + 6, true);
  const onDisk = view.getUint16(end + 8, true);
  const count = view.getUint16(end + 10, true);
  const cdSize = view.getUint32(end + 12, true);
  const cdOffset = view.getUint32(end + 16, true);
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw zip64();
  if (disk !== 0 || cdDisk !== 0 || onDisk !== count) throw new ZipError(t('Mehrteilige ZIP-Archive werden nicht unterstützt.'), 'multidisk');
  if (cdOffset + cdSize > end) throw invalid();
  if (count > L.maxEntries) throw tooLarge();

  const entries = [];
  let declared = 0;
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > end || view.getUint32(p, true) !== SIG_CENTRAL) throw invalid();
    const flags = view.getUint16(p + 8, true);
    const method = view.getUint16(p + 10, true);
    const crc = view.getUint32(p + 16, true);
    const compressedSize = view.getUint32(p + 20, true);
    const size = view.getUint32(p + 24, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const entryDisk = view.getUint16(p + 34, true);
    const localOffset = view.getUint32(p + 42, true);
    if (p + 46 + nameLen + extraLen + commentLen > end) throw invalid();
    const name = decodeName(bytes.subarray(p + 46, p + 46 + nameLen), flags & 0x800);
    // extra fields: 0x0001 = ZIP64 sizes, 0x9901 = WinZip AES
    for (let e = p + 46 + nameLen; e + 4 <= p + 46 + nameLen + extraLen;) {
      const id = view.getUint16(e, true);
      const len = view.getUint16(e + 2, true);
      if (id === 0x0001) throw zip64();
      if (id === 0x9901) throw encrypted();
      e += 4 + len;
    }
    if (compressedSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff || entryDisk === 0xffff) throw zip64();
    if (flags & 0x1 || flags & 0x40 || method === 99) throw encrypted();
    const dir = name.endsWith('/');
    if (!dir) {
      declared += size;
      if (size > L.maxEntryBytes || declared > L.maxTotalBytes) throw tooLarge();
    }
    entries.push({ name, size, compressedSize, method, crc, localOffset, dir });
    p += 46 + nameLen + extraLen + commentLen;
  }

  let inflated = 0;
  const archive = {
    entries: entries.map(({ name, size, compressedSize, method, dir }) => ({ name, size, compressedSize, method, dir })),
    /** Entry by exact name (or null). */
    find: (name) => archive.entries.find((e) => e.name === name) ?? null,
    async read(entryOrName, { maxBytes = L.maxEntryBytes } = {}) {
      const want = typeof entryOrName === 'string' ? entryOrName : entryOrName?.name;
      const e = entries.find((x) => x.name === want && !x.dir);
      if (!e) throw new ZipError(t('Datei {name} fehlt im ZIP-Archiv.', { name: want }), 'missing');
      if (e.size > maxBytes || inflated + e.size > L.maxTotalBytes) throw tooLarge();
      const lp = e.localOffset;
      if (lp + 30 > bytes.length || view.getUint32(lp, true) !== SIG_LOCAL) throw invalid();
      if (view.getUint16(lp + 6, true) & 0x1) throw encrypted();
      const localName = view.getUint16(lp + 26, true);
      const localExtra = view.getUint16(lp + 28, true);
      for (let x = lp + 30 + localName; x + 4 <= Math.min(lp + 30 + localName + localExtra, bytes.length);) {
        if (view.getUint16(x, true) === 0x0001) throw zip64();
        x += 4 + view.getUint16(x + 2, true);
      }
      const start = lp + 30 + localName + localExtra;
      if (start + e.compressedSize > bytes.length) throw invalid();
      const raw = bytes.subarray(start, start + e.compressedSize);
      let out;
      if (e.method === 0) {
        if (e.compressedSize !== e.size) throw invalid();
        out = raw.slice();
      } else if (e.method === 8) {
        out = await inflateRaw(raw, e.size);
      } else {
        throw new ZipError(t('Unbekannte Kompressionsmethode {n} im ZIP-Archiv.', { n: e.method }), 'method');
      }
      if (crc32(out) !== e.crc) throw new ZipError(t('ZIP-Archiv beschädigt (Prüfsumme von {name} stimmt nicht).', { name: e.name }), 'crc');
      inflated += out.length;
      return out;
    },
  };
  return archive;
}

/** Inflates raw deflate data to exactly `size` bytes; stops (and fails) as soon as more would come out. */
async function inflateRaw(raw, size) {
  if (typeof DecompressionStream !== 'function') throw new ZipError(t('Dieser Browser kann ZIP-Archive nicht entpacken.'), 'unsupported');
  const out = new Uint8Array(size);
  let n = 0;
  const reader = new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (n + value.length > size) throw tooLarge();
      out.set(value, n);
      n += value.length;
    }
  } catch (e) {
    reader.cancel().catch(() => {});
    if (e instanceof ZipError) throw e;
    throw invalid();
  }
  if (n !== size) throw invalid();
  return out;
}
