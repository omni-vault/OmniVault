// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Tests only: writes small ZIP archives (node:zlib for deflate), including deliberately broken ones.
// entries: [{ name, data: Uint8Array|string, method?: 0|8, flags?, declaredSize?, crc?, zip64Extra?, aesExtra? }]
// options: { zip64Locator?: boolean }
import { deflateRawSync } from 'node:zlib';
import { crc32 } from '../src/lib/zip.js';

const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };

export function writeZip(entries, { zip64Locator = false } = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const data = typeof e.data === 'string' ? Buffer.from(e.data) : Buffer.from(e.data ?? []);
    const method = e.method ?? 8;
    const comp = method === 8 ? deflateRawSync(data) : data;
    const name = Buffer.from(e.name);
    const crc = e.crc ?? crc32(data);
    const size = e.declaredSize ?? data.length;
    const flags = (e.flags ?? 0) | 0x800;
    const extra = Buffer.concat([
      e.zip64Extra ? Buffer.concat([u16(0x0001), u16(16), Buffer.alloc(16)]) : Buffer.alloc(0),
      e.aesExtra ? Buffer.concat([u16(0x9901), u16(7), u16(2), Buffer.from('AE'), Buffer.from([3]), u16(8)]) : Buffer.alloc(0),
    ]);
    const local = Buffer.concat([u32(0x04034b50), u16(20), u16(flags), u16(method), u16(0), u16(0x21), u32(crc), u32(comp.length), u32(size),
      u16(name.length), u16(extra.length), name, extra, comp]);
    centrals.push(Buffer.concat([u32(0x02014b50), u16(20), u16(20), u16(flags), u16(method), u16(0), u16(0x21), u32(crc), u32(comp.length), u32(size),
      u16(name.length), u16(extra.length), u16(0), u16(0), u16(0), u32(0), u32(offset), name, extra]));
    locals.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(centrals);
  const locator = zip64Locator ? Buffer.concat([u32(0x07064b50), u32(0), u32(0), u32(0), u32(1)]) : Buffer.alloc(0);
  // (a real ZIP64 archive also has the ZIP64 end record before the locator; the reader refuses at the locator already)
  const end = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(entries.length), u16(entries.length), u32(cd.length), u32(offset), u16(0)]);
  return new Uint8Array(Buffer.concat([...locals, cd, locator, end]));
}
