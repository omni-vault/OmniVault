// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// RFC 6238 TOTP from a base32 secret or an otpauth:// URI.
import { t } from '../i18n/index.js';
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(s) {
  const clean = s.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(t('Ungültiges Base32'));
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

const ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

/**
 * Strict check of an otpauth:// URI as found in QR codes (Key URI Format): only `otpauth://totp/…`, a valid base32
 * secret, SHA1/SHA256/SHA512, 6–8 digits, a period of 1–300 s. Returns the parameters plus issuer and account name
 * from the label; throws with a message for the user otherwise.
 */
export function parseOtpauthUri(input) {
  const text = String(input ?? '').trim();
  let u;
  try { u = new URL(text); } catch { u = null; }
  if (!u || u.protocol.toLowerCase() !== 'otpauth:') throw new Error(t('Kein Einmalcode-QR-Code (otpauth://) gefunden'));
  if (u.host.toLowerCase() !== 'totp') throw new Error(t('Nur zeitbasierte Einmalcodes (TOTP) werden unterstützt'));
  const p = u.searchParams;
  const secret = (p.get('secret') ?? '').toUpperCase().replace(/[\s=]/g, '');
  if (!secret || !/^[A-Z2-7]+$/.test(secret) || base32Decode(secret).length < 1) throw new Error(t('Der QR-Code enthält kein gültiges Geheimnis'));
  const algorithm = ALGORITHMS[(p.get('algorithm') ?? 'SHA1').toUpperCase().replace('-', '')];
  const digits = Number(p.get('digits') ?? 6);
  const period = Number(p.get('period') ?? 30);
  if (!algorithm || ![6, 7, 8].includes(digits) || !Number.isInteger(period) || period < 1 || period > 300) {
    throw new Error(t('Der QR-Code enthält ungültige Parameter'));
  }
  let label = '';
  try { label = decodeURIComponent(u.pathname.replace(/^\//, '')); } catch { label = u.pathname.slice(1); }
  const colon = label.indexOf(':');
  const issuer = (p.get('issuer') ?? (colon >= 0 ? label.slice(0, colon) : '')).trim();
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
  return { uri: text, secret, algorithm, digits, period, issuer, account };
}

export function parseTotp(input) {
  if (input.startsWith('otpauth://')) {
    const u = new URL(input);
    const p = u.searchParams;
    return {
      secret: p.get('secret') ?? '',
      digits: Number(p.get('digits') ?? 6),
      period: Number(p.get('period') ?? 30),
      algorithm: (p.get('algorithm') ?? 'SHA1').toUpperCase().replace('SHA', 'SHA-'),
    };
  }
  return { secret: input, digits: 6, period: 30, algorithm: 'SHA-1' };
}

export async function totp(input, now = Date.now()) {
  const { secret, digits, period, algorithm } = parseTotp(input);
  const counter = Math.floor(now / 1000 / period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey('raw', base32Decode(secret),
    { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 10 ** digits;
  return {
    code: String(code).padStart(digits, '0'),
    remaining: period - (Math.floor(now / 1000) % period),
  };
}
