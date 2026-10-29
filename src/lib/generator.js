// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Local generator for passwords, passphrases, PINs and usernames (no network, no alias services). All randomness
// comes from crypto.getRandomValues via randomInt() (rejection sampling, no modulo bias).
import { t } from '../i18n/index.js';
import { EFF_WORDS } from './eff-wordlist.js';
export const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
};
const AMBIGUOUS = /[Il1O0o]/g;

/** Uniform random integer in [0, n) via rejection sampling. */
export function randomInt(n) {
  if (n <= 0 || n > 2 ** 32) throw new RangeError('n');
  const limit = Math.floor(2 ** 32 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

export const DEFAULT_OPTIONS = { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: false };

export function charsets(o) {
  return Object.keys(SETS).filter((k) => o[k]).map((k) => (o.avoidAmbiguous ? SETS[k].replace(AMBIGUOUS, '') : SETS[k]));
}

/** Password with at least one character from every selected class. */
export function generatePassword(options = {}) {
  const o = { ...DEFAULT_OPTIONS, ...options };
  const sets = charsets(o);
  if (!sets.length) throw new Error(t('Mindestens eine Zeichenart auswählen'));
  const length = Math.max(Math.min(Math.floor(o.length), 128), sets.length, 4);
  const all = sets.join('');
  const chars = sets.map((s) => s[randomInt(s.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) { // Fisher–Yates
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

export function generatePin(length = 6) {
  return Array.from({ length: Math.max(4, Math.min(32, length)) }, () => SETS.digits[randomInt(10)]).join('');
}

/** Approximate entropy in bits for a generated password with these options. */
export function entropyBits(options = {}) {
  const o = { ...DEFAULT_OPTIONS, ...options };
  const pool = charsets(o).join('').length;
  return pool ? Math.floor(o.length * Math.log2(pool)) : 0;
}

/* ---------- passphrases (EFF Large Wordlist, 7776 words) ---------- */

let words = null;
/** The EFF Large Wordlist (7776 distinct words, original order). */
export function wordlist() {
  words ??= EFF_WORDS.split(' ');
  return words;
}

export const PASSPHRASE_DEFAULTS = { words: 5, separator: '-', capitalize: false, includeNumber: false };
export const PASSPHRASE_MIN = 3;
export const PASSPHRASE_MAX = 20;

function passphraseOptions(options) {
  const o = { ...PASSPHRASE_DEFAULTS, ...options };
  const n = Math.floor(Number(o.words));
  return {
    words: Math.max(PASSPHRASE_MIN, Math.min(PASSPHRASE_MAX, Number.isFinite(n) ? n : PASSPHRASE_DEFAULTS.words)),
    separator: String(o.separator ?? '').replace(/[\p{C}]/gu, '').slice(0, 3),
    capitalize: !!o.capitalize,
    includeNumber: !!o.includeNumber,
  };
}

const capital = (w) => w.charAt(0).toUpperCase() + w.slice(1);

/**
 * Words chosen uniformly and independently from the list; optionally capitalized, and optionally one random digit
 * appended to one randomly chosen word.
 */
export function generatePassphrase(options = {}) {
  const o = passphraseOptions(options);
  const list = wordlist();
  const parts = Array.from({ length: o.words }, () => list[randomInt(list.length)]).map((w) => (o.capitalize ? capital(w) : w));
  if (o.includeNumber) parts[randomInt(parts.length)] += String(randomInt(10));
  return parts.join(o.separator);
}

/**
 * Entropy in bits of a passphrase generated with these options: log2(7776) per word, plus log2(10) for the digit and
 * log2(words) for the word it is attached to. Capitalization and the separator are fixed choices and add nothing.
 */
export function passphraseEntropy(options = {}) {
  const o = passphraseOptions(options);
  const bits = o.words * Math.log2(wordlist().length) + (o.includeNumber ? Math.log2(10) + Math.log2(o.words) : 0);
  return Math.floor(bits);
}

/* ---------- usernames ---------- */

export const USERNAME_DEFAULTS = { usernameType: 'word', usernameCapitalize: false, usernameNumber: true, plusEmail: '', catchAllDomain: '' };
const ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** `n` characters, uniformly from `alphabet`. */
export function randomString(n, alphabet = ALNUM) {
  return Array.from({ length: n }, () => alphabet[randomInt(alphabet.length)]).join('');
}

/** A random word from the list, optionally capitalized and followed by four random digits. */
export function randomWordUsername({ capitalize = false, number = true } = {}) {
  const list = wordlist();
  const w = list[randomInt(list.length)];
  return (capitalize ? capital(w) : w) + (number ? randomString(4, SETS.digits) : '');
}

/** Normalized domain name (letters, digits, hyphens, at least one dot), or null. */
export function normalizeDomain(input) {
  const d = String(input ?? '').trim().replace(/^@/, '').replace(/\.$/, '').toLowerCase();
  if (!d || d.length > 253) return null;
  let ascii;
  try { ascii = new URL(`https://${d}/`).hostname; } catch { return null; }
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(ascii)) return null;
  return d;
}

/** `name+random@domain` from an email address (an existing +tag is replaced). */
export function plusAddress(email) {
  const e = String(email ?? '').trim();
  const at = e.lastIndexOf('@');
  const local = at > 0 ? e.slice(0, at).split('+')[0] : '';
  const domain = at > 0 ? normalizeDomain(e.slice(at + 1)) : null;
  if (!local || !domain || /[\s@"(),:;<>[\\\]]/.test(local) || local.length > 54) throw new Error(t('Bitte eine gültige E-Mail-Adresse angeben'));
  return `${local}+${randomString(8)}@${domain}`;
}

/** `random@domain` for a domain whose mail server accepts every address (catch-all). */
export function catchAllAddress(domain) {
  const d = normalizeDomain(domain);
  if (!d) throw new Error(t('Bitte eine gültige Domain angeben'));
  return `${randomString(10)}@${d}`;
}

export function generateUsername(options = {}) {
  const o = { ...USERNAME_DEFAULTS, ...options };
  if (o.usernameType === 'plus') return plusAddress(o.plusEmail);
  if (o.usernameType === 'catchall') return catchAllAddress(o.catchAllDomain);
  return randomWordUsername({ capitalize: o.usernameCapitalize, number: o.usernameNumber });
}

/* ---------- all kinds together (settings.generator) ---------- */

export const GENERATOR_TYPES = ['password', 'passphrase', 'pin', 'username'];
export const GENERATOR_DEFAULTS = { type: 'password', ...DEFAULT_OPTIONS, ...PASSPHRASE_DEFAULTS, ...USERNAME_DEFAULTS };

/** Settings of the generator with defaults and valid values (as stored in settings.generator). */
export function normalizeGenerator(g = {}) {
  const o = { ...GENERATOR_DEFAULTS, ...g };
  const length = Math.floor(Number(o.length));
  return {
    ...o,
    type: GENERATOR_TYPES.includes(o.type) ? o.type : 'password',
    length: Math.max(4, Math.min(128, Number.isFinite(length) ? length : DEFAULT_OPTIONS.length)),
    ...Object.fromEntries(['lower', 'upper', 'digits', 'symbols', 'avoidAmbiguous', 'usernameCapitalize', 'usernameNumber'].map((k) => [k, !!o[k]])),
    ...passphraseOptions(o),
    usernameType: ['word', 'plus', 'catchall'].includes(o.usernameType) ? o.usernameType : 'word',
    plusEmail: String(o.plusEmail ?? '').trim().slice(0, 254),
    catchAllDomain: String(o.catchAllDomain ?? '').trim().slice(0, 253),
  };
}

/** A password for a login (editor dice, context menu): a passphrase if that is the chosen kind, else a password. */
export function generateSecret(g = {}) {
  const o = normalizeGenerator(g);
  return o.type === 'passphrase' ? generatePassphrase(o) : generatePassword(o);
}

export function strengthLabel(bits) {
  if (bits >= 100) return t('sehr stark');
  if (bits >= 75) return t('stark');
  if (bits >= 50) return t('mittel');
  return t('schwach');
}
