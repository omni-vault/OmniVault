// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Importing export files from other password managers into an existing OmniVault account.
// Everything here works in memory: a file's bytes (or text) in, a normalized item list out. Nothing is written to
// disk and no secrets leave the browser.
//
// A normalized item: { type: 'login'|'note'|'card'|'identity', name, username, password, totp, uris: [], notes,
// favorite, folder?, fields?: [{ name, value, type }], card?, identity?, passkeys?, files?: [{ fileName, entry, size }] }.
// The target account decides what it can store (background/tools.js); `files` are attachments inside a ZIP archive.

import { mark, t, tn } from '../i18n/index.js';
import { keepassItems, parseXml } from './kdbx.js';
import { decryptBitwardenJson, isPasswordProtected } from './export.js';
import { isZip, openZip } from './zip.js';

/** Errors with a code the popup reacts to: 'bad_password', 'kdf', 'format', 'account'. */
export class ImportError extends Error {
  constructor(message, code) { super(message); this.code = code; }
}
/** RFC 4180 CSV parser: handles quoted fields, embedded commas, quotes ("") and CR/LF inside quotes. */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  const s = text.replace(/^﻿/, ''); // strip BOM
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i++; } else quoted = false;
      } else field += c;
    } else if (c === '"') {
      quoted = true;
    } else if (c === ',') {
      row.push(field); field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && s[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); if (row.length > 1 || row[0] !== '') rows.push(row); }
  return rows;
}

const norm = (h) => h.toLowerCase().replace(/[\s_-]+/g, '');
// Column aliases → canonical field. First match wins, in listed order.
const COLUMN_MAP = {
  name: ['name', 'title', 'account', 'itemname', 'entryname'],
  username: ['username', 'loginusername', 'user', 'loginname', 'login', 'accountusername'],
  email: ['email', 'loginemail', 'emailaddress'],
  password: ['password', 'loginpassword', 'pass', 'accountpassword'],
  uri: ['uri', 'url', 'urls', 'loginuri', 'website', 'websiteurl', 'link', 'loginurl'],
  totp: ['totp', 'logintotp', 'otpauth', 'otp', 'otpsecret', 'twofactor', '2fa', 'authkey', 'verificationcode'],
  notes: ['notes', 'note', 'comment', 'comments', 'extra', 'description'],
  type: ['type'],
  favorite: ['favorite', 'fav', 'favourite', 'starred'],
  folder: ['folder', 'grouping', 'group', 'category', 'collection'],
};

/** Builds a header→field index map for a CSV header row. */
function mapHeaders(header) {
  const idx = {};
  const cols = header.map(norm);
  for (const [field, aliases] of Object.entries(COLUMN_MAP)) {
    for (const a of aliases) {
      const i = cols.indexOf(a);
      if (i >= 0) { idx[field] = i; break; }
    }
  }
  return idx;
}

const nonEmpty = (v) => typeof v === 'string' && v.trim() !== '';

/** Maps a CSV data row to a normalized item using the header index. Extra columns are appended to notes. */
function rowToItem(row, idx, header) {
  const get = (f) => (idx[f] != null ? (row[idx[f]] ?? '').trim() : '');
  const username = get('username') || get('email');
  const uriRaw = get('uri');
  const uris = uriRaw ? uriRaw.split(/[\n,]/).map((u) => u.trim()).filter(Boolean) : [];
  const mapped = new Set(Object.values(idx));
  // keep unmapped, non-empty columns as "Label: value" lines so nothing is silently dropped
  const extra = [];
  for (let i = 0; i < row.length; i++) {
    if (mapped.has(i)) continue;
    const label = (header[i] ?? t('Feld {n}', { n: i + 1 })).trim();
    const val = (row[i] ?? '').trim();
    if (val && !/^folder$|^grouping$/i.test(label)) extra.push(`${label}: ${val}`);
  }
  const notesParts = [get('notes'), ...extra].filter(nonEmpty);
  const hasLogin = nonEmpty(username) || nonEmpty(get('password')) || uris.length || nonEmpty(get('totp'));
  const declaredType = norm(get('type'));
  const isNote = /note|securenote/.test(declaredType) || (!hasLogin && notesParts.length);
  return {
    type: isNote ? 'note' : 'login',
    name: get('name') || username || uris[0] || t('Ohne Namen'),
    username, password: get('password'), totp: get('totp'),
    uris, notes: notesParts.join('\n'),
    favorite: /^(1|true|yes|ja)$/i.test(get('favorite')),
    folder: get('folder') || undefined,
  };
}

/** CSV with a header row (Bitwarden, LastPass, Chrome, Firefox, 1Password, NordPass, Dashlane, KeePass, Safari …). */
export function importCsv(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error(t('CSV ohne Datenzeilen'));
  const header = rows[0];
  const idx = mapHeaders(header);
  if (idx.name == null && idx.username == null && idx.password == null && idx.uri == null) {
    throw new Error(t('CSV-Spalten nicht erkannt (keine Spalte für Name, Benutzer, Passwort oder URL gefunden)'));
  }
  return rows.slice(1).map((r) => rowToItem(r, idx, header)).filter((i) => i.name || i.username || i.password);
}

/* ---------- JSON formats ---------- */

const flattenFields = (obj, labels) => Object.entries(obj || {})
  .filter(([k, v]) => labels.includes(k) && nonEmpty(String(v ?? '')))
  .map(([k, v]) => `${k}: ${v}`);

/** Bitwarden / Vaultwarden JSON export ({ items: [...] } or { encrypted:false, items }). */
export function importBitwardenJson(data) {
  if (isPasswordProtected(data)) throw new ImportError(t('Passwortgeschützter Bitwarden-Export: bitte das Passwort der Datei eingeben.'), 'password');
  if (data.encrypted) throw new ImportError(t('Dieser Bitwarden-Export ist mit dem Kontoschlüssel verschlüsselt. Er lässt sich nur in das entsperrte Bitwarden-Konto importieren, aus dem er stammt.'), 'account');
  if (!Array.isArray(data.items)) throw new Error(t('Kein Bitwarden-JSON (items fehlt)'));
  const folders = Object.fromEntries((data.folders ?? []).map((f) => [f.id, f.name]));
  return data.items.map((i) => {
    const login = i.login ?? {};
    const uris = (login.uris ?? []).map((u) => u.uri).filter(Boolean);
    // cards, identities and custom fields stay structured; the target account decides what it can store
    const fields = (i.fields ?? []).filter((f) => f.type !== 3 && (nonEmpty(f.name) || nonEmpty(f.value)))
      .map((f) => ({ name: f.name ?? '', value: f.value ?? '', type: { 1: 'hidden', 2: 'boolean' }[f.type] ?? 'text' }));
    // SSH keys (type 5) arrive as a note with the key in hidden fields
    if (i.type === 5 && i.sshKey) {
      for (const [name, value, type] of [[t('Privater Schlüssel'), i.sshKey.privateKey, 'hidden'], [t('Öffentlicher Schlüssel'), i.sshKey.publicKey, 'text'], [t('Fingerabdruck'), i.sshKey.keyFingerprint, 'text']]) {
        if (nonEmpty(value)) fields.push({ name, value, type });
      }
    }
    const clean = (o) => Object.fromEntries(Object.entries(o ?? {}).filter(([, v]) => v != null && v !== ''));
    return {
      type: { 1: 'login', 3: 'card', 4: 'identity' }[i.type] ?? 'note',
      name: i.name || t('Ohne Namen'),
      username: login.username ?? '', password: login.password ?? '', totp: login.totp ?? '',
      uris, notes: i.notes ?? '', fields,
      ...(i.type === 3 ? { card: clean(i.card) } : {}), ...(i.type === 4 ? { identity: clean(i.identity) } : {}),
      favorite: !!i.favorite, folder: folders[i.folderId] || undefined,
      // passkeys with their private keys; accounts that store passkeys (Bitwarden) take them over
      ...((login.fido2Credentials ?? []).some((p) => p?.keyValue) ? { passkeys: login.fido2Credentials.filter((p) => p?.keyValue).map((p) => ({ ...p })) } : {}),
    };
  });
}

/** Proton Pass JSON export (data.json: { vaults: { id: { items: [{ data: { type, metadata, content } }] } } }). */
export function importProtonJson(data) {
  const vaults = data.vaults ?? {};
  const out = [];
  for (const vault of Object.values(vaults)) {
    for (const entry of vault.items ?? []) {
      const d = entry.data ?? entry;
      const meta = d.metadata ?? {};
      const content = d.content ?? {};
      const type = d.type || (content.password != null || content.urls ? 'login' : 'note');
      const notes = [meta.note];
      for (const f of d.extraFields ?? []) if (f.data?.content) notes.push(`${f.fieldName}: ${f.data.content}`);
      if (type !== 'login' && type !== 'note') notes.push(...flattenFields(content, Object.keys(content)));
      out.push({
        type: type === 'login' ? 'login' : 'note',
        name: meta.name || t('Ohne Namen'),
        username: content.itemUsername || content.username || content.itemEmail || content.email || '',
        password: content.password ?? '',
        totp: content.totpUri ?? '',
        uris: (content.urls ?? []).filter(Boolean),
        notes: notes.filter(nonEmpty).join('\n'),
        favorite: !!(entry.pinned || entry.favorite), folder: vault.name || undefined,
      });
    }
  }
  if (!out.length) throw new Error(t('Kein Proton-Pass-JSON (keine Einträge gefunden)'));
  return out;
}

/**
 * KeePass 2 XML export (KeePass, KeePassXC). Same mapping as an opened .kdbx file (lib/kdbx.js): custom fields stay
 * fields, groups become folders, the recycle bin is left out.
 */
export function importKeePassXml(text) {
  const doc = parseXml(text.replace(/^\uFEFF/, ''), { lenient: true });
  if (!doc?.child('KeePassFile')) throw new Error(t('Kein KeePass-XML'));
  return keepassItems(doc).items;
}

/* ---------- 1Password (.1pux) ---------- */

// 1PUX: ZIP with export.data (JSON: accounts → vaults → items) and attachments in files/<documentId>…
// (format described in 1Password's support article "About the 1Password Unencrypted Export format").
const CATEGORY = { '001': 'login', '002': 'card', '003': 'note', '004': 'identity', '005': 'password', '006': 'document' };
const CARD_BRANDS = { visa: 'Visa', mc: 'Mastercard', mastercard: 'Mastercard', amex: 'Amex', discover: 'Discover', diners: 'Diners Club', jcb: 'JCB', maestro: 'Maestro', unionpay: 'UnionPay', visaelectron: 'Visa' };
const CARD_IDS = { cardholder: 'cardholderName', ccnum: 'number', cvv: 'code' };
const IDENTITY_IDS = { firstname: 'firstName', initial: 'middleName', lastname: 'lastName', company: 'company', email: 'email', username: 'username' };
const PHONE_IDS = ['defphone', 'cellphone', 'homephone', 'busphone'];

const pad2 = (n) => String(n).padStart(2, '0');
/** A section field's value → { text, hidden, kind } (kind: the value type, e.g. 'totp', 'file', 'address'). */
function onePuxValue(value) {
  const [kind, v] = Object.entries(value ?? {})[0] ?? [];
  if (v == null || kind == null) return { text: '', kind };
  if (kind === 'concealed') return { text: String(v), hidden: true, kind };
  if (kind === 'date' && Number.isFinite(Number(v))) {
    const d = new Date(Number(v) * 1000);
    return { text: `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`, kind };
  }
  if (kind === 'monthYear' && /^\d{6}$/.test(String(v))) return { text: `${String(v).slice(4)}/${String(v).slice(0, 4)}`, kind, year: String(v).slice(0, 4), month: String(Number(String(v).slice(4))) };
  if (kind === 'email' && typeof v === 'object') return { text: String(v.email_address ?? ''), kind };
  if (kind === 'address' && typeof v === 'object') {
    return { text: [v.street, [v.zip, v.city].filter(nonEmpty).join(' '), v.state, v.country].filter(nonEmpty).join(', '), kind, address: v };
  }
  if (kind === 'sshKey' && typeof v === 'object') return { text: String(v.privateKey ?? ''), hidden: true, kind };
  if (kind === 'file') return { text: '', kind, file: v };
  if (typeof v === 'object') return { text: JSON.stringify(v), kind };
  return { text: String(v), kind };
}

/** Items of a .1pux archive (opened with openZip) → { items, skipped: [text] }. Attachments: item.files. */
export async function import1Pux(zip) {
  if (!zip.find('export.data')) throw new Error(t('Kein 1Password-Export (export.data fehlt)'));
  let data;
  try { data = JSON.parse(new TextDecoder().decode(await zip.read('export.data', { maxBytes: 64 * 1024 * 1024 }))); } catch (e) {
    if (e.code) throw e;
    throw new Error(t('Kein 1Password-Export (export.data ist kein JSON)'));
  }
  const files = zip.entries.filter((e) => !e.dir && e.name.startsWith('files/'));
  const fileFor = (documentId, fileName) => {
    const entry = documentId && files.find((e) => e.name.startsWith(`files/${documentId}`));
    return entry ? { fileName: String(fileName || entry.name.slice(6 + documentId.length).replace(/^_+/, '') || documentId), entry: entry.name, size: entry.size } : null;
  };
  const out = [];
  let archived = 0;
  let missingFiles = 0;
  for (const account of data.accounts ?? []) {
    for (const vault of account.vaults ?? []) {
      for (const wrapped of vault.items ?? []) {
        const it = wrapped.item ?? wrapped;
        if (it.state === 'archived') { archived++; continue; }
        const d = it.details ?? {};
        const ov = it.overview ?? {};
        const category = CATEGORY[it.categoryUuid] ?? 'other';
        const item = {
          type: category === 'login' || category === 'password' ? 'login' : category === 'card' || category === 'identity' ? category : 'note',
          name: ov.title || t('Ohne Namen'), username: '', password: '', totp: '', uris: [], notes: d.notesPlain ?? '', fields: [],
          favorite: Number(it.favIndex) > 0, folder: vault.attrs?.name || undefined,
        };
        for (const u of [...(ov.urls ?? []).map((x) => x?.url), ov.url]) if (nonEmpty(u) && !item.uris.includes(u.trim())) item.uris.push(u.trim());
        for (const f of d.loginFields ?? []) {
          if (!nonEmpty(f.value)) continue;
          if (f.designation === 'username' && !item.username) item.username = f.value;
          else if (f.designation === 'password' && !item.password) item.password = f.value;
          else item.fields.push({ name: f.name || f.id || t('Feld'), value: f.value, type: f.fieldType === 'P' || f.type === 'P' ? 'hidden' : 'text' });
        }
        if (nonEmpty(d.password) && !item.password) item.password = d.password;
        const card = {};
        const identity = {};
        const attach = [];
        for (const section of d.sections ?? []) {
          for (const f of section.fields ?? []) {
            const v = onePuxValue(f.value);
            if (v.kind === 'file') {
              const a = fileFor(v.file?.documentId, v.file?.fileName);
              if (a) attach.push(a); else missingFiles++;
              continue;
            }
            if (!nonEmpty(v.text)) continue;
            const id = String(f.id ?? '');
            if (v.kind === 'totp' && !item.totp) { item.totp = v.text; continue; }
            if (item.type === 'card') {
              if (CARD_IDS[id] && !card[CARD_IDS[id]]) { card[CARD_IDS[id]] = v.text; continue; }
              if (id === 'type' && !card.brand) { card.brand = CARD_BRANDS[v.text.toLowerCase()] ?? v.text; continue; }
              if (id === 'expiry' && v.kind === 'monthYear' && !card.expYear) { card.expMonth = v.month; card.expYear = v.year; continue; }
            }
            if (item.type === 'identity') {
              if (IDENTITY_IDS[id] && !identity[IDENTITY_IDS[id]]) { identity[IDENTITY_IDS[id]] = v.text; continue; }
              if (PHONE_IDS.includes(id) && !identity.phone) { identity.phone = v.text; continue; }
              if (v.kind === 'address' && !identity.address1) {
                Object.assign(identity, Object.fromEntries(Object.entries({ address1: v.address.street, city: v.address.city, state: v.address.state, postalCode: v.address.zip, country: v.address.country })
                  .filter(([, x]) => nonEmpty(x))));
                continue;
              }
            }
            item.fields.push({ name: f.title || id || section.title || t('Feld'), value: v.text, type: v.hidden ? 'hidden' : 'text' });
          }
        }
        if (d.documentAttributes) {
          const a = fileFor(d.documentAttributes.documentId, d.documentAttributes.fileName);
          if (a) attach.push(a); else missingFiles++;
        }
        if ((ov.tags ?? []).length) item.fields.push({ name: t('Tags'), value: ov.tags.join(', '), type: 'text' });
        if (item.type === 'card') item.card = card;
        if (item.type === 'identity') item.identity = identity;
        if (attach.length) item.files = attach;
        out.push(item);
      }
    }
  }
  if (!out.length && !archived) throw new Error(t('Keine Einträge im 1Password-Export gefunden'));
  const skipped = [];
  if (archived) skipped.push(tn(archived, 'Archiv: {n} Eintrag wird nicht übernommen.', 'Archiv: {n} Einträge werden nicht übernommen.'));
  if (missingFiles) skipped.push(tn(missingFiles, '{n} Anhang fehlt im Archiv.', '{n} Anhänge fehlen im Archiv.'));
  return { items: out, skipped };
}

/* ---------- dispatch ---------- */

export const FORMATS = [
  { id: 'auto', name: mark('Automatisch'), label: mark('Automatisch erkennen') },
  { id: 'csv', name: mark('CSV'), label: mark('CSV (Bitwarden, LastPass, Chrome, NordPass, Dashlane, 1Password, KeePass, Safari …)') },
  { id: 'bitwarden', name: mark('Bitwarden-JSON'), label: mark('Bitwarden / Vaultwarden (.json, auch verschlüsselt)') },
  { id: '1pux', name: mark('1Password-Export'), label: mark('1Password (.1pux)'), binary: true },
  { id: 'proton', name: mark('Proton-Pass-Export'), label: mark('Proton Pass (.zip, .pgp oder data.json)') },
  { id: 'keepassxml', name: mark('KeePass-XML'), label: mark('KeePass 2 (.xml)') },
  { id: 'kdbx', name: mark('KeePass-Datenbank'), label: mark('KeePass-Datenbank (.kdbx)'), binary: true },
];

/** Largest import file read into memory (ZIP archives and PGP files included). */
export const MAX_IMPORT_BYTES = 256 * 1024 * 1024;
const MAX_TEXT_BYTES = 64 * 1024 * 1024;

/** OpenPGP message: ASCII armor, or a binary packet that can start a message (session key, encrypted data). */
export function isPgp(bytes, fileName = '') {
  const head = new TextDecoder().decode(bytes.subarray(0, 64)).trimStart();
  if (head.startsWith('-----BEGIN PGP MESSAGE-----')) return true;
  const b = bytes[0];
  if (!(b & 0x80)) return false;
  const tag = b & 0x40 ? b & 0x3f : (b >> 2) & 0x0f;
  return [1, 3, 18].includes(tag) && (/\.(pgp|gpg|asc)$/i.test(fileName) || tag === 3);
}

/** Decrypts a passphrase-encrypted OpenPGP message (OpenPGP.js, loaded on demand) → bytes, at most `limit`. */
export async function decryptPgp(bytes, passphrase, limit = MAX_IMPORT_BYTES) {
  const openpgp = await import('../../vendor/openpgp.mjs');
  const armored = new TextDecoder().decode(bytes.subarray(0, 64)).trimStart().startsWith('-----BEGIN PGP');
  let message;
  try {
    // as streams, so the plaintext comes out as a stream too and can be counted
    const stream = new Blob([bytes]).stream();
    message = armored ? await openpgp.readMessage({ armoredMessage: stream.pipeThrough(new TextDecoderStream()) })
      : await openpgp.readMessage({ binaryMessage: stream });
  } catch { throw new ImportError(t('Keine gültige PGP-Datei.'), 'format'); }
  if (!message.packets.filterByTag(openpgp.enums.packet.symEncryptedSessionKey).length) {
    throw new ImportError(t('Diese PGP-Datei ist für einen Schlüssel verschlüsselt, nicht mit einer Passphrase.'), 'format');
  }
  let data;
  try {
    // streamed, so a compressed bomb is stopped at `limit`; the plaintext is used only after the stream ended without an
    // error, i.e. after OpenPGP.js checked its integrity (MDC or AEAD) – releasing chunks earlier only serves the count
    ({ data } = await openpgp.decrypt({ message, passwords: [passphrase], format: 'binary', config: { allowUnauthenticatedStream: true } }));
  } catch { throw new ImportError(t('Falsches Passwort für diese Datei.'), 'bad_password'); }
  const chunks = [];
  let n = 0;
  const reader = data instanceof Uint8Array ? new Blob([data]).stream().getReader() : data.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.length;
      if (n > limit) throw new ImportError(t('Die Datei ist zu groß (höchstens {size}).', { size: `${limit / 1024 / 1024} MiB` }), 'too_large');
      chunks.push(value);
    }
  } catch (e) {
    reader.cancel().catch(() => {});
    if (e instanceof ImportError) throw e;
    throw new ImportError(t('Falsches Passwort für diese Datei.'), 'bad_password');
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

/** A ZIP archive: 1Password (.1pux) or Proton Pass (Proton Pass/data.json), the latter possibly with a Bitwarden data.json. */
async function importZip(zip, opts) {
  if (zip.find('export.data')) return { format: '1pux', ...(await import1Pux(zip)), zip };
  if (opts.format === '1pux') throw new Error(t('Kein 1Password-Export (export.data fehlt)'));
  const data = zip.find('Proton Pass/data.json') ?? zip.entries.find((e) => !e.dir && /(^|\/)data\.json$/.test(e.name));
  if (!data) throw new Error(t('Im ZIP-Archiv steckt kein bekannter Export (export.data oder data.json).'));
  const text = new TextDecoder().decode(await zip.read(data, { maxBytes: MAX_TEXT_BYTES }));
  const parsed = await readText(text, { ...opts, format: 'auto' });
  if (parsed.need) return parsed;
  const others = zip.entries.filter((e) => !e.dir && e !== data && !/(^|\/)(\.|__MACOSX\/)/.test(e.name)).length;
  if (others) parsed.skipped = [...(parsed.skipped ?? []), tn(others, 'Weitere Datei im Archiv wird nicht übernommen ({n}).', 'Weitere Dateien im Archiv werden nicht übernommen ({n}).')];
  return parsed;
}

async function readText(text, { format, password }) {
  const trimmed = text.trimStart();
  if ((format === 'auto' || format === 'bitwarden') && trimmed.startsWith('{')) {
    let doc = null;
    try { doc = JSON.parse(text); } catch { /* not JSON: falls through to the text formats */ }
    if (doc?.encrypted === true) {
      if (!isPasswordProtected(doc)) return { need: 'account', doc };
      if (password == null) return { need: 'password', kind: 'bitwarden' };
      let plain;
      try { plain = await decryptBitwardenJson(doc, password); } catch (e) {
        if (e.code === 'bad_password') throw new ImportError(t('Falsches Passwort für diese Datei.'), 'bad_password');
        if (e.code === 'kdf') throw new ImportError(t('Die Schlüsselableitung der Datei wird nicht unterstützt oder liegt außerhalb der üblichen Grenzen.'), 'kdf');
        throw new ImportError(t('Die verschlüsselte Datei ist beschädigt.'), 'format');
      }
      let inner;
      try { inner = JSON.parse(plain); } catch { throw new ImportError(t('Die verschlüsselte Datei ist beschädigt.'), 'format'); }
      return { format: 'bitwarden', items: importBitwardenJson(inner), protected: true };
    }
  }
  return parseImport(text, format);
}

/**
 * Reads an import file (bytes) in memory → { format, items, skipped?, zip? } or, when more is needed first,
 * { need: 'password', kind: 'bitwarden'|'pgp' } (call again with `password`) or { need: 'account', doc } (an
 * account-restricted Bitwarden export: only the account it came from can open it, see the background).
 * KeePass databases (.kdbx) have their own path (lib/kdbx.js).
 */
export async function readImportFile(bytes, { fileName = '', format = 'auto', password = null } = {}) {
  if (bytes.length > MAX_IMPORT_BYTES) throw new ImportError(t('Die Datei ist zu groß (höchstens {size}).', { size: `${MAX_IMPORT_BYTES / 1024 / 1024} MiB` }), 'too_large');
  const opts = { fileName, format, password };
  if (isZip(bytes)) return importZip(openZip(bytes), opts);
  if (format === '1pux') throw new Error(t('Kein 1Password-Export (keine ZIP-Datei)'));
  if ((format === 'auto' || format === 'proton') && isPgp(bytes, fileName)) {
    if (password == null) return { need: 'password', kind: 'pgp' };
    const plain = await decryptPgp(bytes, password);
    if (isZip(plain)) return importZip(openZip(plain), { ...opts, password: null });
    return readText(new TextDecoder().decode(plain), { ...opts, password: null });
  }
  if (bytes.length > MAX_TEXT_BYTES) throw new ImportError(t('Die Datei ist zu groß (höchstens {size}).', { size: `${MAX_TEXT_BYTES / 1024 / 1024} MiB` }), 'too_large');
  return readText(new TextDecoder().decode(bytes), opts);
}

/** Detects the format of a text file and returns {format, items}. Throws with a clear message on failure. */
export function parseImport(text, format = 'auto') {
  const tryJson = () => { try { return JSON.parse(text); } catch { return null; } };
  if (format === 'csv') return { format: 'csv', items: importCsv(text) };
  if (format === 'keepassxml') return { format: 'keepassxml', items: importKeePassXml(text) };
  if (format === 'bitwarden') return { format: 'bitwarden', items: importBitwardenJson(tryJson() ?? {}) };
  if (format === 'proton') return { format: 'proton', items: importProtonJson(tryJson() ?? {}) };
  // auto
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const json = tryJson();
    if (json) {
      if (Array.isArray(json.items) && (json.encrypted !== undefined || json.folders !== undefined || json.items.some((i) => i.login || i.type != null))) {
        return { format: 'bitwarden', items: importBitwardenJson(json) };
      }
      if (json.vaults) return { format: 'proton', items: importProtonJson(json) };
    }
  }
  if (trimmed.startsWith('<')) return { format: 'keepassxml', items: importKeePassXml(text) };
  return { format: 'csv', items: importCsv(text) };
}
