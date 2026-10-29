// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Export of revealed items as Bitwarden JSON (complete: cards, identities, SSH keys, custom fields, folders),
// unencrypted or password-protected, or as Bitwarden CSV (logins and notes; what most password managers import).
// OmniVault's own import reads all three.
import { argon2 } from './argon2.js';
import { b64, concat, equalBytes, fromB64, fromUtf8, utf8 } from './bytes.js';

const TYPE_IDS = { login: 1, note: 2, card: 3, identity: 4, ssh: 5 };
const FIELD_TYPES = { text: 0, hidden: 1, boolean: 2 };
const PASSKEY_FIELDS = ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'userHandle', 'userName',
  'counter', 'rpName', 'userDisplayName', 'discoverable', 'creationDate'];
/** A passkey as Bitwarden exports it (all values strings, private key included). */
const passkeyJson = (p) => Object.fromEntries(PASSKEY_FIELDS.map((k) => [k, p[k] ?? null]));

/** items: revealed items ({ type, name, username, password, totp, uris, notes, folder, favorite, fields, card, identity }) */
export function toBitwardenJson(items) {
  const folderIds = new Map();
  for (const i of items) if (i.folder && !folderIds.has(i.folder)) folderIds.set(i.folder, crypto.randomUUID());
  return JSON.stringify({
    encrypted: false,
    folders: [...folderIds].map(([name, id]) => ({ id, name })),
    items: items.filter((i) => TYPE_IDS[i.type]).map((i) => ({
      id: crypto.randomUUID(),
      folderId: i.folder ? folderIds.get(i.folder) : null,
      type: TYPE_IDS[i.type],
      reprompt: 0,
      name: i.name ?? '',
      notes: i.notes || null,
      favorite: !!i.favorite,
      fields: (i.fields ?? []).filter((f) => f.type !== 'linked').map((f) => ({ name: f.name, value: f.value ?? null, type: FIELD_TYPES[f.type] ?? 0, linkedId: null })),
      ...(i.type === 'login' ? { login: {
        uris: (i.uris ?? []).map((uri) => ({ match: null, uri })), username: i.username || null, password: i.password || null, totp: i.totp || null,
        ...(i.passkeys?.some((p) => p.keyValue) ? { fido2Credentials: i.passkeys.filter((p) => p.keyValue).map(passkeyJson) } : {}),
      } } : {}),
      ...(i.type === 'note' ? { secureNote: { type: 0 } } : {}),
      ...(i.type === 'card' ? { card: { ...(i.card ?? {}) } } : {}),
      ...(i.type === 'identity' ? { identity: { ...(i.identity ?? {}) } } : {}),
      ...(i.type === 'ssh' ? { sshKey: { privateKey: i.ssh?.privateKey ?? null, publicKey: i.ssh?.publicKey ?? null, keyFingerprint: i.ssh?.fingerprint ?? null } } : {}),
    })),
  }, null, 2);
}

const csvCell = (v) => {
  const s = String(v ?? '');
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/** Bitwarden CSV: one row per login or note (cards and identities are only in the JSON export). */
export function toCsv(items) {
  const header = ['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'reprompt', 'login_uri', 'login_username', 'login_password', 'login_totp'];
  const rows = items.filter((i) => i.type === 'login' || i.type === 'note').map((i) => [
    i.folder ?? '', i.favorite ? 1 : '', i.type, i.name ?? '', i.notes ?? '',
    (i.fields ?? []).filter((f) => f.type !== 'linked').map((f) => `${f.name}: ${f.value ?? ''}`).join('\n'), 0,
    i.type === 'login' ? (i.uris ?? []).join(',') : '', i.username ?? '', i.password ?? '', i.totp ?? '',
  ]);
  return [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\n') + '\n';
}

/* ---------- password-protected Bitwarden JSON ----------
 * The format of Bitwarden's "password protected" JSON export, as documented by Bitwarden and visible in the files:
 *   { encrypted: true, passwordProtected: true, salt, kdfType, kdfIterations, kdfMemory, kdfParallelism,
 *     encKeyValidation_DO_NOT_EDIT, data }
 * The key: KDF(password, salt) as for a master key – PBKDF2-SHA256 over the salt string, or Argon2id over
 * SHA-256(salt string) with kdfMemory in MiB – stretched with HKDF-Expand (SHA-256, info "enc" and "mac", 32 bytes
 * each). `data` (the unencrypted JSON export) and `encKeyValidation_DO_NOT_EDIT` (a random UUID that tells a wrong
 * password from a damaged file) are EncStrings of type 2: "2.<iv>|<ciphertext>|<mac>", AES-256-CBC with PKCS#7
 * padding, HMAC-SHA256 over iv‖ciphertext.
 */

const subtle = globalThis.crypto.subtle;

export const EXPORT_KDF = {
  argon2id: { kdfType: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 },
  pbkdf2: { kdfType: 0, kdfIterations: 600_000 },
};
/** What an import accepts from a file (Bitwarden's own bounds), so a file cannot make the browser work for hours. */
export const KDF_BOUNDS = { pbkdf2: [1, 2_000_000], argon2Iterations: [1, 10], argon2Memory: [16, 1024], argon2Parallelism: [1, 16] };

export class ExportCryptoError extends Error {
  constructor(message, code) { super(message); this.code = code; }
}

async function hmac(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

const loadArgon2id = () => import('../../vendor/argon2id.mjs').then((m) => m.default());

/** File key {enc, mac} from the export password, the salt string and the KDF settings of the file. */
export async function deriveExportKey(password, salt, kdf) {
  const pw = utf8(password);
  let master;
  if (kdf.kdfType === 1) {
    master = await argon2('argon2id', {
      password: pw, salt: new Uint8Array(await subtle.digest('SHA-256', utf8(salt))),
      passes: kdf.kdfIterations, memorySize: kdf.kdfMemory * 1024, parallelism: kdf.kdfParallelism, tagLength: 32,
    }, loadArgon2id);
  } else if (kdf.kdfType === 0) {
    const k = await subtle.importKey('raw', pw, 'PBKDF2', false, ['deriveBits']);
    master = new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: utf8(salt), iterations: kdf.kdfIterations }, k, 256));
  } else {
    throw new ExportCryptoError(`kdf ${kdf.kdfType}`, 'kdf');
  }
  // HKDF-Expand with a 32-byte output is a single HMAC block: T(1) = HMAC(PRK, info ‖ 0x01)
  return { enc: await hmac(master, concat(utf8('enc'), new Uint8Array([1]))), mac: await hmac(master, concat(utf8('mac'), new Uint8Array([1]))) };
}

/** EncString type 2 of `plain` (string or bytes). */
export async function encryptType2(plain, key) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const k = await subtle.importKey('raw', key.enc, 'AES-CBC', false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, k, typeof plain === 'string' ? utf8(plain) : plain));
  return `2.${b64(iv)}|${b64(ct)}|${b64(await hmac(key.mac, concat(iv, ct)))}`;
}

/** Opens an EncString type 2 → bytes. A wrong key fails the MAC check (code 'mac'). */
export async function decryptType2(encString, key) {
  const m = /^2\.([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)\|([A-Za-z0-9+/=]+)$/.exec(String(encString ?? '').trim());
  if (!m) throw new ExportCryptoError('not an EncString of type 2', 'format');
  const [iv, ct, mac] = m.slice(1).map(fromB64);
  if (iv.length !== 16 || mac.length !== 32 || !ct.length || ct.length % 16) throw new ExportCryptoError('bad EncString', 'format');
  if (!equalBytes(await hmac(key.mac, concat(iv, ct)), mac)) throw new ExportCryptoError('MAC mismatch', 'mac');
  const k = await subtle.importKey('raw', key.enc, 'AES-CBC', false, ['decrypt']);
  try {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, k, ct));
  } catch { throw new ExportCryptoError('bad padding', 'format'); }
}

/**
 * Password-protected Bitwarden JSON from the unencrypted export `json` (string). `kdf`: EXPORT_KDF.argon2id (default)
 * or EXPORT_KDF.pbkdf2, or own values in the same shape.
 */
export async function encryptBitwardenJson(json, password, kdf = EXPORT_KDF.argon2id) {
  if (!password) throw new ExportCryptoError('password missing', 'password');
  const salt = b64(globalThis.crypto.getRandomValues(new Uint8Array(16)));
  const key = await deriveExportKey(password, salt, kdf);
  const argon = kdf.kdfType === 1;
  return JSON.stringify({
    encrypted: true,
    passwordProtected: true,
    salt,
    kdfType: kdf.kdfType,
    kdfIterations: kdf.kdfIterations,
    kdfMemory: argon ? kdf.kdfMemory : null,
    kdfParallelism: argon ? kdf.kdfParallelism : null,
    encKeyValidation_DO_NOT_EDIT: await encryptType2(globalThis.crypto.randomUUID(), key),
    data: await encryptType2(json, key),
  }, null, 2);
}

/** True for a password-protected Bitwarden JSON export (parsed). */
export const isPasswordProtected = (doc) => doc?.encrypted === true && doc.passwordProtected === true;

/**
 * Opens a password-protected Bitwarden JSON export (parsed object) → the unencrypted JSON (string).
 * Errors (ExportCryptoError): 'bad_password', 'kdf' (unknown or out of bounds), 'format' (damaged file).
 */
export async function decryptBitwardenJson(doc, password) {
  if (!isPasswordProtected(doc) || typeof doc.salt !== 'string' || typeof doc.data !== 'string' || typeof doc.encKeyValidation_DO_NOT_EDIT !== 'string') {
    throw new ExportCryptoError('not a password-protected export', 'format');
  }
  const kdf = {
    kdfType: doc.kdfType ?? 0, // the first files of this format had PBKDF2 only and no kdfType
    kdfIterations: Number(doc.kdfIterations), kdfMemory: Number(doc.kdfMemory), kdfParallelism: Number(doc.kdfParallelism),
  };
  const within = (v, [lo, hi]) => Number.isInteger(v) && v >= lo && v <= hi;
  const ok = kdf.kdfType === 0 ? within(kdf.kdfIterations, KDF_BOUNDS.pbkdf2)
    : kdf.kdfType === 1 && within(kdf.kdfIterations, KDF_BOUNDS.argon2Iterations) && within(kdf.kdfMemory, KDF_BOUNDS.argon2Memory)
      && within(kdf.kdfParallelism, KDF_BOUNDS.argon2Parallelism);
  if (!ok) throw new ExportCryptoError(`kdf ${JSON.stringify(kdf)}`, 'kdf');
  const key = await deriveExportKey(password, doc.salt, kdf);
  try {
    await decryptType2(doc.encKeyValidation_DO_NOT_EDIT, key);
  } catch (e) {
    throw e.code === 'mac' ? new ExportCryptoError('wrong password', 'bad_password') : e;
  }
  const plain = await decryptType2(doc.data, key).catch((e) => { throw new ExportCryptoError(e.message, 'format'); });
  return fromUtf8(plain);
}
