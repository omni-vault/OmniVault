// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Bitwarden Send: format read from the public sources of the Bitwarden server, the Bitwarden SDK and Vaultwarden
// (no code taken), implemented here independently.
//
// - Every Send has its own 16 random bytes (the "Send key"). The server stores them encrypted with the user key
//   (`key`); the link carries them in the fragment, so the server never sees them in plain text.
// - Content key: HKDF-SHA256 over the Send key with salt "bitwarden-send" and info "send", 64 bytes
//   (32 AES-256-CBC + 32 HMAC-SHA256). It encrypts name, notes, text and file name (EncString type 2) and the file
//   itself (EncArrayBuffer).
// - Password: PBKDF2-HMAC-SHA256 over the password, salt = the Send key, 100 000 rounds, base64; the server hashes
//   it once more. Recipients present the same value when they ask for access.
// - Link: {web vault}/#/send/{accessId}/{base64url(Send key)}; bitwarden.com uses https://send.bitwarden.com/#{…}.
import { t } from '../../i18n/index.js';
import { b64, b64url, fromB64, utf8 } from '../../lib/bytes.js';
import { ProviderError } from '../provider.js';
import { decryptBuffer, decryptSym, decryptSymString, encryptBuffer, encryptSym, hkdfExpand, hmacSha256, pbkdf2, splitKey } from './crypto.js';

export const SEND_TYPE = { text: 0, file: 1 };
export const SEND_PASSWORD_ITERATIONS = 100_000;
/** Both servers refuse deletion dates further away than 31 days. */
export const MAX_DELETION_DAYS = 31;

/** Content key of a Send from its 16-byte Send key. */
export async function sendContentKey(sendKey) {
  const prk = await hmacSha256(utf8('bitwarden-send'), sendKey);
  return splitKey(await hkdfExpand(prk, 'send', 64));
}

/** What the server and recipients see instead of the password. */
export async function sendPasswordHash(password, sendKey) {
  return b64(await pbkdf2(utf8(password), sendKey, SEND_PASSWORD_ITERATIONS, 32));
}

/** Where recipients open a Send (the web vault of the account's server). */
export function sendLink(ep, accessId, sendKey) {
  const base = ep.vault === 'https://vault.bitwarden.com' ? 'https://send.bitwarden.com/#' : `${ep.vault}/#/send/`;
  return `${base}${accessId}/${b64url(sendKey)}`;
}

/** Splits a Send link into access id and Send key (also accepts the bitwarden.com short form). */
export function parseSendLink(link) {
  const m = /#\/?(?:send\/)?([A-Za-z0-9_-]+)\/([A-Za-z0-9_-]+)\/?$/.exec(String(link).trim());
  if (!m) throw new ProviderError(t('Kein gültiger Send-Link'), 'config');
  const key = fromB64(m[2]);
  if (key.length !== 16) throw new ProviderError(t('Kein gültiger Send-Link'), 'config');
  return { accessId: m[1], key };
}

const encOrNull = (v, key) => (v == null || v === '' ? null : encryptSym(String(v), key));

/** The Send key from a Send as the owner gets it (encrypted with the user key). */
export async function ownerSendKey(raw, userKey) {
  const key = await decryptSym(raw.key, userKey);
  if (key.length !== 16) throw new ProviderError(t('Unbekanntes Send-Format'), 'crypto');
  return key;
}

/**
 * A Send as the owner's list shows it. `text` and `notes` are included; the background hands them to the popup
 * only when a Send is opened for editing.
 */
export async function decryptSend(raw, userKey, ep) {
  const sendKey = await ownerSendKey(raw, userKey);
  const key = await sendContentKey(sendKey);
  const dec = (v) => (v ? decryptSymString(v, key).catch(() => '') : Promise.resolve(''));
  const type = raw.type === SEND_TYPE.file ? 'file' : 'text';
  return {
    id: raw.id,
    accessId: raw.accessId,
    type,
    name: await dec(raw.name),
    notes: await dec(raw.notes),
    text: type === 'text' ? await dec(raw.text?.text) : '',
    hidden: !!raw.text?.hidden,
    fileName: type === 'file' ? await dec(raw.file?.fileName) : '',
    size: type === 'file' ? Number(raw.file?.size) || 0 : 0,
    maxAccessCount: raw.maxAccessCount ?? null,
    accessCount: raw.accessCount ?? 0,
    expirationDate: raw.expirationDate ?? null,
    deletionDate: raw.deletionDate,
    revisionDate: raw.revisionDate ?? null,
    disabled: !!raw.disabled,
    hideEmail: !!raw.hideEmail,
    // Bitwarden names the protection (authType 1 = password); Vaultwarden returns the stored hash
    hasPassword: raw.authType === 1 || (raw.authType == null && !!raw.password),
    link: sendLink(ep, raw.accessId, sendKey),
  };
}

const isoOrNull = (d) => (d ? new Date(d).toISOString() : null);

/**
 * Request body for POST /sends, POST /sends/file/v2 and PUT /sends/{id}. A new Send gets a fresh Send key; an
 * existing one keeps its key (the link must stay valid). Without `password` an existing password stays as it is.
 * No `authType` is sent: both servers then set the password exactly when one is given.
 */
export async function sendRequest(data, { userKey, sendKey, existing = null, fileName = null, fileLength = null }) {
  const type = existing ? existing.type : SEND_TYPE[data.type];
  if (type == null) throw new ProviderError(t('Unbekannte Send-Art'), 'config');
  const name = String(data.name ?? '').trim();
  if (!name) throw new ProviderError(t('Der Send braucht einen Namen.'), 'config');
  if (!data.deletionDate) throw new ProviderError(t('Der Send braucht ein Löschdatum.'), 'config');
  const key = await sendContentKey(sendKey);
  const max = data.maxAccessCount == null || data.maxAccessCount === '' ? null : Number(data.maxAccessCount);
  if (max != null && (!Number.isInteger(max) || max < 1)) throw new ProviderError(t('Die Höchstzahl der Zugriffe muss eine ganze Zahl ab 1 sein.'), 'config');
  const body = {
    type,
    name: await encryptSym(name, key),
    notes: await encOrNull(data.notes, key),
    key: await encryptSym(sendKey, userKey),
    maxAccessCount: max,
    expirationDate: isoOrNull(data.expirationDate),
    deletionDate: isoOrNull(data.deletionDate),
    disabled: !!data.disabled,
    hideEmail: !!data.hideEmail,
    password: data.password ? await sendPasswordHash(data.password, sendKey) : null,
  };
  if (body.expirationDate && body.expirationDate > body.deletionDate) {
    throw new ProviderError(t('Das Ablaufdatum darf nicht nach dem Löschdatum liegen.'), 'config');
  }
  if (type === SEND_TYPE.text) {
    body.text = { text: await encOrNull(data.text, key), hidden: !!data.hidden };
  } else if (existing) {
    body.file = { fileName: existing.file?.fileName ?? null }; // the file itself cannot be changed
  } else {
    body.file = { fileName: await encryptSym(fileName, key) };
    body.fileLength = fileLength;
  }
  return body;
}

/** Encrypts the file of a new file Send. */
export async function encryptSendFile(bytes, sendKey) {
  return encryptBuffer(bytes, await sendContentKey(sendKey));
}

/* ---------- recipient side ---------- */

/** Decrypts what a recipient gets from the access endpoint (text or file metadata). */
export async function decryptSendAccess(access, sendKey) {
  const key = await sendContentKey(sendKey);
  const dec = (v) => (v ? decryptSymString(v, key) : Promise.resolve(''));
  return {
    type: access.type === SEND_TYPE.file ? 'file' : 'text',
    name: await dec(access.name),
    text: await dec(access.text?.text),
    hidden: !!access.text?.hidden,
    fileId: access.file?.id ?? null,
    fileName: await dec(access.file?.fileName),
    expirationDate: access.expirationDate ?? null,
    creatorIdentifier: access.creatorIdentifier ?? null,
  };
}

/** Decrypts a downloaded Send file. */
export async function decryptSendFile(buf, sendKey) {
  return decryptBuffer(buf, await sendContentKey(sendKey));
}
