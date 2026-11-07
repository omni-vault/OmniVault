// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Psono's REST API as its server implements it (psono-server, restapi/urls.py and views/): plain JSON before the
// sign-in; afterwards every request and answer body is encrypted with the session's secret key (secretbox,
// { text, nonce }) and each request carries the token plus an encrypted "validator" (request time and device id)
// that the server checks against replay. The API reference is marked "work in progress", so answers are checked
// for the fields used here and anything else is reported as a server error.
import { t } from '../../i18n/index.js';
import { ProviderError } from '../provider.js';
import { decryptSymmetric, encryptSymmetric, verifySignature } from './crypto.js';

/** Address of the API ("…/server" on most installations), without a trailing slash. */
export function apiBase(server) {
  const s = String(server || '').trim().replace(/\/+$/, '');
  if (!/^https?:\/\/[^/]+/.test(s)) throw new ProviderError(t('Bitte die vollständige Server-Adresse angeben (https://…)'), 'config');
  return s;
}

/** Psono's error codes (validation errors) → messages. */
const MESSAGES = {
  USERNAME_OR_PASSWORD_WRONG: () => [t('Benutzername oder Passwort falsch'), 'bad_password'],
  USER_DISABLED_ASK_ADMIN_TO_ENABLE: () => [t('Das Konto ist deaktiviert. Bitte an die Administration wenden.'), 'forbidden'],
  ACCOUNT_NOT_VERIFIED: () => [t('Die E-Mail-Adresse des Kontos ist noch nicht bestätigt.'), 'forbidden'],
  GA_TOKEN_INCORRECT: () => [t('Code falsch'), 'bad_2fa'],
  YUBIKEY_OTP_INCORRECT: () => [t('Code falsch'), 'bad_2fa'],
  YUBIKEY_TOKEN_INCORRECT: () => [t('Code falsch'), 'bad_2fa'],
  NO_PERMISSION_OR_NOT_EXIST: () => [t('Keine Berechtigung oder nicht vorhanden'), 'forbidden'],
};

/** First message of a DRF error body ({"non_field_errors": [...]}, {"detail": ...}, {"field": [...]}, ...). */
function errorText(json) {
  if (!json || typeof json !== 'object') return '';
  if (typeof json.detail === 'string') return json.detail;
  if (typeof json.message === 'string') return json.message;
  if (json.message && typeof json.message === 'object') return errorText(json.message);
  for (const v of Object.values(json)) {
    if (typeof v === 'string') return v;
    if (Array.isArray(v) && typeof v[0] === 'string') return v[0];
  }
  return '';
}

function failure(status, json) {
  const msg = errorText(json);
  if (MESSAGES[msg]) { const [text, code] = MESSAGES[msg](); return new ProviderError(text, code); }
  if (status === 401) return new ProviderError(t('Sitzung abgelaufen – bitte neu anmelden'), 'session_expired');
  if (status === 429) return new ProviderError(t('Zu viele Anfragen – der Server bremst gerade (Rate-Limit). Bitte etwa eine Minute warten.'), 'rate_limited');
  if (status === 403) return new ProviderError(msg ? t('Zugriff verweigert: {error}', { error: msg }) : t('Keine Berechtigung oder nicht vorhanden'), 'forbidden');
  const err = new ProviderError(t('Server-Fehler: {error}', { error: msg || `HTTP ${status}` }), 'server');
  err.serverCode = msg;
  return err;
}

/**
 * One request. `session` ({ token, secretKey, deviceId, clockOffset }) makes it an authenticated, encrypted one.
 * Returns the (decrypted) JSON answer, or null for an empty one.
 */
export async function request(base, path, { method = 'GET', body, session } = {}) {
  const headers = { Accept: 'application/json' };
  let payload;
  if (session) {
    headers.Authorization = `Token ${session.token}`;
    headers['Authorization-Validator'] = JSON.stringify(encryptSymmetric(session.secretKey, JSON.stringify({
      request_time: new Date().toISOString(),
      request_device_fingerprint: session.deviceId,
    })));
    if (body !== undefined) payload = JSON.stringify(encryptSymmetric(session.secretKey, JSON.stringify(body)));
  } else if (body !== undefined) payload = JSON.stringify(body);
  if (payload !== undefined) headers['Content-Type'] = 'application/json';
  let res;
  try {
    res = await fetch(`${base}/${path.replace(/^\/+/, '')}`, { method, headers, body: payload, credentials: 'omit', cache: 'no-store' });
  } catch (e) {
    throw new ProviderError(t('Server nicht erreichbar ({base}): {error}', { base, error: e.message }), 'network');
  }
  const raw = await res.text();
  let json = null;
  if (raw) {
    try { json = JSON.parse(raw); } catch {
      const err = new ProviderError(t('Keine Psono-API unter {base}', { base }), 'not_psono');
      err.status = res.status;
      throw err;
    }
  }
  // answers to a signed-in request come encrypted, error answers too (unless the token itself was refused)
  if (session && json && typeof json.text === 'string' && typeof json.nonce === 'string') {
    try { json = JSON.parse(decryptSymmetric(session.secretKey, json.text, json.nonce)); } catch {
      throw new ProviderError(t('Server-Antwort ungültig (nicht entschlüsselbar)'), 'server');
    }
  }
  if (!res.ok) throw failure(res.status, json);
  return json;
}

/**
 * The server's signed self-description. The signature is checked with the verify key it comes with; that key and the
 * server's public key are pinned on the first sign-in, so a server that later answers with other keys is refused.
 */
export async function serverInfo(base, pinned) {
  const r = await request(base, 'info/');
  if (typeof r?.info !== 'string' || typeof r.signature !== 'string' || typeof r.verify_key !== 'string') {
    throw new ProviderError(t('Keine Psono-API unter {base}', { base }), 'not_psono');
  }
  if (!verifySignature(r.info, r.signature, r.verify_key)) throw new ProviderError(t('Die Signatur der Server-Information ist ungültig.'), 'server');
  let info;
  try { info = JSON.parse(r.info); } catch { info = null; }
  if (!info || !/^[0-9a-f]{64}$/i.test(info.public_key ?? '')) throw new ProviderError(t('Keine Psono-API unter {base}', { base }), 'not_psono');
  if (pinned && pinned.toLowerCase() !== r.verify_key.toLowerCase()) {
    throw new ProviderError(t('Der Serverschlüssel hat sich geändert (jetzt {fingerprint}). Anmeldung abgebrochen.', { fingerprint: r.verify_key }), 'server_key_changed');
  }
  return { info, verifyKey: r.verify_key.toLowerCase() };
}
