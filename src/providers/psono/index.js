// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Psono (self-hosted or psono.pw), spoken to directly over its REST API, end-to-end encrypted as Psono's own
// clients do it (see crypto.js, api.js). Sign-in: scrypt "authkey" instead of the password, a fresh session key pair,
// optional second factor (authenticator app, YubiKey OTP, Duo passcode); the decrypted account keys live only in
// storage.session. The password datastore is a tree of folders and entries (each pointing to a secret with its own
// key); shared folders and entries are separate "shares" with their own key. Secrets are read in parallel during a
// sync, but only the non-secret fields stay in the cache – passwords are read again when needed (lazy).
// Writes: secrets are updated with the server's write-date check; the tree (datastore or share) is changed node by
// node on a fresh copy, again with the write-date check (one retry on a conflict). Deleting moves an entry to Psono's
// trash (the "deleted" flag the web client uses), from where it can be restored or removed for good.
import { mark, t, tn } from '../../i18n/index.js';
import { Provider, ProviderError } from '../provider.js';
import { apiBase, request, serverInfo } from './api.js';
import {
  authkey, checkParams, decryptBox, decryptSymmetric, encryptBox, encryptSymmetric, generateKeyPair, passwordKey,
  PsonoCryptoError, randomKey,
} from './crypto.js';

/** Limits of one sync. */
export const LIMITS = { entries: 2000, shares: 200, depth: 24, parallel: 4 };
/** Session length asked for (the server caps it); afterwards the account locks and asks for the password again. */
export const SESSION_SECONDS = 12 * 3600;

/** Second factors OmniVault can answer, in the order offered. */
const FACTORS = {
  google_authenticator_2fa: { path: 'authentication/ga-verify/', field: 'ga_token', label: mark('Authenticator-App (TOTP)') },
  yubikey_otp_2fa: { path: 'authentication/yubikey-otp-verify/', field: 'yubikey_otp', brand: 'YubiKey OTP' },
  duo_2fa: { path: 'authentication/duo-verify/', field: 'duo_token', label: mark('Duo (Passcode)') },
};

/** Entry types OmniVault edits; every other type is shown read-only. */
const EDITABLE = new Set(['website_password', 'application_password', 'note']);
/** Per-type fields that are not shown as custom fields (the role fields are mapped, the rest is bookkeeping). */
const ROLE_SUFFIXES = ['title', 'username', 'password', 'url', 'notes', 'url_filter', 'auto_submit', 'allow_http',
  'totp_code', 'totp_period', 'totp_algorithm', 'totp_digits', 'code', 'period', 'algorithm', 'digits'];

const str = (v) => (v == null ? '' : typeof v === 'string' ? v : JSON.stringify(v));
const uuid = () => crypto.randomUUID();

/** Host (with port) of an address, as Psono keeps it in url_filter. */
export function urlFilter(url) {
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`).host; } catch { return ''; }
}

/** TOTP secret + parameters → what OmniVault keeps (base32, or an otpauth:// URI for non-default parameters). */
export function totpFrom(code, { period, algorithm, digits } = {}) {
  const secret = str(code).trim();
  if (!secret) return undefined;
  if (/^otpauth:\/\//i.test(secret)) return secret;
  const alg = str(algorithm || 'SHA1').toUpperCase().replace('-', '');
  const p = Number(period) || 30;
  const d = Number(digits) || 6;
  if (p === 30 && d === 6 && alg === 'SHA1') return secret.replace(/\s/g, '').toUpperCase();
  const q = new URLSearchParams({ secret: secret.replace(/[\s=]/g, '').toUpperCase(), period: String(p), digits: String(d), algorithm: alg });
  return `otpauth://totp/OTP?${q}`;
}

/** OmniVault's TOTP (base32 or otpauth://) → Psono's fields. */
export function totpTo(totp) {
  const s = str(totp).trim();
  if (!s) return { code: '' };
  if (!/^otpauth:\/\//i.test(s)) return { code: s.replace(/\s/g, '').toUpperCase(), period: 30, algorithm: 'SHA1', digits: 6 };
  const u = new URL(s);
  const p = u.searchParams;
  return {
    code: (p.get('secret') ?? '').replace(/[\s=]/g, '').toUpperCase(),
    period: Number(p.get('period') ?? 30) || 30,
    algorithm: (p.get('algorithm') ?? 'SHA1').toUpperCase().replace('-', ''),
    digits: Number(p.get('digits') ?? 6) || 6,
  };
}

const FIELD_TYPES = { password: 'hidden', checkbox: 'boolean', text: 'text' };
const FIELD_TYPES_BACK = { hidden: 'password', boolean: 'checkbox', text: 'text' };

/** Card expiry "MM / YY" (Psono's format) → month and year. */
function expiry(v) {
  const m = /^\s*(\d{1,2})\s*\/\s*(\d{2,4})\s*$/.exec(str(v));
  if (!m) return {};
  return { expMonth: String(Number(m[1])), expYear: m[2].length === 2 ? `20${m[2]}` : m[2] };
}

/**
 * Decrypted secret content of a datastore entry → item fields. Website and application passwords become logins,
 * notes notes, cards and identities their own types; other types (keys, connections, …) show their username/password
 * where they have one and all their remaining values as hidden custom fields.
 */
export function mapSecret(type, content = {}, nodeName = '') {
  const c = content && typeof content === 'object' ? content : {};
  const f = (suffix) => c[`${type}_${suffix}`];
  const name = str(f('title')) || nodeName || '';
  const fields = [];
  for (const cf of Array.isArray(c.custom_fields) ? c.custom_fields : []) {
    if (!cf || typeof cf !== 'object') continue;
    const ft = FIELD_TYPES[cf.type] ?? 'text';
    fields.push({ name: str(cf.name), value: ft === 'boolean' ? String(cf.value === true || cf.value === 'true') : str(cf.value), type: ft });
  }
  const base = { name, notes: str(f('notes')) || undefined, fields };
  if (type === 'note') return { ...base, type: 'note' };
  if (type === 'credit_card') {
    const extra = [];
    if (f('pin')) extra.push({ name: 'PIN', value: str(f('pin')), type: 'hidden' });
    return {
      ...base, type: 'card', fields: [...extra, ...fields],
      card: { cardholderName: str(f('name')), number: str(f('number')), code: str(f('cvc')), brand: '', ...expiry(f('valid_through')) },
    };
  }
  if (type === 'identity') {
    return {
      ...base, type: 'identity',
      identity: {
        firstName: str(f('first_name')), lastName: str(f('last_name')), company: str(f('company')), address1: str(f('address')),
        postalCode: str(f('postal_code')), city: str(f('city')), state: str(f('state')), country: str(f('country')),
        phone: str(f('phone_number')), email: str(f('email')),
      },
    };
  }
  // logins and everything else: role fields where the type has them, other values as hidden fields
  const prefix = `${type}_`;
  const known = new Set(ROLE_SUFFIXES.map((s) => prefix + s));
  if (type !== 'website_password' && type !== 'application_password' && type !== 'totp' && type !== 'bookmark') {
    for (const [k, v] of Object.entries(c)) {
      if (!k.startsWith(prefix) || known.has(k) || v == null || v === '' || typeof v === 'object') continue;
      fields.push({ name: k.slice(prefix.length).replace(/_/g, ' '), value: str(v), type: 'hidden' });
    }
  }
  const url = str(f('url'));
  const totp = type === 'totp'
    ? totpFrom(f('code'), { period: f('period'), algorithm: f('algorithm'), digits: f('digits') })
    : totpFrom(f('totp_code'), { period: f('totp_period'), algorithm: f('totp_algorithm'), digits: f('totp_digits') });
  const username = str(f('username')) || undefined;
  const password = str(f('password')) || undefined;
  const isLogin = type === 'website_password' || type === 'application_password' || type === 'totp' || type === 'bookmark' || !!(username || password);
  return {
    ...base,
    type: isLogin ? 'login' : 'note',
    username, password, totp,
    uris: url ? [url] : [],
  };
}

/**
 * Editor data → new secret content for an entry of `type`, starting from the stored content so that values OmniVault
 * does not show (auto-submit, attachments, history, other clients' fields) survive.
 */
export function buildSecret(type, data, previous = {}) {
  const out = { ...(previous && typeof previous === 'object' ? previous : {}) };
  const set = (suffix, value) => { out[`${type}_${suffix}`] = value; };
  set('title', str(data.name));
  if (data.notes !== undefined) set('notes', str(data.notes));
  if (type === 'website_password' || type === 'application_password') {
    set('username', str(data.username));
    set('password', str(data.password));
    if (type === 'website_password') {
      const url = (data.uris ?? []).find(Boolean) ?? '';
      set('url', url);
      set('url_filter', url ? urlFilter(url) : '');
      if (out.website_password_auto_submit === undefined) out.website_password_auto_submit = false;
    }
    const totp = totpTo(data.totp);
    if (totp.code) {
      set('totp_code', totp.code); set('totp_period', totp.period); set('totp_algorithm', totp.algorithm); set('totp_digits', totp.digits);
    } else {
      for (const s of ['totp_code', 'totp_period', 'totp_algorithm', 'totp_digits']) delete out[`${type}_${s}`];
    }
  }
  if (Array.isArray(data.fields)) {
    const fields = data.fields.filter((x) => x && (x.name || x.value)).map((x) => ({
      name: str(x.name), value: x.type === 'boolean' ? (x.value === true || x.value === 'true') : str(x.value), type: FIELD_TYPES_BACK[x.type] ?? 'text',
    }));
    if (fields.length) out.custom_fields = fields; else delete out.custom_fields;
  }
  if (data.password !== undefined && previous?.[`${type}_password`] !== undefined && previous[`${type}_password`] !== out[`${type}_password`]) {
    out.password_modification_datetime = new Date().toISOString();
  }
  return out;
}

/* ---------- datastore tree ---------- */

/** Folder ids carry where the folder lives: "<container>" or "<container>/<folder id>/<folder id>…". */
const containerKey = (kind, id) => `${kind === 'datastore' ? 'ds' : 'sh'}:${id}`;
export function folderRef(container, path) { return [container, ...path].join('/'); }
export function parseFolderRef(ref) {
  const [container, ...path] = String(ref ?? '').split('/');
  if (!/^(ds|sh):[0-9a-f-]{36}$/i.test(container)) return null;
  return { container, path };
}

/** The folder `path` (list of folder ids) inside a tree; null when one of them is gone. */
function folderAt(tree, path) {
  let node = tree;
  for (const id of path) {
    node = (node.folders ?? []).find((f) => f.id === id);
    if (!node) return null;
  }
  return node;
}

/** Runs fn over items with at most `n` at a time. */
async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; await fn(items[k], k); }
  }));
}

function cryptoFailure() {
  return new ProviderError(t('Daten des Servers ließen sich nicht entschlüsseln.'), 'server');
}

class PsonoProvider extends Provider {
  static id = 'psono';
  static label = 'Psono';
  static status = 'ready';
  static note = mark('Psono-Server (selbst betrieben oder psono.pw). Benutzername und Passwort wie in Psono; die Ende-zu-Ende-Verschlüsselung bleibt erhalten.');
  static capabilities = {
    write: true, types: ['login', 'note'], fields: true, favorites: false, createFolder: true, moveFolder: true,
    trash: true, restore: true,
  };
  static configFields = [
    {
      name: 'server', label: mark('Server-Adresse'), type: 'url', required: true, placeholder: 'https://psono.example.org/server',
      hint: mark('Adresse der Psono-API, meist mit „/server“ am Ende (psono.pw: https://www.psono.pw/server).'),
    },
    { name: 'username', label: mark('Benutzername'), type: 'text', required: true, placeholder: 'name@example.org' },
  ];

  /** Called with the number of entries read so far during a sync (set by the background page). */
  static onProgress = null;

  /* ---------- sign-in ---------- */

  /** Finds the API: the address as given, else with "/server" appended (where Psono's installations put it). */
  static async #discover(config) {
    const base = apiBase(config.server);
    try {
      return { base, ...await serverInfo(base, config.serverVerifyKey) };
    } catch (e) {
      if (e.code !== 'not_psono' && !(e.code === 'server' && /HTTP 404/.test(e.message))) throw e;
      if (/\/server$/i.test(base)) throw e;
      try {
        return { base: `${base}/server`, ...await serverInfo(`${base}/server`, config.serverVerifyKey) };
      } catch { throw e; }
    }
  }

  static async login(config, creds) {
    if (creds.pending?.kind === 'psono') return this.#secondFactor(config, creds);
    const password = String(creds.password ?? '');
    if (!password) throw new ProviderError(t('Bitte Passwort eingeben'), 'bad_password');
    const username = String(config.username ?? '').trim().toLowerCase();
    if (!username) throw new ProviderError(t('Bitte den Benutzernamen im Konto eintragen'), 'config');

    const { base, info, verifyKey } = await this.#discover(config);
    const configPatch = {};
    if (!config.serverVerifyKey) configPatch.serverVerifyKey = verifyKey;
    if (base !== apiBase(config.server)) configPatch.server = base;
    const deviceId = config.deviceId || uuid();
    if (!config.deviceId) configPatch.deviceId = deviceId;

    // the account's scrypt parameters (servers before the prelogin endpoint use the defaults)
    let pre = null;
    try {
      pre = await request(base, 'authentication/prelogin/', { method: 'POST', body: { username } });
    } catch (e) {
      if (!['not_psono', 'server', 'forbidden'].includes(e.code)) throw e;
    }
    let params;
    try { params = checkParams(pre?.hashing_algorithm, pre?.hashing_parameters); } catch (e) {
      throw new ProviderError(t('Nicht unterstützte Schlüsselableitung: {error}', { error: e.message }), 'unsupported');
    }

    const keys = generateKeyPair();
    const loginInfo = encryptBox(JSON.stringify({
      username,
      authkey: await authkey(username, password, params),
      device_time: new Date().toISOString(),
      device_fingerprint: deviceId,
      device_description: 'OmniVault',
    }), info.public_key, keys.privateKey);
    const r = await request(base, 'authentication/login/', {
      method: 'POST',
      body: { login_info: loginInfo.text, login_info_nonce: loginInfo.nonce, public_key: keys.publicKey, session_duration: SESSION_SECONDS },
    });
    let data;
    try { data = JSON.parse(decryptBox(r.login_info, r.login_info_nonce, info.public_key, keys.privateKey)); } catch { throw cryptoFailure(); }
    const user = data.user ?? {};
    if (user.authentication && user.authentication !== 'AUTHKEY') {
      throw new ProviderError(t('Dieses Psono-Konto meldet sich über {method} an; das unterstützt OmniVault nicht.', { method: user.authentication }), 'unsupported');
    }
    let pwKey, userPrivateKey, secretKey, validator;
    try {
      pwKey = await passwordKey(password, user.user_sauce, checkParams(user.hashing_algorithm, user.hashing_parameters));
      userPrivateKey = decryptSymmetric(pwKey, user.private_key, user.private_key_nonce);
      secretKey = decryptBox(data.session_secret_key, data.session_secret_key_nonce, data.session_public_key, keys.privateKey);
      // only the holder of the account's private key can read this; returning it activates the session
      validator = decryptBox(data.user_validator, data.user_validator_nonce, data.session_public_key, userPrivateKey);
    } catch (e) {
      if (e instanceof PsonoCryptoError) throw cryptoFailure();
      throw e;
    }
    const pending = {
      kind: 'psono', base, token: data.token, secretKey, deviceId, validator, pwKey, userPrivateKey,
      userPublicKey: user.public_key, username, expiresAt: Date.parse(data.session_valid_till) || Date.now() + SESSION_SECONDS * 1000,
      factors: (data.required_multifactors ?? []).filter(Boolean),
    };
    if (pending.factors.length && !creds.twoFactorCode) return this.#askFactor(pending, configPatch);
    const res = await this.#secondFactor(config, { ...creds, pending });
    return { ...res, configPatch: { ...configPatch, ...res.configPatch } };
  }

  static #askFactor(pending, configPatch) {
    const usable = pending.factors.filter((f) => FACTORS[f]);
    if (!usable.length) {
      throw new ProviderError(t('Nur nicht unterstützte MFA-Methoden aktiv: {methods}', { methods: pending.factors.join(', ') }), 'unsupported');
    }
    return {
      status: 'needs_2fa', configPatch, pending,
      twoFactorProviders: usable.map((id) => ({ id, label: FACTORS[id].brand ?? t(FACTORS[id].label) })),
    };
  }

  /** Answers a second factor (if one is due) and activates the session. */
  static async #secondFactor(config, creds) {
    const p = creds.pending;
    const session = { token: p.token, secretKey: p.secretKey, deviceId: p.deviceId };
    if (p.factors.length) {
      const id = FACTORS[creds.twoFactorProvider] ? creds.twoFactorProvider : p.factors.find((f) => FACTORS[f]);
      const code = String(creds.twoFactorCode ?? '').replace(/\s/g, '');
      if (!id || !p.factors.includes(id)) return this.#askFactor(p);
      if (!code) throw new ProviderError(t('Bitte den Code eingeben.'), 'bad_2fa');
      try {
        await request(p.base, FACTORS[id].path, { method: 'POST', session, body: { [FACTORS[id].field]: code } });
      } catch (e) {
        // a wrong code: the half-open session stays for another try
        if (e.code === 'bad_2fa' || e.code === 'server') {
          const err = new ProviderError(e.code === 'bad_2fa' ? e.message : t('Code falsch'), 'bad_2fa');
          throw err;
        }
        throw e;
      }
      p.factors = p.factors.filter((f) => f !== id);
    }
    const verification = encryptSymmetric(p.secretKey, p.validator);
    let r;
    try {
      r = await request(p.base, 'authentication/activate-token/', {
        method: 'POST', session, body: { verification: verification.text, verification_nonce: verification.nonce },
      });
    } catch (e) {
      // with MULTIFACTOR_ENABLED, Psono wants every factor the account has: ask for the next one
      if (/_CHALLENGE_UNSOLVED$/.test(e.serverCode ?? '') && p.factors.length) return this.#askFactor(p);
      throw e;
    }
    let userSecretKey;
    try { userSecretKey = decryptSymmetric(p.pwKey, r.user.secret_key, r.user.secret_key_nonce); } catch { throw cryptoFailure(); }
    return {
      status: 'ok',
      session: {
        base: p.base, token: p.token, secretKey: p.secretKey, deviceId: p.deviceId,
        userSecretKey, userPrivateKey: p.userPrivateKey, userPublicKey: p.userPublicKey, username: p.username,
        expiresAt: p.expiresAt,
      },
    };
  }

  /** Ends the server session (on lock); failures do not matter. */
  static async logout(config, session) {
    if (!session?.token) return;
    await request(session.base ?? apiBase(config.server), 'authentication/logout/', { method: 'POST', session, body: {} }).catch(() => {});
  }

  static #api(config, session) {
    if (!session?.token || !session.userSecretKey) throw new ProviderError(t('Tresor gesperrt'), 'session_expired');
    if (session.expiresAt && Date.now() >= session.expiresAt) throw new ProviderError(t('Sitzung abgelaufen – bitte neu anmelden'), 'session_expired');
    const base = session.base ?? apiBase(config.server);
    return (path, opts = {}) => request(base, path, { ...opts, session });
  }

  /* ---------- reading ---------- */

  /** The password datastore OmniVault shows: the default one, else the first. Null when the account has none yet. */
  static async #datastoreId(call) {
    const r = await call('datastore/');
    const stores = (r?.datastores ?? []).filter((d) => d.type === 'password');
    return (stores.find((d) => d.is_default) ?? stores[0])?.id ?? null;
  }

  /** Reads a container (datastore or share): { key, tree, writeDate, writable }. */
  static async #readContainer(call, session, container, shareKey) {
    const [kind, id] = container.split(':');
    try {
      if (kind === 'ds') {
        const r = await call(`datastore/${id}/`);
        const key = decryptSymmetric(session.userSecretKey, r.secret_key, r.secret_key_nonce);
        const tree = r.data ? JSON.parse(decryptSymmetric(key, r.data, r.data_nonce)) : {};
        return { key, tree: tree && typeof tree === 'object' ? tree : {}, writeDate: r.write_date, writable: true };
      }
      const r = await call(`share/${id}/`);
      const tree = r.data ? JSON.parse(decryptSymmetric(shareKey, r.data, r.data_nonce)) : {};
      return { key: shareKey, tree: tree && typeof tree === 'object' ? tree : {}, writeDate: r.write_date, writable: !!r.rights?.write };
    } catch (e) {
      if (e instanceof PsonoCryptoError || e instanceof SyntaxError) throw cryptoFailure();
      throw e;
    }
  }

  /**
   * Walks the datastore and every share in it. Returns the entries (with where they live), the folders and the keys of
   * the shares (needed to write into them).
   */
  static async #walk(call, session) {
    const dsId = await this.#datastoreId(call);
    const out = { dsId, entries: [], trash: [], folders: [], shares: {}, skipped: 0, truncated: false };
    if (!dsId) return out;
    const root = containerKey('datastore', dsId);
    const containers = { [root]: await this.#readContainer(call, session, root) };
    const seen = new Set();
    const visit = async (node, ctx, depth) => {
      if (depth > LIMITS.depth) { out.truncated = true; return; }
      for (const f of Array.isArray(node.folders) ? node.folders : []) {
        if (!f || typeof f !== 'object' || f.deleted) continue;
        const names = [...ctx.names, str(f.name) || '?'];
        if (f.share_id && f.share_secret_key) {
          const share = await loadShare(f.share_id, f.share_secret_key);
          if (!share) continue;
          const c = containerKey('share', f.share_id);
          out.folders.push({ id: folderRef(c, []), name: names.join('/'), canWrite: share.writable });
          await visit(share.tree, { container: c, path: [], names, writable: share.writable }, depth + 1);
        } else {
          const path = [...ctx.path, f.id];
          out.folders.push({ id: folderRef(ctx.container, path), name: names.join('/'), canWrite: ctx.writable });
          await visit(f, { ...ctx, path, names }, depth + 1);
        }
      }
      for (const it of Array.isArray(node.items) ? node.items : []) {
        if (!it || typeof it !== 'object') continue;
        let entry = it;
        let loc = { container: ctx.container, path: ctx.path, nodeId: it.id };
        let writable = ctx.writable;
        if (it.share_id && it.share_secret_key) {
          const share = await loadShare(it.share_id, it.share_secret_key);
          if (!share) continue;
          entry = share.tree;
          loc = { container: containerKey('share', it.share_id), path: [], nodeId: null, parent: { ...loc } };
          writable = share.writable;
        }
        if (!entry.secret_id || !entry.secret_key) continue;
        if (out.entries.length + out.trash.length >= LIMITS.entries) { out.truncated = true; return; }
        const record = {
          id: it.id, name: str(entry.name ?? it.name), type: str(entry.type ?? it.type), urlfilter: str(entry.urlfilter ?? it.urlfilter),
          secretId: entry.secret_id, secretKey: entry.secret_key, loc, writable,
          folderId: ctx.names.length ? folderRef(ctx.container, ctx.path) : null, folder: ctx.names.join('/') || undefined,
        };
        (it.deleted || entry.deleted ? out.trash : out.entries).push(record);
      }
    };
    const loadShare = async (shareId, shareKey) => {
      const c = containerKey('share', shareId);
      if (seen.has(c)) return null; // a share linked twice (or into itself) is shown once
      seen.add(c);
      if (seen.size > LIMITS.shares) { out.truncated = true; return null; }
      try {
        containers[c] = await this.#readContainer(call, session, c, shareKey);
      } catch (e) {
        if (e.code !== 'forbidden' && e.code !== 'server') throw e;
        out.skipped++; return null; // a share whose right was taken away
      }
      out.shares[c] = shareKey;
      return containers[c];
    };
    await visit(containers[root].tree, { container: root, path: [], names: [], writable: true }, 0);
    // folders with the same path (two shares with one name) stay apart in the list
    out.folders.sort((a, b) => a.name.localeCompare(b.name));
    return out;
  }

  /** Reads and decrypts one secret: { content, writeDate } or null when it is gone. */
  static async #readSecret(call, secretId, secretKey) {
    let r;
    try { r = await call(`secret/${secretId}/`); } catch (e) {
      if (e.code === 'forbidden') return null;
      throw e;
    }
    try {
      const content = JSON.parse(decryptSymmetric(secretKey, r.data, r.data_nonce));
      return { content: content && typeof content === 'object' ? content : {}, writeDate: r.write_date };
    } catch { throw cryptoFailure(); }
  }

  /** Item for a datastore entry. Secret values are kept only when `full`. */
  static #item(config, rec, secret, full) {
    const m = mapSecret(rec.type, secret?.content ?? {}, rec.name);
    const editable = EDITABLE.has(rec.type) && rec.writable;
    const base = {
      id: rec.id, accountId: config.id, provider: 'psono', type: m.type, name: rec.name || m.name,
      username: m.username, uris: m.uris ?? (rec.urlfilter ? [`https://${rec.urlfilter}`] : []),
      folderId: rec.folderId, folder: rec.folder, favorite: false,
      canEdit: editable, canDelete: editable || (rec.writable && !!rec.loc.nodeId),
      revisionDate: secret?.writeDate || undefined,
      _psono: { type: rec.type, secretId: rec.secretId, secretKey: rec.secretKey, loc: rec.loc, writable: rec.writable },
    };
    if (!full) return { ...base, lazy: true, hasPassword: !!m.password, hasTotp: !!m.totp };
    return {
      ...base, password: m.password, totp: m.totp, notes: m.notes, fields: m.fields, card: m.card, identity: m.identity,
      _psono: { ...base._psono, writeDate: secret?.writeDate },
    };
  }

  static async sync(config, session) {
    const call = this.#api(config, session);
    const tree = await this.#walk(call, session);
    const items = [];
    let done = 0;
    let gone = 0;
    await pool(tree.entries, LIMITS.parallel, async (rec) => {
      const secret = await this.#readSecret(call, rec.secretId, rec.secretKey);
      done++;
      if (done % 10 === 0 || done === tree.entries.length) this.onProgress?.(config.id, done, tree.entries.length);
      if (!secret) { gone++; return; }
      items.push(this.#item(config, rec, secret, false));
    });
    items.sort((a, b) => a.name.localeCompare(b.name));
    const trash = tree.trash.map((rec) => ({ ...this.#item(config, rec, null, false), lazy: false, hasPassword: false, deletedDate: undefined }));
    const warning = [
      tree.truncated ? t('Nur ein Teil geladen: höchstens {n} Einträge', { n: LIMITS.entries }) : '',
      tree.skipped + gone ? tn(tree.skipped + gone, '{n} Eintrag ohne Leserecht übersprungen', '{n} Einträge ohne Leserecht übersprungen') : '',
    ].filter(Boolean).join('; ') || undefined;
    return { items, trash, folders: tree.folders.map(({ id, name }) => ({ id, name })), warning };
  }

  static async reveal(config, session, item) {
    const call = this.#api(config, session);
    const p = item._psono;
    const secret = await this.#readSecret(call, p.secretId, p.secretKey);
    if (!secret) throw new ProviderError(t('Eintrag nicht gefunden oder Tresor gesperrt'), 'not_found');
    const full = this.#item(config, { ...p, id: item.id, name: item.name, folderId: item.folderId, folder: item.folder, writable: p.writable, urlfilter: '' }, secret, true);
    return {
      username: full.username, uris: full.uris, type: full.type, password: full.password, totp: full.totp, notes: full.notes,
      fields: full.fields, card: full.card, identity: full.identity, revisionDate: full.revisionDate, _psono: full._psono,
    };
  }

  /* ---------- writing ---------- */

  /**
   * Changes a container's tree: reads it fresh, lets `change(tree)` edit it in place and writes it back with the
   * write-date check; on a concurrent change it starts over once.
   */
  static async #updateContainer(call, session, container, shareKey, change) {
    for (let attempt = 0; ; attempt++) {
      const c = await this.#readContainer(call, session, container, shareKey);
      if (!c.writable) throw new ProviderError(t('Keine Schreibberechtigung für diesen Ordner'), 'forbidden');
      const result = change(c.tree);
      const enc = encryptSymmetric(c.key, JSON.stringify(c.tree));
      const [kind, id] = container.split(':');
      try {
        // Psono's methods: a datastore is updated with POST, a share with PUT (POST creates one)
        await call(kind === 'ds' ? 'datastore/' : 'share/', {
          method: kind === 'ds' ? 'POST' : 'PUT',
          body: { [kind === 'ds' ? 'datastore_id' : 'share_id']: id, data: enc.text, data_nonce: enc.nonce, old_write_date: c.writeDate },
        });
        return result;
      } catch (e) {
        if (e.serverCode === 'WRITE_DATE_MISMATCH' && attempt === 0) continue;
        if (e.serverCode === 'WRITE_DATE_MISMATCH') throw new ProviderError(t('Der Eintrag wurde inzwischen auf dem Server geändert. Bitte synchronisieren und erneut bearbeiten.'), 'conflict');
        throw e;
      }
    }
  }

  /** The key of a share container, from the datastore (read fresh, so it works after a worker restart as well). */
  static async #shareKey(call, session, container) {
    if (container.startsWith('ds:')) return null;
    const tree = await this.#walk(call, session);
    const key = tree.shares[container];
    if (!key) throw new ProviderError(t('Ordner nicht gefunden – bitte synchronisieren'), 'not_found');
    return key;
  }

  /** A new datastore for an account that has none yet (as the web client creates it on first use). */
  static async #createDatastore(call, session) {
    const key = randomKey();
    const sk = encryptSymmetric(session.userSecretKey, key);
    // empty content, as the web client creates it; the first change writes the tree
    const r = await call('datastore/', {
      method: 'PUT',
      body: { type: 'password', description: 'default', data: '', data_nonce: '', secret_key: sk.text, secret_key_nonce: sk.nonce, is_default: true },
    });
    return r.datastore_id;
  }

  /** Where a folder id points to; null / '' is the datastore's top level. */
  static async #target(call, session, folderId) {
    if (folderId) {
      const ref = parseFolderRef(folderId);
      if (!ref) throw new ProviderError(t('Ordner nicht gefunden – bitte synchronisieren'), 'not_found');
      return ref;
    }
    const dsId = await this.#datastoreId(call) ?? await this.#createDatastore(call, session);
    return { container: containerKey('datastore', dsId), path: [] };
  }

  static async saveItem(config, session, existing, data) {
    const call = this.#api(config, session);
    const name = String(data.name ?? '').trim();
    if (!name) throw new ProviderError(t('Ungültiger Name'), 'config');
    if (existing) return this.#update(config, call, session, existing, { ...data, name });

    const type = data.type === 'note' ? 'note' : 'website_password';
    const target = await this.#target(call, session, data.folderId);
    const shareKey = await this.#shareKey(call, session, target.container);
    const key = randomKey();
    const content = buildSecret(type, { ...data, name });
    const enc = encryptSymmetric(key, JSON.stringify(content));
    const linkId = uuid();
    const [kind, id] = target.container.split(':');
    const r = await call('secret/', {
      method: 'PUT',
      body: {
        data: enc.text, data_nonce: enc.nonce, link_id: linkId, callback_url: '', callback_user: '', callback_pass: '',
        ...(kind === 'ds' ? { parent_datastore_id: id } : { parent_share_id: id }),
      },
    });
    const node = { id: linkId, name, type, secret_id: r.secret_id, secret_key: key };
    if (type === 'website_password') node.urlfilter = content.website_password_url_filter || '';
    try {
      await this.#updateContainer(call, session, target.container, shareKey, (tree) => {
        const folder = folderAt(tree, target.path);
        if (!folder) throw new ProviderError(t('Ordner nicht gefunden – bitte synchronisieren'), 'not_found');
        (folder.items ??= []).push(node);
      });
    } catch (e) {
      await call('secret/link/', { method: 'DELETE', body: { link_id: linkId } }).catch(() => {}); // no orphan
      throw e;
    }
    const rec = {
      id: linkId, name, type, secretId: r.secret_id, secretKey: key, loc: { container: target.container, path: target.path, nodeId: linkId },
      writable: true, folderId: data.folderId || null, folder: undefined,
    };
    return { item: { ...this.#item(config, rec, { content, writeDate: new Date().toISOString() }, true), revealed: true } };
  }

  static async #update(config, call, session, existing, data) {
    const p = existing._psono;
    if (!EDITABLE.has(p.type) || !p.writable) throw new ProviderError(t('Dieser Eintragstyp kann nur gelesen werden.'), 'unsupported');
    // 1. the secret, from its current content (keeps what OmniVault does not show), with the write-date check
    const current = await this.#readSecret(call, p.secretId, p.secretKey);
    if (!current) throw new ProviderError(t('Eintrag nicht gefunden oder Tresor gesperrt'), 'not_found');
    if (p.writeDate && current.writeDate && p.writeDate !== current.writeDate) {
      throw new ProviderError(t('Der Eintrag wurde inzwischen auf dem Server geändert. Bitte synchronisieren und erneut bearbeiten.'), 'conflict');
    }
    const content = buildSecret(p.type, data, current.content);
    const enc = encryptSymmetric(p.secretKey, JSON.stringify(content));
    const r = await call('secret/', {
      method: 'POST',
      body: { secret_id: p.secretId, data: enc.text, data_nonce: enc.nonce, ...(current.writeDate ? { old_write_date: current.writeDate } : {}) },
    }).catch((e) => {
      if (e.serverCode === 'WRITE_DATE_MISMATCH') throw new ProviderError(t('Der Eintrag wurde inzwischen auf dem Server geändert. Bitte synchronisieren und erneut bearbeiten.'), 'conflict');
      throw e;
    });
    // 2. name, address filter and folder live in the tree
    const folderId = data.folderId !== undefined ? data.folderId : existing.folderId;
    const urlfilter = p.type === 'website_password' ? content.website_password_url_filter || '' : undefined;
    let loc = p.loc;
    if (loc.nodeId) {
      const target = (folderId ?? null) === (existing.folderId ?? null) ? { container: loc.container, path: loc.path } : await this.#target(call, session, folderId);
      if (target.container !== loc.container) {
        throw new ProviderError(t('In einen anderen geteilten Ordner kann OmniVault nicht verschieben; bitte in Psono verschieben.'), 'unsupported');
      }
      const shareKey = await this.#shareKey(call, session, loc.container);
      await this.#updateContainer(call, session, loc.container, shareKey, (tree) => {
        const from = folderAt(tree, loc.path);
        const node = from?.items?.find((x) => x.id === loc.nodeId);
        if (!node) throw new ProviderError(t('Eintrag nicht gefunden'), 'not_found');
        node.name = data.name;
        if (urlfilter !== undefined) node.urlfilter = urlfilter;
        if (target.path.join('/') !== loc.path.join('/')) {
          const to = folderAt(tree, target.path);
          if (!to) throw new ProviderError(t('Ordner nicht gefunden – bitte synchronisieren'), 'not_found');
          from.items = from.items.filter((x) => x !== node);
          (to.items ??= []).push(node);
        }
      });
      loc = { ...loc, path: target.path };
    } else {
      // an entry shared on its own: its name sits in the share
      const shareKey = await this.#shareKey(call, session, loc.container);
      await this.#updateContainer(call, session, loc.container, shareKey, (tree) => {
        tree.name = data.name;
        if (urlfilter !== undefined) tree.urlfilter = urlfilter;
      });
    }
    const rec = {
      id: existing.id, name: data.name, type: p.type, secretId: p.secretId, secretKey: p.secretKey, loc, writable: true,
      folderId: loc.nodeId ? (folderId ?? null) : existing.folderId, folder: undefined,
    };
    return { item: { ...this.#item(config, rec, { content, writeDate: r?.write_date }, true), revealed: true } };
  }

  /** Sets or clears Psono's "deleted" (trash) flag on an entry's node. */
  static async #flag(config, session, existing, deleted) {
    const call = this.#api(config, session);
    const { loc } = existing._psono;
    if (!loc.nodeId) throw new ProviderError(t('Einzeln geteilte Einträge bitte in Psono löschen.'), 'unsupported');
    const shareKey = await this.#shareKey(call, session, loc.container);
    await this.#updateContainer(call, session, loc.container, shareKey, (tree) => {
      const node = folderAt(tree, loc.path)?.items?.find((x) => x.id === loc.nodeId);
      if (!node) throw new ProviderError(t('Eintrag nicht gefunden'), 'not_found');
      if (deleted) node.deleted = true; else delete node.deleted;
    });
    return call;
  }

  static async deleteItem(config, session, existing) {
    await this.#flag(config, session, existing, true);
    return { deletedId: existing.id };
  }

  static async restoreItem(config, session, existing) {
    const call = await this.#flag(config, session, existing, false);
    const p = existing._psono;
    const secret = await this.#readSecret(call, p.secretId, p.secretKey);
    const rec = { ...p, id: existing.id, name: existing.name, folderId: existing.folderId, folder: existing.folder, urlfilter: '' };
    return { item: this.#item(config, rec, secret, false) };
  }

  /** Removes an entry from the trash for good: the node goes, and with its link the secret (when no other link has it). */
  static async purgeItem(config, session, existing) {
    const call = this.#api(config, session);
    const { loc } = existing._psono;
    if (!loc.nodeId) throw new ProviderError(t('Einzeln geteilte Einträge bitte in Psono löschen.'), 'unsupported');
    const shareKey = await this.#shareKey(call, session, loc.container);
    await this.#updateContainer(call, session, loc.container, shareKey, (tree) => {
      const folder = folderAt(tree, loc.path);
      if (folder?.items) folder.items = folder.items.filter((x) => x.id !== loc.nodeId);
    });
    await call('secret/link/', { method: 'DELETE', body: { link_id: loc.nodeId } }).catch((e) => {
      if (e.code !== 'forbidden') throw e; // already gone
    });
    return { purgedId: existing.id };
  }

  /** A new folder at the datastore's top level ("a/b" is one folder with that name, as in Psono). */
  static async createFolder(config, session, { name }) {
    const call = this.#api(config, session);
    const clean = String(name ?? '').trim();
    if (!clean || clean.length > 200) throw new ProviderError(t('Ungültiger Name'), 'config');
    const target = await this.#target(call, session, null);
    const id = uuid();
    await this.#updateContainer(call, session, target.container, null, (tree) => {
      (tree.folders ??= []).push({ id, name: clean });
    });
    return { folder: { id: folderRef(target.container, [id]), name: clean } };
  }

  static async setFavorite() {
    throw new ProviderError(t('{provider}: Favoriten werden nicht unterstützt', { provider: this.label }), 'unsupported');
  }
}

export default PsonoProvider;
