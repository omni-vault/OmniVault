// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// A simulated Psono server for unit tests, written after the server's sources (restapi/views, serializers,
// authentication.py, parsers.py, renderers.py): the endpoints OmniVault uses, with the same encryption, validator
// header, replay window, second factors (incl. MULTIFACTOR_ENABLED) and write-date checks. Its crypto uses
// TweetNaCl and node:crypto's scrypt (OpenSSL), not OmniVault's code. test/psono-real.test.js runs the same flows
// against the real server.
import { createHash, randomUUID, scryptSync } from 'node:crypto';
import nacl from '../vendor/tweetnacl.mjs';
import { totp } from '../src/lib/totp.js';

const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (h) => new Uint8Array(Buffer.from(h, 'hex'));
const utf8 = (s) => new TextEncoder().encode(s);
const str = (b) => new TextDecoder().decode(b);
const sha512 = (s) => createHash('sha512').update(s).digest('hex');
const sha256 = (s) => createHash('sha256').update(s).digest('hex');
const scryptHex = (pw, salt, { u, r, p, l }) => scryptSync(pw, salt, l, { N: 2 ** u, r, p, maxmem: 2 ** 31 }).toString('hex');

export function secretbox(keyHex, text) {
  const nonce = nacl.randomBytes(24);
  return { text: hex(nacl.secretbox(utf8(text), nonce, unhex(keyHex))), nonce: hex(nonce) };
}
export function openSecretbox(keyHex, textHex, nonceHex) {
  const out = nacl.secretbox.open(unhex(textHex), unhex(nonceHex), unhex(keyHex));
  if (!out) throw new Error('secretbox: decryption failed');
  return str(out);
}
const box = (text, pubHex, privHex) => {
  const nonce = nacl.randomBytes(24);
  return { text: hex(nacl.box(utf8(text), nonce, unhex(pubHex), unhex(privHex))), nonce: hex(nonce) };
};
const openBox = (textHex, nonceHex, pubHex, privHex) => {
  const out = nacl.box.open(unhex(textHex), unhex(nonceHex), unhex(pubHex), unhex(privHex));
  return out && str(out);
};
const randomKey = () => hex(nacl.randomBytes(32));
export const PARAMS = { u: 14, r: 8, p: 1, l: 64 };

/**
 * opts: { users: [{ username, password, ga?: base32, yubikey?: otp }], multifactor, prefix ('' or '/server'),
 *         serverSeed (32 bytes hex, fixes the server keys) }.
 * Returns { fetch, state, addUser, helpers }.
 */
export function fakePsono({ origin = 'https://psono.test', prefix = '/server', multifactor = false, serverSeed, replayWindow = 20 } = {}) {
  const seed = serverSeed ? unhex(serverSeed) : nacl.randomBytes(32);
  const serverBox = nacl.box.keyPair.fromSecretKey(seed);
  const signing = nacl.sign.keyPair.fromSeed(seed);
  const info = JSON.stringify({ version: '7.5.7 (fake)', api: 1, public_key: hex(serverBox.publicKey), authentication_methods: ['AUTHKEY'], multifactor_enabled: multifactor });
  const signature = hex(nacl.sign.detached(utf8(info), signing.secretKey));

  const state = {
    users: new Map(), tokens: new Map(), datastores: new Map(), shares: new Map(), secrets: new Map(), links: new Map(),
    log: [], logins: 0, clock: () => Date.now(),
  };

  function addUser({ username, password, ga, yubikey, params = PARAMS, authentication = 'AUTHKEY' }) {
    const sauce = randomKey();
    const pk = sha256(scryptHex(password, sha512(sauce), params));
    const kp = nacl.box.keyPair();
    const secretKey = randomKey();
    const encPriv = secretbox(pk, hex(kp.secretKey));
    const encSecret = secretbox(pk, secretKey);
    const user = {
      id: randomUUID(), username: username.toLowerCase(), authkey: scryptHex(password, sha512(username.toLowerCase()), params),
      public_key: hex(kp.publicKey), private_key: encPriv.text, private_key_nonce: encPriv.nonce,
      secret_key: encSecret.text, secret_key_nonce: encSecret.nonce, user_sauce: sauce, hashing_algorithm: 'scrypt',
      hashing_parameters: params, authentication, ga, yubikey, _secretKey: secretKey, _privateKey: hex(kp.secretKey),
    };
    state.users.set(user.username, user);
    return user;
  }

  /** Datastore of a user; `tree` is stored as-is (encrypted with a fresh datastore key). */
  function addDatastore(user, tree = null, { isDefault = true, type = 'password' } = {}) {
    const key = randomKey();
    const sk = secretbox(user._secretKey, key);
    const data = tree ? secretbox(key, JSON.stringify(tree)) : { text: '', nonce: '' };
    const ds = { id: randomUUID(), user: user.id, type, description: 'default', is_default: isDefault, key, secret_key: sk.text, secret_key_nonce: sk.nonce, data: data.text, data_nonce: data.nonce, write_date: new Date().toISOString() };
    state.datastores.set(ds.id, ds);
    return ds;
  }
  /** A secret plus the datastore node pointing to it (the node id is the secret link's id). */
  function addEntry(type, name, content, extra = {}) {
    const key = randomKey();
    const enc = secretbox(key, JSON.stringify(content));
    const id = randomUUID();
    const linkId = randomUUID();
    state.secrets.set(id, { id, data: enc.text, data_nonce: enc.nonce, write_date: new Date().toISOString() });
    state.links.set(linkId, id);
    return { id: linkId, name, type, secret_id: id, secret_key: key, ...extra };
  }
  function addShare(content, rights = { read: true, write: true, grant: true }) {
    const key = randomKey();
    const enc = secretbox(key, JSON.stringify(content));
    const id = randomUUID();
    state.shares.set(id, { id, key, data: enc.text, data_nonce: enc.nonce, rights, write_date: new Date().toISOString() });
    return { share_id: id, share_secret_key: key };
  }
  const treeOf = (ds) => (ds.data ? JSON.parse(openSecretbox(ds.key, ds.data, ds.data_nonce)) : {});
  const shareTree = (sh) => JSON.parse(openSecretbox(sh.key, sh.data, sh.data_nonce));
  const secretContent = (id, key) => { const s = state.secrets.get(id); return JSON.parse(openSecretbox(key, s.data, s.data_nonce)); };

  const json = (status, body) => new Response(body === undefined ? '' : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const bad = (code) => json(400, { non_field_errors: [code] });

  /** TokenAuthentication: token, activation, expiry, validator (device + replay). */
  function authenticate(req, { allowInactive = false } = {}) {
    const auth = (req.headers.get('Authorization') ?? '').split(' ');
    if (auth[0] !== 'Token' || !auth[1]) return { error: json(401, { detail: 'Invalid token header. No token header present.' }) };
    const tok = state.tokens.get(sha512(auth[1]));
    if (!tok || (!allowInactive && !tok.active) || tok.validTill < state.clock()) return { error: json(401, { detail: 'Invalid token or not yet activated.' }) };
    if (tok.deviceFingerprint || tok.clientDate) {
      let v;
      try {
        const h = JSON.parse(req.headers.get('Authorization-Validator') ?? '');
        v = JSON.parse(openSecretbox(tok.secretKey, h.text, h.nonce));
      } catch { return { error: json(401, { detail: 'Invalid token header. Not proper encrypted.' }) }; }
      if (String(v.request_device_fingerprint) !== String(tok.deviceFingerprint)) {
        state.tokens.delete(tok.hash);
        return { error: json(401, { detail: 'Device Fingerprint Protection: device_fingerprint mismatch' }) };
      }
      const diff = Math.abs(((tok.clientDate - tok.createDate) - (Date.parse(v.request_time) - state.clock())) / 1000);
      if (!v.request_time || diff > replayWindow) {
        state.tokens.delete(tok.hash);
        return { error: json(401, { detail: 'Replay Protection: Time difference too big' }) };
      }
    }
    return { tok, user: [...state.users.values()].find((u) => u.id === tok.user) };
  }
  /** DecryptJSONParser + EncryptJSONRenderer. */
  const readBody = async (req, tok) => {
    const raw = await req.text();
    if (!raw) return {};
    const d = JSON.parse(raw);
    if (!tok) return d;
    if (!('text' in d) || !('nonce' in d)) throw new Error('Invalid request');
    return JSON.parse(openSecretbox(tok.secretKey, d.text, d.nonce));
  };
  const reply = (tok, status, body) => json(status, tok?.secretKey ? secretbox(tok.secretKey, JSON.stringify(body)) : body);

  async function handle(req) {
    const url = new URL(req.url);
    if (url.origin !== origin || !url.pathname.startsWith(`${prefix}/`)) return new Response('<html>not here</html>', { status: 404 });
    const path = url.pathname.slice(prefix.length);
    const m = req.method;
    state.log.push(`${m} ${path}`);

    if (path === '/info/' && m === 'GET') return json(200, { info, signature, verify_key: hex(signing.publicKey) });

    if (path === '/authentication/prelogin/' && m === 'POST') {
      const { username } = await readBody(req);
      const u = state.users.get(String(username).toLowerCase());
      return json(200, { hashing_algorithm: 'scrypt', hashing_parameters: u?.hashing_parameters ?? PARAMS });
    }

    if (path === '/authentication/login/' && m === 'POST') {
      state.logins++;
      const body = await readBody(req);
      const plain = openBox(body.login_info, body.login_info_nonce, body.public_key, hex(serverBox.secretKey));
      if (!plain) return bad('LOGIN_INFO_CANNOT_BE_DECRYPTED');
      const li = JSON.parse(plain);
      const u = state.users.get(String(li.username).toLowerCase().trim());
      if (!u || u.authkey !== li.authkey) return bad('USERNAME_OR_PASSWORD_WRONG');
      const clear = hex(nacl.randomBytes(32));
      const tok = {
        hash: sha512(clear), user: u.id, secretKey: randomKey(), userValidator: randomKey(), active: false,
        factors: [...(u.ga ? ['google_authenticator_2fa'] : []), ...(u.yubikey ? ['yubikey_otp_2fa'] : [])],
        deviceFingerprint: li.device_fingerprint ?? '', clientDate: li.device_time ? Date.parse(li.device_time) : null,
        createDate: state.clock(), validTill: state.clock() + Math.min(body.session_duration ?? 86400, 2592000) * 1000,
      };
      state.tokens.set(tok.hash, tok);
      const sess = nacl.box.keyPair();
      const ssk = box(tok.secretKey, body.public_key, hex(sess.secretKey));
      const uv = box(tok.userValidator, u.public_key, hex(sess.secretKey));
      const resp = {
        token: clear, session_valid_till: new Date(tok.validTill).toISOString(), required_multifactors: tok.factors,
        session_public_key: hex(sess.publicKey), session_secret_key: ssk.text, session_secret_key_nonce: ssk.nonce,
        user_validator: uv.text, user_validator_nonce: uv.nonce,
        user: {
          username: u.username, public_key: u.public_key, private_key: u.private_key, private_key_nonce: u.private_key_nonce,
          user_sauce: u.user_sauce, authentication: u.authentication, hashing_algorithm: u.hashing_algorithm, hashing_parameters: u.hashing_parameters,
        },
      };
      const enc = box(JSON.stringify(resp), body.public_key, hex(serverBox.secretKey));
      return json(200, { login_info: enc.text, login_info_nonce: enc.nonce });
    }

    const verify = { '/authentication/ga-verify/': 'google_authenticator_2fa', '/authentication/yubikey-otp-verify/': 'yubikey_otp_2fa' }[path];
    if (verify && m === 'POST') {
      const a = authenticate(req, { allowInactive: true });
      if (a.error) return a.error;
      const body = await readBody(req, a.tok);
      const u = a.user;
      if (verify === 'google_authenticator_2fa') {
        if (!/^\d{6}$/.test(body.ga_token ?? '')) return reply(a.tok, 400, { ga_token: ['GA_TOKENS_ONLY_CONTAIN_DIGITS'] });
        if ((await totp(u.ga)).code !== body.ga_token) return reply(a.tok, 400, { non_field_errors: ['GA_TOKEN_INCORRECT'] });
      } else if (body.yubikey_otp !== u.yubikey) return reply(a.tok, 400, { non_field_errors: ['YUBIKEY_OTP_INCORRECT'] });
      a.tok.factors = multifactor ? a.tok.factors.filter((f) => f !== verify) : [];
      return reply(a.tok, 200, {});
    }

    if (path === '/authentication/activate-token/' && m === 'POST') {
      const a = authenticate(req, { allowInactive: true });
      if (a.error) return a.error;
      const body = await readBody(req, a.tok);
      if (a.tok.active) return reply(a.tok, 400, { non_field_errors: ['TOKEN_INCORRECT'] });
      const unsolved = { google_authenticator_2fa: 'GA_CHALLENGE_UNSOLVED', yubikey_otp_2fa: 'YUBIKEY_CHALLENGE_UNSOLVED' };
      if (a.tok.factors.length) return reply(a.tok, 400, { non_field_errors: [unsolved[a.tok.factors[0]]] });
      let v;
      try { v = openSecretbox(a.tok.secretKey, body.verification, body.verification_nonce); } catch { v = null; }
      if (v !== a.tok.userValidator) return reply(a.tok, 400, { non_field_errors: ['VERIFICATION_CODE_INCORRECT'] });
      a.tok.active = true;
      const u = a.user;
      return reply(a.tok, 200, { user: { id: u.id, secret_key: u.secret_key, secret_key_nonce: u.secret_key_nonce } });
    }

    // everything below needs an active session
    const a = authenticate(req);
    if (a.error) return a.error;
    const { tok, user } = a;
    let body;
    try { body = await readBody(req, tok); } catch { return json(400, { detail: 'Invalid request' }); }

    if (path === '/authentication/logout/' && m === 'POST') { state.tokens.delete(tok.hash); return reply(null, 200, {}); }

    if (path === '/datastore/' && m === 'GET') {
      return reply(tok, 200, { datastores: [...state.datastores.values()].filter((d) => d.user === user.id).map((d) => ({ id: d.id, type: d.type, description: d.description, is_default: d.is_default })) });
    }
    let r = /^\/datastore\/([0-9a-f-]{36})\/$/.exec(path);
    if (r && m === 'GET') {
      const d = state.datastores.get(r[1]);
      if (!d || d.user !== user.id) return reply(tok, 403, { message: 'NO_PERMISSION_OR_NOT_EXIST' });
      return reply(tok, 200, { data: d.data, data_nonce: d.data_nonce, type: d.type, description: d.description, secret_key: d.secret_key, secret_key_nonce: d.secret_key_nonce, is_default: d.is_default, write_date: d.write_date });
    }
    if (path === '/datastore/' && m === 'PUT') {
      const key = openSecretbox(user._secretKey, body.secret_key, body.secret_key_nonce);
      const d = { id: randomUUID(), user: user.id, type: body.type, description: body.description, is_default: body.is_default ?? true, key, secret_key: body.secret_key, secret_key_nonce: body.secret_key_nonce, data: body.data ?? '', data_nonce: body.data_nonce ?? '', write_date: new Date().toISOString() };
      state.datastores.set(d.id, d);
      return reply(tok, 201, { datastore_id: d.id });
    }
    if (path === '/datastore/' && m === 'POST') {
      const d = state.datastores.get(body.datastore_id);
      if (!d || d.user !== user.id) return reply(tok, 400, { non_field_errors: ['NO_PERMISSION_OR_NOT_EXIST'] });
      if (body.old_write_date && Date.parse(body.old_write_date) !== Date.parse(d.write_date)) return reply(tok, 400, { non_field_errors: ['WRITE_DATE_MISMATCH'] });
      Object.assign(d, { data: body.data, data_nonce: body.data_nonce, write_date: new Date(Date.now() + 1).toISOString() });
      return reply(tok, 200, { success: 'Data updated.', write_date: d.write_date });
    }
    r = /^\/share\/([0-9a-f-]{36})\/$/.exec(path);
    if (r && m === 'GET') {
      const s = state.shares.get(r[1]);
      if (!s || !s.rights.read) return reply(tok, 403, { message: 'NO_PERMISSION_OR_NOT_EXIST' });
      return reply(tok, 200, { id: s.id, data: s.data, data_nonce: s.data_nonce, user_id: user.id, rights: s.rights, write_date: s.write_date });
    }
    if (path === '/share/' && m === 'PUT') { // update; POST would create a share
      const s = state.shares.get(body.share_id);
      if (!s || !s.rights.write) return reply(tok, 403, { message: 'NO_PERMISSION_OR_NOT_EXIST' });
      if (body.old_write_date && Date.parse(body.old_write_date) !== Date.parse(s.write_date)) return reply(tok, 400, { non_field_errors: ['WRITE_DATE_MISMATCH'] });
      Object.assign(s, { data: body.data, data_nonce: body.data_nonce, write_date: new Date(Date.now() + 1).toISOString() });
      return reply(tok, 200, { success: 'Data updated.' });
    }
    r = /^\/secret\/([0-9a-f-]{36})\/$/.exec(path);
    if (r && m === 'GET') {
      const s = state.secrets.get(r[1]);
      if (!s) return reply(tok, 403, { message: 'NO_PERMISSION_OR_NOT_EXIST' });
      return reply(tok, 200, { create_date: s.write_date, write_date: s.write_date, data: s.data, data_nonce: s.data_nonce, type: 'password', read_count: 1 });
    }
    if (path === '/secret/' && m === 'PUT') {
      if (!body.parent_datastore_id === !body.parent_share_id) return reply(tok, 400, { non_field_errors: ['EITHER_PARENT_DATASTORE_OR_SHARE_NEED_TO_BE_DEFINED_NOT_BOTH'] });
      if (body.parent_share_id && !state.shares.get(body.parent_share_id)?.rights.write) return reply(tok, 403, { message: 'NO_PERMISSION_OR_NOT_EXIST' });
      const id = randomUUID();
      state.secrets.set(id, { id, data: body.data, data_nonce: body.data_nonce, write_date: new Date().toISOString(), parent: body.parent_datastore_id ?? body.parent_share_id });
      state.links.set(body.link_id, id);
      return reply(tok, 201, { secret_id: id });
    }
    if (path === '/secret/' && m === 'POST') {
      const s = state.secrets.get(body.secret_id);
      if (!s) return reply(tok, 403, { message: 'NO_PERMISSION_OR_NOT_EXIST' });
      if (body.old_write_date && Date.parse(body.old_write_date) !== Date.parse(s.write_date)) return reply(tok, 400, { non_field_errors: ['WRITE_DATE_MISMATCH'] });
      Object.assign(s, { data: body.data, data_nonce: body.data_nonce, write_date: new Date(Date.now() + 1).toISOString() });
      return reply(tok, 200, { success: 'Data updated.', write_date: s.write_date });
    }
    if (path === '/secret/link/' && m === 'DELETE') {
      const id = state.links.get(body.link_id);
      if (!id) return reply(tok, 403, { message: 'NO_PERMISSION_OR_NOT_EXIST' });
      state.links.delete(body.link_id);
      if (![...state.links.values()].includes(id)) state.secrets.delete(id);
      return reply(tok, 200, {});
    }
    return json(405, {});
  }

  const fetch = async (url, init = {}) => handle(new Request(url, init));
  return {
    fetch, state, addUser, addDatastore, addEntry, addShare, treeOf, shareTree, secretContent,
    url: `${origin}${prefix}`, verifyKey: hex(signing.publicKey),
  };
}
