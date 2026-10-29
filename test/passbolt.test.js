// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Passbolt provider against the simulated server (fetch is mocked, with a tiny cookie jar).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { totp } from '../src/lib/totp.js';
import PassboltProvider from '../src/providers/passbolt/index.js';
import { env as cookieEnv } from '../src/providers/passbolt/cookies.js';
import { forgetAllKeepers } from '../src/providers/passbolt/tokens.js';
import * as openpgp from '../vendor/openpgp.mjs';
import { ADMIN_ID, KEYS, USER_ID, fakePassbolt } from './fake-passbolt.js';

const DOMAIN = 'https://passbolt.example.org';

// A third account key in the newest format (RFC 9580): v6 key, Argon2 S2K with AEAD protection. Messages to it
// use SEIPD v2. GnuPG cannot create such keys, so it is generated here with OpenPGP.js.
{
  const passphrase = 'carol-passphrase';
  const v6 = await openpgp.generateKey({
    type: 'curve25519', userIDs: [{ name: 'Carol Test', email: 'carol@passbolt.test' }], passphrase, format: 'armored',
    config: { v6Keys: true, aeadProtect: true, s2kType: openpgp.enums.s2k.argon2 },
  });
  const pub = await openpgp.readKey({ armoredKey: v6.publicKey });
  KEYS.userV6 = { fingerprint: pub.getFingerprint().toUpperCase(), passphrase, public: v6.publicKey, private: v6.privateKey };
}

/**
 * Simulated server behind a mocked fetch with a tiny cookie jar (the browser's), and – with `cookies` – the
 * extension APIs for the optional cookies permission on top of that jar.
 */
async function setup(opts = {}) {
  const { cookies = false, delay, lose, ...fakeOpts } = opts;
  const fake = await fakePassbolt({ domain: DOMAIN, ...fakeOpts });
  forgetAllKeepers();
  const jar = new Map(); // name → { value, secure, httpOnly }
  const requests = []; // { path, token } in the order they reached the server
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url);
    assert.equal(u.searchParams.get('api-version'), 'v2');
    const headers = { ...(init.headers ?? {}) };
    if (init.credentials === 'include' && jar.size) headers.Cookie = [...jar].map(([k, c]) => `${k}=${c.value}`).join('; ');
    requests.push({ path: u.pathname, token: (headers.Authorization ?? '').replace(/^Bearer /, '') || null });
    await delay?.(u.pathname);
    const r = await fake.handle(u.pathname + u.search, { ...init, headers });
    for (const sc of [r.headers?.['Set-Cookie'] ?? []].flat()) {
      const [kv, ...attrs] = sc.split(';').map((x) => x.trim());
      const [k, v] = kv.split('=');
      jar.set(k, { value: v, secure: attrs.some((a) => /^secure$/i.test(a)), httpOnly: attrs.some((a) => /^httponly$/i.test(a)) });
    }
    // the worker stops while the answer is on its way: the server has done its part, the caller never hears back
    if (lose?.(u.pathname)) return new Promise(() => {});
    return new Response(JSON.stringify(r.body), { status: r.status });
  };
  const local = new Map();
  const calls = [];
  cookieEnv.ext = !cookies ? undefined : {
    permissions: { contains: async (p) => p.permissions?.includes('cookies') && cookies !== 'denied' },
    cookies: {
      get: async ({ url, name }) => { calls.push(`get ${name}`); assert.equal(url, `${DOMAIN}/`); const c = jar.get(name); return c ? { name, ...c, path: '/', storeId: '0' } : null; },
      remove: async ({ name }) => { calls.push(`remove ${name}`); jar.delete(name); },
      set: async ({ name, value, secure, httpOnly }) => { calls.push(`set ${name}`); jar.set(name, { value, secure, httpOnly }); },
    },
    storage: { local: {
      get: async (k) => (local.has(k) ? { [k]: structuredClone(local.get(k)) } : {}),
      set: async (o) => { for (const [k, v] of Object.entries(o)) local.set(k, structuredClone(v)); },
      remove: async (k) => { local.delete(k); },
    } },
    runtime: {},
  };
  const user = fakeOpts.user ?? 'userRsa';
  return {
    fake, jar, requests, calls, local,
    config: { id: 'pb1', server: DOMAIN, userId: USER_ID, privateKey: KEYS[user].private }, pass: KEYS[user].passphrase,
  };
}

for (const user of ['userRsa', 'userEcc', 'userV6']) {
  test(`${user}: JWT login, v4 + v5 resources, folders, session keys, lazy secrets`, async () => {
    const { fake, config, pass } = await setup({ user });
    const res = await PassboltProvider.login(config, { password: pass });
    assert.equal(res.status, 'ok');
    assert.equal(res.configPatch.serverFingerprint, KEYS.server.fingerprint, 'server key pinned');
    assert.ok(res.session.accessToken && !res.session.refreshToken, 'no refresh token kept (Passbolt rotates it through a cookie)');
    assert.match(res.session.unlockedKey, /BEGIN PGP PRIVATE KEY/);

    const out = await PassboltProvider.sync({ ...config, ...res.configPatch }, res.session);
    assert.equal(out.warning, undefined);
    const by = Object.fromEntries(out.items.map((i) => [i.name, i]));
    assert.deepEqual(Object.keys(by).sort(), ['GitLab', 'Intranet', 'Router', 'Tresor-Notiz']);
    assert.equal(by.GitLab.username, 'ada@example.com', 'v5 shared-key metadata decrypted (admin signature verified)');
    assert.deepEqual(by.GitLab.uris, ['https://gitlab.example.com/users/sign_in']);
    assert.equal(by.GitLab.folder, 'Team/Infra', 'nested folder path');
    assert.equal(by.Intranet.folder, 'Team');
    assert.equal(by.Router.folder, undefined);
    assert.ok(by.GitLab.hasTotp && by.GitLab.hasPassword);
    assert.equal(by['Tresor-Notiz'].type, 'note', 'metadata opened via session key');
    assert.ok(out.items.every((i) => i.password === undefined), 'secrets not decrypted during sync');
    assert.ok(fake.log.includes('GET /metadata/session-keys.json'));
    assert.ok(fake.log.some((l) => l.startsWith('GET /users/')), 'signer key fetched');

    const reveal = (i) => PassboltProvider.reveal(config, res.session, i);
    assert.equal((await reveal(by.Router)).password, 'router-pw');
    const intranet = await reveal(by.Intranet);
    assert.equal(intranet.password, 'intranet-pw');
    assert.match(intranet.notes, /geheime Notiz/);
    const gitlab = await reveal(by.GitLab);
    assert.equal(gitlab.password, 'gitlab-pw');
    assert.equal((await totp(gitlab.totp, 59_000)).code.length, 6);
    assert.equal((await reveal(by['Tresor-Notiz'])).notes, 'Nur für mich');
  });
}

test('shared metadata key with an untrusted signature is rejected', async () => {
  const { config, pass } = await setup({ forgeMetadataKey: true });
  const res = await PassboltProvider.login(config, { password: pass });
  const out = await PassboltProvider.sync(config, res.session);
  assert.ok(!out.items.some((i) => i.name === 'GitLab'), 'resource behind forged key not shown');
  assert.match(out.warning, /Signatur/);
  assert.equal(out.items.length, 3);
});

test('wrong passphrase is rejected before contacting the server', async () => {
  const { fake, config } = await setup();
  await assert.rejects(PassboltProvider.login(config, { password: 'falsch' }), { code: 'bad_password', message: 'Falsche Passphrase' });
  assert.equal(fake.log.length, 0);
});

test('changed server key is refused (pinning)', async () => {
  const { config, pass } = await setup();
  await assert.rejects(
    PassboltProvider.login({ ...config, serverFingerprint: '0000000000000000000000000000000000000000' }, { password: pass }),
    { code: 'server_key_changed' });
});

test('TOTP MFA flow with passbolt_mfa cookie', async () => {
  const { config, pass, jar } = await setup({ mfa: true });
  const first = await PassboltProvider.login(config, { password: pass });
  assert.equal(first.status, 'needs_2fa');
  assert.deepEqual(first.twoFactorProviders.map((p) => p.id), ['totp']);
  await assert.rejects(PassboltProvider.login(config, { password: pass, twoFactorCode: '000000', twoFactorProvider: 'totp' }), /OTP/);
  const ok = await PassboltProvider.login(config, { password: pass, twoFactorCode: '123 456', twoFactorProvider: 'totp' });
  assert.equal(ok.status, 'ok');
  assert.ok(jar.has('passbolt_mfa'));
  const { items } = await PassboltProvider.sync(config, ok.session);
  assert.equal(items.length, 4);
  jar.clear();
  await assert.rejects(PassboltProvider.sync(config, ok.session), /Zweiter Faktor/);
});

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const MFA_CODE = { twoFactorCode: '123456', twoFactorProvider: 'totp' };

test('without a second factor: an expired access token means a new challenge sign-in, no refresh token is kept', async () => {
  const { fake, config, pass } = await setup({ cookies: true });
  const res = await PassboltProvider.login(config, { password: pass });
  let session = res.session;
  assert.ok(session.sid && !session.mfa && !('refreshToken' in session));
  for (let round = 0; round < 3; round++) {
    fake.expireAll(); // server forgets access tokens
    const out = await PassboltProvider.sync(config, session);
    assert.equal(out.items.length, 4);
    assert.ok(out.session && out.session.accessToken !== session.accessToken, `new access token in round ${round}`);
    assert.equal(out.session.gen, round + 1);
    session = out.session;
  }
  assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/refresh.json').length, 0, 'the refresh endpoint is not used');
  assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/login.json').length, 4);
  // a caller with an older copy of the session gets the newest token, not the one it holds
  const stale = await PassboltProvider.sync(config, res.session);
  assert.equal(stale.session.accessToken, session.accessToken);
  // a session from an older version still carrying a refresh token loses it on the next renewal
  fake.expireAll();
  const old = await PassboltProvider.sync(config, { ...session, sid: 'older', refreshToken: 'alt' });
  assert.equal(old.session.refreshToken, undefined);
});

test('renews shortly before the token expires, before the request', async () => {
  const { fake, config, pass, requests } = await setup({ ttl: 2 });
  const { session } = await PassboltProvider.login(config, { password: pass });
  await sleep(session.expiresAt - (session.expiresAt - session.obtainedAt) / 4 - Date.now() + 50); // a quarter of the lifetime before
  const out = await PassboltProvider.sync(config, session);
  assert.ok(out.session.accessToken !== session.accessToken);
  assert.ok(!requests.some((r) => r.path !== '/auth/jwt/login.json' && r.token === session.accessToken), 'old token not used once due');
  assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/login.json').length, 2);
});

test('second factor with the cookies permission: /auth/jwt/refresh keeps the proof, the cookie is read and removed', async () => {
  const { fake, config, pass, jar, calls } = await setup({ mfa: true, cookies: true });
  const res = await PassboltProvider.login(config, { password: pass, ...MFA_CODE });
  let session = res.session;
  assert.ok(session.mfa && session.refreshToken, 'refresh token of the sign-in kept (memory only)');
  const seen = new Set([session.refreshToken]);
  for (let round = 1; round <= 4; round++) {
    fake.expireAll();
    const out = await PassboltProvider.sync(config, session);
    assert.equal(out.items.length, 4, `round ${round}: still signed in with the second factor`);
    assert.ok(out.session.refreshToken && !seen.has(out.session.refreshToken), `round ${round}: new refresh token from the cookie`);
    assert.equal(out.session.refreshPending, undefined);
    seen.add(out.session.refreshToken);
    assert.ok(!jar.has('refresh_token'), `round ${round}: cookie removed from the browser`);
    session = out.session;
  }
  assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/refresh.json').length, 4);
  assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/login.json').length, 1, 'no new challenge sign-in');
  assert.deepEqual(fake.attacks, [], 'no refresh token used twice');
  assert.deepEqual(fake.voided, [], 'the proof was never voided');
  assert.ok(calls.every((c) => c.endsWith('refresh_token')), 'only the refresh_token cookie is touched');
});

test('second factor without the cookies permission: as before, the code is asked for again after the token expires', async () => {
  for (const cookies of [false, 'denied']) {
    const { fake, config, pass } = await setup({ mfa: true, cookies });
    const { session } = await PassboltProvider.login(config, { password: pass, ...MFA_CODE });
    assert.equal((await PassboltProvider.sync(config, session)).items.length, 4);
    fake.expireAll();
    await assert.rejects(PassboltProvider.sync(config, session), { code: 'session_expired', message: /Zweiter Faktor/ });
    assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/refresh.json').length, 0);
    assert.deepEqual(fake.attacks, []);
  }
});

test('second factor remembered for 30 days: a new challenge sign-in needs no code', async () => {
  const { fake, config, pass } = await setup({ mfa: true });
  const verify = [];
  const handle = fake.handle;
  fake.handle = async (path, init) => { if (path.startsWith('/mfa/verify/')) verify.push(JSON.parse(init.body)); return handle(path, init); };
  const { session } = await PassboltProvider.login(config, { password: pass, ...MFA_CODE, rememberMfa: true });
  assert.equal(verify[0].remember, 1);
  assert.equal(session.mfaRemembered, true);
  fake.expireAll();
  const out = await PassboltProvider.sync(config, session);
  assert.equal(out.items.length, 4);
  assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/login.json').length, 2);
});

test('strict lock: requests in flight finish before the renewal, requests started meanwhile wait for the new token', async () => {
  let slow = false;
  const { fake, config, pass, requests } = await setup({
    mfa: true, cookies: true, ttl: 4,
    delay: (path) => (slow && path === '/resources.json' ? sleep(700) : null),
  });
  const { session } = await PassboltProvider.login(config, { password: pass, ...MFA_CODE });
  const due = session.expiresAt - (session.expiresAt - session.obtainedAt) / 4;
  await sleep(due - Date.now() - 200);
  slow = true;
  const a = PassboltProvider.sync(config, session); // its /resources.json is in flight when the token becomes due
  await sleep(400);
  const b = PassboltProvider.sync(config, session);
  const c = PassboltProvider.permissions(config, session, { id: 'r1' });
  const d = PassboltProvider.folderPermissions(config, session, 'f1');
  const [ra, rb, rc] = await Promise.all([a, b, c, d]);
  assert.equal(ra.items.length, 4);
  assert.equal(rb.items.length, 4);
  assert.ok(rc.permissions.length);
  const refreshAt = requests.findIndex((r) => r.path === '/auth/jwt/refresh.json');
  assert.ok(refreshAt > 0, 'renewed through the refresh endpoint');
  assert.ok(requests.slice(0, refreshAt).some((r) => r.path === '/resources.json' && r.token === session.accessToken), 'a request with the old token was in flight');
  assert.ok(!requests.slice(refreshAt).some((r) => r.token === session.accessToken), 'the old token is never sent after the renewal started');
  assert.equal(fake.log.filter((l) => l === 'POST /auth/jwt/refresh.json').length, 1, 'one renewal for all callers');
  assert.deepEqual(fake.voided, []);
  assert.deepEqual(fake.attacks, []);
  // still valid afterwards
  assert.equal((await PassboltProvider.sync(config, session)).items.length, 4);
});

test('worker stopped between the renewal and storing it: the token left in the cookie is taken next time', async () => {
  let kill = false;
  const { fake, config, pass, jar, local } = await setup({ mfa: true, cookies: true, lose: (path) => kill && path === '/auth/jwt/refresh.json' });
  const stored = [];
  PassboltProvider.onSession = async (id, s) => { stored.push(s); };
  try {
    const { session } = await PassboltProvider.login(config, { password: pass, ...MFA_CODE });
    fake.expireAll();
    kill = true;
    PassboltProvider.sync(config, session).catch(() => {}); // never answers
    for (let i = 0; i < 50 && !jar.has('refresh_token'); i++) await sleep(20);
    kill = false;
    const last = stored.at(-1);
    assert.ok(last.refreshPending && last.refreshToken === null, 'the old refresh token was marked as used before it was sent');
    assert.ok(jar.has('refresh_token'), 'rotated token only in the cookie');
    assert.ok(local.get('passboltRefreshPending')?.['https://passbolt.example.org'], 'server noted for the cleanup at start');
    forgetAllKeepers(); // the worker starts again, with what storage.session has
    const out = await PassboltProvider.sync(config, last);
    assert.equal(out.items.length, 4);
    assert.ok(!jar.has('refresh_token'));
    assert.equal(stored.at(-1).refreshPending, undefined);
    assert.ok(stored.at(-1).refreshToken);
    assert.deepEqual(fake.attacks, [], 'the used token is not sent again');
    assert.deepEqual(fake.voided, []);
    assert.deepEqual(local.get('passboltRefreshPending'), {});
  } finally { PassboltProvider.onSession = null; }
});

test('a refresh cookie that is not ours is put back; leftovers are removed at browser start', async () => {
  const { fake, config, pass, jar, local } = await setup({ mfa: true, cookies: true });
  const { session } = await PassboltProvider.login(config, { password: pass, ...MFA_CODE });
  jar.set('refresh_token', { value: 'web-app-token', secure: true, httpOnly: true }); // Passbolt's own web app
  fake.expireAll();
  const out = await PassboltProvider.sync(config, session);
  assert.equal(out.items.length, 4, 'no CSRF refusal: the cookie was out of the way during the renewal');
  assert.notEqual(out.session.refreshToken, 'web-app-token');
  assert.equal(jar.get('refresh_token')?.value, 'web-app-token', 'the other cookie is back');
  assert.deepEqual(fake.attacks, []);
  // a crash during a renewal: the next start removes the cookie of that server
  local.set('passboltRefreshPending', { 'https://passbolt.example.org': Date.now() });
  assert.equal(await PassboltProvider.cleanup(), 1);
  assert.ok(!jar.has('refresh_token'));
  assert.equal(local.has('passboltRefreshPending'), false);
});

test('refresh cookie only where the browser keeps it (Secure): https, Chrome also http://localhost', async () => {
  const { cookieRefreshPossible } = await import('../src/providers/passbolt/cookies.js');
  assert.equal(cookieRefreshPossible('https://pb.example.org', { firefox: true }), true);
  assert.equal(cookieRefreshPossible('http://localhost:8080', { firefox: false }), true);
  assert.equal(cookieRefreshPossible('http://localhost:8080', { firefox: true }), false);
  assert.equal(cookieRefreshPossible('http://10.0.0.5', { firefox: false }), false);
  // an http server: the refresh endpoint is not tried, the second factor is asked again (or remembered)
  const fake = await setup({ mfa: true, cookies: true });
  const cfg = { ...fake.config, server: 'http://10.0.0.5' };
  assert.equal(cookieRefreshPossible(cfg.server), false);
});

async function unlocked(opts = {}) {
  const env = await setup(opts);
  const res = await PassboltProvider.login(env.config, { password: env.pass });
  const out = await PassboltProvider.sync(env.config, res.session);
  const by = Object.fromEntries(out.items.map((i) => [i.name, i]));
  const revealed = async (i) => ({ ...i, ...(await PassboltProvider.reveal(env.config, res.session, i)), revealed: true });
  return { ...env, session: res.session, out, by, revealed };
}

test('permissions, favorites and public description are read', async () => {
  const { by, out } = await unlocked();
  assert.equal(by.Router.canEdit, false, 'read-only permission');
  assert.equal(by.GitLab.favorite, true);
  assert.equal(by.Intranet.description, 'öffentliche Beschreibung');
  assert.deepEqual(out.folders.map((f) => f.name), ['Team', 'Team/Extern', 'Team/Infra']);
});

test('v6 key (RFC 9580): unlock with Argon2 + AEAD, secrets written to it use SEIPD v2', async () => {
  const key = await openpgp.readPrivateKey({ armoredKey: KEYS.userV6.private });
  assert.equal(key.keyPacket.version, 6);
  const { fake, config, pass } = await setup({ user: 'userV6' });
  const res = await PassboltProvider.login(config, { password: pass });
  assert.equal(res.status, 'ok');
  const { item } = await PassboltProvider.saveItem(config, res.session, null, { type: 'login', name: 'Neu6', username: 'carol', password: 'v6-pw', uris: [] });
  const secret = fake.resources.find((r) => r.id === item.id).secrets[0].data;
  const msg = await openpgp.readMessage({ armoredMessage: secret });
  const seipd = msg.packets.find((p) => p.constructor.tag === openpgp.enums.packet.symEncryptedIntegrityProtectedData);
  assert.equal(seipd.version, 2, 'SEIPD v2 (AEAD) towards a v6 key');
  const again = (await PassboltProvider.sync(config, res.session)).items.find((i) => i.name === 'Neu6');
  assert.equal((await PassboltProvider.reveal(config, res.session, again)).password, 'v6-pw');
  await assert.rejects(PassboltProvider.login(config, { password: 'falsch' }), 'wrong passphrase refused for v6 keys too');
});

test('create a v5 login (shared metadata key) and a v5 note, then read them back', async () => {
  const { config, session, fake } = await unlocked();
  const { item } = await PassboltProvider.saveItem(config, session, null, {
    type: 'login', name: 'Wiki', username: 'ada', password: 'wiki-pw', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://wiki.example'], notes: 'n1', folderId: 'f1', favorite: true,
  });
  const created = fake.resources.find((r) => r.id === item.id);
  assert.equal(created.resource_type_id, 'rt-v5totp');
  assert.equal(created.metadata_key_type, 'shared_key');
  assert.equal(created.folder_parent_id, 'f1');
  assert.ok(!('name' in created), 'no cleartext name for v5');
  assert.ok(created.favorite, 'favorite set');
  await PassboltProvider.saveItem(config, session, null, { type: 'note', name: 'Geheimnis', notes: 'nur Text' });
  const { items } = await PassboltProvider.sync(config, session);
  const wiki = items.find((i) => i.name === 'Wiki');
  assert.equal(wiki.username, 'ada');
  assert.equal(wiki.folder, 'Team');
  const r = await PassboltProvider.reveal(config, session, wiki);
  assert.equal(r.password, 'wiki-pw');
  assert.equal((await totp(r.totp, 59_000)).code.length, 6);
  const note = items.find((i) => i.name === 'Geheimnis');
  assert.equal(note.type, 'note');
  assert.equal((await PassboltProvider.reveal(config, session, note)).notes, 'nur Text');
});

test('v4 server: creates password-and-description resources', async () => {
  const { config, session, fake } = await unlocked({ defaultTypes: 'v4' });
  const { item } = await PassboltProvider.saveItem(config, session, null, { type: 'login', name: 'Alt', username: 'u', password: 'p', uris: ['https://alt.example'], notes: 'x' });
  const r = fake.resources.find((x) => x.id === item.id);
  assert.equal(r.resource_type_id, 'rt-pwd');
  assert.equal(r.name, 'Alt');
  await assert.rejects(PassboltProvider.saveItem(config, session, null, { type: 'note', name: 'N', notes: 'x' }), /v5/);
});

test('edit own v5 resource keeps its metadata key; shared resources get a secret per reader; read-only is refused', async () => {
  const { config, session, by, revealed, fake } = await unlocked();
  const gitlab = await revealed(by.GitLab);
  const { item } = await PassboltProvider.saveItem(config, session, gitlab, {
    type: 'login', name: 'GitLab EE', username: 'ada@example.com', password: 'gitlab-neu', totp: gitlab.totp, uris: gitlab.uris, notes: '', folderId: 'f1', favorite: true,
  });
  const stored = fake.resources.find((r) => r.id === item.id);
  assert.equal(stored.metadata_key_type, 'shared_key');
  assert.equal(stored.metadata_key_id, 'mk1');
  assert.equal(stored.folder_parent_id, 'f1', 'moved to another folder');
  const { items } = await PassboltProvider.sync(config, session);
  const after = items.find((i) => i.id === item.id);
  assert.equal(after.name, 'GitLab EE');
  assert.equal((await PassboltProvider.reveal(config, session, after)).password, 'gitlab-neu');
  // Intranet is shared with the admin: the edited secret is encrypted for both readers
  await PassboltProvider.saveItem(config, session, await revealed(by.Intranet), { type: 'login', name: 'Intranet', username: 'ada', password: 'intranet-neu', uris: [], notes: '' });
  const secrets = fake.sharedSecrets.r1;
  assert.deepEqual(secrets.map((x) => x.user_id).sort(), [ADMIN_ID, USER_ID].sort());
  const adminKey = await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: KEYS.userEcc.private }), passphrase: KEYS.userEcc.passphrase });
  const forAdmin = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: secrets.find((x) => x.user_id === ADMIN_ID).data }), decryptionKeys: adminKey });
  assert.equal(JSON.parse(forAdmin.data).password, 'intranet-neu', 'the other reader can decrypt the new secret');
  await assert.rejects(PassboltProvider.saveItem(config, session, await revealed(by.Router), { type: 'login', name: 'x', uris: [] }), /Schreibberechtigung/);
});

test('favorite toggle and delete (owner only)', async () => {
  const { config, session, by, fake } = await unlocked();
  const fav = await PassboltProvider.setFavorite(config, session, by.Intranet, true);
  assert.equal(fav.item.favorite, true);
  assert.ok(fake.resources.find((r) => r.id === 'r1').favorite);
  const unfav = await PassboltProvider.setFavorite(config, session, by.GitLab, false);
  assert.equal(unfav.item.favorite, false);
  assert.equal(fake.resources.find((r) => r.id === 'r3').favorite, null);
  await PassboltProvider.deleteItem(config, session, by['Tresor-Notiz']);
  assert.ok(!fake.resources.some((r) => r.id === 'r4'));
  await assert.rejects(PassboltProvider.deleteItem(config, session, by.Router), /Besitzer/);
});

test('share a folder: folder permissions, owned subfolders and entries follow, new readers get the secret', async () => {
  const { config, session, fake } = await unlocked();
  const synced = await PassboltProvider.sync(config, session);
  const team = synced.folders.find((f) => f.id === 'f1');
  assert.equal(team.canShare, true);
  assert.equal(synced.folders.find((f) => f.id === 'f3').canShare, false, 'read-only folder cannot be shared');
  assert.equal(synced.items.find((i) => i.id === 'r1').canShareFolder, true);
  const { permissions } = await PassboltProvider.folderPermissions(config, session, 'f1');
  assert.deepEqual(permissions.map((p) => [p.aroId, p.type]), [[USER_ID, 15]]);

  fake.log.length = 0;
  const tree = { folderId: 'f1', folders: synced.folders, items: synced.items };
  const res = await PassboltProvider.shareFolder(config, session, tree, [{ aro: 'User', aroId: ADMIN_ID, type: 7 }]);
  assert.equal(res.skipped, 1, 'the read-only subfolder is left alone');
  assert.deepEqual(res.failed, []);
  assert.ok(fake.log.includes('PUT /share/folder/f1.json') && fake.log.includes('PUT /share/folder/f2.json'));
  assert.ok(!fake.log.includes('PUT /share/folder/f3.json'));
  assert.equal(fake.folderPermissions.f1.find((p) => p.aro_foreign_key === ADMIN_ID).type, 7);
  assert.equal(fake.folderPermissions.f2.find((p) => p.aro_foreign_key === ADMIN_ID).type, 7);
  // r1 already had the admin as reader: only the level changes, no new secret
  assert.equal(fake.permissions.r1.find((p) => p.aro_foreign_key === ADMIN_ID).type, 7);
  assert.deepEqual(fake.sharedSecrets.r1, []);
  // r3 (v5, in the subfolder) is new for the admin: its secret is encrypted for the admin's key
  assert.equal(fake.permissions.r3.find((p) => p.aro_foreign_key === ADMIN_ID).type, 7);
  const adminKey = await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: KEYS.userEcc.private }), passphrase: KEYS.userEcc.passphrase });
  const forAdmin = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: fake.sharedSecrets.r3[0].data }), decryptionKeys: adminKey });
  assert.equal(JSON.parse(forAdmin.data).password, 'gitlab-pw');
  assert.equal(fake.permissions.r2.length, 1, 'entries outside the folder are untouched');

  // removing the admin from the folder removes them from the contents as well
  const again = await PassboltProvider.folderPermissions(config, session, 'f1');
  const adminPerm = again.permissions.find((p) => p.aroId === ADMIN_ID);
  await PassboltProvider.shareFolder(config, session, tree, [{ id: adminPerm.id, delete: true }]);
  for (const list of [fake.folderPermissions.f1, fake.folderPermissions.f2, fake.permissions.r1, fake.permissions.r3]) {
    assert.ok(!list.some((p) => p.aro_foreign_key === ADMIN_ID));
  }
  await assert.rejects(PassboltProvider.shareFolder(config, session, tree, [{ id: 'perm-unknown', delete: true }]), /inzwischen geändert/);
});
