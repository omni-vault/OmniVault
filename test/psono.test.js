// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Psono: crypto against vectors made by the Psono server's own code (test/fixtures/make-psono-vectors.py), item
// mapping, and the protocol against the simulated server in test/fake-psono.js.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import PsonoProvider, { buildSecret, mapSecret, parseFolderRef, totpFrom, totpTo, urlFilter } from '../src/providers/psono/index.js';
import {
  authkey, checkParams, decryptBox, decryptSymmetric, encryptSymmetric, passwordKey, verifySignature,
} from '../src/providers/psono/crypto.js';
import { hostPatterns } from '../src/providers/hosts.js';
import { totp } from '../src/lib/totp.js';
import { fakePsono, openSecretbox } from './fake-psono.js';

const V = JSON.parse(readFileSync(new URL('./fixtures/psono-vectors.json', import.meta.url)));

/* ---------- crypto ---------- */

test('authkey matches the server (scrypt, salt = sha512 of the lower-case username)', async () => {
  assert.equal(await authkey(V.authkey.username, V.authkey.password, V.authkey.params), V.authkey.authkey);
  assert.equal(await authkey(V.authkey.username.toLowerCase(), V.authkey.password, V.authkey.params), V.authkey.authkey);
  assert.notEqual(await authkey(V.authkey.username, `${V.authkey.password}x`, V.authkey.params), V.authkey.authkey);
});

test('password key opens what the server encrypted with encrypt_secret (user_sauce, non-ASCII password)', async () => {
  const v = V.encrypt_secret;
  const key = await passwordKey(v.password, v.user_sauce, v.params);
  assert.equal(decryptSymmetric(key, v.text, v.nonce), v.plaintext);
  const wrong = await passwordKey('passwörd ✓', v.user_sauce, v.params);
  assert.throws(() => decryptSymmetric(wrong, v.text, v.nonce), /decryption failed/);
});

test('secretbox and box interoperate with PyNaCl; signatures verify', () => {
  assert.equal(decryptSymmetric(V.secretbox.key, V.secretbox.text, V.secretbox.nonce), V.secretbox.plaintext);
  const e = encryptSymmetric(V.secretbox.key, 'zurück ✓');
  assert.equal(openSecretbox(V.secretbox.key, e.text, e.nonce), 'zurück ✓', 'readable by an independent implementation');
  assert.equal(decryptBox(V.box.text, V.box.nonce, V.box.sender_public, V.box.recipient_private), V.box.plaintext);
  const s = V.signature;
  assert.ok(verifySignature(s.info, s.signature, s.verify_key));
  assert.equal(verifySignature(s.info.replace('test', 'evil'), s.signature, s.verify_key), false);
  assert.equal(verifySignature(s.info, 'zz', s.verify_key), false);
});

test('scrypt parameters from the server are bounded', () => {
  assert.deepEqual(checkParams('scrypt', { u: 14, r: 8, p: 1, l: 64 }), { u: 14, r: 8, p: 1, l: 64 });
  assert.deepEqual(checkParams(undefined, undefined), { u: 14, r: 8, p: 1, l: 64 });
  assert.throws(() => checkParams('scrypt', { u: 30, r: 8, p: 1, l: 64 }), /out of range/);
  assert.throws(() => checkParams('scrypt', { u: 14, r: 8, p: 1000, l: 64 }), /out of range/);
  assert.throws(() => checkParams('argon2', {}), /unsupported/);
});

/* ---------- mapping ---------- */

test('website password ↔ login, keeping fields OmniVault does not show', () => {
  const content = {
    website_password_title: 'GitHub', website_password_url: 'https://github.com/login', website_password_url_filter: 'github.com',
    website_password_username: 'ada', website_password_password: 'pw', website_password_notes: 'n',
    website_password_auto_submit: true, website_password_totp_code: 'JBSWY3DPEHPK3PXP', website_password_totp_period: 60,
    website_password_totp_algorithm: 'SHA256', website_password_totp_digits: 8,
    custom_fields: [{ name: 'PIN', value: '1234', type: 'password' }, { name: 'Remember', value: true, type: 'checkbox' }],
    attachments: [{ file_id: 'f1' }],
  };
  const m = mapSecret('website_password', content);
  assert.equal(m.type, 'login');
  assert.equal(m.name, 'GitHub');
  assert.deepEqual(m.uris, ['https://github.com/login']);
  assert.match(m.totp, /^otpauth:\/\/totp\/.*period=60.*digits=8.*algorithm=SHA256/);
  assert.deepEqual(m.fields, [{ name: 'PIN', value: '1234', type: 'hidden' }, { name: 'Remember', value: 'true', type: 'boolean' }]);

  const out = buildSecret('website_password', { name: 'GitHub 2', username: 'ada', password: 'neu', uris: ['https://github.com:8443/x'], notes: 'n', totp: m.totp, fields: m.fields }, content);
  assert.equal(out.website_password_title, 'GitHub 2');
  assert.equal(out.website_password_url_filter, 'github.com:8443');
  assert.equal(out.website_password_auto_submit, true, 'kept');
  assert.deepEqual(out.attachments, [{ file_id: 'f1' }], 'kept');
  assert.equal(out.website_password_totp_period, 60);
  assert.equal(out.website_password_totp_algorithm, 'SHA256');
  assert.deepEqual(out.custom_fields, [{ name: 'PIN', value: '1234', type: 'password' }, { name: 'Remember', value: true, type: 'checkbox' }]);
  assert.ok(out.password_modification_datetime, 'password change recorded');
  const cleared = buildSecret('website_password', { name: 'x', username: '', password: 'neu', uris: [], totp: '', fields: [] }, out);
  assert.equal(cleared.website_password_totp_code, undefined);
  assert.equal(cleared.custom_fields, undefined);
  assert.equal(cleared.website_password_url_filter, '');
});

test('other Psono types map to notes, cards, identities and read-only logins', () => {
  assert.deepEqual(mapSecret('note', { note_title: 'N', note_notes: 'text' }).notes, 'text');
  const card = mapSecret('credit_card', { credit_card_title: 'Visa', credit_card_number: '4111', credit_card_name: 'Ada', credit_card_valid_through: '07 / 29', credit_card_cvc: '123', credit_card_pin: '9999' });
  assert.equal(card.type, 'card');
  assert.deepEqual(card.card, { cardholderName: 'Ada', number: '4111', code: '123', brand: '', expMonth: '7', expYear: '2029' });
  assert.deepEqual(card.fields[0], { name: 'PIN', value: '9999', type: 'hidden' });
  const id = mapSecret('identity', { identity_title: 'Me', identity_first_name: 'Ada', identity_city: 'Berlin' });
  assert.equal(id.identity.firstName, 'Ada');
  assert.equal(id.identity.city, 'Berlin');
  const t = mapSecret('totp', { totp_title: '2FA', totp_code: 'jbsw y3dp ehpk 3pxp' });
  assert.equal(t.type, 'login');
  assert.equal(t.totp, 'JBSWY3DPEHPK3PXP');
  const ssh = mapSecret('ssh_connection', { ssh_connection_title: 'Box', ssh_connection_host: 'h.example', ssh_connection_username: 'root', ssh_connection_password: 'x' });
  assert.equal(ssh.type, 'login');
  assert.deepEqual(ssh.fields, [{ name: 'host', value: 'h.example', type: 'hidden' }]);
  const key = mapSecret('ssh_own_key', { ssh_own_key_title: 'Key', ssh_own_key_private: '-----BEGIN', ssh_own_key_notes: 'n' });
  assert.equal(key.type, 'note');
  assert.deepEqual(key.fields, [{ name: 'private', value: '-----BEGIN', type: 'hidden' }]);
});

test('TOTP and address helpers', () => {
  assert.equal(totpFrom(''), undefined);
  assert.equal(totpFrom('jbswy3dpehpk3pxp'), 'JBSWY3DPEHPK3PXP');
  assert.deepEqual(totpTo('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8'), { code: 'JBSWY3DPEHPK3PXP', period: 30, algorithm: 'SHA1', digits: 8 });
  assert.equal(urlFilter('example.org/login'), 'example.org');
  assert.equal(urlFilter('http://[::1]:8080/'), '[::1]:8080');
  assert.equal(parseFolderRef('ds:00000000-0000-0000-0000-000000000000/a/b').path.length, 2);
  assert.equal(parseFolderRef('../x'), null);
  assert.deepEqual(hostPatterns('psono', { server: 'https://psono.example.org:8443/server' }), ['https://psono.example.org/*']);
});

/* ---------- protocol (simulated server) ---------- */

async function withServer(opts, fn) {
  const fake = fakePsono(opts);
  const inner = globalThis.fetch;
  globalThis.fetch = fake.fetch;
  try { return await fn(fake); } finally { globalThis.fetch = inner; }
}

function seed(fake, user) {
  const gh = fake.addEntry('website_password', 'GitHub', { website_password_title: 'GitHub', website_password_url: 'https://github.com', website_password_username: 'ada', website_password_password: 'gh-pw', website_password_url_filter: 'github.com' }, { urlfilter: 'github.com' });
  const note = fake.addEntry('note', 'Notiz', { note_title: 'Notiz', note_notes: 'geheim' });
  const old = fake.addEntry('website_password', 'Alt', { website_password_title: 'Alt', website_password_password: 'x' }, { deleted: true });
  const team = fake.addEntry('application_password', 'DB', { application_password_title: 'DB', application_password_username: 'pg', application_password_password: 'db-pw' });
  const ro = fake.addEntry('website_password', 'Nur lesen', { website_password_title: 'Nur lesen', website_password_password: 'ro-pw' });
  const teamShare = fake.addShare({ name: 'Team', items: [team], folders: [] });
  const roShare = fake.addShare({ name: 'Extern', items: [ro] }, { read: true, write: false, grant: false });
  const ds = fake.addDatastore(user, {
    folders: [
      { id: 'f0000000-0000-4000-8000-000000000001', name: 'Web', items: [gh], folders: [] },
      { id: 'f0000000-0000-4000-8000-000000000002', name: 'Team', ...teamShare },
      { id: 'f0000000-0000-4000-8000-000000000003', name: 'Extern', ...roShare },
      { id: 'f0000000-0000-4000-8000-000000000004', name: 'Weg', deleted: true, items: [] },
    ],
    items: [note, old],
  });
  return { gh, note, old, team, ro, ds, teamShare, roShare };
}

test('sign-in: key pinning, /server discovery, wrong password, then datastore with shares', async () => {
  await withServer({}, async (fake) => {
    const user = fake.addUser({ username: 'ada@example.com', password: 'Richtig 1' });
    const s = seed(fake, user);
    const config = { id: 'p1', server: 'https://psono.test', username: 'Ada@Example.com' };
    await assert.rejects(PsonoProvider.login(config, { password: 'falsch' }), (e) => e.code === 'bad_password');
    const r = await PsonoProvider.login(config, { password: 'Richtig 1' });
    assert.equal(r.status, 'ok');
    assert.equal(r.configPatch.server, 'https://psono.test/server', 'API found below /server');
    assert.equal(r.configPatch.serverVerifyKey, fake.verifyKey);
    assert.match(r.configPatch.deviceId, /^[0-9a-f-]{36}$/);
    Object.assign(config, r.configPatch);
    assert.equal(r.session.userSecretKey, user._secretKey);
    assert.equal(r.session.userPrivateKey, user._privateKey);

    const out = await PsonoProvider.sync(config, r.session);
    const by = Object.fromEntries(out.items.map((i) => [i.name, i]));
    assert.deepEqual(Object.keys(by).sort(), ['DB', 'GitHub', 'Notiz', 'Nur lesen']);
    assert.equal(by.GitHub.username, 'ada');
    assert.equal(by.GitHub.password, undefined, 'lazy: no password in the cache');
    assert.equal(by.GitHub.hasPassword, true);
    assert.equal(by.GitHub.folder, 'Web');
    assert.equal(by.DB.folder, 'Team');
    assert.equal(by.DB.canEdit, true);
    assert.equal(by['Nur lesen'].canEdit, false, 'share without write right');
    assert.equal(by.Notiz.type, 'note');
    assert.deepEqual(out.trash.map((i) => i.name), ['Alt']);
    assert.deepEqual(out.folders.map((f) => f.name), ['Extern', 'Team', 'Web']);
    const full = await PsonoProvider.reveal(config, r.session, by.DB);
    assert.equal(full.password, 'db-pw');
    assert.equal(full.username, 'pg');

    // the server key is pinned: another server under the same address is refused
    await withServer({ prefix: '/server' }, async (other) => {
      other.addUser({ username: 'ada@example.com', password: 'Richtig 1' });
      await assert.rejects(PsonoProvider.login(config, { password: 'Richtig 1' }), (e) => e.code === 'server_key_changed');
    });

    // lock: the token is gone on the server
    await PsonoProvider.logout(config, r.session);
    await assert.rejects(PsonoProvider.sync(config, r.session), (e) => e.code === 'session_expired');
  });
});

test('second factor: TOTP asked, wrong code, then the right one; YubiKey OTP; multifactor asks for each', async () => {
  await withServer({}, async (fake) => {
    const user = fake.addUser({ username: 'mfa@example.com', password: 'pw', ga: 'JBSWY3DPEHPK3PXP', yubikey: 'cccccckdvvulethkhtvkrtbeukiettghhdbnbhfcucbu' });
    fake.addDatastore(user, { items: [] });
    const config = { id: 'p2', server: fake.url, username: 'mfa@example.com' };
    const r = await PsonoProvider.login(config, { password: 'pw' });
    assert.equal(r.status, 'needs_2fa');
    assert.deepEqual(r.twoFactorProviders.map((p) => p.id), ['google_authenticator_2fa', 'yubikey_otp_2fa']);
    assert.equal(r.pending.kind, 'psono');
    Object.assign(config, r.configPatch);
    await assert.rejects(
      PsonoProvider.login(config, { pending: r.pending, twoFactorProvider: 'google_authenticator_2fa', twoFactorCode: '000000' }),
      (e) => e.code === 'bad_2fa',
    );
    const { code } = await totp('JBSWY3DPEHPK3PXP');
    const ok = await PsonoProvider.login(config, { pending: r.pending, twoFactorProvider: 'google_authenticator_2fa', twoFactorCode: code });
    assert.equal(ok.status, 'ok');
    assert.equal((await PsonoProvider.sync(config, ok.session)).items.length, 0);

    // code given together with the password (one step), YubiKey OTP
    const y = await PsonoProvider.login(config, { password: 'pw', twoFactorProvider: 'yubikey_otp_2fa', twoFactorCode: user.yubikey });
    assert.equal(y.status, 'ok');
  });
  await withServer({ multifactor: true }, async (fake) => {
    const user = fake.addUser({ username: 'all@example.com', password: 'pw', ga: 'JBSWY3DPEHPK3PXP', yubikey: 'ccccccotp' });
    fake.addDatastore(user, { items: [] });
    const config = { id: 'p3', server: fake.url, username: 'all@example.com' };
    const { code } = await totp('JBSWY3DPEHPK3PXP');
    const first = await PsonoProvider.login(config, { password: 'pw', twoFactorProvider: 'google_authenticator_2fa', twoFactorCode: code });
    assert.equal(first.status, 'needs_2fa', 'the next factor is asked for');
    assert.deepEqual(first.twoFactorProviders.map((p) => p.id), ['yubikey_otp_2fa']);
    const done = await PsonoProvider.login(config, { pending: first.pending, twoFactorProvider: 'yubikey_otp_2fa', twoFactorCode: 'ccccccotp' });
    assert.equal(done.status, 'ok');
  });
});

test('requests carry the encrypted validator; a forged device id ends the session', async () => {
  await withServer({}, async (fake) => {
    const user = fake.addUser({ username: 'v@example.com', password: 'pw' });
    fake.addDatastore(user, { items: [] });
    const config = { id: 'p4', server: fake.url, username: 'v@example.com', deviceId: 'device-a' };
    const { session } = await PsonoProvider.login(config, { password: 'pw' });
    await PsonoProvider.sync(config, session);
    await assert.rejects(PsonoProvider.sync(config, { ...session, deviceId: 'device-b' }), (e) => e.code === 'session_expired');
    await assert.rejects(PsonoProvider.sync(config, session), (e) => e.code === 'session_expired', 'server deleted the token');
  });
});

test('writes: create in folder and share, edit with conflict check, move, trash, restore, purge, new folder', async () => {
  await withServer({}, async (fake) => {
    const user = fake.addUser({ username: 'w@example.com', password: 'pw' });
    const s = seed(fake, user);
    const config = { id: 'p5', server: fake.url, username: 'w@example.com' };
    const { session } = await PsonoProvider.login(config, { password: 'pw' });
    let out = await PsonoProvider.sync(config, session);
    const folder = (name) => out.folders.find((f) => f.name === name).id;

    // create in a datastore folder
    const created = await PsonoProvider.saveItem(config, session, null, {
      type: 'login', name: 'Shop', username: 'kunde', password: 'shop-pw', uris: ['https://shop.example.org/login'], totp: '', notes: '', folderId: folder('Web'), fields: [],
    });
    assert.equal(created.item.password, 'shop-pw');
    let tree = fake.treeOf(s.ds);
    const web = tree.folders.find((f) => f.name === 'Web');
    const node = web.items.find((i) => i.name === 'Shop');
    assert.equal(node.type, 'website_password');
    assert.equal(node.urlfilter, 'shop.example.org');
    assert.equal(fake.secretContent(node.secret_id, node.secret_key).website_password_username, 'kunde');
    assert.equal(fake.state.secrets.get(node.secret_id).parent, s.ds.id);

    // create in a shared folder: the secret's parent is the share, the node lands in the share
    await PsonoProvider.saveItem(config, session, null, { type: 'note', name: 'Team-Notiz', notes: 'hallo', folderId: folder('Team') });
    const shared = fake.shareTree(fake.state.shares.get(s.teamShare.share_id));
    assert.ok(shared.items.some((i) => i.name === 'Team-Notiz' && i.type === 'note'));
    // a read-only share refuses
    await assert.rejects(PsonoProvider.saveItem(config, session, null, { type: 'note', name: 'x', notes: '', folderId: folder('Extern') }), (e) => e.code === 'forbidden');

    // edit: rename + move to the top level, keeps unknown fields
    out = await PsonoProvider.sync(config, session);
    const gh = out.items.find((i) => i.name === 'GitHub');
    const ghFull = { ...gh, ...await PsonoProvider.reveal(config, session, gh) };
    const edited = await PsonoProvider.saveItem(config, session, ghFull, { type: 'login', name: 'GitHub neu', username: 'ada', password: 'neu', uris: ['https://github.com'], totp: '', notes: '', folderId: null, fields: [] });
    assert.equal(edited.item.folderId, null);
    tree = fake.treeOf(s.ds);
    assert.ok(tree.items.some((i) => i.id === s.gh.id && i.name === 'GitHub neu'), 'moved to the top');
    assert.ok(!tree.folders.find((f) => f.name === 'Web').items.some((i) => i.id === s.gh.id));
    // the same stale copy again: the server changed meanwhile
    await assert.rejects(PsonoProvider.saveItem(config, session, ghFull, { type: 'login', name: 'x', password: 'y', uris: [], folderId: null }), (e) => e.code === 'conflict');
    // across shares: refused with a hint
    const fresh = (await PsonoProvider.sync(config, session)).items.find((i) => i.name === 'GitHub neu');
    await assert.rejects(PsonoProvider.saveItem(config, session, { ...fresh, ...await PsonoProvider.reveal(config, session, fresh) }, { type: 'login', name: 'GitHub neu', password: 'neu', uris: [], folderId: folder('Team') }), (e) => e.code === 'unsupported');

    // a concurrent change of the tree: one retry on a fresh copy
    const realFetch = globalThis.fetch;
    let raced = false;
    globalThis.fetch = async (url, init = {}) => {
      if (!raced && init.method === 'POST' && String(url).endsWith('/datastore/')) {
        raced = true;
        s.ds.write_date = new Date(Date.now() + 5000).toISOString(); // someone else wrote
      }
      return realFetch(url, init);
    };
    const folderRes = await PsonoProvider.createFolder(config, session, { name: 'Neu' });
    globalThis.fetch = realFetch;
    assert.ok(raced);
    assert.ok(fake.treeOf(s.ds).folders.some((f) => f.name === 'Neu'));
    assert.match(folderRes.folder.id, /^ds:/);

    // trash, restore, purge
    out = await PsonoProvider.sync(config, session);
    const shop = out.items.find((i) => i.name === 'Shop');
    await PsonoProvider.deleteItem(config, session, shop);
    out = await PsonoProvider.sync(config, session);
    assert.ok(out.trash.some((i) => i.name === 'Shop'));
    const back = await PsonoProvider.restoreItem(config, session, out.trash.find((i) => i.name === 'Shop'));
    assert.equal(back.item.name, 'Shop');
    out = await PsonoProvider.sync(config, session);
    assert.ok(out.items.some((i) => i.name === 'Shop'));
    const old = out.trash.find((i) => i.name === 'Alt');
    await PsonoProvider.purgeItem(config, session, old);
    assert.equal(fake.state.secrets.has(s.old.secret_id), false, 'secret removed with its last link');
    out = await PsonoProvider.sync(config, session);
    assert.equal(out.trash.length, 0);
  });
});

test('an account without a datastore: empty list, the first entry creates one', async () => {
  await withServer({}, async (fake) => {
    fake.addUser({ username: 'neu@example.com', password: 'pw' });
    const config = { id: 'p6', server: fake.url, username: 'neu@example.com' };
    const { session } = await PsonoProvider.login(config, { password: 'pw' });
    assert.deepEqual((await PsonoProvider.sync(config, session)).items, []);
    await PsonoProvider.saveItem(config, session, null, { type: 'login', name: 'Erster', password: 'p', uris: [], folderId: null });
    const out = await PsonoProvider.sync(config, session);
    assert.deepEqual(out.items.map((i) => i.name), ['Erster']);
    assert.equal(fake.state.datastores.size, 1);
  });
});
