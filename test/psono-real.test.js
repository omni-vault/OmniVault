// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Psono provider against a REAL Psono server (test/psono-server.sh start; data from test/psono-seed.mjs).
// Usage: PSONO_URL=http://127.0.0.1:8935 node --test test/psono-real.test.js  (skipped without PSONO_URL)
import assert from 'node:assert/strict';
import { test } from 'node:test';
import PsonoProvider from '../src/providers/psono/index.js';
import { request } from '../src/providers/psono/api.js';
import { totp } from '../src/lib/totp.js';
import { readDatastore, readSecret, seedPsono } from './psono-seed.mjs';

const BASE = process.env.PSONO_URL;
const skip = !BASE && 'PSONO_URL not set';
const seed = BASE ? await seedPsono(BASE) : null;

async function signIn(username, extra = {}) {
  const config = { id: username, server: BASE, username };
  const r = await PsonoProvider.login(config, { password: seed.password, ...extra });
  Object.assign(config, r.configPatch);
  return { config, r, session: r.session, call: (path, opts = {}) => request(r.session.base, path, { ...opts, session: r.session }) };
}

test('sign-in, datastore with own and foreign shares, lazy read', { skip }, async () => {
  await assert.rejects(PsonoProvider.login({ id: 'x', server: BASE, username: seed.ada }, { password: 'falsch' }), /Benutzername oder Passwort falsch/);
  const { config, r, session } = await signIn(seed.ada);
  assert.equal(r.status, 'ok');
  assert.match(r.configPatch.serverVerifyKey, /^[0-9a-f]{64}$/);
  const out = await PsonoProvider.sync(config, session);
  const by = Object.fromEntries(out.items.map((i) => [i.name, i]));
  assert.deepEqual(Object.keys(by).sort(), ['Datenbank', 'GitHub', 'Lieferant', 'Notiz']);
  assert.deepEqual(out.folders.map((f) => f.name), ['Extern', 'Team', 'Web']);
  assert.deepEqual(out.trash.map((i) => i.name), ['Alt']);
  assert.equal(by.GitHub.folder, 'Web');
  assert.equal(by.GitHub.username, 'ada');
  assert.equal(by.GitHub.password, undefined);
  assert.equal(by.GitHub.hasTotp, true);
  assert.equal(by.Datenbank.canEdit, true);
  assert.equal(by.Lieferant.canEdit, false, 'read-only share');
  assert.equal(by.Lieferant.username, 'einkauf');
  const gh = await PsonoProvider.reveal(config, session, by.GitHub);
  assert.equal(gh.password, 'gh-geheim');
  assert.equal(gh.totp, 'JBSWY3DPEHPK3PXP');
  assert.deepEqual(gh.fields, [{ name: 'Recovery', value: 'r-123', type: 'hidden' }]);
  assert.equal((await PsonoProvider.reveal(config, session, by.Lieferant)).password, 'nur-lesen');
  await PsonoProvider.logout(config, session);
  await assert.rejects(PsonoProvider.sync(config, session), (e) => e.code === 'session_expired', 'token ended on the server');
});

test('writes: create, edit (keeps Psono fields), move, read-only share, conflict, trash, restore, purge, folder', { skip }, async () => {
  const { config, session, call } = await signIn(seed.ada);
  let out = await PsonoProvider.sync(config, session);
  const folder = (name) => out.folders.find((f) => f.name === name).id;

  const shop = await PsonoProvider.saveItem(config, session, null, {
    type: 'login', name: 'Shop', username: 'kunde', password: 'shop-pw', uris: ['https://shop.example.org/login'], totp: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8',
    notes: 'n', folderId: folder('Web'), fields: [{ name: 'Kundennr', value: '7', type: 'text' }],
  });
  let ds = await readDatastore(call, session);
  const node = ds.tree.folders.find((f) => f.name === 'Web').items.find((i) => i.id === shop.item.id);
  assert.equal(node.urlfilter, 'shop.example.org');
  const content = await readSecret(call, node);
  assert.equal(content.website_password_password, 'shop-pw');
  assert.equal(content.website_password_totp_digits, 8);
  assert.deepEqual(content.custom_fields, [{ name: 'Kundennr', value: '7', type: 'text' }]);

  await PsonoProvider.saveItem(config, session, null, { type: 'note', name: 'Team-Notiz', notes: 'hallo', folderId: folder('Team') });
  await assert.rejects(
    PsonoProvider.saveItem(config, session, null, { type: 'note', name: 'nein', notes: '', folderId: folder('Extern') }),
    (e) => e.code === 'forbidden',
  );

  out = await PsonoProvider.sync(config, session);
  assert.ok(out.items.some((i) => i.name === 'Team-Notiz' && i.folder === 'Team'));
  const gh = out.items.find((i) => i.name === 'GitHub');
  const ghFull = { ...gh, ...await PsonoProvider.reveal(config, session, gh) };
  await PsonoProvider.saveItem(config, session, ghFull, {
    type: 'login', name: 'GitHub', username: 'ada', password: 'gh-neu', uris: ['http://localhost/login.html'], totp: ghFull.totp, notes: ghFull.notes,
    folderId: null, fields: ghFull.fields,
  });
  ds = await readDatastore(call, session);
  const ghNode = ds.tree.items.find((i) => i.id === seed.ids.gh);
  assert.ok(ghNode, 'moved to the top level');
  const ghContent = await readSecret(call, ghNode);
  assert.equal(ghContent.website_password_password, 'gh-neu');
  assert.equal(ghContent.website_password_auto_submit, false, 'Psono field kept');
  assert.ok(ghContent.password_modification_datetime);
  await assert.rejects(
    PsonoProvider.saveItem(config, session, ghFull, { type: 'login', name: 'GitHub', password: 'stale', uris: [], folderId: null }),
    (e) => e.code === 'conflict', 'stale copy refused (write date)',
  );

  const folderRes = await PsonoProvider.createFolder(config, session, { name: 'Neu' });
  assert.ok((await readDatastore(call, session)).tree.folders.some((f) => f.name === 'Neu'));
  out = await PsonoProvider.sync(config, session);
  assert.ok(out.folders.some((f) => f.id === folderRes.folder.id));

  const s = out.items.find((i) => i.name === 'Shop');
  await PsonoProvider.deleteItem(config, session, s);
  out = await PsonoProvider.sync(config, session);
  assert.ok(out.trash.some((i) => i.name === 'Shop') && !out.items.some((i) => i.name === 'Shop'));
  await PsonoProvider.restoreItem(config, session, out.trash.find((i) => i.name === 'Shop'));
  out = await PsonoProvider.sync(config, session);
  assert.ok(out.items.some((i) => i.name === 'Shop'));
  const alt = out.trash.find((i) => i.name === 'Alt');
  await PsonoProvider.purgeItem(config, session, alt);
  await assert.rejects(call(`secret/${alt._psono.secretId}/`), (e) => e.code === 'forbidden', 'secret gone with its link');
  out = await PsonoProvider.sync(config, session);
  assert.equal(out.trash.length, 0);
  await PsonoProvider.logout(config, session);
});

test('second factor: authenticator app (TOTP)', { skip }, async () => {
  const config = { id: 'm', server: BASE, username: seed.mfa };
  const r = await PsonoProvider.login(config, { password: seed.password });
  assert.equal(r.status, 'needs_2fa');
  assert.deepEqual(r.twoFactorProviders.map((p) => p.id), ['google_authenticator_2fa']);
  Object.assign(config, r.configPatch);
  await assert.rejects(
    PsonoProvider.login(config, { pending: r.pending, twoFactorProvider: 'google_authenticator_2fa', twoFactorCode: '000000' }),
    (e) => e.code === 'bad_2fa',
  );
  const ok = await PsonoProvider.login(config, { pending: r.pending, twoFactorProvider: 'google_authenticator_2fa', twoFactorCode: (await totp(seed.gaSecret)).code });
  assert.equal(ok.status, 'ok');
  await PsonoProvider.sync(config, ok.session);
  // the half-open session of a login that never answered the factor cannot read anything
  const pending = (await PsonoProvider.login(config, { password: seed.password })).pending;
  await assert.rejects(request(pending.base, 'datastore/', { session: pending }), (e) => e.code === 'session_expired');
  await PsonoProvider.logout(config, ok.session);
});
