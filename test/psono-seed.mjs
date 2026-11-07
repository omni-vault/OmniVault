// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Test data on a REAL Psono server (test/psono-server.sh start), fresh for every run (user names carry a run id):
//  - ada: a datastore with a folder "Web" (GitHub login with TOTP and custom fields), a note, an entry in the trash,
//    her own shared folder "Team" (one application password) and bob's folder "Extern", shared with her read-only
//  - mfa: an account with an authenticator app (TOTP) as second factor
// Users come from Psono's own `createuser` command; everything else goes through the API as a client would.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import PsonoProvider from '../src/providers/psono/index.js';
import { request } from '../src/providers/psono/api.js';
import { decryptSymmetric, encryptBox, encryptSymmetric, randomKey } from '../src/providers/psono/crypto.js';
import { totp } from '../src/lib/totp.js';

const SCRIPT = fileURLToPath(new URL('./psono-server.sh', import.meta.url));
export const PASSWORD = 'Psono-Test 1 ✓';
export const TOTP_SECRET_FIELD = 'JBSWY3DPEHPK3PXP';

function createUser(username) {
  execFileSync(SCRIPT, ['createuser', username, PASSWORD, username], { stdio: 'pipe' });
}

async function signIn(base, username, extra = {}) {
  const config = { id: username, server: base, username };
  const r = await PsonoProvider.login(config, { password: PASSWORD, ...extra });
  if (r.status !== 'ok') throw new Error(`seed login ${username}: ${r.status}`);
  Object.assign(config, r.configPatch);
  return { config, session: r.session, call: (path, opts = {}) => request(r.session.base, path, { ...opts, session: r.session }) };
}

/** A new secret plus its datastore node. */
async function entry(call, parent, type, name, content, extra = {}) {
  const key = randomKey();
  const enc = encryptSymmetric(key, JSON.stringify(content));
  const linkId = crypto.randomUUID();
  const { secret_id } = await call('secret/', {
    method: 'PUT',
    body: { data: enc.text, data_nonce: enc.nonce, link_id: linkId, callback_url: '', callback_user: '', callback_pass: '', ...parent },
  });
  return { id: linkId, name, type, secret_id, secret_key: key, ...extra };
}

async function createDatastore(call, session, tree) {
  const key = randomKey();
  const sk = encryptSymmetric(session.userSecretKey, key);
  const data = encryptSymmetric(key, JSON.stringify(tree));
  const { datastore_id } = await call('datastore/', {
    method: 'PUT', body: { type: 'password', description: 'default', data: data.text, data_nonce: data.nonce, secret_key: sk.text, secret_key_nonce: sk.nonce, is_default: true },
  });
  return { id: datastore_id, key };
}

async function writeDatastore(call, ds, tree) {
  const data = encryptSymmetric(ds.key, JSON.stringify(tree));
  await call('datastore/', { method: 'POST', body: { datastore_id: ds.id, data: data.text, data_nonce: data.nonce } });
}

/** A share below a datastore: { share_id, share_secret_key } for the node, the share's link id as `id`. */
async function createShare(call, session, dsId, content) {
  const key = randomKey();
  const data = encryptSymmetric(key, JSON.stringify(content));
  const k = encryptSymmetric(session.userSecretKey, key);
  const linkId = crypto.randomUUID();
  const { share_id } = await call('share/', {
    method: 'POST', // creates; PUT updates
    body: { link_id: linkId, data: data.text, data_nonce: data.nonce, parent_datastore_id: dsId, key: k.text, key_nonce: k.nonce, key_type: 'symmetric' },
  });
  return { id: linkId, share_id, share_secret_key: key };
}

export async function readDatastore(call, session) {
  const { datastores } = await call('datastore/');
  const d = datastores.find((x) => x.type === 'password' && x.is_default) ?? datastores.find((x) => x.type === 'password');
  const r = await call(`datastore/${d.id}/`);
  const key = decryptSymmetric(session.userSecretKey, r.secret_key, r.secret_key_nonce);
  return { id: d.id, key, tree: r.data ? JSON.parse(decryptSymmetric(key, r.data, r.data_nonce)) : {} };
}

export async function readSecret(call, node) {
  const r = await call(`secret/${node.secret_id}/`);
  return JSON.parse(decryptSymmetric(node.secret_key, r.data, r.data_nonce));
}

export async function seedPsono(base) {
  const run = Date.now().toString(36);
  const ada = `ada-${run}@example.com`;
  const bob = `bob-${run}@example.com`;
  const mfa = `mfa-${run}@example.com`;
  for (const u of [ada, bob, mfa]) createUser(u);

  // bob: a folder he shares read-only with ada
  const B = await signIn(base, bob);
  const bobDs = await createDatastore(B.call, B.session, { folders: [], items: [] });
  const bobShareContent = { name: 'Extern', items: [], folders: [] };
  const extShare = await createShare(B.call, B.session, bobDs.id, bobShareContent);
  bobShareContent.items.push(await entry(B.call, { parent_share_id: extShare.share_id }, 'website_password', 'Lieferant', {
    website_password_title: 'Lieferant', website_password_url: 'https://lieferant.example.net', website_password_username: 'einkauf', website_password_password: 'nur-lesen',
  }, { urlfilter: 'lieferant.example.net' }));
  const enc = encryptSymmetric(extShare.share_secret_key, JSON.stringify(bobShareContent));
  await B.call('share/', { method: 'PUT', body: { share_id: extShare.share_id, data: enc.text, data_nonce: enc.nonce } });
  await writeDatastore(B.call, bobDs, { folders: [{ id: extShare.id, name: 'Extern', share_id: extShare.share_id, share_secret_key: extShare.share_secret_key }], items: [] });

  // ada
  const A = await signIn(base, ada);
  const adaDs = await createDatastore(A.call, A.session, {});
  const parent = { parent_datastore_id: adaDs.id };
  const gh = await entry(A.call, parent, 'website_password', 'GitHub', {
    website_password_title: 'GitHub', website_password_url: 'http://localhost/login.html', website_password_url_filter: 'localhost',
    website_password_username: 'ada', website_password_password: 'gh-geheim', website_password_notes: 'Notiz zu GitHub',
    website_password_auto_submit: false, website_password_totp_code: TOTP_SECRET_FIELD,
    custom_fields: [{ name: 'Recovery', value: 'r-123', type: 'password' }],
  }, { urlfilter: 'localhost' });
  const note = await entry(A.call, parent, 'note', 'Notiz', { note_title: 'Notiz', note_notes: 'geheime Notiz' });
  const old = await entry(A.call, parent, 'website_password', 'Alt', { website_password_title: 'Alt', website_password_password: 'alt' }, { deleted: true });
  const teamContent = { name: 'Team', items: [], folders: [] };
  const team = await createShare(A.call, A.session, adaDs.id, teamContent);
  teamContent.items.push(await entry(A.call, { parent_share_id: team.share_id }, 'application_password', 'Datenbank', {
    application_password_title: 'Datenbank', application_password_username: 'postgres', application_password_password: 'db-geheim',
  }));
  const tenc = encryptSymmetric(team.share_secret_key, JSON.stringify(teamContent));
  await A.call('share/', { method: 'PUT', body: { share_id: team.share_id, data: tenc.text, data_nonce: tenc.nonce } });

  // bob grants ada read access to "Extern"; ada accepts and links it into her datastore
  const found = await B.call('user/search/', { method: 'POST', body: { user_username: ada } });
  const target = Array.isArray(found) ? found[0] : found;
  const box = (text) => encryptBox(text, target.public_key, B.session.userPrivateKey);
  const k = box(extShare.share_secret_key);
  const title = box('Extern');
  const type = box('folder');
  const right = await B.call('share/right/', {
    method: 'PUT',
    body: {
      share_id: extShare.share_id, user_id: target.id, key: k.text, key_nonce: k.nonce, title: title.text, title_nonce: title.nonce,
      type: type.text, type_nonce: type.nonce, read: true, write: false, grant: false,
    },
  });
  const ak = encryptSymmetric(A.session.userSecretKey, extShare.share_secret_key);
  await A.call('share/right/accept/', { method: 'POST', body: { share_right_id: right.share_right_id, key: ak.text, key_nonce: ak.nonce, key_type: 'symmetric' } });

  await writeDatastore(A.call, adaDs, {
    folders: [
      { id: crypto.randomUUID(), name: 'Web', items: [gh], folders: [] },
      { id: team.id, name: 'Team', share_id: team.share_id, share_secret_key: team.share_secret_key },
      { id: crypto.randomUUID(), name: 'Extern', share_id: extShare.share_id, share_secret_key: extShare.share_secret_key },
    ],
    items: [note, old],
  });
  await PsonoProvider.logout(A.config, A.session);
  await PsonoProvider.logout(B.config, B.session);

  // mfa: authenticator app as second factor
  const M = await signIn(base, mfa);
  await createDatastore(M.call, M.session, { items: [] });
  const ga = await M.call('user/ga/', { method: 'PUT', body: { title: 'OmniVault test' } });
  await M.call('user/ga/', { method: 'POST', body: { google_authenticator_id: ga.id, google_authenticator_token: (await totp(ga.secret)).code } });
  await PsonoProvider.logout(M.config, M.session);

  return { run, ada, bob, mfa, password: PASSWORD, gaSecret: ga.secret, ids: { gh: gh.id, note: note.id, old: old.id, team: team.share_id, ext: extShare.share_id } };
}
