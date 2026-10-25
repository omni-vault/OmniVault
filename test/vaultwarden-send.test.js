// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Bitwarden Send against a REAL Vaultwarden server: text and file Sends, list, recipient access through the public
// API with independent decryption (test/send-check.py), password, expiry, access limit, editing, deletion.
// Skipped unless VAULTWARDEN_URL is set (see test/vaultwarden.test.js).
import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import BitwardenProvider from '../src/providers/bitwarden/index.js';
import { endpoints } from '../src/providers/bitwarden/api.js';
import { parseSendLink, sendPasswordHash } from '../src/providers/bitwarden/send.js';
import { seedVaultwarden } from './vaultwarden-seed.mjs';
import { pyCheck, pythonChecker, receiveSend } from './send-recipient.mjs';

const URL_ = process.env.VAULTWARDEN_URL;
const opts = { skip: (!URL_ && 'VAULTWARDEN_URL nicht gesetzt') || (!pythonChecker && 'python3 with cryptography missing') };
const inDays = (d) => new Date(Date.now() + d * 86400_000).toISOString();
let config;
let session;
let ep;

before(async () => {
  if (opts.skip) return;
  const seed = await seedVaultwarden(URL_, { withOrg: false });
  config = { id: 'vws', server: URL_, email: seed.email };
  const res = await BitwardenProvider.login(config, { password: seed.password });
  assert.equal(res.status, 'ok');
  if (res.configPatch) Object.assign(config, res.configPatch);
  session = res.session;
  ep = endpoints(URL_);
});

async function open(link, password) {
  const passwordHash = password == null ? undefined : pyCheck({ link, password }).passwordHash;
  if (password != null) assert.equal(passwordHash, await sendPasswordHash(password, parseSendLink(link).key), 'Python and OmniVault hash alike');
  const r = await receiveSend(ep, link, { passwordHash });
  if (r.status !== 200) return r;
  return { ...r, plain: pyCheck({ link, access: r.access, ...(r.file ? { file: Buffer.from(r.file).toString('base64') } : {}) }) };
}

test('real Vaultwarden: text Send with password and access limit, opened like a recipient', opts, async () => {
  const { send } = await BitwardenProvider.saveSend(config, session, null, {
    type: 'text', name: 'Zugang Drucker', text: 'PIN 4711 – ünïcødé ✓', hidden: true, notes: 'für Bob', password: 'geheim 1',
    maxAccessCount: 2, deletionDate: inDays(7), expirationDate: inDays(3), hideEmail: true,
  });
  assert.match(send.link, new RegExp(`^${URL_.replace(/[.]/g, '\\.')}/#/send/[A-Za-z0-9_-]+/[A-Za-z0-9_-]{22}$`));
  assert.equal(send.hasPassword, true, 'Vaultwarden reports the password');
  assert.equal(send.hidden, true);
  assert.ok(['password_hash_b64_required', 'invalid_request'].includes((await open(send.link)).error), 'password needed');
  assert.equal((await open(send.link, 'falsch')).status >= 400, true);
  const r = await open(send.link, 'geheim 1');
  assert.equal(r.plain.name, 'Zugang Drucker');
  assert.equal(r.plain.text, 'PIN 4711 – ünïcødé ✓');
  assert.equal(r.access.creatorIdentifier ?? null, null, 'e-mail hidden');
  assert.equal((await open(send.link, 'geheim 1')).status, 200);
  assert.ok((await open(send.link, 'geheim 1')).status >= 400, 'third access refused (max 2)');

  const { sends } = await BitwardenProvider.listSends(config, session);
  const mine = sends.find((x) => x.id === send.id);
  assert.equal(mine.accessCount, 2);
  assert.equal(mine.maxAccessCount, 2);
  assert.equal(mine.notes, 'für Bob');
  assert.equal(new Date(mine.expirationDate).getTime() > Date.now(), true);
});

test('real Vaultwarden: file Send uploaded and downloaded by a recipient', opts, async () => {
  const bytes = new Uint8Array(300_000).map((_, i) => (i * 13 + 7) % 256);
  const { send } = await BitwardenProvider.saveSend(config, session, null, {
    type: 'file', name: 'Scan', deletionDate: inDays(2), file: { fileName: 'scan 2026 – ü.bin', data: Buffer.from(bytes).toString('base64') },
  });
  assert.equal(send.fileName, 'scan 2026 – ü.bin');
  assert.ok(send.size > bytes.length, 'size of the encrypted file');
  const r = await open(send.link);
  assert.equal(r.status, 200, r.error);
  assert.equal(r.plain.fileName, 'scan 2026 – ü.bin');
  assert.deepEqual(Buffer.from(r.plain.file, 'base64'), Buffer.from(bytes));
  const listed = (await BitwardenProvider.listSends(config, session)).sends.find((x) => x.id === send.id);
  assert.equal(listed.accessCount, 1, 'download counted');
  // the file cannot change, the rest can
  const { send: edited } = await BitwardenProvider.saveSend(config, session, send.id, { name: 'Scan 2', deletionDate: inDays(3), password: 'pw' });
  assert.equal(edited.name, 'Scan 2');
  assert.equal(edited.fileName, 'scan 2026 – ü.bin');
  assert.equal(edited.link, send.link);
  assert.equal((await open(send.link, 'pw')).plain.fileName, 'scan 2026 – ü.bin');
});

test('real Vaultwarden: editing, remove password, disable, expiry, delete', opts, async () => {
  const { send } = await BitwardenProvider.saveSend(config, session, null, { type: 'text', name: 'Alt', text: 'eins', password: 'pw', deletionDate: inDays(1) });
  const { send: e1 } = await BitwardenProvider.saveSend(config, session, send.id, { name: 'Neu', text: 'zwei', deletionDate: inDays(2) });
  assert.equal(e1.link, send.link);
  assert.equal(e1.hasPassword, true, 'password kept when none is given');
  assert.equal((await open(send.link, 'pw')).plain.text, 'zwei');
  const { send: e2 } = await BitwardenProvider.removeSendPassword(config, session, send.id);
  assert.equal(e2.hasPassword, false);
  assert.equal((await open(send.link)).plain.name, 'Neu');
  await BitwardenProvider.saveSend(config, session, send.id, { name: 'Neu', text: 'zwei', deletionDate: inDays(2), disabled: true });
  assert.ok((await open(send.link)).status >= 400, 'disabled Send refused');

  // Vaultwarden accepts an expiry a moment away (Bitwarden wants at least a minute): it must then be refused
  const { send: soon } = await BitwardenProvider.saveSend(config, session, null, { type: 'text', name: 'Kurz', text: 'x', deletionDate: inDays(1), expirationDate: new Date(Date.now() + 2500).toISOString() });
  assert.equal((await open(soon.link)).status, 200);
  await new Promise((r) => setTimeout(r, 3500));
  assert.ok((await open(soon.link)).status >= 400, 'expired Send refused');

  await assert.rejects(BitwardenProvider.saveSend(config, session, null, { type: 'text', name: 'x', text: 'y', deletionDate: inDays(40) }), /höchstens 31 Tage/);
  for (const id of [send.id, soon.id]) await BitwardenProvider.deleteSend(config, session, id);
  const left = (await BitwardenProvider.listSends(config, session)).sends.map((x) => x.id);
  assert.ok(!left.includes(send.id) && !left.includes(soon.id));
  assert.ok((await open(send.link)).status >= 400, 'deleted Send gone');
});
