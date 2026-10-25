// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Bitwarden Send against the simulated server: key derivation against node:crypto, link format, text and file Sends
// (direct and Azure upload), password, limits, editing, deletion – and every link opened like a recipient and
// decrypted by the independent Python checker.
import assert from 'node:assert/strict';
import { hkdfSync, pbkdf2Sync } from 'node:crypto';
import { test } from 'node:test';
import BitwardenProvider from '../src/providers/bitwarden/index.js';
import { endpoints } from '../src/providers/bitwarden/api.js';
import { parseSendLink, sendContentKey, sendLink, sendPasswordHash } from '../src/providers/bitwarden/send.js';
import { EMAIL, PASSWORD, fakeBitwarden } from './fake-bitwarden.js';
import { pyCheck, pythonChecker, receiveSend } from './send-recipient.mjs';

const config = { id: 'acc1', server: 'https://vault.example.org', email: EMAIL };
const ep = endpoints(config.server);
const inDays = (d) => new Date(Date.now() + d * 86400_000).toISOString();

async function server(opts = {}) {
  const handle = await fakeBitwarden({ kdf: { kdf: 0, kdfIterations: 5000 }, ...opts });
  const uploads = [];
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url);
    let body = init.body;
    if (body instanceof URLSearchParams) body = body.toString();
    else if (body instanceof FormData) {
      const f = body.get('data');
      body = { fileName: f.name, bytes: new Uint8Array(await f.arrayBuffer()) };
      uploads.push(body);
    }
    if (u.hostname.endsWith('.blob.core.windows.net') && init.method === 'PUT') uploads.push({ azure: u.href, headers: init.headers });
    const headers = init.headers instanceof Headers ? Object.fromEntries(init.headers) : init.headers ?? {};
    const r = handle(u.pathname, { ...init, headers, body });
    if (r.raw) return new Response(r.raw, { status: r.status });
    return new Response(r.body == null ? '' : JSON.stringify(r.body), { status: r.status });
  };
  const { session } = await BitwardenProvider.login(config, { password: PASSWORD });
  return { handle, session, uploads };
}

/** Recipient: link (+ password) → server → Python decrypts; also checks the password hash with Python. */
async function open(link, password) {
  const passwordHash = password == null ? undefined : (pythonChecker ? pyCheck({ link, password }).passwordHash : await sendPasswordHash(password, parseSendLink(link).key));
  const r = await receiveSend(ep, link, { passwordHash });
  if (r.status !== 200) return r;
  const plain = pythonChecker
    ? pyCheck({ link, access: r.access, ...(r.file ? { file: Buffer.from(r.file).toString('base64') } : {}) })
    : null;
  return { ...r, plain };
}

test('content key and password hash match node:crypto (HKDF, PBKDF2)', async () => {
  const sendKey = new Uint8Array(16).map((_, i) => i * 7 + 1);
  const k = await sendContentKey(sendKey);
  const ref = Buffer.from(hkdfSync('sha256', sendKey, 'bitwarden-send', 'send', 64));
  assert.deepEqual(Buffer.from(k.enc), ref.subarray(0, 32));
  assert.deepEqual(Buffer.from(k.mac), ref.subarray(32));
  assert.equal(await sendPasswordHash('pässwort', sendKey), pbkdf2Sync(Buffer.from('pässwort'), sendKey, 100_000, 32, 'sha256').toString('base64'));
});

test('link format per server and parsing', () => {
  const key = new Uint8Array(16).fill(255);
  assert.equal(sendLink(endpoints('bitwarden.com'), 'abc_-1', key), 'https://send.bitwarden.com/#abc_-1/_____________________w');
  assert.equal(sendLink(endpoints('bitwarden.eu'), 'abc', key), 'https://vault.bitwarden.eu/#/send/abc/_____________________w');
  assert.equal(sendLink(endpoints('https://vw.example.org/'), 'abc', key), 'https://vw.example.org/#/send/abc/_____________________w');
  for (const l of ['https://send.bitwarden.com/#abc/_____________________w', 'https://vw.example.org/#/send/abc/_____________________w/']) {
    const p = parseSendLink(l);
    assert.equal(p.accessId, 'abc');
    assert.deepEqual([...p.key], [...key]);
  }
  assert.throws(() => parseSendLink('https://vw.example.org/#/send/abc/AAAA'));
});

test('text Send: create with options, nothing in plain text on the wire, recipient decrypts', { skip: !pythonChecker && 'python3 with cryptography missing' }, async () => {
  const { handle, session } = await server();
  const { send } = await BitwardenProvider.saveSend(config, session, null, {
    type: 'text', name: 'WLAN Büro', text: 'Kennwort: grün-42 🔑', hidden: true, notes: 'nur intern', password: 'offen sesam',
    maxAccessCount: 2, deletionDate: inDays(7), expirationDate: inDays(2), hideEmail: true,
  });
  assert.equal(send.name, 'WLAN Büro');
  assert.equal(send.text, 'Kennwort: grün-42 🔑');
  assert.equal(send.hidden, true);
  assert.equal(send.hasPassword, true);
  assert.equal(send.maxAccessCount, 2);
  assert.match(send.link, /^https:\/\/vault\.example\.org\/#\/send\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]{22}$/);
  const wire = JSON.stringify(handle.requests.filter((r) => r.path.includes('/sends')));
  for (const plain of ['WLAN', 'grün', 'intern', 'offen sesam']) assert.ok(!wire.includes(plain), `${plain} not sent in plain text`);
  const stored = handle.sends.all[0];
  assert.match(stored.key, /^2\./, 'Send key encrypted with the user key');
  assert.equal(stored.password.length > 20, true);

  assert.equal((await open(send.link)).error, 'password_hash_b64_required');
  assert.equal((await open(send.link, 'falsch')).error, 'password_hash_b64_invalid');
  const r = await open(send.link, 'offen sesam');
  assert.equal(r.plain.name, 'WLAN Büro');
  assert.equal(r.plain.text, 'Kennwort: grün-42 🔑');
  assert.equal(r.access.creatorIdentifier, null, 'e-mail hidden');
  await open(send.link, 'offen sesam');
  assert.equal((await open(send.link, 'offen sesam')).error, 'send_id_invalid', 'max. 2 accesses');

  const { sends } = await BitwardenProvider.listSends(config, session);
  assert.equal(sends.length, 1);
  assert.equal(sends[0].accessCount, 2);
  assert.equal(sends[0].link, send.link);
});

test('editing keeps key and password, remove-password, disable, delete', { skip: !pythonChecker && 'python3 with cryptography missing' }, async () => {
  const { handle, session } = await server();
  const { send } = await BitwardenProvider.saveSend(config, session, null, { type: 'text', name: 'A', text: 'eins', password: 'pw', deletionDate: inDays(3) });
  const { send: edited } = await BitwardenProvider.saveSend(config, session, send.id, { name: 'B', text: 'zwei', deletionDate: inDays(5), maxAccessCount: 10 });
  assert.equal(edited.link, send.link, 'link unchanged');
  assert.equal(edited.hasPassword, true, 'password kept when none is given');
  assert.equal((await open(send.link, 'pw')).plain.text, 'zwei');
  const put = handle.requests.find((r) => r.method === 'PUT');
  assert.equal(put.json.password, null);

  const { send: open1 } = await BitwardenProvider.removeSendPassword(config, session, send.id);
  assert.equal(open1.hasPassword, false);
  assert.equal((await open(send.link)).plain.name, 'B');

  await BitwardenProvider.saveSend(config, session, send.id, { name: 'B', text: 'zwei', deletionDate: inDays(5), disabled: true });
  assert.equal((await open(send.link)).error, 'send_id_invalid', 'disabled');

  await BitwardenProvider.deleteSend(config, session, send.id);
  assert.equal((await BitwardenProvider.listSends(config, session)).sends.length, 0);
});

for (const azure of [false, true]) {
  test(`file Send, ${azure ? 'Azure Blob upload (bitwarden.com)' : 'direct upload (Vaultwarden)'}`, { skip: !pythonChecker && 'python3 with cryptography missing' }, async () => {
    const { handle, session, uploads } = await server({ sendAzure: azure });
    const bytes = new Uint8Array(70_000).map((_, i) => (i * 31) % 251);
    const { send } = await BitwardenProvider.saveSend(config, session, null, {
      type: 'file', name: 'Vertrag', notes: 'n', deletionDate: inDays(1), file: { fileName: 'vertrag ä.pdf', data: Buffer.from(bytes).toString('base64') },
    });
    assert.equal(send.type, 'file');
    assert.equal(send.fileName, 'vertrag ä.pdf');
    const stored = handle.sends.all[0];
    if (azure) {
      assert.match(uploads[0].azure, /blob\.core\.windows\.net/);
      assert.equal(uploads[0].headers['x-ms-blob-type'], 'BlockBlob');
    } else {
      assert.equal(uploads[0].fileName, stored.file.fileName, 'multipart file name is the encrypted name');
    }
    assert.equal(handle.sends.files.get(stored.file.id).length, Number(stored.file.size), 'size hint = encrypted length');
    const r = await open(send.link);
    assert.equal(r.plain.fileName, 'vertrag ä.pdf');
    assert.deepEqual(Buffer.from(r.plain.file, 'base64'), Buffer.from(bytes));
    assert.equal((await BitwardenProvider.listSends(config, session)).sends[0].accessCount, 1);
  });
}

test('server refusals in plain words; failed upload leaves no Send behind', async () => {
  const { handle, session } = await server({ sendPremium: false });
  const file = { fileName: 'a.txt', data: Buffer.from('hallo').toString('base64') };
  await assert.rejects(BitwardenProvider.saveSend(config, session, null, { type: 'file', name: 'x', deletionDate: inDays(1), file }), /nur mit Premium/);
  await assert.rejects(BitwardenProvider.saveSend(config, session, null, { type: 'text', name: 'x', text: 'y', deletionDate: inDays(40) }), /höchstens 31 Tage/);
  await assert.rejects(BitwardenProvider.saveSend(config, session, null, { type: 'text', name: 'x', text: 'y', deletionDate: inDays(2), expirationDate: inDays(3) }), /Ablaufdatum darf nicht nach dem Löschdatum/);
  await assert.rejects(BitwardenProvider.saveSend(config, session, null, { type: 'text', name: ' ', deletionDate: inDays(2) }), /Namen/);
  assert.equal(handle.sends.all.length, 0);

  const s2 = await server({ sendAzure: true });
  const inner = globalThis.fetch;
  globalThis.fetch = (url, init) => (String(url).includes('.blob.core.windows.net') ? Promise.resolve(new Response('', { status: 403 })) : inner(url, init));
  await assert.rejects(BitwardenProvider.saveSend(config, s2.session, null, { type: 'file', name: 'x', deletionDate: inDays(1), file }), /HTTP 403/);
  assert.equal(s2.handle.sends.all.length, 0, 'Send removed again');
});
