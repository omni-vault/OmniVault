// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Password-protected Bitwarden JSON (export and import, checked against node:crypto, an independent Python check and
// files written by the official Bitwarden CLI), account-restricted Bitwarden exports, ZIP archives (1Password .1pux,
// Proton Pass) including ZIP bombs, ZIP64 and encrypted archives, and PGP-encrypted Proton Pass exports.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createDecipheriv, createHmac, pbkdf2Sync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as openpgp from '../vendor/openpgp.mjs';
import { EXPORT_KDF, decryptBitwardenJson, encryptBitwardenJson, toBitwardenJson } from '../src/lib/export.js';
import { decryptPgp, import1Pux, readImportFile } from '../src/lib/import.js';
import { ZIP_LIMITS, openZip } from '../src/lib/zip.js';
import BitwardenProvider from '../src/providers/bitwarden/index.js';
import { importItems } from '../src/background/tools.js';
import { writeZip } from './zip-write.mjs';

const fixture = (name) => JSON.parse(readFileSync(new URL(`fixtures/bitwarden-cli/${name}`, import.meta.url), 'utf8'));
const META = fixture('fixtures.json');
const bytes = (s) => new TextEncoder().encode(typeof s === 'string' ? s : JSON.stringify(s));
const PLAIN_ITEMS = [
  { type: 'login', name: 'Login ä', username: 'ada', password: 'pw-1', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://example.org/'], notes: 'n', folder: 'F', favorite: true,
    fields: [{ name: 'PIN', value: '0815', type: 'hidden' }] },
  { type: 'card', name: 'Karte', card: { cardholderName: 'Ada', number: '4111111111111111', expMonth: '7', expYear: '2031', code: '321', brand: 'Visa' } },
  { type: 'ssh', name: 'Schlüssel', ssh: { privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----', publicKey: 'ssh-ed25519 AAAA', fingerprint: 'SHA256:abc' } },
];
const python = spawnSync('python3', ['-c', 'import cryptography.hazmat.primitives.kdf.argon2'], { encoding: 'utf8' }).status === 0;

/* ---------- password-protected Bitwarden JSON ---------- */

test('protected export (PBKDF2) decrypts with node:crypto, independently of the code under test', async () => {
  const plain = toBitwardenJson(PLAIN_ITEMS);
  const file = JSON.parse(await encryptBitwardenJson(plain, 'Korrekt Pferd Batterie', { kdfType: 0, kdfIterations: 5000 }));
  assert.equal(file.encrypted, true);
  assert.equal(file.passwordProtected, true);
  assert.equal(file.kdfType, 0);
  assert.equal(file.kdfIterations, 5000);
  assert.equal(Buffer.from(file.salt, 'base64').length, 16, 'salt: 16 random bytes, base64');
  const master = pbkdf2Sync('Korrekt Pferd Batterie', file.salt, 5000, 32, 'sha256');
  const enc = createHmac('sha256', master).update(Buffer.concat([Buffer.from('enc'), Buffer.from([1])])).digest();
  const mac = createHmac('sha256', master).update(Buffer.concat([Buffer.from('mac'), Buffer.from([1])])).digest();
  const open = (s) => {
    const [iv, ct, tag] = s.slice(2).split('|').map((x) => Buffer.from(x, 'base64'));
    assert.ok(s.startsWith('2.'));
    assert.deepEqual(createHmac('sha256', mac).update(Buffer.concat([iv, ct])).digest(), tag);
    const d = createDecipheriv('aes-256-cbc', enc, iv);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  };
  assert.match(open(file.encKeyValidation_DO_NOT_EDIT), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.equal(open(file.data), plain);
});

test('protected export (Argon2id and PBKDF2) passes the independent Python check', { skip: !python && 'python3 with cryptography ≥ 44 not available' }, async () => {
  const plain = toBitwardenJson(PLAIN_ITEMS);
  for (const kdf of [EXPORT_KDF.argon2id, { kdfType: 0, kdfIterations: 10_000 }]) {
    const file = JSON.parse(await encryptBitwardenJson(plain, 'Ein langes Export-Passwort', kdf));
    const run = (password) => spawnSync('python3', ['-I', new URL('bw-export-check.py', import.meta.url).pathname], { input: JSON.stringify({ file, password }), encoding: 'utf8' });
    const r = run('Ein langes Export-Passwort');
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout).data, JSON.parse(plain), `kdfType ${kdf.kdfType}`);
    assert.equal(run('falsch').status, 2, 'wrong password detected by the checker');
  }
});

test('protected exports written by the Bitwarden CLI open (PBKDF2 and Argon2id)', async () => {
  for (const name of ['protected-pbkdf2.json', 'protected-argon2id.json']) {
    const file = readFileSync(new URL(`fixtures/bitwarden-cli/${name}`, import.meta.url));
    assert.deepEqual(await readImportFile(new Uint8Array(file)), { need: 'password', kind: 'bitwarden' });
    const r = await readImportFile(new Uint8Array(file), { password: META[name].password });
    assert.equal(r.format, 'bitwarden');
    assert.ok(r.items.length >= 4, name);
    await assert.rejects(readImportFile(new Uint8Array(file), { password: 'falsch' }), (e) => e.code === 'bad_password' && /Falsches Passwort/.test(e.message));
  }
  const r = await readImportFile(new Uint8Array(readFileSync(new URL('fixtures/bitwarden-cli/protected-argon2id.json', import.meta.url))), { password: META['protected-argon2id.json'].password });
  const login = r.items.find((i) => i.name === 'Fixture Login');
  assert.equal(login.password, 'Fixture-Pass-1');
  assert.equal(login.folder, 'Fixture-Ordner');
  assert.deepEqual(login.fields.map((f) => [f.name, f.value, f.type]), [['Kundennummer', '42', 'text'], ['PIN', '0815', 'hidden']]);
  assert.equal(r.items.find((i) => i.type === 'card').card.number, '4111111111111111');
});

test('protected export: round trip, wrong password, damaged file, KDF bounds', async () => {
  const plain = toBitwardenJson(PLAIN_ITEMS);
  const text = await encryptBitwardenJson(plain, 'Ein langes Export-Passwort');
  const file = JSON.parse(text);
  assert.deepEqual([file.kdfType, file.kdfIterations, file.kdfMemory, file.kdfParallelism], [1, 3, 64, 4], 'Argon2id by default');
  const r = await readImportFile(bytes(text), { password: 'Ein langes Export-Passwort' });
  assert.deepEqual(r.items.map((i) => [i.type, i.name]), [['login', 'Login ä'], ['card', 'Karte'], ['note', 'Schlüssel']]);
  assert.deepEqual(r.items[2].fields.map((f) => [f.value, f.type]), [[PLAIN_ITEMS[2].ssh.privateKey, 'hidden'], ['ssh-ed25519 AAAA', 'text'], ['SHA256:abc', 'text']], 'SSH key kept in fields');
  await assert.rejects(decryptBitwardenJson(file, 'falsch'), { code: 'bad_password' });
  const damaged = { ...file, data: file.data.replace(/\|([A-Za-z0-9+/])/, (m, c) => `|${c === 'A' ? 'B' : 'A'}`) };
  await assert.rejects(readImportFile(bytes(damaged), { password: 'Ein langes Export-Passwort' }), { code: 'format' });
  for (const kdf of [{ kdfType: 1, kdfIterations: 3, kdfMemory: 4096, kdfParallelism: 4 }, { kdfType: 0, kdfIterations: 50_000_000 }, { kdfType: 7, kdfIterations: 1 }]) {
    await assert.rejects(readImportFile(bytes({ ...file, ...kdf }), { password: 'x' }), { code: 'kdf' }, JSON.stringify(kdf));
  }
  // the first files of the format had no kdfType (PBKDF2)
  const old = JSON.parse(await encryptBitwardenJson(plain, 'pw-ohne-kdftyp', { kdfType: 0, kdfIterations: 5000 }));
  delete old.kdfType; delete old.kdfMemory; delete old.kdfParallelism;
  assert.equal((await readImportFile(bytes(old), { password: 'pw-ohne-kdftyp' })).items.length, 3);
});

/* ---------- account-restricted Bitwarden export ---------- */

test('account-restricted export (Bitwarden CLI) opens only with the key of its account', async () => {
  const doc = fixture('account-restricted.json');
  assert.equal((await readImportFile(bytes(doc))).need, 'account');
  const session = { userKey: META['account-restricted.json'].userKey, accessToken: 'x', expiresAt: Date.now() + 3_600_000 };
  const r = await BitwardenProvider.decryptExport({ id: 'a', server: 'https://vault.invalid' }, session, doc);
  assert.equal(r.failed, 0);
  const login = r.items.find((i) => i.name === 'Fixture Login');
  assert.equal(login.password, 'Fixture-Pass-1');
  assert.equal(login.folder, 'Fixture-Ordner');
  // another account: the validation fails, the server is asked for organization keys, none fits
  const other = { ...session, userKey: Buffer.alloc(64, 7).toString('base64') };
  const fetch0 = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ profile: { organizations: [] } }), { status: 200, headers: { 'content-type': 'application/json' } });
  try {
    await assert.rejects(BitwardenProvider.decryptExport({ id: 'a', server: 'https://vault.invalid' }, other, doc), (e) => e.code === 'wrong_account' && /anderen Bitwarden-Konto/.test(e.message));
  } finally { globalThis.fetch = fetch0; }
});

/* ---------- ZIP ---------- */

test('ZIP: stored and deflated entries, UTF-8 names, CRC check', async () => {
  const big = 'Zeile mit Inhalt\n'.repeat(5000);
  const zip = openZip(writeZip([{ name: 'a.txt', data: 'stored', method: 0 }, { name: 'dir/', data: '', method: 0 }, { name: 'Ordner/ä.txt', data: big }]));
  assert.deepEqual(zip.entries.map((e) => [e.name, e.dir, e.method]), [['a.txt', false, 0], ['dir/', true, 0], ['Ordner/ä.txt', false, 8]]);
  assert.equal(new TextDecoder().decode(await zip.read('a.txt')), 'stored');
  assert.equal(new TextDecoder().decode(await zip.read('Ordner/ä.txt')), big);
  await assert.rejects(zip.read('fehlt'), { code: 'missing' });
  await assert.rejects(openZip(writeZip([{ name: 'x', data: 'abc', crc: 1 }])).read('x'), { code: 'crc' });
  await assert.rejects(openZip(writeZip([{ name: 'x', data: 'abc', method: 12 }])).read('x'), { code: 'method' });
});

test('ZIP written by Python zipfile (independent writer) reads; ZIP64 from Python is refused', { skip: spawnSync('python3', ['-V']).status !== 0 && 'python3 not available' }, async () => {
  const py = (zip64) => spawnSync('python3', ['-I', '-c', `
import io, sys, zipfile
b = io.BytesIO()
with zipfile.ZipFile(b, 'w') as z:
    z.writestr(zipfile.ZipInfo('stored.txt'), 'gespeichert', compress_type=zipfile.ZIP_STORED)
    z.writestr('Proton Pass/data.json', '{"vaults": {"v": {"name": "Tresor", "items": [{"data": {"type": "login", "metadata": {"name": "Py"}, "content": {"itemUsername": "u", "password": "p", "urls": []}}}]}}}', compress_type=zipfile.ZIP_DEFLATED)
    if ${zip64 ? 'True' : 'False'}:
        with z.open('big.bin', 'w', force_zip64=True) as f: f.write(b'x' * 10)
sys.stdout.buffer.write(b.getvalue())`]).stdout;
  const zip = openZip(new Uint8Array(py(false)));
  assert.equal(new TextDecoder().decode(await zip.read('stored.txt')), 'gespeichert');
  const r = await readImportFile(new Uint8Array(py(false)), { fileName: 'export.zip' });
  assert.equal(r.format, 'proton');
  assert.deepEqual(r.items.map((i) => [i.name, i.username, i.password, i.folder]), [['Py', 'u', 'p', 'Tresor']]);
  assert.equal(r.skipped.length, 1, 'the other file in the archive is reported');
  // Python marks even a small entry as ZIP64 in its local header when forced to
  await assert.rejects(openZip(new Uint8Array(py(true))).read('big.bin'), { code: 'zip64' });
});

test('ZIP: bombs, ZIP64, encryption and junk are refused', async () => {
  const zeros = new Uint8Array(2 * 1024 * 1024);
  // declares 1 KiB but inflates to 2 MiB: stopped while inflating
  await assert.rejects(openZip(writeZip([{ name: 'bomb', data: zeros, declaredSize: 1024 }])).read('bomb'), { code: 'too_large' });
  // declares more than the limit per entry
  assert.throws(() => openZip(writeZip([{ name: 'big', data: 'x', declaredSize: ZIP_LIMITS.maxEntryBytes + 1 }])), { code: 'too_large' });
  // many entries that are small each but too much together (also the case of overlapping entries)
  assert.throws(() => openZip(writeZip([{ name: 'a', data: zeros }, { name: 'b', data: zeros }]), { maxTotalBytes: 3 * 1024 * 1024 }), { code: 'too_large' });
  // the total is also counted while reading
  const twice = openZip(writeZip([{ name: 'a', data: zeros }]), { maxTotalBytes: 3 * 1024 * 1024 });
  await twice.read('a');
  await assert.rejects(twice.read('a'), { code: 'too_large' });
  assert.throws(() => openZip(writeZip([{ name: 'a', data: 'x' }]), { maxEntries: 0 }), { code: 'too_large' });
  assert.throws(() => openZip(writeZip([{ name: 'z', data: 'x', zip64Extra: true }])), { code: 'zip64' });
  assert.throws(() => openZip(writeZip([{ name: 'z', data: 'x' }], { zip64Locator: true })), { code: 'zip64' });
  assert.throws(() => openZip(writeZip([{ name: 'e', data: 'x', flags: 1 }])), { code: 'encrypted' });
  assert.throws(() => openZip(writeZip([{ name: 'e', data: 'x', method: 99, aesExtra: true }])), { code: 'encrypted' });
  assert.throws(() => openZip(new Uint8Array(100)), { code: 'invalid' });
  const truncated = writeZip([{ name: 'a', data: 'abc' }]);
  assert.throws(() => openZip(truncated.subarray(0, truncated.length - 5)), { code: 'invalid' });
  // and with the message the popup shows
  await assert.rejects(readImportFile(writeZip([{ name: 'export.data', data: '{}', flags: 1 }])), (e) => /Verschlüsselte ZIP-Archive/.test(e.message));
});

/* ---------- 1Password .1pux ---------- */

const ONEPUX = {
  accounts: [{
    attrs: { accountName: 'Test', name: 'Ada', email: 'ada@example.org', uuid: 'ACC', domain: 'https://my.1password.com/' },
    vaults: [{
      attrs: { uuid: 'V1', name: 'Privat', type: 'P' },
      items: [
        { uuid: 'i1', favIndex: 1, state: 'active', categoryUuid: '001',
          overview: { title: 'GitHub', url: 'https://github.com/login', urls: [{ label: '', url: 'https://github.com/login' }, { label: 'alt', url: 'https://gist.github.com' }], tags: ['dev', 'work'] },
          details: {
            loginFields: [{ value: 'ada', name: 'username', fieldType: 'T', designation: 'username' }, { value: 'gh-secret', name: 'password', fieldType: 'P', designation: 'password' },
              { value: 'remember', name: 'remember_me', fieldType: 'C' }],
            notesPlain: 'Notiz',
            sections: [{ title: 'Sicherheit', name: 's1', fields: [
              { title: 'one-time password', id: 'TOTP_x', value: { totp: 'otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP' } },
              { title: 'Recovery', id: 'r1', value: { concealed: 'rec-123' } },
              { title: 'Seit', id: 'd1', value: { date: 1700000000 } },
              { title: 'Datei', id: 'f1', value: { file: { fileName: 'codes.txt', documentId: 'doc1', decryptedSize: 9 } } },
            ] }],
          } },
        { uuid: 'i2', favIndex: 0, state: 'active', categoryUuid: '002', overview: { title: 'Visa' },
          details: { sections: [{ title: '', name: 's', fields: [
            { title: 'Karteninhaber', id: 'cardholder', value: { string: 'Ada Lovelace' } }, { title: 'Typ', id: 'type', value: { creditCardType: 'mc' } },
            { title: 'Nummer', id: 'ccnum', value: { creditCardNumber: '5555444433331111' } }, { title: 'CVV', id: 'cvv', value: { concealed: '123' } },
            { title: 'Ablauf', id: 'expiry', value: { monthYear: 203107 } }, { title: 'PIN', id: 'pin', value: { concealed: '9999' } }] }] } },
        { uuid: 'i3', state: 'active', categoryUuid: '004', overview: { title: 'Ich' },
          details: { sections: [{ title: 'Name', name: 'name', fields: [
            { id: 'firstname', title: 'Vorname', value: { string: 'Ada' } }, { id: 'lastname', title: 'Nachname', value: { string: 'Lovelace' } },
            { id: 'address', title: 'Adresse', value: { address: { street: 'Main St 1', city: 'London', zip: 'NW1', state: '', country: 'uk' } } },
            { id: 'cellphone', title: 'Mobil', value: { phone: '+44 1' } }, { id: 'email', title: 'E-Mail', value: { email: { email_address: 'ada@example.org' } } }] }] } },
        { uuid: 'i4', state: 'active', categoryUuid: '005', overview: { title: 'WLAN-Passwort' }, details: { password: 'wifi-pw' } },
        { uuid: 'i5', state: 'archived', categoryUuid: '003', overview: { title: 'Alt' }, details: { notesPlain: 'weg' } },
        { item: { uuid: 'i6', state: 'active', categoryUuid: '006', overview: { title: 'Pass-Scan' }, details: { documentAttributes: { fileName: 'scan.png', documentId: 'doc2', decryptedSize: 4 } } } },
        { uuid: 'i7', state: 'active', categoryUuid: '110', overview: { title: 'Server' },
          details: { sections: [{ title: '', name: 's', fields: [{ title: 'URL', id: 'url', value: { string: 'ssh://srv' } }, { title: 'Passwort', id: 'password', value: { concealed: 'srv-pw' } }] }] } },
      ],
    }],
  }],
};
const onePux = (data = ONEPUX, extra = []) => writeZip([
  { name: 'export.attributes', data: JSON.stringify({ version: 3, description: '1Password Unencrypted Export', createdAt: 1700000000 }) },
  { name: 'export.data', data: JSON.stringify(data) },
  { name: 'files/', data: '', method: 0 },
  { name: 'files/doc1__codes.txt', data: 'abc\ndef\n!' },
  { name: 'files/doc2__scan.png', data: new Uint8Array([0x89, 0x50, 0x4e, 0x47]), method: 0 },
  ...extra,
]);

test('1PUX: logins, cards, identities, notes, fields, TOTP, attachments, archive', async () => {
  const r = await readImportFile(onePux(), { fileName: 'ACC.1pux' });
  assert.equal(r.format, '1pux');
  const by = Object.fromEntries(r.items.map((i) => [i.name, i]));
  assert.deepEqual(Object.keys(by), ['GitHub', 'Visa', 'Ich', 'WLAN-Passwort', 'Pass-Scan', 'Server']);
  const gh = by.GitHub;
  assert.deepEqual([gh.type, gh.username, gh.password, gh.favorite, gh.folder, gh.notes], ['login', 'ada', 'gh-secret', true, 'Privat', 'Notiz']);
  assert.equal(gh.totp, 'otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP');
  assert.deepEqual(gh.uris, ['https://github.com/login', 'https://gist.github.com']);
  assert.deepEqual(gh.fields.map((f) => [f.name, f.value, f.type]), [['remember_me', 'remember', 'text'], ['Recovery', 'rec-123', 'hidden'], ['Seit', '2023-11-14', 'text'], ['Tags', 'dev, work', 'text']]);
  assert.deepEqual(gh.files, [{ fileName: 'codes.txt', entry: 'files/doc1__codes.txt', size: 9 }]);
  assert.equal(new TextDecoder().decode(await r.zip.read(gh.files[0].entry)), 'abc\ndef\n!');
  assert.deepEqual(by.Visa.card, { cardholderName: 'Ada Lovelace', brand: 'Mastercard', number: '5555444433331111', code: '123', expMonth: '7', expYear: '2031' });
  assert.deepEqual(by.Visa.fields.map((f) => [f.name, f.value, f.type]), [['PIN', '9999', 'hidden']]);
  assert.equal(by.Visa.type, 'card');
  assert.deepEqual(by.Ich.identity, { firstName: 'Ada', lastName: 'Lovelace', address1: 'Main St 1', city: 'London', postalCode: 'NW1', country: 'uk', phone: '+44 1', email: 'ada@example.org' });
  assert.deepEqual([by['WLAN-Passwort'].type, by['WLAN-Passwort'].password], ['login', 'wifi-pw']);
  assert.deepEqual([by['Pass-Scan'].type, by['Pass-Scan'].files[0].fileName], ['note', 'scan.png']);
  assert.deepEqual(by.Server.fields.map((f) => [f.name, f.value, f.type]), [['URL', 'ssh://srv', 'text'], ['Passwort', 'srv-pw', 'hidden']]);
  assert.deepEqual(r.skipped, ['Archiv: 1 Eintrag wird nicht übernommen.']);
  // an attachment that is not in the archive is reported
  const gone = await import1Pux(openZip(writeZip([{ name: 'export.data', data: JSON.stringify(ONEPUX) }])));
  assert.ok(gone.skipped.some((s) => /2 Anhänge fehlen/.test(s)), gone.skipped.join(' | '));
  await assert.rejects(readImportFile(writeZip([{ name: 'export.data', data: 'kein json' }])), /export.data ist kein JSON/);
  await assert.rejects(readImportFile(bytes('a,b\n1,2'), { format: '1pux' }), /keine ZIP-Datei/);
});

test('import into an account: new ids for the attachment upload', async () => {
  const saved = [];
  const deps = {
    account: async () => ({ id: 'acc', config: {} }),
    provider: () => ({ label: 'Test', capabilities: { write: true, types: ['login', 'note'] } }),
    items: async () => ({ items: [], folders: [] }),
    write: async (id, fn) => fn({ saveItem: async (c, s, e, data) => { saved.push(data); return { item: { id: `new-${saved.length}` } }; } }, { id, config: {} }, {}),
  };
  const res = await importItems(deps, { accountId: 'acc', items: [{ type: 'login', name: 'a' }, { type: 'card', name: 'b', card: { number: '4111' } }] });
  assert.deepEqual(res.map((r) => [r.name, r.ok, r.id]), [['a', true, 'new-1'], ['b', true, 'new-2']]);
  assert.equal(saved[1].type, 'note', 'card arrives as a note where cards cannot be stored');
});

/* ---------- Proton Pass: ZIP and PGP ---------- */

const PROTON = { version: '1.0', vaults: { v1: { name: 'Persönlich', items: [{ data: { type: 'login', metadata: { name: 'Proton-Login', note: '' }, content: { itemEmail: 'ada@proton.me', password: 'pp', urls: ['https://proton.me'], totpUri: '' } } }] } } };

test('Proton Pass ZIP (Proton Pass/data.json) and PGP-encrypted export', async () => {
  const zip = writeZip([{ name: 'Proton Pass/', data: '', method: 0 }, { name: 'Proton Pass/data.json', data: JSON.stringify(PROTON) }]);
  const r = await readImportFile(zip, { fileName: 'Proton Pass_export.zip' });
  assert.equal(r.format, 'proton');
  assert.deepEqual(r.items.map((i) => [i.name, i.username, i.password, i.folder]), [['Proton-Login', 'ada@proton.me', 'pp', 'Persönlich']]);
  assert.equal(r.skipped, undefined);
  // PGP (passphrase) around the ZIP, binary and armored; and around the JSON itself
  for (const [format, payload] of [['binary', zip], ['armored', zip], ['binary', bytes(PROTON)]]) {
    const enc = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: payload }), passwords: ['Proton-Passphrase'], format });
    const file = typeof enc === 'string' ? bytes(enc) : enc;
    assert.deepEqual(await readImportFile(file, { fileName: 'export.pgp' }), { need: 'password', kind: 'pgp' });
    const out = await readImportFile(file, { fileName: 'export.pgp', password: 'Proton-Passphrase' });
    assert.equal(out.items[0].password, 'pp', format);
    await assert.rejects(readImportFile(file, { fileName: 'export.pgp', password: 'falsch' }), { code: 'bad_password' });
  }
  // encrypted to a key instead of a passphrase
  const { privateKey } = await openpgp.generateKey({ userIDs: [{ email: 'a@b.c' }], format: 'object' });
  const toKey = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: zip }), encryptionKeys: privateKey.toPublic(), format: 'binary' });
  await assert.rejects(readImportFile(toKey, { fileName: 'x.pgp', password: 'x' }), /für einen Schlüssel verschlüsselt/);
});

test('PGP: a compression bomb is stopped at the size limit', async () => {
  const zeros = new Uint8Array(4 * 1024 * 1024);
  const enc = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: zeros }), passwords: ['pw'], format: 'binary', config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib } });
  assert.ok(enc.length < 64 * 1024, `compressed (${enc.length} bytes)`);
  await assert.rejects(decryptPgp(enc, 'pw', 1024 * 1024), { code: 'too_large' });
  assert.equal((await decryptPgp(enc, 'pw', 8 * 1024 * 1024)).length, zeros.length);
});
