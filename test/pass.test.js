// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// pass provider against the REAL `pass` (zx2c4 password-store) + gpg, driven through the real CLI host.
// The `pass` binary is taken from $OMNIVAULT_PASS_BIN; this repo's CI clones it. Skipped if pass/gpg absent.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProcessTransport, gpgCounter } from './native-transport.mjs';
import { after, before, test } from 'node:test';
import PassProvider from '../src/providers/pass/index.js';
import { matchesUrl } from '../src/lib/match.js';

const PASS_BIN = process.env.OMNIVAULT_PASS_BIN;
let have = false;
try { execFileSync('gpg', ['--version']); have = !!PASS_BIN; } catch { have = false; }
const opts = { skip: have ? false : 'pass/gpg not available (set OMNIVAULT_PASS_BIN)' };

const dir = mkdtempSync(join(tmpdir(), 'omnivault-pass-'));
after(() => { try { if (GNUPGHOME) execFileSync('gpgconf', ['--homedir', GNUPGHOME, '--kill', 'all']); } catch { /* ignore */ } rmSync(dir, { recursive: true, force: true }); });
let GNUPGHOME;
let STORE;


before(() => {
  if (!have) return;
  GNUPGHOME = join(dir, 'gnupg');
  STORE = join(dir, 'store');
  execFileSync('mkdir', ['-p', GNUPGHOME]);
  execFileSync('chmod', ['700', GNUPGHOME]);
  const keyfile = join(dir, 'genkey');
  writeFileSync(keyfile, '%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nSubkey-Type: ecdh\nSubkey-Curve: cv25519\nName-Real: OV Test\nName-Email: pass@omnivault.local\nExpire-Date: 0\n%commit\n');
  execFileSync('gpg', ['--batch', '--quiet', '--gen-key', keyfile], { env: { ...process.env, GNUPGHOME } });
  const env = { ...process.env, GNUPGHOME, PASSWORD_STORE_DIR: STORE };
  execFileSync(PASS_BIN, ['init', 'pass@omnivault.local'], { env });
  execFileSync(PASS_BIN, ['insert', '-m', '-f', 'web/github.com'], { env, input: 'gh-pass\nlogin: ada\nurl: https://github.com\notpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n' });
  execFileSync(PASS_BIN, ['insert', '-m', '-f', 'notes/idee'], { env, input: 'nur ein Gedanke\nmehr Text\n' });
});

function setup() {
  const t = new ProcessTransport({ OMNIVAULT_PASS_BIN: PASS_BIN, GNUPGHOME, PASSWORD_STORE_DIR: STORE });
  PassProvider.transport = t;
  return { t, config: { id: 'p1' } };
}

test('status/login: gpg + pass + initialized store', opts, async () => {
  const { t, config } = setup();
  const res = await PassProvider.login(config, {});
  assert.equal(res.status, 'ok');
  t.close();
});

test('sync parses password, login, url, otp and notes; folders from paths', opts, async () => {
  const { t, config } = setup();
  const { items, folders } = await PassProvider.sync(config);
  const by = Object.fromEntries(items.map((i) => [i.id, i]));
  const gh = by['web/github.com'];
  assert.equal(gh.type, 'login');
  assert.equal(gh.name, 'github.com');
  assert.equal(gh.username, 'ada');
  assert.equal(gh.password, 'gh-pass');
  assert.deepEqual(gh.uris, ['https://github.com']);
  assert.match(gh.totp, /^otpauth:/);
  assert.equal(gh.folder, 'web');
  assert.equal(by['notes/idee'].type, 'login');
  assert.equal(by['notes/idee'].password, 'nur ein Gedanke');
  assert.match(by['notes/idee'].notes, /mehr Text/);
  assert.ok(folders.some((f) => f.id === 'web'));
  t.close();
});

test('create, update, move to another folder, delete', opts, async () => {
  const { t, config } = setup();
  const { item } = await PassProvider.saveItem(config, {}, null, { type: 'login', name: 'example.org', username: 'bob', password: 'p1', totp: '', uris: ['https://example.org'], notes: '', folderId: 'web' });
  assert.equal(item.id, 'web/example.org');
  let items = (await PassProvider.sync(config)).items;
  let e = items.find((i) => i.id === 'web/example.org');
  assert.equal(e.password, 'p1');

  await PassProvider.saveItem(config, {}, e, { ...e, type: 'login', password: 'p2' });
  e = (await PassProvider.sync(config)).items.find((i) => i.id === 'web/example.org');
  assert.equal(e.password, 'p2');

  const moved = await PassProvider.saveItem(config, {}, e, { ...e, type: 'login', folderId: 'archive' });
  assert.equal(moved.deletedId, 'web/example.org');
  assert.equal(moved.item.id, 'archive/example.org');
  items = (await PassProvider.sync(config)).items;
  assert.ok(!items.some((i) => i.id === 'web/example.org'));
  assert.ok(items.some((i) => i.id === 'archive/example.org'));

  await PassProvider.deleteItem(config, {}, moved.item);
  assert.ok(!(await PassProvider.sync(config)).items.some((i) => i.id === 'archive/example.org'));
  t.close();
});

test('custom fields are "key: value" lines; folders are created by saving into them', opts, async () => {
  const { t, config } = setup();
  const { folder } = await PassProvider.createFolder(config, {}, { name: 'neu/../tief' });
  assert.equal(folder.id, 'neu/tief', 'path cleaned');
  const { item } = await PassProvider.saveItem(config, {}, null, { type: 'login', name: 'bank', username: 'ada', password: 'b1', totp: '', uris: [],
    notes: 'freier Text\nzweite Zeile', folderId: folder.id, fields: [{ name: 'PIN', value: '1234', type: 'hidden' }, { name: 'Konto', value: 'DE00 1234', type: 'text' }] });
  const e = (await PassProvider.sync(config)).items.find((i) => i.id === item.id);
  assert.equal(e.folder, 'neu/tief');
  assert.deepEqual(e.fields.map((f) => [f.name, f.value]), [['PIN', '1234'], ['Konto', 'DE00 1234']]);
  assert.equal(e.notes, 'freier Text\nzweite Zeile', 'free text stays in the notes');
  await PassProvider.deleteItem(config, {}, e);
  t.close();
});

test('decrypt on open: the list runs no gpg --decrypt; open, match by path, save', opts, async () => {
  const gpg = gpgCounter(dir);
  const env = { ...process.env, GNUPGHOME, PASSWORD_STORE_DIR: STORE };
  execFileSync(PASS_BIN, ['insert', '-m', '-f', 'websites/example.org/ada'], { env, input: 'ex-pass\nurl: https://login.example.org\n' });
  const t = new ProcessTransport({ OMNIVAULT_PASS_BIN: PASS_BIN, GNUPGHOME, PASSWORD_STORE_DIR: STORE, ...gpg.env });
  PassProvider.transport = t;
  const config = { id: 'p2', decrypt: 'open' };
  try {
    assert.equal((await PassProvider.login(config, {})).status, 'ok');
    // the wrapper sees the decryptions of a full sync, so a zero below means something
    await PassProvider.sync({ id: 'p1' });
    assert.ok(gpg.decrypts() >= 3, `full sync decrypts every entry (${gpg.decrypts()})`);
    gpg.reset();

    const { items, folders } = await PassProvider.sync(config);
    assert.equal(gpg.decrypts(), 0, `no gpg --decrypt for the list (calls: ${JSON.stringify(gpg.calls())})`);
    assert.deepEqual(gpg.calls(), [], 'in fact no gpg call at all');
    const by = Object.fromEntries(items.map((i) => [i.id, i]));
    const gh = by['web/github.com'];
    assert.ok(gh.lazy && gh.password === undefined && gh.username === undefined && gh.notes === undefined, 'nothing from the content');
    assert.deepEqual(gh.siteHints, ['https://github.com']);
    assert.ok(matchesUrl(gh, 'https://github.com/login') && !matchesUrl(by['notes/idee'], 'https://github.com/'), 'site from the path');
    const ada = by['websites/example.org/ada'];
    assert.equal(ada.username, 'ada', 'user name from the path (browserpass convention)');
    assert.ok(matchesUrl(ada, 'https://www.example.org/'));
    assert.ok(folders.some((f) => f.id === 'websites/example.org'));

    // opening decrypts that one entry only
    const extra = await PassProvider.reveal(config, {}, gh);
    assert.equal(gpg.decrypts(), 1);
    assert.equal(extra.password, 'gh-pass');
    assert.equal(extra.username, 'ada');
    assert.deepEqual(extra.uris, ['https://github.com']);
    assert.ok(extra.hasTotp && extra.totp.startsWith('otpauth:'));
    const adaFull = { ...ada, ...(await PassProvider.reveal(config, {}, ada)), revealed: true };
    assert.equal(adaFull.username, 'ada', 'no login: line – the path name stays');
    assert.deepEqual(adaFull.uris, ['https://login.example.org']);

    // saving keeps a path user name out of the file unless it was changed
    const saved = await PassProvider.saveItem(config, {}, adaFull, { ...adaFull, password: 'ex-neu' });
    assert.equal(execFileSync(PASS_BIN, ['show', 'websites/example.org/ada'], { env, encoding: 'utf8' }), 'ex-neu\nurl: https://login.example.org\n');
    assert.ok(saved.item.lazy && saved.item.revealed && saved.item.username === 'ada' && saved.item.siteHints[0] === 'https://example.org');
    await PassProvider.saveItem(config, {}, saved.item, { ...saved.item, username: 'bea' });
    assert.match(execFileSync(PASS_BIN, ['show', 'websites/example.org/ada'], { env, encoding: 'utf8' }), /^ex-neu\nlogin: bea\n/);
    await PassProvider.deleteItem(config, {}, saved.item);
  } finally { t.close(); }
});

test('host rejects malformed ids and unknown commands', opts, async () => {
  const { t } = setup();
  await assert.rejects(t.request('pass', 'reveal', { id: '../../etc/passwd' }), /Ungültige/);
  await assert.rejects(t.request('pass', 'nope'), /Unbekannter Befehl/);
  await assert.rejects(t.request('nobackend', 'status'), /Unbekanntes Backend/);
  t.close();
});
