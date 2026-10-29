// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Encrypted Bitwarden exports against the official Bitwarden CLI and a real Vaultwarden (HTTPS, the CLI refuses
// plain HTTP): the CLI imports OmniVault's password-protected files (PBKDF2 and Argon2id) and OmniVault opens the CLI's
// password-protected, account-restricted (personal and organization) and ZIP exports.
// Usage: test/exports-real.sh (starts Vaultwarden with TLS, sets VAULTWARDEN_TLS_URL and NODE_EXTRA_CA_CERTS).
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { EXPORT_KDF, encryptBitwardenJson, toBitwardenJson } from '../src/lib/export.js';
import { readImportFile } from '../src/lib/import.js';
import BitwardenProvider from '../src/providers/bitwarden/index.js';
import { seedVaultwarden } from './vaultwarden-seed.mjs';

const URL_ = process.env.VAULTWARDEN_TLS_URL;
const skip = !URL_ && 'VAULTWARDEN_TLS_URL not set (run test/exports-real.sh)';
const port = URL_ ? Number(new URL(URL_).port) : 0;
const BW = URL_ ? execFileSync(new URL('bw-cli.sh', import.meta.url).pathname, { encoding: 'utf8' }).trim() : null;
const work = mkdtempSync(join(tmpdir(), 'omnivault-bwcli-test-'));
let proxy;
let proxyPort;

/**
 * The CLI sends its requests through http(s)_proxy when one is set; this local CONNECT proxy only reaches the test
 * server, so the CLI talks to it the same way in every environment.
 */
function startProxy() {
  const s = http.createServer((q, r) => { r.writeHead(405); r.end(); });
  s.on('connect', (req, sock, head) => {
    const [host, p] = req.url.split(':');
    if (!['localhost', '127.0.0.1'].includes(host) || Number(p) !== port) { sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
    const up = net.connect(port, '127.0.0.1', () => { sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); up.write(head); up.pipe(sock); sock.pipe(up); });
    up.on('error', () => sock.destroy());
    sock.on('error', () => up.destroy());
  });
  return new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve(s)));
}

/**
 * Runs the CLI with its own data folder per account → stdout (rejects on a non-zero exit unless `allowFail`, then
 * { status, stdout, stderr }). Asynchronous: the proxy above runs in this process.
 */
function bw(dir, args, { session, allowFail = false } = {}) {
  const env = { ...process.env, BITWARDENCLI_APPDATA_DIR: join(work, dir), http_proxy: `http://127.0.0.1:${proxyPort}`, BW_NOINTERACTION: 'true', ...(session ? { BW_SESSION: session } : {}) };
  return new Promise((resolve, reject) => {
    const p = spawn(BW, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (c) => { stdout += c; });
    p.stderr.on('data', (c) => { stderr += c; });
    const timer = setTimeout(() => p.kill(), 120_000);
    p.on('close', (status) => {
      clearTimeout(timer);
      if (allowFail) resolve({ status, stdout, stderr });
      else if (status !== 0) reject(new Error(`bw ${args[0]}: ${stderr || stdout}`));
      else resolve(stdout);
    });
  });
}

async function cliAccount(dir, seedOpts) {
  const seed = await seedVaultwarden(URL_.replace('127.0.0.1', 'localhost'), seedOpts);
  await bw(dir, ['config', 'server', URL_.replace('127.0.0.1', 'localhost')]);
  const session = (await bw(dir, ['login', seed.email, seed.password, '--raw'])).trim();
  return { seed, dir, session, cli: (args, o) => bw(dir, args, { session, ...o }) };
}

async function omniSession(seed) {
  const config = { id: 'vw-export', server: URL_.replace('127.0.0.1', 'localhost'), email: seed.email };
  const res = await BitwardenProvider.login(config, { password: seed.password });
  assert.equal(res.status, 'ok', JSON.stringify(res));
  Object.assign(config, res.configPatch ?? {});
  return { config, session: res.session };
}

const ITEMS = [
  { type: 'login', name: 'OV-Login ä', username: 'ada@example.org', password: 'OV-pass-1', totp: 'JBSWY3DPEHPK3PXP', uris: ['https://ov.example/login'], notes: 'Notiz', folder: 'OV-Ordner', favorite: true,
    fields: [{ name: 'Kundennummer', value: '42', type: 'text' }, { name: 'PIN', value: '0815', type: 'hidden' }] },
  { type: 'card', name: 'OV-Karte', card: { cardholderName: 'Ada Lovelace', brand: 'Visa', number: '4111111111111111', expMonth: '7', expYear: '2031', code: '321' } },
  { type: 'identity', name: 'OV-Identität', identity: { firstName: 'Ada', lastName: 'Lovelace', email: 'ada@example.org' } },
  { type: 'note', name: 'OV-Notiz', notes: 'geheim' },
];
let pbkdf2Acc;
let argonAcc;

before(async () => {
  if (skip) return;
  proxy = await startProxy();
  proxyPort = proxy.address().port;
  pbkdf2Acc = await cliAccount('pbkdf2', {});
  argonAcc = await cliAccount('argon2', { kdf: { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 }, withOrg: false });
});
after(() => proxy?.close());

const listed = async (acc) => { await acc.cli(['sync']); return JSON.parse(await acc.cli(['list', 'items'])); };

test('the Bitwarden CLI imports OmniVault\'s password-protected exports (PBKDF2 and Argon2id)', { skip }, async () => {
  const plain = toBitwardenJson(ITEMS);
  for (const [kdf, name] of [[EXPORT_KDF.pbkdf2, 'pbkdf2'], [EXPORT_KDF.argon2id, 'argon2id']]) {
    const file = join(work, `ov-${name}.json`);
    writeFileSync(file, await encryptBitwardenJson(plain, `Export-${name}-Passwort!`, kdf));
    writeFileSync(join(work, 'wrong.txt'), 'falsch\n');
    const wrong = await argonAcc.cli(['import', 'bitwardenjson', file, '--passwordfile', join(work, 'wrong.txt')], { allowFail: true });
    assert.ok(wrong.status !== 0 || !/Imported/.test(wrong.stdout), `the CLI refuses a wrong password (${name}): ${wrong.stdout}${wrong.stderr}`);
    writeFileSync(join(work, 'pw.txt'), `Export-${name}-Passwort!\n`);
    assert.match(await argonAcc.cli(['import', 'bitwardenjson', file, '--passwordfile', join(work, 'pw.txt')]), /Imported/, name);
  }
  const items = await listed(argonAcc);
  for (const name of ITEMS.map((i) => i.name)) assert.equal(items.filter((i) => i.name === name).length, 2, `${name} imported twice (once per KDF)`);
  const login = items.find((i) => i.name === 'OV-Login ä');
  assert.equal(login.login.password, 'OV-pass-1');
  assert.equal(login.login.username, 'ada@example.org');
  assert.equal(login.login.totp, 'JBSWY3DPEHPK3PXP');
  assert.equal(login.login.uris[0].uri, 'https://ov.example/login');
  assert.equal(login.favorite, true);
  assert.deepEqual(login.fields.map((f) => [f.name, f.value, f.type]), [['Kundennummer', '42', 0], ['PIN', '0815', 1]]);
  const folders = JSON.parse(await argonAcc.cli(['list', 'folders']));
  assert.equal(folders.find((f) => f.id === login.folderId)?.name, 'OV-Ordner');
  assert.equal(items.find((i) => i.name === 'OV-Karte').card.number, '4111111111111111');
  assert.equal(items.find((i) => i.name === 'OV-Identität').identity.lastName, 'Lovelace');
});

test('OmniVault opens the CLI\'s password-protected exports (account KDF: PBKDF2 and Argon2id)', { skip }, async () => {
  for (const acc of [pbkdf2Acc, argonAcc]) {
    const out = join(work, `cli-protected-${acc.dir}.json`);
    await acc.cli(['export', '--format', 'encrypted_json', '--password', 'CLI-Export-Passwort', '--output', out]);
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(doc.kdfType, acc.dir === 'argon2' ? 1 : 0, 'the CLI uses the account KDF');
    const r = await readImportFile(new Uint8Array(readFileSync(out)), { password: 'CLI-Export-Passwort' });
    const cli = (await listed(acc)).filter((i) => !i.organizationId);
    assert.deepEqual(r.items.map((i) => i.name).sort(), cli.map((i) => i.name).sort(), acc.dir);
    for (const c of cli.filter((i) => i.login?.password)) assert.equal(r.items.find((i) => i.name === c.name && i.password === c.login.password)?.password, c.login.password);
    await assert.rejects(readImportFile(new Uint8Array(readFileSync(out)), { password: 'falsch' }), { code: 'bad_password' });
  }
});

test('OmniVault opens the CLI\'s account-restricted exports only with the matching account (personal and organization)', { skip }, async () => {
  const out = join(work, 'cli-account.json');
  await pbkdf2Acc.cli(['export', '--format', 'encrypted_json', '--output', out]);
  const doc = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal((await readImportFile(new Uint8Array(readFileSync(out)))).need, 'account');
  const own = await omniSession(pbkdf2Acc.seed);
  const r = await BitwardenProvider.decryptExport(own.config, own.session, doc);
  const cli = (await listed(pbkdf2Acc)).filter((i) => !i.organizationId);
  assert.equal(r.failed, 0);
  assert.deepEqual(r.items.map((i) => i.name).sort(), cli.map((i) => i.name).sort());
  assert.equal(r.items.find((i) => i.name === 'GitHub')?.password, 'gh-pass');
  // the organization's export: encrypted with the organization key, which the account gets from the server
  const orgOut = join(work, 'cli-org.json');
  await pbkdf2Acc.cli(['export', '--organizationid', pbkdf2Acc.seed.orgId, '--format', 'encrypted_json', '--output', orgOut]);
  const org = await BitwardenProvider.decryptExport(own.config, own.session, JSON.parse(readFileSync(orgOut, 'utf8')));
  assert.deepEqual(org.items.map((i) => i.name).sort(), ['Team-Notiz', 'Team-Wiki']);
  assert.equal(org.items.find((i) => i.name === 'Team-Wiki').password, 'wiki-pass');
  // another account
  const other = await omniSession(argonAcc.seed);
  await assert.rejects(BitwardenProvider.decryptExport(other.config, other.session, doc), { code: 'wrong_account' });
  await assert.rejects(BitwardenProvider.decryptExport(other.config, other.session, JSON.parse(readFileSync(orgOut, 'utf8'))), { code: 'wrong_account' });
});

test('OmniVault reads the CLI\'s ZIP export (data.json; attachments reported as not imported)', { skip }, async () => {
  const out = join(work, 'cli-export.zip');
  const r0 = await pbkdf2Acc.cli(['export', '--format', 'zip', '--output', out], { allowFail: true });
  if (r0.status !== 0) { console.log(`# ZIP export not available in this CLI: ${r0.stderr || r0.stdout}`); return; }
  const r = await readImportFile(new Uint8Array(readFileSync(out)), { fileName: 'export.zip' });
  assert.equal(r.format, 'bitwarden');
  assert.ok(r.items.some((i) => i.name === 'GitHub' && i.password === 'gh-pass'));
});
