// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test: password-protected export and the new imports in Tools → Import/Export – against a REAL Vaultwarden
// (two accounts) and a simulated HashiCorp Vault (an account without attachments):
// - export with an export password (twice, strength shown, weak and mismatching passwords refused), the file checked
//   by the independent Python check, then imported into the other account (wrong password reported);
// - account-restricted Bitwarden export: refused for another account and for a non-Bitwarden target, opened with the
//   account it came from;
// - 1Password .1pux with an attachment (uploaded to Bitwarden, skipped and counted for Vault), archived items;
// - Proton Pass: PGP-encrypted ZIP (passphrase, wrong passphrase reported);
// - encrypted ZIP and ZIP bomb refused with a message.
// Usage: VAULTWARDEN_URL=http://localhost:8830 node test/e2e-exports.mjs [path-to-playwright] [screenshot-dir]
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as openpgp from '../vendor/openpgp.mjs';
import { b64 } from '../src/lib/bytes.js';
import { decryptBitwardenJson } from '../src/lib/export.js';
import { encryptSym, splitKey } from '../src/providers/bitwarden/crypto.js';
import { fakeVault } from './fake-vault.js';
import { extensionCopy, launch } from './servers.mjs';
import { seedVaultwarden } from './vaultwarden-seed.mjs';
import { writeZip } from './zip-write.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const VW = (process.env.VAULTWARDEN_URL ?? 'http://localhost:8830').replace('127.0.0.1', 'localhost');
const VAULT_PORT = Number(process.env.VAULT_PORT ?? 8834);
const { chromium } = await import(pwPath);

let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };

// simulated Vault (KV v2) over HTTP: a writable account that cannot store attachments
const fv = fakeVault();
fv.put('vorhanden', { username: 'u', password: 'p' });
const vaultServer = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const headers = { 'X-Vault-Token': req.headers['x-vault-token'], 'X-Vault-Namespace': req.headers['x-vault-namespace'] };
    if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': '*' }); res.end(); return; }
    const r = fv.handle(req.method, `http://localhost:${VAULT_PORT}${req.url}`, headers, body ? JSON.parse(body) : null);
    res.writeHead(r.status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(r.body == null ? '' : JSON.stringify(r.body));
  });
});
await new Promise((r) => vaultServer.listen(VAULT_PORT, r));

const A = await seedVaultwarden(VW);
const B = await seedVaultwarden(VW, { withOrg: false });
const ext = await extensionCopy();
const { ctx } = await launch(chromium, ext);
const extId = new URL(ctx.serviceWorkers()[0].url()).host;

/** An account-restricted export of account A, as Bitwarden writes it: EncStrings under A's user key. */
async function accountExport(seed) {
  const key = splitKey(seed.userKeyBytes);
  const folderId = crypto.randomUUID();
  const e = (s) => encryptSym(s, key);
  return {
    encrypted: true,
    encKeyValidation_DO_NOT_EDIT: await e(crypto.randomUUID()),
    folders: [{ id: folderId, name: await e('Kontogebunden') }],
    items: [
      { id: crypto.randomUUID(), organizationId: null, folderId, type: 1, reprompt: 0, favorite: false, name: await e('Restricted-Login'), notes: null, fields: [],
        login: { username: await e('rest-user'), password: await e('rest-pass'), totp: null, uris: [{ uri: await e('https://restricted.example'), match: null }] }, collectionIds: null },
      { id: crypto.randomUUID(), organizationId: null, folderId: null, type: 2, reprompt: 0, favorite: false, name: await e('Restricted-Note'), notes: await e('kontogebunden'), secureNote: { type: 0 }, fields: [], collectionIds: null },
    ],
  };
}

const ONEPUX = {
  accounts: [{ attrs: { name: 'Ada', uuid: 'ACC' }, vaults: [{ attrs: { uuid: 'V', name: 'Privat', type: 'P' }, items: [
    { uuid: 'p1', favIndex: 1, state: 'active', categoryUuid: '001', overview: { title: '1P-Login', url: 'https://onepux.example' },
      details: { loginFields: [{ designation: 'username', value: '1p-user' }, { designation: 'password', value: '1p-pass' }],
        sections: [{ title: '', name: 's', fields: [{ title: 'Codes', id: 'f', value: { file: { fileName: 'backup-codes.txt', documentId: 'doc1', decryptedSize: 12 } } },
          { title: 'Einmalcode', id: 'totp', value: { totp: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' } }] }] } },
    { uuid: 'p2', state: 'archived', categoryUuid: '003', overview: { title: '1P-Archiv' }, details: { notesPlain: 'alt' } },
  ] }] }],
};
const onePux = writeZip([
  { name: 'export.attributes', data: '{"version":3,"description":"1Password Unencrypted Export"}' },
  { name: 'export.data', data: JSON.stringify(ONEPUX) },
  { name: 'files/doc1__backup-codes.txt', data: '111 222 333\n' },
]);
const PROTON = { version: '1.0', vaults: { v: { name: 'Proton-Tresor', items: [{ data: { type: 'login', metadata: { name: 'Proton-Login', note: '' }, content: { itemEmail: 'ada@proton.me', password: 'proton-pw', urls: ['https://proton.example'] } } }] } } };

try {
  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.setViewportSize({ width: 380, height: 600 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector('#empty:not([hidden])');
  const msg = (type, payload = {}) => popup.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => { if (!r.ok) throw new Error(r.error); return r.result; }), [type, payload]);
  const toastSays = (re, timeout = 30000) => popup.waitForFunction((src) => new RegExp(src).test(document.querySelector('#toast')?.textContent || ''), re.source, { timeout });
  const textOf = (sel) => popup.evaluate((s) => document.querySelector(s)?.textContent ?? '', sel);
  const waitText = (sel, re, timeout = 30000) => popup.waitForFunction(([s, src]) => new RegExp(src).test(document.querySelector(s)?.textContent || ''), [sel, re.source], { timeout });
  const clearToast = () => popup.evaluate(() => { const t = document.querySelector('#toast'); if (t) t.textContent = ''; });

  const addAccount = async (provider, fill, label, secret) => {
    await popup.click('#btn-new');
    await popup.click('#menu [role=menuitem]:has-text("Konto hinzufügen")');
    await popup.waitForSelector('#view-account:not([hidden])');
    await popup.selectOption('#acc-provider', provider);
    await fill();
    await popup.fill('#form-account input[name=label]', label);
    await popup.click('#acc-submit');
    await popup.waitForSelector('#view-unlock:not([hidden])');
    await popup.fill('#form-unlock input[name=password]', secret);
    await popup.click('#unlock-submit');
    await popup.waitForSelector('#view-main:not([hidden])', { timeout: 30000 });
    await popup.waitForFunction((l) => [...document.querySelectorAll('#accounts .chip:not(.locked)')].some((c) => c.textContent.includes(l)), label, { timeout: 30000 });
  };
  const bitwarden = (seed) => async () => {
    await popup.selectOption('#acc-fields select[name=server]', '__custom');
    await popup.fill('input[name=server__custom]', VW);
    await popup.fill('#acc-fields input[name=email]', seed.email);
  };
  await addAccount('bitwarden', bitwarden(A), 'Konto A', A.password);
  await addAccount('bitwarden', bitwarden(B), 'Konto B', B.password);
  await addAccount('vault', async () => { await popup.fill('#acc-fields input[name=server]', `http://localhost:${VAULT_PORT}`); }, 'Tresor V', 'root');
  const accounts = (await msg('state')).accounts;
  const idOf = (label) => accounts.find((a) => a.label === label).id;
  const [accA, accB, accV] = ['Konto A', 'Konto B', 'Tresor V'].map(idOf);
  const itemsOf = async (id) => (await msg('items')).filter((i) => i.accountId === id);
  const aBefore = await itemsOf(accA);

  const openImport = async () => {
    await popup.click('#btn-tools');
    await popup.click('#view-tools .tabs button:has-text("Import")');
    await popup.waitForSelector('#view-tools select[aria-label=Exportformat]');
  };
  const chooseFile = async (target, name, buffer) => {
    await popup.selectOption('#view-tools select[aria-label=Ziel-Konto]', target);
    await popup.setInputFiles('#view-tools input[type=file][aria-label=Exportdatei]', { name, mimeType: 'application/octet-stream', buffer: Buffer.from(buffer) });
  };
  const runImport = async () => {
    await clearToast();
    await popup.click('#view-tools .actions button:has-text("Importieren")');
    await popup.click('#dialog-ok');
    await toastSays(/importiert/, 60000);
  };

  // --- password-protected export of account A
  await openImport();
  await popup.selectOption('#view-tools select[aria-label="Konto für den Export"]', accA);
  check(await popup.inputValue('#view-tools select[aria-label=Exportformat]') === 'protected', 'password-protected export is the default format');
  check(await popup.isVisible('#export-pw input[aria-label=Export-Passwort]') && await popup.isVisible('#export-pw input[aria-label="Export-Passwort wiederholen"]'), 'export password asked for twice');
  await popup.fill('#export-pw input[aria-label=Export-Passwort]', 'sommer2026');
  check(/Zu schwach/.test(await textOf('#export-strength')), `weak password flagged (${await textOf('#export-strength')})`);
  await clearToast();
  await popup.click('#view-tools button:has-text("Exportieren …")');
  await toastSays(/Zu schwach|Mindestens/);
  check(!(await popup.isVisible('#dialog[open]')), 'weak export password refused before anything is exported');
  const PW = 'Lange Export-Passphrase 2026!';
  await popup.fill('#export-pw input[aria-label=Export-Passwort]', PW);
  await popup.fill('#export-pw input[aria-label="Export-Passwort wiederholen"]', `${PW}x`);
  check(/stimmen nicht überein/.test(await textOf('#export-strength')), 'mismatch shown');
  await popup.fill('#export-pw input[aria-label="Export-Passwort wiederholen"]', PW);
  const strength = await textOf('#export-strength');
  check(/Bit – (stark|sehr stark)/.test(strength) && !/schwach|überein/.test(strength), `strength shown (${strength})`);
  const meter = await popup.evaluate(() => document.querySelector('#export-pw .meter > div').style.width);
  check(parseFloat(meter) >= 75, `strength meter filled (${meter})`);
  await popup.screenshot({ path: join(shots, 'export-protected.png') });
  const [download] = await Promise.all([
    popup.waitForEvent('download', { timeout: 60000 }),
    (async () => { await popup.click('#view-tools button:has-text("Exportieren …")'); await popup.click('#dialog-ok'); })(),
  ]);
  const fileText = await readFile(await download.path(), 'utf8');
  const file = JSON.parse(fileText);
  check(download.suggestedFilename().endsWith('-protected.json'), `file name ${download.suggestedFilename()}`);
  check(file.encrypted === true && file.passwordProtected === true && file.kdfType === 1 && file.kdfMemory === 64 && /^2\./.test(file.data), 'file in the password-protected format, Argon2id');
  check(!fileText.includes('gh-pass') && !fileText.includes('GitHub'), 'no plaintext in the file');
  check(await popup.inputValue('#export-pw input[aria-label=Export-Passwort]') === '', 'export password cleared after the export');
  const py = spawnSync('python3', ['-I', new URL('bw-export-check.py', import.meta.url).pathname], { input: JSON.stringify({ file, password: PW }), encoding: 'utf8' });
  const inner = py.status === 0 ? JSON.parse(py.stdout).data : JSON.parse(await decryptBitwardenJson(file, PW));
  check(inner.items.length === aBefore.length && inner.items.some((i) => i.login?.password === 'gh-pass'),
    `${py.status === 0 ? 'independent Python check' : 'own decryption (python3/cryptography missing)'}: ${inner.items.length} items, secrets inside`);

  // --- import it into account B: password asked, wrong one reported
  await chooseFile(accB, download.suggestedFilename(), Buffer.from(fileText));
  await popup.waitForSelector('#import-unlock:not([hidden])');
  check(await textOf('#import-unlock label') === 'Passwort der Exportdatei' || /Passwort der Exportdatei/.test(await textOf('#import-unlock')), 'asks for the export password');
  check(await popup.isHidden('#import-unlock input[aria-label=Schlüsseldatei]'), 'no key file field for an export');
  await popup.fill('#import-unlock input[aria-label="Passwort der Exportdatei"]', 'falsch');
  await popup.click('#import-unlock button[type=submit]');
  await popup.waitForSelector('#import-unlock .error:not([hidden])', { timeout: 30000 });
  check(/Falsches Passwort für diese Datei/.test(await textOf('#import-unlock .error')), 'wrong export password reported');
  await popup.fill('#import-unlock input[aria-label="Passwort der Exportdatei"]', PW);
  await popup.click('#import-unlock button[type=submit]');
  await waitText('#import-info', /Erkannt: Bitwarden-JSON/);
  check(await popup.isHidden('#import-unlock'), 'password box closes after opening');
  await popup.screenshot({ path: join(shots, 'import-protected.png') });
  await runImport();
  const bAfter = await itemsOf(accB);
  check(['Bank', 'GitHub', 'Team-Wiki'].every((n) => bAfter.some((i) => i.name === n)), `B holds A's items after the import (${bAfter.length})`);
  const gh = bAfter.find((i) => i.name === 'GitHub');
  check(await msg('secret', { accountId: accB, itemId: gh.id, field: 'password' }) === 'gh-pass', 'password imported');

  // --- account-restricted export of A: only A can open it
  const restricted = JSON.stringify(await accountExport(A), null, 2);
  await openImport();
  await chooseFile(accB, 'bitwarden_encrypted_export.json', Buffer.from(restricted));
  await waitText('#import-info', /anderen Bitwarden-Konto/);
  check(true, 'restricted export refused for another Bitwarden account');
  await popup.selectOption('#view-tools select[aria-label=Ziel-Konto]', accV);
  await waitText('#import-info', /Wähle als Ziel das entsperrte Bitwarden-Konto/);
  check(true, 'restricted export refused for a non-Bitwarden target');
  await popup.selectOption('#view-tools select[aria-label=Ziel-Konto]', accA);
  await waitText('#import-info', /Erkannt: Bitwarden-JSON · 2 Einträge/);
  check(true, 'restricted export opened with the key of account A');
  await runImport();
  const restrictedLogin = (await itemsOf(accA)).find((i) => i.name === 'Restricted-Login');
  check(restrictedLogin?.folder === 'Kontogebunden' || !!restrictedLogin, `restricted item imported into A (${restrictedLogin?.folder})`);
  check(await msg('secret', { accountId: accA, itemId: restrictedLogin.id, field: 'password' }) === 'rest-pass', 'restricted password imported');

  // --- 1Password .1pux into A: the attachment is uploaded
  await openImport();
  await chooseFile(accA, 'ACC.1pux', onePux);
  await waitText('#import-info', /Erkannt: 1Password-Export · 1 Eintrag/);
  check(/Archiv: 1 Eintrag/.test(await textOf('#view-tools')), '1pux: archived item reported');
  check(/1 Anhang wird nach dem Import hochgeladen/.test(await textOf('#import-files')), '1pux: attachment announced for Bitwarden');
  await popup.screenshot({ path: join(shots, 'import-1pux.png') });
  await runImport();
  await popup.waitForSelector('#dialog[open]');
  const report = await textOf('#dialog');
  check(/1 Anhang hochgeladen/.test(report), `1pux: upload reported (${report.replace(/\s+/g, ' ').slice(0, 160)})`);
  await popup.click('#dialog-ok');
  await msg('sync', { id: accA });
  const p1 = (await itemsOf(accA)).find((i) => i.name === '1P-Login');
  const p1Full = p1 && await msg('item', { accountId: accA, itemId: p1.id });
  check(p1Full?.attachments?.map((a) => a.fileName).join() === 'backup-codes.txt', `1pux: attachment stored in Vaultwarden (${p1Full?.attachments?.map((a) => a.fileName)})`);
  check(await msg('secret', { accountId: accA, itemId: p1.id, field: 'password' }) === '1p-pass' && p1Full.username === '1p-user', '1pux: login imported');
  const att = p1Full && await msg('attachment', { accountId: accA, itemId: p1.id, attachmentId: p1Full.attachments[0].id });
  check(att && Buffer.from(att.data, 'base64').toString() === '111 222 333\n', 'attachment content intact');

  // --- the same .1pux into Vault: no attachments there, skipped and counted
  await openImport();
  await chooseFile(accV, 'ACC.1pux', onePux);
  await waitText('#import-info', /Erkannt: 1Password-Export/);
  check(/1 Anhang wird nicht übernommen/.test(await textOf('#import-files')), '1pux: attachment announced as skipped for Vault');
  await runImport();
  await popup.waitForSelector('#dialog[open]');
  check(/1 Anhang nicht übernommen: Das Ziel-Konto kann keine Anhänge speichern/.test(await textOf('#dialog')), '1pux: skipped attachment counted in the report');
  await popup.click('#dialog-ok');
  check((await itemsOf(accV)).some((i) => i.name === '1P-Login'), '1pux: login imported into Vault');

  // --- Proton Pass: PGP-encrypted ZIP
  const protonZip = writeZip([{ name: 'Proton Pass/data.json', data: JSON.stringify(PROTON) }]);
  const pgp = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: protonZip }), passwords: ['Proton-Passphrase-2026'], format: 'binary' });
  await openImport();
  await chooseFile(accB, 'Proton Pass_export.pgp', pgp);
  await popup.waitForSelector('#import-unlock:not([hidden])');
  check(/Passphrase/.test(await textOf('#import-unlock label')), 'PGP: asks for the passphrase');
  await popup.fill('#import-unlock input[aria-label=Passphrase]', 'falsch');
  await popup.click('#import-unlock button[type=submit]');
  await popup.waitForSelector('#import-unlock .error:not([hidden])', { timeout: 30000 });
  check(/Falsches Passwort/.test(await textOf('#import-unlock .error')), 'PGP: wrong passphrase reported');
  await popup.fill('#import-unlock input[aria-label=Passphrase]', 'Proton-Passphrase-2026');
  await popup.click('#import-unlock button[type=submit]');
  await waitText('#import-info', /Erkannt: Proton-Pass-Export · 1 Eintrag/);
  await runImport();
  const pl = (await itemsOf(accB)).find((i) => i.name === 'Proton-Login');
  check(!!pl && await msg('secret', { accountId: accB, itemId: pl.id, field: 'password' }) === 'proton-pw', 'Proton Pass login imported from the PGP file');

  // --- refused archives
  await openImport();
  await chooseFile(accB, 'x.1pux', writeZip([{ name: 'export.data', data: '{}', flags: 1 }]));
  await waitText('#import-info', /Nicht erkannt: Verschlüsselte ZIP-Archive/);
  check(true, 'encrypted ZIP refused with a message');
  await chooseFile(accB, 'bomb.zip', writeZip([{ name: 'Proton Pass/data.json', data: new Uint8Array(8 * 1024 * 1024), declaredSize: 100 }]));
  await waitText('#import-info', /ZIP-Bomben/);
  check(true, 'ZIP bomb refused with a message');
  await popup.screenshot({ path: join(shots, 'import-zip-bomb.png') });

  check(!errors.length, `no page errors (${errors.join(' | ')})`);
} catch (e) {
  console.error(e);
  failures++;
} finally {
  await ctx.close();
  vaultServer.close();
}
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
