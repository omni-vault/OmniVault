// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test for pass with "decrypt on open": Chromium → extension → native messaging → native/omnivault_host.py
// (registered with native/install.py into the test profile) → REAL pass + gpg, with gpg wrapped to count decryptions.
// The list, "matching this page" and search run without a single decryption; opening, copying and filling decrypt
// exactly the entry concerned. Needs OMNIVAULT_PASS_BIN (skipped without it).
// Usage: OMNIVAULT_PASS_BIN=/path/to/pass node test/e2e-pass.mjs [path-to-playwright] [screenshot-dir]
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gpgCounter } from './native-transport.mjs';
import { extensionCopy, launch, startServers } from './servers.mjs';

const PASS_BIN = process.env.OMNIVAULT_PASS_BIN;
if (!PASS_BIN) { console.log('skipped: OMNIVAULT_PASS_BIN not set'); process.exit(0); }
const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const { chromium } = await import(pwPath);

// short path: gpg-agent's socket path must stay below ~100 characters
const work = mkdtempSync('/tmp/ovpass-e2e-');
const GNUPGHOME = join(work, 'gnupg');
const STORE = join(work, 'store');
mkdirSync(GNUPGHOME, { mode: 0o700 });
writeFileSync(join(work, 'genkey'), '%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\nSubkey-Type: ecdh\nSubkey-Curve: cv25519\nName-Real: OV Test\nName-Email: pass-e2e@omnivault.local\nExpire-Date: 0\n%commit\n');
const genv = { ...process.env, GNUPGHOME, PASSWORD_STORE_DIR: STORE };
execFileSync('gpg', ['--batch', '--quiet', '--gen-key', join(work, 'genkey')], { env: genv });
execFileSync(PASS_BIN, ['init', 'pass-e2e@omnivault.local'], { env: genv });
const insert = (path, body) => execFileSync(PASS_BIN, ['insert', '-m', '-f', path], { env: genv, input: body });
insert('websites/example.org/ada', 'ex-geheim\nurl: https://shop.example.org/login.html\n');
insert('web/github.com', 'gh-geheim\nlogin: octo\n');
insert('notizen/idee', 'nur ein Gedanke\n');

const BW_PORT = Number(process.env.E2E_BW_PORT ?? 8787);
const { close: closeServers } = await startServers({ bwPort: BW_PORT, pbPort: Number(process.env.E2E_PB_PORT ?? 8788) });
const SITE = `http://shop.example.org:${BW_PORT}/login.html`;
const gpg = gpgCounter(work);
const ext = await extensionCopy({ permissions: ['nativeMessaging'], hosts: ['http://shop.example.org/*'] });
const { ctx, extId, profile } = await launch(chromium, ext, {
  env: { OMNIVAULT_PASS_BIN: PASS_BIN, GNUPGHOME, PASSWORD_STORE_DIR: STORE, ...gpg.env },
  args: ['--host-resolver-rules=MAP shop.example.org 127.0.0.1'],
});
execFileSync('python3', ['native/install.py', '--chrome-id', extId, '--chrome-profile-dir', profile], { env: { ...process.env, XDG_DATA_HOME: work } });

let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };

try {
  const page = await ctx.newPage();
  await page.goto(SITE);
  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.setViewportSize({ width: 380, height: 560 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector('#empty:not([hidden])');
  const msg = (type, payload = {}) => popup.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => {
    if (r?.error) throw new Error(r.error);
    return r.result;
  }), [type, payload]);

  await popup.click('#btn-new');
  await popup.click('#menu [role=menuitem]:has-text("Konto hinzufügen")');
  await popup.selectOption('#acc-provider', 'pass');
  const select = '#acc-fields select[name=decrypt]';
  check(await popup.inputValue(select) === 'sync', 'decrypting during sync is the default');
  check(/websites\/github\.com\/ada/.test(await popup.textContent('#acc-fields')), 'the setting explains what the list loses');
  await popup.selectOption(select, 'open');
  await popup.fill('#form-account input[name=label]', 'pass');
  await popup.screenshot({ path: join(shots, 'pass-lazy-account.png') });
  gpg.reset();
  await popup.click('#acc-submit');
  await popup.waitForSelector('#view-unlock:not([hidden])');
  await popup.click('#unlock-submit');
  await popup.waitForSelector('#view-main:not([hidden])');
  await popup.waitForFunction(() => document.querySelectorAll('.item').length >= 3);
  const names = await popup.$$eval('.item .name', (n) => n.map((x) => x.textContent));
  check(['ada', 'github.com', 'idee'].every((n) => names.includes(n)), `entries listed: ${names.join(', ')}`);
  check(gpg.decrypts() === 0, `list without decrypting (${gpg.decrypts()} decryptions)`);

  // matching this page (from the path) and search
  const items = await msg('items', { tabUrl: SITE });
  const ada = items.find((i) => i.name === 'ada');
  check(ada?.matches && ada.username === 'ada' && !('password' in ada), 'path websites/example.org/ada matches shop.example.org, user name from the path');
  check(!items.find((i) => i.name === 'github.com').matches && !items.find((i) => i.name === 'idee').matches, 'other entries do not match');
  await popup.fill('#search', 'github');
  await popup.waitForFunction(() => document.querySelectorAll('.item').length === 1);
  await popup.fill('#search', '');
  check(gpg.decrypts() === 0, 'matching and search decrypt nothing');

  // fill: decrypts that entry only
  const filled = await popup.evaluate(async ([accountId, itemId]) => {
    const [tab] = await chrome.tabs.query({ url: 'http://shop.example.org/*' });
    return chrome.runtime.sendMessage({ type: 'fill', accountId, itemId, tabId: tab.id });
  }, [ada.accountId, ada.id]);
  check(filled.ok, `fill reported ${JSON.stringify(filled)}`);
  check(await page.inputValue('#u') === 'ada' && await page.inputValue('#p') === 'ex-geheim', 'login form filled (user name from the path)');
  check(gpg.decrypts() === 1, `filling decrypted one entry (${gpg.decrypts()})`);

  // copying a password of another entry decrypts that one
  const gh = items.find((i) => i.name === 'github.com');
  check(await msg('secret', { accountId: gh.accountId, itemId: gh.id, field: 'password' }) === 'gh-geheim', 'password fetched on demand');
  check(gpg.decrypts() === 2, `second entry decrypted once (${gpg.decrypts()})`);

  // detail view after decrypting: user name from the content
  await popup.click('.item:has(.name:text-is("github.com"))');
  await popup.waitForSelector('#view-item:not([hidden]) h2:has-text("github.com")');
  check(await popup.textContent('#view-item .field[data-field="Benutzername"] .v') === 'octo', 'user name from the file once opened');
  check(gpg.decrypts() === 2, 'an entry already decrypted is not decrypted again');
  await popup.screenshot({ path: join(shots, 'pass-lazy-detail.png') });

  // editing an entry whose user name came from the path writes no login: line
  await msg('saveItem', { accountId: ada.accountId, itemId: ada.id, data: { ...(await msg('item', { accountId: ada.accountId, itemId: ada.id })), password: 'ex-neu' } });
  const file = execFileSync(PASS_BIN, ['show', 'websites/example.org/ada'], { env: genv, encoding: 'utf8' });
  check(file === 'ex-neu\nurl: https://shop.example.org/login.html\n', `saved without a login: line (${JSON.stringify(file)})`);
  check(errors.length === 0, `no page errors ${errors.join('; ')}`);
} catch (e) {
  failures++;
  console.log('FAIL', e.stack ?? e.message);
} finally {
  await ctx.close();
  closeServers();
  try { execFileSync('gpgconf', ['--kill', 'all'], { env: genv }); } catch { /* ignore */ }
  rmSync(work, { recursive: true, force: true });
}
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
