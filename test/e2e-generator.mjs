// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test (Chromium): generator view (password, passphrase, PIN, username; copying), the username dice in the
// editor, copying the TOTP code after filling (read back from the clipboard, cleared after the delay) and reading a
// TOTP QR code from a page (test/qr-encode.mjs draws it; captureVisibleTab needs <all_urls> or activeTab – this
// test copy of the extension gets <all_urls>, the toolbar popup gets activeTab).
// Usage: node test/e2e-generator.mjs [path-to-playwright] [screenshot-dir]
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EMAIL, PASSWORD } from './fake-bitwarden.js';
import { extensionCopy, launch, startServers } from './servers.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const { chromium } = await import(pwPath);

const { ORIGIN, close: closeServers } = await startServers({ bwPort: 8851, pbPort: 8852 });
// a page of another site that embeds the login form (only filled after the user confirmed the pair of sites)
const TOP = 'http://127.0.0.1:8853';
const embedServer = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<!doctype html><title>Portal</title><h1>Portal</h1><iframe id="f" src="${ORIGIN}/login.html" style="width:380px;height:260px"></iframe>`);
});
await new Promise((r) => { embedServer.listen(8853, '127.0.0.1', r); });
const ext = await extensionCopy({ hosts: ['<all_urls>'] });
const { ctx, extId } = await launch(chromium, ext);
await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGIN });

let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WORD = '[a-z]+(?:-[a-z]+)?';

try {
  const site = await ctx.newPage();
  await site.goto(`${ORIGIN}/login.html`);
  const clipboard = () => site.evaluate(() => navigator.clipboard.readText());
  const setClipboard = (text) => site.evaluate((x) => navigator.clipboard.writeText(x), text);

  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.setViewportSize({ width: 380, height: 600 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector('#view-main:not([hidden])');
  const msg = (type, data = {}) => popup.evaluate(([t, d]) => chrome.runtime.sendMessage({ type: t, ...d }), [type, data]);
  const acc = (await msg('addAccount', { provider: 'bitwarden', config: { server: ORIGIN, email: EMAIL }, label: 'Test', short: 'TE' })).result;
  check((await msg('login', { id: acc.id, credentials: { password: PASSWORD } })).ok, 'test account unlocked');
  await popup.reload();
  await popup.waitForSelector('#view-main:not([hidden]) .item');

  /* ---------- generator view ---------- */
  await popup.click('#btn-generator');
  await popup.waitForSelector('#view-generator:not([hidden])');
  check(await popup.textContent('#view-generator h2') === 'Generator', 'generator view opened');
  check(await popup.inputValue('#gen-mode') === 'password' && /^•+$/.test(await popup.textContent('#gen-out')), 'starts with a hidden password');
  await popup.click('#view-generator .gen-row button'); // eye
  const out = () => popup.textContent('#gen-out');

  await popup.selectOption('#gen-mode', 'passphrase');
  let phrase = await out();
  check(new RegExp(`^${WORD}(-${WORD}){4}$`).test(phrase), `passphrase: 5 words with "-" (${phrase})`);
  check((await popup.textContent('#gen-info')).includes('64 Bit'), `passphrase entropy 5 × log2(7776) ≈ 64 bits: "${await popup.textContent('#gen-info')}"`);
  check(await popup.isHidden('#view-generator [data-section=password]') && await popup.isVisible('#view-generator [data-section=passphrase]'), 'passphrase options replace the character options');
  await popup.evaluate(() => { const r = document.querySelector('[data-gen=words]'); r.value = '7'; r.dispatchEvent(new Event('input')); r.dispatchEvent(new Event('change')); });
  await popup.fill('[data-gen=separator]', '_');
  await popup.check('#view-generator input[data-opt=capitalize]');
  await popup.check('#view-generator input[data-opt=includeNumber]');
  phrase = await out();
  const parts = phrase.split('_');
  check(parts.length === 7 && parts.every((w) => /^[A-Z]/.test(w)) && parts.filter((w) => /\d$/.test(w)).length === 1, `passphrase: 7 capitalized words, "_", one digit (${phrase})`);
  check((await popup.textContent('#gen-info')).includes(`${Math.floor(7 * Math.log2(7776) + Math.log2(10) + Math.log2(7))} Bit`), `entropy with digit: "${await popup.textContent('#gen-info')}"`);
  await popup.click('#view-generator button[data-action=copy]');
  await popup.waitForSelector('#toast:not([hidden])');
  check((await popup.textContent('#toast')).startsWith('Passphrase kopiert'), `copy toast: "${await popup.textContent('#toast')}"`);
  check(await clipboard() === phrase, 'passphrase on the clipboard');
  await popup.waitForSelector('#view-generator details.history:not([hidden])');

  await popup.selectOption('#gen-mode', 'pin');
  check(/^\d{12}$/.test(await out()) || /^\d+$/.test(await out()), `PIN (${await out()})`);

  await popup.selectOption('#gen-mode', 'username');
  check(await popup.isHidden('#view-generator .gen-row button') && await popup.isHidden('#gen-info'), 'username: shown directly, no strength meter');
  check(new RegExp(`^${WORD}\\d{4}$`).test(await out()), `username: random word + number (${await out()})`);
  await popup.uncheck('#view-generator input[data-opt=usernameNumber]');
  check(new RegExp(`^${WORD}$`).test(await out()), `username without number (${await out()})`);
  await popup.selectOption('[data-gen=usernameType]', 'plus');
  check(await popup.evaluate(() => document.querySelector('#gen-out').classList.contains('error')), `plus address without an email: message "${await out()}"`);
  await popup.fill('[data-gen=plusEmail]', 'ada@example.org');
  await popup.dispatchEvent('[data-gen=plusEmail]', 'change');
  check(/^ada\+[a-z0-9]{8}@example\.org$/.test(await out()), `plus address (${await out()})`);
  await popup.click('#view-generator button[data-action=copy]');
  await popup.waitForFunction(() => document.querySelector('#toast').textContent.startsWith('Benutzername kopiert'));
  check(/^ada\+[a-z0-9]{8}@example\.org$/.test(await clipboard()), 'plus address copied');
  await popup.selectOption('[data-gen=usernameType]', 'catchall');
  await popup.fill('[data-gen=catchAllDomain]', 'mail.example.net');
  await popup.dispatchEvent('[data-gen=catchAllDomain]', 'change');
  check(/^[a-z0-9]{10}@mail\.example\.net$/.test(await out()), `catch-all address (${await out()})`);
  await popup.screenshot({ path: join(shots, 'generator-username.png') });
  await popup.selectOption('#gen-mode', 'passphrase');
  await popup.waitForFunction(async () => (await chrome.runtime.sendMessage({ type: 'settings' })).result.generator.type === 'passphrase').catch(() => {});
  const stored = (await msg('settings')).result.generator;
  check(stored.type === 'passphrase' && stored.words === 7 && stored.separator === '_' && stored.capitalize && stored.includeNumber
    && stored.usernameType === 'catchall' && stored.plusEmail === 'ada@example.org' && stored.catchAllDomain === 'mail.example.net', 'generator settings persisted');
  const history = await msg('generated');
  check(history.result.length === 1 && history.result[0].value === phrase, 'only secrets go into the recent list, not usernames');
  const width = await popup.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
  check(width[0] <= width[1], 'generator: no horizontal scroll');
  await popup.click('#view-generator button:has-text("Zurück")');

  /* ---------- editor: dice for username and password ---------- */
  await popup.click('#btn-new');
  await popup.click('#menu [role=menuitem]:has-text("Neuer Login")');
  await popup.waitForSelector('#view-edit:not([hidden])');
  await popup.click('#view-edit button[data-action=generate-username]');
  check(/^[a-z0-9]{10}@mail\.example\.net$/.test(await popup.inputValue('#view-edit input[name=username]')), `username dice follows the generator (${await popup.inputValue('#view-edit input[name=username]')})`);
  await popup.click('#view-edit button[aria-label="Passwort generieren"]');
  check(/^[A-Z][a-z-]*\d?(_[A-Z][a-z-]*\d?){6}$/.test(await popup.inputValue('#view-edit input[name=password]')), 'password dice gives a passphrase when that is the chosen kind');
  await popup.click('#view-edit button[data-action=generate-username]', { button: 'right' });
  await popup.waitForSelector('#view-generator:not([hidden])');
  check(await popup.inputValue('#gen-mode') === 'username' && await popup.isVisible('#view-generator button[data-action=use]'), 'right-click opens the username generator with "Use"');
  await popup.selectOption('[data-gen=usernameType]', 'word');
  const chosen = await out();
  await popup.click('#view-generator button[data-action=use]');
  await popup.waitForSelector('#view-edit:not([hidden])');
  check(await popup.inputValue('#view-edit input[name=username]') === chosen, 'username taken over from the generator');
  check((await msg('settings')).result.generator.type === 'passphrase', 'opening the username generator from the editor keeps the default kind');
  await popup.click('#view-edit button:has-text("Abbrechen")');

  /* ---------- TOTP after filling ---------- */
  const items = (await msg('items', { tabUrl: `${ORIGIN}/login.html` })).result;
  const gh = items.find((i) => i.name === 'GitHub');
  const [tab] = await popup.evaluate((o) => chrome.tabs.query({ url: `${o}/*` }), ORIGIN);
  const code = async () => (await msg('secret', { accountId: gh.accountId, itemId: gh.id, field: 'totp' })).result.code;

  await setClipboard('sentinel');
  check((await msg('fill', { accountId: gh.accountId, itemId: gh.id, tabId: tab.id })).result.filled === 2, 'filled (setting off)');
  check(await clipboard() === 'sentinel', 'setting off (default): clipboard untouched');

  await msg('setSettings', { patch: { copyTotpAfterFill: true, clipboardSeconds: 10 } });
  await site.fill('#u', ''); await site.fill('#p', '');
  const before = await code();
  const filled = await msg('fill', { accountId: gh.accountId, itemId: gh.id, tabId: tab.id });
  const after = await code();
  check(filled.result.filled === 2 && await site.inputValue('#p') === 'gh-pass', 'filled (setting on)');
  const copied = await clipboard();
  check(/^\d{6}$/.test(copied) && (copied === before || copied === after), `TOTP code on the clipboard (${copied})`);
  const notice = await site.evaluate(() => !!document.querySelector('omnivault-notice'));
  check(notice, 'short notice on the page');
  await site.screenshot({ path: join(shots, 'totp-copied-notice.png') });
  check(!(await site.evaluate(() => document.querySelector('omnivault-notice')?.shadowRoot)), 'notice in a closed shadow root');
  await sleep(6500);
  check(!(await site.evaluate(() => !!document.querySelector('omnivault-notice'))), 'notice disappears');
  await sleep(5000);
  check((await clipboard()).trim() === '', 'clipboard cleared after the delay (10 s)');

  // embedded login form of another site: nothing is copied while the result only asks for confirmation; once
  // confirmed, the code is copied and the note in the top page names the embedded form
  const portal = await ctx.newPage();
  await portal.goto(`${TOP}/`);
  await (await (await portal.waitForSelector('#f')).contentFrame()).waitForSelector('#p');
  const [portalTab] = await popup.evaluate(() => chrome.tabs.query({ url: 'http://127.0.0.1:8853/*' }));
  await setClipboard('sentinel');
  const ask = (await msg('fill', { accountId: gh.accountId, itemId: gh.id, tabId: portalTab.id })).result;
  check(!ask.filled && ask.confirm?.length === 1 && await clipboard() === 'sentinel', `embedded form not confirmed yet: nothing filled, nothing copied (${JSON.stringify(ask)})`);
  const done = (await msg('fill', { accountId: gh.accountId, itemId: gh.id, tabId: portalTab.id, allow: { top: TOP, frames: ask.confirm } })).result;
  const inner = (await portal.$('#f').then((f) => f.contentFrame()));
  check(done.filled === 2 && done.embedded.length === 1 && await inner.inputValue('#p') === 'gh-pass', 'confirmed: embedded login filled');
  check(/^\d{6}$/.test(await clipboard()), `TOTP code copied after filling the embedded form (${await clipboard()})`);
  check(await portal.evaluate(() => document.querySelectorAll('omnivault-notice').length === 1) && !(await inner.evaluate(() => !!document.querySelector('omnivault-notice'))),
    'one note, in the top page (names the embedded form and the copied code)');
  await portal.screenshot({ path: join(shots, 'totp-copied-embedded.png') });
  await portal.close();

  // a login without TOTP leaves the clipboard alone
  const shop = items.find((i) => i.type === 'login' && i.name === 'Shop');
  if (shop) {
    await setClipboard('sentinel');
    await msg('fill', { accountId: shop.accountId, itemId: shop.id, tabId: tab.id });
    check(await clipboard() === 'sentinel', 'login without TOTP: clipboard untouched');
  }
  // the setting in the settings view
  await popup.click('#btn-settings');
  await popup.waitForSelector('#view-settings:not([hidden])');
  check(await popup.isChecked('#view-settings input[name=copyTotpAfterFill]'), 'setting shown in the settings');
  await popup.uncheck('#view-settings input[name=copyTotpAfterFill]');
  await popup.waitForFunction(async () => !(await chrome.runtime.sendMessage({ type: 'settings' })).result.copyTotpAfterFill);
  check(true, 'setting switched off in the settings');
  await popup.click('#view-settings button:has-text("Zurück")');

  /* ---------- QR code on the page → TOTP field ---------- */
  const uri = 'otpauth://totp/Example%20Shop:ada%40example.org?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Shop&period=30&digits=6&algorithm=SHA1';
  await site.goto(`${ORIGIN}/qr.html?text=${encodeURIComponent(uri)}`);
  await site.bringToFront();
  // the pop-out window targets the last focused browser window (like the toolbar popup targets the active tab)
  const [win] = await Promise.all([ctx.waitForEvent('page'), popup.evaluate(() => chrome.windows.create({ url: 'popup.html?window=1', type: 'popup', width: 420, height: 640 }))]);
  await win.waitForSelector('#view-main:not([hidden])');
  await win.waitForSelector('#target:not([hidden])');
  check((await win.textContent('#target')).includes('localhost:8851'), `window targets the page with the QR code: "${await win.textContent('#target')}"`);
  await win.click('#btn-new');
  await win.click('#menu [role=menuitem]:has-text("Neuer Login")');
  await win.waitForSelector('#view-edit:not([hidden])');
  check(await win.isVisible('#view-edit button[data-action=scan-qr]'), 'scan button next to the TOTP field');
  await win.click('#view-edit button[data-action=scan-qr]');
  await win.waitForSelector('#view-edit [data-hint=totp-scan]:not([hidden])', { timeout: 15000 });
  const hint = await win.textContent('#view-edit [data-hint=totp-scan]');
  check(await win.inputValue('#view-edit input[name=totp]') === uri, `otpauth URI taken over (${hint})`);
  check(await win.inputValue('#view-edit input[name=username]') === 'ada@example.org', 'empty username filled from the QR code');
  check(await win.inputValue('#view-edit input[name=name]') === 'localhost', 'a name already there (from the site) is kept');
  await win.fill('#view-edit input[name=name]', '');
  await win.click('#view-edit button[data-action=scan-qr]');
  await win.waitForFunction(() => document.querySelector('#view-edit input[name=name]').value === 'Example Shop');
  check(true, 'empty name filled with the issuer');
  check(hint.includes('Example Shop'), `hint: "${hint}"`);
  await win.screenshot({ path: join(shots, 'editor-qr-scanned.png') });

  // a QR code that is not a TOTP, and a page without one
  await site.goto(`${ORIGIN}/qr.html?text=${encodeURIComponent('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=3')}`);
  await win.click('#view-edit button[data-action=scan-qr]');
  await win.waitForFunction(() => /TOTP/.test(document.querySelector('[data-hint=totp-scan]').textContent) && document.querySelector('[data-hint=totp-scan]').classList.contains('error'));
  check(await win.inputValue('#view-edit input[name=totp]') === uri, `HOTP code refused: "${await win.textContent('#view-edit [data-hint=totp-scan]')}"`);
  await site.goto(`${ORIGIN}/qr.html?text=${encodeURIComponent('https://example.org/')}`);
  await win.click('#view-edit button[data-action=scan-qr]');
  await win.waitForFunction(() => /otpauth/.test(document.querySelector('[data-hint=totp-scan]').textContent));
  check(true, `other QR codes refused: "${await win.textContent('#view-edit [data-hint=totp-scan]')}"`);
  await site.goto(`${ORIGIN}/login.html`);
  await win.click('#view-edit button[data-action=scan-qr]');
  await win.waitForFunction(() => /Kein QR-Code/.test(document.querySelector('[data-hint=totp-scan]').textContent));
  check(true, `page without a QR code: "${await win.textContent('#view-edit [data-hint=totp-scan]')}"`);
  // save: the item gets the URI and produces codes
  await site.goto(`${ORIGIN}/qr.html?text=${encodeURIComponent(uri)}`);
  await win.click('#view-edit button[data-action=scan-qr]');
  await win.waitForFunction((u) => document.querySelector('#view-edit input[name=totp]').value === u, uri);
  await win.click('#view-edit button[type=submit]');
  await win.waitForSelector('#view-item:not([hidden])');
  const saved = (await msg('items', {})).result.find((i) => i.name === 'Example Shop');
  const savedCode = saved && (await msg('secret', { accountId: saved.accountId, itemId: saved.id, field: 'totp' })).result;
  check(/^\d{6}$/.test(savedCode?.code ?? ''), `saved login produces TOTP codes (${savedCode?.code})`);

  check(!errors.length, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (e) {
  console.error(e);
  failures++;
} finally {
  await ctx.close();
  closeServers();
  embedServer.close();
}
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
