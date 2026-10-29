// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Filling in embedded frames, with two origins: pages on http://127.0.0.1:<port> embed the login form and the
// payment form of http://localhost:8841 (the site the GitHub login belongs to).
// - the GitHub login is filled into the embedded frame (the first time after a question naming both sites, then
//   with a note in the page); a login for 127.0.0.1 only never goes into the localhost frame, not even "anyway";
// - hidden frames (transparent, tiny, off-screen, visibility:hidden, display:none) are never filled;
// - a same-origin frame is filled without a note; the item list counts the frame's logins as matching;
// - the OmniVault button and its list inside the frame, "save this login?" from the frame in the top page;
// - a card goes into an embedded payment frame of another site only after the question.
// Keyboard shortcut and context menu in frames: test/e2e-shortcuts.mjs. Firefox: test/e2e-firefox.mjs.
// Usage: node test/e2e-frames.mjs [path-to-playwright] [screenshot-dir]
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EMAIL, PASSWORD } from './fake-bitwarden.js';
import { LOGIN_PAGE, extensionCopy, launch, startServers } from './servers.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const { chromium } = await import(pwPath);
const { ORIGIN, close: closeServers } = await startServers({ bwPort: 8841, pbPort: 8842, extraItems: 0 });
const TOP_PORT = 8843;
const PAY_PORT = 8844;
const TOP = `http://127.0.0.1:${TOP_PORT}`;
const PAY = `http://127.0.0.1:${PAY_PORT}`;

/** Pages of the embedding site: one login frame each, shown or hidden in different ways. */
const frame = (src, style = 'width:380px;height:260px') => `<iframe id="f" src="${src}" style="border:1px solid #ccc;${style}"></iframe>`;
const PAGES = {
  '/embed': `<h1>Portal</h1><p>Anmeldung beim Partner:</p>${frame(`${ORIGIN}/login.html`)}`,
  '/opacity': frame(`${ORIGIN}/login.html`, 'width:380px;height:260px;opacity:0'),
  '/tiny': frame(`${ORIGIN}/login.html`, 'width:4px;height:4px'),
  '/offscreen': frame(`${ORIGIN}/login.html`, 'width:380px;height:260px;position:absolute;left:-5000px'),
  '/invisible': frame(`${ORIGIN}/login.html`, 'width:380px;height:260px;visibility:hidden'),
  '/none': frame(`${ORIGIN}/login.html`, 'width:380px;height:260px;display:none'),
  '/covered': `${frame(`${ORIGIN}/login.html`)}<div style="position:absolute;left:0;top:0;width:500px;height:300px;background:#fff"></div>`,
  '/same': `<h1>Eigene Seite</h1>${frame('/form')}`,
  '/form': LOGIN_PAGE,
  '/pay': `<h1>Kasse</h1>${frame(`${ORIGIN}/checkout.html`, 'width:500px;height:360px')}`,
};
const serve = (port) => new Promise((resolve) => {
  const s = http.createServer((req, res) => {
    const body = PAGES[req.url.split('?')[0]];
    if (!body) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(body.startsWith('<!doctype') ? body : `<!doctype html><title>Test</title>${body}`);
  });
  s.listen(port, '127.0.0.1', () => resolve(s));
});
const servers = [await serve(TOP_PORT), await serve(PAY_PORT)];

const ext = await extensionCopy({ hosts: ['http://127.0.0.1/*'] });
const { ctx, extId } = await launch(chromium, ext);
let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };
const frameOf = (page, file) => page.frames().find((f) => f.url().endsWith(`/${file}`));
const waitFrame = async (page, file) => {
  for (let i = 0; i < 100; i++) { const f = frameOf(page, file); if (f) { await f.waitForLoadState(); return f; } await page.waitForTimeout(100); }
  throw new Error(`${file} did not appear`);
};
const notice = (page) => page.evaluate(() => !!document.querySelector('omnivault-notice'));
const waitNotice = async (page) => { for (let i = 0; i < 30 && !(await notice(page)); i++) await page.waitForTimeout(100); return notice(page); };

try {
  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  const msg = (type, payload = {}) => popup.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => { if (!r.ok) throw new Error(r.error); return r.result; }), [type, payload]);
  await popup.click('#btn-new');
  await popup.click('#menu [role=menuitem]:has-text("Konto hinzufügen")');
  await popup.selectOption('#acc-fields select[name=server]', '__custom');
  await popup.fill('input[name=server__custom]', ORIGIN);
  await popup.fill('#acc-fields input[name=email]', EMAIL);
  await popup.fill('#form-account input[name=label]', 'Privat');
  await popup.click('#acc-submit');
  await popup.fill('#form-unlock input[name=password]', PASSWORD);
  await popup.click('#unlock-submit');
  await popup.waitForSelector('#view-main:not([hidden]) .item');
  const accountId = (await msg('state')).accounts[0].id;
  // a login that belongs to the embedding site only
  await msg('saveItem', { accountId, data: { type: 'login', name: 'Portal', username: 'portal-user', password: 'portal-pass', totp: '', uris: [TOP], notes: '', folderId: null } });
  let items = [];
  for (let i = 0; i < 50 && !items.some((x) => x.name === 'Portal'); i++) { items = await msg('items'); await popup.waitForTimeout(100); }
  const gh = items.find((x) => x.name === 'GitHub');
  const portal = items.find((x) => x.name === 'Portal');
  check(!!gh && !!portal, 'GitHub (localhost) and Portal (127.0.0.1) in the vault');
  const tabIdOf = (url) => popup.evaluate(async (u) => (await chrome.tabs.query({})).find((t) => t.url === u)?.id, url);

  // 1. item list: the frame's login counts as matching this page, marked as embedded
  const site = await ctx.newPage();
  site.on('pageerror', (e) => errors.push(`Seite: ${e.message}`));
  await site.goto(`${TOP}/embed`);
  let inner = await (await site.waitForSelector('#f')).contentFrame();
  await inner.waitForSelector('#p');
  let tabId = await tabIdOf(`${TOP}/embed`);
  const origins = await msg('loginFrames', { tabId });
  check(JSON.stringify(origins) === JSON.stringify([ORIGIN]), `login frames of the tab: ${JSON.stringify(origins)}`);
  const listed = await msg('items', { tabUrl: `${TOP}/embed`, frameOrigins: origins });
  const lgh = listed.find((x) => x.name === 'GitHub');
  const lportal = listed.find((x) => x.name === 'Portal');
  check(lgh.frameMatch === ORIGIN && !lgh.matches, 'GitHub matches the embedded login frame (frameMatch), not the page');
  check(lportal.matches && !lportal.frameMatch, 'Portal matches the page itself');

  // 2. the pop-out window: "matching this page" shows GitHub with the frame's site; filling asks once
  const [win] = await Promise.all([ctx.waitForEvent('page'), popup.click('#btn-popout')]);
  await win.waitForLoadState();
  await win.setViewportSize({ width: 420, height: 640 });
  win.on('pageerror', (e) => errors.push(`Fenster: ${e.message}`));
  await site.bringToFront();
  await win.evaluate(() => window.dispatchEvent(new Event('focus')));
  await win.waitForSelector('.group:first-child .item:has-text("GitHub") .embedded');
  const groupTitle = await win.textContent('.group:first-child .group-title');
  const note = await win.textContent('.group:first-child .item:has-text("GitHub") .embedded');
  check(groupTitle.includes('Passend') && note.includes('localhost:8841'), `window lists GitHub under "${groupTitle}" with "${note}"`);
  await win.screenshot({ path: join(shots, 'frames-list.png') });
  await win.locator('.group:first-child .item', { hasText: 'GitHub' }).locator('button', { hasText: 'Ausfüllen' }).click();
  await win.waitForSelector('#dialog[open]');
  const question = await win.textContent('#dialog-text');
  check(question.includes('localhost:8841') && question.includes(`127.0.0.1:${TOP_PORT}`), `question names frame and page: "${question}"`);
  await win.screenshot({ path: join(shots, 'frames-question.png') });
  await win.click('#dialog-cancel');
  await site.waitForTimeout(300);
  check(await inner.inputValue('#p') === '', 'declined: nothing filled');
  await win.locator('.group:first-child .item', { hasText: 'GitHub' }).locator('button', { hasText: 'Ausfüllen' }).click();
  await win.waitForSelector('#dialog[open]');
  await win.click('#dialog-ok');
  await inner.waitForFunction(() => document.querySelector('#p').value !== '', null, { timeout: 5000 }).catch(() => {});
  check(await inner.inputValue('#u') === 'alice' && await inner.inputValue('#p') === 'gh-pass', 'confirmed: GitHub filled into the embedded frame (click in the window)');
  check(await waitNotice(site), 'note in the page about the embedded form');
  const noticeText = await site.evaluate(() => document.querySelector('omnivault-notice') && 'present');
  check(noticeText === 'present' && await site.evaluate(() => { try { return !document.querySelector('omnivault-notice').shadowRoot; } catch { return false; } }), 'note sits in a closed shadow root');
  await site.screenshot({ path: join(shots, 'frames-notice.png') });

  // the pair is remembered: no question the second time
  await inner.fill('#u', ''); await inner.fill('#p', '');
  let r = await msg('fill', { accountId, itemId: gh.id, tabId });
  check(r.filled === 2 && !r.confirm.length && JSON.stringify(r.embedded) === JSON.stringify([ORIGIN]), `second fill without question (${JSON.stringify(r)})`);
  check(await inner.inputValue('#p') === 'gh-pass', 'filled again');
  check(await msg('frameTrust') === 1, 'one confirmed pair of sites');

  // 3. a login of the page never goes into the frame of another origin – not even when forced
  await inner.fill('#u', ''); await inner.fill('#p', '');
  r = await msg('fill', { accountId, itemId: portal.id, tabId });
  check(r.filled === 0 && await inner.inputValue('#p') === '' && await inner.inputValue('#u') === '', 'Portal (page only) does not fill the localhost frame');
  r = await msg('fill', { accountId, itemId: portal.id, tabId, force: true });
  check(r.filled === 0 && await inner.inputValue('#p') === '', '… not even "fill anyway"');

  // 4. hidden frames are ignored (the pair is trusted, so only visibility stops it)
  for (const path of ['/opacity', '/tiny', '/offscreen', '/invisible', '/none', '/covered']) {
    await site.goto(`${TOP}${path}`);
    inner = await (await site.waitForSelector('#f', { state: 'attached' })).contentFrame();
    await inner.waitForSelector('#p', { state: 'attached' });
    await site.waitForTimeout(150);
    tabId = await tabIdOf(`${TOP}${path}`);
    r = await msg('fill', { accountId, itemId: gh.id, tabId });
    const value = await inner.evaluate(() => document.querySelector('#p').value);
    check(r.filled === 0 && value === '' && (path === '/none' || path === '/tiny' || r.hidden.includes(ORIGIN)), `hidden frame (${path}) not filled (${JSON.stringify(r.hidden)})`);
    check((await msg('loginFrames', { tabId })).length === 0, `hidden frame (${path}) not listed as a login frame`);
  }

  // 5. same-origin frame: filled without a note
  await site.goto(`${TOP}/same`);
  inner = await (await site.waitForSelector('#f')).contentFrame();
  await inner.waitForSelector('#p');
  tabId = await tabIdOf(`${TOP}/same`);
  r = await msg('fill', { accountId, itemId: portal.id, tabId });
  check(r.filled === 2 && !r.embedded.length && !r.confirm.length, `same-origin frame filled (${JSON.stringify(r)})`);
  check(await inner.inputValue('#u') === 'portal-user' && await inner.inputValue('#p') === 'portal-pass', 'Portal login in the same-origin frame');
  await site.waitForTimeout(300);
  check(!(await notice(site)), 'no note for a same-origin frame');

  // 6. the existing top-level fill still works
  await site.goto(`${ORIGIN}/login.html`);
  tabId = await tabIdOf(`${ORIGIN}/login.html`);
  r = await msg('fill', { accountId, itemId: gh.id, tabId });
  check(r.filled === 2 && await site.inputValue('#p') === 'gh-pass' && !(await notice(site)), 'top-level login page filled as before, no note');

  // 7. button in the login field and its list inside the embedded frame; "save this login?" in the top page
  await msg('setSettings', { patch: { inlineMenu: true, offerSave: true } });
  await site.goto(`${TOP}/embed`);
  inner = await (await site.waitForSelector('#f')).contentFrame();
  await inner.waitForSelector('#u');
  await inner.click('#u');
  await inner.waitForFunction(() => !!document.querySelector('omnivault-inline'));
  check(!(await site.evaluate(() => !!document.querySelector('omnivault-inline'))), 'button drawn in the frame, not in the page around it');
  const box = await (await site.$('#f')).boundingBox();
  const field = await inner.locator('#u').boundingBox();
  await site.mouse.click(field.x + field.width - 15, field.y + field.height / 2);
  const menu = await waitFrame(site, 'inline-menu.html');
  await menu.waitForSelector('.row');
  check(menu.parentFrame() === inner, 'list opens inside the embedded frame');
  const rows = await menu.$$eval('.row strong', (n) => n.map((x) => x.textContent));
  check(rows.includes('GitHub') && !rows.includes('Portal'), `list shows the frame's logins only (${rows.join(', ')})`);
  check((await menu.textContent('.embedded')).includes(`127.0.0.1:${TOP_PORT}`), 'list names the page it is embedded in');
  const mbox = await (await menu.frameElement()).boundingBox();
  check(mbox && mbox.x >= box.x && mbox.y >= box.y && mbox.x + mbox.width <= box.x + box.width + 1 && mbox.y + mbox.height <= box.y + box.height + 1,
    `list fits into the frame (${JSON.stringify(mbox)} in ${JSON.stringify(box)})`);
  await site.screenshot({ path: join(shots, 'frames-inline.png') });
  await menu.click('.row:has-text("GitHub")');
  await inner.waitForFunction(() => document.querySelector('#p').value !== '', null, { timeout: 5000 }).catch(() => {});
  check(await inner.inputValue('#u') === 'alice' && await inner.inputValue('#p') === 'gh-pass', 'filled from the list in the frame');

  await inner.fill('#u', 'neu-im-frame');
  await inner.fill('#p', 'Frame-Passwort-1');
  await inner.click('button');
  const bar = await waitFrame(site, 'save-bar.html');
  await bar.waitForSelector('#save');
  check(bar.parentFrame() === site.mainFrame(), '"save this login?" opens in the top page');
  const detail = await bar.textContent('#detail');
  check(detail.includes('neu-im-frame') && detail.includes('localhost'), `bar offers the frame's login for its own site (${detail})`);
  await bar.click('#save');
  let saved = null;
  for (let i = 0; i < 50 && !saved; i++) { saved = (await msg('items')).find((x) => x.username === 'neu-im-frame'); if (!saved) await site.waitForTimeout(100); }
  check(saved?.uris?.[0] === ORIGIN, `saved with the frame's origin (${saved?.uris?.[0]})`);
  await msg('setSettings', { patch: { inlineMenu: false, offerSave: false } });

  // 8. a card into a payment frame of another site: only after the question, then with a note
  await site.goto(`${PAY}/pay`);
  inner = await (await site.waitForSelector('#f')).contentFrame();
  await inner.waitForSelector('#cc');
  tabId = await tabIdOf(`${PAY}/pay`);
  const card = (await msg('items')).find((x) => x.type === 'card');
  r = await msg('fill', { accountId, itemId: card.id, tabId });
  check(r.filled === 0 && JSON.stringify(r.confirm) === JSON.stringify([ORIGIN]) && await inner.inputValue('#cc') === '', 'card: question first, nothing filled before');
  r = await msg('fill', { accountId, itemId: card.id, tabId, allow: { top: r.top, frames: r.confirm } });
  check(r.filled >= 5 && await inner.inputValue('#cc') === '4111111111111111' && await inner.inputValue('#cvc') === '123', `card filled into the payment frame after the answer (${r.filled} fields)`);
  check(await waitNotice(site), 'note names the payment frame');

  // forgetting the pairs brings the question back
  await msg('forgetFrameTrust');
  check(await msg('frameTrust') === 0, 'pairs forgotten');
  check(errors.length === 0, `no script errors (${errors.join('; ')})`);
} catch (e) {
  failures++;
  console.log('FAIL', e.stack ?? e.message);
} finally {
  await ctx.close();
  closeServers();
  for (const s of servers) s.close();
}
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
