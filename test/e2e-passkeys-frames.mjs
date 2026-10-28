// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Passkeys in embedded frames: a page on one origin (http://127.0.0.1:8809) embeds the passkey site of another
// (http://localhost:8807, relying party "localhost") twice – with allow="publickey-credentials-get;
// publickey-credentials-create" and without. Only the frame with the Permissions Policy is served by OmniVault
// (dialog in the top frame, naming both origins; clientDataJSON with crossOrigin and topOrigin, checked by the
// site's server in test/webauthn-rp.js). The frame without it goes to the browser, even when its page script
// pretends otherwise.
// Usage: node test/e2e-passkeys-frames.mjs [path-to-playwright]
import http from 'node:http';
import { EMAIL, PASSWORD } from './fake-bitwarden.js';
import { embeddingPage, extensionCopy, launch, startServers } from './servers.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const { chromium } = await import(pwPath);
const { ORIGIN, rp, close: closeServers } = await startServers({ bwPort: 8807, pbPort: 8808, extraItems: 0 });
const TOP_PORT = 8809;
const TOP = `http://127.0.0.1:${TOP_PORT}`;
const top = http.createServer((req, res) => {
  if (req.url !== '/') { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(embeddingPage(ORIGIN));
});
await new Promise((r) => { top.listen(TOP_PORT, '127.0.0.1', r); });
rp.topOrigins = [TOP];
const ext = await extensionCopy({ hosts: ['http://127.0.0.1/*'] });
const { ctx, extId } = await launch(chromium, ext);
let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };
const dialogOf = (page) => page.frames().find((f) => f.url().includes('/passkey.html'));
const waitDialog = async (page) => {
  for (let i = 0; i < 100; i++) { const f = dialogOf(page); if (f) { await f.waitForLoadState(); return f; } await page.waitForTimeout(100); }
  throw new Error('passkey dialog did not appear');
};

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
  await msg('setSettings', { patch: { passkeys: true, inlineMenu: false, offerSave: false } });

  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`Seite: ${e.message}`));
  await page.goto(`${TOP}/`);
  const frameEl = { with: await page.waitForSelector('#with'), without: await page.waitForSelector('#without') };
  const frame = { with: await frameEl.with.contentFrame(), without: await frameEl.without.contentFrame() };
  await frame.with.waitForSelector('#register');
  await frame.without.waitForSelector('#register');
  check(await frame.with.evaluate(() => document.featurePolicy.allowsFeature('publickey-credentials-get')) === true
    && await frame.without.evaluate(() => document.featurePolicy.allowsFeature('publickey-credentials-get')) === false, 'the browser applies the Permissions Policy as expected');
  const out = async (f) => {
    await f.waitForFunction(() => document.querySelector('#out').textContent !== '', null, { timeout: 15000 });
    const text = await f.textContent('#out');
    await f.evaluate(() => { document.querySelector('#out').textContent = ''; });
    return text;
  };

  // 1. register inside the frame with the policy: dialog in the top frame, naming both origins
  await frame.with.fill('#user', 'fritz');
  await frame.with.click('#register');
  let dialog = await waitDialog(page);
  check(dialog.parentFrame() === page.mainFrame(), 'dialog opens in the top frame, not in the embedded one');
  await dialog.waitForSelector('#save');
  const note = await dialog.textContent('#frame');
  check(await dialog.isVisible('#frame') && note.includes('localhost:8807') && note.includes(`127.0.0.1:${TOP_PORT}`), `dialog names frame and page (${note})`);
  await dialog.click('#save');
  let o = await out(frame.with);
  check(o.startsWith('registriert:fritz:'), `site in the frame accepted the OmniVault passkey (${o})`);
  check(rp.clientData?.crossOrigin === true && rp.clientData?.topOrigin === TOP && rp.clientData?.origin === ORIGIN,
    `clientDataJSON: origin of the frame, crossOrigin, topOrigin (${JSON.stringify(rp.clientData)})`);
  check(!dialogOf(page), 'dialog closed');

  // 2. sign in from the frame
  await frame.with.click('#login');
  dialog = await waitDialog(page);
  await dialog.waitForSelector('.row');
  await dialog.click('.row:has-text("fritz")');
  o = await out(frame.with);
  check(o === 'angemeldet:fritz', `signed in inside the frame (${o})`);
  check(rp.clientData?.type === 'webauthn.get' && rp.clientData.crossOrigin === true && rp.clientData.topOrigin === TOP, 'assertion: crossOrigin and topOrigin');

  // 3. cancel in the dialog → NotAllowedError in the frame
  await frame.with.click('#login');
  dialog = await waitDialog(page);
  await dialog.click('#cancel');
  o = await out(frame.with);
  check(o === 'fehler:NotAllowedError', `cancel reaches the frame (${o})`);

  // 4. the frame without the policy: OmniVault stays out (although it holds fritz's passkey), the browser refuses
  await frame.without.click('#login');
  o = await out(frame.without);
  check(o === 'fehler:NotAllowedError' && !dialogOf(page), `frame without allow=…: no OmniVault dialog, the browser answers (${o})`);

  // 5. … even when the frame's page claims the policy allows it (the check runs in the isolated world)
  await frame.without.evaluate(() => {
    const p = Object.getPrototypeOf(document.featurePolicy);
    p.allowsFeature = () => true;
    p.allowedFeatures = () => ['publickey-credentials-get', 'publickey-credentials-create'];
  });
  check(await frame.without.evaluate(() => document.featurePolicy.allowsFeature('publickey-credentials-get')), 'page script lies about its policy');
  await frame.without.click('#login');
  o = await out(frame.without);
  check(o === 'fehler:NotAllowedError' && !dialogOf(page), `a lying frame still goes to the browser (${o})`);

  // 6. the top-level page itself (the passkey site opened directly) keeps working, without crossOrigin
  const direct = await ctx.newPage();
  await direct.goto(`${ORIGIN}/webauthn.html`);
  await direct.click('#login');
  dialog = await waitDialog(direct);
  await dialog.waitForSelector('.row');
  check(!(await dialog.isVisible('#frame')), 'top-level request: no frame notice');
  await dialog.click('.row:has-text("fritz")');
  o = await out(direct);
  check(o === 'angemeldet:fritz' && rp.clientData.crossOrigin === false && !('topOrigin' in rp.clientData), `top-level sign-in: crossOrigin false (${o})`);

  check(errors.length === 0, `no script errors${errors.length ? `: ${errors.join(' / ')}` : ''}`);
} catch (e) {
  failures++;
  console.log('FAIL', e.stack);
} finally {
  await ctx.close();
  closeServers();
  top.close();
}
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
