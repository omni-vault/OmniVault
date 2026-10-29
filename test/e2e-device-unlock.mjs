// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test: unlock with the device (WebAuthn PRF) in Chromium with virtual authenticators over CDP.
// 1. In the pop-out window (the ceremony runs on the page): set up, lock, unlock with the device, cancelled
//    verification, a PRF output that does not fit, PIN and device side by side, wrong authenticator, another
//    device (an authenticator that evaluates PRF only when signing in), remove, authenticator without PRF.
// 2. From the real toolbar popup (the ceremony runs in a window of its own): set up there and come back to the
//    popup; unlock with an authenticator that does not know the passkey, cancel, back to the popup.
// Virtual authenticators belong to one page; the device window gets its own before its script starts (the
// browser-wide auto-attach pauses new pages). A passkey cannot be carried over to another page with its PRF secret,
// so a successful unlock in the device window itself is not covered here (it runs the same code as on the page).
// Usage: node test/e2e-device-unlock.mjs [path-to-playwright] [screenshot-dir]   (visible with `xvfb-run -a`)
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EMAIL, PASSWORD } from './fake-bitwarden.js';
import { attachTarget, openToolbarPopup } from './popup-cdp.mjs';
import { extensionCopy, launch, startServers } from './servers.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const { chromium } = await import(pwPath);
const DEBUG_PORT = 9417;
const headless = !process.env.DISPLAY;

const { ORIGIN, close: closeServers } = await startServers({ bwPort: 8917, pbPort: 8918 });
const ext = await extensionCopy();
const { ctx, sw, extId } = await launch(chromium, ext, { headless, debugPort: DEBUG_PORT });

let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, what, timeout = 20000) => {
  const end = Date.now() + timeout;
  for (;;) {
    const v = await fn().catch(() => null);
    if (v) return v;
    if (Date.now() > end) throw new Error(`Timeout: ${what}`);
    await sleep(100);
  }
};
const AUTH = (o = {}) => ({ protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true, ...o });

/* browser-wide CDP: new device windows wait until they have their virtual authenticator */
const { webSocketDebuggerUrl } = await (await fetch(`http://127.0.0.1:${DEBUG_PORT}/json/version`)).json();
const browserWs = new WebSocket(webSocketDebuggerUrl);
await new Promise((r, j) => { browserWs.onopen = r; browserWs.onerror = j; });
let seq = 0;
const pendingCdp = new Map();
const cdp = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++seq;
  pendingCdp.set(id, { resolve, reject });
  browserWs.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
});
let deviceWindowAuth = null; // options for the next device window's authenticator
const deviceWindows = [];
browserWs.onmessage = async (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pendingCdp.has(m.id)) {
    const { resolve, reject } = pendingCdp.get(m.id);
    pendingCdp.delete(m.id);
    if (m.error) reject(new Error(m.error.message)); else resolve(m.result);
    return;
  }
  if (m.method !== 'Target.attachedToTarget') return;
  const { sessionId, targetInfo, waitingForDebugger } = m.params;
  if (targetInfo.url.includes('/device.html') && deviceWindowAuth) {
    await cdp('WebAuthn.enable', { enableUI: false }, sessionId);
    const { authenticatorId } = await cdp('WebAuthn.addVirtualAuthenticator', { options: AUTH(deviceWindowAuth) }, sessionId);
    deviceWindows.push({ url: targetInfo.url, sessionId, authenticatorId });
  }
  if (waitingForDebugger) await cdp('Runtime.runIfWaitingForDebugger', {}, sessionId).catch(() => {});
};
await cdp('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true, filter: [{ type: 'page' }] });

try {
  /* ---------- 1. on the page (pop-out window) ---------- */
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (x) => errors.push(x.message));
  await page.goto(`chrome-extension://${extId}/popup.html?window=1`);
  const msg = (type, payload = {}) => page.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => { if (!r.ok) throw new Error(r.error); return r.result; }), [type, payload]);
  const local = (key) => page.evaluate((k) => chrome.storage.local.get(k).then((r) => r[k]), key);
  const session = (key) => page.evaluate((k) => chrome.storage.session.get(k).then((r) => r[k]), key);
  const acc = await msg('addAccount', { provider: 'bitwarden', config: { server: ORIGIN, email: EMAIL }, label: 'Privat' });
  await msg('login', { id: acc.id, credentials: { password: PASSWORD } });
  const itemCount = (await msg('items')).length;
  await page.reload();
  await page.waitForSelector('.item');
  // toasts disappear after two seconds: keep a record of them
  const recordToasts = () => page.evaluate(() => {
    window.toasts = [];
    new MutationObserver(() => window.toasts.push(document.querySelector('#toast').textContent))
      .observe(document.querySelector('#toast'), { childList: true, characterData: true, subtree: true });
  });
  const toasts = () => page.evaluate(() => window.toasts);
  await recordToasts();

  const cdpPage = await ctx.newCDPSession(page);
  await cdpPage.send('WebAuthn.enable', { enableUI: false });
  const addAuth = async (o) => (await cdpPage.send('WebAuthn.addVirtualAuthenticator', { options: AUTH(o) })).authenticatorId;
  const creds = async (id) => (await cdpPage.send('WebAuthn.getCredentials', { authenticatorId: id })).credentials;
  let A = await addAuth();

  const openSettings = async () => {
    await page.click('#btn-settings');
    await page.waitForSelector('#device-setting button');
  };
  const backToList = async () => {
    await page.click('#view-settings button:has-text("Zurück")');
    await page.waitForSelector('#view-main:not([hidden])');
  };
  const lockAll = async () => {
    await page.click('#btn-lock-all');
    await page.waitForFunction(() => !document.querySelector('.item'));
  };
  const deviceButton = () => page.isVisible('#device-unlock-btn');
  const unlockedCount = async () => (await msg('state')).accounts.filter((a) => a.unlocked).length;

  // settings: explanation and setup
  await openSettings();
  const hint = await page.textContent('#device-setting');
  check(/Windows Hello, Touch ID, dem Smartphone oder einem Sicherheitsschlüssel/.test(hint) && /Neustart des Browsers/.test(hint), 'settings: device unlock explained, not set up yet');
  await page.click('#device-setting button:has-text("Entsperren mit dem Gerät einrichten")');
  await page.waitForSelector('#device-setting button:has-text("Gerät entfernen")', { timeout: 30000 });
  check((await toasts()).includes('Entsperren mit dem Gerät eingerichtet'), 'set up with Windows Hello & co. (virtual platform authenticator with PRF)');
  const lock1 = await local('deviceLock');
  const [c1] = await creds(A);
  check(c1 && c1.rpId === `chrome-extension://${extId}`, `the passkey belongs to the extension itself (rpId ${c1?.rpId})`);
  check(lock1?.credentialId === c1?.credentialId && Buffer.from(lock1.prfSalt, 'base64').length === 32 && !!lock1.publicKey && !!lock1.privateKey,
    'stored: credential ID, PRF salt, public key, encrypted private key');
  check(!('prf' in lock1) && Object.keys(lock1).sort().join() === 'credentialId,iv,kind,prfSalt,privateKey,publicKey,transports,v', `nothing else stored (${Object.keys(lock1).join(', ')})`);
  check((await msg('state')).device?.configured === true, 'state: device unlock configured');

  // lock and unlock with the device
  await backToList();
  await lockAll();
  await page.waitForSelector('#device-unlock-btn');
  check(await page.isVisible('#device-label') && await page.isHidden('#pin-unlock') && !!(await session('deviceSealed')), 'locked: "Mit Gerät entsperren" offered (no PIN set up)');
  await page.screenshot({ path: join(shots, 'device-unlock-locked.png') });
  const signs = (await creds(A))[0].signCount;
  await page.click('#device-unlock-btn');
  await page.waitForSelector('.item', { timeout: 30000 });
  check((await page.$$('.item')).length === itemCount && await unlockedCount() === 1, `unlocked with the device: all ${itemCount} items back`);
  check((await creds(A))[0].signCount > signs && await page.isHidden('#quick-unlock') && !(await session('deviceSealed')), 'the authenticator was asked; the seal is gone');
  check((await toasts()).includes('1 Konto entsperrt'), 'reports the unlocked account');

  // a PRF output that does not belong to the passkey (only extension pages can send this)
  await lockAll();
  await page.waitForSelector('#device-unlock-btn');
  const wrong = await msg('unlockWithDevice', { prf: Buffer.alloc(32, 9).toString('base64') }).then(() => 'opened', (x) => x.message);
  check(/nicht den passenden Schlüssel/.test(wrong) && !!(await session('deviceSealed')), `foreign PRF output rejected, seal kept (${wrong.split('\n')[0]})`);
  await page.click('#device-unlock-btn');
  await page.waitForSelector('.item', { timeout: 30000 }).catch(async (x) => { throw new Error(`${x.message}: ${await page.textContent('#device-error')}`); });
  check(await unlockedCount() === 1, 'then the device itself opens it');

  // PIN and device side by side: both offered, the device opens both seals
  await msg('setPin', { pin: '2468' });
  await page.reload();
  await recordToasts();
  await page.waitForSelector('.item');
  await lockAll();
  await page.waitForSelector('#pin-unlock:not([hidden])');
  check(await deviceButton() && await page.isHidden('#device-label') && await page.$eval('#device-unlock-btn', (b) => b.classList.contains('secondary')),
    'PIN and device: PIN form, device button below it');
  check(!!(await session('pinSealed')) && !!(await session('deviceSealed')), 'both seals made when locking');
  await page.screenshot({ path: join(shots, 'device-unlock-with-pin.png') });
  await page.click('#device-unlock-btn');
  await page.waitForSelector('.item', { timeout: 30000 });
  check(!(await session('pinSealed')) && !(await session('deviceSealed')) && await page.isHidden('#pin-unlock'), 'unlocking with the device removes the PIN seal too');

  // user verification fails or is cancelled (the same error from the browser): still locked, seal kept, the PIN
  // still works. The browser and the device count the failures – OmniVault has no counter of its own here.
  await lockAll();
  await cdpPage.send('WebAuthn.setUserVerified', { authenticatorId: A, isUserVerified: false });
  await page.click('#device-unlock-btn');
  await page.waitForSelector('#device-error:not([hidden])', { timeout: 30000 });
  check(/Abgebrochen, abgelaufen oder vom Gerät abgelehnt/.test(await page.textContent('#device-error')), `verification failed or cancelled: ${await page.textContent('#device-error')}`);
  check(await unlockedCount() === 0 && !!(await session('deviceSealed')) && await deviceButton(), 'still locked, seal kept, device offered again');
  await page.fill('#pin-input', '2468');
  await page.click('#pin-submit');
  await page.waitForSelector('.item', { timeout: 30000 });

  // another platform authenticator (does not know the passkey): error, still locked
  await lockAll();
  await cdpPage.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: A });
  const other = await addAuth();
  await page.click('#device-unlock-btn');
  await page.waitForSelector('#device-error:not([hidden])', { timeout: 30000 });
  check(await unlockedCount() === 0 && !!(await session('deviceSealed')), `wrong authenticator: still locked (${await page.textContent('#device-error')})`);
  await page.fill('#pin-input', '2468');
  await page.click('#pin-submit');
  await page.waitForSelector('.item', { timeout: 30000 });

  // set up another device: a security key; the old passkey is replaced
  await cdpPage.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: other });
  const B = await addAuth({ transport: 'usb', hasResidentKey: false });
  await openSettings();
  await page.click('#device-setting button:has-text("Anderes Gerät einrichten")');
  await until(async () => (await local('deviceLock'))?.credentialId !== lock1.credentialId, 'second device set up', 30000);
  const lock2 = await local('deviceLock');
  check(lock2.credentialId === (await creds(B))[0]?.credentialId, `security key set up instead (transports: ${lock2.transports.join(', ')})`);
  check((await creds(B))[0]?.signCount === 1, 'the key evaluates PRF only when signing in: asked a second time during setup');
  await backToList();
  await lockAll();
  await page.waitForSelector('#device-unlock-btn');
  await page.click('#device-unlock-btn');
  await page.waitForSelector('.item', { timeout: 30000 });
  check(await unlockedCount() === 1, 'unlocked with the security key');

  // remove
  await openSettings();
  await page.click('#device-setting button:has-text("Gerät entfernen")');
  await page.waitForSelector('#device-setting button:has-text("Entsperren mit dem Gerät einrichten")');
  check(!(await local('deviceLock')) && (await toasts()).includes('Entsperren mit dem Gerät entfernt'), 'removed: nothing stored any more');
  await backToList();
  await lockAll();
  await page.waitForSelector('#pin-unlock:not([hidden])');
  check(!(await deviceButton()) && !(await session('deviceSealed')), 'removed: only the PIN is offered');
  await page.fill('#pin-input', '2468');
  await page.click('#pin-submit');
  await page.waitForSelector('.item', { timeout: 30000 });

  // an authenticator without PRF: explained, not set up, not offered
  await cdpPage.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: B });
  await addAuth({ hasPrf: false });
  await openSettings();
  await page.click('#device-setting button:has-text("Entsperren mit dem Gerät einrichten")');
  await page.waitForSelector('#dialog[open]', { timeout: 30000 });
  check(/unterstützt die nötige Passkey-Erweiterung \(PRF\) nicht/.test(await page.textContent('#dialog-text')), `without PRF: ${await page.textContent('#dialog-text')}`);
  await page.click('#dialog-ok');
  check(!(await local('deviceLock')) && !(await msg('state')).device.configured, 'without PRF: nothing set up');
  await backToList();
  await lockAll();
  await page.waitForSelector('#pin-unlock:not([hidden])');
  check(!(await deviceButton()), 'without PRF: device unlock not offered on the lock screen');
  await msg('removePin');
  check(!errors.length, `no script errors on the page (${errors.join(' | ')})`);
  await page.close();

  /* ---------- 2. from the real toolbar popup: the device window ---------- */
  const site = await ctx.newPage();
  await site.goto(`${ORIGIN}/login.html`);
  await site.bringToFront();
  await swCall('login', { id: acc.id, credentials: { password: PASSWORD } });
  let p = await openToolbarPopup(ctx, sw, DEBUG_PORT);
  await p.waitFor(`!!document.querySelector('.item')`, 20000);
  await p.click('#btn-settings');
  await p.waitFor(`!!document.querySelector('#device-setting button')`);
  deviceWindowAuth = {};
  const before = deviceWindows.length;
  await p.click('#device-setting button', 'Entsperren mit dem Gerät einrichten');
  await until(async () => deviceWindows.length > before, 'device window opened');
  check(deviceWindows.at(-1).url.endsWith('/device.html?do=setup'), 'toolbar popup: setup runs in a window of its own (with its own authenticator)');
  await until(async () => !!(await swGet('local', 'deviceLock')), 'set up in the device window', 30000);
  await until(async () => !(await swGet('session', 'deviceWindow')), 'device window done');
  await sleep(300);
  check(!ctx.pages().some((x) => x.url().includes('/device.html')), 'device window closed afterwards');
  p = await attachTarget(DEBUG_PORT, (t) => t.url.endsWith('/popup.html'), 'reopened popup');
  await p.waitFor(`!!document.querySelector('#device-setting button')`, 20000);
  const back = await p.evaluate(`({ remove: [...document.querySelectorAll('#device-setting button')].some((b) => b.textContent.includes('Gerät entfernen')), toast: document.querySelector('#toast').textContent })`);
  check(back.remove && back.toast === 'Entsperren mit dem Gerät eingerichtet', `popup reopened in the settings: ${JSON.stringify(back)}`);

  // lock, then unlock from the popup with an authenticator that does not know the passkey; cancel there
  await p.click('#btn-lock-all');
  await p.waitFor(`!document.querySelector('#device-unlock').hidden`, 20000);
  deviceWindowAuth = {};
  const before2 = deviceWindows.length;
  await p.click('#device-unlock-btn');
  await until(async () => deviceWindows.length > before2, 'device window opened for unlocking');
  const win = await until(async () => ctx.pages().find((x) => x.url().includes('/device.html?do=unlock')), 'device window page');
  await win.waitForSelector('#device-error:not([hidden])', { timeout: 30000 });
  check(await win.isVisible('#device-retry') && /Abgebrochen|abgelehnt/.test(await win.textContent('#device-error')) && await win.isVisible('#device-title'),
    `device window: error and "Erneut versuchen" (${await win.textContent('#device-error')})`);
  await win.screenshot({ path: join(shots, 'device-window-error.png') });
  await win.click('#device-cancel');
  await until(async () => !ctx.pages().some((x) => x.url().includes('/device.html')), 'device window closed after cancelling');
  p = await attachTarget(DEBUG_PORT, (t) => t.url.endsWith('/popup.html'), 'popup after cancelling');
  await p.waitFor(`!document.querySelector('#device-unlock').hidden`, 20000);
  check(!!(await swGet('session', 'deviceSealed')), 'cancelled in the device window: popup back, still locked, seal kept');
} catch (e) {
  check(false, e.stack);
} finally {
  browserWs.close();
  await ctx.close();
  closeServers();
}

/** A message to the background from a short-lived extension page (the test's own page is closed by then). */
async function swCall(type, payload) {
  const pg = await ctx.newPage();
  try {
    await pg.goto(`chrome-extension://${extId}/popup.html?window=1`);
    return await pg.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => { if (!r.ok) throw new Error(r.error); return r.result; }), [type, payload]);
  } finally { await pg.close(); }
}
async function swGet(area, key) {
  return sw.evaluate(([a, k]) => chrome.storage[a].get(k).then((r) => r[k] ?? null), [area, key]);
}

console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
