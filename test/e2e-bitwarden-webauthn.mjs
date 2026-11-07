// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test: a security key (FIDO2/WebAuthn) as second factor of a Bitwarden account (experimental), against a real
// Vaultwarden (DOMAIN http://localhost:<port>, so the relying party is "localhost"). The key is registered on the
// server like a web vault would do it (independent of the code under test), with a virtual authenticator over CDP.
// OmniVault opens a tab of the web vault, shows its box there, asks the authenticator and signs in.
// Covered: cancel in the box, an authenticator that does not know the key (error, then retry), no box on another
// origin in the same tab, the toolbar-free popup (as a tab) continuing after the tab closed, nothing left behind.
// Usage: VAULTWARDEN_URL=http://localhost:8800 node test/e2e-bitwarden-webauthn.mjs [path-to-playwright]
import { deriveMasterKey, masterPasswordHash } from '../src/providers/bitwarden/crypto.js';
import { extensionCopy, launch } from './servers.mjs';
import { seedVaultwarden } from './vaultwarden-seed.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const { chromium } = await import(pwPath);
const server = process.env.VAULTWARDEN_URL ?? 'http://localhost:8800';
if (new URL(server).hostname !== 'localhost') throw new Error('VAULTWARDEN_URL must use localhost (the WebAuthn relying party)');
const other = server.replace('//localhost', '//127.0.0.1'); // same server, another origin

let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, what, timeout = 15_000) => {
  const end = Date.now() + timeout;
  for (;;) {
    const v = await fn().catch(() => null);
    if (v) return v;
    if (Date.now() > end) throw new Error(`Timeout: ${what}`);
    await sleep(100);
  }
};
const AUTH = { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: false, automaticPresenceSimulation: true };

const user = await seedVaultwarden(server, { withOrg: false });
const hash = await masterPasswordHash(await deriveMasterKey(user.password, user.email, user.kdf), user.password);
// 127.0.0.1 too, so the origin check (not a missing permission) keeps the box away from the other origin
const ext = await extensionCopy({ hosts: ['http://127.0.0.1/*'] });
const { ctx, sw, extId } = await launch(chromium, ext);
const flows = () => sw.evaluate(async () => (await chrome.storage.session.get('loginFlows')).loginFlows ?? {});

try {
  /* ---------- register the security key, as the web vault would (not OmniVault's code) ---------- */
  const reg = await ctx.newPage();
  await reg.goto(`${server}/webauthn-connector.html`);
  const regCdp = await ctx.newCDPSession(reg);
  await regCdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId: regAuth } = await regCdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTH });
  const { userVerificationToken } = await user.api('POST', '/two-factor/get-webauthn', { masterPasswordHash: hash });
  const { options } = await user.api('POST', '/two-factor/get-webauthn-challenge', { userVerificationToken });
  const deviceResponse = await reg.evaluate(async (o) => {
    const d = (x) => Uint8Array.from(atob(x.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
    const e = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const c = await navigator.credentials.create({ publicKey: {
      rp: o.rp, user: { ...o.user, id: d(o.user.id) }, challenge: d(o.challenge), pubKeyCredParams: o.pubKeyCredParams,
      timeout: o.timeout, attestation: o.attestation, authenticatorSelection: o.authenticatorSelection,
      excludeCredentials: (o.excludeCredentials ?? []).map((x) => ({ type: x.type, id: d(x.id) })),
    } });
    return { id: c.id, rawId: e(c.rawId), type: c.type, extensions: {}, response: { attestationObject: e(c.response.attestationObject), clientDataJson: e(c.response.clientDataJSON) } };
  }, options);
  const enabled = await user.api('POST', '/two-factor/webauthn', { id: 1, name: 'Testschlüssel', deviceResponse, userVerificationToken });
  check(enabled.webAuthn?.enabled ?? enabled.enabled, 'Vaultwarden: security key registered as second factor');
  const { credentials: [credential] } = await regCdp.send('WebAuthn.getCredentials', { authenticatorId: regAuth });
  await reg.close();

  /** Virtual authenticator for the web vault tab OmniVault opens; `known`: it holds the registered key. */
  const authenticator = async (tab, known) => {
    const cdp = await ctx.newCDPSession(tab);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: AUTH });
    if (known) await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
    return { cdp, authenticatorId };
  };
  const vaultTab = () => until(async () => ctx.pages().find((pg) => pg.url().startsWith(`${server}/webauthn-connector.html`)), 'web vault tab');
  const boxShown = (tab) => tab.evaluate(() => !!document.querySelector('omnivault-webauthn')).catch(() => false);
  /** The box lives in a closed shadow root; its "Sicherheitsschlüssel verwenden" button has the focus. */
  const pressStart = async (tab) => { await tab.bringToFront(); await tab.keyboard.press('Enter'); };
  const pressCancel = async (tab) => { await tab.bringToFront(); await tab.keyboard.press('Shift+Tab'); await tab.keyboard.press('Enter'); };

  /* ---------- account, unlock ---------- */
  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.setViewportSize({ width: 380, height: 560 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector('#empty:not([hidden])');
  await popup.click('#btn-new');
  await popup.click('#menu [role=menuitem]:has-text("Konto hinzufügen")');
  await popup.waitForSelector('#view-account:not([hidden])');
  await popup.selectOption('#acc-provider', 'bitwarden');
  await popup.selectOption('#acc-fields select[name=server]', '__custom');
  await popup.fill('input[name=server__custom]', server);
  await popup.fill('#acc-fields input[name=email]', user.email);
  await popup.fill('#form-account input[name=label]', 'Schlüssel');
  await popup.click('#acc-submit');
  await popup.waitForSelector('#view-unlock:not([hidden])');
  const unlock = async () => {
    await popup.bringToFront();
    await popup.fill('#form-unlock input[name=password]', user.password);
    await popup.click('#unlock-submit');
  };

  /* 1. cancel in the box */
  await unlock();
  let tab = await vaultTab();
  check(true, 'only a security key set up: the web vault opens in a tab right away');
  await until(() => boxShown(tab), 'box in the web vault tab');
  check(true, "OmniVault's box shown in the web vault tab");
  const f1 = Object.values(await flows())[0];
  check(f1?.kind === 'webauthn' && f1.request?.rpId === 'localhost' && !f1.request.appid && f1.origin === new URL(server).origin,
    `background waits for the key (rpId ${f1?.request?.rpId}, no AppID over http, origin ${f1?.origin})`);
  await popup.waitForSelector('#unlock-browser:not([hidden])');
  check((await popup.textContent('#unlock-browser-text')).includes('Sicherheitsschlüssel'), 'popup: waiting for the security key in the tab');
  await pressCancel(tab);
  await until(async () => tab.isClosed(), 'tab closed after cancel');
  await popup.waitForSelector('#unlock-error:not([hidden])');
  check((await popup.textContent('#unlock-error')).includes('abgebrochen'), `cancel reported: "${await popup.textContent('#unlock-error')}"`);

  /* 2. another origin in the same tab gets no box; an unknown authenticator fails, the right one succeeds on retry */
  await unlock();
  tab = await vaultTab();
  await until(() => boxShown(tab), 'box again');
  await tab.goto(`${other}/webauthn-connector.html`);
  await sleep(800);
  check(!await boxShown(tab), 'no box after the tab moved to another origin');
  await tab.goto(`${server}/webauthn-connector.html`);
  await until(() => boxShown(tab), 'box back on the web vault origin');
  check(true, 'box shown again once the tab is back on the web vault');
  const auth = await authenticator(tab, false);
  await pressStart(tab);
  await sleep(1500);
  check(!tab.isClosed() && await boxShown(tab), 'authenticator without the key: the tab stays, the box offers a retry');
  check(Object.values(await flows())[0]?.phase === 'browser', 'background still waits');
  await auth.cdp.send('WebAuthn.addCredential', { authenticatorId: auth.authenticatorId, credential });
  await pressStart(tab);
  await until(async () => tab.isClosed(), 'tab closed after the key answered', 20_000);
  check(true, 'the tab closes once the key answered');
  await popup.bringToFront();
  await popup.waitForSelector('#view-main:not([hidden]) .item', { timeout: 30_000 });
  check(await popup.evaluate(() => [...document.querySelectorAll('#items .item')].some((li) => li.textContent.includes('GitHub'))), 'signed in with the security key: items listed');
  const left = await until(async () => (Object.keys(await flows()).length ? null : 'empty'), 'login state cleared', 5000).catch(async () => JSON.stringify(await flows()));
  check(left === 'empty', `nothing of the login left behind (${left})`);
  check(!errors.length, `no page errors (${errors.join('; ')})`);
} catch (e) {
  console.log(`FAIL ${e.stack ?? e}`);
  failures++;
} finally {
  await ctx.close();
}
console.log(failures ? `\n${failures} failure(s)` : '\nall checks passed');
process.exit(failures ? 1 : 0);
