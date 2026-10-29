// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// SPIKE (feasibility study, not part of the test suite): keeps a Passbolt JWT session with a TOTP proof alive in a
// real browser through /auth/jwt/refresh, reading the rotated refresh token from the cookie jar (cookies permission).
// Needs a real Passbolt CE (test/passbolt-server.sh) with a short access token lifetime and a user with TOTP:
//   PASSBOLT_AUTH_JWT_ACCESS_TOKEN='40 seconds' test/passbolt-server.sh start   (fullBaseUrl http://localhost:PORT)
//   SEED=seed.json (users from test/passbolt-seed.mjs, TOTP secret JBSWY3DPEHPK3PXP for bob)
//   node test/spike-passbolt-mfa-refresh.mjs chrome|firefox [rounds=3] [wait-seconds=45]
// Env: PB=http://localhost:8930 (or an https front with a self-signed certificate), CHROME_3PC_BLOCK=1 (Chrome with third-party cookies blocked),
//      FF_COOKIE_BEHAVIOR=0..5 (Firefox network.cookie.cookieBehavior), FIREFOX_BIN.
import { cp, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as openpgp from '../vendor/openpgp.mjs';
import { totp } from '../src/lib/totp.js';

const [browser = 'chrome', roundsArg = '3', waitArg = '45'] = process.argv.slice(2);
const ROUNDS = Number(roundsArg), WAIT = Number(waitArg) * 1000;
const PB = process.env.PB ?? 'http://localhost:8930';
const SECRET = 'JBSWY3DPEHPK3PXP';
const seed = JSON.parse(await readFile(process.env.SEED, 'utf8'));
const bob = seed.bob;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const t0 = Date.now();
const log = (...a) => console.log(`[${((Date.now() - t0) / 1000).toFixed(0).padStart(4)}s]`, ...a);
let failures = 0;
/** A TOTP code that stays valid for a few more seconds (Passbolt verifies without leeway). */
async function code() {
  let c = await totp(SECRET);
  if (c.remaining < 4) { await sleep(c.remaining * 1000 + 500); c = await totp(SECRET); }
  return c.code;
}
const check = (ok, what, detail) => { if (!ok) failures++; log(ok ? 'OK  ' : 'FAIL', what, detail === undefined ? '' : JSON.stringify(detail)); };

/** GPG challenge login in Node (the browser part only needs the resulting tokens). */
async function challengeLogin() {
  const key = await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: bob.privateKey }), passphrase: bob.passphrase });
  const verify = await (await fetch(`${PB}/auth/verify.json`)).json();
  const serverKey = await openpgp.readKey({ armoredKey: verify.body.keydata });
  const vt = crypto.randomUUID();
  const challenge = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: JSON.stringify({ version: '1.0.0', domain: PB, verify_token: vt, verify_token_expiry: Math.floor(Date.now() / 1000) + 120 }) }),
    encryptionKeys: serverKey, signingKeys: key,
  });
  const res = await (await fetch(`${PB}/auth/jwt/login.json`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify({ user_id: bob.userId, challenge }) })).json();
  const answer = JSON.parse((await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: res.body.challenge }), decryptionKeys: key })).data);
  return { at: answer.access_token, rt: answer.refresh_token, providers: answer.providers };
}

// ---- browser with the spike extension ----
const ext = await mkdtemp(join(tmpdir(), 'pb-spike-ext-'));
await cp(new URL('./fixtures/passbolt-refresh-ext', import.meta.url).pathname, ext, { recursive: true });
const manifest = {
  manifest_version: 3, name: 'Passbolt refresh spike', version: '0.0.1',
  permissions: ['storage', 'cookies'],
  // Firefox ignores host permissions with a port (fetch fails with NetworkError), so name the host without one too
  host_permissions: [`${PB}/*`, ...(browser === 'firefox' ? [`${new URL(PB).protocol}//${new URL(PB).hostname}/*`] : [])],
  background: browser === 'firefox' ? { scripts: ['bg.js'] } : { service_worker: 'bg.js' },
  ...(browser === 'firefox' ? { browser_specific_settings: { gecko: { id: 'pb-spike@omnivault.test' } } } : {}),
};
await writeFile(join(ext, 'manifest.json'), JSON.stringify(manifest));

let call, restartBackground, close;
if (browser === 'chrome') {
  const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');
  const profile = await mkdtemp(join(tmpdir(), 'pb-spike-chrome-'));
  const ctx = await chromium.launchPersistentContext(profile, {
    channel: 'chromium', headless: !process.env.DISPLAY, ignoreHTTPSErrors: true, // self-signed TLS front
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--ignore-certificate-errors',
      ...(process.env.CHROME_3PC_BLOCK ? ['--test-third-party-cookie-phaseout'] : [])],
  });
  if (process.env.CHROME_3PC_BLOCK) {
    // also the explicit user setting "Block third-party cookies"
    const set = await ctx.newPage(); await set.goto('chrome://settings/cookies');
    await set.evaluate(() => chrome.settingsPrivate?.setPref?.('profile.cookie_controls_mode', 1)).catch(() => {});
    await set.close();
  }
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker');
  const id = new URL(sw.url()).host;
  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${id}/page.html`);
  call = async (name, ...args) => {
    const r = await page.evaluate((m) => chrome.runtime.sendMessage(m), { name, args });
    if (r?.error) throw new Error(`${name}: ${r.error}`);
    return r?.ok;
  };
  restartBackground = async () => {
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');
    await sleep(500);
    return ctx.serviceWorkers().length; // 0 = stopped, the next message starts it again
  };
  close = () => ctx.close();
} else {
  const { launchFirefox, Tab } = await import('./firefox-bidi.mjs');
  const UUID = '6f6d6e69-7661-4f75-8c74-0000000000aa';
  const prefs = process.env.FF_COOKIE_BEHAVIOR ? { 'network.cookie.cookieBehavior': Number(process.env.FF_COOKIE_BEHAVIOR) } : {};
  const ff = await launchFirefox({ addonId: 'pb-spike@omnivault.test', uuid: UUID, headless: !process.env.DISPLAY, prefs });
  await ff.send('webExtension.install', { extensionData: { type: 'path', path: ext } });
  log('Firefox cookieBehavior', await ff.chrome("Services.prefs.getIntPref('network.cookie.cookieBehavior')"));
  const tab = await Tab.open(ff, `moz-extension://${UUID}/page.html`);
  call = async (name, ...args) => {
    const r = await tab.$eval((m) => browser.runtime.sendMessage(m), { name, args });
    if (r?.error) throw new Error(`${name}: ${r.error}`);
    return r?.ok;
  };
  restartBackground = null; // no reliable way to force an event page suspension from outside
  close = () => ff.close();
}

let crashed = null;
try {
  log('browser', browser, 'permissions', await call('permissions', PB));
  // 1. challenge login + TOTP in the browser (passbolt_mfa lands in the browser's cookie jar)
  let { at, rt, providers } = await challengeLogin();
  check(providers?.includes('totp'), 'login asks for TOTP', providers);
  const mfa = await call('mfa', PB, at, await code(), false);
  check(mfa.status === 200, 'TOTP verified from the background script', mfa.message);
  const jar = await call('cookies', PB);
  log('cookie jar after MFA:', JSON.stringify(jar));
  check(!!jar.passbolt_mfa, 'passbolt_mfa stored in the jar (HttpOnly, readable with cookies.get)');
  check((await call('check', PB, at)).status === 200, 'API call with access token + MFA cookie');

  // 2. rounds: wait for expiry, refresh with the token in the body, take the new token from the cookie, delete it
  for (let i = 1; i <= ROUNDS; i++) {
    await sleep(WAIT);
    const expired = await call('check', PB, at);
    log(`round ${i}: old access token ->`, expired.status);
    const r = await call('refreshBody', PB, bob.userId, rt, false);
    check(r.status === 200 && !!r.at, `round ${i}: /auth/jwt/refresh (body) ok`, r.message);
    check(!!r.rt && r.rt !== rt, `round ${i}: new refresh token read from the HttpOnly cookie`, r.cookie);
    check(r.removed === true, `round ${i}: refresh_token cookie deleted from the jar`);
    at = r.at; rt = r.rt;
    const ok = await call('check', PB, at);
    check(ok.status === 200, `round ${i}: MFA still valid with the new access token`, ok.status);
  }
  const stored = await call('session');
  check(stored?.rt === rt, 'token pair kept in storage.session');

  // 3. background restart (Chrome: stop the service worker), then continue from storage.session
  if (restartBackground) {
    await call('mark');
    log('service workers after stop:', await restartBackground());
    check(await call('getMark') === null, 'service worker really restarted (global state gone)');
    const s = await call('session');
    check(s?.rt === rt && s?.at === at, 'storage.session survives a service worker restart');
    const r = await call('refreshBody', PB, bob.userId, s.rt, false);
    check(r.status === 200 && (await call('check', PB, r.at)).status === 200, 'refresh + MFA after the restart');
    at = r.at; rt = r.rt;
  }

  // 4. Passbolt's own way: refresh_token cookie + CSRF header (cookie kept once)
  {
    const r1 = await call('refreshBody', PB, bob.userId, rt, true);
    at = r1.at; rt = r1.rt;
    const r2 = await call('refreshCookie', PB, true);
    log('csrfToken cookie:', JSON.stringify(r2.csrf));
    check(r2.status === 200 && r2.rt && r2.rt !== rt, 'cookie refresh with X-CSRF-Token ok', r2.message);
    if (r2.status === 200) { at = r2.at; rt = r2.rt; }
    check((await call('check', PB, at)).status === 200, 'MFA still valid after cookie refresh');
    const noCsrf = await call('refreshCookie', PB, false);
    log('cookie refresh without X-CSRF-Token ->', noCsrf.status, noCsrf.message);
    check(await call('removeCookie', PB, 'refresh_token'), 'refresh_token cookie removed afterwards');
  }

  // 5. Option A: "remember this device" — survives a new challenge login without TOTP
  {
    const a1 = await challengeLogin();
    const m = await call('mfa', PB, a1.at, await code(), true);
    check(m.status === 200, 'TOTP with remember=1', m.message);
    const c = (await call('cookies', PB)).passbolt_mfa;
    log('passbolt_mfa (remember):', JSON.stringify(c));
    const a2 = await challengeLogin();
    const ok = await call('check', PB, a2.at);
    check(ok.status === 200, 'option A: new challenge login is accepted without TOTP (cookie sent by the extension)', ok.status);
  }
} catch (e) {
  crashed = e;
  log('ABORTED', e.message);
} finally {
  log(crashed || failures ? `${failures} FAILED${crashed ? ', aborted' : ''}` : 'all checks passed');
  await close();
}
process.exit(failures || crashed ? 1 : 0);
