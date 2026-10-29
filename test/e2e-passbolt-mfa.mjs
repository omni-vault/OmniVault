// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Passbolt account with a second factor (TOTP) against a REAL Passbolt, in Chromium and Firefox: OmniVault stays
// signed in through several renewals of the access token (/auth/jwt/refresh with the optional cookies permission),
// also with requests in parallel to a renewal and (Chromium) after the service worker was stopped; the refresh
// cookie never stays in the browser, no refresh token is used twice (Passbolt would e-mail an attack warning), and
// "remember for 30 days" signs in again without the code when the cookies permission is gone.
//
// The server needs an https address (the refresh cookie is always Secure) and short-lived access tokens; this test
// puts a TLS front with a self-signed certificate before it. `npm run test:passbolt-mfa` starts everything:
//   PB_PORT=8930 PB_PG_PORT=5463 PB_DIR=/tmp/omnivault-passbolt-mfa PB_BASE_URL=https://localhost:8932 \
//   PASSBOLT_AUTH_JWT_ACCESS_TOKEN='30 seconds' test/passbolt-server.sh start
//   PASSBOLT_URL=http://127.0.0.1:8930 PASSBOLT_HTTPS=https://localhost:8932 FIREFOX_BIN=… \
//     node test/e2e-passbolt-mfa.mjs [chrome|firefox|both] [path-to-playwright]
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { cp, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { totp } from '../src/lib/totp.js';
import PassboltProvider from '../src/providers/passbolt/index.js';
import { seedPassbolt } from './passbolt-seed.mjs';
import { extensionCopy, launch } from './servers.mjs';

const which = process.argv[2] ?? 'both';
const pwPath = process.argv[3] ?? 'playwright';
const BACKEND = new URL(process.env.PASSBOLT_URL ?? 'http://127.0.0.1:8930');
const PB = process.env.PASSBOLT_HTTPS ?? 'https://localhost:8932';
const PB_URL = new URL(PB);
const PG_PORT = process.env.PB_PG_PORT ?? '5463';
const SECRET = 'JBSWY3DPEHPK3PXP';
const OTP_URI = `otpauth://totp/OmniVault%20test:bob%40passbolt.test?issuer=OmniVault%20test&secret=${SECRET}`;
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const t0 = Date.now();
const stamp = () => `[${String(Math.round((Date.now() - t0) / 1000)).padStart(4)}s]`;
let failures = 0;
const check = (cond, msg) => { console.log(`${stamp()} ${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };

// ---- TLS front with a throw-away certificate (Node in this process trusts it for seeding) ----
const certDir = mkdtempSync(join(tmpdir(), 'omnivault-pb-tls-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=localhost',
  '-addext', 'subjectAltName=DNS:localhost', '-keyout', join(certDir, 'key.pem'), '-out', join(certDir, 'cert.pem')], { stdio: 'ignore' });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // only this test process, only for the local front
const front = https.createServer({ key: readFileSync(join(certDir, 'key.pem')), cert: readFileSync(join(certDir, 'cert.pem')) }, (req, res) => {
  const up = http.request({ host: BACKEND.hostname, port: BACKEND.port, path: req.url, method: req.method, headers: { ...req.headers, 'x-forwarded-proto': 'https' } },
    (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
  up.on('error', (e) => { res.writeHead(502); res.end(String(e)); });
  req.pipe(up);
});
await new Promise((r) => { front.listen(Number(PB_URL.port), '127.0.0.1', r); });

/** A TOTP code that stays valid for a few more seconds (Passbolt verifies without leeway). */
async function code() {
  let c = await totp(OTP_URI);
  if (c.remaining < 5) { await sleep(c.remaining * 1000 + 600); c = await totp(OTP_URI); }
  return c.code;
}

async function api(path, { method = 'GET', token, body } = {}) {
  const r = await fetch(`${PB}${path}`, { method, headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: body && JSON.stringify(body) });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${j?.header?.message}`);
  return j?.body;
}

/** E-mails Passbolt queued (the Debug transport keeps them in the database). */
function emails() {
  const out = execFileSync('psql', ['-h', '127.0.0.1', '-p', PG_PORT, '-U', 'postgres', '-d', 'passbolt', '-At', '-c',
    'SELECT template || \' | \' || subject FROM email_queue ORDER BY id'], { encoding: 'utf8' });
  return out.split('\n').filter(Boolean);
}

// ---- users: Ada (admin) turns TOTP on for the organization, Bob sets it up ----
const seed = await seedPassbolt(PB);
const adaCfg = { server: PB, userId: seed.ada.userId, privateKey: seed.ada.privateKey };
const ada = (await PassboltProvider.login(adaCfg, { password: seed.ada.passphrase })).session;
await api('/mfa/settings.json?api-version=v2', { method: 'POST', token: ada.accessToken, body: { providers: ['totp'] } });
const bobCfg = { server: PB, userId: seed.bob.userId, privateKey: seed.bob.privateKey };
const bob0 = (await PassboltProvider.login(bobCfg, { password: seed.bob.passphrase })).session;
await api('/mfa/setup/totp.json?api-version=v2', { method: 'POST', token: bob0.accessToken, body: { otpProvisioningUri: OTP_URI, totp: await code() } });
check((await PassboltProvider.login(bobCfg, { password: seed.bob.passphrase })).status === 'needs_2fa', 'Bob signs in with TOTP');
const mailsBefore = emails().length;

/** One browser: `ui` drives the popup page, `ev(fn, arg)` runs in it, `cookie()` reads refresh_token from the jar. */
async function run(name, { ui, ev, refreshCookie, restartWorker }) {
  const msg = (type, payload = {}) => ev(async ([t, p]) => {
    const r = await (globalThis.browser ?? chrome).runtime.sendMessage({ type: t, ...p });
    if (!r.ok) throw new Error(r.error);
    return r.result;
  }, [type, payload]);
  const session = async () => ev(async (id) => {
    const k = `session:${id}`;
    return (await (globalThis.browser ?? chrome).storage.session.get(k))[k] ?? null;
  }, accountId);
  const syncOk = async (what) => {
    const r = await msg('sync', { id: accountId }).catch((e) => ({ error: e.message }));
    check(!r.error, `${name}: ${what} (${r.error ?? 'ok'})`);
    return r;
  };
  /** Waits until the keeper renews before the next request (a quarter of the token lifetime before it expires). */
  const untilDue = async (extra = 300) => {
    const s = await session();
    const due = s.expiresAt - Math.min(30_000, (s.expiresAt - s.obtainedAt) / 4);
    await sleep(Math.max(0, due - Date.now() + extra));
  };

  // connect Bob's account; the second factor step explains the cookies permission
  await ui.waitFor('#empty');
  await ui.click('#btn-new');
  await ui.click('#menu [role=menuitem]', 'Konto hinzufügen');
  await ui.select('#acc-provider', 'passbolt');
  await ui.fill('#acc-fields input[name=server]', PB);
  await ui.fill('#acc-fields input[name=userId]', seed.bob.userId);
  await ui.fill('#acc-fields textarea[name=privateKey]', seed.bob.privateKey);
  await ui.fill('#form-account input[name=label]', 'Passbolt MFA');
  await ui.click('#acc-submit');
  await ui.waitFor('#view-unlock');
  await ui.fill('#form-unlock input[name=password]', seed.bob.passphrase);
  await ui.click('#unlock-submit');
  await ui.waitFor('#unlock-code', { timeout: 30000 });
  check(await ev(() => !document.querySelector('#unlock-pb-cookies').hidden && document.querySelector('#unlock-pb-nocookies').hidden), `${name}: the second factor step explains the cookies permission`);
  const accountId = await ev(async () => (await (globalThis.browser ?? chrome).runtime.sendMessage({ type: 'state' })).result.accounts.find((a) => a.provider === 'passbolt').id);
  await ui.fill('#form-unlock input[name=twoFactorCode]', await code());
  await ui.click('#unlock-submit');
  await ui.waitFor('#accounts .chip:not(.locked)', { timeout: 30000 });
  check(await ev(() => (globalThis.browser ?? chrome).permissions.contains({ permissions: ['cookies'] })), `${name}: cookies permission granted on submitting the code`);
  let s = await session();
  check(s?.mfa === true && !!s.refreshToken && s.gen === 0, `${name}: session with second factor and refresh token (memory only)`);
  const tokens = new Set([s.refreshToken]);

  // three renewals shortly before expiry, then one after the token expired
  for (let round = 1; round <= 3; round++) {
    await untilDue();
    await syncOk(`renewal ${round}: still signed in`);
    s = await session();
    check(s.gen === round && s.refreshToken && !tokens.has(s.refreshToken) && !s.refreshPending, `${name}: renewal ${round}: new refresh token taken from the cookie`);
    tokens.add(s.refreshToken);
    check(!(await refreshCookie()), `${name}: renewal ${round}: refresh_token cookie removed from the browser`);
  }
  await sleep(Math.max(0, s.expiresAt - Date.now() + 2000));
  await syncOk('renewal after the token expired');
  s = await session();
  tokens.add(s.refreshToken);

  // requests in parallel with a renewal: none may carry the old token afterwards
  await untilDue(-400);
  const genBefore = (await session()).gen;
  const parallel = await Promise.all([1, 2, 3, 4].map((i) => sleep(i * 150).then(() => msg('sync', { id: accountId }).catch((e) => ({ error: e.message })))));
  check(parallel.every((r) => !r.error), `${name}: four syncs around a renewal (${parallel.map((r) => r.error ?? 'ok').join(' / ')})`);
  await syncOk('second factor still valid after the parallel renewal');
  s = await session();
  check(s.gen === genBefore + 1, `${name}: one renewal for the four syncs (${s.gen - genBefore}), ${s.gen} renewals so far`);

  if (restartWorker) {
    await untilDue();
    await restartWorker();
    await syncOk('renewal right after the service worker was stopped');
    check((await session()).gen === s.gen + 1, `${name}: renewed from storage.session after the restart`);
  }
  check(!(await refreshCookie()), `${name}: no refresh_token cookie left`);

  // "remember for 30 days": without the cookies permission the challenge sign-in works without the code
  await msg('lock', { id: accountId });
  await ev(() => (globalThis.browser ?? chrome).permissions.remove({ permissions: ['cookies'] }));
  await ui.reload();
  await ui.waitFor('#accounts .chip.locked');
  await ui.click('#accounts .chip.locked');
  await ui.click('#menu [role=menuitem]', 'Entsperren');
  await ui.waitFor('#view-unlock');
  await ui.fill('#form-unlock input[name=password]', seed.bob.passphrase);
  await ui.click('#unlock-submit');
  await ui.waitFor('#unlock-code', { timeout: 30000 });
  await ui.fill('#form-unlock input[name=twoFactorCode]', await code());
  await ui.click('#unlock-pb-mfa input[name=rememberMfa]');
  await ui.click('#unlock-submit');
  await ui.waitFor('#accounts .chip:not(.locked)', { timeout: 30000 });
  await ev(() => (globalThis.browser ?? chrome).permissions.remove({ permissions: ['cookies'] }));
  check(!(await ev(() => (globalThis.browser ?? chrome).permissions.contains({ permissions: ['cookies'] }))), `${name}: cookies permission not held`);
  s = await session();
  check(s.mfaRemembered === true, `${name}: second factor remembered for 30 days`);
  await sleep(Math.max(0, s.expiresAt - Date.now() + 2000));
  await syncOk('remembered: new challenge sign-in after expiry, without the code');
  await msg('lock', { id: accountId });
}

const errors = [];
if (which === 'chrome' || which === 'both') {
  const { chromium } = await import(pwPath);
  const ext = await extensionCopy({ hosts: [`${PB_URL.origin}/*`, `${PB_URL.protocol}//${PB_URL.hostname}/*`] });
  const { ctx, extId } = await launch(chromium, ext, { args: ['--ignore-certificate-errors'] });
  try {
    const page = await ctx.newPage();
    page.on('pageerror', (e) => errors.push(`chrome: ${e.message}`));
    await page.setViewportSize({ width: 380, height: 600 });
    await page.goto(`chrome-extension://${extId}/popup.html`);
    const ui = {
      waitFor: (sel, o = {}) => page.waitForSelector(`${sel}:not([hidden])`, { timeout: o.timeout ?? 10000 }),
      click: (sel, text) => page.click(text ? `${sel}:has-text("${text}")` : sel),
      fill: (sel, v) => page.fill(sel, v),
      select: (sel, v) => page.selectOption(sel, v),
      reload: () => page.reload(),
    };
    await run('Chromium', {
      ui, ev: (fn, arg) => page.evaluate(fn, arg),
      refreshCookie: async () => (await ctx.cookies(PB)).find((c) => c.name === 'refresh_token') ?? null,
      restartWorker: async () => {
        const cdp = await ctx.newCDPSession(page);
        await cdp.send('ServiceWorker.enable');
        await cdp.send('ServiceWorker.stopAllWorkers');
        await sleep(500);
      },
    });
  } catch (e) {
    failures++;
    console.log('FAIL chrome', e.message);
    await ctx.pages().at(-1)?.screenshot({ path: join(tmpdir(), 'passbolt-mfa-chrome-failure.png') }).catch(() => {});
    console.log(await ctx.pages().at(-1)?.evaluate(() => [...document.querySelectorAll('.error:not([hidden]), #toast')].map((e) => e.textContent).join(' | ')).catch(() => ''));
  } finally { await ctx.close(); }
}

if (which === 'firefox' || which === 'both') {
  const { launchFirefox, Tab } = await import('./firefox-bidi.mjs');
  const ADDON = 'omnivault@royaltysoft.works';
  const UUID = '6f6d6e69-7661-4f75-8c74-0000000000b1';
  const ext = await mkdtemp(join(tmpdir(), 'omnivault-ff-'));
  await cp('dist/firefox', ext, { recursive: true });
  const manifest = JSON.parse(await readFile(join(ext, 'manifest.json'), 'utf8'));
  // Firefox: host permissions with a port are not enough for fetch, so name the host without one as well
  manifest.host_permissions.push(`${PB_URL.origin}/*`, `${PB_URL.protocol}//${PB_URL.hostname}/*`);
  await writeFile(join(ext, 'manifest.json'), JSON.stringify(manifest));
  const ff = await launchFirefox({ addonId: ADDON, uuid: UUID, headless: !process.env.DISPLAY });
  try {
    await ff.send('webExtension.install', { extensionData: { type: 'path', path: ext } });
    const tab = await Tab.open(ff, `moz-extension://${UUID}/popup.html`);
    await tab.$eval(() => browser.runtime.sendMessage({ type: 'setSettings', patch: { language: 'de' } }));
    await tab.reload();
    const ui = {
      waitFor: (sel, o = {}) => tab.waitFor(sel, { timeout: o.timeout ?? 10000 }),
      click: (sel, text) => tab.click(sel, text),
      fill: (sel, v) => tab.fill(sel, v),
      select: (sel, v) => tab.select(sel, v),
      reload: () => tab.reload(),
    };
    await run('Firefox', {
      ui, ev: (fn, arg) => (arg === undefined ? tab.$eval(fn) : tab.$eval(fn, arg)),
      refreshCookie: () => tab.$eval((url) => browser.cookies.get({ url, name: 'refresh_token' }).catch(() => null), `${PB}/`),
    });
  } catch (e) {
    failures++;
    console.log('FAIL firefox', e.message);
  } finally { await ff.close(); }
}

const mails = emails().slice(mailsBefore);
check(!mails.some((m) => /attack|security|jwt/i.test(m)), `no security warning e-mails from Passbolt (${mails.length} new: ${mails.join('; ') || 'none'})`);
check(errors.length === 0, `no script errors (${errors.join('; ')})`);
front.close();
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
