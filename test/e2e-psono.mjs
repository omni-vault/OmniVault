// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test against a REAL Psono server (test/psono-server.sh start): add an account in the popup, sign in with
// the authenticator app as second factor, list the entries (own and shared folders), fill a login form, edit an entry
// (checked on the server), delete it and restore it from the trash, lock (the server session ends).
// Usage: PSONO_URL=http://127.0.0.1:8935 node test/e2e-psono.mjs [path-to-playwright] [screenshot-dir]
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import PsonoProvider from '../src/providers/psono/index.js';
import { request } from '../src/providers/psono/api.js';
import { totp } from '../src/lib/totp.js';
import { readDatastore, readSecret, seedPsono } from './psono-seed.mjs';
import { LOGIN_PAGE, extensionCopy, launch } from './servers.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const BASE = process.env.PSONO_URL ?? 'http://127.0.0.1:8935';
const { chromium } = await import(pwPath);

const site = createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(LOGIN_PAGE); });
await new Promise((r) => site.listen(Number(process.env.SITE_PORT ?? 0), '127.0.0.1', r));
const SITE_PORT = site.address().port;
const seed = await seedPsono(BASE);

// the account with the second factor gets a login for this page (written through the provider, as the popup would)
async function signInNode() {
  const config = { id: 'seed', server: BASE, username: seed.mfa };
  const first = await PsonoProvider.login(config, { password: seed.password });
  const r = await PsonoProvider.login({ ...config, ...first.configPatch }, { pending: first.pending, twoFactorProvider: 'google_authenticator_2fa', twoFactorCode: (await totp(seed.gaSecret)).code });
  return { config: { ...config, ...first.configPatch }, session: r.session };
}
{
  const { config, session } = await signInNode();
  await PsonoProvider.saveItem(config, session, null, {
    type: 'login', name: 'Shop', username: 'kunde', password: 'shop-geheim', uris: [`http://localhost:${SITE_PORT}/login.html`], totp: '', notes: 'Kundennr. 7', folderId: null,
    fields: [{ name: 'PIN', value: '4711', type: 'hidden' }],
  });
  await PsonoProvider.logout(config, session);
}

const ext = await extensionCopy({ hosts: ['http://127.0.0.1/*'] });
const { ctx, extId } = await launch(chromium, ext);
let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };

try {
  const page = await ctx.newPage();
  await page.goto(`http://localhost:${SITE_PORT}/login.html`);
  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.setViewportSize({ width: 380, height: 560 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector('#empty:not([hidden])');
  const msg = (type, payload = {}) => popup.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => r.result), [type, payload]);

  // add the account
  await popup.click('#btn-new');
  await popup.click('#menu [role=menuitem]:has-text("Konto hinzufügen")');
  await popup.selectOption('#acc-provider', 'psono');
  check(/Psono-Server/.test(await popup.textContent('#form-account')), 'provider note shown');
  await popup.fill('#acc-fields input[name=server]', BASE);
  await popup.fill('#acc-fields input[name=username]', seed.mfa);
  await popup.fill('#form-account input[name=label]', 'Psono echt');
  await popup.screenshot({ path: join(shots, 'psono-account.png') });
  await popup.click('#acc-submit');
  await popup.waitForSelector('#view-unlock:not([hidden])');
  await popup.fill('#form-unlock input[name=password]', seed.password);
  await popup.click('#unlock-submit');

  // second factor
  await popup.waitForSelector('#unlock-2fa:not([hidden])');
  const options = await popup.$$eval('#form-unlock select[name=twoFactorProvider] option', (o) => o.map((x) => x.textContent));
  check(options.length === 1 && /TOTP/.test(options[0]), `second factor offered: ${options.join(', ')}`);
  await popup.fill('#form-unlock input[name=twoFactorCode]', '000000');
  await popup.click('#unlock-submit');
  await popup.waitForSelector('#unlock-error:not([hidden])');
  check(/Code falsch/.test(await popup.textContent('#unlock-error')), `wrong code reported (${await popup.textContent('#unlock-error')})`);
  await popup.screenshot({ path: join(shots, 'psono-2fa.png') });
  await popup.fill('#form-unlock input[name=twoFactorCode]', (await totp(seed.gaSecret)).code);
  await popup.click('#unlock-submit');
  await popup.waitForSelector('#view-main:not([hidden])');
  await popup.waitForSelector('#accounts .chip:not(.locked)');
  await popup.waitForFunction(() => document.querySelectorAll('.item').length >= 1);
  check((await popup.$$eval('.item .name', (n) => n.map((x) => x.textContent))).includes('Shop'), 'entry listed after the second factor');

  // fill the login tab
  const items = await msg('items', { tabUrl: `http://localhost:${SITE_PORT}/login.html` });
  const shop = items.find((i) => i.name === 'Shop');
  check(shop?.matches && !('password' in shop), 'entry matches the page, no password in the list');
  const filled = await popup.evaluate(async ([accountId, itemId, port]) => {
    const [tab] = await chrome.tabs.query({ url: `http://localhost:${port}/*` });
    return chrome.runtime.sendMessage({ type: 'fill', accountId, itemId, tabId: tab.id });
  }, [shop.accountId, shop.id, SITE_PORT]);
  check(filled.ok, `fill reported ${JSON.stringify(filled)}`);
  check(await page.inputValue('#u') === 'kunde' && await page.inputValue('#p') === 'shop-geheim', 'login form filled');

  // detail and edit
  await popup.click('.item:has(.name:text-is("Shop"))');
  await popup.waitForSelector('#view-item:not([hidden]) h2:has-text("Shop")');
  const detail = await popup.textContent('#view-item');
  check(detail.includes('PIN') && detail.includes('Kundennr. 7'), 'detail: custom field and notes');
  await popup.screenshot({ path: join(shots, 'psono-detail.png') });
  await popup.click('#view-item button:has-text("Bearbeiten")');
  await popup.fill('#view-edit input[name=password]', 'shop-neu');
  await popup.click('#view-edit button[type=submit]');
  await popup.waitForSelector('#view-item:not([hidden]) h2:has-text("Shop")');
  {
    const { config, session } = await signInNode();
    const call = (path, opts = {}) => request(session.base, path, { ...opts, session });
    const ds = await readDatastore(call, session);
    const node = ds.tree.items.find((i) => i.name === 'Shop');
    const c = await readSecret(call, node);
    check(c.website_password_password === 'shop-neu' && c.website_password_username === 'kunde' && c.custom_fields?.[0]?.value === '4711',
      'edit written to the server, other values kept');
    await PsonoProvider.logout(config, session);
  }

  // delete → trash → restore
  await popup.click('#view-item button:has-text("Löschen")');
  check(/Papierkorb/.test(await popup.textContent('#dialog')), 'delete asks with the trash hint');
  await popup.click('#dialog-ok');
  await popup.waitForSelector('#view-main:not([hidden])');
  await popup.click('#btn-tools');
  await popup.click('#view-tools .tabs button:has-text("Papierkorb")');
  await popup.waitForSelector('#view-tools .pick:has-text("Shop")');
  await popup.check('#view-tools .pick:has-text("Shop") input[type=checkbox]');
  await popup.click('#view-tools button:has-text("Wiederherstellen")');
  await popup.waitForFunction(() => /wiederhergestellt/.test(document.querySelector('#toast')?.textContent || ''), null, { timeout: 20000 });
  check((await msg('items', { tabUrl: `http://localhost:${SITE_PORT}/login.html` })).some((i) => i.name === 'Shop'), 'restored');

  // lock: the server session ends
  const acc = (await msg('state')).accounts.find((a) => a.provider === 'psono');
  const session = await popup.evaluate((id) => chrome.storage.session.get(`session:${id}`).then((r) => r[`session:${id}`] ?? null), acc.id);
  await msg('lock', { id: acc.id });
  if (session?.token) {
    await new Promise((r) => setTimeout(r, 500));
    const ended = await request(session.base, 'datastore/', { session }).then(() => false, (e) => e.code === 'session_expired');
    check(ended, 'token ended on the server after locking');
  } else console.log('note: session storage key not found; logout not checked here (covered by psono-real.test.js)');
  check(errors.length === 0, `no script errors (${errors.join('; ')})`);
} catch (e) {
  failures++;
  console.log('FAIL', e.message);
} finally {
  await ctx.close();
  site.close();
}
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
