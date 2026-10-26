// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test for Tools → Emergency access (as trusted contact, view only). Without VAULTWARDEN_URL against the
// simulated server (Alice is Gerda's contact for viewing, Theo's for takeover); with VAULTWARDEN_URL against a REAL
// Vaultwarden: two seeded accounts, A makes B its emergency contact through the API (invite, accepted at once
// without mail, confirm with B's public key), B requests access in OmniVault, A approves, B views A's items.
// Usage: [VAULTWARDEN_URL=http://localhost:8800] node test/e2e-emergency.mjs [path-to-playwright] [screenshot-dir]
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EMAIL, PASSWORD } from './fake-bitwarden.js';
import { extensionCopy, launch, startServers } from './servers.mjs';
import { grantEmergencyAccess, seedVaultwarden } from './vaultwarden-seed.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const REAL = process.env.VAULTWARDEN_URL?.replace('127.0.0.1', 'localhost');
const { chromium } = await import(pwPath);

let server; let user; let grantorName; let approve; let expected;
if (REAL) {
  const A = await seedVaultwarden(REAL, { withOrg: false, extraLogins: [['Erbschaft', 'erblasser', 'erb-pw-2026', 'https://erb.example']] });
  const B = await seedVaultwarden(REAL, { withOrg: false });
  const grant = await grantEmergencyAccess(A, B, { waitTimeDays: 1 });
  server = REAL; user = { email: B.email, password: B.password }; grantorName = A.email; approve = grant.approve;
  expected = { item: 'Erbschaft', username: 'erblasser', password: 'erb-pw-2026', count: 4 };
} else {
  const s = await startServers({ bwPort: 8851, pbPort: 8852, extraItems: 0 });
  server = s.ORIGIN; user = { email: EMAIL, password: PASSWORD }; grantorName = 'Gerda';
  approve = async () => s.bw.emergency.approve('ea1');
  expected = { item: 'Gerdas Bank', username: 'gerda', password: 'gerda-bank-pw', count: 2 };
  process.on('exit', () => s.close());
}

const ext = await extensionCopy();
const { ctx, extId } = await launch(chromium, ext);
let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };

try {
  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.setViewportSize({ width: 380, height: 560 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector('#empty:not([hidden])');
  await popup.evaluate(() => { navigator.clipboard.writeText = async (x) => { window.__copied = x; }; });
  const copied = () => popup.evaluate(() => window.__copied ?? null);
  const msg = (type, payload = {}) => popup.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => r.result), [type, payload]);
  const tab = () => popup.click('#view-tools .tabs button:has-text("Notfallzugriff")');

  await popup.click('#btn-tools');
  await popup.waitForSelector('#view-tools:not([hidden]) .tabs');
  check(!await popup.$('#view-tools .tabs button:has-text("Notfallzugriff")'), 'no emergency access tab without an unlocked Bitwarden account');
  await popup.click('#view-tools button:has-text("Zurück")');

  await popup.click('#btn-new');
  await popup.click('#menu [role=menuitem]:has-text("Konto hinzufügen")');
  await popup.waitForSelector('#view-account:not([hidden])');
  await popup.selectOption('#acc-provider', 'bitwarden');
  await popup.selectOption('#acc-fields select[name=server]', '__custom');
  await popup.fill('input[name=server__custom]', server);
  await popup.fill('#acc-fields input[name=email]', user.email);
  await popup.fill('#form-account input[name=label]', 'Privat');
  await popup.click('#acc-submit');
  await popup.waitForSelector('#view-unlock:not([hidden])');
  await popup.fill('#form-unlock input[name=password]', user.password);
  await popup.click('#unlock-submit');
  await popup.waitForSelector('#view-main:not([hidden]) .item', { timeout: 30000 });

  await popup.click('#btn-tools');
  await tab();
  const row = popup.locator(`#emergency-list [data-grant-id]:has-text("${grantorName}")`);
  await row.waitFor();
  check((await row.locator('[data-status]').getAttribute('data-status')) === '2', 'grant listed as confirmed');
  check((await row.textContent()).includes(REAL ? '1 Tag' : '7 Tage'), `waiting period shown: "${(await row.locator('[data-status]').textContent()).trim()}"`);
  check(!await row.locator('[data-action=view]').count(), 'no view button before approval');
  if (!REAL) {
    const theo = popup.locator('#emergency-list [data-grant-id]:has-text("Theo")');
    check((await theo.textContent()).includes('nur in den Bitwarden-Apps') && !await theo.locator('button').count(), 'takeover grant: hint, no actions');
  }
  await popup.screenshot({ path: join(shots, 'emergency-list.png') });

  await row.locator('[data-action=initiate]').click();
  await popup.waitForSelector('#dialog[open]');
  check((await popup.textContent('#dialog-text')).includes('benachrichtigt'), 'request asks first');
  await popup.click('#dialog-ok');
  await popup.waitForSelector(`#emergency-list [data-grant-id]:has-text("${grantorName}") [data-status="3"]`);
  check(true, 'status after request: requested');

  await approve();
  await popup.click('#view-tools .tabs button:has-text("Prüfen")');
  await tab();
  await popup.locator(`#emergency-list [data-grant-id]:has-text("${grantorName}") [data-action=view]`).click();
  await popup.waitForSelector('#emergency-items .pick');
  const names = await popup.$$eval('#emergency-items .pick .pick-name', (els) => els.map((e) => e.textContent));
  check(names.length === expected.count && names.includes(expected.item), `grantor's items listed: ${names.join(', ')}`);
  await popup.screenshot({ path: join(shots, 'emergency-items.png') });

  await popup.click(`#emergency-items .pick-name:has-text("${expected.item}")`);
  await popup.waitForSelector('#view-item:not([hidden]) .field[data-field="Passwort"]');
  check((await popup.textContent('#view-item .detail-sub')).includes('nur lesen'), 'detail marked read only');
  check((await popup.textContent('#view-item .field[data-field="Benutzername"] .v')) === expected.username, 'username shown');
  check(!(await popup.textContent('#view-item')).includes(expected.password), 'password masked');
  await popup.click('#view-item .field[data-field="Passwort"] button[aria-label="Passwort kopieren"]');
  check(await copied() === expected.password, 'password copied');
  const buttons = await popup.$$eval('#view-item button', (els) => els.map((e) => e.textContent.trim()).filter(Boolean));
  check(!buttons.some((b) => /Ausfüllen|Bearbeiten|Löschen/.test(b)), `no fill, edit or delete: ${buttons.join(' | ')}`);
  await popup.screenshot({ path: join(shots, 'emergency-item.png') });

  // never part of the account's own items: not listed, not searchable, not filled, not exported
  const [acc] = (await msg('state')).accounts;
  const own = await msg('items', { tabUrl: REAL ? 'https://erb.example/' : 'https://bank.example/' });
  check(!own.some((i) => i.name === expected.item), 'grantor items are not among the own items (search, fill, export)');
  const exported = JSON.stringify(await msg('exportItems', { accountIds: [acc.id], format: 'json' }));
  check(exported.length > 100 && !exported.includes(expected.item), 'not exported');

  await popup.click('#view-item button:has-text("Zurück")');
  await popup.click('#view-tools button:has-text("Zur Übersicht")');
  check(true, 'back from the item returns to the grantor\'s items');
  await popup.waitForSelector('#emergency-list [data-grant-id]');
  // locking forgets them: after unlocking again they are fetched anew
  await msg('lock', { id: acc.id });
  await popup.reload();
  await popup.waitForSelector('#view-main:not([hidden]), #view-unlock:not([hidden])');
  const after = await popup.evaluate((id) => chrome.runtime.sendMessage({ type: 'emergencyView', accountId: id, grantId: 'x' }), acc.id);
  check(!after.ok && /gesperrt/.test(after.error), `after locking nothing is left: ${after.error}`);
  check(!errors.length, `no page errors${errors.length ? `: ${errors.join(' | ')}` : ''}`);
} catch (e) {
  console.error(e);
  failures++;
} finally {
  await ctx.close();
}
console.log(failures ? `\n${failures} FAILED` : '\nall passed');
process.exit(failures ? 1 : 0);
