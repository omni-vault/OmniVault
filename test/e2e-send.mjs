// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test for Tools → Send against a REAL Vaultwarden server: the tab appears only with an unlocked Bitwarden
// account; new text and file Send with options, copy link (opened like a recipient and decrypted independently),
// edit, remove password, delete.
// Usage: VAULTWARDEN_URL=http://localhost:8800 node test/e2e-send.mjs [path-to-playwright] [screenshot-dir]
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { extensionCopy, launch } from './servers.mjs';
import { seedVaultwarden } from './vaultwarden-seed.mjs';
import { pyCheck, pythonChecker, receiveSend } from './send-recipient.mjs';

const pwPath = process.argv[2] ?? 'playwright';
const shots = process.argv[3] ?? tmpdir();
const VW = (process.env.VAULTWARDEN_URL ?? 'http://localhost:8800').replace('127.0.0.1', 'localhost');
const ep = { api: `${VW}/api`, identity: `${VW}/identity` };
const { chromium } = await import(pwPath);

const A = await seedVaultwarden(VW, { withOrg: false });
const ext = await extensionCopy();
const { ctx, extId } = await launch(chromium, ext);
let failures = 0;
const check = (cond, msg) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond) failures++; };

/** Recipient: the link (+ password) → Vaultwarden → test/send-check.py. */
async function receive(link, password) {
  const passwordHash = password == null ? undefined : pyCheck({ link, password }).passwordHash;
  const r = await receiveSend(ep, link, { passwordHash });
  if (r.status !== 200) return r;
  return { ...r, plain: pyCheck({ link, access: r.access, ...(r.file ? { file: Buffer.from(r.file).toString('base64') } : {}) }) };
}

try {
  if (!pythonChecker) throw new Error('python3 with cryptography is needed for the recipient check');
  const popup = await ctx.newPage();
  const errors = [];
  popup.on('pageerror', (e) => errors.push(e.message));
  await popup.setViewportSize({ width: 380, height: 560 });
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.waitForSelector('#empty:not([hidden])');
  // record what the popup copies (the clipboard itself is browser-wide)
  await popup.evaluate(() => { navigator.clipboard.writeText = async (x) => { window.__copied = x; }; });
  const copied = () => popup.evaluate(() => window.__copied ?? null);
  const confirm = async () => { await popup.waitForSelector('#dialog[open]'); await popup.click('#dialog-ok'); };

  // no account yet: no Send tab
  await popup.click('#btn-tools');
  await popup.waitForSelector('#view-tools:not([hidden]) .tabs');
  check(!await popup.$('#view-tools .tabs button:has-text("Send")'), 'no Send tab without an unlocked Bitwarden account');
  await popup.click('#view-tools button:has-text("Zurück")');

  await popup.click('#btn-new');
  await popup.click('#menu [role=menuitem]:has-text("Konto hinzufügen")');
  await popup.waitForSelector('#view-account:not([hidden])');
  await popup.selectOption('#acc-provider', 'bitwarden');
  await popup.selectOption('#acc-fields select[name=server]', '__custom');
  await popup.fill('input[name=server__custom]', VW);
  await popup.fill('#acc-fields input[name=email]', A.email);
  await popup.fill('#form-account input[name=label]', 'Privat');
  await popup.click('#acc-submit');
  await popup.waitForSelector('#view-unlock:not([hidden])');
  await popup.fill('#form-unlock input[name=password]', A.password);
  await popup.click('#unlock-submit');
  await popup.waitForSelector('#view-main:not([hidden]) .item', { timeout: 20000 });

  await popup.click('#btn-tools');
  await popup.click('#view-tools .tabs button:has-text("Send")');
  await popup.waitForSelector('#send-list .empty-note:has-text("Noch keine Sends")');
  check(true, 'Send tab appears with an unlocked Bitwarden account, list empty');

  // new text Send with password, access limit, expiry, hidden text
  await popup.click('#send-new-text');
  await popup.fill('#send-form input[name=name]', 'WLAN Gäste');
  await popup.fill('#send-form textarea[name=text]', 'SSID gast · Kennwort: blau-Wal-17');
  await popup.check('#send-form input[name=hidden]');
  await popup.selectOption('#send-form select[name=deletion]', String(3 * 86400_000));
  await popup.selectOption('#send-form select[name=expiration]', String(86400_000));
  await popup.fill('#send-form input[name=maxAccessCount]', '3');
  await popup.fill('#send-form input[name=password]', 'gast');
  await popup.fill('#send-form textarea[name=notes]', 'für Besuch am Montag');
  await popup.check('#send-form input[name=hideEmail]');
  await popup.screenshot({ path: join(shots, 'send-form.png') });
  await popup.click('#send-save');
  await popup.waitForSelector('#dialog[open]');
  check((await popup.textContent('#dialog-text')).includes('WLAN Gäste'), 'created; offers to copy the link');
  await popup.click('#dialog-ok');
  await popup.waitForFunction(() => window.__copied);
  const link1 = await copied();
  check(link1.startsWith(`${VW}/#/send/`), `link format (${link1.replace(/[^/]+$/, '…')})`);
  await popup.waitForSelector('#send-list .send-row:has-text("WLAN Gäste")');
  const row1 = await popup.textContent('#send-list .send-row:has-text("WLAN Gäste")');
  check(/Text/.test(row1) && /0 von 3 Zugriffen/.test(row1) && /läuft ab/.test(row1) && /Passwort/.test(row1), `list row: ${row1.replace(/\s+/g, ' ')}`);
  await popup.screenshot({ path: join(shots, 'send-list.png') });

  check((await receive(link1)).status >= 400, 'recipient without password refused');
  const r1 = await receive(link1, 'gast');
  check(r1.plain?.name === 'WLAN Gäste' && r1.plain?.text === 'SSID gast · Kennwort: blau-Wal-17', 'recipient decrypts the text (Python)');
  check(r1.access?.text?.hidden === true && (r1.access?.creatorIdentifier ?? null) === null, 'hidden text and e-mail hidden');

  // new file Send
  await popup.click('#send-new-file');
  const bytes = Buffer.from(Array.from({ length: 50_000 }, (_, i) => (i * 17) % 256));
  await popup.setInputFiles('#send-form input[name=file]', { name: 'bericht.pdf', mimeType: 'application/pdf', buffer: bytes });
  await popup.click('#send-save');
  await popup.waitForSelector('#dialog[open]', { timeout: 20000 });
  await popup.click('#dialog-cancel');
  await popup.waitForSelector('#send-list .send-row:has-text("bericht.pdf")');
  check(/Datei/.test(await popup.textContent('#send-list .send-row:has-text("bericht.pdf")')), 'file Send listed (name defaults to the file name)');
  await popup.evaluate(() => { window.__copied = null; });
  await popup.click('#send-list .send-row:has-text("bericht.pdf") button[aria-label*="Link"]');
  await popup.waitForFunction(() => window.__copied);
  const r2 = await receive(await copied());
  check(r2.plain?.fileName === 'bericht.pdf' && Buffer.from(r2.plain.file, 'base64').equals(bytes), 'recipient downloads and decrypts the file (Python)');

  // edit the text Send: link stays, password stays
  await popup.click('#send-list .send-row:has-text("WLAN Gäste") button[aria-label*="bearbeiten"]');
  await popup.waitForSelector('#send-form');
  check(await popup.inputValue('#send-form textarea[name=text]') === 'SSID gast · Kennwort: blau-Wal-17', 'edit form shows the text');
  check(await popup.inputValue('#send-form textarea[name=notes]') === 'für Besuch am Montag', 'edit form shows the notes');
  await popup.fill('#send-form input[name=name]', 'WLAN Gäste (neu)');
  await popup.fill('#send-form textarea[name=text]', 'Kennwort: rot-Hai-18');
  await popup.click('#send-save');
  await popup.waitForSelector('#send-list .send-row:has-text("WLAN Gäste (neu)")');
  const r3 = await receive(link1, 'gast');
  check(r3.plain?.text === 'Kennwort: rot-Hai-18', 'same link shows the new text, password kept');

  // remove password
  await popup.click('#send-list .send-row:has-text("WLAN Gäste (neu)") button[aria-label*="Passwort"]');
  await confirm();
  await popup.waitForFunction(() => !document.querySelector('#send-list .send-row')?.textContent.includes('Passwort') || ![...document.querySelectorAll('#send-list .send-row')].find((r) => r.textContent.includes('WLAN'))?.querySelector('.tag'));
  const r4 = await receive(link1);
  check(r4.plain?.name === 'WLAN Gäste (neu)', 'after removing the password the link opens without one');

  // server refusal in plain words: deletion date more than 31 days away (own date)
  await popup.click('#send-new-text');
  await popup.fill('#send-form input[name=name]', 'Zu lang');
  await popup.fill('#send-form textarea[name=text]', 'x');
  await popup.selectOption('#send-form select[name=deletion]', 'custom');
  await popup.evaluate(() => { const i = document.querySelector('#send-form input[name=deletion-custom]'); i.removeAttribute('max'); const d = new Date(Date.now() + 40 * 86400_000); i.value = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}T12:00`; });
  await popup.click('#send-save');
  await popup.waitForSelector('#toast:has-text("31 Tage")');
  check(true, 'deletion date too far away: message in plain words');
  await popup.click('#send-form button:has-text("Abbrechen")');

  // delete both
  for (const name of ['WLAN Gäste (neu)', 'bericht.pdf']) {
    await popup.click(`#send-list .send-row:has-text("${name}") button[aria-label*="löschen"]`);
    await confirm();
    await popup.waitForSelector(`#send-list .send-row:has-text("${name}")`, { state: 'detached' });
  }
  check(await popup.$('#send-list .empty-note') !== null, 'both Sends deleted');
  check((await receive(link1)).status >= 400, 'deleted link no longer opens');

  // locking hides the tab again
  await popup.evaluate(() => chrome.runtime.sendMessage({ type: 'lockAll' }));
  await popup.reload();
  await popup.waitForSelector('#view-main:not([hidden])');
  await popup.click('#btn-tools');
  await popup.waitForSelector('#view-tools:not([hidden]) .tabs');
  check(!await popup.$('#view-tools .tabs button:has-text("Send")'), 'Send tab gone once the account is locked');
  check(!errors.length, `no page errors ${errors.join('; ')}`);
} catch (e) {
  console.error(e);
  failures++;
} finally {
  await ctx.close();
}
console.log(failures ? `${failures} FAILED` : 'All Send browser tests passed');
process.exit(failures ? 1 : 0);
