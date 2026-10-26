// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Browser test and measurement: unlocks a Bitwarden account with a high Argon2id memory setting in Chromium while
// other messages are sent to the background, and checks that clearing the clipboard (same offscreen document)
// still works during and after the derivation. Then decrypts a KeePass database with 256 MiB Argon2d in the popup
// and checks that the popup keeps running meanwhile.
// Usage: ARGON2_MIB=1024 node test/e2e-argon2.mjs   (default 512 MiB; ARGON2_MEASURE=1 only reports, no checks)
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EMAIL, PASSWORD, fakeBitwarden } from './fake-bitwarden.js';
import { extensionCopy, launch, listen, LOGIN_PAGE } from './servers.mjs';

const { chromium } = await import(process.argv[2] ?? 'playwright');
const MIB = Number(process.env.ARGON2_MIB ?? 512);
const MEASURE = !!process.env.ARGON2_MEASURE;
const PORT = 8789;
const ORIGIN = `http://localhost:${PORT}`;

let failures = 0;
const check = (cond, msg) => { console.log(`${cond || MEASURE ? 'ok  ' : 'FAIL'} ${msg}`); if (!cond && !MEASURE) failures++; };

const bw = await fakeBitwarden({ kdf: { kdf: 1, kdfIterations: 3, kdfMemory: MIB, kdfParallelism: 4 }, loginUri: `${ORIGIN}/login.html` });
const server = await listen(bw, PORT);
const ext = await extensionCopy();
const { ctx, profile } = await launch(chromium, ext);

/** Resident memory of the whole browser (all processes started for this profile), in MiB. */
function browserRss() {
  const rows = execFileSync('ps', ['-eo', 'pid=,ppid=,rss=,args='], { encoding: 'utf8' }).trim().split('\n')
    .map((l) => l.trim().match(/^(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/)).filter(Boolean)
    .map(([, pid, ppid, rss, args]) => ({ pid: +pid, ppid: +ppid, rss: +rss, args }));
  const tree = new Set(rows.filter((r) => r.args.includes(profile) && !r.args.includes('--type=')).map((r) => r.pid));
  for (let grew = true; grew;) {
    grew = false;
    for (const r of rows) if (!tree.has(r.pid) && tree.has(r.ppid)) { tree.add(r.pid); grew = true; }
  }
  return Math.round(rows.filter((r) => tree.has(r.pid)).reduce((s, r) => s + r.rss, 0) / 1024);
}

try {
  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${new URL(ctx.serviceWorkers()[0].url()).host}/popup.html`);
  const site = await ctx.newPage();
  await site.route(`${ORIGIN}/login.html`, (r) => r.fulfill({ contentType: 'text/html', body: LOGIN_PAGE }));
  await site.goto(`${ORIGIN}/login.html`);
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: ORIGIN });
  await page.bringToFront();
  const msg = (type, payload = {}) => page.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }).then((r) => { if (!r.ok) throw new Error(r.error); return r.result; }), [type, payload]);
  const acc = await msg('addAccount', { provider: 'bitwarden', config: { server: ORIGIN, email: EMAIL }, label: 'Argon2' });
  await msg('setSettings', { patch: { clipboardSeconds: 1 } });
  const before = browserRss();

  // copy something: the clipboard is cleared (offscreen document in Chrome) about 1 s into the derivation
  await page.evaluate(async () => {
    await navigator.clipboard.writeText('geheim-argon2');
    await chrome.runtime.sendMessage({ type: 'scheduleClipboardClear' });
  });

  // start the unlock and keep asking the background for its state meanwhile (from the page, so the timing is not
  // distorted by the test driver)
  const result = await page.evaluate(async ([id, password]) => {
    const t0 = performance.now();
    let done = false;
    const login = chrome.runtime.sendMessage({ type: 'login', id, credentials: { password } })
      .then((r) => { done = true; return { r, ms: performance.now() - t0 }; });
    const pings = [];
    while (!done) {
      const s = performance.now();
      await chrome.runtime.sendMessage({ type: 'state' });
      pings.push(performance.now() - s);
      await new Promise((r) => setTimeout(r, 50));
    }
    const { r, ms } = await login;
    return { ok: r.ok, error: r.error, ms, pings };
  }, [acc.id, PASSWORD]);
  let peak = 0;
  // memory a few seconds later (workers ended, offscreen document closed)
  for (let i = 0; i < 6; i++) { peak = Math.max(peak, browserRss()); await page.waitForTimeout(500); }
  const after = browserRss();
  const pings = result.pings.toSorted((a, b) => a - b);
  const p = (q) => Math.round(pings[Math.min(pings.length - 1, Math.floor(q * pings.length))] ?? 0);
  console.log(`  Argon2id ${MIB} MiB, t=3, p=4: unlock ${(result.ms / 1000).toFixed(1)} s; ${pings.length} other messages answered, median ${p(0.5)} ms, max ${p(1)} ms; browser memory ${before} → ${after} MiB`);
  check(result.ok, `unlock with ${MIB} MiB Argon2id succeeds${result.ok ? '' : ` (${result.error})`}`);
  check(pings.length >= Math.floor(result.ms / 1000) && p(1) < 1000, `other messages are answered during the derivation (max ${p(1)} ms)`);
  check(after - before < Math.max(200, MIB / 2), `memory is freed afterwards (${before} → ${after} MiB)`);

  await site.bringToFront();
  const cleared = await site.evaluate(() => navigator.clipboard.readText());
  check(cleared.trim() === '', `clipboard cleared during the derivation (now "${cleared}")`);

  // and afterwards, with the offscreen document closed again
  await page.bringToFront();
  await page.evaluate(async () => {
    await navigator.clipboard.writeText('geheim-danach');
    await chrome.runtime.sendMessage({ type: 'scheduleClipboardClear' });
  });
  await site.bringToFront();
  await site.waitForTimeout(2500);
  const clip = await site.evaluate(() => navigator.clipboard.readText());
  check(clip.trim() === '', `clipboard cleared after the derivation (now "${clip}")`);
  const items = await msg('items');
  check(items.length > 0, `vault readable after the unlock (${items.length} items)`);

  // KeePass database with 256 MiB Argon2d, decrypted in the popup
  const kdbx = join(await mkdtemp(join(tmpdir(), 'omnivault-kdbx-')), 'big.kdbx');
  execFileSync('python3', ['test/fixtures/kdbx/generate.py', 'test/fixtures/kdbx/source.xml', kdbx, '--password', 'omnivault-test',
    '--version', '4.1', '--kdf', 'argon2d', '--memory', String(256 * 1024), '--iterations', '4', '--parallelism', '2', '--cipher', 'chacha20']);
  await page.bringToFront();
  await page.reload();
  await page.click('#btn-tools');
  await page.click('#view-tools .tabs button:has-text("Import")');
  await page.setInputFiles('#view-tools input[type=file][aria-label=Exportdatei]', { name: 'big.kdbx', mimeType: 'application/octet-stream', buffer: await readFile(kdbx) });
  await page.waitForSelector('#view-tools form.kdbx-unlock:not([hidden])');
  await page.fill('#view-tools input[aria-label="Master-Passwort der Datenbank"]', 'omnivault-test');
  // largest gap between timer ticks of the popup while it decrypts
  await page.evaluate(() => {
    globalThis.gap = 0;
    let last = performance.now();
    globalThis.ticker = setInterval(() => { const n = performance.now(); gap = Math.max(gap, n - last); last = n; }, 20);
  });
  const t0 = Date.now();
  await page.click('#view-tools form.kdbx-unlock button[type=submit]');
  const busy = await page.textContent('#view-tools form.kdbx-unlock button[type=submit]');
  await page.waitForFunction(() => /Erkannt: .*4 Einträge/.test(document.querySelector('#view-tools .hint')?.textContent || ''), null, { timeout: 60000 });
  const kdbxMs = Date.now() - t0;
  const gap = Math.round(await page.evaluate(() => { clearInterval(ticker); return gap; }));
  console.log(`  KDBX Argon2d 256 MiB, t=4, p=2 in the popup: ${(kdbxMs / 1000).toFixed(1)} s, longest pause of the popup ${gap} ms`);
  check(/Entschlüssele/.test(busy), `popup shows the progress text ("${busy}")`);
  check(gap < 500, `popup keeps running while decrypting (longest pause ${gap} ms)`);
} catch (e) {
  check(false, e.stack);
} finally {
  await ctx.close();
  server.close();
}
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
