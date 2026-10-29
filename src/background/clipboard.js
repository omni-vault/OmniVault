// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Writes to the clipboard from the background (a TOTP code after filling) and clears it after a delay. Chrome's
// service worker has no DOM, so it uses the offscreen document (reason CLIPBOARD); Firefox's event page has a DOM and
// copies directly (clipboardWrite permission).
import { ext } from '../lib/browser.js';
import { withOffscreen } from '../lib/offscreen.js';

const ALARM = 'clear-clipboard';
let timer = null;

/** Puts `text` on the clipboard from the background; true if the browser accepted it. */
export async function writeClipboard(text) {
  if (typeof document !== 'undefined' && document.body) {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } finally { ta.value = ''; ta.remove(); }
    if (!ok && navigator.clipboard?.writeText) ok = await navigator.clipboard.writeText(text).then(() => true, () => false);
    return ok;
  }
  if (!ext.offscreen) return false;
  // shared with a running Argon2 derivation, if any (one offscreen document per extension)
  return !!await withOffscreen(() => ext.runtime.sendMessage({ target: 'offscreen', type: 'write-clipboard', text }));
}

const writeEmpty = () => writeClipboard(' ');

export async function clearClipboardNow() {
  clearTimeout(timer);
  timer = null;
  await ext.alarms?.clear(ALARM);
  await ext.storage.session.remove('clipboardPending');
  try { await writeEmpty(); } catch (e) { console.warn('OmniVault: clipboard not cleared', e); }
}

export async function scheduleClipboardClear(seconds) {
  if (!seconds) return;
  clearTimeout(timer);
  timer = setTimeout(clearClipboardNow, seconds * 1000);
  // The service worker may be stopped before the timeout; the alarm is the fallback (min. 30 s).
  await ext.alarms?.create(ALARM, { delayInMinutes: Math.max(0.5, seconds / 60) });
  await ext.storage.session.set({ clipboardPending: Date.now() + seconds * 1000 });
}

export function handleAlarm(alarm) {
  if (alarm.name === ALARM) return clearClipboardNow();
  return undefined;
}
