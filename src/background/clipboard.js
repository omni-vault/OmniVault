// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Clears the clipboard after a delay. Chrome's service worker has no DOM, so it uses an offscreen
// document; Firefox's background page has a DOM and copies directly.
import { ext } from '../lib/browser.js';
import { withOffscreen } from '../lib/offscreen.js';

const ALARM = 'clear-clipboard';
let timer = null;

async function writeEmpty() {
  if (typeof document !== 'undefined' && document.body) {
    const ta = document.createElement('textarea');
    ta.value = ' ';
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    return;
  }
  if (!ext.offscreen) return;
  // shared with a running Argon2 derivation, if any (one offscreen document per extension)
  await withOffscreen(() => ext.runtime.sendMessage({ target: 'offscreen', type: 'clear-clipboard' }));
}

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
