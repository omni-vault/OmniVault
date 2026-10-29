// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Chrome-only offscreen document (the service worker has neither a DOM nor dedicated workers):
// writes or overwrites the clipboard, and runs Argon2 in a dedicated worker for the service worker.
import { Unavailable, WORKER_FILE, inWorker, unpack } from '../lib/argon2.js';
import { b64 } from '../lib/bytes.js';

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.target !== 'offscreen' || sender.id !== chrome.runtime.id) return false;
  if (msg.type === 'write-clipboard' && typeof msg.text === 'string') {
    const t = document.getElementById('t');
    t.value = msg.text;
    t.select();
    const ok = document.execCommand('copy');
    t.value = '';
    sendResponse(ok);
    return false;
  }
  if (msg.type === 'argon2') {
    inWorker(Worker, WORKER_FILE, msg.lib, unpack(msg.params)).then(
      (out) => sendResponse({ out: b64(out) }),
      (e) => sendResponse(e instanceof Unavailable ? { unavailable: true } : { error: e.message }),
    );
    return true;
  }
  return false;
});
