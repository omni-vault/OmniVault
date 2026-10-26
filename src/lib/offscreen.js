// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Chrome allows one offscreen document per extension. It serves two purposes (clearing the clipboard, Argon2 in a
// worker), possibly at the same time: it is opened for the first user, shared, and closed after the last one.
import { ext } from './browser.js';

let users = 0;
let ready = null; // promise: document open
let closing = Promise.resolve();

async function open(api) {
  const url = api.runtime.getURL('offscreen.html');
  const contexts = await api.runtime.getContexts?.({ contextTypes: ['OFFSCREEN_DOCUMENT'], documentUrls: [url] });
  if (contexts?.length) return; // left open by an earlier, stopped service worker
  await api.offscreen.createDocument({
    url,
    reasons: ['CLIPBOARD', 'WORKERS'],
    justification: 'Kopierte Passwörter nach Ablauf der Frist aus der Zwischenablage entfernen; Schlüsselableitung (Argon2) in einem Worker, damit die Erweiterung währenddessen reagiert',
  });
}

/** Runs `fn` while the offscreen document is open. */
export async function withOffscreen(fn, api = ext) {
  users++;
  try {
    ready ??= closing.then(() => open(api));
    await ready;
    return await fn();
  } finally {
    if (--users === 0) {
      ready = null;
      closing = Promise.resolve(api.offscreen.closeDocument()).catch(() => {});
    }
  }
}
