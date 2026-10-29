// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// The device window: runs the passkey ceremony for the toolbar popup or the sidebar (see device-flow.js) and
// starts it right away. When it is done, the background closes the window and continues where the user came from.
import { initLanguage, t, tn, translateDom } from '../i18n/index.js';
import { ext } from '../lib/browser.js';
import { setupDevice, unlockDevice } from './device-unlock.js';

try { await initLanguage(); translateDom(); } finally { document.documentElement.classList.remove('i18n-pending'); }

const call = (type, payload = {}) => ext.runtime.sendMessage({ type, ...payload }).then((r) => { if (!r?.ok) throw new Error(r?.error ?? t('Fehler')); return r.result; });
const $ = (id) => document.getElementById(id);
const setup = new URLSearchParams(location.search).get('do') === 'setup';
$(setup ? 'device-title-setup' : 'device-title').hidden = false;
document.title = `OmniVault – ${$(setup ? 'device-title-setup' : 'device-title').textContent}`;

let busy = false;
async function run() {
  if (busy) return;
  busy = true;
  $('device-error').hidden = true;
  $('device-retry').hidden = true;
  $('device-status').hidden = false;
  try {
    let message;
    if (setup) {
      await setupDevice(call);
      message = t('Entsperren mit dem Gerät eingerichtet');
    } else {
      const { unlocked } = await unlockDevice(call);
      message = tn(unlocked, '{n} Konto entsperrt', '{n} Konten entsperrt');
    }
    $('device-status').textContent = message;
    await call('deviceWindowDone', { ok: true, message });
  } catch (e) {
    $('device-status').hidden = true;
    $('device-error').textContent = e.message;
    $('device-error').hidden = false;
    $('device-retry').hidden = false;
    $('device-retry').focus();
  } finally {
    busy = false;
  }
}

$('device-retry').addEventListener('click', run);
$('device-cancel').addEventListener('click', () => call('deviceWindowDone', { ok: false }).catch(() => window.close()));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('device-cancel').click(); });
run();
