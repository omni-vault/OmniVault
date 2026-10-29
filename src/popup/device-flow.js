// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Where the device ceremony runs. The operating system's dialog (Windows Hello and the like) takes the focus, and a
// toolbar popup closes when it loses the focus – the request would be cancelled with it. So the toolbar popup
// (and the sidebar, which the browser's own passkey dialog cannot be anchored to everywhere) hands the ceremony to a
// small window of its own; the background reopens the popup afterwards. A tab or the pop-out window runs it here.
import { ext } from '../lib/browser.js';
import { setupDevice, unlockDevice } from './device-unlock.js';
import { isToolbarPopup, mode, sidebar } from './state.js';
import { call } from './ui.js';

/** 'setup' or 'unlock' → the result when it ran here ({ unlocked } for unlock), or { deferred: true }. */
export async function runDevice(action) {
  const here = mode === 'window' || (mode === 'popup' && !(await isToolbarPopup()));
  if (here) return (action === 'setup' ? setupDevice(call) : unlockDevice(call)).then((r) => r ?? {});
  const w = await ext.windows.getCurrent().catch(() => null);
  await call('openDeviceWindow', { action, returnTo: sidebar ? 'sidebar' : 'popup', windowId: w?.id });
  if (!sidebar) window.close();
  return { deferred: true };
}
