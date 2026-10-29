// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Reads a TOTP QR code from the visible part of the current tab: one screenshot (tabs.captureVisibleTab), decoded
// here in the popup with jsQR. The image stays in this page's memory and is dropped right afterwards; it is never
// stored or sent anywhere. captureVisibleTab needs activeTab (granted when OmniVault is opened from its toolbar
// icon, keyboard shortcut or context menu) or access to all websites.
import { ext } from '../lib/browser.js';
import { parseOtpauthUri } from '../lib/totp.js';
import { t } from './ui.js';

/** RGBA pixels of a data: URL image. */
async function pixels(dataUrl) {
  const bitmap = await createImageBitmap(await (await fetch(dataUrl)).blob());
  try {
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(bitmap, 0, 0);
    return ctx.getImageData(0, 0, bitmap.width, bitmap.height);
  } finally {
    bitmap.close();
  }
}

/** Decodes the first QR code in an ImageData-like object; null if there is none. */
export async function decodeQr(image) {
  const { default: jsQR } = await import('../../vendor/jsqr.mjs');
  return jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' })?.data ?? null;
}

/** Screenshot of the tab's window → otpauth:// parameters (see parseOtpauthUri). Throws with a message for the user. */
export async function scanTotpFromTab(tab) {
  if (!tab || !/^(https?|file):/.test(tab.url ?? '')) throw new Error(t('Keine Webseite zum Scannen'));
  let shot;
  try {
    shot = await ext.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
  } catch (e) {
    console.warn('OmniVault: captureVisibleTab', e);
    throw new Error(t('Kein Zugriff auf die Seite. OmniVault über das Symbol in der Symbolleiste öffnen und erneut versuchen.'));
  }
  let text = await decodeQr(await pixels(shot));
  shot = null;
  if (text === null) throw new Error(t('Kein QR-Code im sichtbaren Teil der Seite gefunden'));
  const result = parseOtpauthUri(text);
  text = null;
  return result;
}
