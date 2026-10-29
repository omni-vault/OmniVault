// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Unlock with the device (Windows Hello, Touch ID, a phone, a security key): the same seal as the PIN lock
// (pinlock.js), but the private key is encrypted with a key derived from a passkey's PRF output instead of the PIN.
// The passkey belongs to the extension itself (rpId = the extension's ID, Chrome only); the authenticator returns
// the same 32 bytes for the same salt only after user verification, and counts failed attempts itself.
// Stored (storage.local): credential ID, transports, PRF salt, public key and the encrypted private key – nothing
// that opens the seal without the authenticator.
import { t } from '../i18n/index.js';
import { b64, fromB64, utf8 } from './bytes.js';
import { createLock, unsealWithKey } from './pinlock.js';

const { subtle } = globalThis.crypto;
const INFO = utf8('OmniVault device unlock v1');

/** AES-GCM key from the authenticator's PRF output (HKDF-SHA-256; the PRF salt already differs per setup). */
export async function deviceKey(prf) {
  const bytes = typeof prf === 'string' ? fromB64(prf) : new Uint8Array(prf);
  if (bytes.length !== 32) throw new Error(t('Das Gerät hat keinen gültigen Schlüssel geliefert'));
  const ikm = await subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: INFO }, ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** New PRF salt for a setup (base64). */
export const newPrfSalt = () => b64(crypto.getRandomValues(new Uint8Array(32)));

/** → lock object to store, from what the setup in the interface returned (all base64 except `transports`). */
export async function createDeviceLock({ credentialId, prfSalt, prf, transports = [] }) {
  if (!credentialId || fromB64(prfSalt).length !== 32) throw new Error(t('Das Gerät hat keinen gültigen Schlüssel geliefert'));
  return createLock(await deviceKey(prf), {
    kind: 'device', credentialId, prfSalt,
    transports: (Array.isArray(transports) ? transports : []).filter((x) => typeof x === 'string').slice(0, 8),
  });
}

/** Opens a sealed value with the PRF output of the lock's passkey; throws if it is not that passkey's output. */
export function unsealWithDevice(lock, sealed, prf) {
  return unsealWithKey(lock, sealed, () => deviceKey(prf), () => t('Das Gerät hat nicht den passenden Schlüssel geliefert'));
}
