// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Unlock with the device: the passkey ceremony on an extension page (popup as a tab or window, or the device
// window). The passkey belongs to OmniVault itself: extension pages leave the rpId out; for the page it is then the
// extension's ID, and Chrome registers it on the authenticator as "chrome-extension://<id>", which no website and no
// other extension can claim. Only the PRF output (32 bytes) goes to the background, which derives the key from it.
// Firefox only lets extensions use relying party IDs of sites they have host permissions for – not their own
// origin – so the feature is not offered there.
/* global __BROWSER__ */
import { t } from '../i18n/index.js';
import { b64, b64url, fromB64 } from '../lib/bytes.js';

const BROWSER = typeof __BROWSER__ !== 'undefined' ? __BROWSER__ : 'chrome';
const TIMEOUT = 120_000;
const random = (n) => crypto.getRandomValues(new Uint8Array(n));

/** null when unlocking with the device can be offered in this browser, otherwise the reason (shown instead). */
export async function deviceUnsupported() {
  if (BROWSER !== 'chrome') return t('Firefox erlaubt Erweiterungen keine eigenen Passkeys. Entsperren mit dem Gerät gibt es deshalb nur in Chrome und anderen Chromium-Browsern.');
  if (!globalThis.PublicKeyCredential || !navigator.credentials?.create) return t('Dieser Browser unterstützt keine Passkeys.');
  const caps = await PublicKeyCredential.getClientCapabilities?.().catch(() => null);
  if (caps && caps['extension:prf'] === false) return t('Dieser Browser unterstützt die nötige Passkey-Erweiterung (PRF) nicht.');
  return null;
}

/** Error from the browser → a message for the user; `cancelled` when the user (or the timeout) stopped it. */
function ceremonyError(e) {
  if (e?.name === 'NotAllowedError' || e?.name === 'AbortError') {
    return Object.assign(new Error(t('Abgebrochen, abgelaufen oder vom Gerät abgelehnt.')), { cancelled: true });
  }
  if (e?.name === 'InvalidStateError') return new Error(t('Auf diesem Gerät ist OmniVault schon eingerichtet.'));
  if (e?.name === 'SecurityError') return new Error(t('Der Browser erlaubt OmniVault hier keine Passkeys.'));
  return e instanceof Error ? e : new Error(String(e));
}

/** Tells the authenticator (where the browser supports it) that OmniVault no longer uses this passkey. */
export function forgetCredential(credentialId) {
  if (!credentialId || !globalThis.PublicKeyCredential?.signalUnknownCredential) return;
  PublicKeyCredential.signalUnknownCredential({ rpId: location.hostname, credentialId: b64url(fromB64(credentialId)) }).catch(() => {});
}

/** PRF output of the passkey for `salt`, after user verification. */
async function evaluate(id, salt, transports) {
  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: {
      challenge: random(32), timeout: TIMEOUT, userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id, ...(transports?.length ? { transports } : {}) }],
      extensions: { prf: { eval: { first: salt } } },
    } });
  } catch (e) {
    throw ceremonyError(e);
  }
  const out = assertion.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error(t('Das Gerät hat keinen Schlüssel geliefert (PRF).'));
  return new Uint8Array(out);
}

/**
 * Creates OmniVault's passkey with the PRF extension → what the background stores (credential ID, transports,
 * PRF salt) plus the PRF output. Authenticators that evaluate PRF only when signing in are asked a second time.
 */
export async function registerDevice() {
  const salt = random(32);
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: {
      rp: { name: 'OmniVault' }, // no id: for an extension page, Chrome takes the extension's own ID
      user: { id: random(16), name: 'OmniVault', displayName: t('OmniVault entsperren') },
      challenge: random(32), timeout: TIMEOUT, attestation: 'none',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'discouraged' },
      extensions: { prf: { eval: { first: salt } } },
    } });
  } catch (e) {
    throw ceremonyError(e);
  }
  const id = new Uint8Array(cred.rawId);
  const credentialId = b64(id);
  const prf = cred.getClientExtensionResults().prf;
  if (!prf?.enabled) {
    forgetCredential(credentialId);
    throw new Error(t('Dieses Gerät unterstützt die nötige Passkey-Erweiterung (PRF) nicht und lässt sich nicht zum Entsperren verwenden.'));
  }
  const transports = cred.response.getTransports?.() ?? [];
  let out = prf.results?.first ? new Uint8Array(prf.results.first) : null;
  if (!out) {
    try { out = await evaluate(id, salt, transports); } catch (e) { forgetCredential(credentialId); throw e; }
  }
  return { credentialId, prfSalt: b64(salt), prf: b64(out), transports };
}

/** Setup: ceremony, then the background seals with a key from the PRF output. `call` sends to the background. */
export async function setupDevice(call) {
  const r = await registerDevice();
  const { replaced } = await call('setDeviceUnlock', r);
  if (replaced && replaced !== r.credentialId) forgetCredential(replaced);
}

/** Unlock: ceremony for the stored passkey, then the background opens the seal → { unlocked }. */
export async function unlockDevice(call) {
  const p = await call('deviceUnlockParams');
  const prf = await evaluate(fromB64(p.credentialId), fromB64(p.prfSalt), p.transports);
  return call('unlockWithDevice', { prf: b64(prf) });
}
