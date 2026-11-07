// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Bitwarden/Vaultwarden: a security key (FIDO2/WebAuthn) as second factor – experimental.
//
// The server checks that the assertion was made on the web vault's origin (clientDataJSON.origin) for the web vault's
// domain (rpId); OmniVault's own pages have another origin, which neither Bitwarden nor Vaultwarden accept. So the
// login flow opens a tab of the web vault and injects `webauthnPrompt` there (scripting, host permission the account
// already has): it shows OmniVault's own box over the page, calls navigator.credentials.get after a click and sends
// the answer to the background only (runtime message, checked there: tab, top frame, origin and a one-time nonce).
// Nothing of the web vault's own scripts is used; the page only provides the origin.
import { t } from '../i18n/index.js';

/** The texts of the box in the page (in the interface language). */
export function promptTexts(host) {
  return {
    title: t('OmniVault: Anmeldung bestätigen'),
    text: t('Bestätige die Anmeldung bei {host} mit deinem Sicherheitsschlüssel oder Passkey. Diese Funktion ist experimentell.', { host }),
    start: t('Sicherheitsschlüssel verwenden'),
    retry: t('Erneut versuchen'),
    cancel: t('Abbrechen'),
    waiting: t('Warte auf den Sicherheitsschlüssel …'),
    done: t('Bestätigt. OmniVault meldet dich an, dieser Tab schließt sich gleich.'),
    failed: t('Nicht bestätigt ({msg}). Bitte erneut versuchen oder abbrechen.'),
  };
}

/**
 * Runs in the web vault's tab (isolated world of the content script, top frame). Self-contained: serialized by
 * scripting.executeScript. `req` comes from the server (see providers/bitwarden webauthnRequest).
 */
export function webauthnPrompt(req, texts, nonce, origin) {
  if (location.origin !== origin) return 'origin';
  if (globalThis.__omnivaultWebauthn2fa === nonce && document.querySelector('omnivault-webauthn')) return 'shown';
  globalThis.__omnivaultWebauthn2fa = nonce;
  document.querySelector('omnivault-webauthn')?.remove();
  const api = globalThis.browser ?? globalThis.chrome;
  const send = (m) => Promise.resolve(api.runtime.sendMessage({ type: 'ov-webauthn-2fa', nonce, ...m })).catch(() => {});
  const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const toB64url = (buf) => {
    let s = '';
    for (const x of new Uint8Array(buf)) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const c = dark ? { bg: '#2a2124', fg: '#f3e9ec', line: '#4a3a40', muted: '#c9b8be' } : { bg: '#fff', fg: '#2b0a17', line: '#e8d6dc', muted: '#6b5560' };
  const host = document.createElement('omnivault-webauthn');
  host.style.cssText = 'all: initial; position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center; background: rgba(20, 8, 14, 0.55);';
  const root = host.attachShadow({ mode: 'closed' });
  const box = document.createElement('div');
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.style.cssText = `box-sizing: border-box; width: min(420px, calc(100vw - 32px)); padding: 20px; border-radius: 12px; font: 14px/1.45 system-ui, sans-serif; color: ${c.fg}; background: ${c.bg}; border: 1px solid ${c.line}; box-shadow: 0 12px 40px rgba(0,0,0,.35); overflow-wrap: anywhere;`;
  const h = document.createElement('h2');
  h.style.cssText = 'margin: 0 0 8px; font: 600 16px/1.3 system-ui, sans-serif;';
  h.textContent = texts.title;
  box.setAttribute('aria-label', texts.title);
  const p = document.createElement('p');
  p.style.cssText = 'margin: 0 0 14px;';
  p.textContent = texts.text;
  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.style.cssText = `margin: 0 0 14px; min-height: 1.45em; color: ${c.muted};`;
  const row = document.createElement('div');
  row.style.cssText = 'display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap;';
  const button = (label, primary) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = label;
    b.style.cssText = `font: 500 14px system-ui, sans-serif; padding: 8px 14px; border-radius: 8px; cursor: pointer; border: 1px solid ${primary ? '#a0174f' : c.line}; background: ${primary ? '#a0174f' : 'transparent'}; color: ${primary ? '#fff' : c.fg};`;
    return b;
  };
  const cancel = button(texts.cancel, false);
  const start = button(texts.start, true);
  start.dataset.action = 'start';
  cancel.dataset.action = 'cancel';
  row.append(cancel, start);
  box.append(h, p, status, row);
  root.append(box);
  document.documentElement.append(host);
  start.focus();

  let busy = false;
  cancel.addEventListener('click', () => { host.remove(); send({ cancel: true }); });
  start.addEventListener('click', async () => {
    if (busy) return;
    busy = true;
    start.disabled = true;
    status.textContent = texts.waiting;
    try {
      const publicKey = {
        challenge: fromB64url(req.challenge),
        rpId: req.rpId,
        timeout: req.timeout,
        userVerification: req.userVerification,
        allowCredentials: req.allowCredentials.map((a) => ({ type: 'public-key', id: fromB64url(a.id), ...(a.transports ? { transports: a.transports } : {}) })),
        ...(req.appid ? { extensions: { appid: req.appid } } : {}),
      };
      const cred = await navigator.credentials.get({ publicKey });
      const r = cred.response;
      const response = JSON.stringify({
        id: cred.id,
        rawId: toB64url(cred.rawId),
        type: cred.type,
        extensions: JSON.parse(JSON.stringify(cred.getClientExtensionResults?.() ?? {})),
        response: {
          authenticatorData: toB64url(r.authenticatorData),
          clientDataJson: toB64url(r.clientDataJSON),
          signature: toB64url(r.signature),
          ...(r.userHandle ? { userHandle: toB64url(r.userHandle) } : {}),
        },
      });
      status.textContent = texts.done;
      cancel.disabled = true;
      await send({ response });
    } catch (e) {
      status.textContent = texts.failed.replace('{msg}', e?.name || String(e));
      start.textContent = texts.retry;
      start.disabled = false;
      busy = false;
      start.focus();
    }
  });
  return 'shown';
}
