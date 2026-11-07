// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Login steps in a browser tab (Duo, the organization's sign-in): the server only sends the browser back to a fixed
// page of its web vault. OmniVault opens the tab, waits until it reaches that page, reads code and state from the
// address, closes the tab and finishes the login here – the popup has closed by then and picks up the outcome when
// it opens again. Reading the address needs no extra permission: it lies on the server the account already may
// reach (host permission). Everything stays in storage.session (memory only) and expires after a few minutes.
// A security key (WebAuthn, experimental) works the same way, except that OmniVault asks for it in the web vault's
// tab itself (see webauthn-2fa.js) and gets the answer as a message from there instead of from the address.
import { t } from '../i18n/index.js';
import { ext } from '../lib/browser.js';
import { promptTexts, webauthnPrompt } from './webauthn-2fa.js';

const KEY = 'loginFlows';
const MAX_AGE = 10 * 60_000;

async function flows() {
  const { [KEY]: all = {} } = await ext.storage.session.get(KEY).catch(() => ({}));
  const now = Date.now();
  for (const [id, f] of Object.entries(all)) if (now - f.at > MAX_AGE) delete all[id];
  return all;
}
const save = (all) => ext.storage.session.set({ [KEY]: all });

/** Same page (origin + path), whatever the query: the connector pages carry code and state there. */
export function isReturnPage(url, returnUrl) {
  try {
    const a = new URL(url); const b = new URL(returnUrl);
    return a.origin === b.origin && a.pathname.replace(/\/+$/, '') === b.pathname.replace(/\/+$/, '');
  } catch { return false; }
}

const originOf = (url) => { try { return new URL(url).origin; } catch { return null; } };
const nonce = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
/** An assertion is a few hundred bytes; anything far larger is not one. */
const MAX_RESPONSE = 64 * 1024;

/**
 * deps: { finish(accountId, pending, reply) → public outcome }, reply = { browserUrl } or { webauthnResponse }.
 * finish runs the provider's next step and returns what the popup should show; when that step needs more input, it
 * returns `pending` to keep.
 */
export function createLoginFlows({ finish }) {
  const busy = new Set();

  async function complete(accountId, reply) {
    if (busy.has(accountId)) return;
    busy.add(accountId);
    try {
      const all = await flows();
      const f = all[accountId];
      if (!f || f.phase !== 'browser') return;
      f.phase = 'working';
      await save(all);
      await ext.tabs.remove(f.tabId).catch(() => {});
      let outcome;
      try {
        outcome = await finish(accountId, f.pending, reply);
      } catch (e) {
        outcome = { status: 'error', error: e.message };
      }
      await settle(accountId, outcome);
    } finally {
      busy.delete(accountId);
    }
  }

  /** Stores what came out of a step: a new tab, more input (with the provider's pending state) or the end. */
  async function settle(accountId, outcome) {
    const all = await flows();
    if (outcome.status === 'needs_browser') {
      const b = outcome.browser;
      const tab = await ext.tabs.create({ url: b.url, active: true });
      all[accountId] = b.kind === 'webauthn'
        ? { phase: 'browser', kind: b.kind, tabId: tab.id, origin: b.origin, request: b.request, nonce: nonce(), pending: outcome.pending, at: Date.now() }
        : { phase: 'browser', kind: b.kind, tabId: tab.id, returnUrl: b.returnUrl, pending: outcome.pending, at: Date.now() };
      await save(all);
      if (b.kind === 'webauthn') {
        // the page may have loaded already (onUpdated then came before the flow was stored)
        const now = await ext.tabs.get(tab.id).catch(() => null);
        if (now?.status === 'complete') prompt(all[accountId], now.url);
      }
      return all[accountId];
    } else {
      const { pending, ...visible } = outcome;
      all[accountId] = { phase: 'done', outcome: visible, pending, at: Date.now() };
    }
    await save(all);
    return all[accountId];
  }

  /**
   * Security key: show OmniVault's box in the web vault's tab, only on the web vault's origin and only in the top frame
   * (checked here and again in the page, in case the tab navigated in between).
   */
  function prompt(f, url) {
    if (originOf(url) !== f.origin) return;
    const host = new URL(f.origin).host;
    ext.scripting.executeScript({
      target: { tabId: f.tabId, frameIds: [0] },
      func: webauthnPrompt,
      args: [f.request, promptTexts(host), f.nonce, f.origin],
    }).catch(() => {});
  }

  ext.tabs?.onUpdated?.addListener((tabId, change, tab) => {
    const url = change.url ?? tab?.url;
    if (!url) return;
    flows().then((all) => {
      for (const [accountId, f] of Object.entries(all)) {
        if (f.phase !== 'browser' || f.tabId !== tabId) continue;
        if (f.kind === 'webauthn') {
          if (change.status === 'complete') prompt(f, url);
        } else if (isReturnPage(url, f.returnUrl)) complete(accountId, { browserUrl: url });
      }
    }).catch(() => {});
  });

  ext.tabs?.onRemoved?.addListener((tabId) => {
    flows().then(async (all) => {
      let changed = false;
      for (const f of Object.values(all)) {
        if (f.phase === 'browser' && f.tabId === tabId) {
          Object.assign(f, { phase: 'done', outcome: { status: 'error', error: t('Der Tab wurde geschlossen, bevor die Anmeldung abgeschlossen war.') }, pending: undefined });
          changed = true;
        }
      }
      if (changed) await save(all);
    }).catch(() => {});
  });

  return {
    /**
     * Message from the box in the web vault's tab (content handler): the security key's answer or a cancel. Accepted only
     * from the flow's own tab, its top frame on the web vault's origin, with the flow's one-time nonce.
     */
    async webauthnReply(msg, sender) {
      const all = await flows();
      const from = originOf(sender.url);
      const hit = Object.entries(all).find(([, f]) => f.phase === 'browser' && f.kind === 'webauthn' && f.tabId === sender.tab?.id
        && (sender.frameId ?? 0) === 0 && from === f.origin && typeof msg?.nonce === 'string' && msg.nonce === f.nonce);
      if (!hit) return false;
      const [accountId] = hit;
      if (msg.cancel) {
        all[accountId] = { phase: 'done', outcome: { status: 'error', error: t('Anmeldung mit dem Sicherheitsschlüssel abgebrochen.') }, at: Date.now() };
        await save(all);
        await ext.tabs.remove(sender.tab.id).catch(() => {});
        return true;
      }
      if (typeof msg.response !== 'string' || !msg.response || msg.response.length > MAX_RESPONSE) return false;
      await complete(accountId, { webauthnResponse: msg.response });
      return true;
    },
    /** Opens the tab for a step that returned needs_browser. */
    start: (accountId, outcome) => settle(accountId, outcome),
    settle,
    /** What the popup shows: phase and outcome, never the pending secrets. */
    async status(accountId) {
      const f = (await flows())[accountId];
      if (!f) return null;
      return { phase: f.phase, kind: f.kind, outcome: f.outcome, awaitingInput: !!f.pending };
    },
    /** Pending state for the next step (taken: a step runs once). */
    async take(accountId) {
      const all = await flows();
      const f = all[accountId];
      if (!f?.pending || f.phase !== 'done') return null;
      delete all[accountId];
      await save(all);
      return f.pending;
    },
    /** The popup has shown the outcome. */
    async clear(accountId) {
      const all = await flows();
      const f = all[accountId];
      if (!f) return;
      if (f.phase === 'browser') await ext.tabs.remove(f.tabId).catch(() => {});
      delete all[accountId];
      await save(all);
    },
    /** Focus the open tab again (the user switched away). */
    async focus(accountId) {
      const f = (await flows())[accountId];
      if (f?.phase !== 'browser') return false;
      const tab = await ext.tabs.update(f.tabId, { active: true }).catch(() => null);
      if (tab?.windowId != null) await ext.windows?.update(tab.windowId, { focused: true }).catch(() => {});
      return !!tab;
    },
  };
}
