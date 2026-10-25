// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Passkeys on websites: OmniVault answers navigator.credentials.create()/get() for the page with passkeys
// kept in a vault that supports them (Bitwarden/Vaultwarden, in Bitwarden's own format).
//
// Flow: page script (MAIN world) → bridge (content script) → `ovPasskey` here. If OmniVault has nothing to
// offer (no passkey for the site, no account that can store one, unsupported options), the page script hands
// the call to the browser unchanged ("fallback"). Otherwise the bridge shows the passkey dialog (an extension
// page in an iframe); the user's choice (`passkeyChoose`) creates or signs here, and the result goes back to
// the page through the bridge. The page never sees account data, and the origin always comes from the
// browser (sender), never from the page.
//
// Embedded frames (Chromium): a request from an iframe is served only when the background itself can confirm,
// in the frame's isolated world (which the page cannot script), that the Permissions Policy allows WebAuthn
// there, which origins it is nested in, and – for creating in a cross-origin frame – that the user just
// interacted with it. The origins come from the browser (sender, tab, location.ancestorOrigins), the dialog stays
// in the top frame and names both origins, and clientDataJSON carries crossOrigin and topOrigin. Where this
// cannot be confirmed (Firefox has neither document.featurePolicy nor location.ancestorOrigins), the browser
// handles the request.
//
// Extensions: credProps is answered. PRF (hmac-secret) and largeBlob are not offered: Bitwarden's passkey
// format (login.fido2Credentials) has no field for a PRF secret or a blob, so the Bitwarden apps would drop
// either and the passkey would silently change its PRF output or lose its blob. The site learns this as the
// standard foresees (prf.enabled false, largeBlob.supported false); a site that requires largeBlob goes to the
// browser.
//
// User verification: like the Bitwarden extension, a choice made in an unlocked OmniVault counts as verified
// (the user unlocked with the master password or PIN and acted in the dialog).
import { t } from '../i18n/index.js';
import { ext } from '../lib/browser.js';
import { fromB64, hex, utf8 } from '../lib/bytes.js';
import { hostOf, matchesUrl } from '../lib/match.js';
import { isRegistrableSuffixOf } from '../lib/psl.js';
import {
  ES256, clientDataJSON, createPasskey, credentialIdBytes, sameBytes, sha256, signAssertion,
} from '../lib/webauthn.js';

const REQUESTS = 'passkeyRequests'; // storage.session: open requests (survive a sleeping service worker)
const INDEX = 'passkeyIndex'; // storage.local: salted hashes of the sites with passkeys, per account (for locked accounts)
const MAX_AGE = 10 * 60_000;

/* ---------- checks without state (unit-tested) ---------- */

/** The page's origin if WebAuthn may run there: https, or http on localhost (a secure context). */
export function pageOrigin(url) {
  let u;
  try { u = new URL(url); } catch { return null; }
  if (u.protocol === 'https:') return u;
  if (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname.endsWith('.localhost') || u.hostname === '127.0.0.1')) return u;
  return null;
}

/** Permissions Policy feature a request needs in an iframe. */
export const frameFeature = (kind) => (kind === 'create' ? 'publickey-credentials-create' : 'publickey-credentials-get');

/**
 * Whether a request from an iframe may be served, from what the browser says about it:
 *   frameUrl / senderOrigin  sender.url and sender.origin of the message (the frame)
 *   tabUrl                   URL of the tab (the top-level page)
 *   inspected                what a script in the frame's isolated world found: { origin, ancestors (location.
 *                            ancestorOrigins, nearest first), allowed (Permissions Policy), active (user activation) },
 *                            null when the browser cannot tell
 * Returns { ok: true, crossOrigin, topOrigin } or { ok: false, reason }.
 */
export function checkFrame({ kind, frameUrl, senderOrigin, tabUrl, inspected }) {
  if (!inspected || !Array.isArray(inspected.ancestors) || !inspected.ancestors.length) return { ok: false, reason: 'frame-unknown' };
  const frame = pageOrigin(frameUrl);
  const top = pageOrigin(tabUrl);
  if (!frame || !top) return { ok: false, reason: 'insecure' };
  if (!senderOrigin || senderOrigin !== frame.origin || inspected.origin !== frame.origin) return { ok: false, reason: 'frame-origin' };
  const { ancestors } = inspected;
  if (ancestors[ancestors.length - 1] !== top.origin) return { ok: false, reason: 'top-origin' };
  if (ancestors.some((a) => !pageOrigin(a) || new URL(a).origin !== a)) return { ok: false, reason: 'insecure' };
  if (inspected.allowed !== true) return { ok: false, reason: 'policy' };
  const crossOrigin = ancestors.some((a) => a !== frame.origin);
  // creating in a cross-origin frame needs a user gesture in that frame (WebAuthn Level 3, §5.1.3)
  if (crossOrigin && kind === 'create' && inspected.active !== true) return { ok: false, reason: 'activation' };
  return { ok: true, crossOrigin, topOrigin: top.origin };
}

/**
 * Whether OmniVault can take this request, and for which relying party. `options` are the page's
 * PublicKeyCredentialCreationOptions / RequestOptions in JSON form (binary values base64url).
 * Returns { ok: true, rpId, origin } or { ok: false, reason } (then the browser handles it).
 */
export function checkRequest({ kind, options, url }) {
  const u = pageOrigin(url);
  if (!u) return { ok: false, reason: 'insecure' };
  if (!options || typeof options.challenge !== 'string' || !options.challenge) return { ok: false, reason: 'challenge' };
  const rpId = String((kind === 'create' ? options.rp?.id : options.rpId) ?? u.hostname).toLowerCase();
  if (!isRegistrableSuffixOf(rpId, u.hostname)) return { ok: false, reason: 'rpId' };
  if (kind === 'create') {
    if (!options.user || typeof options.user.id !== 'string') return { ok: false, reason: 'user' };
    const algs = (options.pubKeyCredParams ?? []).filter((p) => p?.type === 'public-key').map((p) => p.alg);
    if (options.pubKeyCredParams?.length && !algs.includes(ES256)) return { ok: false, reason: 'algorithm' };
    if (options.authenticatorSelection?.authenticatorAttachment === 'cross-platform') return { ok: false, reason: 'attachment' };
    if (options.extensions?.largeBlob?.support === 'required') return { ok: false, reason: 'largeBlob' };
  }
  return { ok: true, rpId, origin: u.origin };
}

/** Passkeys of the items for the relying party, optionally restricted to the ids the site allows. */
export function matchingPasskeys(items, rpId, allowIds = []) {
  const allow = allowIds.map((id) => fromB64(id));
  const out = [];
  for (const item of items) {
    for (const passkey of item.passkeys ?? []) {
      if (passkey.rpId !== rpId) continue;
      if (allow.length) {
        const id = credentialIdBytes(passkey.credentialId);
        if (!id || !allow.some((a) => sameBytes(a, id))) continue;
      }
      out.push({ item, passkey });
    }
  }
  return out;
}

/**
 * Client extension results for the extensions OmniVault answers or declines (see the head of this file).
 * `requested` is the page's extensions in JSON form, `rk` whether a new passkey is discoverable.
 */
export function extensionResults(kind, requested = {}, { rk = false } = {}) {
  const out = {};
  if (kind === 'create') {
    if (requested.credProps) out.credProps = { rk };
    if (requested.prf) out.prf = { enabled: false };
    if (requested.largeBlob) out.largeBlob = { supported: false };
  } else if (requested.largeBlob?.write) out.largeBlob = { written: false };
  else if (requested.largeBlob) out.largeBlob = {};
  return out;
}

/* ---------- the service ---------- */

/**
 * deps.accounts()                  → all accounts
 * deps.provider(account)           → provider class
 * deps.entry(account)              → synced { items } of an unlocked account, null when locked
 * deps.save(accountId, item, data) → saves (item null = new); returns the saved item
 * deps.toTab(tabId, message, frameId = 0) → sends to the bridge in a frame of the tab; resolves to its answer (null on failure)
 * deps.inspectFrame(tabId, frameId, feature) → what the frame's isolated world reports (see checkFrame), null if unknown
 */
export function createPasskeyService(deps) {
  async function requests() {
    const { [REQUESTS]: all = {} } = await ext.storage.session.get(REQUESTS);
    for (const [id, r] of Object.entries(all)) if (Date.now() - r.at > MAX_AGE) delete all[id];
    return all;
  }
  const store = (all) => ext.storage.session.set({ [REQUESTS]: all });

  async function request(id, sender) {
    const r = (await requests())[id];
    if (!r) throw new Error(t('Die Anfrage der Seite ist abgelaufen.'));
    if (sender && sender.tab?.id !== r.tabId) throw new Error(t('Die Anfrage gehört zu einem anderen Tab.'));
    return r;
  }

  /** Ends a request and hands the result (credential, fallback or error name) to the page. */
  async function finish(id, result) {
    const all = await requests();
    const r = all[id];
    if (!r) return;
    delete all[id];
    await store(all);
    await deps.toTab(r.tabId, { type: 'ov-passkey-result', requestId: id, result }, r.frameId ?? 0);
    if (r.frameId) await deps.toTab(r.tabId, { type: 'ov-passkey-close', requestId: id }, 0);
    if (r.conditional) await deps.toTab(r.tabId, { type: 'ov-inline-close' });
  }

  /* site index for locked accounts: salted SHA-256 of each rpId, so nothing readable is stored */
  async function siteHash(rpId) {
    let { [INDEX]: index } = await ext.storage.local.get(INDEX);
    if (!index?.salt) {
      index = { salt: hex(globalThis.crypto.getRandomValues(new Uint8Array(16))), accounts: index?.accounts ?? {} };
      await ext.storage.local.set({ [INDEX]: index });
    }
    return { index, hash: hex(await sha256(utf8(`${index.salt}\n${rpId}`))).slice(0, 24) };
  }
  async function indexAccount(accountId, items) {
    const sites = [...new Set(items.flatMap((i) => (i.passkeys ?? []).map((p) => p.rpId)).filter(Boolean))];
    const hashes = [];
    let index;
    for (const s of sites) { const h = await siteHash(s); index = h.index; hashes.push(h.hash); }
    index ??= (await ext.storage.local.get(INDEX))[INDEX] ?? { accounts: {} };
    const before = JSON.stringify(index.accounts?.[accountId] ?? []);
    if (before === JSON.stringify(hashes)) return;
    index.accounts = { ...(index.accounts ?? {}), [accountId]: hashes };
    await ext.storage.local.set({ [INDEX]: index });
  }
  async function forgetAccount(accountId) {
    const { [INDEX]: index } = await ext.storage.local.get(INDEX);
    if (!index?.accounts?.[accountId]) return;
    delete index.accounts[accountId];
    await ext.storage.local.set({ [INDEX]: index });
  }

  /** Accounts that can hold passkeys, with what they have for the request. */
  async function survey(r) {
    const out = { unlocked: [], locked: [], candidates: [], targets: [], excluded: false };
    const { hash } = await siteHash(r.rpId);
    const { [INDEX]: index } = await ext.storage.local.get(INDEX);
    for (const account of await deps.accounts()) {
      const caps = deps.provider(account).capabilities ?? {};
      if (!caps.passkeys) continue;
      const entry = await deps.entry(account);
      if (!entry) {
        out.locked.push({ account, maybe: (index?.accounts?.[account.id] ?? []).includes(hash) });
        continue;
      }
      out.unlocked.push(account);
      const items = entry.items.filter((i) => i.type === 'login');
      if (r.kind === 'get') {
        for (const m of matchingPasskeys(items, r.rpId, (r.options.allowCredentials ?? []).map((c) => c.id))) out.candidates.push({ account, ...m });
      } else {
        if (matchingPasskeys(items, r.rpId, (r.options.excludeCredentials ?? []).map((c) => c.id)).length && r.options.excludeCredentials?.length) out.excluded = true;
        if (caps.write && !entry.readOnly) {
          out.targets.push({ account, item: null });
          for (const item of items) if (item.canEdit !== false && matchesUrl(item, r.origin)) out.targets.push({ account, item });
        }
      }
    }
    return out;
  }

  const label = (account) => ({ accountId: account.id, accountLabel: account.label, accountShort: account.short, accountHue: account.hue });

  /** A new request from a page. Answers what the page script should do: fallback, dialog or conditional. */
  async function begin({ kind, options, mediation }, sender) {
    if (!sender.tab?.id) return { action: 'fallback' };
    const frameId = sender.frameId ?? 0;
    let frame = { crossOrigin: false, topOrigin: null };
    if (frameId) {
      // autofill suggestions live in the top frame's fields only
      if (mediation === 'conditional' || mediation === 'silent') return { action: 'fallback', reason: 'frame-mediation' };
      const inspected = deps.inspectFrame ? await deps.inspectFrame(sender.tab.id, frameId, frameFeature(kind)).catch(() => null) : null;
      frame = checkFrame({ kind, frameUrl: sender.url, senderOrigin: sender.origin, tabUrl: sender.tab.url, inspected });
      if (!frame.ok) return { action: 'fallback', reason: frame.reason };
    }
    const check = checkRequest({ kind, options, url: sender.url ?? sender.tab?.url });
    if (!check.ok) return { action: 'fallback', reason: check.reason };
    if (kind === 'get' && mediation === 'silent') return { action: 'fallback' };
    const r = {
      id: globalThis.crypto.randomUUID(), tabId: sender.tab.id, frameId, at: Date.now(), kind, options, rpId: check.rpId,
      origin: check.origin, crossOrigin: frame.crossOrigin, topOrigin: frame.crossOrigin ? frame.topOrigin : null,
      conditional: kind === 'get' && mediation === 'conditional',
    };
    const s = await survey(r);
    if (kind === 'create' && !s.unlocked.length && !s.locked.length) return { action: 'fallback', reason: 'no-account' };
    if (kind === 'get' && !s.candidates.length && !s.locked.some((l) => l.maybe)) return { action: 'fallback', reason: 'none' };
    if (r.conditional && !s.candidates.length) return { action: 'fallback', reason: 'locked' };
    const all = await requests();
    for (const [id, other] of Object.entries(all)) {
      // one dialog per tab: a new request ends the previous one (the page gave up on it)
      if (other.tabId === r.tabId && !(other.conditional && !r.conditional)) {
        delete all[id];
        deps.toTab(other.tabId, { type: 'ov-passkey-result', requestId: id, result: { error: 'AbortError' } }, other.frameId ?? 0);
        if (other.frameId) deps.toTab(other.tabId, { type: 'ov-passkey-close', requestId: id }, 0);
      }
    }
    all[r.id] = r;
    await store(all);
    if (frameId) {
      // the dialog opens in the top frame, never inside the (possibly foreign) embedded frame
      const shown = await deps.toTab(r.tabId, { type: 'ov-passkey-show', requestId: r.id }, 0);
      if (!shown?.shown) {
        delete all[r.id];
        await store(all);
        return { action: 'fallback', reason: 'no-top-bridge' };
      }
    }
    return { action: r.conditional ? 'conditional' : 'dialog', requestId: r.id };
  }

  /** What the dialog shows. */
  async function info({ requestId }, sender) {
    const r = await request(requestId, sender);
    const s = await survey(r);
    const o = r.options;
    return {
      kind: r.kind, rpId: r.rpId, rpName: o.rp?.name || r.rpId, host: hostOf(r.origin),
      frame: r.crossOrigin ? { origin: new URL(r.origin).host, top: new URL(r.topOrigin).host } : null,
      user: r.kind === 'create' ? { name: o.user.name ?? '', displayName: o.user.displayName ?? '' } : null,
      excluded: s.excluded,
      locked: s.locked.map((l) => ({ ...label(l.account), maybe: l.maybe })),
      candidates: s.candidates.map((c) => ({
        ...label(c.account), itemId: c.item.id, credentialId: c.passkey.credentialId, name: c.item.name,
        userName: c.passkey.userName || c.item.username || '', userDisplayName: c.passkey.userDisplayName || '',
      })),
      targets: s.targets.map((x) => ({
        ...label(x.account), itemId: x.item?.id ?? null, name: x.item?.name ?? null, username: x.item?.username ?? '',
        hasPasskey: !!x.item?.passkeys?.length,
      })),
    };
  }

  async function register(r, { accountId, itemId }) {
    const s = await survey(r);
    const target = s.targets.find((x) => x.account.id === accountId && (x.item?.id ?? null) === (itemId ?? null));
    if (!target) throw new Error(t('Dieses Ziel ist nicht mehr verfügbar.'));
    if (s.excluded) throw new Error(t('Für diese Seite ist schon ein Passkey gespeichert.'));
    const o = r.options;
    const sel = o.authenticatorSelection ?? {};
    // stored as the site asked (Bitwarden does the same); OmniVault offers every passkey of the site either way
    const discoverable = sel.requireResidentKey === true || ['required', 'preferred'].includes(sel.residentKey);
    const clientData = clientDataJSON({ type: 'webauthn.create', challenge: o.challenge, origin: r.origin, crossOrigin: r.crossOrigin, topOrigin: r.topOrigin });
    const { record, response } = await createPasskey({
      rpId: r.rpId, rpName: o.rp?.name, user: { id: fromB64(o.user.id), name: o.user.name, displayName: o.user.displayName },
      discoverable, clientData, userVerified: true,
    });
    const item = target.item;
    if (item) {
      // Bitwarden keeps one passkey per login: a new one replaces the old
      await deps.save(accountId, item, {
        type: 'login', name: item.name, username: item.username || o.user.name || '', password: item.password ?? '',
        totp: item.totp ?? '', uris: item.uris ?? [], passkeys: [record],
      });
    } else {
      await deps.save(accountId, null, {
        type: 'login', name: o.rp?.name || r.rpId, username: o.user.name ?? '', password: '', uris: [r.origin], passkeys: [record],
      });
    }
    return {
      credential: {
        id: response.id, type: 'public-key', authenticatorAttachment: 'platform', response,
        clientExtensionResults: extensionResults('create', o.extensions, { rk: discoverable }),
      },
    };
  }

  async function authenticate(r, { accountId, itemId, credentialId }) {
    const s = await survey(r);
    const c = s.candidates.find((x) => x.account.id === accountId && x.item.id === itemId && x.passkey.credentialId === credentialId);
    if (!c) throw new Error(t('Dieser Passkey ist nicht mehr verfügbar.'));
    const keyValue = c.item._passkeyKeys?.[credentialId];
    if (!keyValue) throw new Error(t('Der Schlüssel dieses Passkeys ist nicht verfügbar.'));
    // like Bitwarden: a counter that never left 0 stays 0 (synced passkeys); otherwise it counts up and is saved
    let counter = Number(c.passkey.counter) || 0;
    if (counter > 0) {
      counter += 1;
      const passkeys = c.item.passkeys.map((p) => ({
        ...p, keyValue: c.item._passkeyKeys[p.credentialId], counter: p.credentialId === credentialId ? String(counter) : p.counter,
      }));
      await deps.save(accountId, c.item, {
        type: 'login', name: c.item.name, username: c.item.username ?? '', password: c.item.password ?? '',
        totp: c.item.totp ?? '', uris: c.item.uris ?? [], passkeys,
      });
    }
    const clientData = clientDataJSON({ type: 'webauthn.get', challenge: r.options.challenge, origin: r.origin, crossOrigin: r.crossOrigin, topOrigin: r.topOrigin });
    const response = await signAssertion({ record: { ...c.passkey, keyValue }, clientData, userVerified: true, counter });
    return {
      credential: { id: response.id, type: 'public-key', authenticatorAttachment: 'platform', response, clientExtensionResults: extensionResults('get', r.options.extensions) },
    };
  }

  /** The user's choice in the dialog (or in the list of a login field, for conditional requests). */
  async function choose({ requestId, choice }, sender) {
    const r = await request(requestId, sender);
    const result = r.kind === 'create' ? await register(r, choice) : await authenticate(r, choice);
    await finish(requestId, result);
    return true;
  }

  return {
    pageOrigin,
    indexAccount,
    forgetAccount,
    /** Passkeys for the open conditional request of a tab (shown in the list of a login field). */
    async conditionalOffer(tabId) {
      const r = Object.values(await requests()).find((x) => x.tabId === tabId && x.conditional);
      if (!r) return null;
      const s = await survey(r);
      return {
        requestId: r.id,
        passkeys: s.candidates.map((c) => ({
          ...label(c.account), itemId: c.item.id, credentialId: c.passkey.credentialId, name: c.item.name,
          userName: c.passkey.userName || c.item.username || '',
        })),
      };
    },
    contentHandlers: {
      ovPasskey: (msg, sender) => begin(msg, sender),
      /** Whether OmniVault can hold passkeys at all (an account whose service stores them, locked or not). */
      async ovPasskeyCapable() {
        for (const a of await deps.accounts()) if (deps.provider(a).capabilities?.passkeys) return { capable: true };
        return { capable: false };
      },
      /** Whether a login field should offer passkeys right now (a conditional request with matches is open). */
      async ovPasskeyOffer(_msg, sender) {
        const r = Object.values(await requests()).find((x) => x.tabId === sender.tab?.id && x.conditional);
        return { pending: !!r };
      },
      /** The page aborted, or its own browser dialog answered a conditional request first. */
      async ovPasskeyEnd({ requestId }, sender) {
        const all = await requests();
        const r = all[requestId];
        if (r?.tabId !== sender.tab?.id || (r.frameId ?? 0) !== (sender.frameId ?? 0)) return false;
        delete all[requestId];
        await store(all);
        if (r.frameId) await deps.toTab(r.tabId, { type: 'ov-passkey-close', requestId }, 0);
        return true;
      },
    },
    handlers: {
      passkeyInfo: info,
      passkeyChoose: choose,
      /** Dialog closed: `fallback` hands the request to the browser (security key, phone, its own passkeys). */
      async passkeyCancel({ requestId, fallback = false }, sender) {
        const r = await request(requestId, sender);
        // a site that already has this passkey learns that (InvalidStateError), as the standard asks
        const excluded = !fallback && r.kind === 'create' && (await survey(r)).excluded;
        await finish(requestId, fallback ? { fallback: true } : { error: excluded ? 'InvalidStateError' : 'NotAllowedError' });
        return true;
      },
    },
  };
}
