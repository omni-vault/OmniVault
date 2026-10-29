// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Background router: the only place that holds keys and decrypted items.
import { browserLanguages, language, resolveLanguage, setLanguage, t, tn } from '../i18n/index.js';
import { ext } from '../lib/browser.js';
import { generateSecret } from '../lib/generator.js';
import { matchesUrl } from '../lib/match.js';
import { totp } from '../lib/totp.js';
import { describeProviders, getProvider, registry } from '../providers/registry.js';
import * as store from './accounts.js';
import { fillBestInTab, fillFrame, fillTab, forgetPairs, hostLabel, insertIntoFocused, loginFrames, rememberGenerated, showNotice, trustedPairs } from './autofill.js';
import { applyLocalFavorites, forgetLocalFavorites, writer } from './favorites.js';
import { clearClipboardNow, handleAlarm as clipboardAlarm, scheduleClipboardClear, writeClipboard } from './clipboard.js';
import { getSettings, setSettings } from './settings.js';
import { findDuplicates } from '../lib/dupes.js';
import { createDeviceLock, unsealWithDevice } from '../lib/devicelock.js';
import { createPinLock, seal, unseal } from '../lib/pinlock.js';
import { toBitwardenJson, toCsv } from '../lib/export.js';
import { weakness } from '../lib/strength.js';
import { HIBP_ORIGIN, breachCounts } from '../lib/hibp.js';
import { deleteItems, importItems, mirrorTargetSet, passkeysWithKeys, runMirrorRule, transferItems, transferLoss, validateRule } from './tools.js';
import { createPasskeyService } from './passkeys.js';
import { createLoginFlows } from './login-flow.js';

/** Decrypted items per account – memory only, rebuilt from the session after a worker restart. */
const cache = new Map(); // accountId -> { items, folders, syncedAt, error, warning }

const cfg = (account) => ({ ...account.config, id: account.id });

/** Progress of long syncs (providers that read entry by entry report it): accountId → { done, total }. */
const syncProgress = new Map();
for (const p of Object.values(registry)) {
  if ('onProgress' in p) p.onProgress = (id, done, total) => syncProgress.set(id, { done, total });
}

async function ensureSynced(account, force = false) {
  const cached = cache.get(account.id);
  if (cached && !force) return cached;
  const session = await store.getSession(account.id);
  if (!session) { cache.delete(account.id); return null; }
  const provider = getProvider(account.provider);
  try {
    syncProgress.delete(account.id);
    const result = await provider.sync(cfg(account), session).finally(() => syncProgress.delete(account.id));
    if (result.session) await store.setSession(account.id, result.session);
    await applyLocalFavorites(provider, account.id, result.items);
    const entry = { items: result.items, trash: result.trash ?? [], folders: result.folders ?? [], organizations: result.organizations ?? [], syncedAt: Date.now(), error: null, warning: result.warning ?? null, readOnly: !!result.readOnly };
    cache.set(account.id, entry);
    if (provider.capabilities?.passkeys) passkeys.indexAccount(account.id, result.items).catch(() => {});
    return entry;
  } catch (e) {
    if (e.code === 'session_expired') await lock(account.id);
    const entry = { items: cached?.items ?? [], trash: cached?.trash ?? [], folders: cached?.folders ?? [], organizations: cached?.organizations ?? [], syncedAt: cached?.syncedAt, error: e.message, readOnly: cached?.readOnly };
    cache.set(account.id, entry);
    return entry;
  }
}

/**
 * One step of a login: the provider's answer, with the session stored and the account synced when it is done.
 * Returns what the popup may see plus `pending` (kept here) and `browser` (a tab to open).
 */
async function loginStep(id, creds) {
  const account = await store.getAccount(id);
  const provider = getProvider(account.provider);
  const res = await provider.login(cfg(account), creds);
  await store.patchAccountConfig(id, res.configPatch);
  if (res.status !== 'ok') {
    return { status: res.status, twoFactorProviders: res.twoFactorProviders, hint: res.hint, pending: res.pending, browser: res.browser };
  }
  await store.setSession(id, res.session);
  const entry = await ensureSynced(await store.getAccount(id), true);
  return { status: 'ok', itemCount: entry?.items.length ?? 0, error: entry?.error };
}

const loginFlows = createLoginFlows({
  finish: (id, pending, browserUrl) => loginStep(id, { pending, browserUrl }),
});

async function lock(id) {
  cache.delete(id);
  forgetEmergency(id);
  await loginFlows.clear(id); // a login half done (master key after Duo, tokens after SSO) goes as well
  await store.clearSession(id);
}

/**
 * Locks every account. With a PIN or the device set up, the open sessions are sealed first (once per method, each
 * with its own key pair) so the PIN or the device can reopen them.
 */
async function lockAll() {
  const { pinLock, deviceLock } = await ext.storage.local.get(['pinLock', 'deviceLock']);
  if (pinLock || deviceLock) {
    const sessions = {};
    for (const a of await store.listAccounts()) {
      const s = await store.getSession(a.id);
      if (s) sessions[a.id] = s;
    }
    if (Object.keys(sessions).length) {
      await ext.storage.session.set({
        ...(pinLock ? { pinSealed: await seal(pinLock, sessions), pinAttempts: 0 } : {}),
        ...(deviceLock ? { deviceSealed: await seal(deviceLock, sessions) } : {}),
      });
    }
  }
  for (const a of await store.listAccounts()) await lock(a.id);
}

const PIN_ATTEMPTS = 5;
async function pinStatus() {
  const { pinLock } = await ext.storage.local.get('pinLock');
  const { pinSealed } = await ext.storage.session.get('pinSealed');
  return { configured: !!pinLock, sealed: !!(pinLock && pinSealed) };
}
async function deviceStatus() {
  const { deviceLock } = await ext.storage.local.get('deviceLock');
  const { deviceSealed } = await ext.storage.session.get('deviceSealed');
  return { configured: !!deviceLock, sealed: !!(deviceLock && deviceSealed) };
}
/** Puts back the sessions opened with the PIN or the device; both seals go, whichever opened them. */
async function restoreSealed(sessions) {
  await ext.storage.session.remove(['pinSealed', 'pinAttempts', 'deviceSealed']);
  let n = 0;
  for (const a of await store.listAccounts()) {
    if (!sessions[a.id]) continue;
    await store.setSession(a.id, sessions[a.id]);
    await ensureSynced(a, true);
    n++;
  }
  return { unlocked: n };
}

/* ---------- auto-lock ---------- */

const AUTOLOCK = 'autolock';
async function touch() {
  await ext.storage.session.set({ lastActivity: Date.now() });
}
async function checkAutoLock() {
  const { autoLockMinutes } = await getSettings();
  if (!autoLockMinutes) return;
  const { lastActivity = Date.now() } = await ext.storage.session.get('lastActivity');
  if (Date.now() - lastActivity >= autoLockMinutes * 60_000) await lockAll();
}
/**
 * Creates a repeating alarm unless one with the same period exists. The worker runs this code on every start; an
 * alarm created anew would start its period over each time, and a worker that wakes up more often than the period
 * (other alarms, messages) would push it back for ever.
 */
async function ensureAlarm(name, periodInMinutes) {
  const existing = await ext.alarms?.get(name);
  if (existing?.periodInMinutes === periodInMinutes) return;
  await ext.alarms?.create(name, { periodInMinutes });
}
ensureAlarm(AUTOLOCK, 1).catch(() => {});
ext.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK) checkAutoLock();
  else if (alarm.name === 'autosync') autoSync().catch((e) => console.warn('OmniVault: Abgleich fehlgeschlagen', e));
  else clipboardAlarm(alarm);
});
ext.idle?.onStateChanged.addListener(async (state) => {
  if (state === 'locked' && (await getSettings()).lockOnSystemLock) lockAll();
});

/* ---------- items ---------- */

/** Item without secrets, for listing in the popup. */
function publicItem(i, tabUrl, frameOrigins = []) {
  const matches = tabUrl ? matchesUrl(i, tabUrl) : false;
  return {
    id: i.id, accountId: i.accountId, provider: i.provider, type: i.type,
    name: i.name, username: i.username, uris: i.uris, folder: i.folder, folderId: i.folderId ?? null, favorite: i.favorite,
    subtitle: i.subtitle, revisionDate: i.revisionDate,
    hasPassword: i.lazy ? !!i.hasPassword : !!i.password,
    hasTotp: i.lazy ? !!i.hasTotp : !!i.totp,
    hasPasskey: !!i.passkeys?.length,
    canEdit: i.canEdit !== false,
    matches,
    // a login frame embedded in the tab (another origin than the page) this login belongs to
    frameMatch: !matches && i.type === 'login' ? (frameOrigins.find((o) => matchesUrl(i, o)) ?? null) : null,
  };
}

/** Item with everything the detail view shows; internal provider data (raw ciphertexts) stripped. */
function fullItem(i) {
  return Object.fromEntries(Object.entries(i).filter(([k]) => !k.startsWith('_') && k !== 'secretArmored'));
}

async function findItem(accountId, itemId) {
  const account = await store.getAccount(accountId);
  const entry = await ensureSynced(account);
  const item = entry?.items.find((i) => i.id === itemId);
  if (!item) throw new Error(t('Eintrag nicht gefunden oder Tresor gesperrt'));
  if (item.lazy && !item.revealed) {
    // Providers like Passbolt decrypt each secret only when it is actually needed.
    const session = await store.getSession(accountId);
    if (!session) throw new Error(t('Tresor gesperrt'));
    const extra = await getProvider(account.provider).reveal(cfg(account), session, item);
    Object.assign(item, extra, { revealed: true });
  }
  return { item, account, entry };
}

/** Run a provider write operation and keep session + cache in sync. */
/** Runs a Send call for an unlocked account whose provider has Send; keeps a renewed session. */
async function sendCall(accountId, fn, { write: writes = false } = {}) {
  const account = await store.getAccount(accountId);
  if (!account) throw new Error(t('Konto nicht gefunden'));
  const session = await store.getSession(accountId);
  if (!session) throw new Error(t('Tresor gesperrt'));
  const provider = getProvider(account.provider);
  if (!provider.capabilities?.send) throw new Error(t('Send wird für diesen Anbieter nicht unterstützt'));
  if (writes && (cache.get(accountId) ?? await ensureSynced(account))?.readOnly) {
    throw new Error(t('{account} kann OmniVault nur lesen.', { account: account.label }));
  }
  const res = await fn(provider, account, session);
  if (res?.session) await store.setSession(accountId, res.session);
  return res;
}

/*
 * Emergency access (as trusted contact, view only). The grantor's items live only here, in memory, apart from the
 * account's own items: they are not searched, filled, exported or mirrored, and they go when the account locks.
 */
const emergencyViews = new Map(); // "accountId\u0000grantId" → { items, at }
const EMERGENCY_TTL = 10 * 60_000;
const emergencyKey = (accountId, grantId) => `${accountId}\u0000${grantId}`;
function forgetEmergency(accountId) {
  for (const k of emergencyViews.keys()) if (k.startsWith(`${accountId}\u0000`)) emergencyViews.delete(k);
}

async function emergencyCall(accountId, fn) {
  const account = await store.getAccount(accountId);
  if (!account) throw new Error(t('Konto nicht gefunden'));
  const session = await store.getSession(accountId);
  if (!session) throw new Error(t('Tresor gesperrt'));
  const provider = getProvider(account.provider);
  if (!provider.capabilities?.emergencyAccess) throw new Error(t('Notfallzugriff wird für diesen Anbieter nicht unterstützt'));
  const res = await fn(provider, account, session);
  if (res?.session) await store.setSession(accountId, res.session);
  return res;
}

async function emergencyItems(accountId, grantId, { reload = false } = {}) {
  const k = emergencyKey(accountId, grantId);
  const hit = emergencyViews.get(k);
  if (hit && !reload && Date.now() - hit.at < EMERGENCY_TTL) return hit;
  const res = await emergencyCall(accountId, (p, a, s) => p.viewEmergencyAccess(cfg(a), s, grantId));
  const entry = { items: res.items, failed: res.failed, at: Date.now() };
  emergencyViews.set(k, entry);
  setTimeout(() => { if (emergencyViews.get(k) === entry) emergencyViews.delete(k); }, EMERGENCY_TTL);
  return entry;
}

async function write(accountId, fn) {
  const account = await store.getAccount(accountId);
  const session = await store.getSession(accountId);
  if (!session) throw new Error(t('Tresor gesperrt'));
  const provider = writer(getProvider(account.provider), accountId);
  if (!provider.capabilities?.write) throw new Error(t('{provider}: Bearbeiten wird nicht unterstützt', { provider: provider.label }));
  // an account the provider can only read (e.g. Bitwarden's new encryption format): no writes at all
  if ((cache.get(accountId) ?? await ensureSynced(account))?.readOnly) {
    throw new Error(t('{account} kann OmniVault nur lesen.', { account: account.label }));
  }
  const res = await fn(provider, account, session);
  if (res?.session) await store.setSession(accountId, res.session);
  const entry = cache.get(accountId) ?? await ensureSynced(account);
  if (entry && res?.folder && !entry.folders.some((f) => f.id === res.folder.id)) {
    entry.folders = [...entry.folders, res.folder].sort((a, b) => a.name.localeCompare(b.name, 'de'));
  }
  if (entry && res?.item?.folderId) {
    const folder = entry.folders?.find((f) => f.id === res.item.folderId);
    if (!res.item.folder) res.item.folder = folder?.name;
    if (folder && 'canShare' in folder) res.item.canShareFolder = !!folder.canShare;
  }
  if (entry && res?.item) {
    const idx = entry.items.findIndex((i) => i.id === res.item.id);
    if (idx >= 0) entry.items[idx] = res.item; else entry.items.push(res.item);
  }
  if (entry && res?.deletedId) {
    const gone = entry.items.find((i) => i.id === res.deletedId);
    entry.items = entry.items.filter((i) => i.id !== res.deletedId);
    // providers with a trash keep the item there (shown in Tools → Trash until the next sync says otherwise)
    if (gone && provider.capabilities?.restore) entry.trash = [{ ...gone, deletedDate: new Date().toISOString() }, ...(entry.trash ?? [])];
  }
  if (entry && (res?.purgedId || res?.item)) entry.trash = (entry.trash ?? []).filter((i) => i.id !== res.purgedId && i.id !== res.item?.id);
  if (res?.resync) await ensureSynced(account, true); // provider could not tell the new id
  else if (entry && provider.capabilities?.passkeys) await passkeys.indexAccount(accountId, entry.items).catch(() => {});
  return res;
}

/** All items of all unlocked accounts, without secrets, labelled with their account. */
async function allItems(tabUrl, frameOrigins) {
  const out = [];
  for (const a of await store.listAccounts()) {
    const entry = await ensureSynced(a);
    for (const i of entry?.items ?? []) out.push({ ...publicItem(i, tabUrl, frameOrigins), accountLabel: a.label, accountShort: a.short, accountHue: a.hue });
  }
  return out;
}

/** Current TOTP code of a login (secret in the item, or from providers that only hand out the code), or null. */
async function currentTotp(item, account) {
  if (item.totp) return totp(item.totp);
  const provider = getProvider(account.provider);
  if (item.hasTotp && provider.currentTotp) return provider.currentTotp(cfg(account), await store.getSession(account.id), item);
  return null;
}

/**
 * After a login was really filled (`filled` > 0; not when the result only asks for a confirmation, or the form was
 * hidden or out of reach): with the setting "copy TOTP after filling", its current code goes to the clipboard
 * (cleared after the usual delay) and a short note says so – in the top page, together with the note naming an
 * embedded form that was filled, or in the frame whose list in the login field was used (`frameId`).
 */
async function afterFill(tabId, item, filled, { embedded = [], frameId = 0 } = {}) {
  if (!filled || item?.type !== 'login') return;
  const settings = await getSettings();
  if (!settings.copyTotpAfterFill) return;
  try {
    const code = (await currentTotp(item, await store.getAccount(item.accountId)))?.code;
    if (!code || !await writeClipboard(code)) return;
    await scheduleClipboardClear(settings.clipboardSeconds);
    const copied = settings.clipboardSeconds > 0
      ? t('Einmalcode kopiert – wird nach {s} s geleert', { s: settings.clipboardSeconds }) : t('Einmalcode kopiert');
    const where = embedded.length ? `${t('OmniVault hat das eingebettete Formular von {origin} ausgefüllt.', { origin: embedded.map(hostLabel).join(', ') })} ` : '';
    await showNotice(tabId, where + copied, frameId);
  } catch (e) {
    console.warn('OmniVault: TOTP not copied after filling', e);
  }
}

/** The first login of the unlocked accounts that belongs to `tabUrl` (ids only; findItem loads its secrets). */
async function bestMatch(tabUrl) {
  for (const a of await store.listAccounts()) {
    const entry = await ensureSynced(a);
    const hit = entry?.items.find((i) => i.type === 'login' && matchesUrl(i, tabUrl));
    if (hit) return { accountId: a.id, itemId: hit.id };
  }
  return null;
}

/** Runs `fn` for each {accountId, itemId} in the trash; one result per item. */
async function eachTrashed(items, fn) {
  const results = [];
  for (const { accountId, itemId } of items) {
    try {
      const entry = await ensureSynced(await store.getAccount(accountId));
      const it = entry?.trash?.find((i) => i.id === itemId);
      if (!it) throw new Error(t('Nicht im Papierkorb'));
      await write(accountId, (p, a, s) => fn(p, a, s, it));
      results.push({ accountId, itemId, ok: true });
    } catch (e) {
      results.push({ accountId, itemId, ok: false, error: e.message });
    }
  }
  return results;
}

/* ---------- content script: inline menu and "save this login?" ---------- */

const CONTENT_SCRIPT = 'ov-inline';
const hostOf = (url) => { try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return null; } };

/** Registers the content script while one of its features is on and OmniVault may access websites. */
const OWN_SCRIPTS = [CONTENT_SCRIPT, 'ov-webauthn-page', 'ov-webauthn'];
let contentSync = Promise.resolve();
/**
 * Registers the content scripts the settings ask for. One run at a time (settings and permission changes often come
 * together), and only what differs is changed – the service worker runs this on every start, and pages loading
 * meanwhile must not miss their scripts.
 */
function syncContentScript() {
  const run = contentSync.then(syncContentScriptNow);
  contentSync = run.catch((e) => console.warn('OmniVault: Inhaltsskripte', e));
  return run;
}
async function syncContentScriptNow() {
  if (!ext.scripting?.registerContentScripts) return;
  const s = await getSettings();
  const { origins = [] } = await ext.permissions.getAll();
  const matches = origins.filter((o) => o === '<all_urls>' || /^https?:\/\//.test(o)).sort();
  const want = [];
  if (matches.length && (s.inlineMenu || s.offerSave || s.passkeys)) {
    // in all frames: login forms are often embedded; each frame's script only deals with its own fields and origin
    want.push({ id: CONTENT_SCRIPT, js: ['inline.js'], matches, runAt: 'document_idle', allFrames: true, persistAcrossSessions: false });
  }
  if (matches.length && s.passkeys) {
    // the page script replaces navigator.credentials before the page's own scripts run; the bridge talks to us.
    // In all frames: requests from embedded frames are checked in the background (passkeys.js), the dialog
    // always opens in the top frame.
    want.push(
      { id: 'ov-webauthn-page', js: ['webauthn-page.js'], matches, runAt: 'document_start', allFrames: true, world: 'MAIN', persistAcrossSessions: false },
      { id: 'ov-webauthn', js: ['webauthn.js'], matches, runAt: 'document_start', allFrames: true, persistAcrossSessions: false },
    );
  }
  // all registrations, filtered here (Firefox and Chrome differ when asked for ids that do not exist)
  const have = (await ext.scripting.getRegisteredContentScripts().catch(() => [])).filter((r) => OWN_SCRIPTS.includes(r.id));
  const same = (a, b) => a.runAt === b.runAt && (a.world ?? 'ISOLATED') === (b.world ?? 'ISOLATED') && !!a.allFrames === !!b.allFrames
    && JSON.stringify([...(a.matches ?? [])].sort()) === JSON.stringify(b.matches) && JSON.stringify(a.js) === JSON.stringify(b.js);
  const stale = have.filter((h) => !want.some((w) => w.id === h.id && same(h, w))).map((h) => h.id);
  if (stale.length) await ext.scripting.unregisterContentScripts({ ids: stale });
  for (const w of want.filter((x) => !have.some((h) => h.id === x.id && !stale.includes(h.id)))) {
    // one by one: a browser without page-world scripts still gets the others
    await ext.scripting.registerContentScripts([w]).catch((e) => console.warn(`OmniVault: Inhaltsskript ${w.id}`, e));
  }
}
syncContentScript().catch(() => {});
ext.permissions?.onAdded?.addListener(() => syncContentScript().catch(() => {}));
ext.permissions?.onRemoved?.addListener(() => syncContentScript().catch(() => {}));

const PENDING_MAX_AGE = 3 * 60_000;
const originOf = (url) => { try { return new URL(url).origin; } catch { return null; } };
/** The frame whose login field the inline list belongs to (the top page if none was recorded). */
async function inlineFrame(tab) {
  const { inlineFrames = {} } = await ext.storage.session.get('inlineFrames');
  return inlineFrames[tab?.id] ?? { frameId: 0, origin: originOf(tab?.url) };
}
async function pendingSave(tabId) {
  if (tabId == null) return null;
  const { pendingSaves = {} } = await ext.storage.session.get('pendingSaves');
  const p = pendingSaves[tabId];
  return p && Date.now() - p.at < PENDING_MAX_AGE ? p : null;
}
async function clearPendingSave(tabId) {
  const { pendingSaves = {} } = await ext.storage.session.get('pendingSaves');
  delete pendingSaves[tabId];
  await ext.storage.session.set({ pendingSaves });
  if (tabId != null) ext.tabs.sendMessage(tabId, { type: 'ov-save-close' }).catch(() => {});
}
/** Unlocked accounts that can store logins. */
async function saveTargets() {
  const out = [];
  for (const a of await store.listAccounts()) {
    const caps = getProvider(a.provider).capabilities ?? {};
    if (caps.write && (caps.types ?? []).includes('login') && await store.getSession(a.id) && !cache.get(a.id)?.readOnly) out.push(a);
  }
  return out;
}

const passkeys = createPasskeyService({
  accounts: () => store.listAccounts(),
  provider: (account) => getProvider(account.provider),
  entry: async (account) => ((await store.getSession(account.id)) ? ensureSynced(account) : null),
  save: async (accountId, item, data) => (await write(accountId, (p, a, s) => p.saveItem(cfg(a), s, item, data))).item,
  toTab: (tabId, message, frameId = 0) => ext.tabs.sendMessage(tabId, message, { frameId }).catch(() => null),
  inspectFrame: inspectFrame,
});

/**
 * What an embedded frame's isolated world says about a WebAuthn request (see checkFrame in passkeys.js). Runs in
 * the content-script world, where the page's own scripts cannot replace document.featurePolicy, location or
 * navigator.userActivation. null where the browser lacks these (Firefox): then the browser handles the request.
 */
async function inspectFrame(tabId, frameId, feature) {
  if (!ext.scripting?.executeScript) return null;
  const [res] = await ext.scripting.executeScript({
    target: { tabId, frameIds: [frameId] },
    args: [feature],
    func: (f) => {
      const policy = document.permissionsPolicy ?? document.featurePolicy;
      if (typeof policy?.allowsFeature !== 'function' || typeof policy.features !== 'function' || !policy.features().includes(f)) return null;
      if (!location.ancestorOrigins) return null;
      return {
        origin: location.origin, ancestors: [...location.ancestorOrigins], allowed: policy.allowsFeature(f),
        active: !!navigator.userActivation?.isActive,
      };
    },
  });
  return res?.result ?? null;
}

const contentHandlers = {
  ...passkeys.contentHandlers,
  async ovConfig() {
    const s = await getSettings();
    return {
      inline: !!s.inlineMenu, save: !!s.offerSave, passkeys: !!s.passkeys,
      labels: { button: t('OmniVault: passende Logins'), bar: t('OmniVault: Login speichern') },
    };
  },
  /** A login form was sent: offer to save it when it is new, or to update the password when it changed. */
  async ovCapture({ username = '', password = '' }, sender) {
    const s = await getSettings();
    // the frame the form was sent in (an embedded login form belongs to its own site, not to the page around it)
    const url = sender.url ?? sender.tab.url;
    const host = hostOf(url);
    if (!s.offerSave || !password || !host || !/^https?:/.test(url)) return { show: false };
    const { neverSave = [] } = await ext.storage.local.get('neverSave');
    if (neverSave.includes(host)) return { show: false };
    let target = null;
    for (const a of await store.listAccounts()) {
      const entry = await ensureSynced(a);
      for (const i of entry?.items ?? []) {
        if (i.type !== 'login' || !matchesUrl(i, url) || (i.username ?? '').toLowerCase() !== username.toLowerCase()) continue;
        const { item } = await findItem(a.id, i.id);
        if (item.password === password) return { show: false }; // already stored
        if (getProvider(a.provider).capabilities?.write && item.canEdit !== false) target ??= { accountId: a.id, itemId: i.id };
      }
    }
    if (!target && !(await saveTargets()).length) return { show: false };
    const { pendingSaves = {} } = await ext.storage.session.get('pendingSaves');
    pendingSaves[sender.tab.id] = { url, host, username, password, kind: target ? 'update' : 'save', target, at: Date.now() };
    await ext.storage.session.set({ pendingSaves });
    // from an embedded frame: the bar opens in the top page, where it has room; in the frame only if the top page
    // has no OmniVault script (no access to that site)
    if (sender.frameId) {
      const shown = await ext.tabs.sendMessage(sender.tab.id, { type: 'ov-save-show' }, { frameId: 0 }).catch(() => false);
      if (shown === true) return { show: false };
    }
    return { show: true };
  },
  /** The list in a login field is about to open in this frame: remember which frame it belongs to. */
  async ovMenuFrame(_msg, sender) {
    const { inlineFrames = {} } = await ext.storage.session.get('inlineFrames');
    inlineFrames[sender.tab.id] = { frameId: sender.frameId ?? 0, origin: sender.origin && sender.origin !== 'null' ? sender.origin : new URL(sender.url).origin };
    await ext.storage.session.set({ inlineFrames });
  },
  async ovPendingSave(_msg, sender) {
    return { show: !!(await pendingSave(sender.tab.id)) };
  },
};

/* ---------- tools ---------- */

const toolDeps = {
  account: (id) => store.getAccount(id),
  provider: (account) => getProvider(account.provider),
  async items(accountId, force = false) {
    if (!(await store.getSession(accountId))) return null;
    const entry = await ensureSynced(await store.getAccount(accountId), force);
    if (entry?.error) throw new Error(entry.error);
    return entry;
  },
  reveal: async (accountId, itemId) => (await findItem(accountId, itemId)).item,
  write,
};

async function loadMirror() {
  const { mirrorRules = [], mirrorState = {}, mirrorReports = {} } = await ext.storage.local.get(['mirrorRules', 'mirrorState', 'mirrorReports']);
  return { mirrorRules, mirrorState, mirrorReports };
}

let mirrorRunning = null;
/** Runs the given (or all enabled) rules; rules whose accounts are locked are skipped and reported. */
function runMirrors(ruleIds) {
  mirrorRunning ??= (async () => {
    const { mirrorRules, mirrorState, mirrorReports } = await loadMirror();
    const rules = mirrorRules.filter((r) => (ruleIds ? ruleIds.includes(r.id) : r.enabled));
    for (const rule of rules) {
      const at = Date.now();
      try {
        const { state, report } = await runMirrorRule(toolDeps, rule, mirrorState[rule.id] ?? {},
          { mirrorTargets: mirrorTargetSet(mirrorRules, mirrorState) });
        mirrorState[rule.id] = state;
        mirrorReports[rule.id] = { at, ...report };
      } catch (e) {
        mirrorReports[rule.id] = { at, error: e.message };
      }
    }
    await ext.storage.local.set({ mirrorState, mirrorReports });
    return Object.fromEntries(rules.map((r) => [r.id, mirrorReports[r.id]]));
  })().finally(() => { mirrorRunning = null; });
  return mirrorRunning;
}

/* ---------- automatic sync ---------- */

const AUTOSYNC = 'autosync';
async function scheduleAutoSync() {
  const { autoSyncMinutes } = await getSettings();
  if (autoSyncMinutes > 0) await ensureAlarm(AUTOSYNC, autoSyncMinutes);
  else await ext.alarms?.clear(AUTOSYNC);
}
/** Logins whose password appears in Have I Been Pwned's Pwned Passwords (range API with padding). */
async function breachedReport() {
  if (!(await ext.permissions.contains({ origins: [HIBP_ORIGIN] }).catch(() => false))) {
    throw new Error(t('Zugriff auf api.pwnedpasswords.com fehlt'));
  }
  const byPassword = new Map();
  for (const i of (await allItems()).filter((x) => x.type === 'login' && x.hasPassword)) {
    const { item } = await findItem(i.accountId, i.id);
    if (!item.password) continue;
    if (!byPassword.has(item.password)) byPassword.set(item.password, []);
    byPassword.get(item.password).push(i);
  }
  let counts;
  try { counts = await breachCounts([...byPassword.keys()]); } catch (e) {
    throw new Error(t('Have I Been Pwned antwortet nicht ({status})', { status: e.status ?? e.message }));
  }
  const found = [...counts].map(([password, count]) => ({ count, items: byPassword.get(password) }));
  return found.sort((a, b) => b.count - a.count).map(({ count, items }, n) => {
    const accounts = [...new Set(items.map((x) => x.accountId))];
    return {
      key: `b${n}`, host: tn(count, 'In {n} Datenleck bekannt', '{n}-mal in Datenlecks bekannt'),
      username: [...new Set(items.map((x) => x.username).filter(Boolean))].join(', '),
      items, accounts, within: false, across: false,
    };
  });
}

async function autoSync() {
  for (const a of await store.listAccounts()) {
    if (await store.getSession(a.id)) await ensureSynced(a, true);
  }
  await runMirrors();
}
scheduleAutoSync().catch(() => {});

const handlers = {
  ...passkeys.handlers,
  async state() {
    const accounts = await store.listAccounts();
    const out = [];
    for (const a of accounts) {
      const unlocked = !!(await store.getSession(a.id));
      const c = cache.get(a.id);
      out.push({
        id: a.id, provider: a.provider, label: a.label, short: a.short, hue: a.hue,
        config: a.config, server: a.config.server, email: a.config.email,
        unlocked, itemCount: c?.items.length ?? null, syncedAt: c?.syncedAt ?? null, error: c?.error ?? null,
        warning: c?.warning ?? null, readOnly: !!c?.readOnly,
        canMoveToOrganization: !!c?.organizations?.some((o) => o.collections.some((x) => !x.readOnly)),
      });
    }
    return { providers: describeProviders(), accounts: out, settings: await getSettings(), pin: await pinStatus(), device: await deviceStatus() };
  },

  settings: () => getSettings(),
  async setSettings({ patch }) {
    const before = language();
    const next = await setSettings(patch);
    if (applyLanguage(next) !== before) setupContextMenu();
    await applyActionBehavior(next);
    await scheduleAutoSync();
    await syncContentScript();
    return next;
  },

  // inline menu (iframe in a login field) – only logins that belong to the frame the field is in
  async inlineItems(_msg, sender) {
    const frame = await inlineFrame(sender.tab);
    const url = frame.origin;
    const topOrigin = originOf(sender.tab?.url);
    const accounts = await store.listAccounts();
    let unlocked = 0;
    for (const a of accounts) if (await store.getSession(a.id)) unlocked++;
    const { inlineMenu } = await getSettings();
    const items = !inlineMenu ? [] : (await allItems(url)).filter((i) => i.type === 'login' && i.matches)
      .map(({ id, accountId, name, username, accountShort, accountHue, accountLabel }) => ({ id, accountId, name, username, accountShort, accountHue, accountLabel }));
    // passkeys only while the page waits for one (a conditional request: "username webauthn" fields)
    const offer = sender.tab && frame.frameId === 0 ? await passkeys.conditionalOffer(sender.tab.id) : null;
    const embeddedIn = frame.frameId !== 0 && topOrigin && topOrigin !== url ? new URL(topOrigin).host : null;
    return { host: hostOf(url) ?? '', embeddedIn, items, passkeys: offer?.passkeys ?? [], requestId: offer?.requestId ?? null, locked: accounts.length > 0 && unlocked === 0 };
  },
  async inlineFill({ accountId, itemId }, sender) {
    const { item } = await findItem(accountId, itemId);
    const frame = await inlineFrame(sender.tab);
    if (!sender.tab || !matchesUrl(item, frame.origin)) throw new Error(t('Dieser Login gehört nicht zu dieser Seite'));
    const filled = await fillFrame(sender.tab.id, frame, item);
    await afterFill(sender.tab.id, item, filled, { frameId: frame.frameId });
    ext.tabs.sendMessage(sender.tab.id, { type: 'ov-inline-close' }).catch(() => {});
  },

  // "save this login?" bar
  async pendingSaveInfo(_msg, sender) {
    const p = await pendingSave(sender.tab?.id);
    if (!p) return null;
    const target = p.target ? await store.getAccount(p.target.accountId) : null;
    return { host: p.host, username: p.username, kind: p.kind, targetLabel: target?.label, accounts: (await saveTargets()).map((a) => ({ id: a.id, label: a.label })) };
  },
  async savePending({ accountId }, sender) {
    const tabId = sender.tab?.id;
    const p = await pendingSave(tabId);
    if (!p) throw new Error(t('Nichts zu speichern'));
    if (p.kind === 'update') {
      const { item } = await findItem(p.target.accountId, p.target.itemId);
      await write(p.target.accountId, (pr, a, s) => pr.saveItem(cfg(a), s, item, {
        type: 'login', name: item.name, username: item.username, password: p.password, totp: item.totp ?? '',
        uris: item.uris ?? [], notes: item.notes ?? '', folderId: item.folderId ?? null, favorite: !!item.favorite,
      }));
    } else {
      if (!(await saveTargets()).some((a) => a.id === accountId)) throw new Error(t('Dieses Konto kann keine Logins speichern'));
      await write(accountId, (pr, a, s) => pr.saveItem(cfg(a), s, null, {
        type: 'login', name: p.host, username: p.username, password: p.password, totp: '', uris: [new URL(p.url).origin], notes: '', folderId: null,
      }));
    }
    await clearPendingSave(tabId);
  },
  async dismissPending({ never }, sender) {
    const p = await pendingSave(sender.tab?.id);
    if (never && p) {
      const { neverSave = [] } = await ext.storage.local.get('neverSave');
      await ext.storage.local.set({ neverSave: [...new Set([...neverSave, p.host])] });
    }
    await clearPendingSave(sender.tab?.id);
  },

  duplicates: async ({ scope }) => findDuplicates(await allItems(), { scope }),

  /**
   * Password report in the same group shape as duplicates: 'reused' groups logins sharing one password,
   * 'weak' groups weak passwords by reason, 'breached' groups passwords known from data breaches (Have I Been Pwned,
   * k-anonymity: only the first 5 hex digits of each password's SHA-1 leave the browser). Passwords never leave the
   * background.
   */
  async passwordReport({ kind }) {
    if (kind === 'breached') return breachedReport();
    const listed = (await allItems()).filter((i) => i.type === 'login' && i.hasPassword);
    const byPassword = new Map();
    const byReason = new Map();
    for (const i of listed) {
      const { item } = await findItem(i.accountId, i.id);
      if (!item.password) continue;
      if (kind === 'reused') {
        if (!byPassword.has(item.password)) byPassword.set(item.password, []);
        byPassword.get(item.password).push(i);
      } else {
        const why = weakness(item.password, [item.username, item.name]);
        if (why) { if (!byReason.has(why)) byReason.set(why, []); byReason.get(why).push(i); }
      }
    }
    const group = (key, host, username, items) => {
      const accounts = [...new Set(items.map((x) => x.accountId))];
      return { key, host, username, items, accounts, within: accounts.length < items.length, across: accounts.length > 1 };
    };
    if (kind === 'reused') {
      return [...byPassword.values()].filter((g) => g.length > 1).sort((a, b) => b.length - a.length)
        .map((items, n) => group(`r${n}`, t('{n} Einträge mit demselben Passwort', { n: items.length }), [...new Set(items.map((x) => x.username).filter(Boolean))].join(', '), items));
    }
    return [...byReason].map(([why, items]) => ({ ...group(why, why, tn(items.length, '{n} Eintrag', '{n} Einträge'), items), within: false, across: false }));
  },

  async transferInfo({ items, targetAccountId }) {
    const lost = new Set();
    const target = targetAccountId ? await store.getAccount(targetAccountId) : null;
    const caps = target ? getProvider(target.provider).capabilities ?? {} : {};
    for (const { accountId, itemId } of items) {
      for (const l of transferLoss((await findItem(accountId, itemId)).item, caps)) lost.add(l);
    }
    return { lost: [...lost] };
  },
  transfer: (args) => transferItems(toolDeps, args),
  bulkDelete: (args) => deleteItems(toolDeps, args),

  importItems: (args) => importItems(toolDeps, args),

  async mirrorRules() {
    const { mirrorRules, mirrorReports } = await loadMirror();
    return mirrorRules.map((r) => ({ ...r, last: mirrorReports[r.id] ?? null }));
  },
  async saveMirrorRule({ rule }) {
    const r = validateRule(rule);
    const { mirrorRules } = await loadMirror();
    const i = mirrorRules.findIndex((x) => x.id === r.id);
    if (i >= 0) mirrorRules[i] = r; else mirrorRules.push(r);
    await ext.storage.local.set({ mirrorRules });
    return r;
  },
  async deleteMirrorRule({ id }) {
    const { mirrorRules, mirrorState, mirrorReports } = await loadMirror();
    delete mirrorState[id];
    delete mirrorReports[id];
    await ext.storage.local.set({ mirrorRules: mirrorRules.filter((r) => r.id !== id), mirrorState, mirrorReports });
  },
  runMirror: ({ id }) => runMirrors(id ? [id] : undefined),

  async addAccount({ provider, config, label, short, hue }) {
    getProvider(provider);
    return store.addAccount(provider, config, { label, short, hue });
  },

  async updateAccount({ id, label, short, hue, config }) {
    const changed = await store.updateAccount(id, { label, short, hue, config });
    if (changed) await lock(id);
    return { locked: changed };
  },

  async removeAccount({ id }) {
    cache.delete(id);
    forgetEmergency(id);
    await store.removeAccount(id);
    await forgetLocalFavorites(id);
    await passkeys.forgetAccount(id);
    const { mirrorRules = [] } = await ext.storage.local.get('mirrorRules');
    await ext.storage.local.set({ mirrorRules: mirrorRules.filter((r) => r.sourceAccountId !== id && r.targetAccountId !== id) });
  },

  async login({ id, credentials }) {
    // `continue`: the next step of a login begun earlier (after Duo or the organization's sign-in); the state for
    // it never left the background
    const { continue: cont, ...creds } = credentials ?? {};
    if (cont) {
      const pending = await loginFlows.take(id);
      if (!pending) throw new Error(t('Anmeldung abgelaufen – bitte erneut beginnen.'));
      creds.pending = pending;
    } else await loginFlows.clear(id);
    let res;
    try {
      res = await loginStep(id, creds);
    } catch (e) {
      // a mistyped master password after the organization's sign-in: keep the sign-in for another try
      if (cont && e.code === 'bad_password' && creds.pending?.kind === 'token') await loginFlows.settle(id, { status: 'needs_password', pending: creds.pending });
      throw e;
    }
    if (res.status === 'needs_browser') {
      await loginFlows.start(id, res);
      return { status: 'needs_browser', kind: res.browser.kind };
    }
    if (res.pending) await loginFlows.settle(id, res);
    const { pending, ...visible } = res;
    return { ...visible, continues: !!pending };
  },

  progress: ({ id }) => syncProgress.get(id) ?? null,

  /** Where a login running in a browser tab stands (for the popup, also after it was closed). */
  async loginFlow({ id }) {
    if (id) return loginFlows.status(id);
    for (const a of await store.listAccounts()) {
      const s = await loginFlows.status(a.id);
      if (s) return { ...s, id: a.id };
    }
    return null;
  },
  loginFlowClear: ({ id }) => loginFlows.clear(id),
  loginFlowFocus: ({ id }) => loginFlows.focus(id),

  lock: ({ id }) => lock(id),
  lockAll: () => lockAll(),

  async sync({ id }) {
    const entry = await ensureSynced(await store.getAccount(id), true);
    return { itemCount: entry?.items.length ?? 0, error: entry?.error, warning: entry?.warning };
  },

  items: ({ tabUrl, frameOrigins }) => allItems(tabUrl, Array.isArray(frameOrigins) ? frameOrigins : []),
  /** Origins of the login forms embedded in the tab (shown, other origin than the page). */
  loginFrames: ({ tabId }) => (tabId != null ? loginFrames(tabId) : []),
  frameTrust: async () => (await trustedPairs()).length,
  forgetFrameTrust: () => forgetPairs(),

  async item({ accountId, itemId }) {
    const { item, account } = await findItem(accountId, itemId);
    return { ...fullItem(item), accountLabel: account.label, accountShort: account.short, accountHue: account.hue };
  },

  /** Earlier passwords of a provider that reads them only on request (Vault/OpenBao: older KV versions). */
  async passwordHistory({ accountId, itemId }) {
    const { item, account } = await findItem(accountId, itemId);
    if (item.passwordHistory?.length) return item.passwordHistory;
    const provider = getProvider(account.provider);
    if (!provider.passwordHistory || !item.passwordHistoryOnDemand) return [];
    const session = await store.getSession(accountId);
    if (!session) throw new Error(t('Tresor gesperrt'));
    const res = await provider.passwordHistory(cfg(account), session, item);
    if (res.session) await store.setSession(accountId, res.session);
    return res.history;
  },

  async folders({ accountId }) {
    const entry = await ensureSynced(await store.getAccount(accountId));
    return entry?.folders ?? [];
  },

  async secret({ accountId, itemId, field }) {
    const { item, account } = await findItem(accountId, itemId);
    // TOTP: also for providers that hand out the current code but never the secret (KeePassXC)
    if (field === 'totp') return currentTotp(item, account);
    if (!['password', 'username', 'notes'].includes(field)) throw new Error(t('Unbekanntes Feld'));
    return item[field] ?? '';
  },

  async totp({ uri }) { return totp(uri); },

  /** Fills an item into the tab; see fillTab for `force` and `allow` (answers to the questions the result asks). */
  async fill({ accountId, itemId, tabId, force = false, allow = null }) {
    const { item } = await findItem(accountId, itemId);
    const r = await fillTab(tabId, item, { interactive: true, force: !!force, allow });
    await afterFill(tabId, item, r.filled, { embedded: r.embedded });
    return r;
  },

  async saveItem({ accountId, itemId, data }) {
    const existing = itemId ? (await findItem(accountId, itemId)).item : null;
    const res = await write(accountId, (p, a, s) => p.saveItem(cfg(a), s, existing, data));
    return res.item ? fullItem(res.item) : null; // null: saved, but the new id is only known after a sync
  },

  /** Removes one passkey from a login; the others keep their private keys (which the interface never sees). */
  async removePasskey({ accountId, itemId, credentialId }) {
    const { item } = await findItem(accountId, itemId);
    const rest = (item.passkeys ?? []).filter((p) => p.credentialId !== credentialId)
      .map((p) => ({ ...p, keyValue: item._passkeyKeys?.[p.credentialId] }));
    const res = await write(accountId, (p, a, s) => p.saveItem(cfg(a), s, item, {
      type: 'login', name: item.name, username: item.username ?? '', password: item.password ?? '', totp: item.totp ?? '',
      uris: item.uris ?? [], passkeys: rest,
    }));
    return res.item ? fullItem(res.item) : null;
  },

  async deleteItem({ accountId, itemId }) {
    const { item } = await findItem(accountId, itemId);
    await write(accountId, (p, a, s) => p.deleteItem(cfg(a), s, item));
  },

  async setFavorite({ accountId, itemId, favorite }) {
    const { item } = await findItem(accountId, itemId);
    const res = await write(accountId, (p, a, s) => p.setFavorite(cfg(a), s, item, favorite));
    return fullItem(res.item);
  },

  // sharing (Passbolt)
  async permissions({ accountId, itemId }) {
    const { item } = await findItem(accountId, itemId);
    return (await write(accountId, (p, a, s) => p.permissions(cfg(a), s, item))).permissions;
  },
  async shareTargets({ accountId, query }) {
    return (await write(accountId, (p, a, s) => p.shareTargets(cfg(a), s, query))).targets;
  },
  async share({ accountId, itemId, changes }) {
    const { item } = await findItem(accountId, itemId);
    await write(accountId, (p, a, s) => p.share(cfg(a), s, item, changes));
  },
  async folderPermissions({ accountId, folderId }) {
    return (await write(accountId, (p, a, s) => p.folderPermissions(cfg(a), s, folderId))).permissions;
  },
  async shareFolder({ accountId, folderId, changes }) {
    const entry = await ensureSynced(await store.getAccount(accountId));
    const tree = { folderId, folders: entry?.folders ?? [], items: entry?.items ?? [] };
    const res = await write(accountId, (p, a, s) => p.shareFolder(cfg(a), s, tree, changes));
    return { skipped: res.skipped ?? 0, failed: res.failed ?? [] };
  },

  // organizations (Bitwarden): where a personal item can be moved, and the move itself
  async organizations({ accountId }) {
    const entry = await ensureSynced(await store.getAccount(accountId));
    return (entry?.organizations ?? [])
      .map((o) => ({ id: o.id, name: o.name, collections: o.collections.filter((c) => !c.readOnly).map(({ id, name }) => ({ id, name })) }))
      .filter((o) => o.collections.length);
  },
  async moveToOrganization({ accountId, itemId, organizationId, collectionIds }) {
    const { item } = await findItem(accountId, itemId);
    const res = await write(accountId, (p, a, s) => {
      if (!p.moveToOrganization) throw new Error(t('{provider}: Organisationen werden nicht unterstützt', { provider: p.label }));
      return p.moveToOrganization(cfg(a), s, item, { organizationId, collectionIds });
    });
    return fullItem(res.item);
  },

  /** Collections of an organization item: all the user can see, which ones the item is in, which ones may change. */
  async itemCollections({ accountId, itemId }) {
    const { item, entry } = await findItem(accountId, itemId);
    const org = (entry?.organizations ?? []).find((o) => o.id === item.organizationId);
    if (!org) throw new Error(t('Der Eintrag gehört keiner Organisation.'));
    const inItem = new Set(item.collectionIds ?? []);
    return {
      organization: { id: org.id, name: org.name },
      collections: org.collections.map((c) => ({ id: c.id, name: c.name, checked: inItem.has(c.id), editable: !c.readOnly })),
    };
  },
  async setCollections({ accountId, itemId, collectionIds }) {
    const { item, entry } = await findItem(accountId, itemId);
    const org = (entry?.organizations ?? []).find((o) => o.id === item.organizationId);
    // collections the user may not change keep their assignment, whatever the interface sends
    const fixed = new Set((org?.collections ?? []).filter((c) => c.readOnly).map((c) => c.id));
    const known = new Set((org?.collections ?? []).map((c) => c.id));
    const keep = (item.collectionIds ?? []).filter((id) => fixed.has(id) || !known.has(id));
    const wanted = (collectionIds ?? []).filter((id) => known.has(id) && !fixed.has(id));
    const res = await write(accountId, (p, a, s) => {
      if (!p.setCollections) throw new Error(t('{provider}: Organisationen werden nicht unterstützt', { provider: p.label }));
      return p.setCollections(cfg(a), s, item, { collectionIds: [...keep, ...wanted], readOnlyIds: [...fixed] });
    });
    return res?.unavailable ? { unavailable: true } : { item: fullItem(res.item) };
  },

  // unlock with a PIN
  async setPin({ pin }) {
    await ext.storage.local.set({ pinLock: await createPinLock(pin) });
    await ext.storage.session.remove(['pinSealed', 'pinAttempts']);
  },
  async removePin() {
    await ext.storage.local.remove('pinLock');
    await ext.storage.session.remove(['pinSealed', 'pinAttempts']);
  },
  async unlockWithPin({ pin }) {
    const { pinLock } = await ext.storage.local.get('pinLock');
    const { pinSealed, pinAttempts = 0 } = await ext.storage.session.get(['pinSealed', 'pinAttempts']);
    if (!pinLock || !pinSealed) throw new Error(t('Kein mit PIN gesperrter Zustand – bitte mit dem Master-Passwort entsperren'));
    let sessions;
    try {
      sessions = await unseal(pinLock, pinSealed, pin);
    } catch (e) {
      const left = PIN_ATTEMPTS - pinAttempts - 1;
      if (left <= 0) {
        await ext.storage.session.remove(['pinSealed', 'pinAttempts']);
        throw new Error(t('Zu viele Fehlversuche – bitte die Konten mit dem Master-Passwort entsperren'));
      }
      await ext.storage.session.set({ pinAttempts: pinAttempts + 1 });
      throw new Error(tn(left, '{error} – noch {n} Versuch', '{error} – noch {n} Versuche', { error: e.message }));
    }
    return restoreSealed(sessions);
  },

  // unlock with the device: the passkey ceremony runs in the interface (it needs a window); only its PRF output comes here
  /** → the credential ID of a passkey set up before (replaced now), so the interface can let it go. */
  async setDeviceUnlock({ credentialId, prfSalt, prf, transports }) {
    const { deviceLock: old } = await ext.storage.local.get('deviceLock');
    await ext.storage.local.set({ deviceLock: await createDeviceLock({ credentialId, prfSalt, prf, transports }) });
    await ext.storage.session.remove('deviceSealed');
    return { replaced: old?.credentialId ?? null };
  },
  /** → the credential ID, so the interface can tell the authenticator that the passkey is no longer used. */
  async removeDeviceUnlock() {
    const { deviceLock } = await ext.storage.local.get('deviceLock');
    await ext.storage.local.remove('deviceLock');
    await ext.storage.session.remove('deviceSealed');
    return { credentialId: deviceLock?.credentialId ?? null };
  },
  /** What the interface needs to ask the authenticator (nothing secret: credential ID, transports, PRF salt). */
  async deviceUnlockParams() {
    const { deviceLock } = await ext.storage.local.get('deviceLock');
    const { deviceSealed } = await ext.storage.session.get('deviceSealed');
    if (!deviceLock || !deviceSealed) throw new Error(t('Kein mit dem Gerät gesperrter Zustand – bitte mit dem Master-Passwort entsperren'));
    return { credentialId: deviceLock.credentialId, prfSalt: deviceLock.prfSalt, transports: deviceLock.transports ?? [] };
  },
  /** No attempt counter here: the authenticator verifies the user and limits failed attempts itself. */
  async unlockWithDevice({ prf }) {
    const { deviceLock } = await ext.storage.local.get('deviceLock');
    const { deviceSealed } = await ext.storage.session.get('deviceSealed');
    if (!deviceLock || !deviceSealed) throw new Error(t('Kein mit dem Gerät gesperrter Zustand – bitte mit dem Master-Passwort entsperren'));
    return restoreSealed(await unsealWithDevice(deviceLock, deviceSealed, prf));
  },
  /**
   * The ceremony in a small window of its own: the operating system's dialog (Windows Hello and the like) takes the
   * focus, which closes the toolbar popup. `returnTo` says where to continue afterwards (popup or sidebar).
   */
  async openDeviceWindow({ action, returnTo, windowId }) {
    const { deviceWindow: old } = await ext.storage.session.get('deviceWindow');
    if (old?.id != null) await ext.windows.remove(old.id).catch(() => {});
    const w = await ext.windows.create({
      url: ext.runtime.getURL(`device.html?do=${action === 'setup' ? 'setup' : 'unlock'}`),
      type: 'popup', width: 420, height: 360, focused: true,
    });
    await ext.storage.session.set({ deviceWindow: { id: w.id, action, returnTo, windowId } });
    return { id: w.id };
  },
  /** The device window is done (or cancelled): closes it and continues in the popup (reopened) or the sidebar. */
  async deviceWindowDone({ ok = false, message }) {
    const { deviceWindow: d } = await ext.storage.session.get('deviceWindow');
    if (!d) return;
    await ext.storage.session.remove('deviceWindow');
    const device = { action: d.action, ok: !!ok, message: typeof message === 'string' ? message : undefined };
    if (d.returnTo === 'popup') {
      await ext.storage.session.set({ popupResume: { view: d.action === 'setup' ? 'settings' : 'main', device, at: Date.now() } });
    } else ext.runtime.sendMessage({ type: 'ov-device-done', ...device }).catch(() => {});
    await ext.windows.remove(d.id).catch(() => {});
    if (d.returnTo === 'popup') {
      if (d.windowId != null) await ext.windows.update(d.windowId, { focused: true }).catch(() => {});
      await ext.action.openPopup(d.windowId != null ? { windowId: d.windowId } : undefined).catch(() => {});
    }
  },

  /** Unencrypted export of the given unlocked accounts → { fileName, content, count }. */
  async exportItems({ accountIds, format }) {
    const items = [];
    for (const id of accountIds) {
      const account = await store.getAccount(id);
      if (!account || !(await store.getSession(id))) continue;
      const entry = await ensureSynced(account);
      for (const i of entry?.items ?? []) {
        const { item } = await findItem(id, i.id);
        const keys = passkeysWithKeys(item); // the export contains everything, passkey keys too (like Bitwarden's)
        items.push({ ...fullItem(item), ...(keys.length ? { passkeys: keys } : {}) });
      }
    }
    const date = new Date().toISOString().slice(0, 10);
    return format === 'csv'
      ? { fileName: `omnivault-export-${date}.csv`, content: toCsv(items), count: items.filter((i) => i.type === 'login' || i.type === 'note').length }
      : { fileName: `omnivault-export-${date}.json`, content: toBitwardenJson(items), count: items.filter((i) => ['login', 'note', 'card', 'identity'].includes(i.type)).length };
  },

  async attachment({ accountId, itemId, attachmentId }) {
    const { item } = await findItem(accountId, itemId);
    const account = await store.getAccount(accountId);
    const session = await store.getSession(accountId);
    const provider = getProvider(account.provider);
    if (!provider.downloadAttachment) throw new Error(t('Anhänge werden für diesen Anbieter nicht unterstützt'));
    const res = await provider.downloadAttachment(cfg(account), session, item, attachmentId);
    if (res.session) await store.setSession(accountId, res.session);
    return { fileName: res.fileName, data: res.data };
  },

  async addAttachment({ accountId, itemId, fileName, data }) {
    const { item } = await findItem(accountId, itemId);
    const res = await write(accountId, (p, a, s) => {
      if (!p.uploadAttachment) throw new Error(t('Anhänge hochladen wird für diesen Anbieter nicht unterstützt'));
      return p.uploadAttachment(cfg(a), s, item, { fileName, data });
    });
    return fullItem(res.item);
  },

  async deleteAttachment({ accountId, itemId, attachmentId }) {
    const { item } = await findItem(accountId, itemId);
    const res = await write(accountId, (p, a, s) => {
      if (!p.deleteAttachment) throw new Error(t('Anhänge löschen wird für diesen Anbieter nicht unterstützt'));
      return p.deleteAttachment(cfg(a), s, item, attachmentId);
    });
    return fullItem(res.item);
  },

  /* Bitwarden Send. The list goes to the popup without text, notes and link; those come only when asked for. */
  async sends({ accountId }) {
    const res = await sendCall(accountId, (p, a, s) => p.listSends(cfg(a), s));
    return res.sends.map(({ text, notes, link, ...meta }) => meta);
  },

  async send({ accountId, sendId }) {
    const res = await sendCall(accountId, (p, a, s) => p.listSends(cfg(a), s));
    const found = res.sends.find((x) => x.id === sendId);
    if (!found) throw new Error(t('Send nicht gefunden'));
    return found;
  },

  async saveSend({ accountId, sendId = null, data }) {
    const res = await sendCall(accountId, (p, a, s) => p.saveSend(cfg(a), s, sendId, data), { write: true });
    return res.send;
  },

  async deleteSend({ accountId, sendId }) {
    await sendCall(accountId, (p, a, s) => p.deleteSend(cfg(a), s, sendId));
    return true;
  },

  async removeSendPassword({ accountId, sendId }) {
    const { send } = await sendCall(accountId, (p, a, s) => p.removeSendPassword(cfg(a), s, sendId));
    const { text, notes, link, ...meta } = send;
    return meta;
  },

  /* Emergency access as trusted contact: list, ask for access, view (read only, see emergencyViews). */
  async emergencyGrants({ accountId }) {
    return (await emergencyCall(accountId, (p, a, s) => p.listEmergencyGrants(cfg(a), s))).grants;
  },

  async emergencyInitiate({ accountId, grantId }) {
    await emergencyCall(accountId, (p, a, s) => p.initiateEmergencyAccess(cfg(a), s, grantId));
    return true;
  },

  async emergencyView({ accountId, grantId, reload = false }) {
    const { items, failed } = await emergencyItems(accountId, grantId, { reload });
    return { failed, items: items.map((i) => ({ id: i.id, type: i.type, name: i.name, username: i.username, subtitle: i.subtitle, uris: i.uris })) };
  },

  async emergencyItem({ accountId, grantId, itemId }) {
    const { items } = await emergencyItems(accountId, grantId);
    const item = items.find((i) => i.id === itemId);
    if (!item) throw new Error(t('Eintrag nicht gefunden oder Tresor gesperrt'));
    const { attachments, passkeys, ...rest } = fullItem(item);
    return { ...rest, attachmentCount: attachments?.length ?? 0, passkeyCount: passkeys?.length ?? 0 };
  },

  async createFolder({ accountId, name }) {
    const account = await store.getAccount(accountId);
    if (!getProvider(account.provider).capabilities?.createFolder) throw new Error(t('Dieser Anbieter kann keine Ordner anlegen'));
    const res = await write(accountId, (p, a, s) => p.createFolder(cfg(a), s, { name: name.trim() }));
    return res.folder;
  },

  /** Items in the trash of all unlocked accounts whose provider can restore them. */
  async trash() {
    const out = [];
    for (const a of await store.listAccounts()) {
      if (!getProvider(a.provider).capabilities?.restore) continue;
      const entry = await ensureSynced(a);
      for (const i of entry?.trash ?? []) {
        out.push({ ...publicItem(i), deletedDate: i.deletedDate, accountLabel: a.label, accountShort: a.short, accountHue: a.hue });
      }
    }
    return out.sort((x, y) => String(y.deletedDate).localeCompare(String(x.deletedDate)));
  },
  async restoreItems({ items }) {
    return eachTrashed(items, (p, a, s, it) => p.restoreItem(cfg(a), s, it));
  },
  async purgeItems({ items }) {
    return eachTrashed(items, (p, a, s, it) => p.purgeItem(cfg(a), s, it));
  },

  async generated() {
    const { generated = [] } = await ext.storage.session.get('generated');
    return generated;
  },
  rememberGenerated: ({ value }) => rememberGenerated(value),

  /** OmniVault in its own window: focuses the open one or creates it (the page asking may close right after). */
  async popOut() {
    const { popoutWindowId: id } = await ext.storage.session.get('popoutWindowId');
    if (id != null) {
      try { await ext.windows.update(id, { focused: true }); return { id }; } catch { /* closed meanwhile */ }
    }
    const w = await ext.windows.create({ url: ext.runtime.getURL('popup.html?window=1'), type: 'popup', width: 420, height: 640 });
    await ext.storage.session.set({ popoutWindowId: w.id });
    return { id: w.id };
  },

  /**
   * Firefox opens a sidebar only in the window in front – from the pop-out window, that is the pop-out. So the
   * pop-out hands over: until the sidebar is open, the toolbar icon opens the sidebar (action.onClicked below,
   * a user action in the browser window), and sidebarOpened then closes the pop-out.
   */
  async sidebarHandoff({ cancel = false } = {}) {
    if (cancel) return endSidebarHandoff();
    await ext.storage.session.set({ sidebarHandoff: true });
    await ext.action.setPopup({ popup: '' });
  },
  async sidebarOpened() {
    const { sidebarHandoff, popoutWindowId } = await ext.storage.session.get(['sidebarHandoff', 'popoutWindowId']);
    if (!sidebarHandoff) return false;
    await endSidebarHandoff();
    if (popoutWindowId != null) await ext.windows.remove(popoutWindowId).catch(() => {});
    return true;
  },

  async scheduleClipboardClear() {
    await scheduleClipboardClear((await getSettings()).clipboardSeconds);
  },
  clearClipboard: () => clearClipboardNow(),
};

/** The interface language for messages, menus and texts created here; set before any message is answered. */
const applyLanguage = (settings) => setLanguage(resolveLanguage(settings.language, browserLanguages()));
const languageReady = getSettings().then(applyLanguage).catch(() => {});

ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== ext.runtime.id) return false;
  // Our content script (on web pages) may only use the three calls made for it – nothing that returns secrets.
  if (!sender.url?.startsWith(ext.runtime.getURL(''))) {
    const c = sender.tab && contentHandlers[msg?.type];
    if (!c) return false;
    languageReady.then(() => c(msg, sender)).then((result) => sendResponse({ ok: true, result }), (e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
  if (msg?.target === 'offscreen') return false;
  const h = handlers[msg?.type];
  if (!h) return false;
  languageReady
    .then(() => (msg.type === 'state' || msg.type === 'settings' ? null : touch()))
    .then(() => h(msg, sender))
    .then((result) => sendResponse({ ok: true, result }))
    .catch((e) => sendResponse({ ok: false, error: e.message, code: e.code }));
  return true; // async response
});

/* ---------- toolbar icon: popup or sidebar ---------- */

async function applyActionBehavior(settings) {
  const sidebarMode = settings.actionOpens === 'sidebar' && !!(ext.sidePanel || ext.sidebarAction);
  await ext.action.setPopup({ popup: sidebarMode ? '' : 'popup.html' });
  // Chrome opens the side panel itself; Firefox gets action.onClicked (popup is empty) below.
  await ext.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: sidebarMode }).catch(() => {});
}
// Firefox: a click on the icon with no popup → toggle the sidebar (must be called synchronously in the handler).
ext.action.onClicked.addListener(() => { ext.sidebarAction?.toggle?.(); });
getSettings().then(applyActionBehavior).catch(() => {});

/** Ends a hand-over from the pop-out window to the sidebar: the icon opens what the settings say again. */
async function endSidebarHandoff() {
  await ext.storage.session.remove('sidebarHandoff');
  await applyActionBehavior(await getSettings());
}
ext.windows?.onRemoved?.addListener(async (id) => {
  const { sidebarHandoff, popoutWindowId } = await ext.storage.session.get(['sidebarHandoff', 'popoutWindowId']);
  if (id !== popoutWindowId) return;
  await ext.storage.session.remove('popoutWindowId');
  if (sidebarHandoff) await endSidebarHandoff();
});

/* ---------- keyboard shortcut and context menu ---------- */

async function fillBestMatch(tab) {
  if (!tab?.id || !/^https?:/.test(tab.url ?? '')) return;
  await touch();
  let picked = null; // the login fillBestInTab chose (loaded with its secrets)
  const r = await fillBestInTab(tab.id, bestMatch, async (ref) => { picked = (await findItem(ref.accountId, ref.itemId)).item; return picked; })
    .catch((e) => { console.warn('OmniVault: filling failed', e); return null; });
  if (r) await afterFill(tab.id, picked, r.filled, { embedded: r.embedded });
}

ext.commands?.onCommand.addListener(async (command, tab) => {
  const target = tab ?? (await ext.tabs.query({ active: true, currentWindow: true }))[0];
  if (command === 'autofill') fillBestMatch(target);
});

function setupContextMenu() {
  if (!ext.contextMenus) return;
  languageReady.then(() => ext.contextMenus.removeAll(() => {
    ext.contextMenus.create({ id: 'ov-fill', title: t('Mit OmniVault ausfüllen'), contexts: ['editable', 'page'] });
    ext.contextMenus.create({ id: 'ov-generate', title: t('Sicheres Passwort einfügen (OmniVault)'), contexts: ['editable'] });
  }));
}
ext.runtime.onInstalled.addListener(setupContextMenu);
ext.runtime.onStartup?.addListener(setupContextMenu);
ext.contextMenus?.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'ov-fill') fillBestMatch(tab);
  if (info.menuItemId === 'ov-generate' && tab?.id) {
    const pw = generateSecret((await getSettings()).generator);
    await insertIntoFocused(tab.id, info.frameId ?? 0, pw);
  }
});
