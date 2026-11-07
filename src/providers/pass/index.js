// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// pass (zx2c4 password-store) provider. OmniVault talks to the user's local `pass` + gpg through the
// OmniVault native host (native/omnivault_host.py, backend "pass"). Each entry is a gpg-encrypted file; its first line is
// the password, the rest is freeform metadata (login:/url:/otpauth://…).
// Two modes per account (config `decrypt`): "sync" decrypts every entry when the account syncs (user name and website
// known in the list); "open" lists file names only and decrypts an entry when it is opened, copied or filled – the
// site then comes from the path (e.g. `websites/github.com/ada`), see pathHints().
import { mark, t } from '../../i18n/index.js';
import { hasListedTld } from '../../lib/psl.js';
import { CliProvider, hostAtLeast, outdatedHost, virtualFolder } from '../native-host.js';
import { ProviderError } from '../provider.js';

/** First host version with the `names` command (list without decrypting). */
export const LAZY_HOST = '2.1.0';

/** Account setting shared by pass and gopass. */
export const DECRYPT_FIELD = {
  name: 'decrypt', label: mark('Einträge entschlüsseln'), type: 'select', default: 'sync',
  options: [
    { value: 'sync', label: mark('Alle beim Abgleich (Benutzername und Website in der Liste)') },
    { value: 'open', label: mark('Erst beim Öffnen, Kopieren oder Ausfüllen') },
  ],
  hint: mark('„Erst beim Öffnen“ startet gpg nur für den Eintrag, den du brauchst. Die Liste kennt dann nur die Dateinamen: Die Website kommt aus dem Pfad (z. B. „websites/github.com/ada“), Benutzername und Website aus dem Inhalt erst nach dem Öffnen.'),
};

export const decryptOnOpen = (config) => config?.decrypt === 'open';

/** A path segment that names a site: a host name with a known top-level domain (not "notes.v2" or "x.local"). */
const HOST = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?::\d{1,5})?$/i;
// top-level domains that are more often file extensions in a password store
const FILE_LIKE = new Set(['md', 'zip', 'mov', 'sh', 'py', 'pl', 'rs', 'so', 'ps']);
function siteOf(segment) {
  const s = String(segment ?? '').trim().toLowerCase();
  if (!HOST.test(s)) return null;
  const host = s.replace(/:\d+$/, '');
  const tld = host.split('.').pop();
  return hasListedTld(host) && !FILE_LIKE.has(tld) ? s : null;
}

/**
 * What the path of an entry tells without decrypting it (the conventions of browserpass and gopass bridges):
 * `github.com`, `web/github.com` → site; `github.com/ada` → site and user name ada; `mail/ada@example.org` → site
 * example.org; otherwise the innermost folder that is a host name. → { site, user } (either may be missing).
 */
export function pathHints(id) {
  const parts = String(id ?? '').split('/').filter(Boolean);
  const n = parts.length;
  if (!n) return {};
  if (n >= 2 && siteOf(parts[n - 2]) && !siteOf(parts[n - 1])) return { site: siteOf(parts[n - 2]), user: parts[n - 1] };
  const last = parts[n - 1];
  const at = last.lastIndexOf('@');
  if (siteOf(last)) return { site: siteOf(last) };
  if (at > 0 && siteOf(last.slice(at + 1))) return { site: siteOf(last.slice(at + 1)) };
  for (let k = n - 2; k >= 0; k--) if (siteOf(parts[k])) return { site: siteOf(parts[k]) };
  return {};
}

/** Item of a CLI entry in pass format (`e` from the host's list or reveal). */
export function passItem(e, provider, accountId) {
  return {
    id: e.id, accountId, provider, type: 'login',
    name: e.name || e.id, username: e.username || undefined, uris: e.uris ?? [],
    password: e.password || undefined, totp: e.totp || undefined, notes: e.notes || undefined, fields: e.fields ?? [],
    folderId: e.folder ?? null, folder: e.folder ?? undefined, favorite: false,
    canEdit: true, canDelete: true,
  };
}

/**
 * Item of an entry known by name only (decrypt "open"): nothing decrypted yet. `siteHints` match the tab (see
 * lib/match.js) but are not the entry's own websites, so editing never writes them into the file; a user name from
 * the path stands in until the entry is opened.
 */
export function namedItem(e, provider, accountId) {
  const { site, user } = pathHints(e.id);
  return {
    ...passItem({ id: e.id, name: e.name, folder: e.folder }, provider, accountId),
    username: user || undefined, siteHints: site ? [`https://${site}`] : [],
    lazy: true, hasPassword: true, hasTotp: false, usernameUnknown: true,
  };
}

/** Values of a decrypted entry for an item listed by name (background/index.js findItem merges them). */
export function revealedFields(e, item) {
  const fromPath = !e.username && !!pathHints(item.id).user;
  return {
    username: e.username || (fromPath ? pathHints(item.id).user : undefined), uris: e.uris ?? [],
    password: e.password || undefined, totp: e.totp || undefined, notes: e.notes || undefined, fields: e.fields ?? [],
    hasPassword: !!e.password, hasTotp: !!e.totp, usernameUnknown: false, _userFromPath: fromPath,
  };
}

/** What to write: a user name that only came from the path is not written into the file unless it was changed. */
export function payloadOf(data, existing) {
  const keepPathUser = existing?._userFromPath && data.username === existing.username;
  return {
    name: data.name, username: keepPathUser ? '' : data.username, password: data.password,
    uris: data.uris ?? [], totp: data.totp, notes: data.notes, fields: data.fields ?? [],
    folder: data.folderId || null,
  };
}

/** The list of a pass-format account: decrypted entries, or names only (decrypt "open"). */
export async function listEntries(provider, config) {
  if (!decryptOnOpen(config)) {
    const res = await provider.call('list');
    return { ...res, items: res.items.map((e) => passItem(e, provider.id, config.id)) };
  }
  let res;
  try { res = await provider.call('names'); } catch (e) {
    // a host installed by an older OmniVault has no `names`: say so instead of "unknown command"
    const st = await provider.call('status').catch(() => null);
    if (st && !hostAtLeast(st.version, LAZY_HOST)) throw outdatedHost(st.version, LAZY_HOST);
    throw e;
  }
  return { ...res, items: res.items.map((e) => namedItem(e, provider.id, config.id)) };
}

/** Item after saving: as written, with the path hints of the mode. */
export function savedItem(payload, id, provider, config) {
  const name = id.split('/').pop();
  const folder = id.split('/').slice(0, -1).join('/') || null;
  if (!decryptOnOpen(config)) return passItem({ ...payload, id, name, folder }, provider, config.id);
  const item = namedItem({ id, name, folder }, provider, config.id);
  return { ...item, ...revealedFields(payload, item), revealed: true };
}

class PassProvider extends CliProvider {
  static backend = 'pass';
  static id = 'pass';
  static label = 'pass (password-store)';
  static note = mark('Über das lokale „pass“ (zx2c4 password-store) mit gpg und den OmniVault-Host (native/README.md).');
  static capabilities = { write: true, types: ['login'], favorites: false, folderLabel: 'Ordner', trash: false, moveFolder: true, fields: true, createFolder: true };
  static configFields = [DECRYPT_FIELD];

  static async login(config) {
    const st = await this.call('status');
    if (!st.gpg) throw new ProviderError(t('gpg wurde nicht gefunden. Bitte GnuPG installieren.'), 'config');
    if (!st.cli) throw new ProviderError(t('„pass“ wurde nicht gefunden. Bitte password-store installieren.'), 'config');
    if (!st.initialized) throw new ProviderError(t('Kein pass-Speicher gefunden. Bitte zuerst „pass init <gpg-id>“ ausführen.'), 'config');
    if (decryptOnOpen(config) && !hostAtLeast(st.version, LAZY_HOST)) throw outdatedHost(st.version, LAZY_HOST);
    return { status: 'ok', session: { connected: true, store: st.store ?? null } };
  }

  static async sync(config) {
    const { items } = await listEntries(this, config);
    const folders = new Set(items.map((m) => m.folder).filter(Boolean));
    return { items, folders: [...folders].sort().map((f) => ({ id: f, name: f })) };
  }

  /** Decrypts one entry listed by name; entries from a full sync already carry everything. */
  static async reveal(config, session, item) {
    if (!item.lazy) return {};
    return revealedFields(await this.call('reveal', { id: item.id }), item);
  }

  /** A folder in pass is a directory; it exists as soon as an entry is saved into it. */
  static async createFolder(config, session, { name }) {
    return { folder: virtualFolder(name) };
  }

  static async saveItem(config, session, existing, data) {
    const payload = payloadOf(data, existing);
    if (!existing) {
      const { id } = await this.call('create', payload);
      return { item: savedItem(payload, id, this.id, config) };
    }
    // moving to another folder = new path: create at the target, then remove the old entry
    const targetFolder = data.folderId ?? existing.folderId ?? null;
    if ((targetFolder ?? '') !== (existing.folderId ?? '')) {
      const { id } = await this.call('create', payload);
      await this.call('delete', { id: existing.id });
      return { item: savedItem(payload, id, this.id, config), deletedId: existing.id };
    }
    await this.call('update', { ...payload, id: existing.id });
    return { item: savedItem(payload, existing.id, this.id, config) };
  }
}

export default PassProvider;
