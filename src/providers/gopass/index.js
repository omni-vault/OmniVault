// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// gopass provider. OmniVault talks to the user's local `gopass` + gpg through the OmniVault native host
// (native/omnivault_host.py, backend "gopass"). Entries use the pass format (first line = password, then login:/url:/
// otpauth://… and free text); mounted sub-stores show up as top-level folders.
import { mark, t } from '../../i18n/index.js';
import { CliProvider, hostAtLeast, outdatedHost, virtualFolder } from '../native-host.js';
import { DECRYPT_FIELD, LAZY_HOST, decryptOnOpen, listEntries, payloadOf, revealedFields, savedItem } from '../pass/index.js';
import { ProviderError } from '../provider.js';

class GopassProvider extends CliProvider {
  static backend = 'gopass';
  static id = 'gopass';
  static label = 'gopass';
  static note = mark('Über das lokale „gopass“ mit gpg und den OmniVault-Host (native/README.md). Eingehängte Speicher erscheinen als Ordner.');
  static capabilities = { write: true, types: ['login'], favorites: false, folderLabel: 'Ordner', trash: false, moveFolder: true, fields: true, createFolder: true };
  static configFields = [DECRYPT_FIELD];

  static async login(config) {
    const st = await this.call('status');
    if (!st.cli) throw new ProviderError(t('„gopass“ wurde nicht gefunden. Bitte gopass installieren.'), 'config');
    if (!st.gpg) throw new ProviderError(t('gpg wurde nicht gefunden. Bitte GnuPG installieren.'), 'config');
    if (!st.initialized) throw new ProviderError(t('Kein gopass-Speicher gefunden. Bitte zuerst „gopass setup“ ausführen.'), 'config');
    if (decryptOnOpen(config) && !hostAtLeast(st.version, LAZY_HOST)) throw outdatedHost(st.version, LAZY_HOST);
    return { status: 'ok', session: { connected: true } };
  }

  static async sync(config) {
    const { items, mounts = [] } = await listEntries(this, config);
    const folders = new Set(mounts);
    for (const m of items) if (m.folder) folders.add(m.folder);
    return { items, folders: [...folders].sort().map((f) => ({ id: f, name: f })) };
  }

  /** Decrypts one entry listed by name; entries from a full sync already carry everything. */
  static async reveal(config, session, item) {
    if (!item.lazy) return {};
    return revealedFields(await this.call('reveal', { id: item.id }), item);
  }

  /** A folder is a directory; it exists as soon as an entry is saved into it. */
  static async createFolder(config, session, { name }) {
    return { folder: virtualFolder(name) };
  }

  static async saveItem(config, session, existing, data) {
    const payload = payloadOf(data, existing);
    if (!existing) {
      const { id } = await this.call('create', payload);
      return { item: savedItem(payload, id, this.id, config) };
    }
    // another folder or name = another path: `gopass mv` (also across mounts), then write the new content
    let id = existing.id;
    const targetFolder = data.folderId !== undefined ? data.folderId : existing.folderId ?? null;
    const renamed = (data.name ?? existing.name) !== existing.name;
    if ((targetFolder ?? '') !== (existing.folderId ?? '') || renamed) {
      ({ id } = await this.call('move', { id, name: data.name ?? existing.name, folder: targetFolder }));
    }
    await this.call('update', { ...payload, folder: targetFolder, id });
    return { item: savedItem({ ...payload, folder: targetFolder }, id, this.id, config), deletedId: id !== existing.id ? existing.id : undefined };
  }
}

export default GopassProvider;
