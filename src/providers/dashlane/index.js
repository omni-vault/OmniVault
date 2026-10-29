// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Dashlane provider via the official Dashlane CLI `dcli` and the OmniVault host, read only: dcli itself can only read
// the vault. The host drops passwords, notes and OTP secrets from the listing; each one is fetched on demand.
// Logins come from `dcli password`, secure notes from `dcli note`, Dashlane "secrets" from `dcli secret` (as notes),
// personal IDs (identity, passport, ID card, driver's licence, social security and tax number) from `dcli id` (as
// identities). dcli cannot read payment cards.
import { mark, t } from '../../i18n/index.js';
import { CliProvider } from '../native-host.js';
import { ProviderError } from '../provider.js';

/** Dashlane's types of personal ID items (`type` in `dcli id`) → what OmniVault calls them. */
const ID_LABELS = {
  IDENTITY: mark('Identität'),
  PASSPORT: mark('Reisepass'),
  IDCARD: mark('Personalausweis'),
  DRIVERLICENCE: mark('Führerschein'),
  SOCIALSECURITYSTATEMENT: mark('Sozialversicherungsausweis'),
  FISCALSTATEMENT: mark('Steuernummer'),
};

/** Fields of an ID item shown as custom fields: Dashlane key → [label, hidden]. */
const ID_FIELDS = {
  sex: [mark('Geschlecht'), false],
  birthDate: [mark('Geburtsdatum'), false],
  dateOfBirth: [mark('Geburtsdatum'), false],
  birthPlace: [mark('Geburtsort'), false],
  deliveryDate: [mark('Ausgestellt am'), false],
  expireDate: [mark('Gültig bis'), false],
  deliveryPlace: [mark('Ausstellungsort'), false],
  state: [mark('Ausstellungsort'), false], // driver's licence: the issuing state, not an address
  number: [mark('Ausweisnummer'), true],
  idNumber: [mark('Ausweisnummer'), true],
  fiscalNumber: [mark('Steuernummer'), true],
  teledeclarantNumber: [mark('Nummer für die Online-Steuererklärung'), true],
};

/**
 * A personal ID read by `dcli id` (Dashlane's key names with a lower-case first letter) → an OmniVault identity.
 * The holder's name, title and user name go into the identity; passport, driver's licence and social security
 * numbers into their own fields; everything else (dates, places, other numbers) into custom fields, numbers hidden.
 */
export function mapId(idType, data = {}) {
  const d = { ...data };
  const take = (...keys) => { for (const k of keys) { if (d[k]) { const v = d[k]; delete d[k]; return v; } } return undefined; };
  const identity = {};
  const full = take('fullname', 'socialSecurityFullname');
  if (full) identity.firstName = full;
  else {
    identity.title = take('title');
    identity.firstName = take('firstName');
    identity.middleName = take('middleName');
    identity.lastName = [take('lastName'), take('lastName2')].filter(Boolean).join(' ') || undefined;
  }
  identity.username = take('pseudo');
  if (idType === 'PASSPORT') identity.passportNumber = take('number');
  if (idType === 'DRIVERLICENCE') identity.licenseNumber = take('number');
  identity.ssn = take('socialSecurityNumber');
  const fields = [];
  for (const [key, [label, hidden]] of Object.entries(ID_FIELDS)) {
    const value = take(key);
    if (value) fields.push({ name: t(label), value, type: hidden ? 'hidden' : 'text' });
  }
  // keys OmniVault does not know yet stay visible under Dashlane's name (numbers hidden)
  for (const [key, value] of Object.entries(d).sort(([a], [b]) => a.localeCompare(b))) {
    if (typeof value === 'string' && value) fields.push({ name: key, value, type: /number|code|secret/i.test(key) ? 'hidden' : 'text' });
  }
  for (const k of Object.keys(identity)) if (!identity[k]) delete identity[k];
  return { identity, fields };
}

class DashlaneProvider extends CliProvider {
  static backend = 'dashlane';
  static id = 'dashlane';
  static label = 'Dashlane';
  static note = mark('Nur lesen, über das offizielle Dashlane-CLI (dcli) und den OmniVault-Host (native/README.md). Voraussetzung: dcli installiert (Release-Datei von github.com/Dashlane/dashlane-cli oder „brew install dashlane/tap/dashlane-cli“) und einmal im Terminal mit „dcli sync“ angemeldet; das Master-Passwort muss dcli gespeichert haben (Standard).');
  static capabilities = { write: false, types: ['login', 'note', 'identity'], favorites: false, attachments: false };

  static async login() {
    const st = await this.call('status');
    if (!st.cli) throw new ProviderError(t('dcli (Dashlane CLI) wurde nicht gefunden.'), 'config');
    if (!st.loggedIn) throw new ProviderError(t('Dashlane: nicht angemeldet. Bitte im Terminal „dcli sync“ ausführen.'), 'bad_password');
    if (st.locked) throw new ProviderError(t('Dashlane: Der Tresor ist gesperrt. Bitte im Terminal „dcli sync“ ausführen; das Master-Passwort muss gespeichert sein (dcli configure save-master-password true).'), 'bad_password');
    return { status: 'ok', configPatch: st.email ? { email: st.email } : undefined, session: { connected: true } };
  }

  /** The host needs the kind to know which dcli command holds the entry. */
  static ref(item) { return { id: item.id, kind: item._kind ?? (item.type === 'note' ? 'note' : item.type === 'identity' ? 'id' : 'login') }; }

  static async sync(config) {
    const { items, idsUnavailable } = await this.call('list');
    return {
      items: items.map((e) => {
        const type = ['note', 'identity'].includes(e.type) ? e.type : 'login';
        const label = type === 'identity' ? t(ID_LABELS[e.idType] ?? ID_LABELS.IDENTITY) : undefined;
        return {
          id: e.id, accountId: config.id, provider: 'dashlane', type, _kind: e.kind,
          name: e.name || label || '', username: type === 'login' ? e.username || undefined : undefined, uris: e.uris ?? [],
          subtitle: type === 'identity' && e.name ? label : undefined,
          folderId: null, favorite: false, canEdit: false, canDelete: false,
          lazy: true, hasPassword: type === 'login', hasTotp: !!e.hasTotp,
        };
      }),
      folders: [],
      readOnly: true,
      warning: idsUnavailable ? t('Ausweise und Identitäten liest dcli erst ab Version 6.2642.0.') : undefined,
    };
  }

  static async reveal(config, session, item) {
    const r = await this.call('reveal', this.ref(item));
    if (r.type === 'identity') return mapId(r.idType, r.data);
    const out = { notes: r.notes || undefined, fields: (r.fields ?? []).map((f) => ({ name: f.name, value: f.value, type: 'text' })) };
    if (r.type !== 'note') {
      out.password = r.password ?? '';
      if (r.username) out.username = r.username;
      if (r.uris?.length) out.uris = r.uris;
      if (r.totp) out.totp = r.totp;
    }
    return out;
  }

  static async saveItem() { throw new ProviderError(t('Dashlane: Das CLI kann nur lesen. Bitte in der Dashlane-App ändern.'), 'unsupported'); }
  static async deleteItem() { throw new ProviderError(t('Dashlane: Das CLI kann nur lesen. Bitte in der Dashlane-App ändern.'), 'unsupported'); }
}

export default DashlaneProvider;
