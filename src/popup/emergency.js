// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Tools → Emergency access: as trusted contact of a Bitwarden user, ask for access and, once approved, view their
// items. Read only: no filling, editing, copying into other accounts or export. Inviting, accepting, confirming and
// takeover stay with the Bitwarden apps.
import { typeFields } from './detail.js';
import { S, providerOf } from './state.js';
import { $, TYPE_LABEL, ask, back, call, el, show, t, tn, toast, typeIcon } from './ui.js';

let accountId = null;
let viewing = null; // { grantId, name } while the grantor's items are shown

const STATUS = { invited: 0, accepted: 1, confirmed: 2, initiated: 3, approved: 4 };

export const emergencyAccounts = () => S.state.accounts.filter((a) => a.unlocked && providerOf(a.provider)?.capabilities?.emergencyAccess);
export const resetEmergency = () => { viewing = null; };

const who = (g) => g.name || g.email;

/** Renders the tab into `body`; `rerender` redraws the whole tools view. */
export async function renderEmergency(body, rerender, { footer }) {
  const accounts = emergencyAccounts();
  if (!accounts.some((a) => a.id === accountId)) { accountId = accounts[0]?.id ?? null; viewing = null; }
  if (!accountId) { body.append(el('p', { className: 'hint' }, t('Entsperre ein Bitwarden-Konto, um Notfallzugriff zu nutzen.')), footer([])); return; }
  if (viewing) { await renderItems(body, rerender, footer); return; }

  const accSel = accounts.length > 1
    ? el('label', {}, t('Konto'), el('select', { id: 'emergency-account', onchange: (e) => { accountId = e.target.value; rerender(); } },
      accounts.map((a) => el('option', { value: a.id, selected: a.id === accountId }, a.label))))
    : null;
  const list = el('div', { className: 'pick-list', id: 'emergency-list' }, el('p', { className: 'empty-note' }, t('Lade …')));
  body.append(...[
    el('p', { className: 'hint' }, t('Hier erscheinen Personen, die dich in Bitwarden als Notfallkontakt eingetragen haben. Du kannst Zugriff anfordern und nach der Freigabe ihre Einträge ansehen – nur lesen. Einladen, Annehmen, Bestätigen und Übernahme gehen in den Bitwarden-Apps.')),
    accSel, list, footer([])].filter(Boolean));

  let grants;
  try { grants = await call('emergencyGrants', { accountId }); } catch (e) { list.replaceChildren(el('p', { className: 'hint warn' }, e.message)); return; }
  list.replaceChildren(...(grants.length ? grants.map((g) => grantRow(g, rerender))
    : [el('p', { className: 'empty-note' }, t('Niemand hat dir Notfallzugriff gewährt.'))]));
}

function statusText(g) {
  const wait = tn(g.waitTimeDays, '{n} Tag', '{n} Tage');
  switch (g.status) {
    case STATUS.invited: return t('Eingeladen – nimm die Einladung in den Bitwarden-Apps an.');
    case STATUS.accepted: return t('Angenommen – {name} muss dich noch bestätigen.', { name: who(g) });
    case STATUS.confirmed: return t('Bereit. Wartezeit nach einer Anforderung: {wait}.', { wait });
    case STATUS.initiated: return t('Angefordert. {name} kann freigeben oder ablehnen; ohne Antwort gibt der Server den Zugriff nach {wait} frei.', { name: who(g), wait });
    case STATUS.approved: return t('Freigegeben');
    default: return t('Unbekannter Status ({status})', { status: g.status });
  }
}

function grantRow(g, rerender) {
  const takeover = g.type === 'takeover';
  const actions = [];
  if (!takeover && g.status === STATUS.confirmed) {
    actions.push(el('button', { type: 'button', className: 'secondary', 'data-action': 'initiate', onclick: async () => {
      if (!await ask(t('Notfallzugriff auf das Konto von {name} anfordern? {name} wird benachrichtigt. Ohne Antwort gibt der Server den Zugriff nach {wait} frei.',
        { name: who(g), wait: tn(g.waitTimeDays, '{n} Tag', '{n} Tage') }), { ok: t('Anfordern') })) return;
      try { await call('emergencyInitiate', { accountId, grantId: g.id }); toast(t('Zugriff angefordert')); } catch (e) { toast(e.message); }
      rerender();
    } }, t('Zugriff anfordern')));
  }
  if (!takeover && g.status === STATUS.approved) {
    actions.push(el('button', { type: 'button', 'data-action': 'view', onclick: () => { viewing = { grantId: g.id, name: who(g) }; rerender(); } }, t('Einträge ansehen')));
  }
  return el('div', { className: 'send-row', 'data-grant-id': g.id },
    el('span', { className: 'type-ico' }, typeIcon('identity', { size: 14 })),
    el('span', { className: 'pick-name' }, who(g)),
    el('span', { className: 'pick-sub' }, [g.name && g.email !== g.name ? g.email : null, takeover ? t('Übernahme') : t('Ansehen')].filter(Boolean).join(' · ')),
    el('p', { className: 'hint', 'data-status': String(g.status) }, takeover ? t('Übernahme ist nur in den Bitwarden-Apps möglich.') : statusText(g)),
    actions.length ? el('div', { className: 'row' }, actions) : null);
}

async function renderItems(body, rerender, footer) {
  const { grantId, name } = viewing;
  const list = el('div', { className: 'pick-list', id: 'emergency-items' }, el('p', { className: 'empty-note' }, t('Lade …')));
  const leave = el('button', { type: 'button', className: 'secondary', onclick: () => { viewing = null; rerender(); } }, t('Zur Übersicht'));
  body.append(
    el('h3', {}, t('Einträge von {name}', { name })),
    el('p', { className: 'hint' }, t('Nur ansehen und kopieren. Diese Einträge werden nicht ausgefüllt, nicht durchsucht und nicht exportiert; beim Sperren vergisst OmniVault sie.')),
    list, footer([leave]));
  let res;
  try { res = await call('emergencyView', { accountId, grantId }); } catch (e) { list.replaceChildren(el('p', { className: 'hint warn' }, e.message)); return; }
  const rows = res.items.map((i) => el('div', { className: 'pick', 'data-item-id': i.id },
    el('span', { className: 'type-ico' }, typeIcon(i.type, { size: 14 })),
    el('button', { type: 'button', className: 'link pick-name', title: t('Details öffnen'), onclick: () => openEmergencyItem(accountId, grantId, i.id, name) }, i.name || t('(ohne Namen)')),
    el('span', { className: 'pick-sub' }, i.username || i.subtitle || '')));
  list.replaceChildren(...(rows.length ? rows : [el('p', { className: 'empty-note' }, t('Keine Einträge.'))]));
  if (res.failed) list.append(el('p', { className: 'hint warn' }, tn(res.failed, '{n} Eintrag konnte nicht entschlüsselt werden', '{n} Einträge konnten nicht entschlüsselt werden')));
}

/** Read-only detail of one of the grantor's items: fields with show and copy, nothing else. */
async function openEmergencyItem(accId, grantId, itemId, name) {
  const i = await call('emergencyItem', { accountId: accId, grantId, itemId });
  const notes = [];
  if (i.attachmentCount) notes.push(tn(i.attachmentCount, '{n} Anhang – nur in den Bitwarden-Apps abrufbar.', '{n} Anhänge – nur in den Bitwarden-Apps abrufbar.'));
  if (i.passkeyCount) notes.push(tn(i.passkeyCount, '{n} Passkey – im Notfallzugriff nicht nutzbar.', '{n} Passkeys – im Notfallzugriff nicht nutzbar.'));
  $('#view-item').replaceChildren(...[
    el('div', { className: 'detail-head' },
      el('span', { className: 'type-ico', title: TYPE_LABEL[i.type] ?? '' }, typeIcon(i.type, { size: 18 })),
      el('h2', {}, i.name || t('(ohne Namen)'))),
    el('div', { className: 'detail-sub' }, [TYPE_LABEL[i.type], t('Notfallzugriff: {name}', { name }), t('nur lesen')].filter(Boolean).join(' · ')),
    el('div', { className: 'fields' }, typeFields(i)),
    ...notes.map((n) => el('p', { className: 'hint' }, n)),
    el('div', { className: 'row actions' }, el('button', { type: 'button', className: 'secondary', onclick: () => back() }, t('Zurück'))),
  ]);
  show('item', { restore: () => openEmergencyItem(accId, grantId, itemId, name) });
}
