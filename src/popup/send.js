// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Tools → Send: the own Bitwarden Sends of an unlocked account (list, new text or file Send, edit, copy link,
// remove password, delete). The background encrypts; the popup gets text, notes and link only when it asks.
import { ext } from '../lib/browser.js';
import { AZURE_BLOB_ORIGINS, endpoints } from '../providers/bitwarden/api.js';
import { formatDateTime, mark } from '../i18n/index.js';
import { requestPermissions } from './resume.js';
import { S, providerOf } from './state.js';
import { ask, call, copy, el, icon, iconButton, t, tn, toast } from './ui.js';

/** Largest file OmniVault uploads (it travels base64-encoded between popup and background), as for attachments. */
const MAX_UPLOAD_MB = 30;
const HOUR = 3600_000;
const DAY = 24 * HOUR;
/** Durations offered for deletion and expiry, like the Bitwarden apps (the servers allow at most 31 days). */
const DURATIONS = [
  [HOUR, mark('1 Stunde')], [DAY, mark('1 Tag')], [2 * DAY, mark('2 Tage')], [3 * DAY, mark('3 Tage')],
  [7 * DAY, mark('7 Tage')], [14 * DAY, mark('14 Tage')], [30 * DAY, mark('30 Tage')],
];

let accountId = null;
let editing = null; // null: list; { type } for a new Send; a full Send for editing

export const sendAccounts = () => S.state.accounts.filter((a) => a.unlocked && !a.readOnly && providerOf(a.provider)?.capabilities?.send);

const when = (d) => formatDateTime(d, { dateStyle: 'medium', timeStyle: 'short' });
const isCloud = (a) => /\.bitwarden\.(com|eu)$/.test(new URL(endpoints(a.server).api).hostname);

/** Renders the Send tab into `body`; `rerender` redraws the whole tools view. */
export async function renderSend(body, rerender, { footer }) {
  const accounts = sendAccounts();
  if (!accounts.some((a) => a.id === accountId)) accountId = accounts[0]?.id ?? null;
  if (!accountId) { body.append(el('p', { className: 'hint' }, t('Entsperre ein Bitwarden-Konto, um Sends zu nutzen.')), footer([])); return; }
  if (editing) { renderForm(body, rerender); return; }

  const accSel = accounts.length > 1
    ? el('label', {}, t('Konto'), el('select', { id: 'send-account', onchange: (e) => { accountId = e.target.value; rerender(); } },
      accounts.map((a) => el('option', { value: a.id, selected: a.id === accountId }, a.label))))
    : null;
  const list = el('div', { className: 'pick-list', id: 'send-list' }, el('p', { className: 'empty-note' }, t('Lade …')));
  body.append(...[
    el('p', { className: 'hint' }, t('Mit Send teilst du Text oder eine Datei verschlüsselt über einen Link. Der Schlüssel steckt im Link; der Server sieht den Inhalt nicht. Sends werden spätestens zum Löschdatum entfernt.')),
    accSel,
    el('div', { className: 'row' },
      el('button', { type: 'button', id: 'send-new-text', onclick: () => { editing = { type: 'text' }; rerender(); } }, t('Neuer Text-Send')),
      el('button', { type: 'button', id: 'send-new-file', className: 'secondary', onclick: () => { editing = { type: 'file' }; rerender(); } }, t('Neuer Datei-Send'))),
    list,
    footer([])].filter(Boolean));

  let sends;
  try { sends = await call('sends', { accountId }); } catch (e) { list.replaceChildren(el('p', { className: 'hint warn' }, e.message)); return; }
  list.replaceChildren(...(sends.length ? sends.map((s) => sendRow(s, rerender)) : [el('p', { className: 'empty-note' }, t('Noch keine Sends.'))]));
}

function status(s) {
  const now = Date.now();
  if (s.disabled) return t('deaktiviert');
  if (s.expirationDate && new Date(s.expirationDate).getTime() <= now) return t('abgelaufen');
  if (s.maxAccessCount && s.accessCount >= s.maxAccessCount) return t('Zugriffe aufgebraucht');
  return null;
}

function sendRow(s, rerender) {
  const accesses = s.maxAccessCount
    ? t('{n} von {max} Zugriffen', { n: s.accessCount, max: s.maxAccessCount })
    : tn(s.accessCount, '{n} Zugriff', '{n} Zugriffe');
  const sub = [
    s.type === 'file' ? t('Datei') : t('Text'),
    s.expirationDate ? t('läuft ab {date}', { date: when(s.expirationDate) }) : t('gelöscht {date}', { date: when(s.deletionDate) }),
    accesses,
  ].join(' · ');
  const state = status(s);
  const run = async (fn, done) => { try { await fn(); if (done) toast(done); rerender(); } catch (e) { toast(e.message); } };
  return el('div', { className: 'send-row', 'data-send-id': s.id },
    el('span', { className: 'type-ico' }, icon(s.type === 'file' ? 'download' : 'note', { size: 14 })),
    el('span', { className: 'pick-name' }, s.name || t('(ohne Namen)')),
    el('span', { className: 'pick-sub' }, sub),
    el('span', { className: 'send-tags' },
      s.hasPassword ? el('span', { className: 'tag' }, t('Passwort')) : null,
      state ? el('span', { className: 'tag warn' }, state) : null),
    el('div', { className: 'tools' },
      iconButton('copy', t('Link kopieren'), {
        'aria-label': t('Link zu „{name}“ kopieren', { name: s.name }),
        onclick: async () => { try { const full = await call('send', { accountId, sendId: s.id }); await copy(full.link, t('Link')); } catch (e) { toast(e.message); } },
      }),
      iconButton('edit', t('Bearbeiten'), {
        'aria-label': t('„{name}“ bearbeiten', { name: s.name }),
        onclick: async () => { try { editing = await call('send', { accountId, sendId: s.id }); rerender(); } catch (e) { toast(e.message); } },
      }),
      s.hasPassword ? iconButton('unlock', t('Passwort entfernen'), {
        'aria-label': t('Passwort von „{name}“ entfernen', { name: s.name }),
        onclick: async () => {
          if (!await ask(t('Passwort von „{name}“ entfernen? Danach kann jeder mit dem Link den Send öffnen.', { name: s.name }), { ok: t('Passwort entfernen'), danger: true })) return;
          run(() => call('removeSendPassword', { accountId, sendId: s.id }), t('Passwort entfernt'));
        },
      }) : null,
      iconButton('trash', t('Löschen'), {
        'aria-label': t('„{name}“ löschen', { name: s.name }),
        onclick: async () => {
          if (!await ask(t('Send „{name}“ löschen? Der Link funktioniert danach nicht mehr.', { name: s.name }), { ok: t('Löschen'), danger: true })) return;
          run(() => call('deleteSend', { accountId, sendId: s.id }), t('Send gelöscht'));
        },
      })));
}

/** Value for <input type=datetime-local> in local time. */
function localInput(d) {
  const x = new Date(d);
  const p = (n) => String(n).padStart(2, '0');
  return `${x.getFullYear()}-${p(x.getMonth() + 1)}-${p(x.getDate())}T${p(x.getHours())}:${p(x.getMinutes())}`;
}

/** Duration picker with „own date“; `none` adds a first option (e.g. „never“). Returns { label, value() }. */
function datePicker(name, labelText, { current = null, fallback = 7 * DAY, none = null, max }) {
  const custom = el('input', { type: 'datetime-local', name: `${name}-custom`, hidden: true, max: localInput(max), min: localInput(Date.now()) });
  const sel = el('select', { name },
    none ? el('option', { value: '' }, none) : null,
    DURATIONS.map(([ms, label]) => el('option', { value: String(ms) }, t(label))),
    el('option', { value: 'custom' }, t('Eigenes Datum …')));
  if (current) { sel.value = 'custom'; custom.value = localInput(current); custom.hidden = false; } else sel.value = none ? '' : String(fallback);
  sel.addEventListener('change', () => {
    custom.hidden = sel.value !== 'custom';
    if (!custom.hidden && !custom.value) custom.value = localInput(Date.now() + fallback);
  });
  return {
    label: el('label', {}, labelText, sel, custom),
    value: () => {
      if (sel.value === '') return null;
      if (sel.value === 'custom') return custom.value ? new Date(custom.value).toISOString() : null;
      return new Date(Date.now() + Number(sel.value)).toISOString();
    },
  };
}

function renderForm(body, rerender) {
  const s = editing;
  const isNew = !s.id;
  const account = S.state.accounts.find((a) => a.id === accountId);
  const close = () => { editing = null; rerender(); };
  const max = Date.now() + 31 * DAY - 5 * 60_000;
  const name = el('input', { name: 'name', required: s.type === 'text' || !isNew, placeholder: s.type === 'file' && isNew ? t('Dateiname') : '', value: s.name ?? '', autocomplete: 'off' });
  const text = el('textarea', { name: 'text', rows: 5 }, s.text ?? '');
  const hidden = el('input', { type: 'checkbox', name: 'hidden', checked: !!s.hidden });
  const file = el('input', { type: 'file', name: 'file' });
  const deletion = datePicker('deletion', t('Löschdatum'), { current: isNew ? null : s.deletionDate, max });
  const expiry = datePicker('expiration', t('Ablaufdatum'), { current: isNew ? null : s.expirationDate, fallback: DAY, none: t('Nie'), max });
  const maxAccess = el('input', { type: 'number', name: 'maxAccessCount', min: 1, step: 1, inputmode: 'numeric', value: s.maxAccessCount ?? '', placeholder: t('unbegrenzt') });
  const password = el('input', { type: 'password', name: 'password', autocomplete: 'new-password', placeholder: s.hasPassword ? t('unverändert') : t('kein Passwort') });
  const notes = el('textarea', { name: 'notes', rows: 2 }, s.notes ?? '');
  const hideEmail = el('input', { type: 'checkbox', name: 'hideEmail', checked: !!s.hideEmail });
  const disabled = el('input', { type: 'checkbox', name: 'disabled', checked: !!s.disabled });
  const save = el('button', { type: 'submit', id: 'send-save' }, isNew ? t('Send erstellen') : t('Speichern'));

  // bitwarden.com/.eu keep files in Azure Blob Storage, which needs its own permission (asked once, like attachments)
  let granted = !(s.type === 'file' && isNew && isCloud(account));
  const grant = el('button', { type: 'button', className: 'secondary', hidden: granted,
    onclick: () => requestPermissions({ origins: AZURE_BLOB_ORIGINS }, { view: 'send', accountId }).then((ok) => {
      granted = ok; grant.hidden = ok;
      toast(ok ? t('Zugriff erteilt – jetzt die Datei wählen.') : t('Ohne Zugriff auf Bitwardens Dateispeicher lassen sich keine Datei-Sends anlegen.'));
    }).catch((e) => toast(e.message)) }, t('Zugriff auf Bitwardens Dateispeicher erlauben …'));
  if (!granted) ext.permissions.contains({ origins: AZURE_BLOB_ORIGINS }).then((ok) => { granted = ok; grant.hidden = ok; }).catch(() => {});

  const form = el('form', { id: 'send-form', onsubmit: async (e) => {
    e.preventDefault();
    const data = {
      type: s.type, name: name.value.trim(), notes: notes.value, deletionDate: deletion.value(), expirationDate: expiry.value(),
      maxAccessCount: maxAccess.value ? Number(maxAccess.value) : null, password: password.value || null,
      hideEmail: hideEmail.checked, disabled: disabled.checked,
      ...(s.type === 'text' ? { text: text.value, hidden: hidden.checked } : {}),
    };
    if (!data.deletionDate) { toast(t('Bitte ein Löschdatum wählen.')); return; }
    if (s.type === 'file' && isNew) {
      const f = file.files?.[0];
      if (!granted) { toast(t('Ohne Zugriff auf Bitwardens Dateispeicher lassen sich keine Datei-Sends anlegen.')); return; }
      if (!f) { toast(t('Bitte eine Datei wählen.')); return; }
      if (f.size > MAX_UPLOAD_MB * 1024 * 1024) { toast(t('Die Datei ist zu groß (höchstens {n} MB).', { n: MAX_UPLOAD_MB })); return; }
      data.file = { fileName: f.name, data: await fileToBase64(f) };
      if (!data.name) data.name = f.name;
    }
    save.disabled = true;
    toast(isNew ? t('Erstelle Send …') : t('Speichere …'), 120_000);
    try {
      const saved = await call('saveSend', { accountId, sendId: s.id ?? null, data });
      editing = null;
      rerender();
      if (isNew) {
        toast(t('Send erstellt'));
        if (await ask(t('Send „{name}“ erstellt. Link jetzt kopieren?', { name: saved.name }), { ok: t('Link kopieren') })) await copy(saved.link, t('Link'));
      } else toast(t('Send gespeichert'));
    } catch (x) { toast(x.message, 6000); save.disabled = false; }
  } },
  el('h3', {}, isNew ? (s.type === 'file' ? t('Neuer Datei-Send') : t('Neuer Text-Send')) : t('Send bearbeiten')),
  el('label', {}, t('Name'), name),
  s.type === 'text'
    ? [el('label', {}, t('Text'), text), el('label', { className: 'inline-check' }, hidden, t('Text beim Öffnen verbergen'))]
    : isNew
      ? [el('label', {}, t('Datei (höchstens {n} MB)', { n: MAX_UPLOAD_MB }), file), grant]
      : el('p', { className: 'hint' }, t('Datei: {name} (lässt sich nicht ändern)', { name: s.fileName })),
  el('div', { className: 'two' }, deletion.label, expiry.label),
  el('div', { className: 'two' }, el('label', {}, t('Höchstzahl der Zugriffe'), maxAccess), el('label', {}, t('Passwort'), password)),
  !isNew && s.hasPassword ? el('p', { className: 'hint' }, t('Leer lassen, um das bisherige Passwort zu behalten. Entfernen geht über die Liste.')) : null,
  el('label', {}, t('Private Notizen (sehen Empfänger nicht)'), notes),
  el('label', { className: 'inline-check' }, hideEmail, t('Meine E-Mail-Adresse vor Empfängern verbergen')),
  el('label', { className: 'inline-check' }, disabled, t('Deaktiviert – niemand kann den Send öffnen')),
  el('div', { className: 'row actions' }, el('button', { type: 'button', className: 'secondary', onclick: close }, t('Abbrechen')), save));
  body.append(form);
  name.focus();
}

/** Reads a file as base64 without building a huge intermediate string. */
function fileToBase64(f) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result).slice(String(r.result).indexOf(',') + 1));
    r.onerror = () => reject(new Error(t('Datei konnte nicht gelesen werden.')));
    r.readAsDataURL(f);
  });
}

/** Back to the list (another tab was chosen). */
export function resetSend() { editing = null; }

/** After the permission prompt closed the popup: back to a new file Send. */
export function resumeSend(r) {
  accountId = r.accountId;
  editing = { type: 'file' };
}
