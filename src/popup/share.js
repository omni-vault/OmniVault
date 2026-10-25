// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Share dialog (Passbolt): who has access, change their rights, add people or groups, remove access.
// Works for one entry or for a folder (`isFolder: true`), whose changes also apply to the entries inside.
import { mark } from '../i18n/index.js';
import { $, call, el, iconButton, t, toast } from './ui.js';

const LEVELS = [[1, mark('Kann lesen')], [7, mark('Kann bearbeiten')], [15, mark('Ist Besitzer')]];

/**
 * Opens the dialog for one item or folder ({ accountId, id, name, isFolder }); resolves false when nothing changed,
 * otherwise true (entry) or { skipped, failed } (folder).
 */
export async function openShare(item) {
  const d = $('#dialog-transfer');
  const permissions = item.isFolder
    ? await call('folderPermissions', { accountId: item.accountId, folderId: item.id })
    : await call('permissions', { accountId: item.accountId, itemId: item.id });
  const rows = permissions.map((p) => ({ ...p, original: p.type }));
  const list = el('div', { className: 'share-list' });
  const results = el('div', { className: 'share-results' });
  const search = el('input', { type: 'search', placeholder: t('Person oder Gruppe suchen …'), 'aria-label': t('Person oder Gruppe suchen'), autocomplete: 'off' });
  const err = el('p', { className: 'error', hidden: true });

  const draw = () => list.replaceChildren(...rows.filter((r) => !r.removed).map((r) => {
    const level = el('select', { 'aria-label': t('Rechte von {name}', { name: r.name }) }, LEVELS.map(([v, l]) => el('option', { value: v }, t(l))));
    level.value = String(r.type);
    level.addEventListener('change', () => { r.type = Number(level.value); });
    return el('div', { className: 'share-row' },
      el('div', { className: 'share-who' }, el('strong', {}, r.name), el('span', {}, r.sub ?? '')),
      level,
      iconButton('x', t('Zugriff entfernen'), { 'aria-label': t('Zugriff für {name} entfernen', { name: r.name }), onclick: () => { if (r.id) r.removed = true; else rows.splice(rows.indexOf(r), 1); draw(); } }));
  }));

  let timer;
  search.addEventListener('input', () => {
    clearTimeout(timer);
    const q = search.value.trim();
    if (q.length < 2) { results.replaceChildren(); return; }
    timer = setTimeout(async () => {
      const targets = await call('shareTargets', { accountId: item.accountId, itemId: item.id, query: q }).catch((e) => { toast(e.message); return []; });
      const present = new Set(rows.filter((r) => !r.removed).map((r) => `${r.aro}:${r.aroId}`));
      results.replaceChildren(...targets.filter((x) => !present.has(`${x.aro}:${x.aroId}`)).slice(0, 6).map((x) => el('button', {
        type: 'button', className: 'share-target', onclick: () => {
          const again = rows.find((r) => r.aro === x.aro && r.aroId === x.aroId);
          if (again) again.removed = false; else rows.push({ ...x, type: 1 });
          search.value = ''; results.replaceChildren(); draw();
        },
      }, el('strong', {}, x.name), el('span', {}, x.sub ?? ''))));
    }, 250);
  });

  const save = el('button', { type: 'button' }, t('Speichern'));
  let result = true;
  d.replaceChildren(el('div', { className: 'share' },
    el('h3', {}, item.isFolder ? t('Ordner „{name}“ teilen', { name: item.name }) : t('„{name}“ teilen', { name: item.name })),
    list, search, results,
    el('p', { className: 'hint' }, item.isFolder
      ? t('Die Änderungen gelten auch für alle Einträge und Unterordner darin, die dir gehören. Neue Personen bekommen die Geheimnisse für ihren Schlüssel verschlüsselt.')
      : t('Neue Personen bekommen das Geheimnis für ihren Schlüssel verschlüsselt. Mindestens ein Besitzer muss bleiben.')),
    err,
    el('div', { className: 'row' }, el('button', { type: 'button', className: 'secondary', onclick: () => d.close('cancel') }, t('Abbrechen')), save)));
  draw();

  save.addEventListener('click', async () => {
    const changes = [
      ...rows.filter((r) => r.id && r.removed).map((r) => ({ id: r.id, delete: true })),
      ...rows.filter((r) => r.id && !r.removed && r.type !== r.original).map((r) => ({ id: r.id, type: r.type })),
      ...rows.filter((r) => !r.id).map((r) => ({ aro: r.aro, aroId: r.aroId, type: r.type })),
    ];
    if (!changes.length) { d.close('cancel'); return; }
    save.disabled = true;
    try {
      if (item.isFolder) result = await call('shareFolder', { accountId: item.accountId, folderId: item.id, changes });
      else await call('share', { accountId: item.accountId, itemId: item.id, changes });
      d.close('ok');
    } catch (x) {
      err.textContent = x.message; err.hidden = false; save.disabled = false;
    }
  });
  d.returnValue = '';
  d.showModal();
  await new Promise((r) => d.addEventListener('close', r, { once: true }));
  return d.returnValue === 'ok' && result;
}
