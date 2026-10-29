// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Generator view: passwords, passphrases, PINs and usernames. Settings persist; generated secrets are kept in RAM
// only (last 10). Secrets are hidden until the user shows them (eye button), also in the list of recent ones;
// usernames are not secret and are shown directly.
import {
  PASSPHRASE_MAX, PASSPHRASE_MIN, entropyBits, generatePassphrase, generatePassword, generatePin, generateUsername,
  normalizeGenerator, passphraseEntropy, strengthLabel,
} from '../lib/generator.js';
import { S } from './state.js';
import { formatDateTime } from '../i18n/index.js';
import { $, back, call, copy, el, icon, iconButton, show, t } from './ui.js';

const MASK = '••••••••••••';

/** Eye button that shows/hides `target` (value from get()); hidden until the user asks. */
function revealButton(label, render) {
  let shown = false;
  const b = iconButton('eye', t('Anzeigen'), {
    'aria-label': t('{label} anzeigen', { label }), 'aria-pressed': 'false',
    onclick: () => {
      shown = !shown;
      b.setAttribute('aria-pressed', String(shown));
      b.title = shown ? t('Verbergen') : t('Anzeigen');
      b.replaceChildren(icon(shown ? 'eyeOff' : 'eye'));
      render(shown);
    },
  });
  return { button: b, shown: () => shown };
}

const LABELS = { password: () => t('Passwort'), passphrase: () => t('Passphrase'), pin: () => t('PIN'), username: () => t('Benutzername') };

/**
 * `onUse(value)`: "Use" button (editor). `kind: 'username'` opens the username generator for the editor's username
 * field; the chosen kind is then not remembered as the default.
 */
export async function openGenerator({ onUse, kind } = {}) {
  const view = $('#view-generator');
  const opts = normalizeGenerator(S.state.settings?.generator);
  let mode = kind === 'username' ? 'username' : opts.type === 'username' && onUse ? 'password' : opts.type;
  let value = '';
  const out = el('div', { className: 'gen-out', id: 'gen-out', 'aria-live': 'polite', translate: 'no' });
  const reveal = revealButton(t('Wert'), () => render());
  const meter = el('div', { className: 'meter' }, el('div'));
  const info = el('div', { className: 'hint', id: 'gen-info' });
  const typeHint = el('p', { className: 'hint', id: 'gen-type-hint' });

  // password and PIN
  const lenLabel = el('span');
  const len = el('input', { type: 'range', min: '4', max: '64', value: String(Math.min(opts.length, 64)), 'aria-label': t('Länge'), 'data-gen': 'length' });
  const box = (key, label) => el('label', {}, el('input', { type: 'checkbox', checked: !!opts[key], 'data-opt': key }), label);
  const checks = el('div', { className: 'checks', 'data-section': 'password' },
    box('upper', 'A–Z'), box('lower', 'a–z'), box('digits', '0–9'), box('symbols', '!@#$…'), box('avoidAmbiguous', t('ohne I l 1 O 0')));
  const lenBox = el('label', { style: { margin: 0 }, 'data-section': 'length' }, lenLabel, len);

  // passphrase
  const wordsLabel = el('span');
  const words = el('input', { type: 'range', min: String(PASSPHRASE_MIN), max: String(PASSPHRASE_MAX), value: String(opts.words), 'aria-label': t('Wörter'), 'data-gen': 'words' });
  const wordsBox = el('label', { style: { margin: 0 }, 'data-section': 'words' }, wordsLabel, words);
  const separator = el('input', { value: opts.separator, maxLength: 3, spellcheck: 'false', autocomplete: 'off', 'data-gen': 'separator', style: { width: '6em', display: 'block' } });
  const phraseChecks = el('div', { className: 'checks' }, box('capitalize', t('Großschreibung')), box('includeNumber', t('Zahl anhängen')));
  const phraseBox = el('div', { 'data-section': 'passphrase' }, el('label', {}, t('Trennzeichen'), separator), phraseChecks);

  // username
  const userType = el('select', { 'aria-label': t('Benutzername aus'), 'data-gen': 'usernameType' },
    el('option', { value: 'word' }, t('Zufälliges Wort')),
    el('option', { value: 'plus' }, t('Plus-Adresse')),
    el('option', { value: 'catchall' }, t('Catch-all-Domain')));
  userType.value = opts.usernameType;
  const userTypeBox = el('label', { style: { margin: 0 }, 'data-section': 'usernameType' }, t('Benutzername aus'), userType);
  const plusEmail = el('input', { type: 'email', value: opts.plusEmail, placeholder: 'name@example.com', spellcheck: 'false', autocomplete: 'off', 'data-gen': 'plusEmail' });
  const catchAll = el('input', { value: opts.catchAllDomain, placeholder: 'example.com', spellcheck: 'false', autocomplete: 'off', 'data-gen': 'catchAllDomain' });
  const userWordBox = el('div', { className: 'checks', 'data-section': 'username-word' },
    box('usernameCapitalize', t('Großschreibung')), box('usernameNumber', t('Zahl anhängen')));
  const plusBox = el('label', { 'data-section': 'username-plus' }, t('Deine E-Mail-Adresse'), plusEmail);
  const catchAllBox = el('label', { 'data-section': 'username-catchall' }, t('Deine Domain'), catchAll);

  const modeSel = el('select', { 'aria-label': t('Art'), id: 'gen-mode' },
    el('option', { value: 'password' }, t('Passwort')), el('option', { value: 'passphrase' }, t('Passphrase')),
    el('option', { value: 'pin' }, t('PIN')), el('option', { value: 'username' }, t('Benutzername')));
  modeSel.value = mode;
  const historyBox = el('details', { className: 'history' });

  const secret = () => mode !== 'username';
  function render() {
    out.textContent = !value ? out.textContent : secret() && !reveal.shown() ? MASK : value;
  }
  const read = () => {
    opts.length = Number(len.value);
    opts.words = Number(words.value);
    opts.separator = separator.value;
    opts.usernameType = userType.value;
    opts.plusEmail = plusEmail.value.trim();
    opts.catchAllDomain = catchAll.value.trim();
    for (const c of view.querySelectorAll('[data-opt]')) opts[c.dataset.opt] = c.checked;
  };
  const layout = () => {
    lenBox.hidden = !['password', 'pin'].includes(mode);
    wordsBox.hidden = mode !== 'passphrase';
    userTypeBox.hidden = mode !== 'username';
    checks.hidden = mode !== 'password';
    phraseBox.hidden = mode !== 'passphrase';
    userWordBox.hidden = mode !== 'username' || opts.usernameType !== 'word';
    plusBox.hidden = mode !== 'username' || opts.usernameType !== 'plus';
    catchAllBox.hidden = mode !== 'username' || opts.usernameType !== 'catchall';
    reveal.button.hidden = !secret();
    meter.hidden = !secret();
    info.hidden = !secret();
    typeHint.textContent = mode === 'passphrase' ? t('Wörter aus der EFF-Wortliste (7776 Wörter), zufällig gewählt.')
      : mode !== 'username' ? ''
        : opts.usernameType === 'plus' ? t('Mails an name+zufall@… landen bei vielen Anbietern im selben Postfach.')
          : opts.usernameType === 'catchall' ? t('Nur für eigene Domains, deren Mailserver jede Adresse annimmt.')
            : t('Ein zufälliges Wort aus der EFF-Wortliste.');
    typeHint.hidden = !typeHint.textContent;
  };
  const regenerate = () => {
    read();
    layout();
    let bits = 0;
    try {
      if (mode === 'pin') value = generatePin(Math.min(opts.length, 12));
      else if (mode === 'passphrase') value = generatePassphrase(opts);
      else if (mode === 'username') value = generateUsername(opts);
      else value = generatePassword(opts);
      bits = mode === 'pin' ? Math.floor(Math.min(opts.length, 12) * Math.log2(10))
        : mode === 'passphrase' ? passphraseEntropy(opts) : mode === 'password' ? entropyBits(opts) : 0;
    } catch (e) {
      value = '';
      out.textContent = e.message;
    }
    out.dataset.length = String(value.length);
    out.dataset.mode = mode;
    out.classList.toggle('error', !value);
    render();
    meter.firstChild.style.width = `${Math.min(100, bits)}%`;
    info.textContent = t('≈ {bits} Bit – {strength}', { bits, strength: strengthLabel(bits) });
    lenLabel.textContent = t('Länge: {n}', { n: mode === 'pin' ? Math.min(opts.length, 12) : opts.length });
    wordsLabel.textContent = t('Wörter: {n}', { n: opts.words });
  };
  const persist = () => {
    read();
    const generator = { ...opts, type: kind === 'username' ? normalizeGenerator(S.state.settings?.generator).type : mode };
    return call('setSettings', { patch: { generator } }).then((s) => { S.state.settings = s; }).catch(() => {});
  };
  for (const r of [len, words, separator, plusEmail, catchAll]) {
    r.addEventListener('input', regenerate);
    r.addEventListener('change', persist);
  }
  // only the checkboxes: leaving a text field (its change event) must not replace the value just shown
  for (const c of [checks, phraseChecks, userWordBox]) c.addEventListener('change', () => { regenerate(); persist(); });
  userType.addEventListener('change', () => { regenerate(); persist(); });
  modeSel.addEventListener('change', () => { mode = modeSel.value; regenerate(); persist(); });

  const renderHistory = async () => {
    const list = await call('generated').catch(() => []);
    historyBox.hidden = !list.length;
    historyBox.replaceChildren(el('summary', {}, t('Zuletzt erzeugt ({n}, nur bis zum Schließen des Browsers)', { n: list.length })),
      el('div', { className: 'fields' }, list.map((g) => {
        const v = el('div', { className: 'v', translate: 'no' }, MASK);
        const r = revealButton(t('Wert'), (shown) => { v.textContent = shown ? g.value : MASK; });
        return el('div', { className: 'field' },
          el('span', { className: 'k' }, formatDateTime(g.at, { timeStyle: 'medium' })), v,
          el('div', { className: 'tools' }, r.button, iconButton('copy', t('Kopieren'), { onclick: () => copy(g.value, t('Wert')) })));
      })));
  };
  // only secrets go into the list of recent values (usernames are not secret and are not kept)
  const remember = async () => { if (value && secret()) { await call('rememberGenerated', { value }); renderHistory(); } };

  view.replaceChildren(
    el('h2', {}, t('Generator')),
    el('div', { className: 'gen-row' }, out, reveal.button), meter, info,
    el('div', { className: 'two', style: { gridTemplateColumns: '1fr auto', alignItems: 'end', margin: '8px 0' } },
      el('div', {}, lenBox, wordsBox, userTypeBox), el('label', { style: { margin: 0 } }, t('Art'), modeSel)),
    typeHint,
    checks, phraseBox, userWordBox, plusBox, catchAllBox,
    historyBox,
    el('div', { className: 'row actions' },
      el('button', { type: 'button', className: 'secondary', onclick: () => back() }, t('Zurück')),
      el('button', { type: 'button', className: 'secondary', onclick: regenerate }, t('Neu erzeugen')),
      el('button', { type: 'button', className: onUse ? 'secondary' : '', 'data-action': 'copy', onclick: async () => { await copy(value, LABELS[mode]()); remember(); } }, t('Kopieren')),
      onUse ? el('button', { type: 'button', 'data-action': 'use', onclick: async () => { if (!value) return; await remember(); onUse(value); } }, t('Übernehmen')) : null));
  regenerate();
  renderHistory();
  show('generator', { restore: () => openGenerator({ onUse, kind }) });
}
