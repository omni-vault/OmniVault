// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Content script (only when the user turned it on and granted access to websites): an OmniVault button in login
// fields that opens the list of matching logins (and passkeys, while the site waits for one), and "save this
// login?" after a form is submitted.
// The list and the save bar are extension pages in iframes, so the page never sees account data; filling only
// accepts logins that belong to this site.
// Runs in embedded frames as well: there the list shows the logins of the frame's own site, and "save this login?"
// opens in the top page. Passkey suggestions stay with the top page (requests from frames go to the browser).
(() => {
  if (window.__omnivaultInline) return;
  window.__omnivaultInline = true;
  const isTop = window.top === window;
  const ext = globalThis.browser ?? globalThis.chrome;
  const send = (type, payload = {}) => ext.runtime.sendMessage({ type, ...payload }).then((r) => (r?.ok ? r.result : null)).catch(() => null);

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled;
  };
  const isPassword = (el) => el instanceof HTMLInputElement && el.type === 'password';
  const isUser = (el) => el instanceof HTMLInputElement && ['text', 'email', 'tel', ''].includes(el.type)
    && (/username|email/.test(el.autocomplete) || /user|mail|login|account|ident/i.test(`${el.name} ${el.id} ${el.placeholder}`));
  const userFieldFor = (pw) => {
    const inputs = [...document.querySelectorAll('input')].filter(visible);
    const before = inputs.slice(0, inputs.indexOf(pw)).filter((i) => ['text', 'email', 'tel', ''].includes(i.type));
    return before.reverse().find(isUser) ?? before[0] ?? null;
  };

  // One closed shadow root holds everything OmniVault draws on the page.
  const host = document.createElement('omnivault-inline');
  host.style.cssText = 'all: initial; position: absolute; top: 0; left: 0; width: 0; height: 0; z-index: 2147483647;';
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `
    button { all: initial; position: absolute; width: 22px; height: 22px; border-radius: 6px; cursor: pointer; display: none;
      background: #2b0a17 url("${ext.runtime.getURL('icons/icon32.png')}") center / 16px no-repeat; box-shadow: 0 1px 3px #0003; }
    iframe { position: absolute; border: 0; border-radius: 10px; box-shadow: 0 8px 28px #0004; display: none; background: transparent; color-scheme: normal; }
    iframe.bar { position: fixed; top: 12px; right: 12px; width: 360px; height: 128px; }`;
  const button = document.createElement('button');
  button.title = 'OmniVault';
  const menu = document.createElement('iframe');
  menu.title = 'OmniVault';
  const bar = document.createElement('iframe');
  bar.className = 'bar';
  bar.title = 'OmniVault';
  root.append(style, button, menu, bar);
  let config = { inline: false, save: false, passkeys: false };
  // fields where the site offers passkeys in the browser's suggestions (autocomplete="username webauthn")
  const isPasskeyField = (el) => el instanceof HTMLInputElement && /\bwebauthn\b/i.test(el.getAttribute('autocomplete') ?? '');
  let anchor = null;

  const place = () => {
    if (!anchor || !anchor.isConnected) return;
    const r = anchor.getBoundingClientRect();
    const x = r.right + window.scrollX - 26;
    const y = r.top + window.scrollY + (r.height - 22) / 2;
    Object.assign(button.style, { left: `${x}px`, top: `${y}px` });
    // 300 × 230 below the field; in a small embedded frame as much as fits, above the field if there is more room there
    const vw = document.documentElement.clientWidth || window.innerWidth;
    const vh = document.documentElement.clientHeight || window.innerHeight;
    const width = Math.min(300, Math.max(160, vw - 8));
    const below = vh - r.bottom - 8;
    const above = r.top - 8;
    const up = below < 230 && above > below;
    const height = Math.max(90, Math.min(230, up ? above : below));
    const left = Math.min(Math.max(4, r.left + r.width - width), Math.max(4, vw - width - 4));
    const top = up ? r.top - height - 4 : r.bottom + 4;
    Object.assign(menu.style, { left: `${left + window.scrollX}px`, top: `${top + window.scrollY}px`, width: `${width}px`, height: `${height}px` });
  };
  const closeMenu = () => { menu.style.display = 'none'; if (menu.src) menu.src = 'about:blank'; };
  const mount = () => { if (!host.isConnected) document.documentElement.append(host); };

  const openMenu = async (auto = false) => {
    place();
    await send('ovMenuFrame'); // the list belongs to this frame (its logins, and filling goes here)
    menu.src = ext.runtime.getURL(`inline-menu.html${auto ? '?auto' : ''}`); // opened by itself: the field keeps the focus
    menu.style.display = 'block';
  };
  document.addEventListener('focusin', async (e) => {
    if (!config.inline && !config.passkeys) return;
    const el = e.target;
    const login = isPassword(el) || (isUser(el) && !!document.querySelector('input[type=password]'));
    const passkeyField = isPasskeyField(el);
    if (!(login || passkeyField) || !visible(el)) return;
    // passkeys: only while the page waits for one (it asked with mediation "conditional")
    const offer = isTop && config.passkeys && (passkeyField || login) ? (await send('ovPasskeyOffer'))?.pending : false;
    if (!(config.inline || offer) || document.activeElement !== el) return;
    if (anchor !== el) closeMenu();
    anchor = el;
    mount();
    place();
    button.style.display = 'block';
    if (offer && passkeyField && menu.style.display !== 'block') openMenu(true); // like the browser's own suggestions
  }, true);
  document.addEventListener('focusout', (e) => {
    if (e.target === anchor) setTimeout(() => { if (menu.style.display === 'none' && document.activeElement !== anchor) button.style.display = 'none'; }, 150);
  }, true);
  button.addEventListener('mousedown', (e) => e.preventDefault()); // keep the focus in the field
  button.addEventListener('click', (e) => {
    if (!e.isTrusted) return;
    if (menu.style.display === 'block') return closeMenu();
    openMenu();
  });
  document.addEventListener('mousedown', (e) => { if (!e.composedPath().includes(host)) closeMenu(); }, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); }, true);
  window.addEventListener('resize', place);
  window.addEventListener('scroll', place, true);

  const showBar = () => { mount(); bar.src = ext.runtime.getURL('save-bar.html'); bar.style.display = 'block'; };
  ext.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (msg?.type === 'ov-inline-close') { closeMenu(); button.style.display = 'none'; }
    if (msg?.type === 'ov-save-close') { bar.style.display = 'none'; bar.src = 'about:blank'; }
    // a login was sent in an embedded frame: the top page shows the bar
    if (msg?.type === 'ov-save-show' && isTop && config.save) { showBar(); respond(true); }
    return false;
  });

  // "Save this login?": remember what was typed when a login form is sent
  let last = '';
  const capture = async () => {
    if (!config.save) return;
    const pw = [...document.querySelectorAll('input[type=password]')].find((i) => i.value && visible(i));
    if (!pw) return;
    const username = userFieldFor(pw)?.value ?? '';
    const key = `${username}\u0000${pw.value}`;
    if (key === last) return;
    last = key;
    if ((await send('ovCapture', { username, password: pw.value }))?.show) showBar();
  };
  document.addEventListener('submit', capture, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Enter' && isPassword(e.target)) capture(); }, true);
  document.addEventListener('click', (e) => {
    const b = e.target.closest?.('button, input[type=submit], input[type=button]');
    if (b && (b.type === 'submit' || /log ?in|sign ?in|anmeld|einlogg|weiter|continue|next/i.test(`${b.textContent} ${b.value ?? ''}`))) capture();
  }, true);

  send('ovConfig').then(async (c) => {
    config = c ?? config;
    // titles in the interface language (the content script has no catalogs of its own)
    if (config.labels) { button.title = config.labels.button; bar.title = config.labels.bar; }
    if (isTop && config.save && (await send('ovPendingSave'))?.show) showBar();
  });
})();
