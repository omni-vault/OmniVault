// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Fills credentials into a tab – into the top page or an embedded frame. Runs only after an explicit user action
// (popup, keyboard shortcut, context menu, the list in a login field).
import { t } from '../i18n/index.js';
import { ext } from '../lib/browser.js';
import { formTargets, loginCandidates, loginFrameOrigins, pairKey } from '../lib/frames.js';
import { matchesUrl } from '../lib/match.js';

/** Smallest frame (and visible part of it) that counts as shown; Stripe's one-line card frames are about 20 px high. */
const MIN_W = 40;
const MIN_H = 14;

/**
 * Injected into frames of the tab, in the extension's isolated world: the page can neither change what this
 * reports (location, the IntersectionObserver) nor see the values until they are set. Must be self-contained.
 * job.op:
 *  'probe' – what the frame holds: own origin, login fields, form fields (dry run for job.keys), whether it is
 *            shown (frames only: size, intersection with the viewport, Chrome's visibility check), and how the
 *            parent sees its child frames (Firefox, which names their frame ids);
 *  'login' – fills username and password; 'form' – fills a payment or address form.
 * 'login' and 'form' first check that the frame still has the origin the background chose (it may have navigated).
 */
async function frameAgent(job) {
  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled;
  };
  const setValue = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const loginFields = () => {
    const inputs = [...document.querySelectorAll('input')].filter(visible);
    const pw = inputs.find((i) => i.type === 'password');
    const userSel = (i) => ['text', 'email', 'tel', ''].includes(i.type) &&
      /user|mail|login|name|account|ident/i.test(`${i.name} ${i.id} ${i.autocomplete} ${i.placeholder}`);
    let user = null;
    if (pw) {
      const before = inputs.slice(0, inputs.indexOf(pw)).filter((i) => ['text', 'email', 'tel', ''].includes(i.type));
      user = before.reverse().find(userSel) ?? before[0] ?? null;
    } else {
      user = inputs.find(userSel) ?? null; // multi-step login: username page
    }
    return { pw, user };
  };
  // payment and address forms: autocomplete tokens first, then name/id/label keywords
  const HINTS = {
    'cc-name': /card.?holder|name.?on.?card|karteninhaber|ccname/i, 'cc-number': /card.?num|cc.?num|kartennummer|cardnumber/i,
    'cc-exp': /exp(iry|iration)?(.?date)?$|gültig|valid.?thru|mm.?\/?.?(yy|jj)/i, 'cc-exp-month': /exp.*m(onth|m)|monat/i,
    'cc-exp-year': /exp.*y(ear|y)|jahr/i, 'cc-csc': /cvc|cvv|csc|security.?code|prüf/i,
    'given-name': /first.?name|vorname|given/i, 'additional-name': /middle/i, 'family-name': /last.?name|nachname|surname|family/i,
    organization: /company|firma|organi/i, email: /e.?mail/i, tel: /phone|tel/i,
    'address-line1': /street|straße|strasse|address.?1|addr.?line.?1|adresse/i, 'address-line2': /address.?2|line.?2|zusatz/i,
    'postal-code': /zip|postal|plz|postleitzahl/i, 'address-level2': /city|ort|stadt|town/i, 'address-level1': /state|bundesland|region|province/i,
    country: /country|land/i, username: /user.?name|benutzer/i,
  };
  /** [element, value] pairs for the form fields that `values` (autocomplete token → value) would fill. */
  const formPlan = (values) => {
    const usable = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && !el.disabled && !el.readOnly; };
    const fields = [...document.querySelectorAll('input, select')].filter(usable).filter((el) => !['hidden', 'submit', 'button', 'checkbox', 'radio', 'password'].includes(el.type) || /cc-csc|cvc|cvv/i.test(el.autocomplete + el.name + el.id));
    const labelOf = (el) => `${el.name} ${el.id} ${el.placeholder ?? ''} ${el.getAttribute('aria-label') ?? ''} ${el.labels?.[0]?.textContent ?? ''}`;
    const used = new Set();
    const plan = [];
    for (const [token, value] of Object.entries(values)) {
      if (!value) continue;
      const byAuto = fields.find((el) => !used.has(el) && el.autocomplete?.split(/\s+/).includes(token));
      const byName = byAuto ?? fields.find((el) => !used.has(el) && !el.autocomplete?.match(/cc-|name|address|postal|email|tel|country|organization/) && HINTS[token]?.test(labelOf(el)));
      if (byName) { used.add(byName); plan.push([byName, value]); }
    }
    return plan;
  };
  const setFormValue = (el, v) => {
    if (el instanceof HTMLSelectElement) {
      const opt = [...el.options].find((o) => o.value === v || o.textContent.trim() === v || Number(o.value) === Number(v));
      if (!opt) return false;
      el.value = opt.value;
    } else {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, v);
    }
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  };

  if (job.op !== 'probe' && location.origin !== job.origin) return { filled: 0, moved: true };
  if (job.op === 'login') {
    const { pw, user } = loginFields();
    let filled = 0;
    if (user && job.username) { setValue(user, job.username); filled++; }
    if (pw && job.password) { setValue(pw, job.password); filled++; }
    return { filled };
  }
  if (job.op === 'form') {
    let filled = 0;
    for (const [el, v] of formPlan(job.values)) if (setFormValue(el, v)) filled++;
    return { filled };
  }

  // probe
  const isTop = window.top === window;
  const { pw, user } = loginFields();
  const form = job.keys?.length ? formPlan(Object.fromEntries(job.keys.map((k) => [k, '1']))) : [];
  const out = { origin: location.origin, password: !!pw, username: !!user, form: form.length, iframes: document.querySelectorAll('iframe, frame').length };
  // Firefox can name the frame id of a child frame element: report how this frame shows its children
  const getFrameId = (globalThis.browser ?? globalThis.chrome)?.runtime?.getFrameId;
  if (typeof getFrameId === 'function') {
    const hiddenElement = (f) => {
      const r = f.getBoundingClientRect();
      const s = getComputedStyle(f);
      if (r.width < job.minW || r.height < job.minH || s.visibility !== 'visible' || s.display === 'none') return true;
      let opacity = 1;
      for (let e = f; e; e = e.parentElement) opacity *= Number(getComputedStyle(e).opacity);
      return opacity < 0.8;
    };
    out.children = [...document.querySelectorAll('iframe, frame')].map((f) => {
      try { return { frameId: getFrameId(f), hidden: hiddenElement(f) }; } catch { return null; }
    }).filter((c) => c && c.frameId >= 0);
  }
  if (isTop) { out.shown = true; return out; }
  const target = pw ?? user ?? form[0]?.[0];
  if (!target) { out.shown = false; return out; }
  if (innerWidth < job.minW || innerHeight < job.minH) { out.shown = false; return out; }
  // Shown at all: the field intersects the viewport of the top page (catches display:none, zero size, off-screen
  // and clipped frames). Chrome also tells whether the frame is really visible – not transparent, covered, rotated
  // or skewed; the frame's document is observed for this, so the page's own labels over a field do not count.
  // A frame with visibility:hidden is not rendered at all: no answer within the time limit counts as hidden.
  out.shown = await new Promise((resolve) => {
    const v2 = 'isVisible' in IntersectionObserverEntry.prototype;
    const seen = new Map();
    let io = null;
    const finish = (v) => { io?.disconnect(); resolve(v); };
    io = new IntersectionObserver((entries) => {
      for (const e of entries) seen.set(e.target, e);
      const f = seen.get(target);
      const d = seen.get(document.documentElement);
      if (!f || (v2 && !d)) return;
      const area = f.isIntersecting && f.intersectionRect.width >= Math.min(job.minW, f.boundingClientRect.width) && f.intersectionRect.height >= Math.min(job.minH, f.boundingClientRect.height);
      finish(area && (!v2 || d.isVisible || f.isVisible));
    }, v2 ? { trackVisibility: true, delay: 100 } : {});
    io.observe(target);
    if (v2) io.observe(document.documentElement);
    setTimeout(() => finish(false), 1000);
  });
  return out;
}

/** autocomplete tokens → values of a card or identity item */
function formValues(item) {
  if (item.type === 'card') {
    const c = item.card ?? {};
    const month = String(c.expMonth ?? '').padStart(2, '0');
    const year = String(c.expYear ?? '');
    return {
      'cc-name': c.cardholderName, 'cc-number': c.number?.replace(/\s/g, ''), 'cc-exp-month': c.expMonth ? month : '',
      'cc-exp-year': year, 'cc-exp': c.expMonth && year ? `${month}/${year.slice(-2)}` : '', 'cc-csc': c.code,
    };
  }
  const d = item.identity ?? {};
  return {
    'given-name': d.firstName, 'additional-name': d.middleName, 'family-name': d.lastName, organization: d.company,
    email: d.email, tel: d.phone, 'address-line1': d.address1, 'address-line2': d.address2, 'postal-code': d.postalCode,
    'address-level2': d.city, 'address-level1': d.state, country: d.country, username: d.username,
  };
}

const hostLabel = (origin) => { try { return new URL(origin).host; } catch { return origin; } };

/**
 * What every reachable frame of the tab holds. Frames OmniVault may not access (other sites without the site
 * permission) are skipped by the browser; the top frame must be reachable. Origins come from the frames themselves.
 */
export async function probeFrames(tabId, keys) {
  const results = await ext.scripting.executeScript({
    target: { tabId, allFrames: true }, func: frameAgent, args: [{ op: 'probe', keys, minW: MIN_W, minH: MIN_H }],
  });
  const frames = (results ?? []).filter((r) => r?.result?.origin).map((r) => ({ frameId: r.frameId, documentId: r.documentId, ...r.result }));
  // Firefox: a frame its parent shows hidden, tiny or transparent is not shown, whatever it says itself
  const hiddenByParent = new Set(frames.flatMap((f) => f.children ?? []).filter((c) => c.hidden).map((c) => c.frameId));
  for (const f of frames) {
    f.shown = f.frameId === 0 || (f.shown && !hiddenByParent.has(f.frameId));
    delete f.children;
  }
  // frames the browser did not let OmniVault into (other sites without site access, or not loaded yet)
  frames.unreached = frames.reduce((n, f) => n + (f.iframes ?? 0), 1) > frames.length;
  return frames;
}

async function runIn(tabId, frame, job) {
  const target = frame.documentId ? { tabId, documentIds: [frame.documentId] } : { tabId, frameIds: [frame.frameId] };
  const [r] = await ext.scripting.executeScript({ target, func: frameAgent, args: [{ ...job, origin: frame.origin }] });
  return r?.result?.filled ?? 0;
}

/* ---------- confirmed pairs (top page, embedded frame of another site) ---------- */

export async function trustedPairs() {
  const { frameFillAllowed = [] } = await ext.storage.local.get('frameFillAllowed');
  return frameFillAllowed;
}
async function allowPairs(keys) {
  if (!keys.length) return;
  const have = await trustedPairs();
  await ext.storage.local.set({ frameFillAllowed: [...new Set([...have, ...keys])] });
}
export const forgetPairs = () => ext.storage.local.remove('frameFillAllowed');

/** A short note in the top page (text only, nothing to click): where OmniVault filled, or why it did not. */
function noticeInPage(text, iconUrl) {
  document.querySelector('omnivault-notice')?.remove();
  const host = document.createElement('omnivault-notice');
  host.style.cssText = 'all: initial; position: fixed; top: 12px; right: 12px; z-index: 2147483647;';
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = `div { max-width: 340px; padding: 10px 12px 10px 34px; border-radius: 10px; font: 13px/1.4 system-ui, sans-serif;
      color: #2b0a17; background: #fff url("${iconUrl}") 10px 11px / 16px no-repeat; border: 1px solid #e8d6dc;
      box-shadow: 0 8px 28px #0003; overflow-wrap: anywhere; }
    @media (prefers-color-scheme: dark) { div { color: #f3e9ec; background-color: #2a2124; border-color: #4a3a40; } }`;
  const box = document.createElement('div');
  box.setAttribute('role', 'status');
  box.textContent = text;
  root.append(style);
  root.append(box);
  document.documentElement.append(host);
  setTimeout(() => host.remove(), 6000);
}
export async function showNotice(tabId, text) {
  await ext.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: noticeInPage, args: [text, ext.runtime.getURL('icons/icon32.png')] }).catch(() => {});
}

async function siteAccess() {
  return ext.permissions.contains({ origins: ['https://*/*', 'http://*/*'] }).catch(() => false);
}

/**
 * Fills an item into the tab. `interactive`: the user picked it in OmniVault's window, which can ask; otherwise
 * (keyboard shortcut, context menu) frames of other sites are only filled once confirmed there.
 * `force`: the user confirmed filling a login that belongs to no frame of the tab (only the top page's origin).
 * `allow`: { top, frames } – the user confirmed these embedded frames on this top page.
 * Returns { filled, top, embedded: [origin], confirm: [origin], hidden: [origin], noAccess }.
 */
export async function fillTab(tabId, item, { interactive = true, force = false, allow = null } = {}) {
  const form = item.type === 'card' || item.type === 'identity';
  const values = form ? formValues(item) : null;
  const frames = await probeFrames(tabId, form ? Object.keys(values).filter((k) => values[k]) : undefined);
  const top = frames.find((f) => f.frameId === 0)?.origin ?? null;
  if (allow && allow.top === top) await allowPairs((allow.frames ?? []).map((o) => pairKey(top, o)));
  const pairs = new Set(await trustedPairs());
  const trusted = (k) => pairs.has(k);

  if (form) {
    const plan = formTargets(frames, { trusted });
    const confirm = [...new Set(plan.targets.filter((c) => c.needsConfirm).map((c) => c.frame.origin))];
    if (interactive && confirm.length) return { filled: 0, top, embedded: [], confirm, hidden: plan.hidden };
    return execute(tabId, plan.targets.filter((c) => !c.needsConfirm), { op: 'form', values }, { top, confirm, hidden: plan.hidden, interactive, unreached: frames.unreached });
  }
  const plan = { ...loginCandidates(frames, (origin) => matchesUrl(item, origin), { force, trusted }), unreached: frames.unreached };
  const best = plan.candidates[0];
  if (best?.needsConfirm && interactive) return { filled: 0, top, embedded: [], confirm: [best.frame.origin], hidden: plan.hidden };
  return fillLogin(tabId, plan, item, interactive);
}

function fillLogin(tabId, plan, item, interactive) {
  const pick = plan.candidates.find((c) => !c.needsConfirm);
  const confirm = [...new Set(plan.candidates.filter((c) => c.needsConfirm).map((c) => c.frame.origin))];
  return execute(tabId, pick ? [pick] : [], { op: 'login', username: item.username ?? '', password: item.password ?? '' },
    { top: plan.top, confirm, hidden: plan.hidden, interactive, unreached: plan.unreached });
}

async function execute(tabId, targets, job, { top, confirm, hidden, interactive, unreached }) {
  let filled = 0;
  const embedded = [];
  for (const c of targets) {
    const n = await runIn(tabId, c.frame, job);
    filled += n;
    if (n && c.embedded) embedded.push(c.frame.origin);
  }
  const result = { filled, top, embedded: [...new Set(embedded)], confirm, hidden, noAccess: false };
  if (embedded.length) {
    await showNotice(tabId, t('OmniVault hat das eingebettete Formular von {origin} ausgefüllt.', { origin: result.embedded.map(hostLabel).join(', ') }));
  } else if (!filled) {
    // some frames stayed closed to OmniVault: without site access it only reaches the page's own origin
    result.noAccess = !!unreached && !(await siteAccess());
    if (!interactive) await explainInPage(tabId, result);
  }
  return result;
}

/** Keyboard shortcut and context menu have no window of their own: say in the page why nothing was filled. */
async function explainInPage(tabId, r) {
  if (r.confirm.length) {
    await showNotice(tabId, t('Das Anmeldeformular von {origin} ist in diese Seite eingebettet. Zum ersten Mal bitte über das OmniVault-Symbol ausfüllen, um es hier zu erlauben.', { origin: hostLabel(r.confirm[0]) }));
  } else if (r.hidden.length) {
    await showNotice(tabId, t('Das eingebettete Formular von {origin} ist verdeckt oder unsichtbar und wurde nicht ausgefüllt.', { origin: hostLabel(r.hidden[0]) }));
  }
}

/**
 * Keyboard shortcut and context menu: the best frame (password frames first, see frames.js) with a login for its
 * origin. `bestFor(origin)` names the login for an origin (without secrets), or null; `reveal(ref)` loads only the
 * chosen one with its secrets. Frames of other sites only once confirmed.
 */
export async function fillBestInTab(tabId, bestFor, reveal) {
  const frames = await probeFrames(tabId);
  const found = new Map();
  for (const f of frames) if ((f.password || f.username) && !found.has(f.origin)) found.set(f.origin, await bestFor(f.origin));
  const pairs = new Set(await trustedPairs());
  const plan = { ...loginCandidates(frames, (origin) => !!found.get(origin), { trusted: (k) => pairs.has(k) }), unreached: frames.unreached };
  const pick = plan.candidates.find((c) => !c.needsConfirm);
  return fillLogin(tabId, plan, pick ? await reveal(found.get(pick.frame.origin)) : {}, false);
}

/** Origins of the tab's shown login frames other than the top page (none if the tab cannot be read). */
export async function loginFrames(tabId) {
  return loginFrameOrigins(await probeFrames(tabId).catch(() => []));
}

/**
 * The list in a login field: fills exactly the frame that list belongs to, if it still has the origin the item
 * matched and is shown (the user picked the login inside that frame, so there is nothing to confirm).
 */
export async function fillFrame(tabId, frame, item) {
  const frames = await probeFrames(tabId);
  const f = frames.find((x) => x.frameId === frame.frameId && x.origin === frame.origin);
  if (!f) throw new Error(t('Das Formular hat inzwischen die Seite gewechselt.'));
  if (!f.shown) throw new Error(t('Das Formular ist verdeckt oder unsichtbar und wurde nicht ausgefüllt.'));
  return runIn(tabId, f, { op: 'login', username: item.username ?? '', password: item.password ?? '' });
}

/** Injected: put a value into the focused input (used by the context menu generator). */
function insertInPage(value) {
  const el = document.activeElement;
  if (!(el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) return false;
  const proto = el instanceof HTMLInputElement ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}

/** Keeps the last ten generated passwords (RAM only), so the user can still look them up in the generator. */
export async function rememberGenerated(value) {
  const { generated = [] } = await ext.storage.session.get('generated');
  await ext.storage.session.set({ generated: [{ value, at: Date.now() }, ...generated.filter((g) => g.value !== value)].slice(0, 10) });
}

export async function insertIntoFocused(tabId, frameId, value) {
  await rememberGenerated(value);
  const [r] = await ext.scripting.executeScript({ target: { tabId, frameIds: [frameId] }, func: insertInPage, args: [value] });
  return r?.result ?? false;
}
