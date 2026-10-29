// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Choosing the frame(s) of a tab to fill into. Pure functions over what the background found out about each frame
// (see frameAgent in background/autofill.js): { frameId, origin, password, username, form, shown }.
//
// Rules (see "Filling in embedded frames" in DEVELOPMENT.md):
// - a login only goes into a frame whose own origin matches the item – never because the top page matches;
// - frames that are hidden, tiny or covered are never filled;
// - a frame of another site than the top page (cross-site embedding) needs a one-time confirmation per pair of
//   origins; until then only an interactive fill may ask for it, the others skip the frame.
import { baseDomain, hostOf } from './match.js';

export const sameSite = (a, b) => {
  const x = baseDomain(hostOf(a));
  return !!x && x === baseDomain(hostOf(b));
};

/** Key under which a confirmed pair (top page, embedded frame) is remembered. */
export const pairKey = (top, frame) => `${top} ${frame}`;

/** Origin of the top frame (frame 0). */
export const topOriginOf = (frames) => frames.find((f) => f.frameId === 0)?.origin ?? null;

/** Frames whose own origin is known (sandboxed frames report "null" and are never filled). */
const real = (f) => typeof f.origin === 'string' && /^https?:\/\//.test(f.origin);

function classify(f, top, trusted) {
  const embedded = f.frameId !== 0 && f.origin !== top;
  const crossSite = embedded && !sameSite(f.origin, top);
  return { frame: f, embedded, crossSite, needsConfirm: crossSite && !trusted(pairKey(top, f.origin)) };
}

/**
 * Candidate frames for a login, best first: frames with a password field before username-only ones; then the top
 * frame, frames of the same origin, of the same site, of other sites. `matches(origin)` says whether the item (or
 * any item, for the keyboard shortcut) belongs to an origin. With `force` (the user confirmed filling a login that
 * belongs to no frame) frames of the top page's own origin qualify as well – never other origins.
 * Returns { candidates: [{ frame, embedded, crossSite, needsConfirm }], hidden: [origin] }.
 */
export function loginCandidates(frames, matches, { force = false, trusted = () => false } = {}) {
  const top = topOriginOf(frames);
  const fits = frames.filter((f) => real(f) && (f.password || f.username) && (matches(f.origin) || (force && f.origin === top)));
  const rank = (f) => (f.password ? 0 : 4) + (f.frameId === 0 ? 0 : f.origin === top ? 1 : sameSite(f.origin, top) ? 2 : 3);
  const candidates = fits.filter((f) => f.shown).sort((a, b) => rank(a) - rank(b) || a.frameId - b.frameId)
    .map((f) => classify(f, top, trusted));
  const hidden = [...new Set(fits.filter((f) => !f.shown).map((f) => f.origin))];
  return { top, candidates, hidden };
}

/**
 * Frames for a card or identity: every shown frame with matching form fields (payment providers often split a
 * card form over several frames, one per field). Returns { top, targets, hidden } like loginCandidates.
 */
export function formTargets(frames, { trusted = () => false } = {}) {
  const top = topOriginOf(frames);
  const fits = frames.filter((f) => real(f) && f.form > 0);
  return {
    top,
    targets: fits.filter((f) => f.shown).sort((a, b) => a.frameId - b.frameId).map((f) => classify(f, top, trusted)),
    hidden: [...new Set(fits.filter((f) => !f.shown).map((f) => f.origin))],
  };
}

/** Origins of shown login frames that differ from the top page (for "matching this page" in the item list). */
export function loginFrameOrigins(frames) {
  const top = topOriginOf(frames);
  return [...new Set(frames.filter((f) => f.frameId !== 0 && real(f) && f.shown && (f.password || f.username) && f.origin !== top).map((f) => f.origin))];
}
