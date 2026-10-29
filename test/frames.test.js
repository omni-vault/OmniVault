// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Choosing the frame to fill into (src/lib/frames.js): own origin of the frame, visibility, preference for
// password frames, one-time confirmation for frames of another site.
import assert from 'node:assert/strict';
import test from 'node:test';
import { formTargets, loginCandidates, loginFrameOrigins, pairKey, sameSite } from '../src/lib/frames.js';
import { matchesUrl } from '../src/lib/match.js';

const TOP = 'https://shop.example';
const frame = (frameId, origin, extra = {}) => ({ frameId, origin, password: false, username: false, form: 0, shown: true, ...extra });
const item = (...uris) => (origin) => matchesUrl({ uris }, origin);

test('sameSite compares registrable domains', () => {
  assert.equal(sameSite('https://login.example.co.uk', 'https://www.example.co.uk'), true);
  assert.equal(sameSite('https://a.github.io', 'https://b.github.io'), false); // public suffix
  assert.equal(sameSite('http://localhost:1', 'http://localhost:2'), true);
  assert.equal(sameSite('http://127.0.0.1:1', 'http://localhost:1'), false);
});

test('a login only goes into a frame of its own site – never because the page matches', () => {
  const frames = [frame(0, TOP), frame(3, 'https://login.partner.example', { password: true, username: true })];
  assert.deepEqual(loginCandidates(frames, item(TOP)).candidates, []);
  // not even when the user forces a login that belongs nowhere: only the page's own origin then
  assert.deepEqual(loginCandidates(frames, item('https://other.example'), { force: true }).candidates, []);
  const c = loginCandidates(frames, item('https://partner.example')).candidates;
  assert.equal(c.length, 1);
  assert.equal(c[0].frame.frameId, 3);
  assert.equal(c[0].embedded, true);
  assert.equal(c[0].crossSite, true);
  assert.equal(c[0].needsConfirm, true);
});

test('confirmed pairs, same-site frames and the page itself need no question', () => {
  const frames = [frame(0, TOP, { username: true }), frame(2, 'https://accounts.shop.example', { password: true }), frame(4, 'https://login.partner.example', { password: true })];
  const own = loginCandidates(frames, item('https://shop.example')).candidates;
  assert.deepEqual(own.map((c) => [c.frame.frameId, c.needsConfirm]), [[2, false], [0, false]]); // password frame first
  assert.equal(own[0].embedded, true);
  assert.equal(own[0].crossSite, false);
  const trusted = (k) => k === pairKey(TOP, 'https://login.partner.example');
  assert.equal(loginCandidates(frames, item('https://partner.example'), { trusted }).candidates[0].needsConfirm, false);
});

test('order: password frames first; top, same origin, same site, other sites', () => {
  const frames = [
    frame(0, TOP, { username: true }),
    frame(5, 'https://x.other.example', { password: true }),
    frame(6, 'https://shop.example', { password: true }),
    frame(7, 'https://login.shop.example', { password: true }),
    frame(8, 'https://y.other.example', { username: true }),
  ];
  const all = () => true;
  assert.deepEqual(loginCandidates(frames, all).candidates.map((c) => c.frame.frameId), [6, 7, 5, 0, 8]);
});

test('hidden frames and sandboxed frames are never candidates', () => {
  const frames = [
    frame(0, TOP),
    frame(1, 'https://login.shop.example', { password: true, shown: false }),
    frame(2, 'null', { password: true }),
  ];
  const r = loginCandidates(frames, () => true);
  assert.deepEqual(r.candidates, []);
  assert.deepEqual(r.hidden, ['https://login.shop.example']);
  assert.deepEqual(loginFrameOrigins(frames), []);
});

test('cards go into every shown frame with fields (split payment forms), other sites need a question', () => {
  const frames = [
    frame(0, TOP, { form: 2 }),
    frame(3, 'https://js.stripe.com', { form: 1 }),
    frame(4, 'https://js.stripe.com', { form: 2 }),
    frame(5, 'https://ads.example', { form: 0 }),
    frame(6, 'https://hidden.example', { form: 3, shown: false }),
  ];
  const r = formTargets(frames);
  assert.deepEqual(r.targets.map((c) => [c.frame.frameId, c.needsConfirm]), [[0, false], [3, true], [4, true]]);
  assert.deepEqual(r.hidden, ['https://hidden.example']);
  const ok = formTargets(frames, { trusted: (k) => k === pairKey(TOP, 'https://js.stripe.com') });
  assert.ok(ok.targets.every((c) => !c.needsConfirm));
});

test('login frames for the item list: shown, other origin than the page', () => {
  const frames = [
    frame(0, TOP, { password: true }),
    frame(1, TOP, { password: true }),
    frame(2, 'https://login.partner.example', { username: true }),
    frame(3, 'https://cards.example', { form: 3 }),
  ];
  assert.deepEqual(loginFrameOrigins(frames), ['https://login.partner.example']);
});
