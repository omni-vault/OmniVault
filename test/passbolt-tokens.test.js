// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// The per-account token keeper of the Passbolt provider: no request with the old token after a renewal began.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TokenKeeper, forgetAllKeepers, keeperFor } from '../src/providers/passbolt/tokens.js';

const deferred = () => { let resolve; const p = new Promise((r) => { resolve = r; }); return { p, resolve }; };
const tick = () => new Promise((r) => { setImmediate(r); });

function keeper({ expiresAt = 10_000, now = () => 0 } = {}) {
  const sent = []; // [event, token]
  let n = 0;
  const gate = { renew: null };
  const k = new TokenKeeper({ accessToken: 't0', expiresAt, obtainedAt: 0, sid: 's' }, {
    now,
    renew: async (s) => {
      sent.push(['renew', s.accessToken]);
      if (gate.renew) await gate.renew.p;
      return { ...s, accessToken: `t${++n}`, expiresAt: expiresAt + n * 10_000, obtainedAt: n * 10_000 };
    },
  });
  const request = (name, until) => k.run(async (token) => { sent.push([name, token]); if (until) await until.p; sent.push([`${name} done`, token]); return token; });
  return { k, sent, request, gate };
}

test('a renewal waits for every request in flight; requests started meanwhile wait and get the new token', async () => {
  const { k, sent, request, gate } = keeper();
  const slow1 = deferred(); const slow2 = deferred();
  const a = request('a', slow1);
  const b = request('b', slow2);
  await tick();
  assert.equal(k.active, 2);
  gate.renew = deferred();
  const renewal = k.renew('t0');
  const c = request('c');
  const d = request('d');
  await tick();
  assert.ok(!sent.some(([e]) => e === 'renew'), 'not before the requests in flight are answered');
  slow1.resolve(); await tick();
  assert.ok(!sent.some(([e]) => e === 'renew'));
  slow2.resolve(); await tick();
  assert.deepEqual(sent.at(-1), ['renew', 't0']);
  assert.ok(!sent.some(([e]) => e === 'c' || e === 'd'), 'new requests wait for the renewal');
  gate.renew.resolve();
  await renewal;
  assert.deepEqual(await Promise.all([a, b, c, d]), ['t0', 't0', 't1', 't1']);
  const renewAt = sent.findIndex(([e]) => e === 'renew');
  assert.ok(sent.slice(renewAt + 1).every(([, token]) => token === 't1'), 'old token never sent after the renewal began');
});

test('one renewal for many callers; a caller with an outdated token does not renew again', async () => {
  const { k, sent } = keeper();
  await Promise.all([k.renew('t0'), k.renew('t0'), k.renew('t0')]);
  await k.renew('t0'); // already renewed since t0 was handed out
  assert.equal(sent.filter(([e]) => e === 'renew').length, 1);
  assert.equal(k.session.accessToken, 't1');
  assert.equal(k.session.gen, 1);
});

test('proactive renewal before a request, once per request even when the new token is short-lived', async () => {
  let now = 9_000; // within a quarter of the lifetime before expiry
  const { k, sent, request } = keeper({ now: () => now });
  assert.equal(await request('a'), 't1');
  assert.deepEqual(sent.map(([e]) => e), ['renew', 'a', 'a done']);
  now = 0;
  assert.equal(await request('b'), 't1');
  assert.equal(k.session.gen, 1);
});

test('a refused request (expired) renews and is repeated once with the new token', async () => {
  const { k } = keeper();
  const seen = [];
  const r = await k.run(async (token) => {
    seen.push(token);
    if (token === 't0') throw Object.assign(new Error('expired'), { code: 'session_expired' });
    return 'ok';
  }, { retryIf: (e) => e.code === 'session_expired' });
  assert.equal(r, 'ok');
  assert.deepEqual(seen, ['t0', 't1']);
  // failing again with the new token: no endless loop
  await assert.rejects(k.run(async () => { throw Object.assign(new Error('expired'), { code: 'session_expired' }); },
    { retryIf: (e) => e.code === 'session_expired' }), /expired/);
  assert.equal(k.session.gen, 2);
});

test('a failed renewal reaches every waiting caller', async () => {
  const k = new TokenKeeper({ accessToken: 't0', expiresAt: 1, sid: 's' }, { now: () => 10, renew: async () => { throw new Error('second factor needed'); } });
  const calls = [];
  const all = await Promise.allSettled([1, 2, 3].map(() => k.run(async (t) => { calls.push(t); })));
  assert.ok(all.every((r) => r.status === 'rejected' && /second factor/.test(r.reason.message)));
  assert.deepEqual(calls, [], 'nothing sent with the expired token');
});

test('keeperFor: a new sign-in replaces the keeper, an older copy of the session gets the current one', () => {
  forgetAllKeepers();
  const opts = { renew: async (s) => s };
  const k1 = keeperFor('acc', { accessToken: 'a', sid: 'one', gen: 0 }, opts);
  k1.session = { ...k1.session, accessToken: 'b', gen: 3 };
  assert.equal(keeperFor('acc', { accessToken: 'a', sid: 'one', gen: 1 }, opts), k1);
  const k2 = keeperFor('acc', { accessToken: 'c', sid: 'two', gen: 0 }, opts);
  assert.notEqual(k2, k1);
  assert.equal(k2.session.accessToken, 'c');
});
