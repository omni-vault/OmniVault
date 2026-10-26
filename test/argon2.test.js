// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
import assert from 'node:assert/strict';
import { test } from 'node:test';
import loadArgon2id from '../vendor/argon2id.mjs';
import loadArgon2 from '../vendor/argon2.mjs';
import { argon2, pack, unpack } from '../src/lib/argon2.js';
import { withOffscreen } from '../src/lib/offscreen.js';

const PARAMS = { password: new TextEncoder().encode('pw'), salt: new Uint8Array(16).fill(7), passes: 1, memorySize: 64, parallelism: 1, tagLength: 32 };
const LOAD = { argon2id: loadArgon2id, argon2: loadArgon2 };
const expected = (await loadArgon2id())(PARAMS);
const tick = () => new Promise((r) => setTimeout(r, 5));
const settled = () => new Promise((r) => setTimeout(r, 30)); // closing is not awaited by the users

/** Stands in for a dedicated worker running src/workers/argon2-worker.js. */
function fakeWorker({ fail = false, error = null } = {}) {
  const log = { created: [], terminated: 0 };
  class W {
    constructor(url, opts) { log.created.push({ url, opts }); }
    postMessage({ lib, params }) {
      setTimeout(async () => {
        if (fail) return this.onerror({ message: 'blocked', preventDefault() {} });
        if (error) return this.onmessage({ data: { error } });
        this.onmessage({ data: { out: (await LOAD[lib]())(structuredClone(params)) } });
      });
    }
    terminate() { log.terminated++; }
  }
  return { W, log };
}

/** Chrome's offscreen and runtime APIs; messages go through JSON like in Chrome. */
function fakeChrome({ answer } = {}) {
  const log = { created: [], closed: 0, messages: [] };
  let open = false;
  const api = {
    runtime: {
      getURL: (p) => `chrome-extension://id/${p}`,
      getContexts: async () => (open ? [{}] : []),
      sendMessage: async (msg) => {
        const m = JSON.parse(JSON.stringify(msg));
        log.messages.push(m);
        assert.ok(open, 'offscreen document is open while it is used');
        await tick();
        if (answer) return answer;
        if (m.type !== 'argon2') return true;
        const out = (await LOAD[m.lib]())(unpack(m.params));
        return { out: Buffer.from(out).toString('base64') };
      },
    },
    offscreen: {
      createDocument: async (o) => { assert.ok(!open, 'only one offscreen document'); await tick(); log.created.push(o); open = true; },
      closeDocument: async () => { await tick(); open = false; log.closed++; },
    },
  };
  return { api, log };
}

test('Argon2 switch: directly without workers (Node, old browsers)', async () => {
  let direct = 0;
  const out = await argon2('argon2id', PARAMS, () => { direct++; return loadArgon2id(); }, { Worker: undefined, api: undefined });
  assert.deepEqual(out, expected);
  assert.equal(direct, 1);
});

test('Argon2 switch: dedicated worker where available (Firefox background page, popup), terminated afterwards', async () => {
  const { W, log } = fakeWorker();
  const { api } = fakeChrome();
  const out = await argon2('argon2id', PARAMS, () => assert.fail('no direct computation'), { Worker: W, api });
  assert.deepEqual(out, expected);
  assert.deepEqual(log.created, [{ url: 'chrome-extension://id/argon2-worker.js', opts: { type: 'module' } }]);
  assert.equal(log.terminated, 1);
  // Argon2d from the reference implementation (KeePass files)
  const d = { ...PARAMS, type: 'd', version: 0x13 };
  assert.deepEqual(await argon2('argon2', d, () => assert.fail(), { Worker: W, api }), (await loadArgon2())(d));
});

test('Argon2 switch: worker cannot start → direct; error of the computation → no fallback', async () => {
  const blocked = fakeWorker({ fail: true });
  assert.deepEqual(await argon2('argon2id', PARAMS, loadArgon2id, { Worker: blocked.W, api: fakeChrome().api }), expected);
  assert.equal(blocked.log.terminated, 1);
  const oom = fakeWorker({ error: 'Argon2: memory allocation failed' });
  await assert.rejects(argon2('argon2id', PARAMS, () => assert.fail('no fallback'), { Worker: oom.W, api: fakeChrome().api }), /memory allocation failed/);
});

test('Argon2 switch: Chrome service worker uses the offscreen document and closes it afterwards', async () => {
  const { api, log } = fakeChrome();
  const out = await argon2('argon2id', PARAMS, () => assert.fail('no direct computation'), { Worker: undefined, api });
  assert.deepEqual(out, expected);
  assert.equal(log.created.length, 1);
  assert.deepEqual(log.created[0].reasons.toSorted(), ['CLIPBOARD', 'WORKERS']);
  await settled();
  assert.equal(log.closed, 1);
  // no worker in the offscreen document → direct
  const none = fakeChrome({ answer: { unavailable: true } });
  assert.deepEqual(await argon2('argon2id', PARAMS, loadArgon2id, { Worker: undefined, api: none.api }), expected);
  const err = fakeChrome({ answer: { error: 'Argon2: memory allocation failed' } });
  await assert.rejects(argon2('argon2id', PARAMS, () => assert.fail(), { Worker: undefined, api: err.api }), /memory allocation/);
});

test('offscreen document: shared by clipboard and derivations, closed after the last user, reopened afterwards', async () => {
  const { api, log } = fakeChrome();
  const clear = () => withOffscreen(() => api.runtime.sendMessage({ target: 'offscreen', type: 'clear-clipboard' }), api);
  const derive = () => argon2('argon2id', PARAMS, () => assert.fail(), { Worker: undefined, api });
  const [a, , b] = await Promise.all([derive(), clear(), derive(), clear()]);
  assert.deepEqual(a, expected);
  assert.deepEqual(b, expected);
  await settled();
  assert.equal(log.created.length, 1, 'opened once for all four');
  assert.equal(log.closed, 1, 'closed once, after the last');
  // a new use right after closing waits for the close and opens a new document
  const later = clear();
  await later;
  await Promise.all([clear(), derive()]);
  await settled();
  assert.equal(log.created.length, 3);
  assert.equal(log.closed, 3);
  // the user's function failing still releases the document
  await assert.rejects(withOffscreen(async () => { throw new Error('x'); }, api), /x/);
  await settled();
  assert.equal(log.closed, 4);
});

test('Argon2 switch: parameters survive JSON messages', () => {
  const back = unpack(JSON.parse(JSON.stringify(pack(PARAMS))));
  assert.deepEqual(back, PARAMS);
  assert.ok(back.password instanceof Uint8Array);
});
