// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Login steps in a tab, security key (WebAuthn): which messages the background accepts, with simulated browser APIs.
// The flow against a real Vaultwarden runs in test/e2e-bitwarden-webauthn.mjs.
import assert from 'node:assert/strict';
import { test } from 'node:test';

const session = {};
const tabs = new Map();
const injected = [];
const removed = [];
const listeners = { updated: [], removed: [] };
let nextTab = 1;
globalThis.chrome = {
  storage: { session: {
    get: async (k) => ({ [k]: structuredClone(session[k]) }),
    set: async (o) => { Object.assign(session, structuredClone(o)); },
  } },
  tabs: {
    create: async ({ url }) => { const tab = { id: nextTab++, url, status: 'loading' }; tabs.set(tab.id, tab); return tab; },
    get: async (id) => tabs.get(id),
    remove: async (id) => { removed.push(id); tabs.delete(id); },
    update: async (id) => tabs.get(id),
    onUpdated: { addListener: (f) => listeners.updated.push(f) },
    onRemoved: { addListener: (f) => listeners.removed.push(f) },
  },
  scripting: { executeScript: async (o) => { injected.push(o); return [{ result: 'shown' }]; } },
};
const { createLoginFlows } = await import('../src/background/login-flow.js');

const finished = [];
const flows = createLoginFlows({ finish: async (id, pending, reply) => { finished.push({ id, pending, reply }); return { status: 'ok' }; } });
const ORIGIN = 'https://vault.example.org';
const request = { challenge: 'Y2g', rpId: 'vault.example.org', timeout: 60000, userVerification: 'discouraged', allowCredentials: [{ id: 'a2V5' }] };
const settle = () => new Promise((r) => setTimeout(r, 20));
const start = async (id) => {
  const f = await flows.start(id, { status: 'needs_browser', browser: { kind: 'webauthn', url: `${ORIGIN}/webauthn-connector.html`, origin: ORIGIN, request }, pending: { kind: 'browser', step: 'webauthn', masterKey: 'MK' } });
  return f;
};
const load = async (tabId, url) => {
  tabs.get(tabId).url = url;
  for (const l of listeners.updated) l(tabId, { status: 'complete' }, { id: tabId, url, status: 'complete' });
  await settle();
};

test('the box is injected only into the top frame of the web vault origin, with the flow nonce', async () => {
  const f = await start('acc1');
  assert.equal(f.kind, 'webauthn');
  assert.match(f.nonce, /^[0-9a-f]{32}$/);
  await load(f.tabId, 'https://evil.example/webauthn-connector.html');
  assert.equal(injected.length, 0, 'no injection on another origin');
  await load(f.tabId, `${ORIGIN}/webauthn-connector.html`);
  assert.equal(injected.length, 1);
  const [o] = injected;
  assert.deepEqual(o.target, { tabId: f.tabId, frameIds: [0] });
  assert.deepEqual(o.args[0], request);
  assert.equal(o.args[2], f.nonce);
  assert.equal(o.args[3], ORIGIN);
  assert.equal(typeof o.args[1].start, 'string');
  const status = await flows.status('acc1');
  assert.deepEqual(status, { phase: 'browser', kind: 'webauthn', outcome: undefined, awaitingInput: true });
});

test('answers are taken only from the flow tab, top frame, web vault origin and with the nonce', async () => {
  const f = (await chrome.storage.session.get('loginFlows')).loginFlows.acc1;
  const ok = { type: 'ov-webauthn-2fa', nonce: f.nonce, response: '{"id":"a2V5"}' };
  const sender = { id: 'ext', tab: { id: f.tabId }, frameId: 0, url: `${ORIGIN}/webauthn-connector.html` };
  assert.equal(await flows.webauthnReply(ok, { ...sender, tab: { id: 999 } }), false, 'another tab');
  assert.equal(await flows.webauthnReply(ok, { ...sender, frameId: 3 }), false, 'an embedded frame');
  assert.equal(await flows.webauthnReply(ok, { ...sender, url: 'https://evil.example/' }), false, 'another origin');
  assert.equal(await flows.webauthnReply({ ...ok, nonce: 'guess' }, sender), false, 'wrong nonce');
  assert.equal(await flows.webauthnReply({ ...ok, response: 'x'.repeat(70_000) }, sender), false, 'implausibly large');
  assert.equal(finished.length, 0);
  assert.equal(await flows.webauthnReply(ok, sender), true);
  assert.deepEqual(finished, [{ id: 'acc1', pending: { kind: 'browser', step: 'webauthn', masterKey: 'MK' }, reply: { webauthnResponse: '{"id":"a2V5"}' } }]);
  assert.ok(removed.includes(f.tabId), 'tab closed');
  assert.equal((await flows.status('acc1')).phase, 'done');
  assert.equal(await flows.webauthnReply(ok, sender), false, 'a second answer is not taken');
});

test('cancel in the box ends the flow with an error and closes the tab', async () => {
  const f = await start('acc2');
  const sender = { id: 'ext', tab: { id: f.tabId }, frameId: 0, url: `${ORIGIN}/x` };
  assert.equal(await flows.webauthnReply({ type: 'ov-webauthn-2fa', nonce: f.nonce, cancel: true }, sender), true);
  const s = await flows.status('acc2');
  assert.equal(s.phase, 'done');
  assert.equal(s.outcome.status, 'error');
  assert.equal(s.awaitingInput, false, 'nothing of the login kept');
  assert.ok(removed.includes(f.tabId));
});
