// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Bitwarden emergency access as trusted contact (view only) against the simulated server: list, ask for access,
// view after approval with the grantor's key unwrapped by the own RSA key; takeover grants cannot be viewed.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import BitwardenProvider from '../src/providers/bitwarden/index.js';
import { EMAIL, PASSWORD, fakeBitwarden } from './fake-bitwarden.js';

const config = { id: 'acc1', server: 'https://vault.example.org', email: EMAIL };

async function server() {
  const handle = await fakeBitwarden({ kdf: { kdf: 0, kdfIterations: 5000 } });
  globalThis.fetch = async (url, init = {}) => {
    const u = new URL(url);
    let body = init.body;
    if (body instanceof URLSearchParams) body = body.toString();
    const headers = init.headers instanceof Headers ? Object.fromEntries(init.headers) : init.headers ?? {};
    const r = handle(u.pathname, { ...init, headers, body });
    return new Response(r.body == null ? '' : JSON.stringify(r.body), { status: r.status });
  };
  const { session } = await BitwardenProvider.login(config, { password: PASSWORD });
  return { handle, session };
}

test('emergency access: list, ask for access, view after approval (read only, no trash)', async () => {
  const { handle, session } = await server();
  const { grants } = await BitwardenProvider.listEmergencyGrants(config, session);
  assert.deepEqual(grants.map((g) => [g.id, g.name, g.type, g.status, g.waitTimeDays]),
    [['ea1', 'Gerda', 'view', 2, 7], ['ea2', 'Theo', 'takeover', 2, 3]]);

  await assert.rejects(BitwardenProvider.viewEmergencyAccess(config, session, 'ea1'), /not valid/);
  await BitwardenProvider.initiateEmergencyAccess(config, session, 'ea1');
  assert.equal((await BitwardenProvider.listEmergencyGrants(config, session)).grants[0].status, 3);
  assert.ok(handle.requests.some((r) => r.method === 'POST' && r.path.endsWith('/api/emergency-access/ea1/initiate')));
  await assert.rejects(BitwardenProvider.viewEmergencyAccess(config, session, 'ea1'), /not valid/);

  handle.emergency.approve('ea1');
  const { items, failed } = await BitwardenProvider.viewEmergencyAccess(config, session, 'ea1');
  assert.equal(failed, 0);
  assert.deepEqual(items.map((i) => i.name), ['Gerdas Bank', 'Gerdas Testament']);
  const bank = items[0];
  assert.deepEqual([bank.username, bank.password, bank.uris[0], bank.canEdit], ['gerda', 'gerda-bank-pw', 'https://bank.example', false]);
  assert.equal(bank.attachments[0].fileName, 'Vertrag.pdf');
  assert.equal(items[1].notes, 'Liegt im Schrank');
  // reading only: nothing was written
  assert.ok(!handle.requests.some((r) => /\/api\/ciphers/.test(r.path) && r.method !== 'GET'));
});

test('emergency access: takeover grants are not viewable, a wrong key is reported', async () => {
  const { handle, session } = await server();
  handle.emergency.approve('ea2');
  await assert.rejects(BitwardenProvider.viewEmergencyAccess(config, session, 'ea2'), /not valid/);
  handle.emergency.approve('ea1');
  handle.emergency.keyEncrypted = `4.${Buffer.alloc(256, 7).toString('base64')}`;
  await assert.rejects(BitwardenProvider.viewEmergencyAccess(config, session, 'ea1'), /passt nicht zu deinem Konto/);
});
