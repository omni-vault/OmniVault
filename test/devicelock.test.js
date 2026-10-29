// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
import assert from 'node:assert/strict';
import { createCipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { createDeviceLock, deviceKey, newPrfSalt, unsealWithDevice } from '../src/lib/devicelock.js';
import { createPinLock, seal, unseal } from '../src/lib/pinlock.js';

const prfOf = (n) => Buffer.alloc(32, n).toString('base64');

test('device lock: key is HKDF-SHA-256 of the PRF output (checked against node:crypto)', async () => {
  const prf = randomBytes(32);
  const expected = Buffer.from(hkdfSync('sha256', prf, Buffer.alloc(32), Buffer.from('OmniVault device unlock v1'), 32));
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', expected, iv);
  const ct = Buffer.concat([c.update('probe'), c.final(), c.getAuthTag()]);
  const key = await deviceKey(prf.toString('base64'));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  assert.equal(Buffer.from(pt).toString(), 'probe');
  assert.equal((await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await deviceKey(new Uint8Array(prf)), ct)).byteLength, 5, 'bytes and base64 give the same key');
  await assert.rejects(deviceKey(Buffer.alloc(16).toString('base64')), /keinen gültigen Schlüssel/);
});

test('device lock: seal without the device, open only with its PRF output', async () => {
  const prfSalt = newPrfSalt();
  assert.equal(Buffer.from(prfSalt, 'base64').length, 32);
  assert.notEqual(prfSalt, newPrfSalt());
  const lock = await createDeviceLock({ credentialId: 'Y3JlZA', prfSalt, prf: prfOf(7), transports: ['internal', 'hybrid', 3] });
  assert.equal(lock.kind, 'device');
  assert.equal(lock.credentialId, 'Y3JlZA');
  assert.equal(lock.prfSalt, prfSalt);
  assert.deepEqual(lock.transports, ['internal', 'hybrid']);
  assert.ok(!JSON.stringify(lock).includes(prfOf(7)), 'the PRF output is not stored');
  const sessions = { a1: { userKey: 'geheim', accessToken: 't' }, a2: { connected: true } };
  const sealed = await seal(lock, sessions);
  assert.ok(!JSON.stringify(sealed).includes('geheim'), 'sealed data is encrypted');
  await assert.rejects(unsealWithDevice(lock, sealed, prfOf(8)), /nicht den passenden Schlüssel/);
  await assert.rejects(unsealWithDevice(lock, sealed, 'kein base64!'), /nicht den passenden Schlüssel/);
  await assert.rejects(unsealWithDevice(lock, sealed, undefined), /nicht den passenden Schlüssel/);
  assert.deepEqual(await unsealWithDevice(lock, sealed, prfOf(7)), sessions);
  await assert.rejects(createDeviceLock({ credentialId: 'Y3JlZA', prfSalt: 'AAAA', prf: prfOf(7) }), /keinen gültigen Schlüssel/);
  await assert.rejects(createDeviceLock({ credentialId: '', prfSalt, prf: prfOf(7) }), /keinen gültigen Schlüssel/);
});

test('device lock and PIN lock side by side: separate key pairs, neither opens the other seal', async () => {
  const pin = await createPinLock('2468');
  const device = await createDeviceLock({ credentialId: 'Y3JlZA', prfSalt: newPrfSalt(), prf: prfOf(1) });
  assert.notEqual(pin.publicKey, device.publicKey);
  const sessions = { a1: { userKey: 'k' } };
  const byPin = await seal(pin, sessions);
  const byDevice = await seal(device, sessions);
  await assert.rejects(unsealWithDevice(pin, byPin, prfOf(1)), /nicht den passenden Schlüssel/);
  await assert.rejects(unseal(device, byDevice, '2468'), /Falsche PIN/);
  assert.deepEqual(await unseal(pin, byPin, '2468'), sessions);
  assert.deepEqual(await unsealWithDevice(device, byDevice, prfOf(1)), sessions);
});
