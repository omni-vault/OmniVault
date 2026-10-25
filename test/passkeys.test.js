// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Passkeys outside the browser: which page requests OmniVault takes, which passkeys match, and what happens to
// passkeys when items are copied, exported and imported.
import assert from 'node:assert/strict';
import test from 'node:test';
import { checkFrame, checkRequest, extensionResults, frameFeature, matchingPasskeys, pageOrigin } from '../src/background/passkeys.js';
import { clientDataJSON } from '../src/lib/webauthn.js';
import { passkeysWithKeys, transferData, transferLoss } from '../src/background/tools.js';
import { toBitwardenJson } from '../src/lib/export.js';
import { importBitwardenJson } from '../src/lib/import.js';

const create = (extra = {}) => ({
  challenge: 'Y2g', rp: { id: 'example.com', name: 'Example' }, user: { id: 'dQ', name: 'ada' },
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }], ...extra,
});

test('page requests: secure origin, relying party, algorithm', () => {
  assert.equal(pageOrigin('https://example.com/a')?.origin, 'https://example.com');
  assert.ok(pageOrigin('http://localhost:8080/'));
  assert.equal(pageOrigin('http://example.com/'), null, 'plain http only on localhost');
  assert.equal(pageOrigin('file:///x'), null);

  assert.deepEqual(checkRequest({ kind: 'create', options: create(), url: 'https://login.example.com/' }), { ok: true, rpId: 'example.com', origin: 'https://login.example.com' });
  assert.equal(checkRequest({ kind: 'create', options: create({ rp: { name: 'x' } }), url: 'https://login.example.com/' }).rpId, 'login.example.com', 'rp.id defaults to the host');
  assert.equal(checkRequest({ kind: 'create', options: create({ rp: { id: 'other.com' } }), url: 'https://example.com/' }).reason, 'rpId');
  assert.equal(checkRequest({ kind: 'get', options: { challenge: 'Y2g', rpId: 'co.uk' }, url: 'https://example.co.uk/' }).reason, 'rpId');
  assert.equal(checkRequest({ kind: 'create', options: create({ pubKeyCredParams: [{ type: 'public-key', alg: -257 }] }), url: 'https://example.com/' }).reason, 'algorithm', 'RSA only: browser');
  assert.equal(checkRequest({ kind: 'create', options: create({ pubKeyCredParams: [] }), url: 'https://example.com/' }).ok, true, 'empty list means the defaults (ES256 among them)');
  assert.equal(checkRequest({ kind: 'create', options: create({ authenticatorSelection: { authenticatorAttachment: 'cross-platform' } }), url: 'https://example.com/' }).reason, 'attachment', 'security key wanted');
  assert.equal(checkRequest({ kind: 'get', options: {}, url: 'https://example.com/' }).reason, 'challenge');
  assert.equal(checkRequest({ kind: 'get', options: { challenge: 'Y2g' }, url: 'http://example.com/' }).reason, 'insecure');
});

test('matching passkeys: same relying party, allowed ids only', () => {
  const items = [
    { id: 'a', passkeys: [{ rpId: 'example.com', credentialId: '00112233-4455-6677-8899-aabbccddeeff' }] },
    { id: 'b', passkeys: [{ rpId: 'example.com', credentialId: 'b64.AQID' }] },
    { id: 'c', passkeys: [{ rpId: 'example.org', credentialId: 'b64.AQID' }] },
    { id: 'd' },
  ];
  assert.deepEqual(matchingPasskeys(items, 'example.com').map((m) => m.item.id), ['a', 'b']);
  assert.deepEqual(matchingPasskeys(items, 'example.com', ['AQID']).map((m) => m.item.id), ['b']);
  assert.deepEqual(matchingPasskeys(items, 'example.com', ['ABEiM0RVZneImaq7zN3u_w']).map((m) => m.item.id), ['a'], 'UUID id as bytes');
  assert.deepEqual(matchingPasskeys(items, 'example.com', ['BAU']), []);
});

test('copying and moving: passkeys go along to accounts that store them, otherwise they are named as lost', () => {
  const item = {
    type: 'login', name: 'Shop', username: 'ada', uris: [],
    passkeys: [{ credentialId: 'x', rpId: 'shop.example', userName: 'ada' }], _passkeyKeys: { x: 'PKCS8' },
  };
  assert.deepEqual(passkeysWithKeys(item), [{ credentialId: 'x', rpId: 'shop.example', userName: 'ada', keyValue: 'PKCS8' }]);
  assert.deepEqual(transferData(item, null, { passkeys: true }).passkeys[0].keyValue, 'PKCS8');
  assert.equal(transferData(item, null, { passkeys: false }).passkeys, undefined);
  assert.deepEqual(transferLoss(item, { passkeys: true }), []);
  assert.deepEqual(transferLoss(item, {}), ['Passkeys']);
  // Proton Pass passkeys: only shown, their keys stay in Proton Pass
  assert.deepEqual(transferLoss({ type: 'login', passkeys: [{ rpId: 'a.example' }] }, { passkeys: true }), ['Passkeys']);
});

test('export and import keep passkeys in Bitwarden\'s JSON format', () => {
  const passkey = {
    credentialId: '00112233-4455-6677-8899-aabbccddeeff', keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256',
    keyValue: 'MIGH', rpId: 'shop.example', userHandle: 'dQ', userName: 'ada', counter: '0', rpName: 'Shop',
    userDisplayName: 'Ada', discoverable: 'true', creationDate: '2026-10-16T10:00:00.000Z',
  };
  const json = JSON.parse(toBitwardenJson([{ type: 'login', name: 'Shop', username: 'ada', uris: ['https://shop.example'], passkeys: [passkey] }]));
  assert.deepEqual(json.items[0].login.fido2Credentials, [passkey]);
  const [back] = importBitwardenJson(json);
  assert.deepEqual(back.passkeys, [passkey]);
  assert.equal(transferData(back, null, { passkeys: true }).passkeys[0].keyValue, 'MIGH');
  const [plain] = importBitwardenJson({ items: [{ type: 1, name: 'x', login: { username: 'u' } }] });
  assert.equal(plain.passkeys, undefined);
});

test('embedded frames: only what the browser confirms', () => {
  const base = { kind: 'get', frameUrl: 'https://login.idp.example/frame', senderOrigin: 'https://login.idp.example', tabUrl: 'https://shop.example/checkout' };
  const seen = (extra = {}) => ({ origin: 'https://login.idp.example', ancestors: ['https://shop.example'], allowed: true, active: false, ...extra });
  assert.equal(frameFeature('get'), 'publickey-credentials-get');
  assert.equal(frameFeature('create'), 'publickey-credentials-create');
  assert.deepEqual(checkFrame({ ...base, inspected: seen() }), { ok: true, crossOrigin: true, topOrigin: 'https://shop.example' });
  assert.equal(checkFrame({ ...base, inspected: null }).reason, 'frame-unknown', 'browser cannot tell (Firefox): browser handles it');
  assert.equal(checkFrame({ ...base, inspected: seen({ allowed: false }) }).reason, 'policy', 'no allow="publickey-credentials-get"');
  assert.equal(checkFrame({ ...base, inspected: seen({ allowed: 'yes' }) }).reason, 'policy');
  assert.equal(checkFrame({ ...base, senderOrigin: undefined, inspected: seen() }).reason, 'frame-origin');
  assert.equal(checkFrame({ ...base, senderOrigin: 'https://evil.example', inspected: seen() }).reason, 'frame-origin');
  assert.equal(checkFrame({ ...base, inspected: seen({ origin: 'https://evil.example' }) }).reason, 'frame-origin');
  assert.equal(checkFrame({ ...base, inspected: seen({ ancestors: ['https://other.example'] }) }).reason, 'top-origin', 'top must be the tab');
  assert.equal(checkFrame({ ...base, inspected: seen({ ancestors: ['http://mid.example', 'https://shop.example'] }) }).reason, 'insecure');
  assert.equal(checkFrame({ ...base, tabUrl: 'http://shop.example/' }).reason, 'frame-unknown');
  assert.equal(checkFrame({ ...base, tabUrl: 'http://shop.example/', inspected: seen({ ancestors: ['http://shop.example'] }) }).reason, 'insecure');
  assert.equal(checkFrame({ ...base, kind: 'create', inspected: seen() }).reason, 'activation', 'creating in a foreign frame needs a gesture');
  assert.equal(checkFrame({ ...base, kind: 'create', inspected: seen({ active: true }) }).ok, true);
  // same origin all the way up: not cross-origin, no gesture needed
  const same = { kind: 'create', frameUrl: 'https://shop.example/f', senderOrigin: 'https://shop.example', tabUrl: 'https://shop.example/', inspected: seen({ origin: 'https://shop.example' }) };
  assert.deepEqual(checkFrame(same), { ok: true, crossOrigin: false, topOrigin: 'https://shop.example' });
  // A embeds B embeds A: the inner A is cross-origin
  assert.equal(checkFrame({ ...same, kind: 'get', inspected: seen({ origin: 'https://shop.example', ancestors: ['https://login.idp.example', 'https://shop.example'] }) }).crossOrigin, true);
});

test('clientDataJSON in a cross-origin frame', () => {
  const cd = (x) => JSON.parse(new TextDecoder().decode(clientDataJSON({ type: 'webauthn.get', challenge: 'Y2g', origin: 'https://a.example', ...x })));
  assert.deepEqual(Object.entries(cd({})), [['type', 'webauthn.get'], ['challenge', 'Y2g'], ['origin', 'https://a.example'], ['crossOrigin', false]]);
  assert.deepEqual(Object.keys(cd({ crossOrigin: true, topOrigin: 'https://b.example' })), ['type', 'challenge', 'origin', 'crossOrigin', 'topOrigin']);
  assert.equal(cd({ crossOrigin: true, topOrigin: 'https://b.example' }).topOrigin, 'https://b.example');
  assert.equal(cd({ crossOrigin: false, topOrigin: 'https://b.example' }).topOrigin, undefined, 'topOrigin only when cross-origin');
});

test('extensions: credProps answered, PRF and largeBlob declined', () => {
  assert.deepEqual(extensionResults('create', { credProps: true }, { rk: true }), { credProps: { rk: true } });
  assert.deepEqual(extensionResults('create', { prf: true, largeBlob: { support: 'preferred' } }), { prf: { enabled: false }, largeBlob: { supported: false } });
  assert.deepEqual(extensionResults('create', {}), {});
  assert.deepEqual(extensionResults('create', undefined), {});
  assert.deepEqual(extensionResults('get', { prf: true }), {}, 'no PRF output: not supported');
  assert.deepEqual(extensionResults('get', { largeBlob: { read: true } }), { largeBlob: {} });
  assert.deepEqual(extensionResults('get', { largeBlob: { write: true } }), { largeBlob: { written: false } });
  const required = checkRequest({ kind: 'create', options: create({ extensions: { largeBlob: { support: 'required' } } }), url: 'https://example.com/' });
  assert.equal(required.reason, 'largeBlob', 'largeBlob required: browser');
  assert.equal(checkRequest({ kind: 'create', options: create({ extensions: { largeBlob: { support: 'preferred' }, prf: true } }), url: 'https://example.com/' }).ok, true);
});
