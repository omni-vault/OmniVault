// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// otpauth:// URIs from QR codes: strict parsing, and decoding with the vendored jsQR (the same file the popup loads).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import jsQR from '../vendor/jsqr.mjs';
import { parseOtpauthUri, totp } from '../src/lib/totp.js';
import { encodeQr, renderQr } from './qr-encode.mjs';

const URI = 'otpauth://totp/Example%20Shop:ada%40example.org?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Shop&algorithm=SHA1&digits=6&period=30';

test('otpauth parsing: label, issuer, defaults', () => {
  const r = parseOtpauthUri(URI);
  assert.deepEqual({ ...r, uri: undefined }, { uri: undefined, secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA-1', digits: 6, period: 30, issuer: 'Example Shop', account: 'ada@example.org' });
  const minimal = parseOtpauthUri('  otpauth://totp/alice?secret=jbsw%20y3dp%3D%3D  ');
  assert.equal(minimal.secret, 'JBSWY3DP');
  assert.equal(minimal.issuer, '');
  assert.equal(minimal.account, 'alice');
  assert.equal(minimal.uri, 'otpauth://totp/alice?secret=jbsw%20y3dp%3D%3D');
  const sha = parseOtpauthUri('OTPAUTH://TOTP/Corp:bob?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA512&digits=8&period=60');
  assert.deepEqual([sha.algorithm, sha.digits, sha.period, sha.issuer, sha.account], ['SHA-512', 8, 60, 'Corp', 'bob']);
});

test('otpauth parsing: rejects everything that is not a usable TOTP', () => {
  for (const bad of [
    'https://example.org/?secret=JBSWY3DPEHPK3PXP',
    'JBSWY3DPEHPK3PXP',
    'otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1',
    'otpauth://totp/x',
    'otpauth://totp/x?secret=',
    'otpauth://totp/x?secret=JBSWY3DP1',
    'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
    'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4',
    'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10',
    'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0',
    'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=1.5',
    'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=86400',
    'otpauth-migration://offline?data=abc',
  ]) assert.throws(() => parseOtpauthUri(bad), bad);
});

test('QR code with an otpauth URI → jsQR → parser → working code', async () => {
  const image = renderQr(encodeQr(URI), 3);
  const decoded = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
  assert.equal(decoded?.data, URI);
  const r = parseOtpauthUri(decoded.data);
  assert.equal(r.issuer, 'Example Shop');
  // RFC 6238 style check against the same secret entered directly
  assert.deepEqual(await totp(r.uri, 1_700_000_000_000), await totp('JBSWY3DPEHPK3PXP', 1_700_000_000_000));
  // an image without a QR code
  const blank = { data: new Uint8ClampedArray(120 * 120 * 4).fill(255), width: 120, height: 120 };
  assert.equal(jsQR(blank.data, blank.width, blank.height), null);
});

test('test QR encoder covers versions 1–9 (checked by jsQR)', () => {
  for (const len of [1, 30, 50, 80, 105, 135, 160, 200]) {
    const text = `otpauth://totp/x?secret=${'A'.repeat(len)}`;
    const img = renderQr(encodeQr(text), 2);
    assert.equal(jsQR(img.data, img.width, img.height)?.data, text, `length ${text.length}`);
  }
});
