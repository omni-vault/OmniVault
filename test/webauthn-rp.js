// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// A small WebAuthn relying party for tests, written independently of src/lib/webauthn.js: own CBOR decoder,
// Node's crypto for the signature (DER as WebAuthn sends it). Checks what a real site checks
// (W3C WebAuthn §7.1 and §7.2): type, challenge, origin, crossOrigin/topOrigin, rpId hash, flags, algorithm,
// signature, counter. A site that may be embedded names the top-level origins it accepts (`topOrigins`); any other
// cross-origin answer is refused.
import { createHash, createPublicKey, verify } from 'node:crypto';

const fromB64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const sha256 = (b) => createHash('sha256').update(b).digest();

export function decodeCbor(buf) {
  let p = 0;
  const read = () => {
    const ib = buf[p++];
    const major = ib >> 5;
    let n = ib & 31;
    if (n === 24) n = buf[p++];
    else if (n === 25) { n = buf.readUInt16BE(p); p += 2; } else if (n === 26) { n = buf.readUInt32BE(p); p += 4; } else if (n > 26) throw new Error(`CBOR: length ${n} not supported`);
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const v = buf.subarray(p, p + n); p += n; return v; }
      case 3: { const v = buf.subarray(p, p + n).toString('utf8'); p += n; return v; }
      case 4: return Array.from({ length: n }, read);
      case 5: { const m = new Map(); for (let i = 0; i < n; i++) { const k = read(); m.set(k, read()); } return m; }
      default: throw new Error(`CBOR: type ${major} not supported`);
    }
  };
  const v = read();
  return { value: v, length: p };
}

export function parseAuthData(ad) {
  const out = { rpIdHash: ad.subarray(0, 32), flags: ad[32], counter: ad.readUInt32BE(33) };
  out.up = !!(out.flags & 1); out.uv = !!(out.flags & 4); out.be = !!(out.flags & 8); out.bs = !!(out.flags & 16);
  if (out.flags & 0x40) {
    out.aaguid = ad.subarray(37, 53);
    const len = ad.readUInt16BE(53);
    out.credentialId = ad.subarray(55, 55 + len);
    const { value, length } = decodeCbor(ad.subarray(55 + len));
    out.cose = value;
    out.rest = ad.length - (55 + len + length);
  }
  return out;
}

function checkClientData(json, type, challenge, origin, topOrigins = []) {
  const raw = Buffer.from(fromB64url(json)).toString('utf8');
  const cd = JSON.parse(raw);
  if (cd.type !== type) throw new Error(`clientData.type ${cd.type}`);
  if (cd.challenge !== challenge) throw new Error('challenge does not match');
  if (cd.origin !== origin) throw new Error(`origin ${cd.origin} ≠ ${origin}`);
  if (cd.crossOrigin !== undefined && typeof cd.crossOrigin !== 'boolean') throw new Error('crossOrigin is not a boolean');
  if (cd.crossOrigin) {
    if (!topOrigins.includes(cd.topOrigin)) throw new Error(`crossOrigin from ${cd.topOrigin ?? '(no topOrigin)'}`);
    if (cd.topOrigin === origin) throw new Error('topOrigin = origin, aber crossOrigin');
  } else if (cd.topOrigin !== undefined) throw new Error('topOrigin without crossOrigin');
  // §5.8.1.2 limited verification: the first members come in this order
  const prefix = `{"type":${JSON.stringify(type)},"challenge":${JSON.stringify(challenge)},"origin":${JSON.stringify(origin)}`;
  if (!raw.startsWith(prefix)) throw new Error('clientDataJSON: field order');
  if (cd.crossOrigin && !raw.startsWith(`${prefix},"crossOrigin":true,"topOrigin":`)) throw new Error('clientDataJSON: crossOrigin/topOrigin');
  return cd;
}

/** Registration → what the site stores: { credentialId (base64url), jwk, counter, flags }. */
export function verifyRegistration(cred, { challenge, origin, rpId, requireUV = false, topOrigins = [] }) {
  if (cred.type !== 'public-key' || cred.id !== cred.rawId) throw new Error('id/type');
  const clientData = checkClientData(cred.response.clientDataJSON, 'webauthn.create', challenge, origin, topOrigins);
  const att = decodeCbor(fromB64url(cred.response.attestationObject)).value;
  if (att.get('fmt') !== 'none' || att.get('attStmt').size !== 0) throw new Error('attestation is not "none"');
  const ad = parseAuthData(att.get('authData'));
  if (!ad.rpIdHash.equals(sha256(rpId))) throw new Error('rpIdHash');
  if (!ad.up) throw new Error('UP missing');
  if (requireUV && !ad.uv) throw new Error('UV missing');
  if (!ad.credentialId || ad.rest !== 0) throw new Error('attested credential data');
  if (Buffer.from(ad.credentialId).toString('base64url') !== cred.id) throw new Error('credential ID does not match');
  const c = ad.cose;
  if (c.get(1) !== 2 || c.get(3) !== -7 || c.get(-1) !== 1) throw new Error('not an ES256 key');
  const jwk = { kty: 'EC', crv: 'P-256', x: Buffer.from(c.get(-2)).toString('base64url'), y: Buffer.from(c.get(-3)).toString('base64url') };
  if (cred.response.publicKey) { // getPublicKey(): same key as SPKI
    const spki = createPublicKey({ key: fromB64url(cred.response.publicKey), format: 'der', type: 'spki' }).export({ format: 'jwk' });
    if (spki.x !== jwk.x || spki.y !== jwk.y) throw new Error('getPublicKey() ≠ COSE key');
  }
  return { credentialId: cred.id, jwk, counter: ad.counter, flags: ad, clientData };
}

/** Sign-in with a stored credential; returns the new counter. */
export function verifyAuthentication(cred, { challenge, origin, rpId, stored, requireUV = false, topOrigins = [] }) {
  if (cred.type !== 'public-key' || cred.id !== stored.credentialId) throw new Error('unbekannte Credential-ID');
  const clientData = checkClientData(cred.response.clientDataJSON, 'webauthn.get', challenge, origin, topOrigins);
  const adBytes = fromB64url(cred.response.authenticatorData);
  const ad = parseAuthData(adBytes);
  if (!ad.rpIdHash.equals(sha256(rpId))) throw new Error('rpIdHash');
  if (!ad.up) throw new Error('UP missing');
  if (requireUV && !ad.uv) throw new Error('UV missing');
  const data = Buffer.concat([adBytes, sha256(fromB64url(cred.response.clientDataJSON))]);
  const key = createPublicKey({ key: stored.jwk, format: 'jwk' });
  if (!verify('sha256', data, key, fromB64url(cred.response.signature))) throw new Error('invalid signature');
  if ((ad.counter || stored.counter) && ad.counter <= stored.counter) throw new Error('counter did not increase');
  return { counter: ad.counter, userHandle: cred.response.userHandle, flags: ad, clientData };
}
