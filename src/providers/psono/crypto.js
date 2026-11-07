// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Psono's client-side cryptography, written from the server's sources (restapi/utils, views/login.py):
//  - NaCl box (X25519 + XSalsa20-Poly1305) and secretbox (XSalsa20-Poly1305) – TweetNaCl.js, the same constructions
//    as libsodium's crypto_box / crypto_secretbox that the server uses through PyNaCl
//  - Ed25519 signatures of the server's /info/ answer
//  - scrypt (@noble/hashes) for the login key ("authkey") and for the key that unlocks the account's keys
// Keys travel as hex strings; symmetric keys are themselves hex strings of 32 random bytes.
import nacl from '../../../vendor/tweetnacl.mjs';
import { scryptAsync } from '../../../vendor/noble-hashes.mjs';
import { fromUtf8, hex, utf8 } from '../../lib/bytes.js';

export class PsonoCryptoError extends Error {}

/** Strict hex → bytes (bytes.js' fromHex accepts anything). */
export function unhex(h, length) {
  const s = String(h ?? '');
  if (s.length % 2 || !/^[0-9a-fA-F]*$/.test(s)) throw new PsonoCryptoError('invalid hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  if (length != null && out.length !== length) throw new PsonoCryptoError(`expected ${length} bytes`);
  return out;
}

async function digestHex(alg, text) {
  return hex(await crypto.subtle.digest(alg, utf8(text)));
}
export const sha256Hex = (text) => digestHex('SHA-256', text);
export const sha512Hex = (text) => digestHex('SHA-512', text);

/** Bounds for the scrypt parameters a server announces (it could otherwise ask for gigabytes or hours). */
const LIMITS = { u: [10, 20], r: [1, 32], p: [1, 16], l: [16, 128] };
export const DEFAULT_PARAMS = { u: 14, r: 8, p: 1, l: 64 };

export function checkParams(algorithm, params) {
  if ((algorithm ?? 'scrypt') !== 'scrypt') throw new PsonoCryptoError(`unsupported hashing algorithm ${algorithm}`);
  const out = {};
  for (const [k, [lo, hi]] of Object.entries(LIMITS)) {
    const v = params?.[k] ?? DEFAULT_PARAMS[k];
    if (!Number.isInteger(v) || v < lo || v > hi) throw new PsonoCryptoError(`hashing parameter ${k} out of range`);
    out[k] = v;
  }
  return out;
}

/** hex(scrypt(password, salt)) with N = 2^u. */
async function scryptHex(password, salt, params) {
  const { u, r, p, l } = checkParams('scrypt', params);
  return hex(await scryptAsync(utf8(password), utf8(salt), { N: 2 ** u, r, p, dkLen: l, maxmem: 2 ** 31 }));
}

/** What the server checks instead of the password: scrypt(password, salt = sha512(lower-case username)). */
export async function authkey(username, password, params) {
  return scryptHex(password, await sha512Hex(String(username).toLowerCase()), params);
}

/**
 * Key that encrypts the account's private key and secret key: sha256(hex(scrypt(password, salt = sha512(user_sauce)))),
 * a hex string used as secretbox key.
 */
export async function passwordKey(password, userSauce, params) {
  return sha256Hex(await scryptHex(password, await sha512Hex(String(userSauce)), params));
}

/* ---------- secretbox ---------- */

/** Encrypts a string: { text, nonce } in hex, with a fresh random nonce. */
export function encryptSymmetric(keyHex, plaintext) {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const box = nacl.secretbox(utf8(plaintext), nonce, unhex(keyHex, nacl.secretbox.keyLength));
  return { text: hex(box), nonce: hex(nonce) };
}

export function decryptSymmetric(keyHex, textHex, nonceHex) {
  const out = nacl.secretbox.open(unhex(textHex), unhex(nonceHex, nacl.secretbox.nonceLength), unhex(keyHex, nacl.secretbox.keyLength));
  if (!out) throw new PsonoCryptoError('decryption failed');
  return fromUtf8(out);
}

/* ---------- box ---------- */

export function generateKeyPair() {
  const k = nacl.box.keyPair();
  return { publicKey: hex(k.publicKey), privateKey: hex(k.secretKey) };
}

export function publicKeyOf(privateKeyHex) {
  return hex(nacl.box.keyPair.fromSecretKey(unhex(privateKeyHex, nacl.box.secretKeyLength)).publicKey);
}

export function encryptBox(plaintext, theirPublicHex, myPrivateHex) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const box = nacl.box(utf8(plaintext), nonce, unhex(theirPublicHex, nacl.box.publicKeyLength), unhex(myPrivateHex, nacl.box.secretKeyLength));
  return { text: hex(box), nonce: hex(nonce) };
}

export function decryptBox(textHex, nonceHex, theirPublicHex, myPrivateHex) {
  const out = nacl.box.open(unhex(textHex), unhex(nonceHex, nacl.box.nonceLength),
    unhex(theirPublicHex, nacl.box.publicKeyLength), unhex(myPrivateHex, nacl.box.secretKeyLength));
  if (!out) throw new PsonoCryptoError('decryption failed');
  return fromUtf8(out);
}

/* ---------- signatures ---------- */

/** Ed25519 signature (hex) of a UTF-8 text by a verify key (hex). */
export function verifySignature(text, signatureHex, verifyKeyHex) {
  try {
    return nacl.sign.detached.verify(utf8(text), unhex(signatureHex, nacl.sign.signatureLength), unhex(verifyKeyHex, nacl.sign.publicKeyLength));
  } catch { return false; }
}

/** A fresh random symmetric key (hex), as Psono uses for secrets, shares and datastores. */
export const randomKey = () => hex(nacl.randomBytes(nacl.secretbox.keyLength));
