// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { SETS, entropyBits, generatePassword, generatePin, randomInt } from '../src/lib/generator.js';

test('every selected character class is present, others absent', () => {
  for (let n = 0; n < 200; n++) {
    const pw = generatePassword({ length: 12, upper: true, lower: true, digits: true, symbols: false });
    assert.equal(pw.length, 12);
    assert.match(pw, /[A-Z]/);
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[0-9]/);
    assert.doesNotMatch(pw, /[^A-Za-z0-9]/);
  }
  assert.throws(() => generatePassword({ upper: false, lower: false, digits: false, symbols: false }));
});

test('avoidAmbiguous removes look-alike characters', () => {
  const pw = Array.from({ length: 50 }, () => generatePassword({ length: 64, avoidAmbiguous: true })).join('');
  assert.doesNotMatch(pw, /[Il1O0o]/);
});

test('randomInt is unbiased (chi-square, 6 buckets)', () => {
  const counts = new Array(6).fill(0);
  const N = 60000;
  for (let i = 0; i < N; i++) counts[randomInt(6)]++;
  const exp = N / 6;
  const chi = counts.reduce((s, c) => s + (c - exp) ** 2 / exp, 0);
  assert.ok(chi < 20.5, `chi² ${chi.toFixed(2)} (p<0.001 bound for 5 dof)`);
});

test('PIN and entropy', () => {
  assert.match(generatePin(8), /^\d{8}$/);
  assert.equal(entropyBits({ length: 20, lower: true, upper: true, digits: true, symbols: false }), Math.floor(20 * Math.log2(62)));
  assert.equal(SETS.digits.length, 10);
});

test('weak password check', async () => {
  const { weakness } = await import('../src/lib/strength.js');
  for (const pw of ['123456', 'Passwort1', 'kurz', 'aaaaaaaaaaaa', 'qwertzui', 'adalovelace!1', 'sommer2026']) assert.ok(weakness(pw, ['adalovelace@example.org']), pw);
  for (const pw of ['Kq7#mZ2!pL9x', 'korrekt-pferd-batterie-heftklammer', 'gh-neu-2026-Xy!q']) assert.equal(weakness(pw), null, pw);
});

test('sample identities: every language, reserved e-mail domain, no document numbers', async () => {
  const { sampleIdentity, SAMPLE_LANGUAGES } = await import('../src/lib/sample-identity.js');
  for (const lang of SAMPLE_LANGUAGES) {
    for (let n = 0; n < 20; n++) {
      const { name, identity } = sampleIdentity(lang);
      assert.ok(name && identity.firstName && identity.lastName && identity.city && identity.postalCode && identity.address1, lang);
      assert.match(identity.email, /^[a-z]+\.[a-z0-9]+\d\d@example\.com$/, `${lang}: ${identity.email}`);
      assert.ok(!identity.phone || /^\+1 555-01\d\d$/.test(identity.phone), identity.phone);
      assert.ok(!('ssn' in identity) && !('passportNumber' in identity) && !('licenseNumber' in identity));
    }
  }
  assert.equal(sampleIdentity('fr-CA').identity.country, 'France', 'region falls back to the language');
});

/* ---------- passphrases ---------- */

test('EFF wordlist: matches the published file, 7776 distinct words in dice order', async () => {
  const { readFile } = await import('node:fs/promises');
  const { createHash } = await import('node:crypto');
  const { wordlist } = await import('../src/lib/generator.js');
  const src = await readFile(new URL('../vendor/eff_large_wordlist.txt', import.meta.url), 'utf8');
  assert.equal(createHash('sha256').update(src).digest('hex'), 'addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e');
  const words = wordlist();
  assert.equal(words.length, 7776);
  assert.equal(new Set(words).size, 7776);
  assert.deepEqual(words, src.trimEnd().split('\n').map((l) => l.split('\t')[1]), 'generated module equals the source file (npm run wordlist:build)');
  for (const w of words) assert.match(w, /^[a-z]+(-[a-z]+)?$/);
  assert.equal(words[0], 'abacus');
  assert.equal(words[7775], 'zoom');
});

test('passphrase: word count, separator, capitalization, number', async () => {
  const { generatePassphrase, wordlist } = await import('../src/lib/generator.js');
  const list = new Set(wordlist());
  for (let n = 0; n < 50; n++) {
    const p = generatePassphrase({ words: 6, separator: '.', capitalize: false, includeNumber: false });
    const parts = p.split('.');
    assert.equal(parts.length, 6);
    for (const w of parts) assert.ok(list.has(w), w);
  }
  for (let n = 0; n < 50; n++) {
    const p = generatePassphrase({ words: 4, separator: ' ', capitalize: true, includeNumber: true });
    const parts = p.split(' ');
    assert.equal(parts.length, 4);
    for (const w of parts) assert.match(w, /^[A-Z]/);
    assert.equal(parts.filter((w) => /\d$/.test(w)).length, 1, p);
    for (const w of parts) assert.ok(list.has(w.replace(/\d$/, '').toLowerCase()), w);
  }
  // limits: 3–20 words, separator at most 3 characters, no control characters
  assert.equal(generatePassphrase({ words: 1, separator: '-' }).split('-').length >= 3, true);
  assert.equal(generatePassphrase({ words: 99, separator: '+' }).split('+').length, 20);
  assert.equal(generatePassphrase({ words: 3, separator: '\n' }).includes('\n'), false);
});

test('passphrase: words are drawn uniformly (chi-square over the first dice digit)', async () => {
  const { generatePassphrase, wordlist } = await import('../src/lib/generator.js');
  // the list is in dice order: word i belongs to bucket floor(i / 1296) (first die), 6 equally large buckets
  const index = new Map(wordlist().map((w, i) => [w, i]));
  const counts = new Array(6).fill(0);
  const N = 6000;
  for (let i = 0; i < N / 10; i++) for (const w of generatePassphrase({ words: 10, separator: ' ' }).split(' ')) counts[Math.floor(index.get(w) / 1296)]++;
  const exp = N / 6;
  const chi = counts.reduce((s, c) => s + (c - exp) ** 2 / exp, 0);
  assert.ok(chi < 20.5, `chi² ${chi.toFixed(2)} (p<0.001 bound for 5 dof)`);
  // no word should dominate: 6000 draws from 7776 words, expected maximum count is small
  const seen = new Map();
  for (let i = 0; i < 600; i++) for (const w of generatePassphrase({ words: 10 }).split('-')) seen.set(w, (seen.get(w) ?? 0) + 1);
  assert.ok(Math.max(...seen.values()) <= 7, 'no word repeats suspiciously often');
});

test('passphrase entropy: log2(7776) per word plus the digit', async () => {
  const { passphraseEntropy } = await import('../src/lib/generator.js');
  assert.equal(passphraseEntropy({ words: 5 }), Math.floor(5 * Math.log2(7776))); // 64
  assert.equal(passphraseEntropy({ words: 5 }), 64);
  assert.equal(passphraseEntropy({ words: 6, capitalize: true, separator: '_' }), 77);
  assert.equal(passphraseEntropy({ words: 4, includeNumber: true }), Math.floor(4 * Math.log2(7776) + Math.log2(10) + Math.log2(4)));
  assert.equal(passphraseEntropy({ words: 20 }), 258);
});

/* ---------- usernames ---------- */

test('usernames: random word, plus address, catch-all', async () => {
  const { generateUsername, plusAddress, catchAllAddress, randomWordUsername, wordlist, normalizeDomain } = await import('../src/lib/generator.js');
  const list = new Set(wordlist());
  for (let n = 0; n < 30; n++) {
    const u = randomWordUsername({ number: true });
    assert.match(u, /^[a-z-]+\d{4}$/);
    assert.ok(list.has(u.slice(0, -4)));
    assert.match(randomWordUsername({ capitalize: true, number: false }), /^[A-Z][a-z-]*$/);
  }
  assert.match(plusAddress('ada.lovelace@example.org'), /^ada\.lovelace\+[a-z0-9]{8}@example\.org$/);
  assert.match(plusAddress(' Ada+old@Example.ORG '), /^Ada\+[a-z0-9]{8}@example\.org$/, 'an existing tag is replaced, domain lower case');
  assert.notEqual(plusAddress('a@example.org'), plusAddress('a@example.org'));
  for (const bad of ['', 'ada', '@example.org', 'ada@', 'ada@localhost', 'a b@example.org', 'ada@exa mple.org']) assert.throws(() => plusAddress(bad), bad);
  assert.match(catchAllAddress('@Mail.Example.net'), /^[a-z0-9]{10}@mail\.example\.net$/);
  assert.match(catchAllAddress('bücher.example'), /^[a-z0-9]{10}@bücher\.example$/);
  for (const bad of ['', 'example', '-a.example', 'a..example', 'exa_mple.org', 'https://example.org/x']) assert.throws(() => catchAllAddress(bad), bad);
  assert.equal(normalizeDomain('Example.org.'), 'example.org');
  assert.match(generateUsername({ usernameType: 'plus', plusEmail: 'me@example.org' }), /^me\+[a-z0-9]{8}@example\.org$/);
  assert.match(generateUsername({ usernameType: 'catchall', catchAllDomain: 'example.org' }), /@example\.org$/);
  assert.match(generateUsername({}), /^[a-z-]+\d{4}$/);
  assert.throws(() => generateUsername({ usernameType: 'plus', plusEmail: '' }));
});

test('generator settings are normalized; the editor dice follows the chosen kind', async () => {
  const { normalizeGenerator, generateSecret, GENERATOR_DEFAULTS } = await import('../src/lib/generator.js');
  assert.equal(GENERATOR_DEFAULTS.type, 'password');
  const n = normalizeGenerator({ type: 'bogus', words: '7', length: 1000, separator: 'abcdef', usernameType: 'x', symbols: 0 });
  assert.equal(n.type, 'password');
  assert.equal(n.words, 7);
  assert.equal(n.length, 128);
  assert.equal(n.separator, 'abc');
  assert.equal(n.usernameType, 'word');
  assert.equal(n.symbols, false);
  assert.equal(normalizeGenerator({ length: 32, symbols: false }).length, 32, 'old stored settings keep working');
  assert.equal(generateSecret({ type: 'passphrase', words: 3, separator: '~' }).split('~').length, 3);
  assert.equal(generateSecret({ type: 'pin', length: 10 }).length, 10, 'a PIN setting still gives the dice a password');
  assert.equal(generateSecret({ type: 'username', length: 16 }).length, 16);
});
