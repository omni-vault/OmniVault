// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// pass/gopass "decrypt on open" without the real programs: path hints, the list from names only, an outdated host.
// The same mode runs against real pass and gopass in pass.test.js and gopass.test.js.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import GopassProvider from '../src/providers/gopass/index.js';
import PassProvider, { pathHints, payloadOf } from '../src/providers/pass/index.js';
import { hostAtLeast } from '../src/providers/native-host.js';
import { matchesUrl } from '../src/lib/match.js';

test('path hints: site and user name from the path, file names that only look like hosts ignored', () => {
  const cases = {
    'web/github.com': { site: 'github.com' },
    'github.com': { site: 'github.com' },
    'websites/github.com/ada': { site: 'github.com', user: 'ada' },
    'mail/ada@example.org': { site: 'example.org' },
    'work/example.co.uk/login/main': { site: 'example.co.uk' },
    'intranet/wiki.example.com:8443/ada': { site: 'wiki.example.com:8443', user: 'ada' },
    'notes/idee': {}, bank: {}, 'docs/readme.md': {}, 'backup/keys.zip': {}, 'x/foo.txt': {}, 'lan/nas.local': {}, 'v/notes.v2': {},
  };
  for (const [path, want] of Object.entries(cases)) assert.deepEqual(pathHints(path), want, path);
});

test('hostAtLeast compares versions numerically', () => {
  assert.ok(hostAtLeast('2.1.0', '2.1.0') && hostAtLeast('2.10.0', '2.1.0') && hostAtLeast('3.0', '2.1.0'));
  assert.ok(!hostAtLeast('2.0.0', '2.1.0') && !hostAtLeast(undefined, '2.1.0') && !hostAtLeast('dev', '2.1.0'));
});

function fakeHost({ version = '2.1.0', names = [], entries = {} } = {}) {
  const calls = [];
  return {
    calls,
    request: async (backend, cmd, args) => {
      calls.push(cmd);
      if (cmd === 'status') return { version, cli: '/bin/x', gpg: true, initialized: true };
      if (cmd === 'names') {
        if (version < '2.1.0') throw new Error('Unbekannter Befehl names');
        return { items: names.map((id) => ({ id, name: id.split('/').pop(), folder: id.split('/').slice(0, -1).join('/') || null })), mounts: [] };
      }
      if (cmd === 'reveal') return { id: args.id, ...entries[args.id] };
      if (cmd === 'list') return { items: [], mounts: [] };
      if (cmd === 'update' || cmd === 'create') { calls.push(args); return { id: args.id ?? args.name }; }
      throw new Error(`Unbekannter Befehl ${cmd}`);
    },
  };
}

for (const P of [PassProvider, GopassProvider]) {
  test(`${P.id}: decrypt on open lists names, reveals one entry, keeps a path user name out of the file`, async () => {
    const host = fakeHost({
      names: ['web/github.com', 'sites/example.org/ada', 'notes/idee'],
      entries: { 'web/github.com': { password: 'gh', username: 'octo', uris: ['https://github.com'], totp: 'otpauth://totp/x?secret=A' }, 'sites/example.org/ada': { password: 'ex', uris: [] } },
    });
    P.transport = host;
    const config = { id: 'a1', decrypt: 'open' };
    assert.equal((await P.login(config, {})).status, 'ok');
    const { items, folders } = await P.sync(config);
    assert.deepEqual(host.calls, ['status', 'names'], 'no list, no reveal');
    assert.deepEqual(folders.map((f) => f.id), ['notes', 'sites/example.org', 'web']);
    const [gh, ada, idee] = items;
    assert.ok(gh.lazy && gh.hasPassword && !gh.hasTotp && gh.usernameUnknown && gh.password === undefined);
    assert.ok(matchesUrl(gh, 'https://gist.github.com/') && matchesUrl(ada, 'https://example.org') && !matchesUrl(idee, 'https://example.org'));
    assert.deepEqual(gh.uris, [], 'path hints are not the entry\'s websites');
    const r = await P.reveal(config, {}, gh);
    assert.equal(host.calls.filter((c) => c === 'reveal').length, 1);
    assert.ok(r.username === 'octo' && r.password === 'gh' && r.hasTotp && r.usernameUnknown === false && !r._userFromPath);
    const full = { ...ada, ...(await P.reveal(config, {}, ada)), revealed: true };
    assert.ok(full.username === 'ada' && full._userFromPath);
    assert.equal(payloadOf({ ...full, password: 'neu' }, full).username, '', 'unchanged path user name not written');
    assert.equal(payloadOf({ ...full, username: 'bea' }, full).username, 'bea');
    const saved = await P.saveItem(config, {}, full, { ...full, password: 'neu' });
    assert.equal(host.calls.at(-1).username, '');
    assert.ok(saved.item.revealed && saved.item.username === 'ada' && saved.item.password === 'neu' && matchesUrl(saved.item, 'https://example.org'));
    // the full sync still reads everything and reveals nothing more
    assert.deepEqual(await P.reveal({ id: 'a2' }, {}, { id: 'x' }), {});
  });

  test(`${P.id}: an older host is reported as outdated, only when decrypting on open`, async () => {
    P.transport = fakeHost({ version: '2.0.0' });
    await assert.rejects(P.login({ id: 'a3', decrypt: 'open' }, {}), (e) => e.code === 'host_outdated' && /2\.0\.0.*2\.1\.0/.test(e.message));
    await assert.rejects(P.sync({ id: 'a3', decrypt: 'open' }), (e) => e.code === 'host_outdated');
    assert.equal((await P.login({ id: 'a3' }, {})).status, 'ok');
    assert.deepEqual((await P.sync({ id: 'a3' })).items, []);
  });
}
