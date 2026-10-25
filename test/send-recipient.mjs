// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Opens a Send the way a recipient does – only the link (and the password) – and decrypts it independently with
// test/send-check.py (Python, `cryptography`). Shared by the simulated-server and the Vaultwarden tests.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CHECKER = fileURLToPath(new URL('./send-check.py', import.meta.url));
export const pythonChecker = spawnSync('python3', ['-c', 'import cryptography'], { encoding: 'utf8' }).status === 0;

/** Runs the Python checker: { name, text?, fileName?, file? (base64), passwordHash? }. */
export function pyCheck(input) {
  const r = spawnSync('python3', ['-I', CHECKER], { input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`send-check.py: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout);
}

const fragment = (link) => /#\/?(?:send\/)?([A-Za-z0-9_-]+)\/([A-Za-z0-9_-]+)\/?$/.exec(link);

/**
 * Recipient flow of current servers: identity grant `send_access` (client "send", the access id, optionally the
 * password hash) → token → POST /api/sends/access, for files then /api/sends/access/file/{id} → download URL.
 * `api` and `identity` are the server's base URLs. Returns { status, access?, file? (Uint8Array), error? }.
 */
export async function receiveSend({ api, identity }, link, { passwordHash } = {}) {
  const [, accessId] = fragment(link);
  const form = new URLSearchParams({ grant_type: 'send_access', client_id: 'send', scope: 'api.send.access', send_id: accessId });
  if (passwordHash) form.set('password_hash_b64', passwordHash);
  const tok = await fetch(`${identity}/connect/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form });
  const tokBody = await tok.json().catch(() => ({}));
  if (!tok.ok) return { status: tok.status, error: tokBody.send_access_error_type ?? tokBody.error ?? `HTTP ${tok.status}` };
  const auth = { Authorization: `Bearer ${tokBody.access_token}`, 'Content-Type': 'application/json' };
  const res = await fetch(`${api}/sends/access`, { method: 'POST', headers: auth, body: '{}' });
  if (!res.ok) return { status: res.status, error: `HTTP ${res.status}` };
  const access = await res.json();
  const fileMeta = access.file ?? access.File;
  if (!fileMeta) return { status: 200, access };
  const dl = await fetch(`${api}/sends/access/file/${fileMeta.id ?? fileMeta.Id}`, { method: 'POST', headers: auth, body: '{}' });
  if (!dl.ok) return { status: dl.status, access, error: `HTTP ${dl.status}` };
  const { url } = await dl.json();
  const bin = await fetch(new URL(url, api));
  return { status: 200, access, file: new Uint8Array(await bin.arrayBuffer()) };
}
