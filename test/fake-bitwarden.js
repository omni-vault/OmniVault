// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Simulated Bitwarden/Vaultwarden server state built with the real client crypto.
import { createHash } from 'node:crypto';
import { b64 } from '../src/lib/bytes.js';
import {
  deriveMasterKey, encryptSym, masterPasswordHash, splitKey, stretchMasterKey,
} from '../src/providers/bitwarden/crypto.js';

export const EMAIL = 'alice@example.org';
export const PASSWORD = 'Tr0ub4dor&3';

/** Returns handle(path, {method, headers, body}) → {status, body}. */
export const USER_ID = '7b2c9a51-0000-4f00-9000-0000000000a1';
export const API_CLIENT_ID = 'user.0c3e5d8e-1111-4ad0-9a8f-aaaaaaaaaaaa';
export const API_CLIENT_SECRET = 'Xo7sh2kLq9ZtAPIsecret';

/** Private key of the passkey in the "Shop" item (P-256, PKCS #8, base64url), so tests can check its signatures. */
export const SHOP_PASSKEY_PKCS8 = 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8vikK4kvONUuo9NrZhZEdd0XyTxGI8tlWPJtMIEdy72hRANCAASjXiPTXcahHFuI2QEnubExE2rZQDYkagJfwr26qVGc4idAIRQ3hFJfvtjb7dmodxCSaaF3shRnYN662gwZv0h5';

async function encryptedPasskey(key, fields) {
  const out = { CreationDate: '2026-02-03T04:05:06.000Z' };
  for (const [k, v] of Object.entries(fields)) out[k] = await encryptSym(v, key);
  return out;
}

const b64u = (s) => Buffer.from(s).toString('base64url');
const page = (title, body) => ({ status: 200, html: `<!doctype html><meta charset="utf-8"><title>${title}</title><body>${body}</body>` });
const redirect = (location) => ({ status: 302, headers: { Location: location }, body: {} });

/**
 * Options beyond the vault:
 * - origin: the server's own address (web vault, as configured in DOMAIN); the connector pages live there
 * - duo: 2 (personal) or 6 (organization) – Duo Universal Prompt as the only second factor; duoOrigin is Duo's host;
 *   duoCodeParam 'duo_code' like Duo with use_duo_code_attribute (Bitwarden's library), else 'code' (Vaultwarden)
 * - sso: { identifier } – Enterprise SSO for that organization identifier; ssoTwoFactor: TOTP after the sign-in
 * - masterPassword: false | 'tde' | 'keyconnector' – an account without master password (SSO only)
 * - sendAzure: file Sends go to a (simulated) Azure Blob URL like on bitwarden.com; sendPremium: false refuses file Sends
 */
export async function fakeBitwarden({
  kdf, twoFactor = false, loginUri = 'https://github.com/login', extraItems = 0, collections = false, collectionsV2 = true,
  origin = 'https://vault.example.org', duo = null, duoOrigin = 'https://api-1234abcd.duosecurity.com', duoCodeParam = 'code',
  sso = null, ssoTwoFactor = false, masterPassword = true, sendAzure = false, sendPremium = true,
}) {
  const mk = await deriveMasterKey(PASSWORD, EMAIL, kdf);
  const hash = await masterPasswordHash(mk, PASSWORD);
  const userKeyBytes = crypto.getRandomValues(new Uint8Array(64));
  const userKey = splitKey(userKeyBytes);

  const rsa = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
    true, ['encrypt', 'decrypt']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', rsa.privateKey));
  const orgKeyBytes = crypto.getRandomValues(new Uint8Array(64));
  const orgKey = splitKey(orgKeyBytes);
  const orgKeyEnc = `4.${b64(new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsa.publicKey, orgKeyBytes)))}`;
  const itemKeyBytes = crypto.getRandomValues(new Uint8Array(64));
  const itemKey = splitKey(itemKeyBytes);

  const findCipherInit = (id) => sync.Ciphers.find((c) => (c.Id ?? c.id) === id);
  const sync = {
    Profile: { // PascalCase on purpose (Vaultwarden/older servers)
      Id: USER_ID,
      PrivateKey: await encryptSym(pkcs8, userKey),
      Organizations: [{ Id: 'org1', Key: orgKeyEnc }],
    },
    Folders: [{ Id: 'f1', Name: await encryptSym('Arbeit', userKey) }],
    Ciphers: [
      {
        Id: 'c1', Type: 1, FolderId: 'f1', Name: await encryptSym('GitHub', userKey),
        Login: {
          Username: await encryptSym('alice', userKey),
          Password: await encryptSym('gh-pass', userKey),
          Totp: await encryptSym('JBSWY3DPEHPK3PXP', userKey),
          Uris: [{ Uri: await encryptSym(loginUri, userKey) }],
        },
      },
      { // per-item key
        id: 'c2', type: 1, key: await encryptSym(itemKeyBytes, userKey),
        name: await encryptSym('Bank', itemKey),
        login: { username: await encryptSym('a123', itemKey), password: await encryptSym('bank-pass', itemKey), uris: [] },
      },
      { // organization item
        id: 'c3', type: 2, organizationId: 'org1', name: await encryptSym('Team-Notiz', orgKey),
        notes: await encryptSym('Nur für das Team', orgKey),
      },
      { id: 'c4', type: 1, deletedDate: '2026-01-01', name: await encryptSym('Gelöscht', userKey) },
    ],
  };
  // Optional filler entries with very long unbroken strings (layout stress test).
  for (let n = 0; n < extraItems; n++) {
    sync.Ciphers.push({
      Id: `x${n}`, Type: 1, Name: await encryptSym(`Langer-Eintrag-${n}-${'x'.repeat(80)}`, userKey),
      Login: {
        Username: await encryptSym(`benutzer.mit.sehr.langem.namen.${n}@${'sub.'.repeat(12)}example.org`, userKey),
        Password: await encryptSym(`pw${n}`, userKey),
        Uris: [{ Uri: await encryptSym(`https://${'very-long-subdomain-'.repeat(6)}${n}.example.net/path`, userKey) }],
      },
    });
  }
  // More item types: card, identity, SSH key, custom fields, password history, a passkey (must survive edits)
  sync.Ciphers.push(
    {
      Id: 'c5', Type: 3, Name: await encryptSym('Visa privat', userKey),
      Card: {
        CardholderName: await encryptSym('Alice Example', userKey), Brand: await encryptSym('Visa', userKey),
        Number: await encryptSym('4111 1111 1111 1111', userKey), ExpMonth: await encryptSym('7', userKey),
        ExpYear: await encryptSym('2029', userKey), Code: await encryptSym('123', userKey),
      },
    },
    {
      Id: 'c6', Type: 4, Name: await encryptSym('Ausweis', userKey),
      Identity: { FirstName: await encryptSym('Alice', userKey), LastName: await encryptSym('Example', userKey), Email: await encryptSym('alice@example.org', userKey), PassportNumber: await encryptSym('C01X00T47', userKey) },
    },
    {
      Id: 'c7', Type: 5, Name: await encryptSym('Server-Schlüssel', userKey),
      SshKey: { PrivateKey: await encryptSym('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----', userKey), PublicKey: await encryptSym('ssh-ed25519 AAAAC3Nz alice', userKey), KeyFingerprint: await encryptSym('SHA256:abc123', userKey) },
    },
    {
      Id: 'c8', Type: 1, Name: await encryptSym('Shop', userKey), RevisionDate: '2026-01-01T00:00:00Z',
      Login: {
        Username: await encryptSym('alice', userKey), Password: await encryptSym('shop-old', userKey),
        Uris: [{ Uri: await encryptSym('https://shop.example.com', userKey), Match: 1 }],
        // a passkey as the Bitwarden apps store it (all fields encrypted except CreationDate)
        Fido2Credentials: [await encryptedPasskey(userKey, {
          CredentialId: 'c0ffee00-1111-4222-8333-444455556666', KeyType: 'public-key', KeyAlgorithm: 'ECDSA', KeyCurve: 'P-256',
          KeyValue: SHOP_PASSKEY_PKCS8, RpId: 'shop.example.com', UserHandle: 'YWxpY2UtaWQ', UserName: 'alice',
          Counter: '0', RpName: 'Shop', UserDisplayName: 'Alice', Discoverable: 'true',
        })],
      },
      Fields: [
        { Type: 0, Name: await encryptSym('Kundennummer', userKey), Value: await encryptSym('K-4711', userKey) },
        { Type: 1, Name: await encryptSym('PIN', userKey), Value: await encryptSym('9876', userKey) },
        { Type: 2, Name: await encryptSym('Newsletter', userKey), Value: await encryptSym('true', userKey) },
        { Type: 3, Name: await encryptSym('Login-Name', userKey), Value: null, LinkedId: 100 },
      ],
      PasswordHistory: [{ Password: await encryptSym('shop-older', userKey), LastUsedDate: '2025-06-01T10:00:00Z' }],
    },
  );
  if (collections) {
    // organization collections: "Team" (writable, holds c3), "Vertrieb" (writable), "Archiv" (read only)
    sync.Collections = [
      { Id: 'col1', OrganizationId: 'org1', Name: await encryptSym('Team', orgKey), ReadOnly: false },
      { Id: 'col2', OrganizationId: 'org1', Name: await encryptSym('Vertrieb', orgKey), ReadOnly: false },
      { Id: 'col3', OrganizationId: 'org1', Name: await encryptSym('Archiv', orgKey), ReadOnly: true },
    ];
    findCipherInit('c3').CollectionIds = ['col1', 'col3'];
  }
  const folderSeq = { n: 0 };
  void folderSeq;
  const protectedKey = await encryptSym(userKeyBytes, await stretchMasterKey(mk));
  const validTokens = new Set(['Bearer AT1', 'Bearer AT2', 'Bearer ATK']);
  const requests = [];
  const findCipher = (id) => sync.Ciphers.find((c) => (c.Id ?? c.id) === id);

  // Duo: state → { email, code } as the server keeps it; SSO: state → { challenge, redirectUri, code }
  const duoStates = new Map();
  const ssoAuth = new Map();
  const flow = { duoUrls: [], ssoAuthorize: [], tokenForms: [] };
  const sends = createSendStore({ sendAzure, sendPremium });
  const header = (headers, name) => headers[name] ?? headers[name.toLowerCase()] ?? Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1];

  function duoChallenge(headers) {
    // like the servers: Duo's address with a signed request; the return address is fixed by the server
    const client = header(headers, 'Bitwarden-Client-Name') || 'web';
    const state = `st${crypto.randomUUID().replace(/-/g, '')}`;
    duoStates.set(state, { email: EMAIL });
    const redirectUri = `${origin}/duo-redirect-connector.html?client=${client}`;
    const claims = { response_type: 'code', scope: 'openid', client_id: 'DIXXXXXXXXXXXXXXXXXX', redirect_uri: redirectUri, state, duo_uname: EMAIL, nonce: 'n1' };
    const jwt = `${b64u(JSON.stringify({ alg: 'HS512', typ: 'JWT' }))}.${b64u(JSON.stringify(claims))}.c2lnbmF0dXJl`;
    const authUrl = `${duoOrigin}/oauth/v1/authorize?response_type=code&client_id=DIXXXXXXXXXXXXXXXXXX&request=${jwt}`;
    flow.duoUrls.push(authUrl);
    return { status: 400, body: { error: 'invalid_grant', error_description: 'Two factor required.', TwoFactorProviders: [String(duo)], TwoFactorProviders2: { [duo]: { Host: new URL(duoOrigin).host, AuthUrl: authUrl } } } };
  }
  const duoValid = (f) => {
    if (f.get('twoFactorProvider') !== String(duo)) return false;
    const [code, state] = (f.get('twoFactorToken') ?? '').split('|');
    const s = duoStates.get(state);
    if (!s?.code || s.code !== code) return false;
    duoStates.delete(state); // single use
    return true;
  };

  function tokenResponse() {
    const kdfJson = { KdfType: kdf.kdf, Iterations: kdf.kdfIterations, Memory: kdf.kdfMemory ?? null, Parallelism: kdf.kdfParallelism ?? null };
    if (masterPassword !== true) {
      return {
        access_token: 'AT1', refresh_token: 'RT1', expires_in: 3600,
        UserDecryptionOptions: {
          HasMasterPassword: false,
          ...(masterPassword === 'tde' ? { TrustedDeviceOption: { HasAdminApproval: true, HasLoginApprovingDevice: false, HasManageResetPasswordPermission: false } } : {}),
          ...(masterPassword === 'keyconnector' ? { KeyConnectorOption: { KeyConnectorUrl: 'https://key-connector.example.org' } } : {}),
        },
      };
    }
    return {
      access_token: 'AT1', refresh_token: 'RT1', expires_in: 3600, Key: protectedKey,
      Kdf: kdf.kdf, KdfIterations: kdf.kdfIterations, KdfMemory: kdf.kdfMemory, KdfParallelism: kdf.kdfParallelism,
      UserDecryptionOptions: { HasMasterPassword: true, MasterPasswordUnlock: { Kdf: kdfJson, MasterKeyEncryptedUserKey: protectedKey, Salt: EMAIL } },
    };
  }

  const handle = function handle(path, { method = 'GET', headers = {}, body, query = new URLSearchParams() } = {}) {
    const auth = headers.Authorization ?? headers.authorization;
    // web vault pages the servers send the browser back to (the real ones hand over to the app; here just a page)
    if (path === '/duo-redirect-connector.html' || path === '/sso-connector.html') return page('Connector', '<p>Weiterleitung …</p>');
    // Duo's prompt (on Duo's host in reality): a button that confirms and redirects back with code and state
    if (path === '/oauth/v1/authorize') {
      let claims;
      try { claims = JSON.parse(Buffer.from(query.get('request').split('.')[1], 'base64url').toString()); } catch { return { status: 400, body: { error: 'invalid_request' } }; }
      return page('Duo', `<h1>Duo</h1><p>${claims.duo_uname}</p><a id="duo-approve" href="/duo/approve?state=${claims.state}&redirect=${encodeURIComponent(claims.redirect_uri)}">Approve</a>`);
    }
    if (path === '/duo/approve') {
      const s = duoStates.get(query.get('state'));
      if (!s) return { status: 400, body: { error: 'unknown state' } };
      s.code = `duo${Math.random().toString(36).slice(2, 10)}`;
      const back = new URL(query.get('redirect'));
      back.searchParams.set(duoCodeParam, s.code);
      back.searchParams.set('state', query.get('state'));
      return redirect(back.href);
    }
    // SSO: prevalidate, authorize (fixed return address for client "browser"), the identity provider, token exchange
    if (path.endsWith('/sso/prevalidate')) {
      if (!sso || query.get('domainHint')?.toLowerCase() !== sso.identifier.toLowerCase()) return { status: 400, body: { message: 'Organization not found or SSO configuration not enabled' } };
      return { status: 200, body: { token: 'SSOTOKEN1' } };
    }
    if (path.endsWith('/connect/authorize')) {
      flow.ssoAuthorize.push(Object.fromEntries(query));
      if (!sso) return { status: 400, body: { error: 'SSO sign-in is not available' } };
      if (query.get('client_id') !== 'browser') return { status: 400, body: { error: 'invalid_client' } };
      if (query.get('redirect_uri') !== `${origin}/sso-connector.html`) return { status: 400, body: { error: 'invalid_request', error_description: 'Invalid redirect_uri' } };
      if (query.get('code_challenge_method') !== 'S256' || !query.get('code_challenge')) return { status: 400, body: { error: 'Unsupported code challenge method' } };
      if (query.get('domain_hint') !== sso.identifier || query.get('ssoToken') !== 'SSOTOKEN1') return { status: 400, body: { error: 'No domain_hint provided' } };
      const state = query.get('state');
      ssoAuth.set(state, { challenge: query.get('code_challenge'), redirectUri: query.get('redirect_uri') });
      return redirect(`/idp/login?state=${encodeURIComponent(state)}`);
    }
    if (path === '/idp/login') return page('Identity provider', `<h1>Company sign-in</h1><a id="idp-approve" href="/idp/approve?state=${encodeURIComponent(query.get('state'))}">Sign in</a>`);
    if (path === '/idp/approve') {
      const a = ssoAuth.get(query.get('state'));
      if (!a) return { status: 400, body: { error: 'unknown state' } };
      a.code = `sso${Math.random().toString(36).slice(2, 10)}`;
      const back = new URL(a.redirectUri);
      back.searchParams.set('code', a.code);
      back.searchParams.set('state', query.get('state'));
      return redirect(back.href);
    }
    if (path.endsWith('/accounts/prelogin') && method === 'POST') {
      return { status: 200, body: { Kdf: kdf.kdf, KdfIterations: kdf.kdfIterations, KdfMemory: kdf.kdfMemory, KdfParallelism: kdf.kdfParallelism } };
    }
    if (path.endsWith('/connect/token') && new URLSearchParams(body).get('grant_type') === 'send_access') {
      return sends.grant(new URLSearchParams(body));
    }
    const recipient = sends.recipient(path, { method, auth, body });
    if (recipient) return recipient;
    if (path.endsWith('/connect/token')) {
      const f = new URLSearchParams(body);
      flow.tokenForms.push(Object.fromEntries(f));
      if (f.get('grant_type') === 'authorization_code') {
        const a = [...ssoAuth.values()].find((x) => x.code && x.code === f.get('code'));
        if (!a) return { status: 400, body: { error: 'invalid_grant', error_description: 'Invalid code cannot retrieve sso auth' } };
        if (f.get('redirect_uri') !== a.redirectUri) return { status: 400, body: { error: 'invalid_grant', error_description: 'redirect_uri mismatch' } };
        const challenge = createHash('sha256').update(f.get('code_verifier') ?? '').digest('base64url');
        if (challenge !== a.challenge) return { status: 400, body: { error: 'invalid_grant', error_description: 'PKCE verification failed' } };
        if (!f.get('deviceIdentifier') || !f.get('deviceName') || !f.get('deviceType')) return { status: 400, body: { error: 'invalid_request' } };
        if (ssoTwoFactor && f.get('twoFactorToken') !== '123456') return { status: 400, body: { error: 'invalid_grant', TwoFactorProviders2: { 0: null } } };
        if (duo && !duoValid(f)) return duoChallenge(headers);
        return { status: 200, body: tokenResponse() };
      }
      if (f.get('grant_type') === 'client_credentials') {
        if (f.get('client_id') !== API_CLIENT_ID || f.get('client_secret') !== API_CLIENT_SECRET) return { status: 400, body: { error: 'invalid_client' } };
        return { status: 200, body: { access_token: 'ATK', expires_in: 3600, Key: protectedKey, Kdf: kdf.kdf, KdfIterations: kdf.kdfIterations } };
      }
      if (f.get('grant_type') === 'refresh_token') return { status: 200, body: { access_token: 'AT2', expires_in: 3600 } };
      if (f.get('password') !== hash) return { status: 400, body: { error: 'invalid_grant', ErrorModel: { Message: 'Username or password is incorrect. Try again.' } } };
      if (twoFactor && f.get('twoFactorToken') !== '123456') return { status: 400, body: { error: 'invalid_grant', TwoFactorProviders2: { 0: null, 7: {} } } };
      if (duo && !duoValid(f)) return duoChallenge(headers);
      if (duo) return { status: 200, body: tokenResponse() };
      return { status: 200, body: { access_token: 'AT1', refresh_token: 'RT1', expires_in: 3600, Key: protectedKey } };
    }
    if (path.includes('/sync')) {
      return validTokens.has(auth) ? { status: 200, body: { ...sync, Sends: sends.list() } } : { status: 401, body: {} };
    }
    if (!validTokens.has(auth)) return { status: 401, body: {} };
    const json = body && typeof body === 'string' ? JSON.parse(body) : null;
    requests.push({ method, path, json });
    const owner = sends.owner(path, { method, json, body });
    if (owner) return owner;
    let m;
    if (path.endsWith('/api/accounts/profile') && method === 'GET') return { status: 200, body: { Id: USER_ID } };
    // like current Vaultwarden: writes must name the user the cipher is encrypted for
    if (/\/api\/ciphers(\/[^/]+)?$/.test(path) && (method === 'POST' || method === 'PUT') && json?.encryptedFor !== USER_ID) {
      return { status: 422, body: { message: 'missing field `encryptedFor`' } };
    }
    if (path.endsWith('/api/ciphers') && method === 'POST') {
      const c = { ...json, id: `n${requests.length}`, revisionDate: new Date().toISOString(), edit: true };
      delete c.lastKnownRevisionDate;
      sync.Ciphers.push(c);
      return { status: 200, body: c };
    }
    if ((m = /\/api\/ciphers\/([^/]+)\/(collections|collections_v2)$/.exec(path)) && method === 'PUT' && collections) {
      if (m[2] === 'collections_v2' && !collectionsV2) return { status: 404, body: {} };
      const c = findCipher(m[1]);
      if (!c?.organizationId && !c?.OrganizationId) return { status: 400, body: { message: 'Cipher is not owned by an organization' } };
      // like Vaultwarden: the request is compared with the collections the user may write to; read-only ones stay,
      // and naming one that would change is refused
      const current = c.CollectionIds ?? c.collectionIds ?? [];
      const ro = new Set(sync.Collections.filter((x) => x.ReadOnly).map((x) => x.Id));
      const before = new Set(current.filter((x) => !ro.has(x)));
      const after = new Set(json.collectionIds);
      for (const id of [...before, ...after].filter((x) => before.has(x) !== after.has(x))) {
        const col = sync.Collections.find((x) => x.Id === id);
        if (!col) return { status: 400, body: { message: 'Invalid collection ID provided' } };
        if (col.ReadOnly) return { status: 400, body: { message: 'No rights to modify the collection' } };
      }
      delete c.collectionIds;
      c.CollectionIds = [...current.filter((x) => ro.has(x)), ...after];
      c.RevisionDate = new Date().toISOString();
      return { status: 200, body: m[2] === 'collections_v2' ? { object: 'optionalCipherDetails', unavailable: false, cipher: c } : c };
    }
    if ((m = /\/api\/ciphers\/([^/]+)\/partial$/.exec(path)) && method === 'PUT') {
      const c = findCipher(m[1]);
      if (!c) return { status: 404, body: {} };
      if ('Favorite' in c) c.Favorite = json.favorite; else c.favorite = json.favorite;
      return { status: 200, body: c };
    }
    if ((m = /\/api\/ciphers\/([^/]+)\/delete$/.exec(path)) && method === 'PUT') {
      const c = findCipher(m[1]);
      if (!c) return { status: 404, body: {} };
      c.DeletedDate = new Date().toISOString();
      return { status: 200, body: {} };
    }
    if ((m = /\/api\/ciphers\/([^/]+)$/.exec(path)) && method === 'PUT') {
      const i = sync.Ciphers.findIndex((c) => (c.Id ?? c.id) === m[1]);
      if (i < 0) return { status: 404, body: {} };
      const old = sync.Ciphers[i];
      const rev = old.RevisionDate ?? old.revisionDate;
      if (json.lastKnownRevisionDate && rev && json.lastKnownRevisionDate !== rev) {
        return { status: 400, body: { message: 'The cipher you are updating is out of date.' } };
      }
      const c = { ...json, id: m[1], revisionDate: new Date().toISOString(), edit: true };
      delete c.lastKnownRevisionDate;
      sync.Ciphers[i] = c;
      return { status: 200, body: c };
    }
    return { status: 404, body: {} };
  };
  handle.requests = requests;
  handle.flow = flow;
  handle.sync = sync;
  handle.sends = sends;
  return handle;
}

/**
 * Send endpoints like Bitwarden's server and Vaultwarden: the owner's CRUD under /api/sends, file upload direct or
 * via Azure, and the recipient side (send_access grant on identity, then /api/sends/access with that token).
 * The store keeps everything as the client sent it, so tests can decrypt it independently.
 */
function createSendStore({ sendAzure, sendPremium }) {
  const all = []; // { ...request, id, accessId, password (hash of the client hash), accessCount, file: { id, fileName, size } }
  const files = new Map(); // fileId → bytes
  const tokens = new Map(); // send access token → send id
  let n = 0;
  const now = () => new Date().toISOString();
  const hashOf = (clientHash) => createHash('sha256').update(`server:${clientHash}`).digest('base64');
  const view = (x) => ({
    object: 'send', id: x.id, accessId: x.accessId, type: x.type, authType: x.password ? 1 : 2, name: x.name, notes: x.notes, key: x.key,
    maxAccessCount: x.maxAccessCount, accessCount: x.accessCount, revisionDate: x.revisionDate, expirationDate: x.expirationDate,
    deletionDate: x.deletionDate, password: x.password, disabled: x.disabled, hideEmail: x.hideEmail,
    ...(x.type === 0 ? { text: x.text, file: null } : { file: x.file, text: null }),
  });
  const bad = (message) => ({ status: 400, body: { message, validationErrors: null, object: 'error' } });
  const accessible = (x) => x && !x.disabled && (!x.maxAccessCount || x.accessCount < x.maxAccessCount)
    && (!x.expirationDate || new Date(x.expirationDate) > new Date()) && new Date(x.deletionDate) > new Date() && (x.type === 0 || files.has(x.file.id));
  function validate(json, creating) {
    if (!json.key || !json.deletionDate || json.disabled == null) return bad('The Key field is required.');
    const del = new Date(json.deletionDate);
    if (del <= new Date(Date.now() + 60_000)) return bad('You cannot have a Send with a deletion date in the past. Adjust the deletion date and try again.');
    if (del > new Date(Date.now() + 31 * 86400_000)) return bad('You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.');
    if (json.expirationDate && new Date(json.expirationDate) > del) return bad('You cannot have a Send with an expiration date greater than the deletion date. Adjust the expiration date and try again.');
    if (creating && json.expirationDate && new Date(json.expirationDate) <= new Date(Date.now() + 60_000)) return bad('You cannot create a Send that is already expired. Adjust the expiration date and try again.');
    return null;
  }
  function create(json) {
    const id = `5e0d0000-0000-4000-8000-${String(++n).padStart(12, '0')}`;
    const x = { ...json, id, accessId: Buffer.from(id.replace(/-/g, ''), 'hex').toString('base64url'), accessCount: 0, revisionDate: now(), password: json.password ? hashOf(json.password) : null };
    delete x.fileLength;
    all.push(x);
    return x;
  }
  return {
    all, files,
    list: () => all.map(view),
    owner(path, { method, json, body }) {
      let m;
      if (path.endsWith('/api/sends') && method === 'GET') return { status: 200, body: { object: 'list', data: all.map(view), continuationToken: null } };
      if (path.endsWith('/api/sends') && method === 'POST') {
        if (json.type !== 0) return bad('File sends should use /api/sends/file/v2');
        const e = validate(json, true);
        return e ?? { status: 200, body: view(create(json)) };
      }
      if (path.endsWith('/api/sends/file/v2') && method === 'POST') {
        if (json.type !== 1) return bad('Invalid content.');
        if (!json.fileLength) return bad('Invalid content. File size hint is required.');
        if (!sendPremium) return bad('You must have premium status to use file Sends.');
        const e = validate(json, true);
        if (e) return e;
        const x = create(json);
        x.file = { id: `f${n}${'0'.repeat(30)}`.slice(0, 32), fileName: json.file.fileName, size: String(json.fileLength), sizeName: `${json.fileLength} Bytes` };
        const url = sendAzure ? `https://bwsends.blob.core.windows.net/sendfiles/${x.id}/${x.file.id}?sv=2024-08-04&sig=fake` : `/sends/${x.id}/file/${x.file.id}`;
        return { status: 200, body: { object: 'send-fileUpload', fileUploadType: sendAzure ? 1 : 0, url, sendResponse: view(x) } };
      }
      if ((m = /\/api\/sends\/([^/]+)\/file\/([^/]+)$/.exec(path)) && method === 'POST') {
        const x = all.find((y) => y.id === m[1]);
        if (!x || x.file?.id !== m[2] || sendAzure) return bad('Send not found. Unable to save the file.');
        if (body?.fileName !== x.file.fileName) return bad('Send file name does not match.');
        if (body.bytes.length !== Number(x.file.size)) return bad('Send file size does not match.');
        files.set(x.file.id, body.bytes);
        return { status: 200, body: null };
      }
      if ((m = /\/api\/sends\/([^/]+)\/remove-password$/.exec(path)) && method === 'PUT') {
        const x = all.find((y) => y.id === m[1]);
        if (!x) return { status: 404, body: { message: 'Send not found' } };
        x.password = null;
        x.revisionDate = now();
        return { status: 200, body: view(x) };
      }
      if ((m = /\/api\/sends\/([^/]+)$/.exec(path))) {
        const i = all.findIndex((y) => y.id === m[1]);
        if (i < 0) return { status: 404, body: { message: 'Send not found' } };
        const x = all[i];
        if (method === 'GET') return { status: 200, body: view(x) };
        if (method === 'DELETE') { all.splice(i, 1); if (x.file) files.delete(x.file.id); return { status: 200, body: null }; }
        if (method === 'PUT') {
          if (json.type !== x.type) return bad("Sends can't change type");
          const e = validate(json, false);
          if (e) return e;
          Object.assign(x, {
            name: json.name, notes: json.notes, key: json.key, maxAccessCount: json.maxAccessCount, expirationDate: json.expirationDate,
            deletionDate: json.deletionDate, disabled: json.disabled, hideEmail: json.hideEmail, revisionDate: now(),
            ...(x.type === 0 ? { text: json.text } : {}),
            ...(json.password ? { password: hashOf(json.password) } : {}),
          });
          return { status: 200, body: view(x) };
        }
      }
      return null;
    },
    /** identity: grant_type=send_access → a short-lived token for one Send. */
    grant(f) {
      const x = all.find((y) => y.accessId === f.get('send_id'));
      if (f.get('client_id') !== 'send') return { status: 400, body: { error: 'invalid_client' } };
      if (!accessible(x)) return { status: 400, body: { error: 'invalid_grant', send_access_error_type: 'send_id_invalid' } };
      if (x.password) {
        if (!f.get('password_hash_b64')) return { status: 400, body: { error: 'invalid_request', send_access_error_type: 'password_hash_b64_required' } };
        if (hashOf(f.get('password_hash_b64')) !== x.password) return { status: 400, body: { error: 'invalid_grant', send_access_error_type: 'password_hash_b64_invalid' } };
      }
      const token = `SEND${tokens.size + 1}`;
      tokens.set(token, x.id);
      return { status: 200, body: { access_token: token, expires_in: 120, token_type: 'Bearer', scope: 'api.send.access' } };
    },
    recipient(path, { method, auth, body }) {
      let m;
      if ((m = /\/sendfiles\/[^/]+\/([^/?]+)$/.exec(path)) && method === 'PUT' && sendAzure) {
        files.set(m[1], new Uint8Array(body));
        return { status: 201, body: null };
      }
      if ((m = /\/sendfiles\/[^/]+\/([^/?]+)$/.exec(path)) && method === 'GET') {
        return files.has(m[1]) ? { status: 200, raw: files.get(m[1]) } : { status: 404, body: {} };
      }
      if (!/\/api\/sends\/access(\/file\/[^/]+)?$/.test(path) || method !== 'POST') return null;
      const x = all.find((y) => y.id === tokens.get(String(auth ?? '').replace(/^Bearer /, '')));
      if (!accessible(x)) return { status: 404, body: { message: 'Send does not exist or is no longer available' } };
      if ((m = /\/file\/([^/]+)$/.exec(path))) {
        if (x.file?.id !== m[1]) return { status: 404, body: {} };
        x.accessCount++;
        return { status: 200, body: { object: 'send-fileDownload', id: m[1], url: `https://bwsends.blob.core.windows.net/sendfiles/${x.id}/${m[1]}` } };
      }
      if (x.type === 0) x.accessCount++;
      return {
        status: 200,
        body: { object: 'send-access', id: x.accessId, type: x.type, name: x.name, file: x.file ?? null, text: x.text ?? null, expirationDate: x.expirationDate, creatorIdentifier: x.hideEmail ? null : EMAIL },
      };
    },
  };
}
