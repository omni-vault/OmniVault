// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Passbolt's refresh endpoint, for accounts with a second factor (optional `cookies` permission).
//
// Only POST /auth/jwt/refresh moves the second-factor proof (passbolt_mfa cookie, sent along) to the new access
// token; a new sign-in with the GPG challenge would ask for the code again. Passbolt answers with the new access
// token in the body, but hands out the rotated refresh token only as a Secure HttpOnly cookie `refresh_token` of its
// own host. OmniVault reads exactly that cookie right after the answer, keeps the value with the session in
// storage.session (memory) and deletes the cookie from the browser. With the cookie in the jar Passbolt would also
// demand a CSRF token for the next refresh.
//
// A refresh token is used once: it is marked as used in the stored session before the request goes out. If the
// worker stops after the server rotated the token but before the session was stored, the cookie is still there and
// the session says so (`refreshPending`): the next renewal takes the token from the cookie. storage.local remembers
// (without any token) which servers had a renewal under way, so a cookie left behind by a browser crash is removed
// on the next start.

const NAME = 'refresh_token';
const PENDING = 'passboltRefreshPending';

/** The browser APIs (replaceable in tests). */
export const env = { ext: globalThis.browser ?? globalThis.chrome };

const isLoopback = (host) => ['localhost', '127.0.0.1', '[::1]'].includes(host);

/**
 * Can the browser keep Passbolt's refresh cookie for this server? It is always `Secure`: both browsers keep it from
 * https servers, Chrome also from http://localhost; Firefox drops it on any http server.
 */
export function cookieRefreshPossible(server, { firefox = !!env.ext?.runtime?.getBrowserInfo } = {}) {
  let u;
  try { u = new URL(server); } catch { return false; }
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && isLoopback(u.hostname) && !firefox;
}

export async function hasCookiePermission() {
  const { ext } = env;
  if (!ext?.cookies?.get || !ext.permissions?.contains) return false;
  try { return await ext.permissions.contains({ permissions: ['cookies'] }); } catch { return false; }
}

async function getCookie(url) {
  try { return await env.ext.cookies.get({ url, name: NAME }); } catch { return null; }
}
async function removeCookie(url, c) {
  try { await env.ext.cookies.remove({ url, name: NAME, ...(c?.storeId ? { storeId: c.storeId } : {}) }); } catch { /* gone */ }
}
/** Puts back a cookie that was not ours (Passbolt's own web app or extension in this profile). */
async function restoreCookie(url, c) {
  try {
    await env.ext.cookies.set({
      url, name: NAME, value: c.value, path: c.path, secure: c.secure, httpOnly: c.httpOnly,
      ...(c.sameSite && c.sameSite !== 'unspecified' ? { sameSite: c.sameSite } : {}),
      ...(c.expirationDate ? { expirationDate: c.expirationDate } : {}), ...(c.storeId ? { storeId: c.storeId } : {}),
    });
  } catch (e) { console.warn('OmniVault: cannot put back the Passbolt cookie', e); }
}

async function markPending(origin, on) {
  const local = env.ext?.storage?.local;
  if (!local) return;
  try {
    const { [PENDING]: all = {} } = await local.get(PENDING);
    if (on) all[origin] = Date.now(); else delete all[origin];
    await local.set({ [PENDING]: all });
  } catch { /* best effort */ }
}

/** On browser start: removes refresh cookies left behind by a renewal that a crash cut off. */
export async function cleanupRefreshCookies() {
  const local = env.ext?.storage?.local;
  if (!local) return 0;
  let all;
  try { ({ [PENDING]: all = {} } = await local.get(PENDING)); } catch { return 0; }
  let n = 0;
  if (await hasCookiePermission()) {
    for (const origin of Object.keys(all)) {
      const url = `${origin}/`;
      const c = await getCookie(url);
      if (c) { await removeCookie(url, c); n++; }
    }
  }
  await local.remove(PENDING).catch(() => {});
  return n;
}

/**
 * Renews through /auth/jwt/refresh. Returns the renewed session, or null when this way is not available (no
 * permission, no refresh token, server without https) or failed – the caller then signs in with the challenge.
 * @param {(path, opts) => Promise<object>} request  POST helper (credentials included, so passbolt_mfa goes along)
 * @param {(s) => Promise<void>} save  stores an intermediate session at once
 */
export async function cookieRefresh({ base, userId, session, request, save, jwtExpiry }) {
  if (!session.mfa || !cookieRefreshPossible(base) || !(await hasCookiePermission())) return null;
  const url = `${base}/`;
  const origin = new URL(base).origin;
  let s = session;
  let token = s.refreshToken;
  let foreign = null;
  const left = await getCookie(url);
  if (left) {
    if (s.refreshPending) token = left.value; // rotated by a renewal of ours that was cut off
    else foreign = left;
    await removeCookie(url, left);
  }
  try {
    for (let attempt = 0; attempt < 2 && token; attempt++) {
      // used from now on, whatever happens to the request
      s = { ...s, refreshToken: null, refreshPending: Date.now() };
      await save(s);
      await markPending(origin, true);
      let body = null;
      try {
        body = await request('/auth/jwt/refresh.json', { method: 'POST', body: { user_id: userId, refresh_token: token } });
      } catch (e) {
        console.warn('OmniVault: Passbolt refresh failed', e.message);
      }
      const fresh = await getCookie(url);
      if (fresh) await removeCookie(url, fresh);
      if (body?.access_token) {
        const next = {
          ...s, accessToken: body.access_token, expiresAt: jwtExpiry(body.access_token), obtainedAt: Date.now(),
          refreshToken: fresh?.value ?? null, refreshPending: undefined,
        };
        await save(next);
        await markPending(origin, false);
        return next;
      }
      // the server may have rotated the token although the answer got lost: then the cookie has the new one
      token = fresh?.value ?? null;
      s = { ...s, refreshToken: token, refreshPending: undefined };
      await save(s);
      await markPending(origin, false);
    }
    return null;
  } finally {
    if (foreign && !(await getCookie(url))) await restoreCookie(url, foreign);
  }
}
