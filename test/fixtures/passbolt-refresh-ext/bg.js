// Spike: can an extension keep a Passbolt JWT session (with its MFA proof) alive through /auth/jwt/refresh?
// Background script of a minimal test extension (Chrome: service worker, Firefox: event page). Not shipped.
const ext = globalThis.browser ?? globalThis.chrome;

async function req(base, path, { method = 'GET', token, body, headers = {} } = {}) {
  const res = await fetch(`${base}${path}`, {
    method, credentials: 'include', redirect: 'manual',
    headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* redirect or not JSON */ }
  return { status: res.status || res.type, message: json?.header?.message ?? null, body: json?.body ?? null };
}

const pick = (c) => c && { name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite, path: c.path, hostOnly: c.hostOnly, session: c.session, storeId: c.storeId, partitionKey: c.partitionKey ?? null, firstPartyDomain: c.firstPartyDomain ?? null };

const H = {
  async permissions(base) { return { cookies: await ext.permissions.contains({ permissions: ['cookies'] }), host: await ext.permissions.contains({ origins: [`${base}/*`] }) }; },
  /** The named cookies (cookies.getAll misses localhost cookies in Chromium, cookies.get finds them). */
  async cookies(base) {
    const out = {};
    for (const name of ['passbolt_mfa', 'refresh_token', 'csrfToken', 'passbolt_session']) out[name] = pick(await ext.cookies.get({ url: `${base}/`, name }));
    return out;
  },
  mfa: (base, at, code, remember) => req(base, '/mfa/verify/totp.json', { method: 'POST', token: at, body: { totp: code, ...(remember ? { remember: 1 } : {}) } }),
  check: (base, at) => req(base, '/resources.json?api-version=v2', { token: at }),
  /** Refresh with the token in the body, then take the new one out of the cookie jar and delete the cookie. */
  async refreshBody(base, userId, refreshToken, keepCookie = false) {
    const r = await req(base, '/auth/jwt/refresh.json', { method: 'POST', body: { user_id: userId, refresh_token: refreshToken } });
    const c = await ext.cookies.get({ url: `${base}/`, name: 'refresh_token' });
    let removed = null;
    if (c && !keepCookie) {
      removed = !!(await ext.cookies.remove({ url: `${base}/`, name: 'refresh_token', storeId: c.storeId }));
      removed = removed && !(await ext.cookies.get({ url: `${base}/`, name: 'refresh_token' }));
    }
    const at = r.body?.access_token ?? null;
    await ext.storage.session.set({ pb: { at, rt: c?.value ?? null } });
    return { status: r.status, message: r.message, at, rt: c?.value ?? null, cookie: pick(c), removed };
  },
  /** Refresh the way Passbolt's web app does: refresh_token cookie + CSRF token (cookie value echoed in a header). */
  async refreshCookie(base, withCsrf = true) {
    await req(base, '/auth/verify.json'); // hands out the csrfToken cookie (JWT POST responses delete it)
    const csrf = await ext.cookies.get({ url: `${base}/`, name: 'csrfToken' });
    const r = await req(base, '/auth/jwt/refresh.json', { method: 'POST', body: {}, headers: withCsrf && csrf ? { 'X-CSRF-Token': csrf.value } : {} });
    const c = await ext.cookies.get({ url: `${base}/`, name: 'refresh_token' });
    return { status: r.status, message: r.message, at: r.body?.access_token ?? null, rt: c?.value ?? null, csrf: pick(csrf) };
  },
  async mark() { globalThis.marker = 'alive'; return true; },
  async getMark() { return globalThis.marker ?? null; },
  async session() { return (await ext.storage.session.get('pb')).pb ?? null; },
  async removeCookie(base, name) { await ext.cookies.remove({ url: `${base}/`, name }); return !(await ext.cookies.get({ url: `${base}/`, name })); },
};
globalThis.H = H;
ext.runtime.onMessage.addListener((m, _s, reply) => {
  H[m.name](...m.args).then((r) => reply({ ok: r }), (e) => reply({ error: String(e?.message ?? e) }));
  return true;
});
