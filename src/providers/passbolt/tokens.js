// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// One access token per Passbolt account at a time. Passbolt binds a second-factor proof (passbolt_mfa cookie) to the
// access token; once a renewal has moved it to the new token, a single request that still carries the old one (even
// one that has not expired yet) makes the server void the proof for good. So every request of an account goes
// through its keeper: a renewal waits until the requests in flight are answered, requests that start meanwhile wait
// for the renewal and then use the new token, and the old token is never sent again.

/** Renew this long before the token expires (at most a quarter of its lifetime, for servers with very short tokens). */
const MARGIN = 30_000;

export class TokenKeeper {
  #active = 0;
  #idle = [];
  #renewing = null;

  /**
   * @param {object} session  { accessToken, expiresAt, obtainedAt?, sid?, gen? , … }
   * @param {object} o
   * @param {(session, save) => Promise<object>} o.renew  returns the renewed session; `save(s)` stores an
   *   intermediate state at once (e.g. a refresh token marked as used before it is sent)
   * @param {(session) => Promise<void>} [o.persist]  keeps the newest session (storage.session)
   * @param {() => number} [o.now]
   */
  constructor(session, { renew, persist, now = Date.now } = {}) {
    this.session = session;
    this.sid = session.sid;
    this.renewFn = renew;
    this.persist = persist;
    this.now = now;
  }

  /** In flight right now (for tests). */
  get active() { return this.#active; }
  get renewing() { return !!this.#renewing; }

  due() {
    const { expiresAt, obtainedAt, refreshPending } = this.session;
    // a renewal was cut off (worker stopped): the server may have moved the proof to a token we never saw
    if (refreshPending) return true;
    if (expiresAt == null) return false;
    const margin = obtainedAt != null ? Math.min(MARGIN, (expiresAt - obtainedAt) / 4) : MARGIN;
    return this.now() > expiresAt - margin;
  }

  /**
   * Runs `fn(accessToken)` (one request) with the current token. Renews first when the token is about to expire;
   * when the request is refused as expired (`retryIf`), renews and repeats it once with the new token.
   */
  async run(fn, { retryIf = () => false } = {}) {
    for (let renewed = false; ;) {
      if (this.#renewing) { await this.#renewing; continue; }
      if (!renewed && this.due()) { renewed = true; await this.renew(this.session.accessToken); continue; }
      break;
    }
    const token = this.session.accessToken;
    this.#active++;
    let error;
    try {
      return await fn(token);
    } catch (e) {
      error = e;
    } finally {
      this.#release();
    }
    if (!retryIf(error)) throw error;
    await this.renew(token);
    if (this.session.accessToken === token) throw error;
    return this.run(fn);
  }

  /**
   * Renews the token unless that already happened since `usedToken` was handed out. One renewal at a time; it
   * starts only when no request with the old token is in flight any more.
   */
  renew(usedToken = this.session.accessToken) {
    if (this.#renewing) return this.#renewing;
    if (usedToken !== this.session.accessToken) return Promise.resolve();
    this.#renewing = (async () => {
      await this.#whenIdle();
      // a locked account must not use up a refresh token any more (a sealed copy of the session may still hold it)
      const save = async (s) => {
        if (this.closed) throw Object.assign(new Error('locked'), { code: 'session_expired' });
        this.session = s;
        await this.#store(s);
      };
      const next = await this.renewFn(this.session, save);
      await save({ ...next, gen: (this.session.gen ?? 0) + 1 });
    })().finally(() => { this.#renewing = null; });
    return this.#renewing;
  }

  async #store(s) {
    try { await this.persist?.(s); } catch (e) { console.warn('OmniVault: cannot store the renewed Passbolt session', e); }
  }

  #release() {
    this.#active--;
    if (this.#active === 0) for (const wake of this.#idle.splice(0)) wake();
  }

  #whenIdle() {
    return this.#active === 0 ? Promise.resolve() : new Promise((r) => { this.#idle.push(r); });
  }
}

const keepers = new Map(); // account → TokenKeeper

/**
 * The keeper of an account. A session of another sign-in (new `sid`) replaces it; a caller holding an older copy of
 * the same session (lower `gen`) gets the keeper with the newest token.
 */
export function keeperFor(key, session, opts) {
  const k = keepers.get(key);
  if (k && k.sid === session.sid && (session.gen ?? 0) <= (k.session.gen ?? 0)) {
    Object.assign(k, { renewFn: opts.renew, persist: opts.persist });
    return k;
  }
  const fresh = new TokenKeeper(session, opts);
  keepers.set(key, fresh);
  return fresh;
}

export function forgetKeeper(key) {
  const k = keepers.get(key);
  if (k) k.closed = true;
  keepers.delete(key);
}
export function forgetAllKeepers() { for (const k of keepers.keys()) forgetKeeper(k); }
