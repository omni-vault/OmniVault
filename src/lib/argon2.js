// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Runs Argon2 off the main thread, so the background (and the popup) keep answering while a derivation with up to
// 1 GiB of memory takes several seconds:
// - where dedicated workers exist (Firefox's background page, popup, offscreen document): in a worker of its own,
// - in Chrome's service worker (no dedicated workers there): in a worker started by the offscreen document,
// - otherwise (Node tests, old browsers): directly, as before.
// Each worker computes one derivation and is terminated afterwards, which frees its WebAssembly memory at once.
import { ext } from './browser.js';
import { b64, fromB64 } from './bytes.js';
import { withOffscreen } from './offscreen.js';

export const WORKER_FILE = 'argon2-worker.js';

export class Unavailable extends Error {}

/** Uint8Array fields as base64, because Chrome's runtime messages are JSON. */
export const pack = (params) => Object.fromEntries(Object.entries(params).map(([k, v]) => [k, v instanceof Uint8Array ? { b64: b64(v) } : v]));
export const unpack = (params) => Object.fromEntries(Object.entries(params).map(([k, v]) => [k, typeof v?.b64 === 'string' ? fromB64(v.b64) : v]));

/** One derivation in a new dedicated worker; rejects with Unavailable if the worker cannot start. */
export function inWorker(WorkerClass, url, lib, params) {
  return new Promise((resolve, reject) => {
    let w;
    try { w = new WorkerClass(url, { type: 'module' }); } catch { reject(new Unavailable('no worker')); return; }
    w.onmessage = ({ data }) => {
      w.terminate();
      if (data?.out instanceof Uint8Array) resolve(data.out);
      else reject(new Error(data?.error ?? 'Argon2 failed'));
    };
    w.onerror = (e) => {
      e?.preventDefault?.();
      w.terminate();
      reject(new Unavailable(e?.message ?? 'worker failed'));
    };
    w.postMessage({ lib, params });
  });
}

/**
 * Argon2 hash with `params` ({ password, salt, passes, memorySize, parallelism, tagLength, … }) by the library `lib`
 * ('argon2id' = vendor/argon2id.mjs, 'argon2' = vendor/argon2.mjs). `direct` loads the hash function for the fallback.
 * `env` is for tests only.
 */
export async function argon2(lib, params, direct, { Worker: WorkerClass = globalThis.Worker, api = ext } = {}) {
  try {
    if (typeof WorkerClass === 'function' && api?.runtime?.getURL) {
      return await inWorker(WorkerClass, api.runtime.getURL(WORKER_FILE), lib, params);
    }
    if (api?.offscreen?.createDocument) {
      const r = await withOffscreen(() => api.runtime.sendMessage({ target: 'offscreen', type: 'argon2', lib, params: pack(params) }), api);
      if (typeof r?.out === 'string') return fromB64(r.out);
      if (r?.error) throw new Error(r.error);
      throw new Unavailable('no answer from the offscreen document');
    }
  } catch (e) {
    if (!(e instanceof Unavailable)) throw e;
    console.warn('OmniVault: Argon2 running without a worker', e.message);
  }
  return (await direct())(params);
}
