// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Dedicated worker: computes one Argon2 hash and is then terminated by its creator (see src/lib/argon2.js).
import loadArgon2id from '../../vendor/argon2id.mjs';
import loadArgon2 from '../../vendor/argon2.mjs';

const LOAD = { argon2id: loadArgon2id, argon2: loadArgon2 };

self.onmessage = async ({ data: { lib, params } }) => {
  try {
    const out = (await LOAD[lib]())(params);
    self.postMessage({ out }, [out.buffer]);
  } catch (e) {
    self.postMessage({ error: e.message });
  }
};
