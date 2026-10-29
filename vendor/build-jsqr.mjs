// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Builds vendor/jsqr.mjs (Apache-2.0) from the jsQR sources pinned in vendor/sources.json: QR code decoding from
// RGBA pixels (no camera access, no network). The TypeScript sources are bundled unchanged as an ES module with a
// default export. Runs as part of vendor/build.mjs; alone (no clang needed): node vendor/build-jsqr.mjs
import * as esbuild from 'esbuild';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const s = JSON.parse(readFileSync(join(here, 'sources.json'), 'utf8')).jsqr;
const src = join(here, 'src/jsqr/src');
const version = JSON.parse(readFileSync(join(here, 'src/jsqr/package.json'), 'utf8')).version;
await esbuild.build({
  stdin: { contents: `import jsQR from ${JSON.stringify(join(src, 'index.ts'))};\nexport default jsQR;`, resolveDir: src, loader: 'js' },
  bundle: true, format: 'esm', platform: 'browser', target: ['chrome120', 'firefox128'], legalComments: 'inline', logLevel: 'warning',
  outfile: join(here, 'jsqr.mjs'),
  banner: { js: `/*! jsQR ${version} – Apache-2.0, see LICENSES/jsqr-Apache-2.0.txt. Unmodified sources, built from ${s.repo} ${s.commit.slice(0, 12)}. */` },
});
console.log('vendor/jsqr.mjs written');
