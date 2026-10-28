# Open-source software and licenses used

License texts: folder [`LICENSES/`](LICENSES/). OmniVault itself is licensed under the MPL-2.0 ([LICENSE](LICENSE)).
Principle: as little third-party software as possible. Third-party code is only added for cryptography, and only as an established open-source library.

## Included in the extension

All five files are kept as **separate, unmodified libraries** in `vendor/` and are imported at runtime,
not bundled into OmniVault's own code. They are built reproducibly from the upstream commits pinned in
[`vendor/sources.json`](vendor/sources.json)
(`vendor/fetch-sources.sh` verifies the commit hashes, `vendor/build.mjs` builds).

| File | Library | Version | License | Use |
|---|---|---|---|---|
| `vendor/openpgp.mjs` | [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) | 6.3.2 | LGPL-3.0-or-later ([text](LICENSES/openpgpjs-LGPL-3.0.txt), plus [GPL-3.0](LICENSES/GPL-3.0.txt)) | Passbolt: unlock keys, sign and encrypt the login challenge, decrypt secrets and metadata, verify signatures |
| ↳ included | [@noble/ciphers](https://github.com/paulmillr/noble-ciphers) | 1.3.0 | MIT ([text](LICENSES/noble-ciphers-MIT.txt)) | AES for OpenPGP.js |
| ↳ included | [@noble/curves](https://github.com/paulmillr/noble-curves) | 1.9.7 | MIT ([text](LICENSES/noble-curves-MIT.txt)) | Elliptic curves for OpenPGP.js |
| ↳ included | [@noble/hashes](https://github.com/paulmillr/noble-hashes) | 1.8.0 | MIT ([text](LICENSES/noble-hashes-MIT.txt)) | Hash functions for OpenPGP.js |
| ↳ included | [web-stream-tools](https://github.com/openpgpjs/web-stream-tools) | 0.3.1 | MIT ([text](LICENSES/web-stream-tools-MIT.txt)) | Stream processing in OpenPGP.js |
| ↳ included | [bn.js](https://github.com/indutny/bn.js) | 5.2.3 | MIT ([text](LICENSES/bn.js-MIT.txt)) | Big integers (fallback) in OpenPGP.js |
| ↳ included | [fflate](https://github.com/101arrowz/fflate) | 0.8.3 | MIT ([text](LICENSES/fflate-MIT.txt)) | Decompression in OpenPGP.js |
| ↳ included | [tweetnacl-js (OpenPGP.js fork)](https://github.com/openpgpjs/tweetnacl-js) | 1.0.4-2 | Unlicense ([text](LICENSES/tweetnacl-js-Unlicense.txt)) | Fallback for Curve25519 if WebCrypto does not provide it |
| ↳ included | argon2id (see below) | 1.0.1 | MIT | Argon2 S2K in OpenPGP.js |
| `vendor/argon2id.mjs` | [argon2id](https://github.com/openpgpjs/argon2id) (© Proton AG) | 1.0.1 | MIT ([text](LICENSES/argon2id-MIT.txt)); C core partly from the Argon2 reference implementation (CC0) | Bitwarden: key derivation for accounts with Argon2id |
| `vendor/argon2.mjs` | [Argon2 reference implementation](https://github.com/P-H-C/phc-winner-argon2) (C sources unmodified, compiled to WebAssembly without threads, minimal libc in `vendor/shims/argon2-ref`) | 20190702 | CC0-1.0 or Apache-2.0 ([text](LICENSES/argon2-ref-CC0-1.0.txt)) | KeePass files (.kdbx 4): key derivation with Argon2d and Argon2id |
| `vendor/noble-ciphers.mjs` | [@noble/ciphers](https://github.com/paulmillr/noble-ciphers), only `xchacha20poly1305`, `chacha20` and `salsa20` | 1.3.0 (same commit as in OpenPGP.js) | MIT ([text](LICENSES/noble-ciphers-MIT.txt)) | Bitwarden "Encryption V2": older envelopes with XChaCha20-Poly1305; KeePass files: ChaCha20 (content, protected values) and Salsa20 (protected values in KDBX 3.1) – WebCrypto provides neither |
| `vendor/tweetnacl.mjs` | [TweetNaCl.js](https://github.com/dchest/tweetnacl-js), `nacl-fast.js` unmodified | 1.0.3 | Unlicense ([text](LICENSES/tweetnacl-js-Unlicense.txt)) | KeePassXC: NaCl box (X25519, XSalsa20-Poly1305) for the browser protocol |

**Differences from the official build:** built with esbuild instead of rollup; the WebAssembly core of argon2id is
compiled with clang instead of Emscripten, only in the portable variant without SIMD. The SIMD variant is omitted; the library
then automatically uses the portable one. BZip2 decompression (`@openpgp/unbzip2-stream`) is left out because
version 2.1.0 is not published as source code; BZip2-compressed messages are rejected with an error
message. The source code of OpenPGP.js itself is unmodified.

**Source code (LGPL):** `vendor/sources/openpgpjs-6.3.2-source.tar.gz` and `vendor/sources/argon2id-1.0.1-source.tar.gz`
in OmniVault's source package; complete sources via the commits in `vendor/sources.json`.
**Replaceability (LGPL):** `vendor/openpgp.mjs` can be replaced with your own build of OpenPGP.js
(same ES module interface), e.g. when loading the unpacked extension.

Cryptographic primitives for Bitwarden (AES-CBC, HMAC, PBKDF2, RSA-OAEP, SHA, AES-GCM – also as the basis of
XAES-256-GCM), for KeePass files (AES-256-CBC, AES-KDF, SHA-256/512, HMAC-SHA-256), for TOTP and for passkeys (ECDSA P-256) come from the browser's WebCrypto API.

### Data

| File | Source | Date | License | Use |
|---|---|---|---|---|
| `vendor/public_suffix_list.dat` → `src/lib/psl-data.js` | [Public Suffix List](https://publicsuffix.org/) (Mozilla Foundation and contributors) | 2026-10-17 (SHA-256 `3d92f70d…25e5f33`, [publicsuffix/list](https://github.com/publicsuffix/list) commit `52b71b3`) | MPL-2.0 (like OmniVault, [LICENSE](LICENSE)) | Registrable domain for site matching and the rpId check for passkeys |
| `test/fixtures/psl-test.txt` | Test cases of the Public Suffix List (`tests/test_psl.txt`, same repository and same commit) | 2026-10-17 | Public domain (CC0) | test only: `test/psl.test.js` checks OmniVault's evaluation against all cases |

`src/lib/psl-data.js` contains only the rules of the list (comments removed, domains in ASCII form) and is
regenerated with `npm run psl:build`. Updating (before every release): `git clone --depth 1
https://github.com/publicsuffix/list`, copy `public_suffix_list.dat` to `vendor/` and `tests/test_psl.txt` to
`test/fixtures/psl-test.txt`, run `npm run psl:build` and `npm test`, and enter the date, hash and commit here.

## External programs (not included, only invoked)

The native host (`native/omnivault_host.py`) starts these programs as separate processes without a shell when the
user connects the respective provider. None of them is included in or linked with OmniVault; users install them
themselves.

| Program | License | Use |
|---|---|---|
| Python 3 | PSF-2.0 | Runtime of the host; only the standard library is used |
| [pass (zx2c4 password-store)](https://git.zx2c4.com/password-store/) | GPL-2.0-or-later | Provider "pass" |
| GnuPG (`gpg`) | GPL-3.0-or-later | Used by `pass` for decryption and encryption |
| [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) | proprietary | Provider 1Password |
| [lastpass-cli](https://github.com/lastpass/lastpass-cli) (`lpass`) | GPL-2.0-or-later | Provider LastPass |
| [KeePassXC](https://keepassxc.org) (`keepassxc-proxy`) | GPL-2.0 or GPL-3.0 | Provider KeePassXC: OmniVault registers its own native-messaging manifest that starts KeePassXC's proxy and speaks KeePassXC's documented browser protocol. Not started by the OmniVault host. |
| [gopass](https://github.com/gopasspw/gopass) (`gopass`) | MIT | Provider gopass (uses GnuPG like `pass`) |
| [Dashlane CLI](https://github.com/Dashlane/dashlane-cli) (`dcli`) | Apache-2.0 | Provider Dashlane (read only). Only the JSON output format was read from its source code; no code was copied. |
| [Proton Pass CLI](https://github.com/protonpass/pass-cli) (`pass-cli`) | GPL-3.0 | Provider Proton Pass (on hold). Only the JSON output format was read from the source code of `pass-cli` and `proton-pass-common`; no code was copied. |

## Downloaded for testing only (not redistributed)

| Program | License | Use |
|---|---|---|
| [Passbolt CE API](https://github.com/passbolt/passbolt_api) (v5.16.0) with its Composer dependencies | AGPL-3.0 (dependencies MIT and others) | Local test server for `npm run test:passbolt` (`test/passbolt-server.sh`), only on 127.0.0.1 with throwaway data and PostgreSQL. OmniVault only talks to it over HTTP. For this test instance, the script skips the PRO requirement for the PHP ldap extension. |
| [Vaultwarden](https://github.com/dani-garcia/vaultwarden), static Linux build from [zouzonghao/vaultwarden](https://github.com/zouzonghao/vaultwarden) (release `upstream-20261010-183532-64895524`, SHA-256 verified) | AGPL-3.0 | Local test server for `npm run test:vaultwarden`, only on 127.0.0.1 with throwaway data. The Vaultwarden project only publishes container images, hence this third-party build; `VAULTWARDEN_BIN` lets you use your own build. OmniVault only talks to the server over HTTP. |
| [Proton Pass CLI](https://github.com/protonpass/pass-cli) 2.3.1 (official release, SHA-256 verified) | GPL-3.0 | Cross-check of the commands, error messages and exit codes used by the host; not part of the repository. |

## For building and testing only (not in the extension)

| Package | Version | License | Use |
|---|---|---|---|
| [esbuild](https://github.com/evanw/esbuild) | 0.28 | MIT ([text](LICENSES/esbuild-MIT.txt)) | Bundles OmniVault's code and the vendor libraries |
| [Playwright](https://github.com/microsoft/playwright) | 1.56 | Apache-2.0 ([text](LICENSES/playwright-Apache-2.0.txt), [NOTICE](LICENSES/playwright-NOTICE.txt)) | Browser tests `test/e2e-*.mjs` |
| Chromium (via Playwright) | – | BSD-3-Clause and others | Test browser, not redistributed |
| clang / wasm-ld (LLVM, system program) | 18 | Apache-2.0 with LLVM exception | Compiles the argon2id WebAssembly core; not part of the extension |
| GnuPG (optional, system program) | 2.4 | GPL-3.0-or-later | Cross-check in `test/pgp.test.js`, generation of the test keys; only invoked as an external program |

## Specifications from which OmniVault implements its own code

| Specification | Use |
|---|---|
| RFC 5869 (HKDF) | Stretching the Bitwarden master key (HMAC from WebCrypto) |
| RFC 6238 / RFC 4226 | TOTP codes (HMAC from WebCrypto) |
| Bitwarden Security Whitepaper / client API | `src/providers/bitwarden/`: independent, no code from the Bitwarden clients |
| Passbolt API documentation | `src/providers/passbolt/`: independent, no code from the Passbolt extension |
