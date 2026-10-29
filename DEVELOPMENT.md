# OmniVault – Development

Browser extension (Chrome and Firefox, Manifest V3) that brings several password managers together in one interface:
search entries from all accounts, copy them and fill them in on websites (optionally with a button in the login field
and "Save login?"), create passkeys and sign in with them (in Bitwarden/Vaultwarden accounts, in the format of the
Bitwarden apps), copy, move and mirror entries between accounts, find duplicates and weak passwords, import exports
from other managers and export everything again.

| Provider | Connection | Status |
|---|---|---|
| Bitwarden (bitwarden.com, bitwarden.eu) | direct, decryption in the browser | read and write, tested against real Vaultwarden |
| Vaultwarden / self-hosted Bitwarden | direct | as above |
| Passbolt v4 and v5 | direct, OpenPGP in the browser | read, write, share; tested against real Passbolt CE 5.16 |
| HashiCorp Vault / OpenBao (KV v2) | direct via the HTTP API, token or userpass | read, write, trash; tested against real OpenBao 2.7.1 |
| pass (password-store) | local host → `pass` + GnuPG | read and write, tested against real pass |
| gopass | local host → `gopass` + GnuPG | read and write, stores as folders; tested against real gopass 1.17.4 |
| 1Password | local host → official `op` | read and write, tested against a simulated CLI |
| LastPass | local host → official `lpass` | read and write, tested against a simulated CLI |
| Dashlane | local host → official `dcli` | read only (dcli cannot write); tested against a simulated CLI, and without an account against real dcli 6.2642.0 |
| KeePassXC | KeePassXC's browser interface via `keepassxc-proxy` | read, create, edit, delete logins; tested against a simulated KeePassXC |
| Proton Pass | local host → official `pass-cli` | on hold: Proton only offers the CLI on paid plans |
| KeePass files, browsers and others | file import (KeePass database `.kdbx`, CSV, JSON, KeePass XML) | into any writable account |

- **Status by feature and provider:** [FEATURES.md](FEATURES.md)
- **Local host for pass, gopass, 1Password, LastPass, Dashlane, Proton:** [native/README.md](native/README.md)
- Third-party software and licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

OmniVault is an independent project and is not affiliated with Bitwarden Inc., Passbolt S.A., Proton AG, AgileBits Inc.
(1Password), LastPass US LP, Dashlane SAS, HashiCorp or the Linux Foundation (OpenBao). All trademarks mentioned belong to their owners.

## Building

```bash
npm install
npm run build        # → dist/chrome, dist/firefox
npm run package      # builds and packs dist/packages/: Chrome, Firefox and source package (reproducible) + SHA256SUMS
npm test             # unit tests: crypto test vectors, simulated servers and CLIs, import, tools
npm run test:cli     # pass and gopass (real, with gpg), 1Password, LastPass and Dashlane (simulated CLIs) via the host
npm run test:e2e     # extension in Chromium: popup as a tab, separate window (Playwright)
npm run test:popup   # real toolbar popup via CDP; visible instead of headless with `xvfb-run -a`
npm run test:proton  # Proton Pass: Chromium → native messaging → host → simulated pass-cli
npm run test:vaultwarden  # starts a local Vaultwarden and tests provider, tools, import, attachments, Send, organizations
                          # (moving, collections) and automatic sync across a service worker restart
                          # Send: links are opened as a recipient would and decrypted with test/send-check.py (Python, `cryptography`)
npm run test:vaultwarden-sso  # Vaultwarden with SSO against a local OIDC provider: sign-in, master password, renewal
npm run test:login        # Duo and SSO in a tab (simulated servers), with a real toolbar popup; visible with `xvfb-run -a`
npm run test:emergency    # Bitwarden emergency access (trusted contact, view only) against the simulated server;
                          # the same test runs against real Vaultwarden as part of test:vaultwarden
npm run test:passbolt     # sets up a local Passbolt CE (PostgreSQL) and tests provider and sharing against it
npm run test:openbao      # starts a local OpenBao (dev mode, port 8820) and tests provider and browser against it
npm run test:inline       # button in the login field, "Save login?", filling cards
npm run test:frames       # filling in embedded frames (two origins): question per pair of sites, note in the page,
                          # hidden frames, same-origin frames, list in the frame, "Save login?" from a frame, cards
npm run test:i18n         # languages: browser language, language picker, every view in every language + pseudo-locale
npm run test:passkeys     # passkeys: test page with server-side verification, OmniVault dialog, fallback to the browser,
                          # embedded frames (two origins, with and without Permissions Policy)
npm run test:argon2       # Argon2 in a worker: unlocking with 512 MiB (ARGON2_MIB=1024) and KeePass with 256 MiB while
                          # other messages are answered; clearing the clipboard during and after
npm run test:hibp         # data breach check: consent first, only 5-character prefixes (service simulated)
npm run test:shortcuts    # keyboard shortcuts and context menu with real X11 input (visible browser under Xvfb),
                          # also in an embedded login frame of another site; scans a TOTP QR code from the toolbar
                          # popup opened by the shortcut (activeTab)
npm run test:generator    # generator (password, passphrase, PIN, username; copying), username die in the editor,
                          # TOTP code copied after filling (clipboard read back, cleared), TOTP QR code read from a page
npm run test:firefox      # the same features in Firefox (WebDriver BiDi, see below)
```

The e2e scripts take the path to Playwright as their first argument if it is not installed in the project.
`test:popup` checks the fixed popup size; this only works with a visible browser (`xvfb-run -a npm run test:popup`).
On its first run, `test:vaultwarden` downloads a static Vaultwarden Linux binary (third-party build, hash verified, see
`test/vaultwarden-server.sh`); with `VAULTWARDEN_BIN=/path/to/vaultwarden` it uses your own. The GnuPG cross-checks
in `npm test` need an installed `gpg`, otherwise they are skipped; the pass tests run with
`OMNIVAULT_PASS_BIN=/path/to/pass`, the gopass tests with `OMNIVAULT_GOPASS_BIN=/path/to/gopass` or
`OMNIVAULT_GOPASS_DOWNLOAD=1` (downloads the pinned release 1.17.4, hash verified, see `test/gopass-bin.sh`). The Dashlane tests run with a simulated `dcli`; with
`OMNIVAULT_DCLI_DOWNLOAD=1` (or `OMNIVAULT_DCLI_BIN_REAL=/path/to/dcli`) one test additionally checks the real release 6.2642.0
without an account (hash verified, see `test/dcli-bin.sh`). `test:passbolt` needs PHP ≥ 8.2 (with `phpize`), Composer, git, a C compiler,
GnuPG with libgpgme and the PostgreSQL programs; package repositories, packagist.org and pecl.php.net are not needed. Passbolt CE
5.16.0 and its dependencies come from their Git sources (commits pinned: tag or `composer.lock`); if PHP lacks the
gnupg extension, the script builds php-gnupg 1.5.4 once against the existing libgpgme (headers generated from the Git sources of
libgpg-error 1.47 and gpgme 1.18.0, all commits verified). First run takes about 3–4 minutes, afterwards about 1.5 minutes
(details in `test/passbolt-server.sh`). On its first run, `test:openbao` downloads the official
OpenBao release 2.7.1 for Linux amd64 (hash verified, see `test/openbao-server.sh`); with `OPENBAO_BIN=/path/to/bao`
it uses your own.

**Firefox test** (`test/e2e-firefox.mjs`): Playwright's Firefox cannot load extensions, so the test starts a regular
Firefox ≥ 140 and controls it via WebDriver BiDi (`test/firefox-bidi.mjs`, no extra packages,
Node ≥ 22). The extension is installed temporarily (`webExtension.install`, no signature needed). With
`-remote-allow-system-access` the test also reaches the browser window itself: toolbar popup, sidebar,
keyboard shortcuts, context menu, browser console. On its first run, `npm run test:firefox` downloads Firefox 158 (third-party build
as an AppImage that contains Mozilla's official release archive unchanged; hash verified, see `test/firefox.sh`);
with `FIREFOX_BIN=/path/to/firefox` it uses your own. Headless is sufficient; under `xvfb-run -a` Firefox runs visibly,
and Ctrl+Shift+L is pressed as a real X11 key.

**Argon2 in a worker** (`src/lib/argon2.js`): Bitwarden Argon2id, the PIN derivation and KeePass Argon2 run in
a separate dedicated worker (`argon2-worker.js`) that is terminated after the derivation – which frees its WebAssembly
memory immediately. Firefox starts it directly from the event page, and so does the popup; Chrome's service worker cannot
start workers and uses the offscreen document instead (reasons `CLIPBOARD` and `WORKERS`). Chrome only allows one
offscreen document: `src/lib/offscreen.js` opens it for the first user (clearing the clipboard or a derivation),
shares it and closes it after the last one. Without workers (Node tests, old browsers) the computation runs directly as before.

Measured with `npm run test:argon2` (Chromium, 2 CPUs, Argon2id t=3, p=4; `ARGON2_MIB=1024`, default 512): a
derivation still takes about 0.7 s (64 MiB) to 8–9 s (1 GiB). Previously, other messages to the
background waited that long (up to 9.0 s at 1 GiB); now they are answered in the meantime (162 messages, median 5 ms,
at most 0.25 s while the offscreen document opens). 3 s after a 1 GiB derivation, browser memory used to be
1.1 GiB higher (the old WebAssembly instance was waiting for garbage collection); now it is 70 MiB higher. In
Firefox (256 MiB), another message used to wait up to 2.1 s, now at most 30 ms. A KeePass database with
256 MiB Argon2d used to freeze the popup for 2.8 s ("Decrypting …" stood still), now at most 25 ms.

Cryptography comes from established open-source libraries – OpenPGP.js (LGPL), argon2id (MIT), the
Argon2 reference implementation (CC0/Apache-2.0, for Argon2d in KeePass files) and, for XChaCha20-Poly1305, ChaCha20 and
Salsa20, @noble/ciphers (MIT), all as separate files in `vendor/` – and from WebCrypto. There are no other runtime dependencies. Rebuilding the libraries
(normally not necessary, the results are in the repository). QR codes for one-time codes are read with jsQR
(Apache-2.0, `vendor/jsqr.mjs`, loaded only when you scan); the tests draw their QR codes with a small encoder of their
own (`test/qr-encode.mjs`):

```bash
npm run vendor:fetch   # clones the sources at the commits from vendor/sources.json and verifies the hashes
npm run vendor:build   # builds all files in vendor/ (needs clang with the wasm32 target)
npm run wordlist:build # src/lib/eff-wordlist.js from vendor/eff_large_wordlist.txt (checks the SHA-256)
```

## Languages

The interface is available in German, English, Spanish, French, Italian, Portuguese (Brazil),
Chinese (Simplified) and Japanese. Without a setting, the browser language applies; Settings → Appearance →
Language selects another one.

**The source strings of the user interface are written in German, and the German text is the translation key.**
Every user-visible string in the code is German: `t('Konto hinzufügen')`, `tn(n, '{n} Eintrag', '{n} Einträge')`,
`mark('…')` for strings that are translated later, and the German text in the HTML pages (translated by walking the DOM).
These German strings must not be translated in place – changing one changes the key and breaks every translation of it.
The translations, including English, are in `src/i18n/locales/<language>.json`. `npm run i18n:keys` finds new or changed
strings; `npm test` reports missing, outdated and incorrectly translated entries. Everything else in the repository
(documentation, code comments, command-line output) is in English.

What quality assurance checks:

- **Completeness:** every string the code uses (collected from `t()`, `tn()`, `tx()`, the HTML pages and the
  manifest) exists in every language; nothing outdated is left behind.
- **Placeholders and plurals:** `{name}` etc. match; plural forms fit the rules of the language.
- **Leftovers:** no German words or umlauts in translations, no HTML; no German text in the code outside of
  `t()`.
- **Pseudo-locale** (`qps`, tests only): marks every translated string (⟦…⟧) and makes it 40 % longer. The
  browser test clicks through every view with it and reports every unmarked string (one that bypassed the translator) as well as
  truncated buttons, tabs and headings.
- **Every language in the browser:** the same views in all eight languages, without horizontal scrolling or truncated
  controls; plus a contact sheet of all screens (`index.html` in the screenshot folder) for review.
- **Language picker:** browser language without asking, keyboard navigation of the grid, immediate switching, messages from the
  background in the selected language, date format.

Tone, terminology and meaning cannot be checked automatically: the translations are machine-generated and should be
proofread by native speakers using the contact sheet before a release.

## Loading

- **Chrome, Edge, Brave:** `chrome://extensions` → Developer mode → "Load unpacked" → `dist/chrome`
- **Firefox (≥ 140):** `about:debugging#/runtime/this-firefox` → "Load Temporary Add-on" → `dist/firefox/manifest.json`

## Structure

```
src/
  background/        router, account store, autofill, tools (the only part that holds keys and plaintext)
  popup/             interface – receives secrets only on request (copy, reveal, fill)
    icons.js         custom line icons (SVG)
  providers/
    provider.js      interface for all providers
    native-host.js   shared native messaging transport and base class for CLI providers
    bitwarden/       API, crypto, provider (also covers Vaultwarden)
    passbolt/        JWT login, MFA, v4/v5 resources, folders, decrypting secrets on demand
    vault/           HashiCorp Vault / OpenBao: KV v2, token/userpass, check-and-set, trash via undelete
    pass/ gopass/ onepassword/ lastpass/ dashlane/ protonpass/   thin providers via the host
  content/inline.js  content script (opt-in, in all frames): button in the login field, "Save login?"
  inline/            list and save bar as extension pages in iframes
  lib/               TOTP (incl. otpauth:// check), URL matching, choosing the frame to fill (frames.js), generator (EFF wordlist in eff-wordlist.js), duplicates, import (incl. KeePass databases), export, password check, PIN lock
  i18n/              language selection, t()/tn()/tx(), translations (locales/*.json)
tools/i18n-extract.mjs  collects all strings for translation
tools/store-screenshots.mjs  screenshots (1280 × 800) from the web demo: `npm run build:demo`, then
                     `node tools/store-screenshots.mjs <output folder> [Playwright path] [en,de]`
native/              one host for all CLI providers (Python 3, standard library only), installer, self-test
vendor/              OpenPGP.js, argon2id, Argon2 reference, @noble/ciphers, TweetNaCl, jsQR (separate files), EFF wordlist,
                     source manifest, build scripts
```

## Security in brief

- Master passwords are never stored. Decrypted keys are kept only in `storage.session` (memory)
  and disappear on locking, after the configured inactivity period, on screen lock and when the browser is closed.
- The background page only answers messages from the extension's own pages; content scripts may only use
  a few calls, none of which returns secrets. Filling happens only on click, with a confirmation if the address does not match;
  the list in the login field only fills logins for the page.
- Filling in embedded frames: login forms (and the card forms of payment providers) often live in a frame of another
  origin. The background never takes a frame's origin from the page or the message sender: it injects a probe into
  every frame it may access (`scripting.executeScript` with `allFrames: true` – no `webNavigation` permission needed;
  frames without access are skipped by the browser) and reads `location.origin` in the extension's isolated world,
  which the page cannot modify. Each result carries the `frameId`, in Chrome also the `documentId`, which is the
  target when filling (a frame that navigated meanwhile is not filled); the fill function checks the origin once more.
  Rules (`src/lib/frames.js`):
  - a login goes only into a frame whose **own** origin matches it (registrable domain, as for pages) – never because
    the top page matches; "fill anyway" only reaches the top page's own origin. Order: frames with a password field
    before username-only ones, then the top frame, same origin, same site, other sites;
  - hidden frames are never filled: smaller than 40 × 14 px; the field does not intersect the viewport
    (IntersectionObserver: `display:none`, off-screen, clipped); in Chrome not visible according to IntersectionObserver
    v2 (transparent, covered, rotated or skewed – the frame's document is observed, so the page's own labels over a
    field do not count); no answer within 1 s (frames with `visibility:hidden` are not rendered). Firefox has no v2,
    but `runtime.getFrameId` lets the parent frame report its frame elements: hidden, below the minimum size or less
    than 80 % opaque. A frame partly covered by another element (e.g. a cookie banner) is not filled in Chrome; the
    message says the form is covered;
  - a frame of another site than the page (different registrable domain) needs a confirmation in the OmniVault window,
    naming both, once per pair of origins (remembered in `storage.local`, can be forgotten in the settings). The
    frame's origin proves that the form belongs to the login's site, but not that the user wants to sign in to that
    site inside this page: a page that embeds a (possibly vulnerable) page of another site should not get it filled
    with one key press. Keyboard shortcut and context menu skip such frames until confirmed and say so in the page.
    Frames of the same site (`login.example.com` in `www.example.com`) need no confirmation, like Bitwarden, which
    asks only for frames that do not match the item;
  - every fill into a frame of another origin shows a note in the page (text only, closed shadow root, nothing to
    click, so nothing to trick the user into);
  - cards and identities have no site: they go into every shown frame with matching fields (payment providers split
    card forms across frames, one per field), only on a click in the OmniVault window (shortcut, context menu and the
    list in the login field fill logins only), with the same confirmation for frames of other sites and the note;
  - the button and list in a login field run inside the frame and list the logins of the frame's own site, naming the
    page around it; no confirmation, since the user picked the login inside that frame, but the background checks the
    frame's origin and visibility before filling. "Save login?" from a frame stores the frame's origin and opens in the
    top page;
  - without site access, the browser's temporary access (`activeTab`) covers only the page's own origin; frames of
    other sites stay out of reach, and the message says so.
- Unlocking with a PIN: on locking, the sessions are sealed with a public key; the private key is
  opened only by the PIN (Argon2id). The seal is kept in memory only, and five failed attempts discard it. That is why
  4 to 12 digits are enough: without the seal the PIN is useless, and after a browser restart the
  master password is required again.
- Passkeys: the website learns nothing about accounts; it only gets its own passkey back. OmniVault takes the origin and rpId
  from the tab's address (rpId check with the Public Suffix List); private keys leave the
  background only encrypted, to the server, and never reach the interface. For locked accounts only
  salted hashes of the sites with passkeys are available.
- Passkeys in embedded frames: a cross-origin frame may only use WebAuthn if the page above it allows this via
  Permissions Policy (`allow="publickey-credentials-get"` or `-create`). OmniVault must not take the page script's
  word for this permission, since the frame itself can manipulate it. That is why the background checks every
  frame request itself: via `scripting.executeScript` in the isolated world of exactly that frame
  (`document.featurePolicy.allowsFeature`, `location.ancestorOrigins`, and when creating in cross-origin frames
  `navigator.userActivation.isActive`); the page cannot modify this world. The frame's origin must match
  `sender.origin`/`sender.url`, the top-level origin must match the tab's address, all ancestors must be
  secure origins, and the rpId must match the frame's origin as usual. The dialog always opens in the
  top-level frame and names the frame and the page; `clientDataJSON` contains `crossOrigin: true` and `topOrigin`, so
  the website itself can check where it was embedded. Conditional requests from frames go to the browser.
  Firefox offers neither `featurePolicy` nor `ancestorOrigins`: there, frame requests still go to the browser.
- OmniVault does not offer the passkey extensions PRF and largeBlob (on creation `prf.enabled: false`,
  `largeBlob.supported: false`; `largeBlob.support: "required"` goes to the browser). The Bitwarden format
  `login.fido2Credentials` has no field for a PRF secret or a blob (checked against the source code of the
  Bitwarden server and clients, October 2026); a custom field would be lost when editing in the Bitwarden apps,
  and the passkey would then silently return different PRF values – for websites that encrypt data with them,
  that would mean data loss.
- Self-hosted servers: host permission is only requested when connecting.
- Passbolt: the private key is stored passphrase-protected in `storage.local` (as in the official extension);
  the server key is remembered on the first login; if it changes, sign-in is aborted. When editing and
  sharing, secrets are encrypted with the public keys that the server names for the readers.
- CLI providers: secrets are passed to the programs via stdin, never on the command line (exception: editing in
  Proton Pass, see native/README.md).

## License

MPL-2.0 ([LICENSE](LICENSE)), © Die OmniVault-Mitwirkenden.
