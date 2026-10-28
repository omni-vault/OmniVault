# Native host: pass, gopass, 1Password, LastPass, Dashlane and Proton Pass

Some password managers have no network API open to third-party clients, but they do have an official command-line program.
OmniVault talks to these programs through **one** small local host via *native messaging*. The host
(`omnivault_host.py`, name `org.omnivault.host`) only needs Python 3 (≥ 3.8) with the standard library. It contains
no code from the providers and ships none of their programs: you install and unlock the program yourself.

```
Browser extension ⇄ (native messaging, JSON) ⇄ omnivault_host.py ⇄ pass | gopass | op | lpass | dcli | pass-cli
```

| Provider | Program | Sign-in | Module |
|---|---|---|---|
| pass | `pass` (password-store) + `gpg` | `pass init <gpg-id>`; the gpg agent unlocks the key | `ov_pass.py` |
| gopass | `gopass` (≥ 1.15, with gpg) + `gpg` | `gopass setup` or `gopass init`; the gpg agent unlocks the key | `ov_gopass.py` |
| 1Password | `op` (1Password CLI 2.x) | `op signin`, desktop app integration or service account | `ov_onepassword.py` |
| LastPass | `lpass` (lastpass-cli) | `lpass login <email>` | `ov_lastpass.py` |
| Dashlane (read only) | `dcli` (Dashlane CLI ≥ 6) | `dcli sync` (email, second factor, master password in the terminal) | `ov_dashlane.py` |
| Proton Pass | `pass-cli` (≥ 2.3 recommended) | `pass-cli login` | `ov_proton.py` |

Shared building blocks (message format, program invocation, ID validation) are in `ov_common.py`.

**Proton Pass is on hold.** Proton currently only offers `pass-cli` on paid plans; other
accounts get "Your account is not yet allowed to use our CLI". The provider is kept and will work
as soon as the CLI is enabled for your account.

## 1. Install the program and sign in

Install the program following the provider's instructions and sign in in a terminal. Check the
sign-in with `pass ls`, `gopass ls`, `op whoami`, `lpass status`, `dcli status` or `pass-cli info`.

**Dashlane:** `dcli` is available as a ready-made binary for Linux, macOS and Windows (x64) at
[github.com/Dashlane/dashlane-cli/releases](https://github.com/Dashlane/dashlane-cli/releases) or via Homebrew
(`brew install dashlane/tap/dashlane-cli`); instructions: [dashlane.github.io/dashlane-cli](https://dashlane.github.io/dashlane-cli/install).
Run `dcli sync` once in a terminal: dcli asks for your email, verification code and master password and stores
the master password encrypted, with its key in the system keychain (on Linux e.g. via libsecret).
Afterwards, `dcli status` must show `Logged in: Yes` and `Locked: No`. If storing is turned off
(`dcli configure save-master-password false`) or `dcli lock` has locked the vault, dcli asks for the master password
on every call; OmniVault then reports the vault as locked and never enters a password itself. Biometrics
(`dcli configure user-presence --method biometrics`, macOS only) is untested.

OmniVault never sees your master password. The session belongs to the respective program; `op signout`, `lpass logout`,
`dcli logout` or `pass-cli logout` end it.

## 2. Register the host

The extension's Chrome ID is shown at `chrome://extensions` (developer mode).

```bash
python3 install.py --chrome-id <EXTENSION-ID>   # Chrome, Chromium, Brave, Edge and Firefox
python3 install.py --firefox-only               # Firefox only
python3 install.py --uninstall                  # remove everything again
```

The script copies the host to `~/.local/share/omnivault` (Linux), `~/Library/Application Support/OmniVault`
(macOS) or `%LOCALAPPDATA%\OmniVault` (Windows) and registers it for every browser it finds: on Linux and
macOS in the browser's `NativeMessagingHosts` folder, on Windows in the registry under `HKCU`. It also removes hosts of older
OmniVault versions (`org.omnivault.proton`, `org.omnivault.cli`).

The first line of the host points to the Python that ran `install.py`, because browsers start hosts without the shell's
`PATH`. The host looks for the programs in `PATH` and additionally in `/opt/homebrew/bin`, `/usr/local/bin`,
`~/.local/bin` and `~/bin`. If a program is somewhere else, set its location with an environment variable:

| Program | Variable |
|---|---|
| `pass` / `gpg` | `OMNIVAULT_PASS_BIN` / `OMNIVAULT_GPG_BIN` |
| `gopass` | `OMNIVAULT_GOPASS_BIN` |
| `op` | `OMNIVAULT_OP_BIN` |
| `lpass` | `OMNIVAULT_LPASS_BIN` |
| `dcli` | `OMNIVAULT_DCLI_BIN` |
| `pass-cli` | `OMNIVAULT_PASS_CLI` |

## 3. Connect in OmniVault

*New* (plus icon at the top right) → *Add account* → choose the provider → *Connect*. The browser asks once
for the permission "Communicate with cooperating native applications".

## What works

| Feature | pass | gopass | 1Password | LastPass | Proton Pass | Dashlane |
|---|---|---|---|---|---|---|
| Read (username, password, URL, notes) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (logins, secure notes, secrets) |
| Read cards, identities, SSH keys | – | – | ✅ (cards, identities) | – | ✅ | – (secrets as notes) |
| Create and edit cards, identities | – | – | ✅ (from the `op` template; address read only) | – | – | – |
| Download attachments (up to 30 MB) | – | – | ✅ (`op read`, `op document get`) | ✅ (`lpass show --attach`) | ✅ (`item attachment download`) | – |
| Password history | – | – | if `op` outputs it | – | – | – |
| Read TOTP | ✅ (`otpauth://` line) | ✅ (`otpauth://` line) | ✅ | – | ✅ | ✅ (`otpSecret` or `otpUrl`) |
| Create, edit, delete login / note | ✅ (logins only) | ✅ (logins only) | ✅ (deleting moves to "Recently Deleted") | ✅ | ✅ (deleting moves to the trash) | – (dcli can only read) |
| Read and edit custom fields | ✅ (`Name: value` lines) | ✅ (`Name: value` lines) | ✅ (other fields and sections are preserved) | – | read only | read only (email, second login) |
| Folder / group / vault | ✅ (path, create new) | ✅ (path and mounted stores; moving with `gopass mv`) | ✅ (vaults: move, create new) | ✅ (group, create new) | ✅ (vault, moving from 2.3) | – |
| Load secrets only when needed | – (loads during sync) | – (loads during sync) | ✅ | ✅ | ✅ | 🟡 (dcli always returns them; the host discards them in the list) |
| Favorites | stored in OmniVault | stored in OmniVault | ✅ (`--favorite`) | stored in OmniVault | stored in OmniVault | stored in OmniVault |
| Change TOTP | ✅ | ✅ | ✅ | – | – | – |
| Conflict detection (a change made elsewhere is not overwritten) | – | – | ✅ (`version`) | ✅ (`last_modified_gmt`) | ✅ (`modify_time`) | – (read only) |

pass and gopass have no separate note type: every entry starts with a password line. gopass: the host only calls
`gopass ls --flat`, `gopass mounts`, `gopass show -f -n`, `gopass insert -f` (content via stdin), `gopass mv -f`
and `gopass rm -f`; mounted stores (`gopass mounts`) appear as top-level folders, and moving
between them uses `gopass mv`. gopass notifications and reminders are turned off for these calls.

Dashlane: the host only calls `dcli --version`, `dcli status`, `dcli sync` and `dcli password|note|secret --output json`
(with the filter `id={…}` when an entry is opened), always with `/dev/null` as input. dcli always outputs these lists
with all secrets; for the list, the host keeps only the title, username or email, URL and whether there is a
TOTP, and reads the password, note and TOTP secret only when you open an entry – again via dcli; nothing
is cached. IDs must have the form `{UUID}`. Dashlane "secrets" (arbitrary text, e.g. an
SSH key) appear as notes; dcli does not output IDs (`dcli id`), folders and attachments, or not as a list.
dcli itself syncs with the server at most once an hour; `dcli sync` forces it.

## Security

- When creating and editing, secrets are passed to the programs via **stdin**, never on the command line:
  `pass insert -m` and `gopass insert -f` read the content, `op item create -` and `op item edit <id>` read JSON (when editing, the
  complete item with the changed values, because the template replaces the item),
  `lpass add/edit --non-interactive` reads `Field: value` lines. This keeps them out of the process list.
- 1Password cards and identities start from the template of the installed `op` (`op item template get`), so that
  field IDs, types and sections match 1Password. **Passkeys:** according to the 1Password documentation, `op item edit`
  with a JSON template overwrites an existing passkey; `op` does not show passkeys. Edit logins with a passkey in the
  1Password app instead (the editor points this out).
- The program writes attachments into a freshly created private folder (permissions 0700) under a fixed
  file name; the host reads the file, deletes the folder and passes on at most 30 MB. Large files are sent to the browser in
  several messages. Commands: `op read --out-file <file> op://<vault ID>/<item ID>/<file ID>`,
  `op document get <ID> --vault <vault ID> --out-file <file>`, `lpass show --attach=att-<ID> --quiet <ID>` (via
  stdout, with a size limit) and `pass-cli item attachment download … --output <file>`.
- **Exception Proton Pass:** `pass-cli item update` only accepts new values as the argument `--field name=value`. During
  this short call, another program **of the same user** can see the changed field in the process list.
  Other users cannot see it on common systems. When creating, password, TOTP and note are passed via stdin.
- For each provider, the host only passes on commands from a fixed list, checks every ID against a strict pattern
  (no absolute paths, no `..`) and starts the programs without a shell.
- The programs never get the connection to the browser as input, but `/dev/null` or the data that the
  host supplies itself. If a program prompts for something, the command fails with an understandable message instead
  of hanging.
- For `pass-cli`, the host sets `PROTON_PASS_NO_UPDATE_CHECK=1`; update it in the terminal as usual.
- Only the OmniVault extension may start the host (`allowed_origins` or `allowed_extensions` in the manifest).
- Responses over 1 MB (browser limit) are sent in parts.

## KeePassXC

KeePassXC does not need the OmniVault host. OmniVault speaks KeePassXC's own publicly documented
browser protocol ([keepassxc-protocol.md](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md))
via the bundled program `keepassxc-proxy`. The messages are encrypted with a NaCl box
(TweetNaCl.js); the proxy only relays them.

```
Browser extension ⇄ (native messaging, NaCl box) ⇄ keepassxc-proxy ⇄ KeePassXC
```

1. In KeePassXC, turn on the integration under *Settings → Browser Integration*. Under *Advanced*, turn on the
   option "Allow keepassxc-proxy to list all entries …", otherwise OmniVault cannot show a list.
2. Register the manifest: `python3 install.py --chrome-id <EXTENSION-ID> --keepassxc`. The script looks for
   `keepassxc-proxy` (Linux `/usr/bin`, Snap `/snap/bin/keepassxc.proxy`, macOS in the application bundle, Windows in the
   installation folder); otherwise pass `--keepassxc-proxy PATH`. It creates a manifest under OmniVault's own
   name `org.omnivault.keepassxc`. KeePassXC's own manifest is left untouched: it only admits the official
   extensions and is rewritten by KeePassXC itself.
3. In OmniVault, *Add account → KeePassXC → Connect*. KeePassXC asks whether to accept the connection and
   for a name for it (e.g. "OmniVault"). You can remove this association at any time in KeePassXC under *Database →
   Database Settings → Browser Integration*.

**Flatpak:** a manifest must point to an executable file. Create a small script, e.g.
`~/.local/bin/keepassxc-proxy-flatpak` with the content `#!/bin/sh` and
`exec flatpak run --command=keepassxc-proxy org.keepassxc.KeePassXC "$@"`, make it executable and pass
it with `--keepassxc-proxy`. (This path is untested.)

What the protocol supports: listing entries (title, address), fetching username and password per entry by its
address (KeePassXC may ask for confirmation), showing the current TOTP code, creating and editing logins
(KeePassXC names new entries after the site), creating groups, deleting (KeePassXC asks). Not possible:
notes, custom fields, changing titles, TOTP secrets, reading entries without a website address, moving.

## Troubleshooting

The messages are quoted as they appear in the English interface.

| Message | Cause and fix |
|---|---|
| "The OmniVault helper app isn't installed" | `install.py` was not run or the extension ID is wrong; run it again with the correct ID |
| "… isn't installed" / "… wasn't found" | the program is missing or not in the search path; install it or set the variable from the table above |
| Account stays "locked" | sign in in a terminal (`op signin`, `lpass login`, `dcli sync`, `pass-cli login`) or unlock the gpg key |
| "Dashlane: the vault is locked" | dcli has not stored the master password: `dcli configure save-master-password true`, then `dcli sync`; this does not work without a keychain (Linux without libsecret) |
| "dcli is waiting for input" | dcli wants to ask something (e.g. after a CLI update, whether the local storage should be reset): run `dcli sync` once in a terminal |
| "Your account is not yet allowed to use our CLI" | Proton has not (yet) enabled the CLI for your account |
| "The pass-cli session is locked with a PIN" | `pass-cli` session with a lock code: run `pass-cli session unlock` in a terminal |
| "update pass-cli" | version older than 2.3: `pass-cli update` |
| "KeePassXC doesn't allow listing the items" | in KeePassXC, turn on "Allow keepassxc-proxy to list all entries" under Browser Integration → Advanced |
| "KeePassXC: The database is locked" | unlock the database in KeePassXC |
| "KeePassXC doesn't recognize this connection (anymore)" | the association was removed in KeePassXC: edit the account → connect again |

## Testing with your own account

`selftest.py` calls the host the same way the browser does. The output contains only counts, types and ok/error, no
titles, usernames or passwords, so it can be shared:

```bash
python3 selftest.py pass                       # read only
python3 selftest.py gopass --write             # create, edit, move, delete a throwaway entry
python3 selftest.py onepassword --write        # additionally create, edit, delete (login, card, identity)
python3 selftest.py lastpass --write
python3 selftest.py dashlane                   # read only: dcli sync, list, one login, one note, one secret each
python3 selftest.py proton --write --vault OmniVault-Test   # Proton: create an EMPTY vault first
python3 selftest.py lastpass --limit 200       # search more entries for attachments (default 25)
```

The self-test counts attachments, password histories and passkeys in the first entries and downloads one attachment it finds
once (only its size is printed). For 1Password, `--write` additionally creates a throwaway card and a
throwaway identity from the `op` template, reads them back, edits and deletes them; it only reports whether the fields
match. Both show whether the real program delivers the formats that the tests simulate.

## Verified

pass is tested against real `pass` + GnuPG, gopass against the official release 1.17.4 (Linux amd64,
hash verified, `test/gopass-bin.sh`) + GnuPG, also with a mounted second store. 1Password and LastPass are tested against simulated programs
that reproduce the formats of `op` 2.x and `lastpass-cli` 1.x; Proton Pass against a simulated `pass-cli` whose
commands, error messages and exit codes have been compared with the real `pass-cli` 2.3.1 (without signing in). Dashlane is
tested against a simulated `dcli` whose JSON fields follow the dcli source code; version, `dcli status` and
the message when not signed in have been compared against the real release 6.2642.0 (Linux x64, hash verified, `test/dcli-bin.sh`).
Check these four with `selftest.py` against the real programs before using them in production.

All names mentioned are trademarks of their respective owners; OmniVault is not affiliated with them.
