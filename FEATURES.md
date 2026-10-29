# Feature list

As of 2026-10-26, version 0.5.5. This file is the tracking list: each row states whether **OmniVault** implements a feature
and how it is tested. Whoever changes a provider updates the row in the same commit.

**Legend**

| Symbol | Meaning |
|---|---|
| ✅ R | implemented, tested against the **real counterpart**: local Vaultwarden, local Passbolt CE 5.16, local OpenBao 2.7.1, real `pass` or `gopass` + GnuPG |
| ✅ S | implemented, tested against a **simulated** server or a simulated CLI |
| ✅ U | implemented, covered by unit tests with sample data |
| ✅ | implemented, only checked manually or indirectly |
| ✅ L | implemented **in OmniVault** because the provider does not support it (e.g. favorites stored locally) |
| 🟡 | partial (limitation in the footnote) |
| ❌ | possible with the provider, **not yet** implemented in OmniVault |
| ⛔ | **not possible** via the available interface |
| ❓ | implemented, but not yet tested in this browser |
| – | does not exist at the provider |

## Providers at a glance

| Provider | Connection | Test basis |
|---|---|---|
| Bitwarden (cloud) and Vaultwarden | direct via the server API, decryption in the browser | R (Vaultwarden) |
| Passbolt v4 and v5 | direct via the server API, OpenPGP in the browser | R (Passbolt CE 5.16, two users) |
| HashiCorp Vault / OpenBao (KV v2) | direct via the HTTP API, token or userpass | R (OpenBao 2.7.1) ²⁴ |
| pass (password-store) | native host → `pass` + GnuPG | R |
| gopass | native host → `gopass` + GnuPG | R (gopass 1.17.4) ²⁵ |
| 1Password | native host → official `op` | S |
| LastPass | native host → official `lpass` | S |
| Dashlane | native host → official `dcli`, **read only** | S, plus R without an account (dcli 6.2642.0) ²⁶ |
| KeePassXC | KeePassXC's browser interface via `keepassxc-proxy` (no OmniVault host) | S ¹⁶ |
| Proton Pass | native host → official `pass-cli` | S, **on hold** ¹ |
| all others (KeePass files `.kdbx`, Chrome, Firefox …) | file import into a writable account | see Import |

¹ Proton currently only offers `pass-cli` on paid plans ("Your account is not yet allowed to use our
CLI"). The provider stays in the code and the tests but will not be developed further until the CLI is usable
for all accounts. A replacement for the official CLI is deliberately not planned.

¹⁶ KeePassXC: tested against a simulated KeePassXC that speaks the documented protocol with a real NaCl box
(unit test and browser test). The protocol supports: listing logins, fetching username and password per entry
by its address, the current TOTP code, creating, editing and deleting logins, creating groups. Not possible
(⛔ via the interface): notes, custom fields, titles, TOTP secrets, cards and identities, favorites,
moving, reading entries without a website address, passkeys (the protocol supports them, OmniVault does not use them
yet). A cross-check against real KeePassXC is still pending.

Bitwarden cloud and Vaultwarden use the same provider; nothing is tested automatically against bitwarden.com/.eu.

## Parity between providers

| Feature | Bitwarden / Vaultwarden | Vault / OpenBao | Passbolt | pass | gopass | 1Password | LastPass | Proton Pass | Dashlane |
|---|---| --- |---|---| --- |---|---|---|---|
| Read, create, edit, delete logins | ✅ R | ✅ R ²⁴ | ✅ R | ✅ R | ✅ R ²⁵ | ✅ S | ✅ S | ✅ S | 🟡 S (read only) ²⁶ |
| Notes | ✅ R | ✅ R (without `password` key) | ✅ R (v5) ² | – ³ | – | ✅ S | ✅ S | ✅ S | 🟡 S (secure notes and secrets, read only) |
| Read cards, identities | ✅ R | – | – | – | – | ✅ S ⁴ | – | ✅ S | ❌ (`dcli id` reads IDs, OmniVault does not use it) |
| Create and edit cards, identities | ✅ R | – | – | – | – | 🟡 S ⁴ | – | ⛔ | ⛔ |
| Read custom fields | ✅ R | ✅ R (remaining keys, hidden) | ✅ R (v5) | ✅ R | ✅ R | ✅ S | ⛔ | ✅ S | ✅ S (email, second login) |
| Edit custom fields | ✅ R | ✅ R | ✅ R (v5 logins) | ✅ R ⁵ | ✅ R | ✅ S | ⛔ | ⛔ | ⛔ |
| Read and change TOTP | ✅ R | ✅ R | ✅ R | ✅ R | ✅ R | ✅ S | ⛔ | 🟡 S (read only) | 🟡 S (read only) |
| Favorites | ✅ R | ✅ L | ✅ R | ✅ L | ✅ L | ✅ S | ✅ L | ✅ L | ✅ L |
| Show folders / vaults and move between them | ✅ R | ✅ R (paths) | ✅ R (show), ✅ S (move) | ✅ R (paths) | ✅ R (paths, mounted stores) | ✅ S (vaults) | ✅ S (groups) | ✅ S (vaults) | ⛔ (`dcli` does not output folders) |
| Create folder / vault | ✅ R | ✅ R | ✅ R ⁶ | ✅ R | ✅ R | ✅ S | ✅ S | ❌ | ⛔ |
| Trash: deleted items end up there | ✅ R | ✅ R (soft delete of the current version) | – (permanent) | – (permanent) | – (permanent) | ✅ S ("Recently Deleted") | – (permanent) | ✅ S | ⛔ |
| Show trash in OmniVault, restore, delete permanently | ✅ R | ✅ R (`undelete`; permanent: all versions) | – | – | – | ⛔ ¹⁷ | – | ❌ (on hold) | ⛔ |
| Download attachments | ✅ R | – | – | – | – | ✅ S ¹⁹ | ✅ S ¹⁹ | ✅ S ¹⁹ | ⛔ |
| Upload and delete attachments | ✅ R ¹⁸ | – | – | – | – | ⛔ ²⁰ | ⛔ ²⁰ | ⛔ ²⁰ | ⛔ |
| Password history | ✅ R | ❌ (versions exist, OmniVault does not show them) | – | – | – | 🟡 S ²¹ | ⛔ ²¹ | ⛔ ²¹ | ⛔ |
| Show passkeys | ✅ R | – | – ⁹ | – ⁹ | – | ⛔ ²² | ⛔ ²² | ✅ S (site and user only) | ⛔ |
| Create passkeys on websites, sign in with them, remove them | ✅ R (Bitwarden format, interchangeable with the official apps) | – | – ⁹ | – ⁹ | – | ⛔ ¹⁰ | ⛔ ¹⁰ | ⛔ ¹⁰ | ⛔ ¹⁰ |
| Share, change permissions, revoke access | 🟡 R ⁷ | ⛔ (policies are managed by the server) | ✅ R (entries and folders) | – | – | ⛔ | ⛔ | ⛔ | ⛔ |
| Edit shared entries | ✅ R (organization) | ✅ R (depending on policy) | ✅ R (secret re-encrypted for all readers) | – | – | 🟡 (like own entries, untested) | 🟡 (like own entries, untested) | ❌ | ⛔ |
| Conflict detection (an outdated state is not overwritten) | ✅ R | ✅ R (check-and-set) | ✅ R | – | – | ✅ S ¹³ | ✅ S ¹³ | ✅ S ¹³ | – (read only) |
| Decrypt secrets only when needed | – (everything local) | ✅ R (values read only when needed) | ✅ R | ❌ ⁸ | ❌ | ✅ S | ✅ S | ✅ S | 🟡 S (the host discards them in the list) ²⁶ |
| Report rate limits clearly | ✅ R | ✅ | ✅ | – | – | – | – | – | – |

²⁴ HashiCorp Vault / OpenBao: KV engine version 2, tested against real OpenBao 2.7.1 (dev server) with token and userpass (integration and browser test), plus a simulated server for unit tests; nothing is tested automatically against HashiCorp Vault itself, the API used is the same. Key mapping in README.md. Limits: at most 2000 entries and 12 folder levels per account; paths without read permission are skipped with a notice; KV version 1, other auth methods (OIDC, AppRole, LDAP …) and `custom_metadata` are not supported.
²⁵ gopass: via the OmniVault host with the gopass CLI, tested against the official release 1.17.4 + GnuPG (also with a mounted second store and moving into it). Entry format as in pass; mounted stores are top-level folders. Not supported: attachments (`gopass fscopy`), history from git; age encryption untested.
²⁶ Dashlane: via the OmniVault host with the official Dashlane CLI `dcli` (Apache-2.0), which can only read the vault. Tested against a simulated `dcli` whose JSON output (`dcli password|note|secret --output json`) follows the dcli source code and documentation; version, `dcli status` and the behavior when not signed in have been compared against the real release 6.2642.0 (Linux x64, hash verified). `dcli` always outputs the list including secrets: the host removes passwords, note texts and TOTP secrets before the list goes to the browser, and reads an entry again by its ID when it is opened. Dashlane "secrets" (e.g. SSH keys as text) appear as notes. Sign-in, second factor and SSO are handled by `dcli` in the terminal (`dcli sync`); `dcli` must have stored the master password, otherwise the vault is considered locked. Not supported: IDs (`dcli id`), folders, attachments, passkeys, writing (⛔ via the CLI).

² A freshly installed Passbolt 5.16 works with v4 resources; notes without a password and custom fields only exist
once an admin enables encrypted metadata (v5). Both states are tested against the real server.
³ In pass, every entry starts with a password line.
⁴ 1Password: cards and identities are created from the category template of the installed `op`
(`op item template get "Credit Card"` or `"Identity"`, JSON via stdin), so the fields keep 1Password's IDs, types and
sections; expiry date as `MONTH_YEAR` in the format YYYYMM. Written fields are cardholder, number,
verification number, expiry date, name, company, username, email and phone. 1Password derives the card type from the number.
The address of an identity (field type `ADDRESS`) is read but cannot be written reliably via `op`
(user report in the 1Password forum: the validator expects an object, the parser a string); a new address is therefore
put in the notes, and OmniVault rejects a change with a pointer to the 1Password app. The 1Password documentation does not
list the field IDs of the templates; the simulated `op` reproduces them, and `selftest.py onepassword --write` checks them
against the real program.
⁵ pass: custom fields are `Name: value` lines; pass has no hidden fields.
⁶ Passbolt 5.16 rejects v5 folders while its action log is active (it requires a plaintext name);
OmniVault then creates a simple folder if the server allows it.
⁷ Bitwarden shares via organizations and collections: OmniVault moves personal entries into an organization
and selects the collections (all values including password history, passkeys and attachments are re-encrypted with the
organization key, or only the item key; checked against real Vaultwarden). For organization entries, OmniVault
changes the collections (`collections_v2`, falling back to the older endpoint; only collections the user
may edit, at least one remains; checked against real Vaultwarden with an owner and a member with a
read-only collection, not automated against bitwarden.com). Permissions are assigned by the organization; that is
still only possible in the Bitwarden apps. OmniVault refuses to move attachments in the very old format (without their own key).
¹⁹ Downloads up to 30 MB per file, via a file in a private temporary folder, never via the shell.
1Password: files attached to items with `op read op://<vault ID>/<item ID>/<file ID>` (file attachments addressable by their
name or ID according to the [secret reference syntax](https://www.1password.dev/cli/secret-reference-syntax)),
document items with `op document get` ([docs](https://www.1password.dev/cli/reference/management-commands/document)).
LastPass: `lpass show` lists attachments as `att-<ID>: filename`, `lpass show --attach=att-<ID> --quiet` outputs the file
([lpass.1](https://github.com/lastpass/lastpass-cli/blob/master/lpass.1.txt), section Examples). Proton Pass:
`pass-cli item attachment download --share-id … --item-id … --attachment-id … --output <file>` (present in 2.3.1
and 2.5.0, [docs](https://protonpass.github.io/pass-cli/commands/item/)); the list comes from `item view --output json`.
²⁰ `lpass` and `pass-cli` (2.5.0) have no command for uploading or deleting attachments. `op` can only attach files when
**creating** an item via the assignment `[file]=<path>` ([docs](https://www.1password.dev/cli/item-create));
for existing items `op item edit` documents no file fields, and according to 1Password staff this only works
on creation ([forum](https://www.1password.community/developers-69/how-do-i-create-attach-a-file-field-to-an-existing-item-using-the-1password-cli-10003)).
²¹ 1Password: `op` outputs the history in an undocumented way; according to a user report in the 1Password forum as a list of old
passwords without timestamps (`password_details.history`). OmniVault shows it if `op` provides it; whether the real `op`
does is shown by `selftest.py`. LastPass: `lpass show --json` contains only id, name, fullname, username, password,
last_modified_gmt, last_touch, share, group, url and note
([json-format.c](https://github.com/lastpass/lastpass-cli/blob/master/json-format.c)), no history. Proton Pass:
`pass-cli` 2.5.0 has no command and no field for password history
([docs](https://protonpass.github.io/pass-cli/commands/item/)).
²² 1Password: the documentation only mentions passkeys with the warning that JSON templates do not support them and that an
`op item edit` with a template overwrites an existing passkey ([Edit items](https://www.1password.dev/cli/item-edit),
also in the help since `op` 2.33.1); they are not documented in the output of `op item get`. OmniVault warns about this loss in the
editor. LastPass: `lastpass-cli` has no passkeys (neither in `show` nor in `--json`).
¹⁷ `op` can neither list nor restore "Recently Deleted"; according to the 1Password documentation this is only possible in the
1Password apps (checked 2026-10-20). Deleted items remain there for 30 days.
¹⁸ As in the official apps: a separate key per file, encrypted with the item or organization key;
up to 30 MB per file. Tested against Vaultwarden (direct upload), also for organization entries. Bitwarden.com/.eu
store files in Azure Blob Storage; for this, OmniVault asks for permission for
`*.blob.core.windows.net` on the first upload. This path is not tested automatically. In the Bitwarden cloud, attachments require
a premium or organization account.
⁸ pass stores URL and username in the encrypted file; without decrypting there would be no site matching.
⁹ Passbolt and pass have no passkeys.
¹⁰ The programs `op`, `lpass`, `dcli` and `pass-cli` do not hand out the private keys of passkeys; Proton Pass
only shows for which site and which user a passkey exists.
¹³ Before changing an entry, the host compares the program's revision (1Password `version`, LastPass
`last_modified_gmt`, Proton `modify_time`). If a program reports none, no check is made; `selftest.py --write`
shows whether the real program provides it.

## Sign-in and session

| Feature | Bitwarden / Vaultwarden | Vault / OpenBao | Passbolt | CLI providers |
|---|---| --- |---|---|
| Sign in with master password / passphrase | ✅ R (PBKDF2, Argon2id) | ✅ R (token or userpass) | ✅ R (private key + passphrase) | in the CLI (`op signin`, `lpass login`, `dcli sync`, gpg agent) |
| OpenPGP keys: RSA, Ed25519/Cv25519, v6 according to RFC 9580 (Argon2 S2K, AEAD, SEIPD v2) | – | – | ✅ R (RSA, ECC), ✅ U (v6) ¹⁵ | – |
| Bitwarden's new encryption format ("Encryption V2": COSE, XAES-256-GCM, cipher blobs) | ✅ U read; writing blocked ¹⁴ | – | – | – |
| Sign in with API key | ✅ R | – | – | – |
| Two-factor | 🟡 S ¹¹ | ❌ (server MFA) | 🟡 S ¹² | handled by the CLI |
| Duo Universal Prompt (personal and organization) in a tab, popup continues afterwards | ✅ S ²⁷ | – | ❌ | – |
| New device verification (email code) | ✅ S | – | – | – |
| Self-hosted server | ✅ R | ✅ R | ✅ R | – |
| Token renewal / keeping the session alive | ✅ R | ✅ R (`renew-self`) | ✅ S | ✅ S |
| Verify server identity | – | – (browser TLS) | ✅ R (key pinning) | – |
| Unlock with PIN, 4–12 digits, checked while typing (after auto-lock, until the browser restarts) | ✅ S | ✅ (same path, not tested separately) | ✅ S | ✅ (same path, not tested separately) |
| Organization SSO (OIDC with PKCE in a tab), then master password | ✅ R (Vaultwarden with local OIDC provider), ✅ S (Bitwarden) ²⁷ | ❌ (OIDC) | ❌ | – |
| Accounts without master password (trusted devices, Key Connector) | ❌ – clear message (R + S) | – | – | – |
| Unlock with the device: Windows Hello, Touch ID, a phone or a security key via a passkey of OmniVault's own with the PRF extension (after auto-lock, until the browser restarts; next to or instead of the PIN) | ✅ S ³⁰ | ✅ (same path, not tested separately) | ✅ (same path, not tested separately) | ✅ (same path, not tested separately) |
| Biometrics directly (fingerprint, face) | ⛔ (browser extensions have no access; Windows Hello and Touch ID work through device unlock, see above) | ⛔ | ⛔ | – |

¹¹ TOTP, email, YubiKey OTP, Duo (²⁷). WebAuthn is missing; in that case the API key helps.
³⁰ Chrome and other Chromium browsers only. Chromium (virtual authenticators over CDP): setup, unlock, PIN and device side by side, cancelled or failed verification, an authenticator that does not know the passkey, a security key that evaluates PRF only when signing in (asked a second time during setup), replacing and removing, an authenticator without PRF (explained, not offered); from the real toolbar popup the ceremony runs in a window of its own and the popup is reopened afterwards. Real Windows Hello, Touch ID, phones (hybrid) and security keys were not tested automatically. Firefox only lets extensions use WebAuthn for sites in their host permissions, not for their own origin (checked: `SecurityError`), so the settings explain this instead.
¹² TOTP and YubiKey OTP. Duo is missing.
¹⁴ Not yet used by any production account and not supported by Vaultwarden (as of 2026-10-19). Checked against
the vectors of the XAES specification, Bitwarden's published vectors (local only) and a V2 account generated independently in Python.
In OmniVault, such accounts are read-only until writing in the new format is implemented.
¹⁵ OmniVault supports v6 keys, but Passbolt CE 5.16 does not accept them (checked): account setup with a
v6 key fails with "A valid OpenPGP key must be provided." ("The public key could not be parsed."), because the server
checks public keys with a parser for v4 packets; its GnuPG 2.4 does not support RFC 9580 either.
²⁷ Duo and SSO only send the browser back to fixed pages of the web vault (`duo-redirect-connector.html`,
`sso-connector.html`). For this, OmniVault opens a tab, waits in the background until it arrives there, reads code and
state from the address, closes the tab and signs in; the popup, which closes when the tab switches, shows the result the
next time it is opened or asks for the master password. No additional permission: the pages are
on the server the account accesses anyway. SSO is tested against a real Vaultwarden with a local
OIDC provider (including token renewal); Bitwarden's flow (`/sso/prevalidate`, `ssoToken`) and Duo only against
the simulated server, which builds addresses like the real servers. Not verified with real Duo and Bitwarden SSO.

## Tools (across providers)

| Feature | Status |
|---|---|
| Duplicates within an account and between accounts (website + username) | ✅ R + U |
| Reused and weak passwords (Tools → Check, local only) | ✅ R + U |
| Passwords known from data breaches (Have I Been Pwned, k-anonymity: only 5 characters of the SHA-1 per password, with padding; only after consent, via the optional permission `api.pwnedpasswords.com`) | ✅ S + U (service simulated in the browser test) |
| Multi-select: copy, move, delete | ✅ R |
| Copy / move from the detail view and the editor | ✅ R |
| Transfer between providers | ✅ R: logins, notes, cards, identities and custom fields, as far as the target can store them; otherwise they are written readably into the notes. Passkeys are carried over if the target can store them (Bitwarden → Bitwarden); attachments, history and otherwise also passkeys stay in the original (notice beforehand, depending on the target account). |
| Mirror rules (source → target, optionally with deletion, without ping-pong) | ✅ R + U |
| Automatic sync of unlocked accounts (also after a service worker restart, with mirror rules) | ✅ R (browser test: worker terminated, alarm wakes it, a change from another client arrives and is mirrored) |
| Trash (Tools → Trash) | ✅ R (Bitwarden/Vaultwarden, Vault/OpenBao) |
| Bitwarden Send (Tools → Send, Bitwarden/Vaultwarden only): list own Sends (name, type, expiration or deletion, access count), create text and file Sends (up to 30 MB) with deletion date (at most 31 days), expiration date, maximum access count, password, hide text, hide email, disabled; edit (the link stays the same, the file itself cannot be changed), copy link, remove password, delete | ✅ R + S + U: against Vaultwarden (text and file, direct upload); every link is opened as a recipient would via the public interface (`send_access` token, `/sends/access`, file download) and decrypted by an independent Python checker; password protection, expiration, access limit, disabling and deletion against the real server; Azure upload and the premium message of the Bitwarden cloud only simulated ²⁸ |
| Bitwarden emergency access as a trusted contact, view only (Tools → Emergency access): accounts that grant you access, with type, status and wait time; request access (with confirmation); after approval, the person's own entries (without trash and organization entries) as a separate read-only list with detail view, reveal and copy – no filling, no search, no export, no mirroring; discarded on locking. Inviting, accepting, confirming, approving and takeover: in the Bitwarden apps | ✅ R + S + U: fully against Vaultwarden (two accounts; inviting, confirming and approving via the API, requesting and viewing in OmniVault); takeover approvals only simulated ²⁹ |
| Export: Bitwarden JSON (complete, with passkeys including keys as in Bitwarden) and CSV, per account or all | ✅ R + U |

²⁸ Send format from the public sources of the Bitwarden server, the Bitwarden SDK and Vaultwarden (no code copied): 16 random bytes per Send, encrypted with the user key; contents with the 64-byte key derived from it via HKDF-SHA256 (salt "bitwarden-send", info "send"); password as PBKDF2-SHA256 (100,000 iterations, salt = Send key). Links: `https://send.bitwarden.com/#…` (bitwarden.com), otherwise `{web vault}/#/send/…`. In the Bitwarden cloud, file Sends require premium and a verified email address; OmniVault shows the server's message in an understandable way. A password is sent without `authType` so that both servers set it exactly when one is given. OmniVault does not create Sends with email verification (new at Bitwarden, premium) or item Sends.

²⁹ Flow from the public sources of the Bitwarden server and Vaultwarden (no code copied): `GET /emergency-access/granted`, `POST /emergency-access/{id}/initiate`, `POST /emergency-access/{id}/view` returns `keyEncrypted` (the grantor's user key, RSA-OAEP for your own public key) and the grantor's own entries. Both servers only allow viewing for the type "View" and after approval; the wait time is 1–90 days, and the response does not include the time of the request, so OmniVault only shows the wait time. Vaultwarden without SMTP: emergency access is allowed (`EMERGENCY_ACCESS_ALLOWED`, on by default); inviting an existing account counts as accepted immediately, no invitation token is needed. OmniVault does not download the grantor's attachments.

## File import

Import of an export into an existing, writable account (Tools → Import/Export). The file is read only in the
browser. Cards, identities and custom fields are preserved if the target account can store them, otherwise
they are written into the notes. Unmapped CSV columns end up in the notes.

| Format | Status |
|---|---|
| CSV with header row (Bitwarden, LastPass, Chrome, Firefox, NordPass, Dashlane, 1Password, KeePass, Safari …) | ✅ R + U |
| Bitwarden / Vaultwarden JSON (unencrypted), also OmniVault's own export; passkeys are carried over into Bitwarden accounts | ✅ R + U |
| Proton Pass JSON (`data.json` from the export) | ✅ U |
| KeePass 2 XML (KeePass, KeePassXC); custom fields stay fields, groups become folders | ✅ R |
| Detect format automatically | ✅ U |
| Target: account and folder selectable | ✅ R |
| Encrypted exports, ZIP archives (1PUX, Proton ZIP) | ⛔ (export unencrypted or unpacked first) |
| Open a KeePass database `.kdbx` directly (KDBX 3.1, 4.0, 4.1; AES-KDF, Argon2d, Argon2id; AES-256, ChaCha20; master password and/or key file – XML v1/v2, 32/64 bytes, any file); trash and attachments are not imported and are listed in the report | ✅ R + U ²³ |
| `.kdbx` with Twofish, KeePass 1 (`.kdb`), writing back to the file | ⛔ or ❌ (Twofish and `.kdb` rejected with a notice) |

²³ `.kdbx`: checked against files written by real KeePassXC (keepassxc-cli 2.7), against an independent
Python writer (`test/fixtures/kdbx/generate.py`) and against the sample files from kdbxweb (MIT); imported into
real Vaultwarden in the browser (`test/e2e-tools.mjs`).

## Interface

| Feature | Status |
|---|---|
| Several accounts at once, also from the same provider | ✅ R |
| Account color and initials on every entry | ✅ R |
| Entries matching the current page at the top | ✅ R |
| Search by name, username, address, folder, account; filter by type and favorites | ✅ R |
| Quick copy: username, password, TOTP | ✅ R |
| Detail view with all fields, hidden values on request, live TOTP | ✅ R |
| Editor: logins, notes, cards, identities, custom fields (text, hidden, yes/no), multiple addresses | ✅ R |
| "New folder …" directly in the folder field | ✅ R |
| Share dialog (Passbolt): search people and groups, permissions read/edit/owner | ✅ R |
| "Share folder "…" …" (Passbolt, in an entry's menu): the folder's permissions; the same change applies to own subfolders and entries in it, new readers receive the secrets encrypted; other people's entries stay unchanged | ✅ R (real Passbolt, browser test) |
| "Move to organization …" (Bitwarden): choose organization and collections | ✅ R (real Vaultwarden, browser test) |
| "Change collections …" (Bitwarden organization entry): read-only collections visible but locked | ✅ R (real Vaultwarden, browser test) |
| Password generator (character classes, without ambiguous characters, PIN, strength meter), list of recently generated passwords; passwords hidden, revealed via the eye icon | ✅ R + U |
| Light and dark appearance (follows the system), custom line icons | ✅ |
| Keyboard navigation: menus with arrow keys, Esc goes back | ✅ R |
| Back/forward between views as in the browser: arrows in the header, Alt+←/→ (Mac: ⌘[ / ⌘]), mouse buttons 4/5; forms keep their input when you return | ✅ R (real popup) |
| Settings list all accounts with status; lock, unlock, edit, remove | ✅ R |
| Consistent checkboxes in all views (the browser test checks the size) | ✅ R |
| Sample identities: made-up data (email under example.com, no ID numbers) in the New menu and in the editor | ✅ R + U |
| After a permission prompt (the popup closes) you continue at the same place, without passwords being remembered | ✅ R |

## Languages

German, English, Spanish, French, Italian, Portuguese (Brazil), Chinese (Simplified) and
Japanese. Without a setting, the browser's language applies (English for other languages); there is no prompt.
Settings → Appearance → Language switches immediately.

| Feature | Status |
|---|---|
| Popup, sidebar, window, list in the login field, "Save login?" | ✅ R (clicked through in all languages) |
| Messages from the background and the providers, context menu, texts of the local host | ✅ U |
| Name, description and keyboard shortcuts in the browser (`_locales`) | ✅ R |
| Plurals according to the rules of the language (`Intl.PluralRules`), date and time (`Intl.DateTimeFormat`) | ✅ U |
| Language picker as a grid (keyboard: arrow keys in both directions, Home/End, Esc) | ✅ R |
| Translations worded for the context of use (button, hint, error message), with the usual password manager terms in each language | ✅ |
| Translation reviewed by native speakers | ❌ (all translations except German are machine-generated) |
| Right-to-left languages | ❌ (not offered) |

## Browsers

| Feature | Chrome / Chromium | Firefox |
|---|---|---|
| Toolbar popup | ✅ R (real popup tested) | ✅ R (real popup opened via the browser window, fixed size 380 × 560; Firefox 158) |
| Separate window, sidebar; switching window ↔ sidebar in both directions | ✅ R | ✅ R (real sidebar opened and closed via its icon; handover window → sidebar: the icon opens it, the window closes) |
| Fill by click, keyboard shortcut, context menu (also "Insert secure password") | ✅ R (shortcuts and context menu with real keyboard and mouse input) | ✅ R (context menu opened by right-click, item chosen via the browser window; shortcut as a real key under Xvfb, headless via the registered command) |
| Fill cards and identities into payment and address forms | ✅ S | ✅ S |
| OmniVault button in login fields with matching logins (opt-in) | ✅ S | ✅ S |
| "Save login?" / "Update password?" after signing in (opt-in) | ✅ S | ✅ S |
| Fill into embedded frames (click, keyboard shortcut, context menu): a login only into a frame whose own origin matches it, never into hidden, tiny or covered frames; frames of another site after a one-time question per pair of sites; note in the page naming the frame's site | ✅ S (two origins; click in the window with the question, shortcut and context menu with real input; a login of the page does not reach the other origin's frame, not even "fill anyway"; transparent, tiny, off-screen, `visibility:hidden`, `display:none` and covered frames ignored; same-origin frame without note) | ✅ S (click with the question; transparent and `visibility:hidden` frames ignored via the parent frame); shortcut and context menu in frames: same code, not tested separately |
| Cards and identities into embedded payment and address frames (e.g. payment providers): only on a click in the window, question once per pair of sites, note naming the frame | ✅ S | ✅ (same code) |
| Item list: logins of login forms embedded in the page under "For this site", marked with the frame's site | ✅ S | ✅ (same code) |
| OmniVault button and list inside embedded login frames (frame's own logins, names the page around it); "Save login?" from a frame opens in the top page and stores the frame's site | ✅ S | ✅ (same code, not tested separately) |
| Auto-lock (time, screen lock), clearing the clipboard | ✅ | ✅ (lock after inactivity via the event page's alarm and clipboard clearing checked automatically; screen lock not) |
| Key derivation (Argon2) in a worker: OmniVault stays responsive meanwhile, memory freed afterwards | ✅ S (offscreen document with worker; unlocking with 1 GiB, KeePass file with 256 MiB in the popup) | ✅ S (event page worker; unlocking with 256 MiB) |
| Native host for CLI providers | ✅ R | ✅ S (manifest in `~/.mozilla/native-messaging-hosts` with `allowed_extensions`; Firefox starts the host, Proton Pass via simulated `pass-cli`) |
| Passkeys: site asks → OmniVault dialog (create in a new or existing login, sign in, "other device or browser"), opt-in | ✅ R (test page with independent signature verification, passkeys against real Vaultwarden); confirmed manually on webauthn.io | ✅ S (test page with independent signature verification: create, sign in, cancel; simulated server); confirmed manually on webauthn.io (2026-10-19) |
| Passkeys in the list of a `username webauthn` field (conditional request, "conditional mediation") | ✅ S | ✅ S |
| Locked account: the dialog offers unlocking if a passkey for the site may be stored there | ✅ S | ✅ S |
| Passkeys in embedded frames of other origins, only with Permissions Policy (`allow="publickey-credentials-get"` / `-create`), dialog in the top-level frame with frame and page, `crossOrigin`/`topOrigin` in `clientDataJSON` | ✅ S (two origins: with policy OmniVault answers; without policy and with a policy manipulated in the page script the browser answers; the test page checks `crossOrigin`/`topOrigin`) | – (Firefox cannot confirm a frame's policy and ancestors: the browser takes over, checked) |
| Passkey extensions: `credProps` answered; PRF and largeBlob declined (`prf.enabled: false`, `largeBlob.supported: false`) | ✅ S | ✅ (same code) |
| Unlock with the device (WebAuthn PRF on the extension's own pages) | ✅ S ³⁰ | ⛔ (Firefox refuses a passkey for the extension's own origin; checked, setting explains it) |

## Still missing compared to the official apps

| Feature | Reason |
|---|---|
| Passkeys in embedded frames in Firefox | Firefox gives extensions no reliable information about a frame's Permissions Policy and ancestors; the browser handles these requests |
| Passkey extensions PRF and largeBlob | the Bitwarden passkey format has no field for the PRF secret or the blob; the Bitwarden apps would discard both |
| Passkeys for 1Password, LastPass, Dashlane, Proton Pass | their command-line programs do not hand out the keys |
| Dashlane: create, edit, delete entries | the official `dcli` can only read |
| Bitwarden: invite, accept, confirm, approve, take over emergency access | only in the Bitwarden apps; as a trusted contact OmniVault can only request and view. Takeover resets someone else's master password and is deliberately left out |
| Bitwarden: manage permissions in an organization (members, groups, permissions per collection) | not implemented; OmniVault changes an entry's collections |
| Bitwarden: WebAuthn as second factor; accounts that unlock without a master password (trusted devices, Key Connector) | WebAuthn only works through an internal page of the web vault (workaround: API key); the other two need undocumented key exchange. Duo and SSO are supported, see above |
| Passbolt: Duo, account recovery | Duo does not work with OmniVault's JWT sign-in without a new permission: the prompt (`POST /mfa/verify/duo/prompt`) and the callback (`/mfa/verify/duo/callback`) require the access token in the `Authorization` header, which a tab does not send (checked against Passbolt CE 5.16: without the header 403, with the header the prompt reaches the Duo health check), and the background cannot read the redirect address to Duo (`redirect: 'manual'` returns an empty `opaqueredirect` response in Chrome and Firefox, `follow` fails due to CORS at Duo). It would be possible with `webRequest` or `declarativeNetRequestWithHostAccess`. Account recovery only exists in Passbolt Pro |
| Unlocking after a browser restart without the master password | deliberately not: the sealed sessions are kept in memory only |
| Unlock with the device in Firefox | Firefox lets extensions use WebAuthn only for sites in their host permissions; a passkey for a website domain would need a domain of OmniVault's and a new permission |
