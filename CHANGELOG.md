# Changelog

## Unreleased

### Improvements
- **Argon2 no longer blocks OmniVault**: unlocking an account with a high Argon2 memory setting (up to 1 GiB), unlocking
  with a PIN and opening a KeePass database now compute the key in a separate worker. Other accounts, the popup and
  the "Decrypting …" indicator keep responding meanwhile, and the memory is released as soon as the key is derived.

### Bitwarden and Vaultwarden
- **Emergency access as a trusted contact** (Tools → Emergency access): see who granted you emergency access, with
  status and waiting period, request access and, once approved, view and copy their items. Read only: these items
  are never filled in, searched or exported and are forgotten when you lock. Inviting, confirming and takeover stay
  in the Bitwarden apps.

### Fixes
- **Passbolt stayed signed in for only about 10 minutes**: Passbolt's access tokens last 5 minutes, and the second
  renewal reused a refresh token that Passbolt only accepts once (Passbolt treats this as an attack and notifies the
  user and the administrators). OmniVault now gets a new token by signing in again with the key that is already
  unlocked, and no longer keeps a refresh token.
- **Self-hosted servers on a non-standard port in Firefox**: Firefox ignores permissions that include a port, so
  requests to e.g. `https://vault.example.org:8443` were blocked. OmniVault now asks for the host without the port.
- Going back from an item opened in Tools (or reopening the popup) now returns to the tab you were on instead of the
  first one.

## 0.5.4 – 2026-10-26

### New password managers
- **KeePassXC** through KeePassXC's own browser integration (`keepassxc-proxy`): list, fill, TOTP, create, edit and
  delete logins, create groups.
- **HashiCorp Vault / OpenBao** (KV v2), directly from the extension: token or username/password sign-in, conflict
  detection, trash with restore.
- **gopass** through the local helper; mounted stores appear as folders.
- **Dashlane** (read only) through the official `dcli` command-line tool.

### Bitwarden and Vaultwarden
- Sign in with **Duo** as the second factor and with your organization's **single sign-on (SSO)**, followed by your
  master password. Accounts that unlock without a master password get a clear message.
- **Bitwarden Send**: create, edit, copy the link of and delete text and file Sends (Tools → Send).
- **Attachments**: add and delete files.
- **Organizations**: move personal items into an organization and change an item's collections.
- Accounts that use Bitwarden's new encryption format (not yet enabled by Bitwarden) can be read.

### Other password managers
- 1Password: create and edit cards and identities.
- 1Password, LastPass, Proton Pass: download attachments.
- 1Password, LastPass, Proton Pass: a change made elsewhere in the meantime is no longer overwritten.
- Passbolt: share folders, including their subfolders and items.

### Everyone
- **Import KeePass databases (`.kdbx`)** directly: KDBX 3.1 and 4.x, password and/or key file. KeePass XML imports
  now keep custom fields as fields.
- **Password check against data breaches** (Have I Been Pwned), only after you allow it; only the first 5 characters
  of each password's hash are sent.
- **Passkeys in embedded frames** (Chrome) when the page explicitly allows it; the dialog names both sites.
- Automatic sync now actually runs at the chosen interval (it was postponed every time the background restarted).
- Mirror rules no longer store item contents to compare versions, only a hash (before, pass passwords could end up
  in the browser's local storage).
- After unlocking an account with a very high Argon2 memory setting, that memory is now released again.
- Tool tabs no longer break words across lines in some languages; Japanese and Chinese use one term for items.

### Firefox
- Firefox **140 or later** is required. At installation Firefox asks you to agree to the transfer of sign-in data,
  personal information (identities) and payment information (cards) to the servers you add.
- Final add-on ID `omnivault@royaltysoft.works`. If you use the local helper with Firefox, run `install.py` again.
- Fixed an error in the popup when it closed while Firefox moved the focus.

### Privacy and releases
- Privacy policy: [PRIVACY.md](PRIVACY.md).
- Release packages are built reproducibly with `npm run package`.
