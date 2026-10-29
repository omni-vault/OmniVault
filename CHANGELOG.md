# Changelog

## Unreleased

### New
- **Unlock with your device** (Settings → Security, Chrome and other Chromium browsers): after an automatic lock,
  Windows Hello, Touch ID, your phone or a security key reopens your accounts, next to or instead of the PIN. OmniVault
  creates a passkey for itself and derives the key for the sealed session copy from the device's PRF answer, which it
  only gives after you verify yourself. From the toolbar popup the confirmation runs in a small window of its own
  (the system dialog would close the popup), and the popup opens again afterwards. As with the PIN, only until the
  browser restarts. Not available in Firefox, which does not let extensions create passkeys for themselves.
- **Passphrases** in the generator: 3–20 words from the EFF Large Wordlist (7,776 words), your choice of separator,
  optional capital letters and a digit. The strength meter shows the real entropy (log2(7776) ≈ 12.9 bits per word).
- **Usernames** in the generator: a random word (optionally with a number), a plus address
  (`name+random@your-domain`, from your email address) or a catch-all address (`random@your-domain`). Everything is
  generated locally; no alias services are used. A new die next to the username in the editor uses these settings;
  right-click it to open the username generator. The password die now creates a passphrase if that is the kind you
  chose in the generator.
- **Copy the TOTP code after filling** (Settings → Security, off by default): after a login with a one-time code is
  filled in, its current code goes to the clipboard and is cleared after the usual delay; a short notice on the page
  says so. Works for the popup, the keyboard shortcut, the context menu and the button in login fields.
- **Scan a TOTP QR code on the page** (button next to the one-time code in the editor): OmniVault takes one screenshot
  of the visible part of the tab, finds the QR code, checks that it is a valid `otpauth://totp/…` code and takes it
  over, filling in an empty name and username from it. The screenshot is processed in the popup's memory only and is
  never stored or sent. It needs OmniVault to be opened from its toolbar button, keyboard shortcut or context menu
  (activeTab); no new permission.

### Improvements
- **Filling in embedded frames**: login forms embedded in a page (for example a bank's or a partner's sign-in in an
  iframe) and card forms of payment providers can now be filled – with a click, the keyboard shortcut, the context
  menu and the OmniVault button in the field. A login only goes into a frame whose own website matches it, never
  because the page around it does; hidden, tiny or covered frames are never filled. For a form of another site than
  the page, OmniVault asks once per pair of sites (Settings → On websites lets you forget these answers), and every
  fill into an embedded form shows a short note in the page naming its site. "For this site" in the list now also
  shows the logins of embedded login forms, marked as such, and "Save login?" works in embedded forms. No new
  permissions; forms embedded from other sites need the existing access to websites.

## 0.5.5 – 2026-10-26

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
