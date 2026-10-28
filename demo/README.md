# Web demo of the popup

The project site (omni-vault.github.io) shows the extension's **real popup**, not a replica. Popup and
background run unmodified as ES modules in a web page; only two files are replaced:

| File in the demo build | Source | Purpose |
|---|---|---|
| `src/lib/browser.js` | `demo/browser.js` | the `chrome.*` APIs in use, in the same window; storage in the tab's `sessionStorage` |
| `src/providers/registry.js` | generated from the real `registry.js` | providers with the real metadata (name, account form, capabilities), but simulated vaults (`demo/vault.js`) |

On top of that come sample accounts and entries (`demo/data.js`), a neutral sample page for filling (`demo/page.html`,
example.com) and a browser toolbar around it (`demo/index.html`). The sample page is behind the button
"Show sample website" and is shown automatically when the popup fills: "Fill" runs the real
`fillInPage` or `fillFormInPage` function in it. The popup stays open and only closes via the
OmniVault icon. When embedded, `index.html` tells the surrounding page via `postMessage`
(`{ omnivaultDemo: 'layout', expanded }`) whether the sample page is open, so that it can make more room.

```bash
npm run build:demo        # → dist/demo (no dependencies, no bundler)
python3 -m http.server -d dist/demo 8765   # ES modules need http://, not file://
```

For the project site, copy the contents of `dist/demo` to `demo/` in the repository `omni-vault.github.io`.

Notes:

- Every tab starts with four unlocked accounts (Bitwarden, Passbolt, 1Password, KeePassXC). Locked accounts
  can be unlocked with any password; newly created accounts are empty.
- `demo/build.mjs` aborts if `popup.html` or the imports in `registry.js` change in a way that the replacement
  no longer works.
- Not in the demo: sidebar (the browser "does not offer one"), content scripts (button in the login field, "Save
  login?", passkeys on websites) and real servers.
