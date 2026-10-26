// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 Die OmniVault-Mitwirkenden
// Host permissions an account needs. Kept free of crypto code so the popup can import it
// cheaply and call permissions.request() synchronously inside a click.
import { endpoints } from './bitwarden/api.js';

/**
 * Host permission for a server address. Without the port: Firefox does not accept match patterns with a port (a
 * pattern like https://host:8443/* is granted but does not lift CORS), and in Chrome a pattern without a port covers
 * every port of the host.
 */
export function originPattern(url) {
  try {
    const u = new URL(url);
    if (!/^https?:$/.test(u.protocol) || !u.hostname) return null;
    return `${u.protocol}//${u.hostname}/*`;
  } catch { return null; }
}

export function hostPatterns(provider, config) {
  switch (provider) {
    case 'bitwarden': {
      const ep = endpoints(config.server);
      return [...new Set([ep.api, ep.identity].map(originPattern).filter(Boolean))];
    }
    case 'passbolt':
    case 'vault': {
      const p = originPattern(config.server);
      return p ? [p] : [];
    }
    default:
      return [];
  }
}
