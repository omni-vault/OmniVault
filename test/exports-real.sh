#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
#
# Encrypted exports and ZIP imports against real servers (npm run test:exports):
# 1. Vaultwarden over HTTP ($VW_PORT, default 8830): browser test test/e2e-exports.mjs (arguments are passed on);
# 2. Vaultwarden over HTTPS ($VW_TLS_PORT, default 8831, throw-away self-signed certificate): the official Bitwarden
#    CLI (test/bw-cli.sh) against OmniVault's exports and the other way round (test/vaultwarden-export.test.js).
set -eu
PLAIN=${VW_PORT:-8830}
TLS=${VW_TLS_PORT:-8831}
BASE=${TMPDIR:-/tmp}
D1=$BASE/omnivault-vw-exports
D2=$BASE/omnivault-vw-exports-tls
CERTS=$(mktemp -d "$BASE/omnivault-tls-XXXXXX")
stop() {
  VW_PORT=$PLAIN VW_DIR=$D1 test/vaultwarden-server.sh stop
  VW_PORT=$TLS VW_DIR=$D2 test/vaultwarden-server.sh stop
  rm -rf "$CERTS"
}
trap stop EXIT
s=0
VW_PORT=$PLAIN VW_DIR=$D1 test/vaultwarden-server.sh start
VAULTWARDEN_URL=http://localhost:$PLAIN node test/e2e-exports.mjs "$@" || s=1
VW_PORT=$PLAIN VW_DIR=$D1 test/vaultwarden-server.sh stop

openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERTS/key.pem" -out "$CERTS/cert.pem" -days 1 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 2>/dev/null
[ -n "${VAULTWARDEN_BIN:-}" ] || [ ! -x "$D1/vaultwarden" ] || export VAULTWARDEN_BIN="$D1/vaultwarden"
VW_PORT=$TLS VW_DIR=$D2 ROCKET_TLS="{certs=\"$CERTS/cert.pem\",key=\"$CERTS/key.pem\"}" test/vaultwarden-server.sh start
NODE_EXTRA_CA_CERTS=$CERTS/cert.pem VAULTWARDEN_TLS_URL=https://localhost:$TLS node --test test/vaultwarden-export.test.js || s=1
exit $s
