#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
#
# Prints the path of the official Bitwarden CLI for the tests: $BW_CLI if set, otherwise the pinned release
# cli-v2026.9.0 (github.com/bitwarden/clients, bw-linux-2026.9.0.zip; SHA-256 recorded when it was pinned, the release
# has no checksum file), downloaded once to $BW_CLI_DIR (default /tmp/omnivault-bwcli). Never shipped with OmniVault.
set -eu
if [ -n "${BW_CLI:-}" ]; then echo "$BW_CLI"; exit 0; fi
DIR=${BW_CLI_DIR:-${TMPDIR:-/tmp}/omnivault-bwcli}
URL=https://github.com/bitwarden/clients/releases/download/cli-v2026.9.0/bw-linux-2026.9.0.zip
SHA256=580c1deec8345b19dbac7f8b02babb6cc4fe250c69c567e29061f727f1e40768
BIN=$DIR/bw-2026.9.0
if [ ! -x "$BIN" ]; then
  mkdir -p "$DIR" && rm -rf "$DIR/dl" && mkdir -p "$DIR/dl"
  curl -fsSL -o "$DIR/dl/bw.zip" "$URL"
  echo "$SHA256  $DIR/dl/bw.zip" | sha256sum -c - >/dev/null
  unzip -q -o "$DIR/dl/bw.zip" bw -d "$DIR/dl"
  mv "$DIR/dl/bw" "$BIN" && chmod +x "$BIN" && rm -rf "$DIR/dl"
fi
echo "$BIN"
