#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
#
# Local Passbolt CE for tests (127.0.0.1 only, throw-away data, never shipped with OmniVault):
#   test/passbolt-server.sh start            fresh install, server on http://127.0.0.1:$PB_PORT (default 8900)
#   test/passbolt-server.sh register E F L R prints the setup URL of a new user (R = user | admin)
#   test/passbolt-server.sh cake ARGS…       runs bin/cake as the service user
#   test/passbolt-server.sh stop
#
# Needs: PHP ≥ 8.2 (with its phpize/php-config), composer, git, a C compiler, gpg, libgpgme and the PostgreSQL
# server binaries (PG_BIN, default from pg_config). Everything else comes from GitHub, pinned to commit hashes:
# Passbolt v$PB_VERSION, its dependencies from their git sources (composer --prefer-source, commits from
# composer.lock) and, when PHP lacks the gnupg extension, php-gnupg (built once into $DIR/php; or set
# PHP_GNUPG_SO=/path/gnupg.so). No package manager, no packagist.org or pecl.php.net access is needed.
# PHP's ldap extension is only used by Passbolt PRO; when it is missing, the requirement check is skipped for this
# test instance only. Run as root, everything runs as the user $PB_USER (created if missing), because
# PostgreSQL refuses to run as root.
set -eu
PB_VERSION=${PB_VERSION:-5.16.0}
PB_COMMIT=${PB_COMMIT:-8ff0944c9b6c4020204d60e776d0eb53dcbe8a3a} # tag v5.16.0
PORT=${PB_PORT:-8900}
PG_PORT=${PB_PG_PORT:-5433}
DIR=${PB_DIR:-${TMPDIR:-/tmp}/omnivault-passbolt}
PB_USER=${PB_USER:-omnivault-pb}
PG_BIN=${PG_BIN:-$(pg_config --bindir 2>/dev/null || echo /usr/lib/postgresql/16/bin)}
APP=$DIR/passbolt_api
HOME_DIR=$DIR/home

as_user() { # run a shell snippet as the service user with Passbolt's environment
  env_line="export HOME=$HOME_DIR GNUPGHOME=$HOME_DIR/.gnupg PHP_INI_SCAN_DIR=${PHP_INI_SCAN_DIR:-$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;')}:$DIR/php OMNIVAULT_TEST_NO_LDAP=1;"
  if [ "$(id -u)" = 0 ]; then su "$PB_USER" -s /bin/sh -c "$env_line $1"; else sh -c "$env_line $1"; fi
}
cake() { as_user "cd $APP && ./bin/cake $*"; }

fetch() { # fetch URL TAG COMMIT DEST: shallow clone of a tag, refuses anything but the pinned commit
  [ -d "$4/.git" ] || git clone -q -c advice.detachedHead=false --depth 1 --branch "$2" "$1" "$4"
  got=$(git -c safe.directory='*' -C "$4" rev-parse HEAD)
  [ "$got" = "$3" ] || { echo "$1 $2: commit $got, expected $3" >&2; exit 1; }
}

# php-gnupg from its git sources, built against the system's libgpgme (no -dev packages needed): the two headers
# are generated from the libgpg-error and gpgme sources of the matching release, exactly as their build would do.
build_gnupg() {
  out=$DIR/php/gnupg.so; [ -f "$out" ] && return
  b=$DIR/build-gnupg; mkdir -p "$b/prefix/include" "$b/prefix/lib"
  fetch https://github.com/gpg/libgpg-error.git libgpg-error-1.47 a25cea92798a5ece3f49924911507f5335915ecc "$b/libgpg-error"
  fetch https://github.com/gpg/gpgme.git gpgme-1.18.0 26ff163bd6912fa7e8cb522d0799e17095ac1efb "$b/gpgme"
  fetch https://github.com/php-gnupg/php-gnupg.git gnupg-1.5.4 ced3b06792ead4898974ae95817f09479af843bb "$b/php-gnupg"
  git -c safe.directory='*' -C "$b/php-gnupg" submodule -q update --init --depth 1 phpc # pinned by php-gnupg
  printf '#define HAVE_STDINT_H 1\n#define HAVE_SYS_TYPES_H 1\n#define USE_POSIX_THREADS 1\n#define REPLACEMENT_FOR_OFF_T "long"\n' > "$b/config.h"
  (cd "$b/libgpg-error/src" && cc -I. -o "$b/mkheader" mkheader.c &&
    "$b/mkheader" --cross "$(uname -m)-unknown-linux-gnu" gpg-error.h.in "$b/config.h" 1.47 0x012f00 2>/dev/null > "$b/prefix/include/gpg-error.h")
  printf '#include <sys/types.h>\ntypedef off_t   gpgme_off_t;\ntypedef ssize_t gpgme_ssize_t;\n' > "$b/typedefs.h"
  sed -e 's/@GPGME_CONFIG_HOST@/linux/; s/@PACKAGE_VERSION@/1.18.0/; s/@VERSION_NUMBER@/0x011200/' \
    -e 's/@NEED__FILE_OFFSET_BITS@/0/g; s/@API__SSIZE_T@/ssize_t/g; s/@API__OFF_T@/off_t/g' \
    -e "/@INSERT__TYPEDEFS_FOR_GPGME_H@/{r $b/typedefs.h" -e 'd}' "$b/gpgme/src/gpgme.h.in" > "$b/prefix/include/gpgme.h"
  for l in libgpgme.so.11 libgpg-error.so.0; do
    p=$(ldconfig -p | awk -v l="$l" '$1 == l && /x86-64|aarch64/ {print $NF; exit}')
    [ -n "$p" ] || { echo "$l is missing" >&2; exit 1; }
    ln -sf "$p" "$b/prefix/lib/${l%.so.*}.so"
  done
  (cd "$b/php-gnupg" && phpize >/dev/null && ./configure -q --with-gnupg="$b/prefix" >/dev/null && make -s -j2 >/dev/null 2>&1)
  install -m 755 "$b/php-gnupg/modules/gnupg.so" "$out"
}

install_app() {
  [ -f "$APP/vendor/autoload.php" ] && return
  fetch https://github.com/passbolt/passbolt_api.git "v$PB_VERSION" "$PB_COMMIT" "$APP"
  (cd "$APP" && COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_NO_INTERACTION=1 composer install -q --no-dev --prefer-source \
    --ignore-platform-req=ext-gnupg --ignore-platform-req=ext-ldap --no-scripts)
  # The ldap extension is a PRO requirement; allow this test instance to run without it.
  sed -i "s/if (!extension_loaded('ldap')) {/if (!extension_loaded('ldap') \&\& !getenv('OMNIVAULT_TEST_NO_LDAP')) {/" "$APP/config/requirements.php"
}

case "${1:-start}" in
  start)
    "$0" stop >/dev/null 2>&1 || true
    if [ "$(id -u)" = 0 ] && ! id "$PB_USER" >/dev/null 2>&1; then useradd -M -s /bin/sh "$PB_USER"; fi
    mkdir -p "$DIR/php"
    install_app
    if [ -n "${PHP_GNUPG_SO:-}" ]; then echo "extension=$PHP_GNUPG_SO" > "$DIR/php/gnupg.ini"
    elif ! php -r 'exit(extension_loaded("gnupg") ? 0 : 1);'; then
      build_gnupg; echo "extension=$DIR/php/gnupg.so" > "$DIR/php/gnupg.ini"
    fi
    rm -rf "$DIR/pgdata" "$HOME_DIR" "$APP/config/jwt/jwt.key" "$APP/config/jwt/jwt.pem"
    mkdir -p "$DIR/pgdata" "$HOME_DIR/.gnupg"
    chmod 700 "$DIR/pgdata" "$HOME_DIR" "$HOME_DIR/.gnupg"
    [ "$(id -u)" = 0 ] && chown -R "$PB_USER" "$DIR"

    # database
    as_user "$PG_BIN/initdb -D $DIR/pgdata -U postgres --auth=trust -E UTF8 >/dev/null && \
      $PG_BIN/pg_ctl -D $DIR/pgdata -o '-p $PG_PORT -k /tmp -c listen_addresses=127.0.0.1' -l $DIR/pg.log -w start >/dev/null && \
      $PG_BIN/createdb -h 127.0.0.1 -p $PG_PORT -U postgres passbolt"

    # server key (RSA 3072, signing primary + encryption subkey, no passphrase)
    as_user "gpg --batch --quiet --passphrase '' --quick-gen-key 'Passbolt Test Server <server@passbolt.test>' rsa3072 sign never 2>/dev/null; \
      FP=\$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr/ {print \$10; exit}'); \
      gpg --batch --quiet --passphrase '' --quick-add-key \$FP rsa3072 encr never 2>/dev/null; \
      gpg --armor --export \$FP > $APP/config/gpg/serverkey.asc; \
      gpg --armor --batch --pinentry-mode loopback --passphrase '' --export-secret-keys \$FP > $APP/config/gpg/serverkey_private.asc; \
      echo \$FP > $DIR/server.fpr"
    FPR=$(cat "$DIR/server.fpr")
    cat > "$APP/config/passbolt.php" <<EOF
<?php
// Local test instance for OmniVault (127.0.0.1 only, throw-away data).
return [
    'App' => ['fullBaseUrl' => 'http://127.0.0.1:$PORT'],
    'Security' => ['salt' => '$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')'],
    'Datasources' => ['default' => [
        'className' => \Cake\Database\Connection::class, 'driver' => \Cake\Database\Driver\Postgres::class,
        'host' => '127.0.0.1', 'port' => $PG_PORT, 'username' => 'postgres', 'password' => '', 'database' => 'passbolt',
        'encoding' => 'utf8',
    ]],
    'EmailTransport' => ['default' => ['className' => 'Debug']],
    'Email' => ['default' => ['transport' => 'default', 'from' => ['passbolt@passbolt.test' => 'Passbolt']]],
    'passbolt' => [
        'ssl' => ['force' => false],
        'gpg' => ['serverKey' => [
            'fingerprint' => '$FPR',
            'public' => CONFIG . 'gpg' . DS . 'serverkey.asc',
            'private' => CONFIG . 'gpg' . DS . 'serverkey_private.asc',
        ]],
        'security' => ['cookies' => ['secure' => false]],
    ],
];
EOF
    [ -f "$APP/config/app.php" ] || cp "$APP/config/app.default.php" "$APP/config/app.php"
    [ "$(id -u)" = 0 ] && chown -R "$PB_USER" "$APP/config"
    chmod 750 "$APP/config/jwt"
    cake passbolt create_jwt_keys >/dev/null
    chmod 550 "$APP/config/jwt" && chmod 440 "$APP/config/jwt/jwt.key" "$APP/config/jwt/jwt.pem"
    cake passbolt install --no-admin --force > "$DIR/install.log" 2>&1 || { tail -20 "$DIR/install.log" >&2; exit 1; }

    as_user "cd $APP && PHP_CLI_SERVER_WORKERS=4 setsid nohup php -S 127.0.0.1:$PORT -t webroot webroot/index.php > $DIR/web.log 2>&1 < /dev/null & echo \$! > $DIR/web.pid"
    for i in $(seq 1 50); do
      curl -fs "http://127.0.0.1:$PORT/healthcheck/status.json" >/dev/null 2>&1 && { echo "Passbolt läuft: http://127.0.0.1:$PORT"; exit 0; }
      sleep 0.2
    done
    echo "Passbolt startet nicht, siehe $DIR/web.log" >&2; exit 1 ;;
  register)
    cake passbolt register_user -u "$2" -f "$3" -l "$4" -r "${5:-user}" 2>/dev/null | grep -o "http://[^ ]*/setup/start/[^ ]*" ;;
  cake)
    shift; cake "$@" ;;
  stop)
    # the web server runs in its own process group (setsid), so its worker processes stop with it
    [ -f "$DIR/web.pid" ] && kill -- "-$(cat "$DIR/web.pid")" 2>/dev/null || true
    [ -d "$DIR/pgdata" ] && as_user "$PG_BIN/pg_ctl -D $DIR/pgdata -m fast stop >/dev/null 2>&1" || true
    rm -f "$DIR/web.pid" ;;
esac
