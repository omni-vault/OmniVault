#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
#
# Local Psono server for tests (127.0.0.1 only, throw-away data, never shipped with OmniVault):
#   test/psono-server.sh start                     fresh database, server on http://127.0.0.1:$PS_PORT (default 8935; PostgreSQL on PS_PG_PORT, default 8936)
#   test/psono-server.sh createuser USER PASS MAIL  creates an activated user (USER like name@example.com)
#   test/psono-server.sh manage ARGS…               runs Psono's manage.py
#   test/psono-server.sh stop
# PS_MULTIFACTOR=true makes Psono ask for every second factor a user has (MULTIFACTOR_ENABLED).
#
# Needs: Python ≥ 3.11 with cffi, cryptography, PyYAML, requests, python-dateutil and Pillow (as most systems ship
# them), a C compiler, the system's libsodium (1.0.18 ABI, libsodium.so.23), libpq, libcrypt and the PostgreSQL
# server binaries (PG_BIN). Everything else comes from GitHub/GitLab, pinned to commit hashes: the Psono server
# v$PS_VERSION and the pure-Python packages it uses; PyNaCl's binding is compiled against the system's libsodium (headers
# from the matching libsodium release). No package manager and no pypi.org access is needed. Three small test-only
# shims stand in for C/Rust packages and unused cloud SDKs (test/psono-shims: bcrypt via libcrypt, scrypt via hashlib,
# placeholders for sentry and the storage SDKs); the server code itself runs unmodified. Run as root, PostgreSQL runs
# as the user $PS_USER (created if missing), because it refuses to run as root.
set -eu
PS_VERSION=${PS_VERSION:-7.5.7}
PS_COMMIT=${PS_COMMIT:-9ebf3d4df579ebd4b9992b558ff9986d97d8313b} # tag v7.5.7
PORT=${PS_PORT:-8935}
PG_PORT=${PS_PG_PORT:-8936}
DIR=${PS_DIR:-${TMPDIR:-/tmp}/omnivault-psono}
PS_USER=${PS_USER:-omnivault-ps}
PG_BIN=${PG_BIN:-$(pg_config --bindir 2>/dev/null || echo /usr/lib/postgresql/16/bin)}
HERE=$(cd "$(dirname "$0")" && pwd)
APP=$DIR/psono-server/psono
LIB=$DIR/pylib

as_pg() { if [ "$(id -u)" = 0 ]; then su "$PS_USER" -s /bin/sh -c "$1"; else sh -c "$1"; fi; }
py() { (cd "$APP" && PSONO_HOME=$DIR/home PYTHONPATH=$LIB:$HERE/psono-shims python3 "$@"); }

fetch() { # fetch URL TAG COMMIT DEST: shallow clone of a tag, refuses anything but the pinned commit
  [ -d "$4/.git" ] || git clone -q -c advice.detachedHead=false --depth 1 --branch "$2" "$1" "$4"
  got=$(git -c safe.directory='*' -C "$4" rev-parse HEAD)
  [ "$got" = "$3" ] || { echo "$1 $2: commit $got, expected $3" >&2; exit 1; }
}

# name tag commit repository path-in-repository (linked into $LIB) version-for-metadata
DEPS="django 5.2.8 47fe39af56ecd0ad73b9c7562511015e96b91b80 https://github.com/django/django.git django Django
django-rest-framework 3.16.1 de018df2aaacb1d2d947c0cfbfaa6d08fb50557d https://github.com/encode/django-rest-framework.git rest_framework djangorestframework
asgiref 3.9.1 fbe9506df140a437921a01ea824dbe51d8c38c24 https://github.com/django/asgiref.git asgiref -
sqlparse 0.5.3 ec0af5bf6345750d84274bc5c857d4a75b88619b https://github.com/andialbrecht/sqlparse.git sqlparse -
drf-spectacular 0.28.0 9bf8e9229322472e79aa347ffc69e3f2fbcaa470 https://github.com/tfranzel/drf-spectacular.git drf_spectacular drf-spectacular
inflection 0.5.1 b00d4d348b32ef5823221b20ee4cbd1d2d924462 https://github.com/jpvanhal/inflection.git inflection -
uritemplate 4.1.1 1f7fa333075527f777717a103af25e7e18a8522b https://github.com/python-hyper/uritemplate.git uritemplate -
django-cors-headers 3.10.1 ce4da63f76d8e0402abc635601659eb02094ca73 https://github.com/adamchainz/django-cors-headers.git src/corsheaders django-cors-headers
django-anymail v12.0 35383c7140289e82b39ada5980077898aa07d18d https://github.com/anymail/django-anymail.git anymail django-anymail
pyotp v2.3.0 041f5d3c65379d7188821caf92436c7f226ec60e https://github.com/pyauth/pyotp.git src/pyotp -
py_webauthn v2.7.0 0c8f53b08fdac667587e22d1792f59afa9e8455d https://github.com/duo-labs/py_webauthn.git webauthn webauthn
cbor2 5.6.5 6427d378872f6ea43d1f7053ad40bc1b760727f5 https://github.com/agronholm/cbor2.git cbor2 cbor2
asn1crypto 1.5.1 835365ca6744c7afee793f050faf0a91ddb140b7 https://github.com/wbond/asn1crypto.git asn1crypto -
pyopenssl 26.4.0 07b1ef7cc2ed71c77ebc113d0c10fc045e40861a https://github.com/pyca/pyopenssl.git src/OpenSSL pyOpenSSL
python-yubico-client v1.12.0 d48e67ee587260dc7d6ddc5ee378372ff9323182 https://github.com/Kami/python-yubico-client.git yubico_client -
duo_client_python 5.5.0 b964296308aec1704a7fbabbe4087a059e839c30 https://github.com/duosecurity/duo_client_python.git duo_client -
django-countries v7.6.1 70f7896ae635a644c545f3faa97d076666402279 https://github.com/SmileyChris/django-countries.git django_countries -
django-timezone-field 7.1 268095d7c27b66f042b38bee23714de863472e60 https://github.com/mfogel/django-timezone-field.git timezone_field -
more-itertools v10.5.0 4998a257373f36e91edef7324572ed8df10f39d1 https://github.com/more-itertools/more-itertools.git more_itertools -
ntplib 0.4.0 b9c11c5906bc802a20a2dab390e57c50be558808 https://github.com/cf-natali/ntplib.git ntplib.py -
dj-database-url v2.1.0 9292e1fa8af99a73e6c9cbdd7321236741016c06 https://github.com/jazzband/dj-database-url.git dj_database_url -
psycopg 3.2.3 ce8f07321b8d0f0d95043596cbbbb6fd1e5831e7 https://github.com/psycopg/psycopg.git psycopg/psycopg psycopg
pynacl 1.5.0 ba3638fef06697ce3e1e30abe9bfd93a5ef816fc https://github.com/pyca/pynacl.git - -
libsodium 1.0.18-RELEASE 940ef42797baa0278df6b7fd9e67c7590f87744b https://github.com/jedisct1/libsodium.git - -"

install() {
  [ -f "$DIR/installed" ] && return
  mkdir -p "$DIR/src" "$LIB"
  fetch https://gitlab.com/esaqa/psono/psono-server.git "v$PS_VERSION" "$PS_COMMIT" "$DIR/psono-server"
  echo "$DEPS" | while read -r name tag commit repo path meta; do
    fetch "$repo" "$tag" "$commit" "$DIR/src/$name"
    [ "$path" = - ] || ln -sfn "$DIR/src/$name/$path" "$LIB/$(basename "$path")"
    # packages that ask importlib.metadata for their own version
    if [ "$meta" != - ]; then
      mkdir -p "$LIB/$meta-${tag#v}.dist-info"
      printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "$meta" "${tag#v}" > "$LIB/$meta-${tag#v}.dist-info/METADATA"
    fi
  done
  # PyNaCl: its cffi binding compiled against the system's libsodium, with the headers of the same release
  so=$(ldconfig -p | awk '$1 == "libsodium.so.23" && /x86-64|aarch64/ {print $NF; exit}')
  [ -n "$so" ] || { echo "libsodium.so.23 is missing" >&2; exit 1; }
  inc=$DIR/src/libsodium/src/libsodium/include
  sed -e 's/@VERSION@/1.0.18/; s/@SODIUM_LIBRARY_VERSION_MAJOR@/10/; s/@SODIUM_LIBRARY_VERSION_MINOR@/3/; s/@SODIUM_LIBRARY_MINIMAL_DEF@//' \
    "$inc/sodium/version.h.in" > "$inc/sodium/version.h"
  mkdir -p "$DIR/sodium-lib" && ln -sf "$so" "$DIR/sodium-lib/libsodium.so"
  rm -rf "$LIB/nacl" && cp -r "$DIR/src/pynacl/src/nacl" "$LIB/nacl"
  (cd "$DIR/src/pynacl/src/bindings" && grep -v '^ffi.set_source' build.py > nacl_cdef.py &&
    python3 - "$DIR" "$inc" "$(dirname "$so")" <<'PY'
import os, sys
d, inc, libdir = sys.argv[1:4]
sys.path.insert(0, os.getcwd())
import nacl_cdef as b  # the binding's declarations, as PyNaCl's own build reads them
b.ffi.set_source("nacl._sodium", "\n".join(b.source), libraries=["sodium"], include_dirs=[inc],
                 library_dirs=[d + "/sodium-lib"], runtime_library_dirs=[libdir])
b.ffi.compile(tmpdir=d + "/nacl-build", verbose=False)
PY
  )
  cp "$DIR"/nacl-build/nacl/_sodium*.so "$LIB/nacl/"
  touch "$DIR/installed"
}

case "${1:-start}" in
  start)
    "$0" stop >/dev/null 2>&1 || true
    if [ "$(id -u)" = 0 ] && ! id "$PS_USER" >/dev/null 2>&1; then useradd -r -M -s /bin/sh "$PS_USER"; fi
    install
    rm -rf "$DIR/pgdata" "$DIR/home"
    mkdir -p "$DIR/pgdata" "$DIR/home/.psono_server"
    chmod 700 "$DIR/pgdata"
    [ "$(id -u)" = 0 ] && chown "$PS_USER" "$DIR" "$DIR/pgdata"
    as_pg "$PG_BIN/initdb -D $DIR/pgdata -U postgres --auth=trust -E UTF8 >/dev/null && \
      $PG_BIN/pg_ctl -D $DIR/pgdata -o '-p $PG_PORT -k /tmp -c listen_addresses=127.0.0.1' -l $DIR/pg.log -w start >/dev/null && \
      $PG_BIN/createdb -h 127.0.0.1 -p $PG_PORT -U postgres psono"
    # fresh server keys (Psono's own generator), then the test configuration
    py generateserverkeys.py | grep -E '^(SECRET_KEY|ACTIVATION_LINK_SECRET|DB_SECRET|EMAIL_SECRET_SALT|PRIVATE_KEY|PUBLIC_KEY|ADMIN_RECOVERY_PUBLIC_KEY):' \
      > "$DIR/home/.psono_server/settings.yaml"
    cat >> "$DIR/home/.psono_server/settings.yaml" <<EOF
DEBUG: False
ALLOWED_HOSTS: ['*']
ALLOWED_DOMAINS: ['example.com']
HOST_URL: 'http://127.0.0.1:$PORT'
WEB_CLIENT_URL: 'http://127.0.0.1:$PORT'
EMAIL_FROM: 'psono@example.com'
EMAIL_BACKEND: 'django.core.mail.backends.dummy.EmailBackend'
DISABLE_EMAIL_NEW_LOGIN: True
CACHE_ENABLE: False
ALLOW_REGISTRATION: True
MULTIFACTOR_ENABLED: ${PS_MULTIFACTOR:-False}
THROTTLE_RATE_LOGIN: '10000/day'
THROTTLE_RATE_PRE_LOGIN: '10000/day'
THROTTLE_RATE_GA_VERIFY: '1000/minute'
THROTTLE_RATE_YUBIKEY_OTP_VERIFY: '1000/minute'
THROTTLE_RATE_PASSWORD: '10000/day'
DATABASES:
    default:
        'ENGINE': 'django.db.backends.postgresql'
        'NAME': 'psono'
        'USER': 'postgres'
        'PASSWORD': ''
        'HOST': '127.0.0.1'
        'PORT': '$PG_PORT'
TEMPLATES: [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': ['$APP/templates'], 'APP_DIRS': True, 'OPTIONS': {'context_processors': ['django.template.context_processors.debug', 'django.template.context_processors.request', 'django.contrib.auth.context_processors.auth', 'django.contrib.messages.context_processors.messages']}}]
EOF
    py manage.py migrate > "$DIR/migrate.log" 2>&1 || { tail -20 "$DIR/migrate.log" >&2; exit 1; }
    (cd "$APP" && PSONO_HOME=$DIR/home PYTHONPATH=$LIB:$HERE/psono-shims setsid nohup python3 manage.py runserver --noreload \
      "127.0.0.1:$PORT" > "$DIR/web.log" 2>&1 < /dev/null & echo $! > "$DIR/web.pid")
    for i in $(seq 1 100); do
      curl -fs "http://127.0.0.1:$PORT/info/" >/dev/null 2>&1 && { echo "Psono running: http://127.0.0.1:$PORT"; exit 0; }
      sleep 0.2
    done
    echo "Psono does not start, see $DIR/web.log" >&2; exit 1 ;;
  createuser)
    py manage.py createuser "$2" "$3" "$4" ;;
  manage)
    shift; py manage.py "$@" ;;
  stop)
    [ -f "$DIR/web.pid" ] && kill -- "-$(cat "$DIR/web.pid")" 2>/dev/null || true
    [ -d "$DIR/pgdata" ] && as_pg "$PG_BIN/pg_ctl -D $DIR/pgdata -m fast stop >/dev/null 2>&1" || true
    rm -f "$DIR/web.pid" ;;
esac
