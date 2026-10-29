#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
#
# Independent check of a password-protected Bitwarden JSON export, written separately from OmniVault's JavaScript:
# derives the file key from the password (PBKDF2-SHA256 with hashlib, Argon2id with `cryptography`), stretches it
# with HKDF-Expand (hmac), checks both MACs and decrypts with AES-256-CBC (`cryptography`).
#
# stdin: {"file": {...the export...}, "password": "..."}
# stdout: {"validation": "<decrypted encKeyValidation_DO_NOT_EDIT>", "data": <decrypted data, parsed>}
# exit 2 on a wrong password (MAC of encKeyValidation_DO_NOT_EDIT does not match)
import base64
import hashlib
import hmac
import json
import re
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def derive(password, salt, f):
    if f.get('kdfType', 0) == 0:
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), int(f['kdfIterations']), 32)
    if f['kdfType'] == 1:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        return Argon2id(salt=hashlib.sha256(salt.encode()).digest(), length=32, iterations=int(f['kdfIterations']),
                        lanes=int(f['kdfParallelism']), memory_cost=int(f['kdfMemory']) * 1024).derive(password.encode())
    raise SystemExit('unknown kdfType %r' % f['kdfType'])


def expand(prk, info):
    # HKDF-Expand (RFC 5869) for one 32-byte block
    return hmac.new(prk, info.encode() + b'\x01', hashlib.sha256).digest()


def open_type2(enc, enc_key, mac_key):
    m = re.fullmatch(r'2\.([^|]+)\|([^|]+)\|([^|]+)', enc)
    if not m:
        raise SystemExit('not an EncString of type 2')
    iv, ct, mac = (base64.b64decode(x) for x in m.groups())
    if not hmac.compare_digest(hmac.new(mac_key, iv + ct, hashlib.sha256).digest(), mac):
        return None
    d = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = d.update(ct) + d.finalize()
    n = padded[-1]
    if not 1 <= n <= 16 or padded[-n:] != bytes([n]) * n:
        raise SystemExit('bad padding')
    return padded[:-n].decode()


def main():
    req = json.load(sys.stdin)
    f, password = req['file'], req['password']
    assert f['encrypted'] is True and f['passwordProtected'] is True
    master = derive(password, f['salt'], f)
    enc_key, mac_key = expand(master, 'enc'), expand(master, 'mac')
    validation = open_type2(f['encKeyValidation_DO_NOT_EDIT'], enc_key, mac_key)
    if validation is None:
        sys.exit(2)
    data = open_type2(f['data'], enc_key, mac_key)
    if data is None:
        raise SystemExit('MAC of data does not match')
    json.dump({'validation': validation, 'data': json.loads(data)}, sys.stdout)


main()
