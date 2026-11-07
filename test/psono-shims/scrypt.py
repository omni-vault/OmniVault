# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
# Test server only (test/psono-server.sh): scrypt.hash through hashlib (OpenSSL) instead of the C extension.
import hashlib
def hash(password, salt, N=1 << 14, r=8, p=1, buflen=64):
    if isinstance(password, str): password = password.encode()
    if isinstance(salt, str): salt = salt.encode()
    return hashlib.scrypt(password, salt=salt, n=N, r=r, p=p, dklen=buflen, maxmem=2**31 - 1)
