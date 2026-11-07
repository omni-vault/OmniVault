# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
# Test server only (test/psono-server.sh): bcrypt through the system's libcrypt (libxcrypt knows $2b$),
# because the bcrypt package needs a Rust build with crates from crates.io.
import ctypes, ctypes.util, os, base64
_lib = ctypes.CDLL(ctypes.util.find_library("crypt") or "libcrypt.so.1")
_lib.crypt.restype = ctypes.c_char_p
_lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.crypt_gensalt.restype = ctypes.c_char_p
_lib.crypt_gensalt.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int]
def gensalt(rounds=12, prefix=b"2b"):
    rnd = os.urandom(16)
    return _lib.crypt_gensalt(b"$" + prefix + b"$", rounds, rnd, 16)
def hashpw(password, salt):
    if isinstance(password, str): password = password.encode()
    if isinstance(salt, str): salt = salt.encode()
    r = _lib.crypt(password, salt)
    if not r or r.startswith(b"*"): raise ValueError("Invalid salt")
    return r
def checkpw(password, hashed):
    return hashpw(password, hashed) == hashed
