#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
#
# Independent check of a Bitwarden Send link, written separately from OmniVault's JavaScript: takes the link and
# what the server's access endpoint returned, derives the content key from the key in the link and decrypts.
# Standard library plus `cryptography` (AES-CBC only).
#
# stdin: {"link": "...", "access": {...}, "password": "..."?, "file": "<base64 of the encrypted file>"?}
# stdout: {"name": "...", "text": "...", "fileName": "...", "file": "<base64 plain>", "passwordHash": "..."}
import base64
import hashlib
import hmac
import json
import re
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def content_key(send_key):
    # HKDF-SHA256 (RFC 5869): extract with salt "bitwarden-send", expand with info "send" to 64 bytes
    prk = hmac.new(b"bitwarden-send", send_key, hashlib.sha256).digest()
    okm, block, i = b"", b"", 1
    while len(okm) < 64:
        block = hmac.new(prk, block + b"send" + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:32], okm[32:64]


def aes_cbc_open(enc_key, mac_key, iv, ct, mac):
    if not hmac.compare_digest(hmac.new(mac_key, iv + ct, hashlib.sha256).digest(), mac):
        raise ValueError("MAC mismatch")
    d = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = d.update(ct) + d.finalize()
    pad = padded[-1]
    if pad < 1 or pad > 16 or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return padded[:-pad]


def open_enc_string(s, keys):
    if not s:
        return ""
    kind, rest = s.split(".", 1)
    if kind != "2":
        raise ValueError("unexpected EncString type " + kind)
    iv, ct, mac = (base64.b64decode(p) for p in rest.split("|"))
    return aes_cbc_open(*keys, iv, ct, mac).decode("utf-8")


def main():
    req = json.load(sys.stdin)
    m = re.search(r"#/?(?:send/)?([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)/?$", req["link"])
    if not m:
        raise SystemExit("not a Send link")
    send_key = b64url_decode(m.group(2))
    if len(send_key) != 16:
        raise SystemExit("Send key must be 16 bytes")
    keys = content_key(send_key)
    access = req.get("access") or {}
    access = {k[0].lower() + k[1:]: v for k, v in access.items()}
    out = {"accessId": m.group(1), "name": open_enc_string(access.get("name"), keys)}
    text = access.get("text") or {}
    if text:
        out["text"] = open_enc_string(text.get("text") or text.get("Text"), keys)
    f = access.get("file") or {}
    if f:
        out["fileName"] = open_enc_string(f.get("fileName") or f.get("FileName"), keys)
    if req.get("file"):
        b = base64.b64decode(req["file"])
        if b[0] != 2:
            raise SystemExit("unexpected file format")
        out["file"] = base64.b64encode(aes_cbc_open(*keys, b[1:17], b[49:], b[17:49])).decode()
    if req.get("password") is not None:
        out["passwordHash"] = base64.b64encode(
            hashlib.pbkdf2_hmac("sha256", req["password"].encode("utf-8"), send_key, 100_000, 32)).decode()
    json.dump(out, sys.stdout)


main()
