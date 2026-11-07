# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
# Writes test/fixtures/psono-vectors.json with the Psono server's own functions (PyNaCl/libsodium, scrypt):
#   test/psono-server.sh manage shell -c "exec(open('$PWD/test/fixtures/make-psono-vectors.py').read())" | sed -n '/^{/,$p' > test/fixtures/psono-vectors.json
import json, binascii, nacl.secret, nacl.public, nacl.signing, nacl.encoding, nacl.utils
from restapi.utils.various import generate_authkey, encrypt_secret, encrypt_symmetric
H = nacl.encoding.HexEncoder
out = {}
out["authkey"] = {"username": "Alice@Example.com", "password": "Correct horse 1", "params": {"u": 14, "r": 8, "p": 1, "l": 64},
  "authkey": generate_authkey("Alice@Example.com", "Correct horse 1", 14, 8, 1, 64).decode()}
sauce = "6f6d6e697661756c742d7465737473" * 2
priv = nacl.public.PrivateKey.generate()
privhex = priv.encode(encoder=H)
text, nonce = encrypt_secret(privhex, "pässwörd ✓", sauce.encode(), 14, 8, 1, 64)
out["encrypt_secret"] = {"password": "pässwörd ✓", "user_sauce": sauce, "params": {"u": 14, "r": 8, "p": 1, "l": 64},
  "text": text.decode(), "nonce": nonce.decode(), "plaintext": privhex.decode()}
key = binascii.hexlify(nacl.utils.random(32)).decode()
e = encrypt_symmetric(key, json.dumps({"hello": "wörld"}).encode())
out["secretbox"] = {"key": key, "text": e["text"].decode() if isinstance(e["text"], bytes) else e["text"], "nonce": e["nonce"].decode() if isinstance(e["nonce"], bytes) else e["nonce"], "plaintext": json.dumps({"hello": "wörld"})}
a = nacl.public.PrivateKey.generate(); b = nacl.public.PrivateKey.generate()
n = nacl.utils.random(24)
c = nacl.public.Box(a, b.public_key).encrypt(b"login info \xe2\x9c\x93", n)[24:]
out["box"] = {"sender_public": a.public_key.encode(encoder=H).decode(), "recipient_private": b.encode(encoder=H).decode(),
  "text": binascii.hexlify(c).decode(), "nonce": binascii.hexlify(n).decode(), "plaintext": "login info ✓"}
sk = nacl.signing.SigningKey(binascii.unhexlify(privhex))
info = json.dumps({"version": "test", "public_key": priv.public_key.encode(encoder=H).decode()})
out["signature"] = {"info": info, "verify_key": sk.verify_key.encode(encoder=H).decode(),
  "signature": binascii.hexlify(sk.sign(info.encode()))[:128].decode()}
print(json.dumps(out, indent=1, ensure_ascii=False))
