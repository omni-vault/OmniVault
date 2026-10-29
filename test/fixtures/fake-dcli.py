#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
"""Test double for the Dashlane CLI `dcli` 6.x (subset used by OmniVault). State in $FAKE_DCLI_STATE.

Formats follow the public documentation and the open-source CLI: `password|note|secret --output json` print one JSON
array of the decrypted items (keys = Dashlane field names with a lower-case first letter), filters are `key=value`
(case-insensitive substring; without a key: url/title for passwords, title otherwise). Without a signed-in device
or with a locked vault dcli prompts on stderr; with stdin closed the prompt fails like the real 6.2642.0 binary:
`error: User force closed the prompt with 0 null`, exit code 1. `dcli status` never prompts.
`id --output json` (since 6.2642.0) prints the personal ID items: every field of the item's XML (`KWDataItem key=…`,
first letter lower-cased) plus `kwType` (root element, e.g. KWPassport) and `type` (transaction type, e.g. PASSPORT);
filters default to type/fullname/firstName/lastName/number/idNumber. There is no command for payment cards.
$FAKE_DCLI_MODE: "ok" (default), "logged-out", "locked"; $FAKE_DCLI_WARN=1 prints a keychain warning on stdout first;
$FAKE_DCLI_NO_ID=1 behaves like dcli before 6.2642.0 (no `id` command).
"""
import json
import os
import sys

STATE = os.environ["FAKE_DCLI_STATE"]
LOG = os.environ.get("FAKE_DCLI_LOG")
MODE = os.environ.get("FAKE_DCLI_MODE", "ok")

GH = "{6A1C3E0B-2F4D-4B7A-9C11-0D2E3F4A5B6C}"
SHOP = "{7B2D4F1C-3A5E-4C8B-8D22-1E3F4A5B6C7D}"
APP = "{8C3E5A2D-4B6F-4D9C-9E33-2F4A5B6C7D8E}"
NOTE = "{9D4F6B3E-5C7A-4EAD-AF44-3A5B6C7D8E9F}"
SECRET = "{AE5A7C4F-6D8B-4FBE-B055-4B6C7D8E9FA0}"
IDENT = "{B06B8D5A-7E9C-4A0F-8166-5C7D8E9FA0B1}"
PASSPORT = "{C17C9E6B-8FAD-4B1A-9277-6D8E9FA0B1C2}"
IDCARD = "{D28DAF7C-9ABE-4C2B-A388-7E9FA0B1C2D3}"
LICENCE = "{E39EB08D-ABCF-4D3C-B499-8FA0B1C2D3E4}"
SOCIAL = "{F4AFC19E-BCD0-4E4D-85AA-9AB1C2D3E4F5}"
FISCAL = "{05B0D2AF-CDE1-4F5E-96BB-AB12C3D4E5F6}"


def personal(iid, tx_type, kw_type, **fields):
    base = {"id": iid, "anonId": "anon-" + iid[1:9], "creationDatetime": "1750000000", "localeFormat": "DE",
            "spaceId": "", "userModificationDatetime": "1760000400", "lastBackupTime": "1760000000"}
    return {**base, **fields, "kwType": kw_type, "type": tx_type}


def cred(iid, title, url, login, email, password, note="", otp_secret=None, otp_url=None, secondary=""):
    c = {"anonId": "anon-" + iid[1:9], "autoLogin": "true", "autoProtected": "false", "category": "", "checked": "false",
         "email": email, "id": iid, "lastBackupTime": "1760000000", "lastUse": "1760000100", "localeFormat": "UNIVERSAL",
         "login": login, "modificationDatetime": "1760000200", "note": note, "numberUse": "3", "password": password,
         "secondaryLogin": secondary, "status": "ACCOUNT_VERIFIED", "strength": "80", "subdomainOnly": "false",
         "title": title, "url": url, "useFixedUrl": "false"}
    if otp_secret is not None:
        c["otpSecret"] = otp_secret
    if otp_url is not None:
        c["otpUrl"] = otp_url
    return c


def text_item(iid, title, content):
    return {"anonId": "anon-" + iid[1:9], "category": "", "content": content, "creationDate": "1750000000",
            "creationDateTime": "1750000000", "id": iid, "lastBackupTime": "1760000000", "localeFormat": "UNIVERSAL",
            "secured": "false", "spaceId": "", "title": title, "type": "GRAY", "updateDate": "1760000300",
            "userModificationDatetime": "1760000300"}


def load():
    if not os.path.exists(STATE):
        seed = {
            "login": "ada@example.com",
            "password": [
                cred(GH, "GitHub", "https://github.com", "ada", "ada@example.com", "dl-secret", "Wiederherstellung im Safe",
                     otp_secret="JBSWY3DPEHPK3PXP"),
                cred(SHOP, "", "https://shop.example", "", "kunde@example.com", "shop-pw",
                     otp_url="otpauth://totp/Shop:kunde?secret=GEZDGNBVGY3TQOJQ&issuer=Shop"),
                cred(APP, "App", "", "app-user", "", "app-pw", secondary="team-42"),
            ],
            "note": [text_item(NOTE, "WLAN zuhause", "SSID: Haus\nSchlüssel: wlan-geheim")],
            "secret": [text_item(SECRET, "deploy.key", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")],
            "id": [
                personal(IDENT, "IDENTITY", "KWIdentity", title="MS", firstName="Ada", middleName="Augusta", lastName="King",
                         lastName2="", pseudo="ada", birthDate="1815-12-10", birthPlace="London"),
                personal(PASSPORT, "PASSPORT", "KWPassport", fullname="Ada King", sex="FEMALE", dateOfBirth="1815-12-10",
                         number="C01X00T47", deliveryDate="2020-03-01", expireDate="2030-02-28", deliveryPlace="Berlin",
                         linkedIdentity=IDENT),
                personal(IDCARD, "IDCARD", "KWIDCard", fullname="Ada King", sex="FEMALE", dateOfBirth="1815-12-10",
                         number="L01X00T48", deliveryDate="2021-05-01", expireDate="2031-04-30", linkedIdentity=IDENT),
                personal(LICENCE, "DRIVERLICENCE", "KWDriverLicence", fullname="Ada King", sex="FEMALE",
                         dateOfBirth="1815-12-10", number="B072RRE2I55", deliveryDate="2019-01-15", expireDate="2034-01-14",
                         state="BE", linkedIdentity=IDENT),
                personal(SOCIAL, "SOCIALSECURITYSTATEMENT", "KWSocialSecurityStatement", socialSecurityFullname="Ada King",
                         socialSecurityNumber="65101215K007", sex="FEMALE", dateOfBirth="1815-12-10"),
                personal(FISCAL, "FISCALSTATEMENT", "KWFiscalStatement", fullname="", fiscalNumber="86095742719",
                         teledeclarantNumber="TD-4711", taxOffice="Finanzamt Mitte"),
            ],
            "syncs": 0,
        }
        save(seed)
    with open(STATE, encoding="utf-8") as f:
        return json.load(f)


def save(state):
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(state, f)


def log(argv):
    if LOG:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(" ".join(argv) + "\n")


def prompt(message):
    """Like @inquirer/prompts on a closed stdin: the question goes to stderr, then the prompt is aborted."""
    sys.stderr.write(f"\x1b[34m?\x1b[39m \x1b[1m{message}\x1b[22m\x1b[36G\n\x1b[?25h")
    sys.stderr.write("\x1b[31merror: User force closed the prompt with 0 null\x1b[0m\n")
    sys.exit(1)


def unlock():
    if MODE == "logged-out":
        prompt("Please enter your email address:")
    if MODE == "locked":
        prompt("Please enter your master password:")


def matches(item, filters, default_keys):
    for f in filters:
        key, sep, value = f.partition("=")
        keys = key.split(",") if sep else default_keys
        value = (value if sep else key).lower()
        if not any(isinstance(item.get(k), str) and value in item[k].lower() for k in keys):
            return False
    return True


def main():
    argv = sys.argv[1:]
    log(argv)
    if argv in (["--version"], ["-V"]):
        print("6.2642.0")
        return
    if not argv:
        sys.stderr.write("Usage: dcli [options] [command]\n")
        sys.exit(1)
    cmd, rest = argv[0], argv[1:]
    state = load()
    if cmd == "status":
        if MODE == "logged-out":
            print("Logged in: No")
            return
        print("Logged in: Yes")
        print(f"Login: {state['login']}")
        print(f"Locked: {'Yes' if MODE == 'locked' else 'No'}")
        return
    if cmd in ("sync", "s"):
        unlock()
        state["syncs"] += 1
        save(state)
        print("\x1b[32m✔ \x1b[0mSuccessfully synced")
        return
    names = {"password": "password", "p": "password", "note": "note", "n": "note", "secret": "secret"}
    if os.environ.get("FAKE_DCLI_NO_ID") != "1":
        names["id"] = "id"
    if cmd in names:
        kind = names[cmd]
        output, filters, i = None, [], 0
        while i < len(rest):
            if rest[i] in ("-o", "--output"):
                output = rest[i + 1]
                i += 2
                continue
            if rest[i].startswith("-"):
                sys.stderr.write(f"\x1b[31merror: unknown option '{rest[i]}'\x1b[0m\n")
                sys.exit(1)
            filters.append(rest[i])
            i += 1
        allowed = ["clipboard", "console", "json"] if kind == "password" else ["text", "json"]
        if output not in allowed:
            sys.stderr.write(f"\x1b[31merror: option '-o, --output <type>' argument '{output}' is invalid.\x1b[0m\n")
            sys.exit(1)
        if output != "json":
            sys.stderr.write("\x1b[31merror: the simulated dcli only supports --output json\x1b[0m\n")
            sys.exit(1)
        unlock()
        if os.environ.get("FAKE_DCLI_WARN") == "1":
            print("\x1b[33mwarn: \x1b[0mUnable to reach OS keychain because of error: \"no backend\"")
        default = {"password": ["url", "title"], "id": ["type", "fullname", "firstName", "lastName", "number", "idNumber"]}.get(kind, ["title"])
        print(json.dumps([x for x in state[kind] if matches(x, filters, default)]))
        return
    sys.stderr.write(f"\x1b[31merror: unknown command '{cmd}'\x1b[0m\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
