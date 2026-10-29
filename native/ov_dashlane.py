# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
"""
Dashlane backend via the official Dashlane CLI `dcli` (github.com/Dashlane/dashlane-cli), read only.

Commands run (fixed list, no shell, stdin /dev/null): `dcli --version`, `dcli status`, `dcli sync`,
`dcli password --output json [id=<id>]`, `dcli note --output json [id=<id>]`, `dcli secret --output json [id=<id>]`,
`dcli id --output json [id=<id>]` (personal IDs: identity, passport, ID card, driver's licence, social security and
tax numbers; since dcli 6.2642.0, older versions answer "unknown command" and the IDs are left out).
The JSON output always contains the secrets; the listing drops them here, in the host, before anything goes to the
browser (for IDs it keeps only the type and the holder's name), and `reveal` reads the one entry again. Nothing is
kept between requests. dcli has no command for payment cards, so they cannot be read.
dcli asks interactively when it is not signed in or the vault is locked; with stdin closed that prompt fails, and the
host turns the failure into a clear message (sign in once in the terminal with `dcli sync`).
"""
import json
import re

from ov_common import HostError, run, which

# Dashlane item ids are a UUID in braces: {0A1B2C3D-…}
DL_ID = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
KINDS = {"login": "password", "note": "note", "secret": "secret", "id": "id"}  # OmniVault kind → dcli command
# `dcli id`: the transaction type of each personal ID item
ID_TYPES = ("IDENTITY", "PASSPORT", "IDCARD", "DRIVERLICENCE", "SOCIALSECURITYSTATEMENT", "FISCALSTATEMENT")
# keys of an ID item that are bookkeeping, not content (dcli exposes every field of the item)
ID_INTERNAL = {"id", "anonid", "kwtype", "type", "localeformat", "spaceid", "creationdatetime", "creationdate",
               "usermodificationdatetime", "lastbackuptime", "lastuse", "linkedidentity", "attachments", "checked"}
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

NOT_FOUND = "`dcli` (Dashlane CLI) wurde nicht gefunden."
NOT_SIGNED_IN = "Dashlane: nicht angemeldet. Bitte im Terminal „dcli sync“ ausführen."
LOCKED = ("Dashlane: Der Tresor ist gesperrt. Bitte im Terminal „dcli sync“ ausführen; das Master-Passwort muss "
          "gespeichert sein (dcli configure save-master-password true).")
PROMPT = "dcli wartet auf eine Eingabe. Bitte einmal im Terminal „dcli sync“ ausführen."
BAD_JSON = "Dashlane CLI lieferte kein gültiges JSON"


def dl_bin():
    b = which("dcli", "OMNIVAULT_DCLI_BIN")
    if not b:
        raise HostError(NOT_FOUND)
    return b


def _clean(text):
    return ANSI.sub("", text or "")


def describe(proc):
    """User-facing message for a failed dcli call. dcli prints its prompts and `error: …` lines to stderr."""
    text = _clean((proc.stderr or "") + "\n" + (proc.stdout or ""))
    low = text.lower()
    if "enter your email address" in low or "no device registered" in low:
        return NOT_SIGNED_IN
    if "enter your master password" in low or "master password is incorrect" in low:
        return LOCKED
    if "force closed the prompt" in low:
        return PROMPT
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("error:"):
            return line[len("error:"):].strip() or f"Exit-Code {proc.returncode}"
    line = next((l.strip() for l in text.splitlines() if l.strip()), None)
    return line or f"Exit-Code {proc.returncode}"


def _run(args, check=True):
    return run(dl_bin(), args, check=check, describe=describe)


def _status():
    """`dcli status` prints `Logged in: Yes|No`, then `Login: …` and `Locked: Yes|No`. It never prompts."""
    b = which("dcli", "OMNIVAULT_DCLI_BIN")
    if not b:
        return {"cli": None, "ready": False, "loggedIn": False, "locked": False}
    out = _clean(run(b, ["status"], check=False).stdout)
    fields = {}
    for line in out.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip().lower()] = value.strip()
    logged_in = fields.get("logged in", "").lower() == "yes"
    locked = logged_in and fields.get("locked", "").lower() == "yes"
    return {"cli": b, "loggedIn": logged_in, "locked": locked, "ready": logged_in and not locked,
            "email": fields.get("login") if logged_in else None}


def _require_ready():
    st = _status()
    if not st["cli"]:
        raise HostError(NOT_FOUND)
    if not st["loggedIn"]:
        raise HostError(NOT_SIGNED_IN)
    if st["locked"]:
        raise HostError(LOCKED)


def _parse(stdout):
    """dcli prints the JSON array as one line; warnings (e.g. about the OS keychain) can precede it on stdout."""
    text = _clean(stdout).strip()
    candidates = [text] + [l.strip() for l in reversed(text.splitlines()) if l.strip().startswith("[")]
    for c in candidates:
        try:
            data = json.loads(c or "[]")
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
    raise HostError(BAD_JSON)


class NoIdCommand(Exception):
    """The installed dcli predates `dcli id` (6.2642.0)."""


def _fetch(kind, iid=None):
    args = [KINDS[kind], "--output", "json"]
    if iid is not None:
        args.append(f"id={iid}")  # dcli filter: substring match on the id field; the exact id is picked below
    if kind != "id":
        return _parse(_run(args).stdout)
    proc = _run(args, check=False)
    if proc.returncode != 0:
        if "unknown command 'id'" in _clean(proc.stderr or ""):
            raise NoIdCommand()
        raise HostError(describe(proc))
    return _parse(proc.stdout)


def _text(v):
    return v.strip() if isinstance(v, str) else ""


def _summary(kind, e):
    """What the listing may show: no password, no note text, no OTP secret."""
    iid = _text(e.get("id"))
    if not DL_ID.match(iid):
        return None
    if kind == "login":
        url = _text(e.get("url"))
        username = _text(e.get("login")) or _text(e.get("email")) or _text(e.get("secondaryLogin"))
        return {"id": iid, "kind": kind, "type": "login", "name": _text(e.get("title")) or url,
                "username": username, "uris": [url] if url else [],
                "hasTotp": bool(_text(e.get("otpSecret")) or _text(e.get("otpUrl"))),
                "revision": _text(e.get("modificationDatetime")) or None}
    if kind == "id":
        id_type = _text(e.get("type")).upper()
        if id_type not in ID_TYPES:
            return None
        return {"id": iid, "kind": kind, "type": "identity", "idType": id_type, "name": _holder(e)}
    return {"id": iid, "kind": kind, "type": "note", "name": _text(e.get("title")),
            "revision": _text(e.get("userModificationDatetime")) or _text(e.get("updateDate")) or None}


def _holder(e):
    """Name of the person an ID belongs to (the only content of an ID item the listing shows)."""
    full = _text(e.get("fullname")) or _text(e.get("socialSecurityFullname"))
    if full:
        return full
    parts = [_text(e.get(k)) for k in ("firstName", "middleName", "lastName", "lastName2")]
    return " ".join(p for p in parts if p)


def _id_fields(e):
    """Every content field of an ID item as text (dcli names them after Dashlane's keys: number, expireDate, …)."""
    return {k: v.strip() for k, v in e.items()
            if isinstance(k, str) and isinstance(v, str) and v.strip() and k.lower() not in ID_INTERNAL}


def dl_status(_a):
    return _status()


def dl_sync(_a):
    _require_ready()
    _run(["sync"])
    return {"synced": True}


def dl_list(a):
    _require_ready()
    if a.get("sync"):
        _run(["sync"])
    items = []
    no_ids = False
    for kind in KINDS:
        try:
            entries = _fetch(kind)
        except NoIdCommand:
            no_ids = True
            continue
        for e in entries:
            s = _summary(kind, e)
            if s:
                items.append(s)
    return {"items": items, **({"idsUnavailable": True} if no_ids else {})}


def dl_reveal(a):
    iid = a.get("id")
    if not isinstance(iid, str) or not DL_ID.match(iid):
        raise HostError("Ungültige Eintrags-ID")
    kind = a.get("kind") or "login"
    if kind not in KINDS:
        raise HostError("Ungültige Eintragsart")
    _require_ready()
    try:
        found = _fetch(kind, iid)
    except NoIdCommand:
        found = []
    e = next((x for x in found if _text(x.get("id")).lower() == iid.lower()), None)
    if e is None:
        raise HostError("Eintrag nicht gefunden")
    out = _summary(kind, e)
    if kind == "login":
        username = out["username"]
        extra = []
        for key in ("email", "secondaryLogin"):
            value = _text(e.get(key))
            if value and value != username and value not in (f["value"] for f in extra):
                extra.append({"name": key, "value": value})
        out.update(password=e.get("password") or "", notes=e.get("note") or "",
                   totp=_text(e.get("otpUrl")) or _text(e.get("otpSecret")), fields=extra)
    elif kind == "id":
        if out is None:
            raise HostError("Eintrag nicht gefunden")
        out.update(data=_id_fields(e))
    else:
        out.update(notes=e.get("content") or "")
    return out


COMMANDS = {"status": dl_status, "sync": dl_sync, "list": dl_list, "reveal": dl_reveal}
