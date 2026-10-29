#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Copyright (c) 2026 Die OmniVault-Mitwirkenden
"""
Self-test of the OmniVault host against YOUR own, unlocked CLI session.

  python3 selftest.py pass                         # read-only
  python3 selftest.py dashlane                     # Dashlane is read only (no --write); also lists the field names
                                                   # of personal IDs (never their values)
  python3 selftest.py gopass --write               # gopass: also create, edit, move and delete a throw-away entry
  python3 selftest.py onepassword --write          # also create, edit and delete throw-away entries
                                                   # (1Password: a login, a card and an identity)
  python3 selftest.py proton --write --vault OmniVault-Test   # Proton: use an EMPTY test vault

Prints only counts, types and ok/fail – never titles, user names or secrets – so the output can be shared.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import omnivault_host  # noqa: E402
from ov_common import HostError  # noqa: E402

results = []
NAME = "OmniVault-Selftest"


def step(name, fn):
    t = time.time()
    try:
        info = fn()
        results.append(True)
        print(f"ok    {name} ({time.time() - t:.1f} s){f' – {info}' if info else ''}")
        return True
    except Exception as e:  # report and continue
        results.append(False)
        print(f"FAIL  {name}: {e}")
        return False


def finish():
    print(f"\n{results.count(True)} ok, {results.count(False)} failed")
    sys.exit(0 if all(results) else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("backend", choices=sorted(omnivault_host.BACKENDS))
    ap.add_argument("--write", action="store_true", help="create, edit and delete a throwaway entry")
    ap.add_argument("--vault", help="Proton: name of the (empty) test vault for --write")
    ap.add_argument("--limit", type=int, default=25, help="check this many entries for attachments, history, passkeys (default 25)")
    a = ap.parse_args()
    cmd = omnivault_host.BACKENDS[a.backend]
    proton = a.backend == "proton"
    # Proton addresses items by vault (shareId) + itemId, the other backends by a single id.
    ref = (lambda it: {"shareId": it["shareId"], "itemId": it["itemId"]}) if proton else (lambda it: {"id": it["id"], **({"kind": it["kind"]} if it.get("kind") else {})})
    state = {}

    def status():
        st = cmd["status"]({})
        if not st.get("cli"):
            raise RuntimeError("program not found")
        if not (st.get("loggedIn") or st.get("ready")):
            raise RuntimeError("not signed in or not initialized")
        if st.get("locked"):
            raise RuntimeError("signed in, but locked")
        return st.get("cli")

    def listing():
        r = cmd["list"]({})
        state["list"] = r
        types = {}
        for it in r["items"]:
            types[it.get("type", "login")] = types.get(it.get("type", "login"), 0) + 1
        return f"{len(r['items'])} entries {types}"

    def reveal():
        items = state["list"]["items"]
        if not items:
            return "no entries"
        # one entry of each kind (Dashlane: logins, notes and secrets come from different dcli commands)
        firsts = {}
        for it in items:
            firsts.setdefault(it.get("kind", ""), it)
        out = []
        for kind, it in firsts.items():
            got = cmd["reveal"](ref(it))
            filled = sorted(k for k, v in got.items() if v not in (None, '', [], {}))
            out.append(f"{kind + ': ' if kind else ''}{filled}")
        return "fields: " + "; ".join(out)

    def extras():
        """Attachments, password history and passkeys over a sample of entries (only counts are printed). The
        first attachment found is downloaded once and only its size is compared."""
        if "attachment" not in cmd:
            return "skipped (provider has no attachments via the CLI)"
        sample = state["list"]["items"][:a.limit]
        counts = {"entries checked": 0, "with attachments": 0, "attachments": 0, "with password history": 0, "with passkeys": 0}
        first = None
        for it in sample:
            got = cmd["reveal"](ref(it))
            counts["entries checked"] += 1
            att = got.get("attachments") or []
            counts["attachments"] += len(att)
            counts["with attachments"] += bool(att)
            counts["with password history"] += bool(got.get("passwordHistory"))
            counts["with passkeys"] += bool(got.get("passkeys") or it.get("passkeys"))
            if att and first is None:
                first = (it, att[0])
        state["attachment"] = first
        return ", ".join(f"{k}: {v}" for k, v in counts.items())

    def download():
        if not state.get("attachment"):
            return "skipped (no attachment in the sample; check more with --limit)"
        it, meta = state["attachment"]
        got = cmd["attachment"]({**ref(it), "fileId": meta["id"]})
        size = len(__import__("base64").b64decode(got["data"]))
        if meta.get("size") and meta["size"] != size:
            raise RuntimeError(f"size {size} B instead of {meta['size']} B")
        return f"{size} B"

    if not step("Status", status):
        finish()
    if a.backend == "dashlane":
        step("Sync with the server (dcli sync)", lambda: cmd["sync"]({}) and None)
    def personal_ids():
        """Dashlane: personal IDs from `dcli id` (since 6.2642.0). Prints per type how many there are and which field
        NAMES dcli delivers (never their values), so the mapping can be checked against a real vault."""
        r = state["list"]
        if r.get("idsUnavailable"):
            return "skipped (this dcli has no `id` command; needs 6.2642.0 or later)"
        ids = [it for it in r["items"] if it.get("kind") == "id"]
        for it in ids:
            if set(it) - {"id", "kind", "type", "idType", "name"}:
                raise RuntimeError(f"listing carries more than type and holder: {sorted(set(it))}")
        seen = {}
        for it in ids:
            keys = seen.setdefault(it["idType"], {"count": 0, "fields": set()})
            keys["count"] += 1
            if keys["count"] == 1:  # one reveal per type is enough
                keys["fields"] = set(cmd["reveal"](ref(it)).get("data", {}))
        return "; ".join(f"{t}: {v['count']} ({', '.join(sorted(v['fields'])) or 'no fields'})" for t, v in sorted(seen.items())) or "no personal IDs"

    if step("List without secrets", listing):
        step("Fetch a secret", reveal)
        if a.backend == "dashlane":
            step("Personal IDs (dcli id): types and field names", personal_ids)
        step("Count attachments, password history, passkeys", extras)
        step("Download an attachment (size only)", download)
    if a.write and "create" not in cmd:
        print(f"--write skipped: {a.backend} is read-only via the CLI")
    if not a.write or "create" not in cmd:
        finish()

    created = {}
    if proton:
        vaults = {v["name"]: v["shareId"] for v in state["list"]["vaults"]}
        if a.vault not in vaults:
            print(f"FAIL  test vault \"{a.vault}\" not found – create it empty and pass it with --vault")
            results.append(False)
            finish()
        share = vaults[a.vault]

    def create():
        if proton:
            r = cmd["create"]({"shareId": share, "type": "login", "title": NAME, "username": "selftest",
                               "password": "Selftest-1!", "urls": ["https://example.org"]})
            created.update(shareId=share, itemId=r["itemId"])
        else:
            r = cmd["create"]({"type": "login", "name": NAME, "username": "selftest", "password": "Selftest-1!",
                               "uris": ["https://example.org"], "notes": "Note", "folder": None})
            created["id"] = r.get("id") or next(i["id"] for i in cmd["list"]({})["items"] if i.get("name") == NAME)
        return None

    def update():
        if proton:
            cmd["update"]({**created, "fields": {"password": "Selftest-2!"}})
        else:
            cmd["update"]({**created, "name": NAME, "username": "selftest", "password": "Selftest-2!",
                           "uris": ["https://example.org"], "notes": "Note", "folder": None})
        assert cmd["reveal"](created).get("password") == "Selftest-2!", "password not changed"
        return None

    def conflict():
        """The host must refuse an edit based on an outdated revision (item changed elsewhere meanwhile)."""
        if a.backend in ("pass", "gopass"):
            return f"skipped ({a.backend} has no revision)"
        rev = cmd["reveal"](created).get("revision")
        if not rev:
            raise RuntimeError("the program reports no revision – conflict detection does not apply")
        stale = {"revision": "outdated-0"}
        try:
            if proton:
                cmd["update"]({**created, **stale, "fields": {"password": "Selftest-3!"}})
            else:
                cmd["update"]({**created, **stale, "name": NAME, "username": "selftest", "password": "Selftest-3!",
                               "uris": ["https://example.org"], "notes": "Note", "folder": None})
        except HostError as e:
            if e.code == "conflict":
                return "outdated revision is rejected"
            raise
        raise RuntimeError("an outdated revision was overwritten")

    def move():
        other = next((s for n, s in vaults.items() if n != a.vault), None)
        if not other:
            return "skipped (only one vault)"
        there = cmd["move"]({**created, "toShareId": other})
        back = cmd["move"]({"shareId": other, "itemId": there["itemId"], "toShareId": share})
        created["itemId"] = back["itemId"] or created["itemId"]
        return "there and back"

    def move_folder():
        r = cmd["move"]({**created, "name": NAME, "folder": f"{NAME}-Folder"})
        assert cmd["reveal"]({"id": r["id"]}).get("password") == "Selftest-2!", "content changed after moving"
        created["id"] = r["id"]
        return None

    def delete():
        cmd["delete"](created)
        return "trash" if proton else "deleted"

    if step("Create (secrets via stdin)", create):
        step("Edit", update)
        step("Conflict detection (program revision)", conflict)
        if proton:
            step("Move to another vault", move)
        if a.backend == "gopass":
            step("Move into a subfolder (gopass mv)", move_folder)
        step("Delete", delete)
    if a.backend == "onepassword":
        typed_items(cmd)
    finish()


CARD = {"cardholderName": "Self Test", "number": "4111111111111111", "code": "123", "expMonth": "07", "expYear": "2031"}
IDENTITY = {"firstName": "Self", "middleName": "T", "lastName": "Test", "company": "Example Inc.",
            "email": "selftest@example.com", "phone": "+49 30 000000", "username": "selftest"}


def typed_items(cmd):
    """1Password: a card and an identity from the category templates of the installed `op` – created, read back,
    edited and deleted. Compares values, prints only which fields matched."""
    for kind, data, change in (("card", CARD, {"code": "456", "expMonth": "12", "expYear": "2032"}),
                               ("identity", IDENTITY, {"phone": "+49 30 111111", "company": "Example Corp."})):
        label = "Card" if kind == "card" else "Identity"
        made = {}

        def create():
            r = cmd["create"]({"type": kind, "name": f"{NAME} {label}", "notes": "Note", kind: data})
            made["id"] = r["id"]
            return None

        def check(expected):
            got = (cmd["reveal"](made).get(kind) or {})
            wrong = sorted(k for k, v in expected.items() if str(got.get(k) or "") != v)
            if wrong:
                raise RuntimeError(f"fields differ: {wrong}")
            return f"{len(expected)} fields match"

        def update():
            current = cmd["reveal"](made)
            cmd["update"]({**made, "type": kind, "name": f"{NAME} {label}", "notes": "Note", "revision": current.get("revision"),
                           kind: {**(current.get(kind) or {}), **change}})
            return check({**data, **change})

        if step(f"Create {label.lower()} from the op template", create):
            step(f"Read {label.lower()} back", lambda: check(data))
            step(f"Edit {label.lower()}", update)
            step(f"Delete {label.lower()}", lambda: cmd["delete"](made) and None)


if __name__ == "__main__":
    main()
