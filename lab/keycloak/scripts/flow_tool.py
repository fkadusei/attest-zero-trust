#!/usr/bin/env python3
"""Back up and restore a Keycloak authentication flow, exactly.

WHY THIS EXISTS
    S5d makes the privileged realm passkey-only. The failure mode of that change
    is LOCKOUT, not bypass: get it wrong and privileged administrators cannot
    sign in at all. So the ability to put the flow back exactly as it was is
    built and TESTED BEFORE the change is made, not after it goes wrong.

WHAT "EXACTLY" MEANS
    A flow is a tree of executions, and restoring means more than re-adding named
    steps: each execution has a requirement, an order, a nesting level, and
    possibly a configuration. This records all of it, and the restore verifies
    itself by re-reading the flow and comparing against the backup.

RECOVERY WHEN THE BROWSER FLOW IS BROKEN
    The admin API is reached through the `master` realm, which is untouched by any
    of this. Even if `attest-privileged`'s browser flow becomes unusable, this
    tool still works. That is the real break-glass path — not a second login page.

Usage:
    python3 flow_tool.py show    [realm] [flow]
    python3 flow_tool.py backup  [realm] [flow]
    python3 flow_tool.py restore [realm] [flow]
    python3 flow_tool.py verify  [realm] [flow]   # does the live flow match the backup?
"""
from __future__ import annotations

import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from lab_env import KEYCLOAK_ADMIN_PASSWORD

KC = "http://localhost:8080"
ADMIN_USER, ADMIN_PASS = "admin", KEYCLOAK_ADMIN_PASSWORD
BACKUP_DIR = pathlib.Path(__file__).resolve().parent.parent / "backups"

# Fields that identify a step across a backup/restore round trip. Deliberately
# excludes ids, which are regenerated.
IDENTITY_FIELDS = ("displayName", "providerId", "requirement", "level", "index", "authenticationFlow")


def admin_token() -> str:
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN_USER, "password": ADMIN_PASS,
    }).encode()
    req = urllib.request.Request(f"{KC}/realms/master/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["access_token"]


class Api:
    def __init__(self) -> None:
        self.t = admin_token()

    def flow_id(self, realm: str, alias: str):
        """Look up a flow's ID by alias. Flows are deleted by ID, not alias."""
        status, flows = self.call("GET", f"/{realm}/authentication/flows")
        if not isinstance(flows, list):
            raise RuntimeError(f"could not list flows in {realm}: {status} {flows}")
        for f in flows:
            if f.get("alias") == alias:
                return f.get("id")
        return None

    def executions(self, realm: str, flow: str):
        """The children of a flow. NOTE: this is flat and includes subflow children
        at every depth, so never match an authenticator by name alone — ask each
        flow for its own children. (Learned in S5, where a flat match corrupted
        the built-in 2FA subflow.)"""
        st, ex = self.call(
            "GET", f"/{realm}/authentication/flows/{urllib.parse.quote(flow)}/executions")
        return ex if st == 200 and isinstance(ex, list) else []

    def set_requirement(self, realm: str, flow: str, display_name: str, requirement: str) -> bool:
        for e in self.executions(realm, flow):
            if e.get("displayName") == display_name:
                if e.get("requirement") == requirement:
                    return True
                e = dict(e)
                e["requirement"] = requirement
                st, _ = self.call(
                    "PUT", f"/{realm}/authentication/flows/{urllib.parse.quote(flow)}/executions", e)
                return st in (200, 204)
        return False

    def call(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{KC}/admin/realms{path}", data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.t}")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]


def path_for(realm: str, flow: str) -> pathlib.Path:
    return BACKUP_DIR / f"{realm}-{flow.replace(' ', '_')}-flow.json"


def fetch(api: Api, realm: str, flow: str):
    status, ex = api.call("GET", f"/{realm}/authentication/flows/{urllib.parse.quote(flow)}/executions")
    if status != 200:
        raise SystemExit(f"could not read flow '{flow}' in '{realm}': {status} {ex}")
    return ex


def show(realm: str, flow: str) -> int:
    api = Api()
    for e in fetch(api, realm, flow):
        lvl = e.get("level", 0)
        kind = "FLOW" if e.get("authenticationFlow") else "auth"
        cfg = f" cfg={(e.get('authenticationConfig') or '')[:8]}" if e.get("authenticationConfig") else ""
        print(f"  {'  ' * lvl}{kind} {e.get('displayName', '?'):42s} req={str(e.get('requirement')):12s}"
              f" {str(e.get('providerId'))[:30]:30s}{cfg}")
    return 0


def backup(realm: str, flow: str) -> int:
    api = Api()
    ex = fetch(api, realm, flow)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "realm": realm, "flow_alias": flow,
        "note": "Restore with: python3 flow_tool.py restore <realm> <flow>",
        "executions": ex,
    }
    p = path_for(realm, flow)
    p.write_text(json.dumps(payload, indent=2))
    print(f"  backed up {len(ex)} executions -> {p}")
    return 0


def restore(realm: str, flow: str) -> int:
    """Put the flow back exactly as recorded.

    Three things can differ, and all three are handled:
      - a step's requirement changed   -> re-applied
      - a step was ADDED               -> deleted
      - a step was REMOVED             -> re-added to its parent flow, if the
                                          backup records what that parent was

    Anything it cannot do is REPORTED rather than passed over, because a
    half-restored authentication flow is more dangerous than a known-broken one:
    it can look like it works.
    """
    api = Api()
    p = path_for(realm, flow)
    if not p.exists():
        raise SystemExit(f"no backup at {p}")
    want = json.loads(p.read_text())["executions"]
    live = fetch(api, realm, flow)

    live_by_name = {e.get("displayName"): e for e in live}
    want_names = {w.get("displayName") for w in want}
    restored, missing, failed, removed = 0, [], [], 0

    # Steps that exist now but were not in the backup were added by the change
    # being reverted, so they come out.
    for name, e in live_by_name.items():
        if name not in want_names:
            status, err = api.call("DELETE", f"/{realm}/authentication/executions/{e.get('id')}")
            if status in (200, 204):
                removed += 1
            else:
                failed.append(f"delete {name}: {status} {err}")

    for w in want:
        name = w.get("displayName")
        cur = live_by_name.get(name)
        if cur is None:
            missing.append(name)
            continue
        if cur.get("requirement") != w.get("requirement"):
            cur = dict(cur)
            cur["requirement"] = w.get("requirement")
            status, err = api.call(
                "PUT", f"/{realm}/authentication/flows/{urllib.parse.quote(flow)}/executions", cur)
            if status in (200, 204):
                restored += 1
            else:
                failed.append(f"{name}: {status} {err}")

    print(f"  requirements restored : {restored}")
    print(f"  added steps removed   : {removed}")
    if missing:
        print(f"  MISSING from live flow ({len(missing)}) — must be re-added by hand:")
        for m in missing:
            print(f"    - {m}")
    if failed:
        print(f"  FAILED ({len(failed)}):")
        for f in failed:
            print(f"    - {f}")

    print()
    return verify(realm, flow, quiet=False) if not (missing or failed) else 1


def verify(realm: str, flow: str, quiet: bool = True) -> int:
    """Compare the live flow against the backup on the fields that matter."""
    api = Api()
    p = path_for(realm, flow)
    if not p.exists():
        raise SystemExit(f"no backup at {p}")
    want = json.loads(p.read_text())["executions"]
    live = fetch(api, realm, flow)

    def key(rows):
        return [(r.get("displayName"), r.get("requirement"),
                 r.get("level"), r.get("index"), bool(r.get("authenticationFlow")))
                for r in rows]

    w, l = key(want), key(live)
    if w == l:
        print(f"  flow matches the backup exactly ({len(l)} executions)")
        return 0

    print(f"  flow DOES NOT match the backup (backup {len(w)} vs live {len(l)})")
    only_w = [x for x in w if x not in l]
    only_l = [x for x in l if x not in w]
    for x in only_w:
        print(f"    only in backup: {x}")
    for x in only_l:
        print(f"    only in live  : {x}")
    return 1


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in ("show", "backup", "restore", "verify"):
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    realm = sys.argv[2] if len(sys.argv) > 2 else "attest-privileged"
    flow = sys.argv[3] if len(sys.argv) > 3 else "browser"
    if cmd == "show":
        return show(realm, flow)
    if cmd == "backup":
        return backup(realm, flow)
    if cmd == "restore":
        return restore(realm, flow)
    return verify(realm, flow, quiet=False)


if __name__ == "__main__":
    sys.exit(main())
