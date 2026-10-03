#!/usr/bin/env python3
"""S5d — make the privileged realm require a passkey.

THE PROBLEM
    `attest-privileged` is meant to be the realm where only a hardware key gets
    you in. S5c read its browser flow and found a `Username Password Form`
    REQUIRED, with `WebAuthn Authenticator` DISABLED. So it was password-only.
    Until that changes, "prove yourself again" proves you signed in recently —
    not that you used a key.

WHY THIS COPIES RATHER THAN EDITS
    The `forms` subflow is built in, and Keycloak refuses to modify built-in
    flows:
      "It is illegal to add execution to a built in flow"
    (The same wall S5 hit.) So the flow is COPIED, the copy is modified, and the
    realm is pointed at the copy.

    That is a happy accident for safety: the original `browser` flow is left
    completely untouched, so **rollback is a single API call** that rebinds the
    realm to it. Nothing needs rebuilding.

THE RISK IS LOCKOUT, NOT BYPASS
    Get this wrong and privileged administrators cannot sign in at all. So:
      - the original flow is untouched and remains a working fallback
      - `revert` is one call and is tested before the change is trusted
      - the admin API is reached through the `master` realm, which none of this
        touches, so recovery never depends on the broken realm

Usage:
    python3 make_privileged_passkey_only.py status
    python3 make_privileged_passkey_only.py apply
    python3 make_privileged_passkey_only.py revert
"""
from __future__ import annotations

import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8080"
REALM = "attest-privileged"
ADMIN_USER, ADMIN_PASS = "admin", "lab-only-not-a-secret"

BASE_FLOW = "browser"                 # the untouched built-in flow: the fallback
NEW_FLOW = "browser-passkey-only"     # the copy we configure
NEW_FORMS = f"{NEW_FLOW} forms"       # copied subflows inherit a name prefix
PASSWORDLESS = "webauthn-authenticator-passwordless"


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
            return e.code, e.read().decode()[:250]

    def flow_id(self, alias: str):
        """Flows are deleted by ID, not alias. (The delete-by-alias call 404s or
        leaves the flow in place, and the copy then fails with "already exists".)"""
        _, flows = self.call("GET", f"/{REALM}/authentication/flows")
        for f in flows or []:
            if f.get("alias") == alias:
                return f.get("id")
        return None

    def executions(self, flow: str):
        st, ex = self.call("GET", f"/{REALM}/authentication/flows/{urllib.parse.quote(flow)}/executions")
        return ex if st == 200 else []

    def set_requirement(self, flow: str, display_name: str, requirement: str) -> bool:
        for e in self.executions(flow):
            if e.get("displayName") == display_name:
                if e.get("requirement") == requirement:
                    return True
                e = dict(e)
                e["requirement"] = requirement
                st, err = self.call(
                    "PUT", f"/{REALM}/authentication/flows/{urllib.parse.quote(flow)}/executions", e)
                return st in (200, 204)
        return False


GRANT_BACKUP = pathlib.Path(__file__).resolve().parent.parent / "backups" / f"{REALM}-direct-grants.json"


def clients_with_direct_grants(api: Api):
    """Clients that accept a password at the TOKEN endpoint.

    These bypass the browser flow completely. Making the browser flow
    passkey-only leaves them untouched, so a realm can look passkey-only at the
    login page and still hand out tokens for a password. Proven by test A' in
    spike5d-matrix.mjs, which passed only while the password happened to be
    unknown — a false pass that hid a real bypass.
    """
    st, clients = api.call("GET", f"/{REALM}/clients")
    return [c for c in (clients or []) if c.get("directAccessGrantsEnabled")]


def disable_direct_grants(api: Api) -> int:
    targets = clients_with_direct_grants(api)
    if not targets:
        print("   none found — nothing to close")
        return 0
    GRANT_BACKUP.parent.mkdir(parents=True, exist_ok=True)
    GRANT_BACKUP.write_text(json.dumps(
        [{"id": c["id"], "clientId": c["clientId"]} for c in targets], indent=2))
    for c in targets:
        c = dict(c)
        c["directAccessGrantsEnabled"] = False
        st, err = api.call("PUT", f"/{REALM}/clients/{c['id']}", c)
        mark = "closed" if st in (200, 204) else f"FAILED {st} {err}"
        print(f"   {c['clientId']:28s} direct grants -> {mark}")
    return 0 if not clients_with_direct_grants(api) else 1


def restore_direct_grants(api: Api) -> int:
    if not GRANT_BACKUP.exists():
        print("   no record of which clients to restore")
        return 0
    for rec in json.loads(GRANT_BACKUP.read_text()):
        st, client = api.call("GET", f"/{REALM}/clients/{rec['id']}")
        if st != 200:
            print(f"   {rec['clientId']:28s} no longer exists")
            continue
        client = dict(client)
        client["directAccessGrantsEnabled"] = True
        st, err = api.call("PUT", f"/{REALM}/clients/{rec['id']}", client)
        print(f"   {rec['clientId']:28s} direct grants -> {'restored' if st in (200, 204) else f'FAILED {st}'}")
    return 0


def bound_flow(api: Api) -> str:
    st, realm = api.call("GET", f"/{REALM}")
    return (realm or {}).get("browserFlow", "?")


def status() -> int:
    api = Api()
    print(f"realm              : {REALM}")
    print(f"browserFlow bound  : {bound_flow(api)}")
    print(f"fallback '{BASE_FLOW}' exists  : {api.flow_id(BASE_FLOW) is not None}")
    print(f"'{NEW_FLOW}' exists         : {api.flow_id(NEW_FLOW) is not None}")

    bypass = clients_with_direct_grants(api)
    print(f"\nclients accepting direct password grants : {len(bypass)}"
          + (f"  <-- PASSWORD BYPASS: {[c['clientId'] for c in bypass]}" if bypass else "  (none — closed)"))

    print(f"\nsteps in '{NEW_FORMS}' (the subflow that decides how you get in):")
    for e in api.executions(NEW_FORMS):
        print(f"  {e.get('displayName', '?'):46s} {str(e.get('requirement')):12s} {e.get('providerId') or ''}")
    return 0


def apply() -> int:
    api = Api()
    print(f"=== making {REALM} require a passkey ===\n")

    # Start from a clean copy so this is idempotent. Note: by ID, not alias.
    existing = api.flow_id(NEW_FLOW)
    if existing:
        st, _ = api.call("DELETE", f"/{REALM}/authentication/flows/{existing}")
        print(f"0. removed the previous '{NEW_FLOW}' copy ({st})")
        if st not in (200, 204):
            print("   could not remove it; refusing to continue rather than half-apply")
            return 1

    print(f"1. copy the built-in '{BASE_FLOW}' flow -> '{NEW_FLOW}'")
    print("   (built-in flows cannot be modified: 'It is illegal to add execution to a built in flow')")
    st, resp = api.call("POST", f"/{REALM}/authentication/flows/{BASE_FLOW}/copy", {"newName": NEW_FLOW})
    if st not in (200, 201, 204):
        print(f"   FAILED: {st} {resp}")
        return 1
    print(f"   ok ({st}); the original '{BASE_FLOW}' is left untouched as the fallback")

    print(f"\n2. add the passwordless authenticator to '{NEW_FORMS}'")
    st, resp = api.call(
        "POST",
        f"/{REALM}/authentication/flows/{urllib.parse.quote(NEW_FORMS)}/executions/execution",
        {"provider": PASSWORDLESS})
    if st not in (200, 201, 204):
        print(f"   FAILED: {st} {resp}")
        return 1
    print(f"   ok ({st}) — it is added DISABLED, so it must be promoted next")

    print("\n3. require the passkey, and stop accepting a password")
    ok_key = api.set_requirement(NEW_FORMS, "WebAuthn Passwordless Authenticator", "REQUIRED")
    ok_pw = api.set_requirement(NEW_FORMS, "Username Password Form", "DISABLED")
    print(f"   WebAuthn Passwordless Authenticator -> REQUIRED : {'ok' if ok_key else 'FAILED'}")
    print(f"   Username Password Form              -> DISABLED : {'ok' if ok_pw else 'FAILED'}")
    if not (ok_key and ok_pw):
        print("\n   REFUSING to bind a flow that is not configured as intended.")
        return 1

    print("\n4. close the direct-grant bypass")
    print("   (a passkey-only browser flow does NOT stop password grants at the token")
    print("    endpoint — those skip the flow entirely)")
    if disable_direct_grants(api) != 0:
        print("\n   FAILED to close every direct-grant client; the realm is NOT passkey-only")
        return 1

    print(f"\n5. bind '{NEW_FLOW}' as the realm's browser flow")
    st, err = api.call("PUT", f"/{REALM}", {"browserFlow": NEW_FLOW})
    if st not in (200, 204):
        print(f"   FAILED: {st} {err}")
        return 1
    print(f"   ok ({st})")

    print()
    status()
    return 0


def revert() -> int:
    """One call. The original flow was never modified, so there is nothing to rebuild."""
    api = Api()
    print(f"=== reverting {REALM} to the original '{BASE_FLOW}' flow ===")
    before = bound_flow(api)
    st, err = api.call("PUT", f"/{REALM}", {"browserFlow": BASE_FLOW})
    if st not in (200, 204):
        print(f"  FAILED: {st} {err}")
        return 1
    after = bound_flow(api)
    print(f"  browserFlow: {before} -> {after}")
    restore_direct_grants(api)
    print(f"  the '{NEW_FLOW}' copy is left in place and unbound; delete it if you want it gone.")
    return 0 if after == BASE_FLOW else 1


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        return status()
    if cmd == "apply":
        return apply()
    if cmd == "revert":
        return revert()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
