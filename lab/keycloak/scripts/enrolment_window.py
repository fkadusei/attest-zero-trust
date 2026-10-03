#!/usr/bin/env python3
"""S5e — a time-boxed, audited window for enrolling a first passkey.

THE PROBLEM THIS SOLVES
    A passkey can only be registered by someone who can already authenticate, so a
    passkey-only realm has no way to enrol anyone. S5d's answer was to revert the
    WHOLE REALM to a password flow while enrolling — which opens a password path
    for every user, for an unbounded time, with no record. That is a worse hole
    than the one it was fixing.

WHAT THIS DOES INSTEAD
    A dedicated client (`enrolment`) is bound to a password-capable flow. Normal
    clients are untouched and stay passkey-only. The window is:

      - CLOSED by default — the enrolment client is DISABLED, so there is no
        password path anywhere in the realm
      - OPENED deliberately, for a bounded time, with a recorded reason
      - SWEPT — a sweep closes any window past its expiry
      - AUDITED — Keycloak's event log is enabled, and every open/close is
        recorded with who and when

WHAT IT DOES NOT DO, AND THIS MATTERS
    Per-user restriction did NOT work. The intent was that a `conditional-user-role`
    gate would let only one named user use a password. It was tried in four
    arrangements and never gated — including an exact mirror of Keycloak's own
    built-in conditional subflow, which works. The evidence is in
    SPIKE-5e-RESULTS.md.

    **Consequence: while a window is open, any user in the realm can authenticate
    through the enrolment client with their password.** The window is therefore
    bounded and audited rather than restricted, and that is a real residual risk,
    not a rounding error.

Usage:
    python3 enrolment_window.py setup
    python3 enrolment_window.py status
    python3 enrolment_window.py open <username> [minutes]
    python3 enrolment_window.py close
    python3 enrolment_window.py sweep
    python3 enrolment_window.py audit [limit]
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8080"
REALM = "attest-privileged"
CLIENT = "enrolment"
ADMIN_USER, ADMIN_PASS = "admin", "lab-only-not-a-secret"
DEFAULT_MINUTES = 15
STATE = pathlib.Path(__file__).resolve().parent.parent / "backups" / "enrolment-window.json"


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.replace(microsecond=0).isoformat()


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

    def client(self):
        st, cs = self.call("GET", f"/{REALM}/clients?clientId={CLIENT}")
        if st != 200 or not cs:
            raise SystemExit(f"client '{CLIENT}' not found in {REALM} — run make_privileged_passkey_only.py apply first")
        return cs[0]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
def ensure_events(api: Api) -> dict:
    """Turn on the event log. Without this there is NO audit trail at all —
    Keycloak ships with events disabled, so an enrolment window would leave no
    trace of who authenticated through it."""
    st, cfg = api.call("GET", f"/{REALM}/events/config")
    if st != 200:
        return {"error": st}
    before = {k: cfg.get(k) for k in ("eventsEnabled", "adminEventsEnabled", "adminEventsDetailsEnabled")}
    cfg = dict(cfg)
    cfg["eventsEnabled"] = True
    cfg["adminEventsEnabled"] = True
    cfg["adminEventsDetailsEnabled"] = True
    api.call("PUT", f"/{REALM}/events/config", cfg)
    st, after = api.call("GET", f"/{REALM}/events/config")
    return {
        "before": before,
        "after": {k: after.get(k) for k in ("eventsEnabled", "adminEventsEnabled", "adminEventsDetailsEnabled")},
    }


def load_state() -> dict:
    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except Exception:
            pass
    return {"open": None, "history": []}


def save_state(s: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(s, indent=2))


def record_event(s: dict, action: str, **fields) -> None:
    s.setdefault("history", []).append({"at": iso(now()), "action": action, **fields})


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------
FLOW = "browser-enrolment"
FLOW_FORMS = f"{FLOW} forms"


def setup(api: Api) -> int:
    """Create the enrolment flow and the client that uses it, idempotently.

    S5e needs both, and neither existed as code: they were built by hand while
    working out the design. A fresh realm therefore had no `enrolment` client at
    all, and the CI job failed with "client 'enrolment' not found". If a test
    depends on it, a script must create it.
    """
    # Teardown first, and in this order, because Keycloak will not clear a flow
    # binding back to "none": an empty or null authenticationFlowBindingOverrides
    # is accepted with 204 and then IGNORED, so the client stays bound, the flow
    # stays "in use", and deleting it fails with a 500 whose only explanation is
    # in the container log ("Cannot remove authentication flow, it is currently
    # in use"). Deleting the client outright is the only reliable unbind.
    print("1. remove any previous enrolment client and flow")
    st, clients = api.call("GET", f"/{REALM}/clients?clientId={CLIENT}")
    if clients:
        st, _ = api.call("DELETE", f"/{REALM}/clients/{clients[0]['id']}")
        print(f"   deleted the previous client ({st})")

    st, flows = api.call("GET", f"/{REALM}/authentication/flows")
    fid = next((f["id"] for f in (flows or []) if f.get("alias") == FLOW), None)
    if fid:
        st, realm = api.call("GET", f"/{REALM}")
        if (realm or {}).get("browserFlow") == FLOW:
            api.call("PUT", f"/{REALM}", {"browserFlow": "browser"})
            print("   unbound the realm from the old flow")
        st, resp = api.call("DELETE", f"/{REALM}/authentication/flows/{fid}")
        if st not in (200, 204):
            print(f"   FAILED to remove the old flow: {st} {str(resp)[:120]}")
            return 1
        print(f"   deleted the previous flow ({st})")

    print("2. copy the built-in password flow")
    st, resp = api.call("POST", f"/{REALM}/authentication/flows/browser/copy", {"newName": FLOW})
    if st not in (200, 201, 204):
        print(f"   FAILED to copy the flow: {st} {resp}")
        return 1
    print(f"   copied 'browser' -> '{FLOW}' ({st})")

    # This flow IS password-capable. Its protection is the client, not a
    # condition — see SPIKE-5e-RESULTS.md §2 for why the condition was abandoned.
    st, ex = api.call("GET", f"/{REALM}/authentication/flows/{urllib.parse.quote(FLOW_FORMS)}/executions")
    for e in (ex or []):
        if e.get("providerId") == "auth-username-password-form":
            e = dict(e)
            e["requirement"] = "REQUIRED"
            api.call("PUT", f"/{REALM}/authentication/flows/{urllib.parse.quote(FLOW_FORMS)}/executions", e)
    print("   password form set REQUIRED in the copy")

    print("3. create the client bound to it, with direct grants OFF")
    st, flows = api.call("GET", f"/{REALM}/authentication/flows")
    fid = next((f["id"] for f in (flows or []) if f.get("alias") == FLOW), None)
    if not fid:
        print("   FAILED: the copied flow has no id")
        return 1

    st, resp = api.call("POST", f"/{REALM}/clients", {
        "clientId": CLIENT,
        "name": "First passkey enrolment",
        "description": "Used only to enrol a first passkey. Bound to the enrolment flow. "
                       "Disabled except during a bounded, audited window.",
        "enabled": False,                      # closed by default
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,    # the S5d lesson: never a password path here
        "redirectUris": ["http://localhost:8099/callback"],
        "webOrigins": ["+"],
        "authenticationFlowBindingOverrides": {"browser": fid},
    })
    if st not in (200, 201, 204):
        print(f"   FAILED to create the client: {st} {str(resp)[:120]}")
        return 1
    print(f"   created the client ({st})")

    st, c = api.call("GET", f"/{REALM}/clients?clientId={CLIENT}")
    bound = (c[0].get("authenticationFlowBindingOverrides") or {}).get("browser") == fid
    print(f"   bound to the enrolment flow : {bound}")
    print(f"   enabled                     : {c[0].get('enabled')}  (closed by default)")
    return 0 if bound else 1


def set_client_enabled(api: Api, enabled: bool) -> bool:
    c = dict(api.client())
    c["enabled"] = enabled
    st, _ = api.call("PUT", f"/{REALM}/clients/{c['id']}", c)
    return st in (200, 204)


def is_open(api: Api) -> bool:
    return bool(api.client().get("enabled"))


def open_window(api: Api, username: str, minutes: int, opened_by: str) -> int:
    s = load_state()
    if s.get("open"):
        print(f"  already open for {s['open']['username']} until {s['open']['expires_at']}")
        print("  refusing to extend silently — close it first, so the record stays honest")
        return 1

    ev = ensure_events(api)
    if ev.get("after", {}).get("eventsEnabled") is not True:
        print(f"  could not enable the event log: {ev}")
        print("  refusing to open an unauditable window")
        return 1

    # The named user must exist, even though the gate cannot enforce that only
    # they use it. Recording who it is FOR is still what makes the audit useful.
    st, users = api.call("GET", f"/{REALM}/users?username={urllib.parse.quote(username)}&exact=true")
    if st != 200 or not users:
        print(f"  no such user: {username}")
        return 1

    if not set_client_enabled(api, True):
        print("  FAILED to enable the enrolment client")
        return 1

    expires = now() + dt.timedelta(minutes=minutes)
    s["open"] = {
        "username": username, "user_id": users[0]["id"],
        "opened_at": iso(now()), "expires_at": iso(expires),
        "minutes": minutes, "opened_by": opened_by,
    }
    record_event(s, "open", username=username, minutes=minutes, opened_by=opened_by, expires_at=iso(expires))
    save_state(s)

    print(f"  window OPEN for {username}")
    print(f"    opened   : {s['open']['opened_at']}")
    print(f"    expires  : {s['open']['expires_at']}  ({minutes} min)")
    print(f"    opened by: {opened_by}")
    print("    NOTE: the client is realm-wide, so any user could use a password")
    print("          while this is open. That limitation is recorded, not hidden.")
    return 0


def close_window(api: Api, reason: str = "closed") -> int:
    s = load_state()
    if not set_client_enabled(api, False):
        print("  FAILED to disable the enrolment client")
        return 1
    was = s.get("open")
    if was:
        record_event(s, reason, username=was["username"])
    s["open"] = None
    save_state(s)
    print(f"  window CLOSED{' (was ' + was['username'] + ')' if was else ''}")
    return 0


def sweep(api: Api) -> int:
    """Close the window if it has expired. This is the time limit.

    It is a sweep rather than an enforced deadline, so there is a gap between
    expiry and the sweep running. That gap is the residual risk, and it is
    measured in SPIKE-5e-RESULTS.md rather than assumed to be small.
    """
    s = load_state()
    op = s.get("open")
    if not op:
        # No record, but the client might still be enabled from an earlier run.
        if is_open(api):
            record_event(s, "sweep-orphan")
            save_state(s)
            if not set_client_enabled(api, False):
                print("  FAILED to disable the orphaned enrolment client")
                return 1
            print("  no recorded window, but the client was ENABLED — closed as an orphan")
            return 0
        print("  nothing to do")
        return 0

    exp = dt.datetime.fromisoformat(op["expires_at"])
    if now() < exp:
        remaining = int((exp - now()).total_seconds())
        print(f"  window for {op['username']} still open, {remaining}s remaining")
        return 0

    # Check the result. This previously discarded it and printed "was closed by
    # the sweep" unconditionally, so the tool could report success while the
    # client stayed enabled — and the test grepped for that message.
    if not set_client_enabled(api, False):
        print(f"  FAILED to disable the enrolment client for {op['username']}")
        return 1
    if is_open(api):
        print("  FAILED: the client is still enabled after being told to disable")
        return 1
    record_event(s, "sweep-expired", username=op["username"])
    s["open"] = None
    save_state(s)
    print(f"  window for {op['username']} EXPIRED and was closed by the sweep")
    return 0


def status(api: Api) -> int:
    s = load_state()
    op = s.get("open")
    enabled = is_open(api)
    st, cfg = api.call("GET", f"/{REALM}/events/config")
    print(f"  enrolment client enabled : {enabled}")
    print(f"  events enabled           : {cfg.get('eventsEnabled') if st == 200 else '?'}")
    print(f"  admin events enabled     : {cfg.get('adminEventsEnabled') if st == 200 else '?'}")
    if op:
        exp = dt.datetime.fromisoformat(op["expires_at"])
        delta = int((exp - now()).total_seconds())
        state = f"OPEN, {'expires in ' + str(delta) + 's' if delta > 0 else 'EXPIRED — run sweep'}"
        print(f"  window                   : {state}")
        print(f"  for                      : {op['username']}")
        print(f"  opened by                : {op['opened_by']} at {op['opened_at']}")
    else:
        print("  window                   : closed")
    if enabled and not op:
        print("  WARNING: the client is enabled with no recorded window — run sweep")
    return 0


def audit(api: Api, limit: int = 20) -> int:
    """Show the audit trail: who authenticated through the enrolment client."""
    st, events = api.call("GET", f"/{REALM}/events?client={CLIENT}&first=0&max={limit}")
    print(f"  authentication events for the '{CLIENT}' client ({st}):")
    if st != 200 or not events:
        print("    (none recorded)")
        return 0
    for e in events:
        when = dt.datetime.fromtimestamp((e.get("time") or 0) / 1000, dt.timezone.utc)
        print(f"    {iso(when)}  {str(e.get('type')):22s} {str(e.get('username') or '-'):28s} {e.get('error') or 'ok'}")
    print()
    s = load_state()
    hist = s.get("history", [])[-8:]
    print(f"  window history ({len(s.get('history', []))} records, last {len(hist)}):")
    for h in hist:
        extra = " ".join(f"{k}={v}" for k, v in h.items() if k not in ("at", "action"))
        print(f"    {h['at']}  {h['action']:16s} {extra}")
    return 0


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    api = Api()
    if cmd == "setup":
        return setup(api)
    if cmd == "status":
        return status(api)
    if cmd == "open":
        if len(sys.argv) < 2 + 1:
            print("usage: open <username> [minutes]")
            return 2
        username = sys.argv[2]
        minutes = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_MINUTES
        return open_window(api, username, minutes, opened_by=ADMIN_USER)
    if cmd == "close":
        return close_window(api)
    if cmd == "sweep":
        return sweep(api)
    if cmd == "audit":
        return audit(api, int(sys.argv[2]) if len(sys.argv) > 2 else 20)
    if cmd == "events":
        print(json.dumps(ensure_events(api), indent=2))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
