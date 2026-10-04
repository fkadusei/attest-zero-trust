#!/usr/bin/env python3
"""S5e — is the enrolment window time-boxed, gated and audited?

THE GAP THIS CLOSES
    S5d left the bootstrap problem open: to give someone their first passkey, the
    whole realm had to be reverted to a password flow — a password path for every
    user, for an unbounded time, with no record. That is a worse hole than the one
    it fixes. This replaces it with a window that is closed by default, bounded,
    and audited.

WHAT IS TESTED, AND THE CONTROLS THAT MAKE IT MEAN SOMETHING
      E1-E3  closed by default: no password on the enrolment client, no password
             grant anywhere, and the normal client unaffected
      E4-E5  open: the enrolment client accepts a password AND the normal client
             still does not. Without E5, "open" would be satisfied by a design
             that just breaks everything. E4c completes a real sign-in, because a
             password FIELD appearing proves nothing about whether it is accepted
      E6     CONTROL: the sweep must NOT close a window that has not expired.
             Without this, "the sweep closed it" would be satisfied by a sweep
             that closes everything unconditionally
      E7-E9  the time limit: expiry, the sweep, and enforcement afterwards
      E10-11 the audit trail exists and records the window

THE LIMITATION, TESTED RATHER THAN DESCRIBED
    E12 proves the per-user restriction does NOT work, by showing that a second
    user can also use a password while a window is open. It is a FINDING rather
    than a gate: it is a known, accepted residual risk, and pinning it as a test
    means it cannot quietly be forgotten or quietly assumed to work.

Usage:
    ./.venv/bin/python lab/keycloak/scripts/spike5e-matrix.py
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from lab_env import KEYCLOAK_ADMIN_PASSWORD

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from freshness_spike import Browser          # a working Keycloak HTTP session
from flow_tool import Api as FlowApi          # flow inspection, for the E5 control

KC = "http://localhost:8080"
REALM = "attest-privileged"
CLIENT = "enrolment"
OTHER_CLIENT = "account"
USER = "spike-attest-privileged"
OTHER_USER = "spike-second-user"
PASSWORD = "Spike-Lab-Password-123!"
PY = sys.executable
WINDOW_TOOL = str(pathlib.Path(__file__).resolve().parent / "enrolment_window.py")
PASSKEY_TOOL = str(pathlib.Path(__file__).resolve().parent / "make_privileged_passkey_only.py")

RESULTS: list[tuple[str, object, object]] = []
FINDINGS: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    RESULTS.append((label, got, want))
    print(f"  {label:56s} {str(got):9s} (want {str(want):6s}) {'PASS' if ok else 'FAIL'}")


def window(*args: str) -> str:
    r = subprocess.run([PY, WINDOW_TOOL, *args], capture_output=True, text=True, timeout=120)
    return (r.stdout + r.stderr).strip()


def auth_page(client: str, redirect: str) -> str:
    b = Browser()
    _, _, body = b.go(f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": client, "response_type": "code", "scope": "openid",
        "redirect_uri": redirect, "state": "s5e"}))
    return body


def has_password(client: str, redirect: str) -> bool:
    return bool(re.search(r'type=["\']?password', auth_page(client, redirect), re.I))


def auth_refusal_reason(client: str, redirect: str) -> str:
    """WHY the auth request was refused, not merely THAT it was.

    E1 originally asserted only "no password field appears". A disabled client
    returns HTTP 400 with no password field either, so E1 passed whether the flow
    was correctly closed OR completely broken. That is the exact flaw that led to
    a wrong published conclusion in S5e: "denied" and "broken" looked identical.

    This returns a reason string so the check can assert on the CAUSE.
    """
    b = Browser()
    st, _, body = b.go(f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": client, "response_type": "code", "scope": "openid",
        "redirect_uri": redirect, "state": "s5e"}))
    text = re.sub(r"<[^>]+>", " ", re.sub(r"<script.*?</script>", " ", body, flags=re.S | re.I))
    text = re.sub(r"\s+", " ", text).strip().lower()
    for marker, reason in (("client disabled", "client_disabled"),
                           ("invalid username or password", "invalid_credentials")):
        if marker in text:
            return reason
    return f"http_{st}" if st != 200 else "flow_rendered"


def password_login_works(client: str, redirect: str, username: str) -> bool:
    """Actually sign in with a username and password through the browser flow.

    Stronger than looking for a password field on the page: a field appearing
    proves nothing about whether the credential is accepted. This completes the
    login and checks that a code came back.
    """
    b = Browser()
    _, _, body = b.go(f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": client, "response_type": "code", "scope": "openid",
        "redirect_uri": redirect, "state": "s5e"}))
    m = re.search(r'<form[^>]*\baction="([^"]+)"', body)
    if not m:
        return False
    _, h, _ = b.go(m.group(1).replace("&amp;", "&"),
                   urllib.parse.urlencode({"username": username, "password": PASSWORD}).encode())
    loc = h.get("Location") or ""
    # Authentication SUCCEEDED if we get a code, OR if we are sent to a required
    # action — the latter means the password was accepted and the user is now
    # being made to enrol a passkey. Counting only `code=` reports a false
    # negative for any user with a pending required action. That mistake was made
    # here first, and it nearly hid the limitation this check exists to record.
    return "code=" in loc or "required-action" in loc


def password_grant(client: str, username: str = USER) -> int:
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": client,
        "username": username, "password": PASSWORD, "scope": "openid",
    }).encode()
    try:
        with urllib.request.urlopen(
                urllib.request.Request(f"{KC}/realms/{REALM}/protocol/openid-connect/token", data=data),
                timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def client_enabled() -> bool:
    """Read the client's REAL enabled state from the API."""
    t = admin_token()
    req = urllib.request.Request(f"{KC}/admin/realms/{REALM}/clients?clientId={CLIENT}")
    req.add_header("Authorization", f"Bearer {t}")
    with urllib.request.urlopen(req) as r:
        return bool(json.load(r)[0].get("enabled"))


def keycloak_events() -> int:
    """How many authentication events KEYCLOAK recorded for the enrolment client.

    Independent of our own JSON: this is the identity provider's own audit trail.
    """
    t = admin_token()
    req = urllib.request.Request(
        f"{KC}/admin/realms/{REALM}/events?client={CLIENT}&first=0&max=100")
    req.add_header("Authorization", f"Bearer {t}")
    with urllib.request.urlopen(req) as r:
        return len(json.load(r))


def admin_token() -> str:
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": KEYCLOAK_ADMIN_PASSWORD}).encode()
    with urllib.request.urlopen(
            urllib.request.Request(f"{KC}/realms/master/protocol/openid-connect/token", data=data)) as r:
        return json.load(r)["access_token"]


def ensure_user(name: str) -> None:
    """Create the user if it is missing, with a known password.

    The matrix must not assume a user exists. `spike-attest-privileged` is
    created by S3's harness, and in a fresh CI realm this job never runs that —
    so `open` failed with "no such user" and every downstream check failed too.
    A self-contained test creates what it needs.
    """
    t = admin_token()

    def call(method, path, body=None):
        d = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{KC}/admin/realms{path}", data=d, method=method)
        req.add_header("Authorization", f"Bearer {t}")
        if d:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:150]

    st, users = call("GET", f"/{REALM}/users?username={name}&exact=true")
    if not users:
        call("POST", f"/{REALM}/users", {
            "username": name, "enabled": True, "emailVerified": True,
            "email": f"{name}@lab.invalid", "firstName": "Spike", "lastName": "Lab",
        })
        st, users = call("GET", f"/{REALM}/users?username={name}&exact=true")
    call("PUT", f"/{REALM}/users/{users[0]['id']}/reset-password",
         {"type": "password", "value": PASSWORD, "temporary": False})
    # Clear required actions so a profile prompt cannot be mistaken for a
    # credential failure.
    st, u = call("GET", f"/{REALM}/users/{users[0]['id']}")
    call("PUT", f"/{REALM}/users/{users[0]['id']}", {**u, "requiredActions": []})


def main() -> int:
    print("=" * 80)
    print("S5e — is the enrolment window time-boxed, gated and audited?")
    print("=" * 80)

    # The whole point of the window is that NORMAL clients stay passkey-only, so
    # the realm has to be in that state for E3/E5 to mean anything. Apply it here
    # rather than assuming the caller did, or those controls would pass or fail
    # depending on leftovers from an earlier run.
    # Create the enrolment flow and client if they are missing. Neither existed
    # as code before this: they were built by hand while working out the design,
    # so a fresh realm had no `enrolment` client and the window could not open.
    print("\n[setup] ensure the enrolment flow and client exist")
    r = subprocess.run([PY, WINDOW_TOOL, "setup"], capture_output=True, text=True, timeout=240)
    print("  " + r.stdout.strip().replace("\n", "\n  "))
    if r.returncode != 0:
        print("  FAILED to set up the enrolment flow/client")
        print(r.stderr[-400:])
        return 1

    print("\n[setup] put the realm into the passkey-only state the controls depend on")
    r = subprocess.run([PY, PASSKEY_TOOL, "apply"], capture_output=True, text=True, timeout=180)
    ok = r.returncode == 0
    print(f"  passkey-only applied: {ok}")
    if not ok:
        print(r.stdout[-400:], r.stderr[-400:])
        return 1
    ensure_user(USER)
    ensure_user(OTHER_USER)

    ENR_REDIRECT = "http://localhost:8099/callback"
    ACC_REDIRECT = f"{KC}/realms/{REALM}/account/"

    # ---- E1-E3: closed by default -------------------------------------------
    print("\n[E1-E3] closed by default")
    window("close")
    window("sweep")
    # Assert the CAUSE. "No password field" alone is satisfied by a broken client.
    reason = auth_refusal_reason(CLIENT, ENR_REDIRECT)
    check("E1a closed window refuses for the RIGHT reason", reason, "client_disabled")
    check("E1b enrolment client offers no password when closed",
          has_password(CLIENT, ENR_REDIRECT), False)
    check("E2 password grant refused on the enrolment client",
          password_grant(CLIENT) in (400, 401, 403), True)
    check("E3 normal client unaffected (still passkey-only)",
          has_password(OTHER_CLIENT, ACC_REDIRECT), False)

    # ---- E4-E5: open ---------------------------------------------------------
    print("\n[E4-E5] window open")
    out = window("open", USER, "1")
    opened = "window OPEN" in out
    if not opened:
        # Print WHY. A bare "False" here cost a CI round trip: the cause was a
        # missing user, and the tool had said so in text nobody was reading.
        print("       the window tool said:")
        for line in out.splitlines():
            print(f"         {line}")
    check("E4a the window opened", opened, True)
    check("E4b enrolment client offers a password while open",
          has_password(CLIENT, ENR_REDIRECT), True)
    check("E4c the named user can actually COMPLETE a password sign-in",
          password_login_works(CLIENT, ENR_REDIRECT, USER), True)
    check("E5 CONTROL: normal client is STILL passkey-only",
          has_password(OTHER_CLIENT, ACC_REDIRECT), False)

    # ---- E6: the sweep must not close an unexpired window --------------------
    print("\n[E6] control: the sweep is conditional, not indiscriminate")
    window("sweep")
    check("E6 sweep leaves an unexpired window OPEN", has_password(CLIENT, ENR_REDIRECT), True)

    # ---- E12: the limitation, pinned as a finding ---------------------------
    print("\n[E12] the per-user restriction — pinned so it cannot be forgotten")
    # Not a page check: this completes a full sign-in as a DIFFERENT user.
    other_can = password_login_works(CLIENT, ENR_REDIRECT, OTHER_USER)
    print(f"       a second user ({OTHER_USER}) completed a password sign-in: {other_can}")
    if other_can:
        FINDINGS.append(
            "The window is NOT restricted to the named user. While it is open, ANY user in the "
            "realm can authenticate through the enrolment client with their password, because "
            "per-user gating via conditional-user-role did not work in four arrangements tested "
            "(including an exact mirror of Keycloak's own working conditional subflow). The window "
            "is therefore bounded and audited rather than restricted — a real residual risk.")

    # ---- E7-E9: the time limit ----------------------------------------------
    print("\n[E7-E9] the time limit (waiting for the 1-minute window to expire)")
    for _ in range(20):
        time.sleep(5)
        if "EXPIRED" in window("status"):
            break
    expired = "EXPIRED" in window("status")
    check("E7 the window reports itself expired", expired, True)
    out = window("sweep")
    check("E8a the sweep reported success", "EXPIRED and was closed" in out, True)
    # Assert the STATE, not the tool's own message. A tool that prints success
    # while leaving the client enabled would satisfy a message grep.
    check("E8b the client is ACTUALLY disabled after the sweep", client_enabled(), False)
    check("E8c no window is recorded any more",
          "window                   : closed" in window("status"), True)
    # E9a previously used has_password, which DISCARDS the HTTP status — so a
    # broken request and a correctly-refused one looked identical.
    check("E9a the post-sweep refusal has the right CAUSE",
          auth_refusal_reason(CLIENT, ENR_REDIRECT), "client_disabled")
    check("E9b it offers no password either", has_password(CLIENT, ENR_REDIRECT), False)
    check("E9c password grant refused again", password_grant(CLIENT) in (400, 401, 403), True)

    # ---- E10-E11: the audit trail -------------------------------------------
    print("\n[E10-E11] the audit trail")
    # E10/E11 originally read the tool's OWN stdout — it was vouching for itself.
    # A local record is worth having, but the point of an AUDIT trail is that the
    # identity provider recorded the authentication independently.
    local = window("audit")
    check("E10 the local record has the open", "open" in local and USER in local, True)
    check("E11 the local record has the sweep", "sweep-expired" in local, True)

    # Independent of our own bookkeeping: did KEYCLOAK log authentications
    # through the enrolment client? (Events were switched on by this slice.)
    events = keycloak_events()
    check("E12 Keycloak itself logged events for the enrolment client",
          events > 0, True)
    print(f"       Keycloak auth events for '{CLIENT}': {events}")

    # ---- summary -------------------------------------------------------------
    # Leave the shared lab fixture as we found it: S3's matrix signs in with a
    # password against this realm and would break if it stayed passkey-only.
    print("\n[teardown] restore the shared fixture")
    subprocess.run([PY, PASSKEY_TOOL, "revert"], capture_output=True, text=True, timeout=180)
    print("  realm browser flow restored")

    passed = sum(1 for _, got, want in RESULTS if got == want)
    print("\n" + "=" * 80)
    print(f"Enrolment window: {passed}/{len(RESULTS)} behaved as expected")
    if FINDINGS:
        print(f"\nFINDINGS ({len(FINDINGS)}) — these do NOT gate, but must not be missed:")
        for f in FINDINGS:
            print(f"  * {f}")
    else:
        print("Findings: none.")
    print("=" * 80)
    if passed != len(RESULTS):
        for label, got, want in RESULTS:
            if got != want:
                print(f"  FAILED: {label} — got {got!r}, expected {want!r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
