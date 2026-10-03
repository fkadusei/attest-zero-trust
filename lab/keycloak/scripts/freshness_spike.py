#!/usr/bin/env python3
"""S5c — does the step-up replacement actually force a fresh check?

WHY THIS EXISTS
    S5b rejected Keycloak's ACR/LoA step-up because the component carries
    CVE-2026-97176 (a user with a low-level session can obtain a token asserting a
    higher level than they performed). ADR-013 replaced it with:

        prompt=login + max_age=0   to force a genuine re-authentication
        auth_time                  to judge how recently that happened
        never acr                  because acr is the claim that can lie

    That replacement was a PLAN. This script tests whether it is a CONTROL.

WHAT WOULD MAKE IT A CONTROL
    Two things, and both need a control of their own:

      1. Asking for a fresh sign-in must actually produce one. Asking an
         already-signed-in user to "sign in again" is exactly the kind of thing
         that quietly does nothing — which is the failure S5 found.
      2. The freshness check must be capable of REFUSING. A policy that accepts
         everything would make a present auth_time look like proof.

    So the controls here are as important as the tests:
      - a reused session must NOT get a new auth_time (else "it changed" proves
        nothing, because it always changes)
      - an old token must keep its OLD auth_time (else freshness is being faked)
      - a policy given a stale token must REFUSE
      - a policy given a token with NO auth_time must REFUSE (fail closed)

EXIT CODE
    Non-zero if any check did not behave as expected — including the controls.
    This gate has been negative-tested; a gate that cannot fail is not a gate.
    See EVIDENCE.md, "Is the test harness itself trustworthy?".

Usage:
    ./.venv/bin/python lab/keycloak/scripts/freshness_spike.py
"""
from __future__ import annotations

import base64
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8080"
REALM = "attest-freshness-lab"
PRIVILEGED = "attest-privileged"
ADMIN_USER, ADMIN_PASS = "admin", "lab-only-not-a-secret"
USERNAME, PASSWORD = "fresh-user", "Spike-Lab-Password-123!"
CLIENT = "freshness-lab-client"
REDIRECT = "http://localhost:8099/callback"

RESULTS: list[tuple[str, bool, bool]] = []   # (label, got, expected) — these GATE
FINDINGS: list[str] = []                     # observed problems that do NOT gate


def record(label: str, got, expected) -> None:
    RESULTS.append((label, got, expected))
    mark = "PASS" if got == expected else "FAIL"
    print(f"  {label:52s} {str(got):>22s}  (want {str(expected):<8s}) {mark}")


# ---------------------------------------------------------------------------
# Admin API
# ---------------------------------------------------------------------------
def admin_token() -> str:
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN_USER, "password": ADMIN_PASS,
    }).encode()
    req = urllib.request.Request(f"{KC}/realms/master/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["access_token"]


def api(token: str, method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{KC}/admin/realms{path}", data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]


# ---------------------------------------------------------------------------
# An HTTP session that actually works against Keycloak.
#
# http.cookiejar CANNOT be used here: Keycloak marks its login cookies Secure,
# and for a bare hostname like `localhost` cookiejar rewrites the domain to
# `localhost.local`, so over plain HTTP they are never sent back. Every login
# then fails with "Restart login cookie not found", which reads like an expired
# session rather than a cookie bug. Learned the hard way in S5.
# ---------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Browser:
    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}
        self.opener = urllib.request.build_opener(NoRedirect())

    def _capture(self, headers) -> None:
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                pair = v.split(";", 1)[0].strip()
                if "=" in pair:
                    name, val = pair.split("=", 1)
                    self.cookies[name.strip()] = val.strip()

    def go(self, url: str, data: bytes | None = None):
        req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
        if data:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        if self.cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        try:
            with self.opener.open(req, timeout=30) as r:
                self._capture(r.headers)
                return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            self._capture(e.headers)
            return e.code, dict(e.headers), e.read().decode("utf-8", "replace")


def authorize(browser: Browser, extra: dict) -> tuple[str, str]:
    """Start an authorization request.

    Returns (kind, detail) where kind is one of:
      'code'   — a code was issued without re-authenticating
      'form'   — a login form was demanded (detail is the form action)
      'other'  — something else (detail describes it)
    """
    params = {
        "client_id": CLIENT, "response_type": "code", "scope": "openid",
        "redirect_uri": REDIRECT, "state": "s5c",
    }
    params.update(extra)
    status, headers, body = browser.go(
        f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(params))
    if status in (301, 302, 303):
        loc = headers.get("Location", "")
        if "code=" in loc:
            return "code", urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
        return "other", loc[:120]
    m = re.search(r'<form[^>]*\baction="([^"]+)"', body)
    if m:
        return "form", m.group(1).replace("&amp;", "&")
    return "other", f"HTTP {status}"


def submit_login(browser: Browser, action: str) -> tuple[str, str]:
    status, headers, _ = browser.go(
        action, urllib.parse.urlencode({"username": USERNAME, "password": PASSWORD}).encode())
    if status in (301, 302, 303):
        loc = headers.get("Location", "")
        if "code=" in loc:
            return "code", urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code", [""])[0]
        return "other", loc[:120]
    return "other", f"HTTP {status}"


def exchange(code: str) -> dict:
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "client_id": CLIENT,
        "redirect_uri": REDIRECT,
    }).encode()
    req = urllib.request.Request(f"{KC}/realms/{REALM}/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def claims(jwt: str) -> dict:
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# ---------------------------------------------------------------------------
# The policy a resource server would run. Freshness, never acr.
# ---------------------------------------------------------------------------
def policy_allows(token_claims: dict, now: int, window: int) -> tuple[bool, str]:
    auth_time = token_claims.get("auth_time")
    if auth_time is None:
        # FAIL CLOSED. A token with no auth_time cannot demonstrate freshness,
        # so it must not be treated as fresh. This is the single most important
        # line in the file.
        return False, "no auth_time in token — cannot demonstrate freshness"
    age = now - int(auth_time)
    if age < -60:
        return False, f"auth_time is {-age}s in the future — clock skew or a bad issuer"
    if age <= window:
        return True, f"authenticated {age}s ago (within {window}s)"
    return False, f"authenticated {age}s ago (exceeds {window}s)"


def main() -> int:
    print("=" * 78)
    print("S5c — does the step-up replacement actually force a fresh check?")
    print("=" * 78)

    tok = admin_token()

    # ---- build a clean realm, so nothing from the S5 experiment leaks in ----
    api(tok, "DELETE", f"/{REALM}")
    status, _ = api(tok, "POST", "", {
        "realm": REALM, "enabled": True,
        "sslRequired": "none",
        "accessTokenLifespan": 300,
    })
    if status not in (201, 204):
        print(f"  could not create realm: {status}")
        return 1

    api(tok, "POST", f"/{REALM}/clients", {
        "clientId": CLIENT, "enabled": True, "protocol": "openid-connect",
        "publicClient": True, "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "redirectUris": [REDIRECT], "webOrigins": ["+"],
    })
    api(tok, "POST", f"/{REALM}/users", {
        "username": USERNAME, "enabled": True, "emailVerified": True,
        "email": f"{USERNAME}@lab.invalid", "firstName": "Fresh", "lastName": "Lab",
        "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
    })
    print(f"\nrealm {REALM} built from scratch (clean browser flow, no LoA subflow)")

    b = Browser()

    # =======================================================================
    # T1 — establish a session, and record its auth_time
    # =======================================================================
    print("\n[T1] first sign-in — establishes the session and its auth_time")
    kind, detail = authorize(b, {})
    if kind != "form":
        print(f"  expected a login form, got {kind}: {detail}")
        return 1
    kind, code = submit_login(b, detail)
    if kind != "code":
        print(f"  expected a code, got {kind}: {code}")
        return 1
    t1 = exchange(code)
    c1 = claims(t1["id_token"])
    auth1 = c1.get("auth_time")
    print(f"  auth_time present : {auth1}")
    print(f"  acr claim         : {c1.get('acr', '(absent)')}")
    if auth1 is None:
        print("  auth_time is ABSENT without max_age — the whole replacement depends on it")
    print(f"  waiting 3s so a re-authentication would be visibly later ...")
    time.sleep(3)

    # =======================================================================
    # T2 — CONTROL: reusing the session must NOT produce a new auth_time
    #
    # Without this, "auth_time changed after prompt=login" would prove nothing —
    # it might simply change on every request.
    # =======================================================================
    print("\n[T2] control: reuse the live session, no prompt — must NOT re-authenticate")
    kind, detail = authorize(b, {})
    record("T2a session reused, no login form demanded", kind, "code")
    if kind == "code":
        c2 = claims(exchange(detail)["id_token"])
        record("T2b auth_time unchanged on reuse", c2.get("auth_time"), auth1)

    # =======================================================================
    # T3 — prompt=login must force a genuine ceremony
    # =======================================================================
    print("\n[T3] prompt=login with a live session — must demand the login form")
    kind, detail = authorize(b, {"prompt": "login"})
    record("T3a login form demanded despite live session", kind, "form")

    auth3 = None
    if kind == "form":
        kind, code = submit_login(b, detail)
        record("T3b re-authentication completed", kind, "code")
        if kind == "code":
            t3 = exchange(code)
            c3 = claims(t3["id_token"])
            auth3 = c3.get("auth_time")
            record("T3c auth_time advanced after re-auth",
                   isinstance(auth3, int) and isinstance(auth1, int) and auth3 > auth1, True)
            print(f"       before={auth1}  after={auth3}  delta={(auth3 - auth1) if auth3 and auth1 else '?'}s")

    # =======================================================================
    # T4 — CONTROL: the OLD token must keep its OLD auth_time
    #
    # If the old token's auth_time moved, freshness would be being faked rather
    # than measured — the same class of failure as the CVE we just rejected.
    # =======================================================================
    print("\n[T4] control: an OLD token must not gain freshness from a later re-authentication")
    #
    # The first version of this re-parsed the SAME token string and compared it to
    # itself. `claims()` is pure, so that could not fail and proved nothing — it
    # was a tautology wearing the label "control".
    #
    # The question that actually matters: after re-authenticating, does the OLD
    # token still FAIL a freshness check that the NEW one passes? If the old token
    # were ever treated as fresh, freshness would be fabricated rather than
    # measured — the same class of failure as the CVE we rejected.
    now_ts = int(time.time())
    if auth3 is not None and auth1 is not None and auth3 > auth1:
        window = (now_ts - auth3) + 1      # a window the NEW token fits inside
        old_ok, old_why = policy_allows(c1, now_ts, window)
        new_ok, new_why = policy_allows(c3, now_ts, window)
        record("T4a the OLD token is REFUSED as stale", old_ok, False)
        record("T4b the NEW token passes the SAME window", new_ok, True)
        print(f"       window={window}s")
        print(f"       old: {old_why}")
        print(f"       new: {new_why}")
    else:
        record("T4a re-authentication produced a later auth_time", False, True)

    # =======================================================================
    # T5 — does max_age work, and does it work conditionally?
    #
    # A first version of this test requested max_age=0 immediately after signing
    # in and saw the session reused, which looked like max_age being ignored.
    # It was not: the session was 0 seconds old, and `elapsed > max_age` is
    # `0 > 0`, which is false. Reusing the session was CORRECT.
    #
    # So the test now pairs a within-window request (must reuse) with an
    # out-of-window one (must re-authenticate). Without the first, "it
    # re-authenticated" would not prove max_age was being read at all.
    # =======================================================================
    print("\n[T5] max_age — honoured, and only when the window is actually exceeded")
    b5 = Browser()
    kind, detail = authorize(b5, {})
    if kind == "form":
        submit_login(b5, detail)
    time.sleep(2)   # make the session measurably older than zero
    kind, _ = authorize(b5, {"max_age": "3600"})
    record("T5a max_age=3600, session 2s old -> reused", kind, "code")
    kind, _ = authorize(b5, {"max_age": "0"})
    record("T5b max_age=0, session 2s old -> re-authenticated", kind, "form")

    # =======================================================================
    # T6 — CONTROL: the freshness policy must be able to REFUSE
    #
    # This is the part that makes auth_time a control rather than a field. A
    # policy that accepts everything would make "auth_time is present" look like
    # proof.
    # =======================================================================
    print("\n[T6] the freshness policy PROTOTYPE — unit tests, not a deployed control")
    #
    # IMPORTANT, and previously mislabelled: `policy_allows` below is defined IN
    # THIS FILE. These assertions test a ten-line prototype, not any shipped
    # control. No product policy engine exists yet (that is slice S2, Amazon
    # Verified Permissions, which needs AWS). Treating these as "verified" of the
    # product inflated the claims register; they are recorded as prototype tests.
    print("       (testing the prototype in this file, NOT a product control)")
    now = int(time.time())
    fresh = {"auth_time": now - 5}
    stale = {"auth_time": now - 3600}
    absent = {}
    future = {"auth_time": now + 3600}

    allowed, why = policy_allows(fresh, now, 300)
    record("T6a fresh token accepted", allowed, True)
    allowed, why = policy_allows(stale, now, 300)
    record("T6b stale token REFUSED", allowed, False)
    print(f"       reason: {why}")
    allowed, why = policy_allows(absent, now, 300)
    record("T6c token with NO auth_time REFUSED (fail closed)", allowed, False)
    print(f"       reason: {why}")
    allowed, why = policy_allows(future, now, 300)
    record("T6d token with future auth_time REFUSED", allowed, False)

    if auth3 is not None:
        allowed, _ = policy_allows(c3, int(time.time()), 300)
        record("T6e the real re-authenticated token passes", allowed, True)
        allowed, _ = policy_allows(c1, int(time.time()), 1)
        record("T6f a real token older than the window is refused", allowed, False)

    # =======================================================================
    # T7 — is ADR-013's strength argument actually true today?
    #
    # ADR-013 justifies the replacement partly on this: on the privileged realm
    # the only way in is a hardware key, so re-running the flow IS a fresh
    # hardware-key assertion, and freshness and strength come from the same act.
    #
    # That is a claim about the configured flow, not about the mechanism, so it
    # is recorded as a finding rather than gating on it here. It is nonetheless
    # a claim the decision depends on, and if it is false the decision's
    # reasoning needs correcting.
    # =======================================================================
    print("\n[T7] the privileged realm — is re-authentication a passkey assertion?")
    # Inspect the flow the realm is ACTUALLY bound to, not the `browser` alias.
    #
    # The alias was hard-coded, so this always examined the original
    # password-capable flow and emitted "the flow needs to be made passkey-only"
    # even after S5d had done exactly that. A finding that cannot be cleared is
    # not a finding — it is noise that trains people to ignore the output.
    st_r, realm_repr = api(tok, "GET", f"/{PRIVILEGED}")
    active_flow = (realm_repr or {}).get("browserFlow", "browser")
    print(f"  the realm's ACTIVE browser flow is '{active_flow}'")
    status, flow = api(
        tok, "GET", f"/{PRIVILEGED}/authentication/flows/{urllib.parse.quote(active_flow)}/executions")
    if status == 200 and isinstance(flow, list):
        names = [e.get("displayName", "?") for e in flow]
        # Only count steps that can ACTUALLY RUN. A DISABLED execution is still
        # listed, so matching on presence alone reports a password step in a flow
        # where the password form has been switched off — a false positive that
        # made this finding uncleareable.
        runnable = [e for e in flow
                    if (e.get("requirement") or "").upper() not in ("DISABLED", "")]
        has_passkey = any("webauthn" in (e.get("providerId") or "").lower() for e in runnable)
        # Match the PASSWORD FORMS exactly. A substring test for "password" also
        # matches `webauthn-authenticator-passwordless` — the PASSKEY step — which
        # made this finding a false positive in every version until now, including
        # one that claimed to have fixed it.
        PASSWORD_FORMS = {"auth-username-password-form", "auth-password-form"}
        has_password = any((e.get("providerId") or "") in PASSWORD_FORMS for e in runnable)
        disabled_pw = [e.get("displayName") for e in flow
                       if "password" in (e.get("providerId") or "").lower()
                       and e.get("requirement") == "DISABLED"]
        if disabled_pw:
            print(f"  (password steps present but DISABLED, so not counted: {disabled_pw})")
        print(f"  flow steps: {names}")
        print(f"  passkey/WebAuthn step present : {has_passkey}")
        print(f"  password step present         : {has_password}")
        if has_password:
            FINDINGS.append(
                f"ADR-013's strength premise is NOT met for the ACTIVE flow '{active_flow}': it "
                "contains a Username Password Form, so re-authentication there can be a password "
                "rather than a hardware-key assertion. Apply the passkey-only flow "
                "(make_privileged_passkey_only.py apply) for that argument to hold.")
        else:
            print("  no password step in the active flow — ADR-013's strength premise holds")
        if not has_passkey:
            FINDINGS.append(
                "The privileged realm's browser flow contains no WebAuthn step at all.")
    else:
        print(f"  could not read the privileged browser flow: {status}")
        FINDINGS.append("Could not read the privileged realm's browser flow; T7 unproven.")

    # =======================================================================
    print("\n" + "=" * 78)
    passed = sum(1 for _, got, want in RESULTS if got == want)
    print(f"Freshness mechanism: {passed}/{len(RESULTS)} behaved as expected")
    if FINDINGS:
        print()
        print(f"FINDINGS ({len(FINDINGS)}) — these do NOT gate, but must not be missed:")
        for f in FINDINGS:
            print(f"  * {f}")
    else:
        print("Findings: none.")
    print("=" * 78)

    if passed != len(RESULTS):
        for label, got, want in RESULTS:
            if got != want:
                print(f"  FAILED: {label} — got {got!r}, expected {want!r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
