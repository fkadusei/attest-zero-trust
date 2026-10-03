#!/usr/bin/env python3
"""S5 — does asking for a stronger check actually force one?

THE QUESTION
    Some actions should require the user to prove themselves again, right then.
    If the system instead notices an existing session and waves the request
    through, "step-up" is a button that does nothing — while appearing to work,
    which is worse than not having it.

    So: given a signed-in session, does requesting a *higher* authentication
    level cause a fresh credential check, or is it satisfied by the session
    that already exists?

WHY A DEDICATED REALM
    This needs its own browser flow, its own ACR-level mapping and its own
    client. Doing that inside `attest-users` would leave the realm in a state
    that no longer matches its declarative configuration, and the whole point of
    that configuration is that it is reproducible. So the whole experiment is
    built in a throwaway realm that the script creates from nothing.

HOW THE ANSWER IS OBSERVED
    By following the authorization-code flow by hand and never following
    redirects, so the two possible outcomes stay distinguishable:

      a redirect back to the client carrying a `code`  -> nothing was asked of the user
      a login/step-up page (HTTP 200)                   -> the user was asked again

    That distinction is the entire measurement. Everything else is setup.

WHY A CONTROL IS MANDATORY HERE
    A harness that always reports "the user was prompted" would look exactly
    like a pass. So the first test signs in again *without* asking for a higher
    level and requires the opposite result — a code, no prompt.

Usage:
    ./.venv/bin/python lab/keycloak/scripts/stepup_spike.py
"""
from __future__ import annotations

import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8080"
REALM = "attest-stepup-lab"
FLOW = "browser-stepup"
SUBFLOW = "step-up-loa2"
CLIENT_ID = "stepup-lab-client"
REDIRECT = "http://localhost:8099/callback"
USERNAME, PASSWORD = "stepup-user", "Spike-Lab-Password-123!"
LOW_ACR, HIGH_ACR = "low", "silver"


# --------------------------------------------------------------------------
# Admin API
# --------------------------------------------------------------------------
def admin_token() -> str:
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": "lab-only-not-a-secret"}).encode()
    req = urllib.request.Request(
        f"{KC}/realms/master/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]


class Admin:
    def __init__(self) -> None:
        self.t = admin_token()

    def __call__(self, method: str, path: str, body=None):
        url = f"{KC}/admin{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.t}")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]


def q(s: str) -> str:
    return urllib.parse.quote(s, safe="")


# --------------------------------------------------------------------------
# Setup — build everything from nothing so the run is reproducible
# --------------------------------------------------------------------------
def setup(api: Admin) -> None:
    # A realm of our own, so no shared configuration is disturbed.
    api("DELETE", f"/realms/{REALM}")
    st, _ = api("POST", "/realms", {
        "realm": REALM, "enabled": True, "sslRequired": "external",
        # Map human-readable ACR names onto numeric levels. The client asks for
        # "silver"; the server compares the number.
        "attributes": {"acr.loa.map": json.dumps({LOW_ACR: "1", HIGH_ACR: "2"})},
    })
    print(f"  realm {REALM}                    -> {st}")

    st, _ = api("POST", f"/realms/{REALM}/users", {
        "username": USERNAME, "enabled": True, "emailVerified": True,
        "firstName": "Step", "lastName": "Up",
        "email": f"{USERNAME}@example.test", "requiredActions": [],
    })
    _, users = api("GET", f"/realms/{REALM}/users?username={USERNAME}&exact=true")
    uid = users[0]["id"]
    # Clear any default required actions, or login fails with the unhelpful
    # "Account is not fully set up".
    user = {k: v for k, v in users[0].items() if k not in ("access",)}
    user.update({"requiredActions": [], "emailVerified": True, "enabled": True})
    api("PUT", f"/realms/{REALM}/users/{uid}", user)
    api("PUT", f"/realms/{REALM}/users/{uid}/reset-password",
        {"type": "password", "value": PASSWORD, "temporary": False})
    print(f"  user {USERNAME}")

    api("POST", f"/realms/{REALM}/clients", {
        "clientId": CLIENT_ID, "enabled": True, "publicClient": True,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "redirectUris": [REDIRECT], "protocol": "openid-connect",
    })
    print(f"  client {CLIENT_ID}")

    # Copy the built-in browser flow: Keycloak refuses to let a subflow be
    # added to a built-in flow ("It is illegal to add sub-flow to a built in
    # flow"), so copying is the only route.
    st, _ = api("POST", f"/realms/{REALM}/authentication/flows/browser/copy",
                {"newName": FLOW})
    print(f"  copy browser flow                -> {st}")

    # A conditional subflow that only runs when a higher level is demanded.
    #
    # WHERE it lives matters, and this cost real time to find. A CONDITIONAL
    # subflow placed at the TOP LEVEL of the browser flow breaks it: the auth
    # endpoint returns HTTP 400 rendering "Invalid username or password" before
    # anyone has typed anything, which reads like bad credentials and is
    # actually a malformed flow. Nested inside the existing `forms` subflow —
    # a sibling of the username/password form — it works.
    api("POST", f"/realms/{REALM}/authentication/flows/{q(FLOW + ' forms')}/executions/flow",
        {"alias": SUBFLOW, "type": "basic-flow",
         "description": "a second factor, for a higher level"})
    api("POST", f"/realms/{REALM}/authentication/flows/{q(SUBFLOW)}/executions/execution",
        {"provider": "conditional-level-of-authentication"})
    api("POST", f"/realms/{REALM}/authentication/flows/{q(SUBFLOW)}/executions/execution",
        {"provider": "auth-otp-form"})
    print(f"  flow {FLOW} + subflow {SUBFLOW}")

    # Turn the subflow on and set its requirements.
    #
    # Everything is created DISABLED, which is a silent failure if you forget.
    # And the flat executions list mixes every nesting level together: matching
    # on "an OTP form, at some depth" also hits the built-in 2FA subflow's OTP
    # form and demotes it from ALTERNATIVE to REQUIRED, which breaks the flow
    # with a confusing "Invalid username or password" before anyone has typed
    # anything. So ask each flow for *its own* children instead.
    _, parents = api("GET", f"/realms/{REALM}/authentication/flows/{q(FLOW + ' forms')}/executions")
    for e in parents or []:
        if e.get("authenticationFlow") and e.get("displayName") == SUBFLOW:
            e["requirement"] = "CONDITIONAL"
            api("PUT", f"/realms/{REALM}/authentication/flows/{q(FLOW + ' forms')}/executions", e)

    _, kids = api("GET", f"/realms/{REALM}/authentication/flows/{q(SUBFLOW)}/executions")
    for e in kids or []:
        if e.get("providerId") == "conditional-level-of-authentication":
            e["requirement"] = "REQUIRED"
            api("PUT", f"/realms/{REALM}/authentication/flows/{q(SUBFLOW)}/executions", e)
            api("POST", f"/realms/{REALM}/authentication/executions/{e['id']}/config",
                {"alias": "loa2", "config": {"loa-condition-level": "2"}})
        elif e.get("providerId") == "auth-otp-form":
            e["requirement"] = "REQUIRED"
            api("PUT", f"/realms/{REALM}/authentication/flows/{q(SUBFLOW)}/executions", e)

    # Bind it, or none of the above is used and the default flow keeps running.
    st, realm = api("GET", f"/realms/{REALM}")
    realm["browserFlow"] = FLOW
    api("PUT", f"/realms/{REALM}", realm)
    print(f"  bound realm browserFlow          -> {FLOW}")

    _, ex = api("GET", f"/realms/{REALM}/authentication/flows/{q(FLOW)}/executions")
    print("\n  flow as built:")
    for e in ex or []:
        mark = "  " * e.get("level", 0)
        print(f"    {mark}{str(e.get('displayName'))[:38]:40s} {e.get('requirement')}"
              f"  cfg={e.get('authenticationConfig')}")


# --------------------------------------------------------------------------
# A tiny browser: cookies, and no automatic redirect following
# --------------------------------------------------------------------------
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Browser:
    """A tiny HTTP client with its own cookie handling.

    Deliberately does NOT use http.cookiejar. Keycloak marks its login cookies
    Secure, and for a bare hostname like `localhost` cookiejar rewrites the
    domain to `localhost.local` — so over plain http the cookies are never sent
    back, and every login fails with "Restart login cookie not found", which
    reads like an expired session and is really a cookie-jar policy problem.

    Keeping name=value pairs and replaying them sidesteps both issues.
    """

    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}
        self.opener = urllib.request.build_opener(NoRedirect())

    def _capture(self, headers) -> None:
        # headers.items() keeps duplicates; dict(headers) would drop all but the
        # last Set-Cookie.
        for key, value in headers.items():
            if key.lower() != "set-cookie":
                continue
            pair = value.split(";", 1)[0].strip()
            if "=" in pair:
                name, val = pair.split("=", 1)
                self.cookies[name.strip()] = val.strip()

    def _do(self, req):
        if self.cookies:
            req.add_header("Cookie",
                           "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        try:
            with self.opener.open(req) as r:
                self._capture(r.headers)
                return r.status, dict(r.headers), r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            self._capture(e.headers)
            return e.code, dict(e.headers), e.read().decode("utf-8", "replace")

    def get(self, url: str):
        return self._do(urllib.request.Request(url))

    def post(self, url: str, fields: dict):
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return self._do(req)


def auth_url(acr: str | None = None, port: int = 0) -> str:
    p = {
        "client_id": CLIENT_ID, "response_type": "code", "scope": "openid",
        "redirect_uri": REDIRECT, "state": f"s{port}",
    }
    if acr:
        p["acr_values"] = acr
    return f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(p)


def form_action(html: str) -> str | None:
    m = re.search(r'<form[^>]*\baction="([^"]+)"', html)
    return m.group(1).replace("&amp;", "&") if m else None


def code_from(location: str) -> str | None:
    if not location:
        return None
    qs = urllib.parse.urlparse(location).query
    return urllib.parse.parse_qs(qs).get("code", [None])[0]


def sign_in(browser: Browser, acr: str | None, label: str) -> dict:
    """Follow the auth-code flow by hand. Returns what happened."""
    status, headers, html = browser.get(auth_url(acr))
    out = {"label": label, "acr_requested": acr, "first_status": status,
           "prompted": False, "got_code": False, "detail": ""}

    if status in (301, 302, 303):
        loc = headers.get("Location", "")
        out["got_code"] = code_from(loc) is not None
        out["detail"] = "redirected straight back (existing session honoured)"
        out["final_location"] = loc
        return out

    # A login page appeared.
    action = form_action(html)
    if not action:
        out["detail"] = "no login form found"
        return out
    status, headers, html = browser.post(action, {"username": USERNAME, "password": PASSWORD})

    if status in (301, 302, 303):
        loc = headers.get("Location", "")
        out["got_code"] = code_from(loc) is not None
        out["detail"] = "signed in, code issued without any second factor"
        out["final_location"] = loc
        return out

    # Not a redirect: something is being asked of the user.
    out["prompted"] = True
    low = html.lower()
    if 'name="otp"' in low or 'id="otp"' in low:
        out["detail"] = "prompted for a one-time code (second factor demanded)"
    elif "configure" in low and "otp" in low:
        out["detail"] = "prompted to set up a second factor"
    else:
        title = re.search(r"<title[^>]*>(.*?)</title>", html, re.S)
        out["detail"] = f"prompted with a page: {title.group(1).strip() if title else 'unknown'}"
    out["prompt_action"] = form_action(html)
    return out


def token_for(browser: Browser, code: str) -> dict:
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": CLIENT_ID,
        "code": code, "redirect_uri": REDIRECT}).encode()
    req = urllib.request.Request(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token", data=data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def acr_claim(token: str):
    import base64
    p = token.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p)).get("acr")


# --------------------------------------------------------------------------
def main() -> int:
    api = Admin()
    print("=" * 74)
    print("S5 — does asking for a stronger check actually force one?")
    print("=" * 74)

    print("\n[setup]")
    setup(api)

    print("\n[test] each step uses its own browser session (a fresh cookie jar)")
    results = []

    # T1 — sign in at the base level. Establishes the session and tells us what
    #      level has actually been achieved.
    b = Browser()
    r1 = sign_in(b, None, "T1 sign in, no level requested")
    print(f"\n  T1 {r1['label']}\n     {r1['detail']}")
    if r1.get("final_location"):
        code = code_from(r1["final_location"])
        if code:
            try:
                tok = token_for(b, code)
                r1["acr"] = acr_claim(tok["access_token"])
                print(f"     token acr claim: {r1['acr']!r}")
            except Exception as e:
                print(f"     token exchange failed: {e}")

    # T2 — THE CONTROL. With the session already established, ask again for
    #      nothing in particular. This must NOT prompt, or the harness would
    #      report a prompt no matter what and the next test would prove nothing.
    b2 = Browser()
    sign_in(b2, None, "warm up session")
    r2 = sign_in(b2, None, "T2 existing session, no level requested (CONTROL)")
    print(f"\n  T2 {r2['label']}\n     {r2['detail']}")
    print(f"     prompted={r2['prompted']}  expected False")

    # T3 — THE QUESTION. Same session, now demanding a higher level.
    b3 = Browser()
    sign_in(b3, None, "warm up session")
    r3 = sign_in(b3, HIGH_ACR, f"T3 existing session, requesting '{HIGH_ACR}'")
    print(f"\n  T3 {r3['label']}\n     {r3['detail']}")
    print(f"     prompted={r3['prompted']}  expected True")

    print("\n" + "=" * 74)
    rows = [
        ("T1 signed in and got a code", bool(r1.get("got_code")), True),
        ("T2 control: no prompt without a higher level", r2["prompted"], False),
        ("T3 step-up: prompted when a higher level was asked for", r3["prompted"], True),
    ]
    passed = 0
    for label, got, want in rows:
        ok = got == want
        passed += ok
        print(f"  {label:56s} {str(got):6s} {'PASS' if ok else 'FAIL'}")
    print("=" * 74)
    print(f"Result: {passed}/{len(rows)}")
    print(f"\n(Realm {REALM} is left in place so the flow can be inspected.)")
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
