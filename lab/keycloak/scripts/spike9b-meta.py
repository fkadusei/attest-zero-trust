#!/usr/bin/env python3
"""S9b — is a BROAD relying-party ID actually exploitable?

WHY THIS EXISTS
    S9 proved that a passkey cannot be used through a phishing proxy. What it could
    not show is the COUNTER-CASE: that the property depends on the relying-party ID
    being narrow, rather than on something else entirely.

    That matters. A defence nobody can demonstrate failing is a defence nobody
    understands. S9's meta-test could not run because Chrome refuses a broad RP ID
    over `*.localhost` — `.localhost` is not in the public suffix list, so its
    subdomains do not share a registrable parent.

HOW THE COUNTER-CASE IS REACHED WITHOUT ROOT
    It needs two hostnames under a REAL registrable domain. The obvious route is
    /etc/hosts, which is root-owned and needs a password this environment does not
    have.

    Chrome can resolve them itself:

        --host-resolver-rules="MAP app.attest.test 127.0.0.1,
                               MAP evil.attest.test 127.0.0.1"

    `.test` IS a reserved TLD treated as registrable, so a broad RP ID of
    `attest.test` is accepted — and the WebAuthn test runs entirely inside Chrome,
    so nothing outside it needs to resolve these names. **No system change at all.**

WHAT IS MEASURED — both directions, in one suite
    NARROW RP ID (`app.attest.test`) + phishing origin (`evil.attest.test`)
        -> must be REFUSED. This is S9's result reproduced on a real domain.
    BROAD RP ID (`attest.test`) + the same phishing origin
        -> must be ACCEPTED. This is the counter-case.

    The first is the control for the second: without it, an acceptance could be an
    artefact of the new hostnames rather than of the RP ID.

Usage:
    ./.venv/bin/python lab/keycloak/scripts/spike9b-meta.py
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

KC = "http://localhost:8080"
REALM = "attest-privileged"
REAL_ORIGIN = "http://app.attest.test:8080"
PHISH_ORIGIN = "http://evil.attest.test:9001"
CLIENT = "phishing-lab"
USER = "spike-phishing"
PASSWORD = "Spike-Lab-Password-123!"
PY = sys.executable
PROXY = str(HERE / "phishing_proxy.py")
PASSKEY_TOOL = str(HERE / "make_privileged_passkey_only.py")
# Resolve Chrome rather than hard-coding a macOS path — the same environment
# assumption that has broken every other CI job in this project.
CHROME = os.environ.get(
    "CHROME_BIN",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if sys.platform == "darwin" else "google-chrome")
CDP_PORT = 9224
PROXY_PORT = 9001

RESULTS: list[tuple[str, object, object]] = []
FINDINGS: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    RESULTS.append((label, got, want))
    print(f"  {label:58s} {str(got):16s} (want {str(want):12s}) {'PASS' if ok else 'FAIL'}")


# --------------------------------------------------------------------------
# HTTP helpers (same shapes as the other matrices)
# --------------------------------------------------------------------------
def admin_token() -> str:
    d = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": "lab-only-not-a-secret"}).encode()
    with urllib.request.urlopen(urllib.request.Request(
            f"{KC}/realms/master/protocol/openid-connect/token", data=d)) as r:
        return json.load(r)["access_token"]


def call(method: str, path: str, body=None):
    t = admin_token()
    d = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"{KC}/admin/realms{path}", data=d, method=method)
    r.add_header("Authorization", f"Bearer {t}")
    if d:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r) as x:
            raw = x.read()
            return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]


def set_rp_id(rp_id: str) -> None:
    st, realm = call("GET", f"/{REALM}")
    call("PUT", f"/{REALM}", {**realm,
        "webAuthnPolicyPasswordlessRpId": rp_id,
        "webAuthnPolicyPasswordlessExtraOrigins": [REAL_ORIGIN, PHISH_ORIGIN],
        "webAuthnPolicyPasswordlessAcceptableAaguids": [],
        "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none"})


def ensure_fixtures() -> None:
    """Create the user and client this suite needs, with a working password.

    The standing rule for this project, learned the hard way three times: **every
    harness creates the fixtures it depends on.** Its violation here was subtle —
    a CI seeding step DID create the user, but without credentials, so the
    enrolment sat on the login page and reported "no-register-button", which looks
    like a missing UI element rather than a missing password.
    """
    st, us = call("GET", f"/{REALM}/users?username={USER}&exact=true")
    if not us:
        call("POST", f"/{REALM}/users", {
            "username": USER, "enabled": True, "emailVerified": True,
            "email": f"{USER}@example.test", "firstName": "Spike", "lastName": "Lab",
            "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}]})
        st, us = call("GET", f"/{REALM}/users?username={USER}&exact=true")
    if not us:
        raise SystemExit(f"could not create or find user: {USER}")

    uid = us[0]["id"]
    st, fresh = call("GET", f"/{REALM}/users/{uid}")
    call("PUT", f"/{REALM}/users/{uid}", {**fresh,
        "firstName": fresh.get("firstName") or "Spike",
        "lastName": fresh.get("lastName") or "Lab",
        "email": fresh.get("email") or f"{USER}@example.test",
        "emailVerified": True, "requiredActions": []})
    # Set the password every time: an existing user may have none, and a login
    # that fails leaves the flow on the login page looking like a missing button.
    call("PUT", f"/{REALM}/users/{uid}/reset-password",
         {"type": "password", "value": PASSWORD, "temporary": False})

    st, cs = call("GET", f"/{REALM}/clients?clientId={CLIENT}")
    body = {
        "clientId": CLIENT, "enabled": True, "publicClient": True,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "redirectUris": [f"{REAL_ORIGIN}/callback", f"{PHISH_ORIGIN}/callback"],
        "webOrigins": ["+"],
    }
    if cs:
        call("PUT", f"/{REALM}/clients/{cs[0]['id']}", {**cs[0], **body})
    else:
        call("POST", f"/{REALM}/clients", body)


def user_id() -> str:
    st, us = call("GET", f"/{REALM}/users?username={USER}&exact=true")
    if not us:
        raise SystemExit(f"no such user: {USER}")
    return us[0]["id"]


def clear_and_arm() -> None:
    uid = user_id()
    st, creds = call("GET", f"/{REALM}/users/{uid}/credentials")
    for c in (creds or []):
        if c.get("type", "").startswith("webauthn"):
            call("DELETE", f"/{REALM}/users/{uid}/credentials/{c['id']}")
    st, u = call("GET", f"/{REALM}/users/{uid}")
    call("PUT", f"/{REALM}/users/{uid}", {**u,
        "requiredActions": ["webauthn-register-passwordless"]})


def cred_count() -> int:
    st, creds = call("GET", f"/{REALM}/users/{user_id()}/credentials")
    return len([c for c in (creds or []) if c.get("type", "").startswith("webauthn")])


def ensure_client() -> None:
    """Kept for compatibility; ensure_fixtures() does the real work."""
    ensure_fixtures()


def _legacy_ensure_client() -> None:
    st, cs = call("GET", f"/{REALM}/clients?clientId={CLIENT}")
    body = {"redirectUris": [f"{REAL_ORIGIN}/callback", f"{PHISH_ORIGIN}/callback"],
            "webOrigins": ["+"]}
    if cs:
        call("PUT", f"/{REALM}/clients/{cs[0]['id']}", {**cs[0], **body})


def authz_url(origin: str) -> str:
    return f"{origin}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": CLIENT, "response_type": "code", "scope": "openid",
        "redirect_uri": f"{origin}/callback", "state": "s9b"})


def set_realm_flow(mode: str) -> None:
    subprocess.run([PY, PASSKEY_TOOL, mode], capture_output=True, text=True, timeout=180)


# --------------------------------------------------------------------------
# The browser cycle: enrol with a password, then attempt at both origins
# --------------------------------------------------------------------------
CYCLE_JS = r"""
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
const require = createRequire(__PKG__);
const puppeteer = require('puppeteer-core');
const CDP = __CDP__;
const ORIGIN = __ORIGIN__;
const AUTHZ = __AUTHZ__;
const PHISH = __PHISH__;
const PHISH_AUTHZ = __PHISH_AUTHZ__;
const USERNAME = __USER__;
const PASSWORD = __PASS__;
const PY = __PY__;
const TOOL = __TOOL__;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const setFlow = mode => execFileSync(PY, [TOOL, mode], { stdio: 'pipe' });

const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 45000 });
const page = await browser.newPage();
const client = await page.createCDPSession();
await client.send('Network.enable').catch(() => {});
await client.send('Network.clearBrowserCookies').catch(() => {});
await client.send('WebAuthn.enable');
const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
             hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true }});
page.on('dialog', async d => { try { await d.accept('S9b Key'); } catch {} });
await page.evaluateOnNewDocument(() => {
  window.__s9 = [];
  const g = navigator.credentials && navigator.credentials.get;
  if (g) navigator.credentials.get = function (o) {
    return g.call(navigator.credentials, o).then(
      r => { window.__s9.push('resolved'); return r; },
      e => { window.__s9.push('rejected:' + e.name); throw e; });
  };
  const c = navigator.credentials && navigator.credentials.create;
  if (c) navigator.credentials.create = function (o) {
    return c.call(navigator.credentials, o).then(
      r => { window.__s9.push('created'); return r; },
      e => { window.__s9.push('create-rejected:' + e.name + ':' + String(e.message).slice(0,70)); throw e; });
  };
});

try {
  setFlow('revert');
  await page.goto(AUTHZ, { waitUntil: 'networkidle2', timeout: 45000 });
  const u = await page.$('#username');
  if (!u) console.log('ENROL: no-username-field');
  else {
    await page.type('#username', USERNAME);
    await page.type('#password', PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 45000 }).catch(() => {}),
      page.click('#kc-login')]);
    await sleep(1200);
    const h = await page.evaluateHandle(() => {
      const c = [...document.querySelectorAll('input[type=submit], button')];
      return c.find(e => /register|save|continue|submit/i.test(e.value || e.textContent || '')) || null; });
    const el = h.asElement();
    if (!el) {
      let st = []; try { st = await page.evaluate(() => window.__s9 || []); } catch (e) {}
      console.log('ENROL: no-register-button ' + JSON.stringify(st));
    } else { await el.click().catch(() => {}); await sleep(8000); console.log('ENROL: attempted'); }
  }

  setFlow('apply');
  async function attempt(origin, authz, tag) {
    await client.send('Network.clearBrowserCookies').catch(() => {});
    await page.goto(authz, { waitUntil: 'networkidle2', timeout: 45000 });
    try { await page.evaluate(() => { window.__s9 = []; }); } catch (e) {}
    const btn = await page.$('#authenticateWebAuthnButton');
    if (!btn) { console.log(`OUTCOME-${tag}: no-passkey-button`); return; }
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 }).catch(() => {}),
      btn.click()]);
    await sleep(3500);
    const url = page.url();
    const reached = url.startsWith(origin) && !url.includes('openid-connect/auth')
                    && !url.includes('login-actions');
    let st = []; try { st = await page.evaluate(() => window.__s9 || []); } catch (e) { st = ['(unreadable)']; }
    console.log(`OUTCOME-${tag}: ` + (reached ? 'AUTHENTICATED' : 'NOT-authenticated'));
    console.log(`WEBAUTHN-${tag}: ` + JSON.stringify(st));
    console.log(`FINALURL-${tag}: ` + url.slice(0, 110));
  }
  await attempt(ORIGIN, AUTHZ, 'real');
  await attempt(PHISH, PHISH_AUTHZ, 'phish');
} catch (e) { console.log('OUTCOME: error ' + e.message.slice(0, 120)); }
await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
await page.close(); browser.disconnect();
"""


def run_cycle() -> str:
    pkg = (HERE.parent / "package.json").as_posix()
    src = (CYCLE_JS
           .replace("__PKG__", json.dumps(pkg))
           .replace("__CDP__", json.dumps(f"http://127.0.0.1:{CDP_PORT}"))
           .replace("__ORIGIN__", json.dumps(REAL_ORIGIN))
           .replace("__AUTHZ__", json.dumps(authz_url(REAL_ORIGIN)))
           .replace("__PHISH__", json.dumps(PHISH_ORIGIN))
           .replace("__PHISH_AUTHZ__", json.dumps(authz_url(PHISH_ORIGIN)))
           .replace("__USER__", json.dumps(USER))
           .replace("__PASS__", json.dumps(PASSWORD))
           .replace("__PY__", json.dumps(PY))
           .replace("__TOOL__", json.dumps(PASSKEY_TOOL)))
    path = pathlib.Path("/tmp/s9b-cycle.mjs")
    path.write_text(src)
    r = subprocess.run(["node", str(path)], capture_output=True, text=True, timeout=300)
    return (r.stdout + r.stderr).strip()


def main() -> int:
    print("=" * 84)
    print("S9b — is a BROAD relying-party ID actually exploitable?")
    print("=" * 84)

    print("\n[setup] Chrome with a DNS override, so no /etc/hosts edit is needed")
    subprocess.run(["pkill", "-f", "user-data-dir=/tmp/s9b-chrome"], capture_output=True)
    time.sleep(1)
    subprocess.run(["rm", "-rf", "/tmp/s9b-chrome"], capture_output=True)
    # TWO flags, and the second is the one that matters.
    #
    # --host-resolver-rules lets Chrome resolve the names itself, so no /etc/hosts
    # edit is needed (which is just as well: it is root-owned here and sudo wants a
    # password this environment does not have).
    #
    # --unsafely-treat-insecure-origin-as-secure is REQUIRED, and its absence was
    # the real blocker. **WebAuthn only exists in a secure context.** `*.localhost`
    # is treated as trustworthy over plain HTTP, which is why S9 worked; a real
    # domain is not, so Keycloak refused with:
    #
    #     web_authn_registration_error_detail="WebAuthnUnsupportedBrowser"
    #
    # Nothing about DNS. Resolvable hostnames over HTTP would still have failed.
    # This flag is a lab-only shortcut standing in for the TLS a real deployment
    # would have.
    subprocess.Popen([CHROME, "--headless", "--disable-gpu", "--no-sandbox",
                      f"--remote-debugging-port={CDP_PORT}",
                      "--user-data-dir=/tmp/s9b-chrome",
                      "--host-resolver-rules=MAP app.attest.test 127.0.0.1,"
                      "MAP evil.attest.test 127.0.0.1",
                      "--unsafely-treat-insecure-origin-as-secure="
                      "http://app.attest.test:8080,http://evil.attest.test:9001"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2)
            break
        except Exception:
            time.sleep(1)
    print(f"  Chrome on {CDP_PORT} with host-resolver-rules")

    subprocess.run(["pkill", "-f", "phishing_proxy.py"], capture_output=True)
    time.sleep(1)
    # Bind to 0.0.0.0 because Chrome resolves evil.attest.test to loopback itself,
    # but rewrite URLs to the NAME the victim is on — never to 0.0.0.0.
    subprocess.Popen([PY, PROXY, "--listen", f"0.0.0.0:{PROXY_PORT}",
                      "--public", f"evil.attest.test:{PROXY_PORT}",
                      "--upstream", "localhost:8080"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    print(f"  relay on 0.0.0.0:{PROXY_PORT} (Chrome maps evil.attest.test to it)")

    ensure_fixtures()
    check("setup: the test user has a password",
          call("GET", f"/{REALM}/users/{user_id()}/credentials")[1] is not None, True)

    # ---------------------------------------------------------------- narrow
    print("\n[NARROW] RP ID = app.attest.test — the control for what follows")
    set_rp_id("app.attest.test")
    clear_and_arm()
    out = run_cycle()
    print("     " + out.replace("\n", "\n     ")[:460])
    check("narrow: a passkey was registered", cred_count(), 1)
    check("narrow: signs in at the REAL origin", "OUTCOME-real: AUTHENTICATED" in out, True)
    check("narrow CONTROL: the phishing origin is REFUSED",
          "OUTCOME-phish: AUTHENTICATED" in out, False)

    # ---------------------------------------------------------------- broad
    print("\n[BROAD] RP ID = attest.test — the shared parent, a realistic misconfiguration")
    set_rp_id("attest.test")
    clear_and_arm()
    out = run_cycle()
    print("     " + out.replace("\n", "\n     ")[:460])
    check("broad: a passkey was registered", cred_count(), 1)
    check("broad: signs in at the REAL origin", "OUTCOME-real: AUTHENTICATED" in out, True)
    # The security-critical fact is whether the CREDENTIAL ANSWERED for the
    # attacker's origin — not whether this hand-rolled relay then completes the
    # session end to end. A phishing site obtains an assertion and relays it; the
    # assertion is the thing the design promises an attacker cannot get.
    #
    # Under a narrow RP ID the same origin produced a SecurityError and no
    # assertion at all. The difference is the whole finding.
    check("broad: THE COUNTER-CASE — the credential ANSWERS at the phishing origin",
          'WEBAUTHN-phish: ["resolved"]' in out, True)
    print("       (narrow produced SecurityError; broad produced an assertion)")
    if "OUTCOME-phish: AUTHENTICATED" in out:
        print("       the relay also completed the full session")
    else:
        print("       the relay did not complete the session; the ASSERTION is the"
              " security-relevant result")
    if 'WEBAUTHN-phish: ["resolved"]' in out:
        FINDINGS.append(
            "CONFIRMED BY MEASUREMENT: with the relying-party ID set to a shared parent "
            "domain (attest.test), the BROWSER PRODUCES A VALID ASSERTION for the attacker's "
            "origin — WEBAUTHN reported `resolved`. With a narrow RP ID (app.attest.test) the "
            "same origin gets `SecurityError` and no assertion at all. "
            "Stated precisely: what was measured is that the credential ANSWERS for the "
            "attacker's origin. Whether this hand-rolled relay then completes the session is "
            "plumbing — an attacker with a real site would relay the assertion to the genuine "
            "server, which is what makes the answer sufficient. "
            "The design's phishing resistance therefore rests entirely on the RP ID being a "
            "domain the attacker cannot serve a matching origin for, and being as narrow as "
            "the deployment allows. This is the meta-test S9 could not run on *.localhost.")

    # ---------------------------------------------------------------- restore
    set_rp_id("localhost")
    set_realm_flow("revert")
    st, realm = call("GET", f"/{REALM}")
    call("PUT", f"/{REALM}", {**realm, "webAuthnPolicyPasswordlessExtraOrigins": []})
    subprocess.run(["pkill", "-f", "phishing_proxy.py"], capture_output=True)
    subprocess.run(["pkill", "-f", "user-data-dir=/tmp/s9b-chrome"], capture_output=True)
    print("\n     fixtures restored; Chrome and the relay stopped")

    passed = sum(1 for _, got, want in RESULTS if got == want)
    print("\n" + "=" * 84)
    print(f"Broad relying-party ID: {passed}/{len(RESULTS)} behaved as expected")
    if FINDINGS:
        print(f"\nFINDINGS ({len(FINDINGS)}) — these do NOT gate, but must not be missed:")
        for f in FINDINGS:
            print(f"  * {f}")
    else:
        print("Findings: none.")
    print("=" * 84)
    if passed != len(RESULTS):
        for label, got, want in RESULTS:
            if got != want:
                print(f"  FAILED: {label} — got {got!r}, expected {want!r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
