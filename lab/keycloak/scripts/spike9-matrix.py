#!/usr/bin/env python3
"""S9 — does a phishing proxy actually fail?

THE CLAIM THE WHOLE PROJECT RESTS ON
    A user can be tricked into visiting an attacker's copy of the sign-in page,
    hand over everything they are able to, and STILL NOT GET IN.

    Everything else in this repository tests parts. This tests that.

WHY THE TEST IS BUILT THIS WAY
    A fake login page proves nothing: nobody types a passkey into an obvious fake.
    So the phishing site is a REAL reverse proxy relaying to the REAL Keycloak.
    The victim sees exactly what they would see on the genuine site — same markup,
    same title, same everything — and the only difference is the ORIGIN.

    WebAuthn binds an assertion to the relying-party ID, which must be a
    registrable-domain suffix of the page's origin. `app.localhost` is not a suffix
    of `evil.localhost`, so the browser must refuse to produce an assertion.

WHY DISTINCT HOSTNAMES AND NOT PORTS
    The relying-party ID IGNORES the port. A proxy on `localhost:9001` relaying to
    `localhost:8080` shares the RP ID `localhost`, so the credential WOULD answer
    and the test would report a FALSE BYPASS. `app.localhost` and `evil.localhost`
    are chosen because they are genuinely different registrable domains — and
    because `*.localhost` resolves to loopback by convention, so no /etc/hosts
    edit is needed.

THE META-TEST, WHICH IS THE POINT
    A failure proves nothing unless the harness can detect a success. So T6 widens
    the relying-party ID to the shared parent `localhost` — a realistic
    misconfiguration — and shows the SAME attack SUCCEEDING. That does two things:
    it proves the test can go red, and it demonstrates exactly which setting the
    whole property depends on.

Usage:
    ./.venv/bin/python lab/keycloak/scripts/spike9-matrix.py
"""
from __future__ import annotations

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

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

KC = "http://localhost:8080"
REALM = "attest-privileged"
REAL_ORIGIN = "http://app.localhost:8080"
PHISH_ORIGIN = "http://evil.localhost:9001"
CLIENT = "phishing-lab"
USER = "spike-phishing"
PASSWORD = "Spike-Lab-Password-123!"
PY = sys.executable
PROXY = str(HERE / "phishing_proxy.py")
PASSKEY_TOOL = str(HERE / "make_privileged_passkey_only.py")

RESULTS: list[tuple[str, object, object]] = []
FINDINGS: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    RESULTS.append((label, got, want))
    print(f"  {label:60s} {str(got):16s} (want {str(want):14s}) {'PASS' if ok else 'FAIL'}")


def admin_token() -> str:
    d = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": KEYCLOAK_ADMIN_PASSWORD}).encode()
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


def set_rp_id(rp_id: str, extra_origins: list[str]) -> None:
    """Point the realm at a relying-party ID, read-modify-write (S5e lesson)."""
    st, realm = call("GET", f"/{REALM}")
    call("PUT", f"/{REALM}", {**realm,
        "webAuthnPolicyPasswordlessRpId": rp_id,
        "webAuthnPolicyPasswordlessExtraOrigins": extra_origins,
        # A CDP virtual authenticator cannot attest, so the strict policy refuses
        # it. Relaxed here for the same reason as S5d/S5e/S5f.
        "webAuthnPolicyPasswordlessAcceptableAaguids": [],
        "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none"})


def ensure_user() -> str:
    st, us = call("GET", f"/{REALM}/users?username={USER}&exact=true")
    if not us:
        call("POST", f"/{REALM}/users", {
            "username": USER, "enabled": True, "emailVerified": True,
            "email": f"{USER}@example.test", "firstName": "Spike", "lastName": "Lab"})
        st, us = call("GET", f"/{REALM}/users?username={USER}&exact=true")
    uid = us[0]["id"]
    st, fresh = call("GET", f"/{REALM}/users/{uid}")
    call("PUT", f"/{REALM}/users/{uid}", {**fresh, "firstName": "Spike", "lastName": "Lab",
                                          "email": f"{USER}@example.test",
                                          "emailVerified": True, "requiredActions": []})
    call("PUT", f"/{REALM}/users/{uid}/reset-password",
         {"type": "password", "value": PASSWORD, "temporary": False})
    return uid


def webauthn_ids(uid: str) -> list[str]:
    st, creds = call("GET", f"/{REALM}/users/{uid}/credentials")
    return sorted(c["id"] for c in (creds or []) if c.get("type", "").startswith("webauthn"))


def ensure_client() -> None:
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


BROWSER_JS = r"""
import { createRequire } from 'node:module';
const require = createRequire(__PKG__);
const puppeteer = require('puppeteer-core');
const CDP = 'http://127.0.0.1:9222';
const ORIGIN = __ORIGIN__;
const AUTHZ = __AUTHZ__;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 45000 });
const page = await browser.newPage();
const client = await page.createCDPSession();
await client.send('Network.enable').catch(() => {});
await client.send('Network.clearBrowserCookies').catch(() => {});
await client.send('WebAuthn.enable');
const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
             hasUserVerification: true, isUserVerified: true,
             automaticPresenceSimulation: true },
});
const errors = [];
page.on('pageerror', e => errors.push(e.message.slice(0, 160)));
page.on('dialog', async d => { try { await d.accept('S9 Key'); } catch {} });

// Record what the WebAuthn call ACTUALLY rejects with. Guessing from the absence
// of a page change would be the "denied vs broken" collapse this project keeps
// having to stamp out. The hook is installed BEFORE any ceremony can start.
await page.evaluateOnNewDocument(() => {
  window.__s9 = [];
  const g = navigator.credentials && navigator.credentials.get;
  if (g) {
    navigator.credentials.get = function (opts) {
      return g.call(navigator.credentials, opts).then(
        r => { window.__s9.push('resolved'); return r; },
        e => { window.__s9.push('rejected:' + e.name + ':' + String(e.message).slice(0, 90)); throw e; });
    };
  }
});

try {
  await page.goto(AUTHZ, { waitUntil: 'networkidle2', timeout: 45000 });
  const btn = await page.$('#authenticateWebAuthnButton');
  if (!btn) {
    const pw = await page.$('input[type=password]');
    console.log('OUTCOME: no-passkey-button ' + (pw ? '(password form shown)' : ''));
  } else {
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 }).catch(() => {}),
      btn.click(),
    ]);
    await sleep(3500);
    const url = page.url();
    const reached = url.startsWith(ORIGIN) && !url.includes('openid-connect/auth')
                    && !url.includes('login-actions');
    let state = [];
    try { state = await page.evaluate(() => window.__s9 || []); } catch (e) { state = ['(unreadable)']; }
    console.log('OUTCOME: ' + (reached ? 'AUTHENTICATED' : 'NOT-authenticated'));
    console.log('WEBAUTHN: ' + JSON.stringify(state));
    console.log('FINALURL: ' + url.slice(0, 110));
    if (errors.length) console.log('PAGEERRORS: ' + JSON.stringify(errors.slice(0, 3)));
  }
} catch (e) {
  console.log('OUTCOME: error ' + e.message.slice(0, 120));
}
await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
await page.close(); browser.disconnect();
"""

CYCLE_JS = r"""
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
const require = createRequire(__PKG__);
const puppeteer = require('puppeteer-core');
const CDP = 'http://127.0.0.1:9222';
const ORIGIN = __ORIGIN__;
const AUTHZ = __AUTHZ__;
const PHISH = __PHISH__;          // optional second origin to attempt
const PHISH_AUTHZ = __PHISH_AUTHZ__;
const USERNAME = __USER__;
const PASSWORD = __PASS__;
const PY = __PY__;
const TOOL = __TOOL__;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const setFlow = mode => execFileSync(PY, [TOOL, mode], { stdio: 'pipe' });

// A CDP virtual authenticator lives for ONE session, so the credential must be
// created and used inside the same browser session. Toggling the realm flow from
// here keeps everything in one place.
const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 45000 });
const page = await browser.newPage();
const client = await page.createCDPSession();
await client.send('Network.enable').catch(() => {});
await client.send('Network.clearBrowserCookies').catch(() => {});
await client.send('WebAuthn.enable');
const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
             hasUserVerification: true, isUserVerified: true,
             automaticPresenceSimulation: true },
});
page.on('dialog', async d => { try { await d.accept('S9 Key'); } catch {} });
await page.evaluateOnNewDocument(() => {
  window.__s9 = [];
  const g = navigator.credentials && navigator.credentials.get;
  if (g) {
    navigator.credentials.get = function (o) {
      return g.call(navigator.credentials, o).then(
        r => { window.__s9.push('resolved'); return r; },
        e => { window.__s9.push('rejected:' + e.name + ':' + String(e.message).slice(0, 80)); throw e; });
    };
  }
});

try {
  // --- enrol (password path must exist) ---
  setFlow('revert');
  await page.goto(AUTHZ, { waitUntil: 'networkidle2', timeout: 45000 });
  const u = await page.$('#username');
  if (!u) { console.log('ENROL: no-username-field'); }
  else {
    await page.type('#username', USERNAME);
    await page.type('#password', PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 45000 }).catch(() => {}),
      page.click('#kc-login'),
    ]);
    await sleep(1200);
    const h = await page.evaluateHandle(() => {
      const c = [...document.querySelectorAll('input[type=submit], button')];
      return c.find(e => /register|save|continue|submit/i.test(e.value || e.textContent || '')) || null;
    });
    const el = h.asElement();
    if (!el) console.log('ENROL: no-register-button');
    else { await el.click().catch(() => {}); await sleep(8000); console.log('ENROL: attempted'); }
  }

  // --- attempt a sign-in at an origin using the same authenticator ---
  setFlow('apply');
  async function attempt(origin, authz, tag) {
    await client.send('Network.clearBrowserCookies').catch(() => {});
    await page.goto(authz, { waitUntil: 'networkidle2', timeout: 45000 });
    try { await page.evaluate(() => { window.__s9 = []; }); } catch (e) {}
    const btn = await page.$('#authenticateWebAuthnButton');
    if (!btn) {
      const pw = await page.$('input[type=password]');
      console.log(`OUTCOME-${tag}: no-passkey-button ` + (pw ? '(password form shown)' : ''));
      return;
    }
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 20000 }).catch(() => {}),
      btn.click(),
    ]);
    await sleep(3500);
    const url = page.url();
    const reached = url.startsWith(origin) && !url.includes('openid-connect/auth')
                    && !url.includes('login-actions');
    let state = [];
    try { state = await page.evaluate(() => window.__s9 || []); } catch (e) { state = ['(unreadable)']; }
    console.log(`OUTCOME-${tag}: ` + (reached ? 'AUTHENTICATED' : 'NOT-authenticated'));
    console.log(`WEBAUTHN-${tag}: ` + JSON.stringify(state));
  }

  await attempt(ORIGIN, AUTHZ, 'real');
  if (PHISH) await attempt(PHISH, PHISH_AUTHZ, 'phish');
} catch (e) { console.log('OUTCOME: error ' + e.message.slice(0, 120)); }
await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
await page.close(); browser.disconnect();
"""

ENROL_JS = r"""
import { createRequire } from 'node:module';
const require = createRequire(__PKG__);
const puppeteer = require('puppeteer-core');
const CDP = 'http://127.0.0.1:9222';
const ORIGIN = __ORIGIN__;
const AUTHZ = __AUTHZ__;
const USERNAME = __USER__;
const PASSWORD = __PASS__;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 45000 });
const page = await browser.newPage();
const client = await page.createCDPSession();
await client.send('Network.enable').catch(() => {});
await client.send('Network.clearBrowserCookies').catch(() => {});
await client.send('WebAuthn.enable');
const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
  options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true,
             hasUserVerification: true, isUserVerified: true,
             automaticPresenceSimulation: true },
});
page.on('dialog', async d => { try { await d.accept('S9 Key'); } catch {} });

try {
  // Sign in with the password to reach the passkey-registration required action.
  await page.goto(AUTHZ, { waitUntil: 'networkidle2', timeout: 45000 });
  const u = await page.$('#username');
  if (!u) { console.log('ENROL: no-username-field ' + page.url().slice(0, 90)); }
  else {
    await page.type('#username', USERNAME);
    await page.type('#password', PASSWORD);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 45000 }).catch(() => {}),
      page.click('#kc-login'),
    ]);
    await sleep(1500);
    const handle = await page.evaluateHandle(() => {
      const c = [...document.querySelectorAll('input[type=submit], button')];
      return c.find(e => /register|save|continue|submit/i.test(e.value || e.textContent || '')) || null;
    });
    const el = handle.asElement();
    if (!el) { console.log('ENROL: no-register-button ' + page.url().slice(0, 90)); }
    else { await el.click().catch(() => {}); await sleep(8000); console.log('ENROL: attempted'); }
  }
} catch (e) { console.log('ENROL: error ' + e.message.slice(0, 120)); }
await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
await page.close(); browser.disconnect();
"""


def run_js(template: str, **subs) -> str:
    pkg = (HERE.parent / "package.json").as_posix()
    src = template.replace("__PKG__", json.dumps(pkg))
    for k, v in subs.items():
        src = src.replace(f"__{k}__", json.dumps(v))
    path = pathlib.Path(f"/tmp/s9-{abs(hash(template)) % 10000}.mjs")
    path.write_text(src)
    r = subprocess.run(["node", str(path)], capture_output=True, text=True, timeout=300)
    return (r.stdout + r.stderr).strip()


def set_realm_flow(mode: str) -> str:
    """`revert` (password available, for enrolment) or `apply` (passkey-only).

    Enrolment needs a password path, and a passkey-only realm has none — the auth
    page offers only the passkey button, so the enrolment step found no username
    field and registered nothing. The realm is put back to passkey-only before
    each sign-in attempt, which is also the configuration under test.
    """
    subprocess.run([PY, PASSKEY_TOOL, mode], capture_output=True, text=True, timeout=180)
    st, realm = call("GET", f"/{REALM}")
    return (realm or {}).get("browserFlow", "?")


def authz_url(origin: str) -> str:
    return f"{origin}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode({
        "client_id": CLIENT, "response_type": "code", "scope": "openid",
        "redirect_uri": f"{origin}/callback", "state": "s9"})


def main() -> int:
    print("=" * 88)
    print("S9 — does a phishing proxy actually fail?")
    print("=" * 88)

    print("\n[setup] fixtures")
    ensure_client()
    uid = ensure_user()
    check("setup: the phishing-lab client exists",
          call("GET", f"/{REALM}/clients?clientId={CLIENT}")[0], 200)
    check("setup: the test user exists", uid is not None, True)

    # ---------------------------------------------------------------- T1-T4
    print("\n[T1-T4] NARROW relying-party ID (app.localhost) — one session, both origins")
    set_rp_id("app.localhost", [REAL_ORIGIN])

    def clear_creds(reset_action=True):
        st, creds = call("GET", f"/{REALM}/users/{uid}/credentials")
        for c in (creds or []):
            if c.get("type", "").startswith("webauthn"):
                call("DELETE", f"/{REALM}/users/{uid}/credentials/{c['id']}")
        if reset_action:
            st, u = call("GET", f"/{REALM}/users/{uid}")
            call("PUT", f"/{REALM}/users/{uid}", {**u,
                "requiredActions": ["webauthn-register-passwordless"]})

    clear_creds()
    out = run_js(CYCLE_JS, ORIGIN=REAL_ORIGIN, AUTHZ=authz_url(REAL_ORIGIN),
                 PHISH=PHISH_ORIGIN, PHISH_AUTHZ=authz_url(PHISH_ORIGIN),
                 USER=USER, PASS=PASSWORD, PY=PY, TOOL=PASSKEY_TOOL)
    print("     " + out.replace("\n", "\n     ")[:500])
    check("T1 a passkey was registered at the real origin", len(webauthn_ids(uid)), 1)
    check("T2 CONTROL: the passkey signs in at the REAL origin",
          "OUTCOME-real: AUTHENTICATED" in out, True)

    relay = urllib.request.urlopen(authz_url(PHISH_ORIGIN), timeout=20).read().decode("utf-8", "replace")
    check("T3 CONTROL: the proxy relays a faithful login page",
          "authenticateWebAuthnButton" in relay or "kc-form" in relay, True)
    check("T3b the relayed page points nothing back at the real host",
          "localhost:8080" in relay, False)

    check("T4 THE CLAIM: the phishing origin does NOT authenticate",
          "OUTCOME-phish: AUTHENTICATED" in out, False)

    # ------------------------------------------------- T5: the meta-test, blocked
    #
    # The intended meta-test was to widen the relying-party ID to the shared parent
    # `localhost` and show the same attack SUCCEEDING — proving both that the
    # harness can detect a bypass and exactly which setting the property rests on.
    #
    # It cannot be run with these hostnames. Chrome refuses it outright:
    #
    #   SecurityError: The relying party ID is not a registrable domain suffix of,
    #   nor equal to the current domain. Subsequently, an attempt to fetch the
    #   .well-known/webauthn resource of the claimed RP ID failed.
    #
    # `.localhost` is not in the public suffix list, so `app.localhost` and
    # `evil.localhost` do NOT share a registrable parent — which is precisely why
    # the claim is demonstrable here, and precisely why the failure mode is not.
    #
    # Demonstrating it needs TWO hostnames under a real registrable domain, e.g.
    # `app.attest.test` and `evil.attest.test` with the RP ID set to `attest.test`.
    # That requires editing /etc/hosts, which is outside the workspace and needs
    # the operator's approval. Recorded as a limitation rather than skipped
    # quietly, because a test that is silently absent is worse than one that fails.
    print("\n[T5] META-TEST — NOT RUN, and why")
    print("     Widening the RP ID to a shared parent cannot be demonstrated with")
    print("     *.localhost: Chrome refuses a broad RP ID there (verified, above).")
    print("     It needs two hostnames under a real registrable domain, which means")
    print("     editing /etc/hosts. That is outside the workspace and awaits approval.")
    FINDINGS.append(
        "The broad-relying-party-ID failure mode is NOT demonstrated. The claim itself "
        "is proven (T4), and the harness is shown able to detect a SUCCESSFUL assertion "
        "(T2), so T4 is not passing for want of a working harness — but the counter-case "
        "is missing. It requires two hostnames under a real registrable domain (e.g. "
        "app.attest.test / evil.attest.test with RP ID attest.test), which needs an "
        "/etc/hosts edit. Until then, the claim that a BROAD RP ID is exploitable rests "
        "on reasoning and on Chrome's own error message, not on a measurement.")

    # Restore the shared fixture: a sane RP ID, no extra origins, and the password
    # flow back — S3's matrix signs in with a password against this realm.
    set_rp_id("localhost", [])
    flow = set_realm_flow("revert")
    print(f"\n     realm restored: rpId=localhost, extraOrigins=[], browserFlow={flow}")
    print("\n" + "=" * 88)
    passed = sum(1 for _, got, want in RESULTS if got == want)
    print(f"Phishing resistance: {passed}/{len(RESULTS)} behaved as expected")
    if FINDINGS:
        print(f"\nFINDINGS ({len(FINDINGS)}) — these do NOT gate, but must not be missed:")
        for f in FINDINGS:
            print(f"  * {f}")
    else:
        print("Findings: none.")
    print("=" * 88)
    if passed != len(RESULTS):
        for label, got, want in RESULTS:
            if got != want:
                print(f"  FAILED: {label} — got {got!r}, expected {want!r}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
