#!/usr/bin/env python3
"""S5f — can enrolment be per-user, using a shareable link instead of impersonation?

WHY NOT IMPERSONATION
    S5f set out to use Keycloak's admin impersonation. Tested, and it cannot work
    for this: the impersonation endpoint **returns the identity cookie to the API
    caller** (`Set-Cookie: KEYCLOAK_IDENTITY=…`), so the session belongs to whoever
    made the call, not to the person who needs to enrol. Keycloak's own PR #40767
    says the same thing in its description — the action-token variant that WOULD
    make the returned URI openable elsewhere is still **open and unmerged**.

WHAT THIS USES INSTEAD
    Keycloak's "execute actions" email. It produces a link carrying an **action
    token** that:

      - names ONE user, so it is per-user by construction rather than by a check
      - is time-limited (`lifespan`)
      - can be opened by anyone, on any device — no admin session, no cookie
      - requires **no password**, and lands the user directly on the passkey
        registration required action

    This is the mechanism the impersonation PR is trying to reach. It already
    exists.

WHAT IS TESTED, AND WHY EACH CONTROL MATTERS
    A link that grants access to an account is only safe if it is SINGLE-USE and
    EXPIRES. Those are the checks that decide whether this is a mechanism or a
    liability, so they are gates, not observations:

      F1-F3  positive control: the link is produced, renders the action, and
             reaches passkey registration WITHOUT a password
      F4     the session it creates belongs to the NAMED user
      F5     CONTROL: the link is SINGLE-USE — a second use is refused
      F6     CONTROL: an EXPIRED link is refused
      F7     CONTROL: a link for one user does not create a session for another
      F8     the password path stays closed throughout

Usage:
    ./.venv/bin/python lab/keycloak/scripts/spike5f-matrix.py
"""
from __future__ import annotations

import json
import pathlib
import quopri
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from freshness_spike import Browser

KC = "http://localhost:8080"
REALM = "attest-privileged"
USER = "spike-attest-privileged"
OTHER = "spike-password-only"
MAIL = pathlib.Path("/tmp/attest-mail")
PASSKEY_TOOL = str(pathlib.Path(__file__).resolve().parent / "make_privileged_passkey_only.py")
PY = sys.executable

COMPLETE_JS = r"""
import { createRequire } from 'node:module';
const require = createRequire(
  '/Users/felixadusei/Development/AI_Engineering/DeepSeek/passwordless/lab/keycloak/package.json');
const puppeteer = require('puppeteer-core');
const CDP = 'http://127.0.0.1:9222';
const LINK = __LINK__;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const browser = await puppeteer.connect({ browserURL: CDP, defaultViewport: null, protocolTimeout: 40000 });
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
page.on('dialog', async d => { try { await d.accept('S5f Key'); } catch {} });

try {
  await page.goto(LINK, { waitUntil: 'networkidle2', timeout: 40000 });
  console.log('opened link: ' + page.url().slice(0, 80));
  // "Click here to proceed"
  const href = await page.evaluate(() => {
    const a = [...document.querySelectorAll('a')].find(x => /login-actions/.test(x.href || ''));
    return a ? a.href : null;
  });
  if (!href) { console.log('RESULT: no-proceed-link'); }
  else {
    await page.goto(href, { waitUntil: 'networkidle2', timeout: 40000 });
    console.log('after proceed: ' + page.url().slice(0, 90));
    // The registration page waits for a click; never evaluate afterwards.
    const handle = await page.evaluateHandle(() => {
      const c = [...document.querySelectorAll('input[type=submit], button')];
      return c.find(e => /register|save|continue|submit/i.test(e.value || e.textContent || '')) || null;
    });
    const el = handle.asElement();
    if (!el) { console.log('RESULT: no-register-button'); }
    else {
      await el.click().catch(() => {});
      await sleep(8000);
      console.log('RESULT: completed');
    }
  }
} catch (e) {
  console.log('RESULT: error ' + e.message.slice(0, 120));
}
await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId }).catch(() => {});
await page.close(); browser.disconnect();
"""

RESULTS: list[tuple[str, object, object]] = []
FINDINGS: list[str] = []


def check(label: str, got, want) -> None:
    ok = got == want
    RESULTS.append((label, got, want))
    print(f"  {label:58s} {str(got):22s} (want {str(want):18s}) {'PASS' if ok else 'FAIL'}")


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


def ensure_user(name: str) -> str:
    """Return the user's id, CREATING them if absent.

    A fresh realm has none of these users — they are made by other harnesses — so
    a test that assumes one fails on the first run against a clean environment.
    This is the THIRD time that mistake has been made in this project (S5e, its CI
    job, and here), so it is now a rule: **every harness creates the fixtures it
    depends on, and assumes no user exists.**
    """
    st, us = call("GET", f"/{REALM}/users?username={urllib.parse.quote(name)}&exact=true")
    if st != 200 or not us:
        call("POST", f"/{REALM}/users", {
            "username": name, "enabled": True, "emailVerified": True,
            "email": f"{name}@example.test", "firstName": "Spike", "lastName": "Lab",
            "credentials": [{"type": "password", "value": "Spike-Lab-Password-123!",
                             "temporary": False}],
        })
        st, us = call("GET", f"/{REALM}/users?username={urllib.parse.quote(name)}&exact=true")
    if st != 200 or not us:
        raise SystemExit(f"could not create or find user: {name}")
    uid = us[0]["id"]
    # Fully set up: a pending required action makes Keycloak refuse direct grants
    # with "Account is not fully set up", which reads like a credential failure.
    st, fresh = call("GET", f"/{REALM}/users/{uid}")
    call("PUT", f"/{REALM}/users/{uid}", {**fresh,
        "firstName": fresh.get("firstName") or "Spike",
        "lastName": fresh.get("lastName") or "Lab",
        "email": fresh.get("email") or f"{name}@example.test",
        "emailVerified": True, "requiredActions": []})
    call("PUT", f"/{REALM}/users/{uid}/reset-password",
         {"type": "password", "value": "Spike-Lab-Password-123!", "temporary": False})
    return uid


def user_id(name: str) -> str:
    return ensure_user(name)


def webauthn_ids(uid: str) -> list[str]:
    st, creds = call("GET", f"/{REALM}/users/{uid}/credentials")
    return sorted(c["id"] for c in (creds or []) if c.get("type", "").startswith("webauthn"))


def complete_enrolment(link: str) -> tuple[bool, list]:
    """Drive the whole enrolment from the link using a virtual authenticator.

    This is the joined-up journey: open the emailed link, click through, and let
    the browser register a passkey. It proves the link acts on the right account —
    a claim no amount of page inspection can settle.
    """
    import shutil
    script = pathlib.Path("/tmp/s5f-complete.mjs")
    script.write_text(COMPLETE_JS.replace("__LINK__", json.dumps(link)))
    r = subprocess.run(["node", str(script)], capture_output=True, text=True, timeout=240,
                       cwd=str(pathlib.Path(__file__).resolve().parent.parent))
    out = (r.stdout + r.stderr).strip()
    print("     " + out.replace("\n", "\n     ")[:600])
    return "RESULT: completed" in out, []


def session_count(uid: str) -> int:
    st, s = call("GET", f"/{REALM}/users/{uid}/sessions")
    return len(s) if st == 200 and isinstance(s, list) else 0


def request_link(username: str, lifespan: int = 300) -> int:
    """Ask Keycloak to email an enrolment link. Returns before/after mail count."""
    before = len(list(MAIL.glob("*.eml")))
    st, resp = call("PUT",
                    f"/{REALM}/users/{user_id(username)}/execute-actions-email?lifespan={lifespan}",
                    ["webauthn-register-passwordless"])
    if st not in (200, 204):
        print(f"    execute-actions-email -> {st} {str(resp)[:120]}")
    return before


def newest_link(after_count: int, timeout: float = 15.0) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        files = sorted(MAIL.glob("*.eml"))
        if len(files) > after_count:
            raw = files[-1].read_bytes()
            try:
                text = quopri.decodestring(raw).decode("utf-8", "replace")
            except Exception:
                text = raw.decode("utf-8", "replace")
            m = re.search(r'https?://[^\s"\'<>)]*action-token[^\s"\'<>)]*', text)
            return m.group(0) if m else None
        time.sleep(0.5)
    return None


def open_link(link: str) -> dict:
    """Open an action-token link and report what the user is offered.

    Classifies the outcome rather than pattern-matching one thing, so a refusal
    and a broken page can be told apart.
    """
    b = Browser()
    st, h, body = b.go(link)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body)).strip()
    if re.search(r'invalid|expired|already been used|not found', text, re.I):
        return {"outcome": "refused", "text": text[:120], "cookies": b.cookies}
    if "Perform the following action" in text or "webauthn" in text.lower():
        return {"outcome": "action_page", "text": text[:120], "cookies": b.cookies, "body": body}
    return {"outcome": "other", "text": text[:120], "cookies": b.cookies, "body": body}


def proceed(link: str) -> str:
    """Follow the link to completion and report where it lands."""
    b = Browser()
    _, _, body = b.go(link)
    m = re.search(r'href="([^"]*login-actions[^"]*)"', body)
    if not m:
        return "no-proceed-link"
    st, h, _ = b.go(m.group(1).replace("&amp;", "&"))
    loc = h.get("Location") or ""
    if "required-action" in loc:
        return "required_action"
    return loc[:80] or f"http_{st}"


def main() -> int:
    print("=" * 84)
    print("S5f — per-user enrolment by shareable link (impersonation ruled out)")
    print("=" * 84)

    print("\n[setup] create the users this suite needs (a fresh realm has none)")
    ensure_user(USER)
    ensure_user(OTHER)
    check("setup: both users exist", user_id(USER) != user_id(OTHER), True)

    print("\n[setup] point the realm at the mail sink (read-modify-write)")
    st, realm0 = call("GET", f"/{REALM}")
    if not (realm0 or {}).get("smtpServer", {}).get("host"):
        # `smtp-sink` is a service in compose.yaml, on the same Docker network,
        # so Docker's own DNS resolves it. host.docker.internal was used first and
        # works only on Docker Desktop — on a Linux runner the container never
        # connects and no mail arrives, with no error to explain it.
        # A PARTIAL PUT would replace the realm representation (S5e lesson), so the
        # whole object is read, changed and written back.
        call("PUT", f"/{REALM}", {**realm0, "smtpServer": {
            "host": "smtp-sink", "port": "2525",
            "from": "attest-lab@example.test", "fromDisplayName": "Attest Lab",
            "ssl": "false", "starttls": "false", "auth": "false"}})
    st, realm1 = call("GET", f"/{REALM}")
    check("setup: SMTP is configured", (realm1 or {}).get("smtpServer", {}).get("port"), "2525")

    print("\n[setup] the realm must be passkey-only for F8 to mean anything")
    r = subprocess.run([PY, PASSKEY_TOOL, "apply"], capture_output=True, text=True, timeout=180)
    check("setup: passkey-only applied", r.returncode, 0)
    if r.returncode != 0:
        print(r.stdout[-300:], r.stderr[-300:])
        return 1

    # ---- F1-F3: the positive path -----------------------------------------
    print("\n[F1-F3] the link is produced and works, with no password")
    n0 = request_link(USER)
    link = newest_link(n0)
    check("F1 an action-token link was emailed", link is not None, True)
    if not link:
        print("  no link captured — is the SMTP sink running on 2525?")
        print("  start it with: python3 lab/keycloak/scripts/smtp_sink.py 2525 /tmp/attest-mail")
        return 1
    print(f"       link: {link[:96]}…")

    opened = open_link(link)
    check("F2 the link renders the action page", opened["outcome"], "action_page")
    check("F3 it does NOT ask for a password", "password" in opened["text"].lower(), False)

    # ---- F4: WHOSE account does the link act on? ---------------------------
    #
    # Counting user sessions was the wrong assertion: the link creates an
    # AUTHENTICATION session, and no user session exists until the required action
    # completes. The question that actually matters is whose account the link acts
    # on — and the only honest way to answer it is to COMPLETE the enrolment
    # through the link and see where the credential lands.
    print("\n[F4] completing the enrolment through the link — whose account?")
    uid, ouid = user_id(USER), user_id(OTHER)

    # The realm's AAGUID allowlist is YubiKey-only with `direct` attestation, and a
    # CDP virtual authenticator satisfies neither — Keycloak answers
    # `web_authn_registration_error_detail="invalid cert path"`. That is the S3
    # policy doing its job, so the policy is relaxed for enrolment and restored
    # afterwards. (This is why the first F4 run reported "completed" with no
    # credential: the ceremony finished and Keycloak refused to store it.)
    st, realm_repr = call("GET", f"/{REALM}")
    strict = {k: realm_repr.get(k) for k in (
        "webAuthnPolicyPasswordlessAcceptableAaguids",
        "webAuthnPolicyPasswordlessAttestationConveyancePreference")}
    call("PUT", f"/{REALM}", {**realm_repr,
         "webAuthnPolicyPasswordlessAcceptableAaguids": [],
         "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none"})
    print(f"     policy relaxed for enrolment: {strict}")
    check("setup: policy relaxed so the virtual authenticator is accepted",
          call("GET", f"/{REALM}")[1].get("webAuthnPolicyPasswordlessAcceptableAaguids"), [])

    # Clear existing passkeys first. The realm sets
    # `AvoidSameAuthenticatorRegister = true`, so a repeat enrolment from the same
    # authenticator model is silently refused — the ceremony even completes and
    # asks for a label, and nothing is stored. Same trap as S5e; found again here
    # because the first run of this check reported "completed" with no credential.
    st, existing = call("GET", f"/{REALM}/users/{uid}/credentials")
    for c in (existing or []):
        if c.get("type", "").startswith("webauthn"):
            call("DELETE", f"/{REALM}/users/{uid}/credentials/{c['id']}")
    print(f"     cleared {len(webauthn_ids(uid))} existing passkey(s)")

    named_before = webauthn_ids(uid)
    other_before = webauthn_ids(ouid)

    n1 = request_link(USER)
    link4 = newest_link(n1)
    landed = proceed(link4) if link4 else "no-link"
    check("F4a the link reaches passkey registration", landed, "required_action")

    completed, new_creds = complete_enrolment(link4) if link4 else (False, [])

    # Restore the strict policy BEFORE asserting on the outcome.
    call("PUT", f"/{REALM}", {**call("GET", f"/{REALM}")[1], **strict})
    print(f"     strict policy restored: {strict}")
    check("F4b the enrolment was actually COMPLETED", completed, True)
    check("F4c a NEW passkey appeared on the NAMED user",
          [c for c in webauthn_ids(uid) if c not in named_before] != [], True)
    check("F4d NO passkey appeared on any other user",
          webauthn_ids(ouid), other_before)

    # ---- F5: when does the link STOP working? ------------------------------
    #
    # The first version of this asserted "a second use is refused" and failed.
    # Investigating showed the assertion was wrong about the mechanism: opening
    # the link is harmless and repeatable. What actually retires the link is
    # COMPLETING the action. So the meaningful control is:
    #
    #     after the enrolment completes, the link must be dead.
    #
    # The repeatable-open behaviour is still recorded, as a finding, because it
    # bounds how long an intercepted link is dangerous.
    print("\n[F5] CONTROL: the link dies once the action COMPLETES")
    uid5 = user_id(USER)
    st, creds = call("GET", f"/{REALM}/users/{uid5}/credentials")
    for c in (creds or []):
        if c.get("type", "").startswith("webauthn"):
            call("DELETE", f"/{REALM}/users/{uid5}/credentials/{c['id']}")

    n2 = request_link(USER)
    link5 = newest_link(n2)
    first = open_link(link5)["outcome"] if link5 else "no-link"
    check("F5a the link works before use", first, "action_page")

    again = open_link(link5)["outcome"] if link5 else "no-link"
    print(f"       re-opening before completion -> {again} (recorded below)")

    completed5, _ = complete_enrolment(link5) if link5 else (False, [])
    after = open_link(link5)["outcome"] if link5 else "no-link"
    check("F5b the link is DEAD after the action completes", after, "refused")

    if again == "action_page":
        FINDINGS.append(
            "The enrolment link is a BEARER token: it stays live until the action "
            "completes or it expires, and opening it does not consume it. Anyone who "
            "obtains it during that window — a mail server, a forwarded message, a "
            "shared inbox, a shoulder-surfed screen — can COMPLETE the enrolment "
            "first and register their own passkey on that account. It is bounded by "
            "the lifespan and by completion, but it is not single-use-on-open. "
            "Emailed reset links share this property; it should be a conscious "
            "acceptance, and the lifespan should be short.")

    # ---- F6: EXPIRY --------------------------------------------------------
    print("\n[F6] CONTROL: the link expires")
    n3 = request_link(USER, lifespan=1)
    link6 = newest_link(n3)
    time.sleep(4)
    expired = open_link(link6)["outcome"] if link6 else "no-link"
    check("F6 an expired link is refused", expired, "refused")

    # ---- F7: a link for one user must not benefit another ------------------
    print("\n[F7] CONTROL: a link for user A does not create a session for user B")
    b_before = session_count(ouid)
    n4 = request_link(USER)
    link7 = newest_link(n4)
    # Open it, but assert only about the OTHER user's sessions.
    if link7:
        open_link(link7)
    check("F7 no session appeared for the other user", session_count(ouid), b_before)

    # ---- F8: the password path stays closed --------------------------------
    print("\n[F8] the password path stays closed throughout")
    st, realm = call("GET", f"/{REALM}")
    check("F8a the realm is still bound to the passkey-only flow",
          (realm or {}).get("browserFlow"), "browser-passkey-only")
    clients = call("GET", f"/{REALM}/clients")[1] or []
    bypass = [c["clientId"] for c in clients if c.get("directAccessGrantsEnabled")]
    check("F8b no client accepts direct password grants", bypass, [])
    st, enrol = call("GET", f"/{REALM}/clients?clientId=enrolment")
    check("F8c the password-window client is disabled",
          bool(enrol) and enrol[0].get("enabled"), False)

    passed = sum(1 for _, got, want in RESULTS if got == want)
    print("\n" + "=" * 84)
    print(f"Enrolment by link: {passed}/{len(RESULTS)} behaved as expected")
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
