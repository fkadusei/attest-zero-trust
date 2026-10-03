# Evidence register

Every load-bearing claim in this project, how it is actually evidenced, and **how much confidence it
deserves**. This file exists because a security project's reputation rests on being precise about the
difference between "we tested this" and "we believe this".

If you find a claim elsewhere in this repository that is stated more strongly than it is recorded
here, **this file is right and the other one is a bug.** Please report it.

---

## How to read the confidence levels

| Level | Means |
|---|---|
| **Verified** | We ran an experiment, it had a **control**, and the control behaved as required. This is the only level that justifies the word "proven". |
| **Corroborated** | Multiple independent external sources agree, and we checked at least two of them ourselves. |
| **Documented** | One authoritative external source states it and we have not tested it. Could be wrong; some documented things have been. |
| **Assumed** | Believed on reasoning, not evidence. Treat as a risk, not a fact. |
| **Unverified** | Explicitly not tested. Named so it cannot be quietly forgotten. |

---

## 1. Verified — we ran it, with a control

| Claim | Evidence | Confidence |
|---|---|---|
| A non-approved authenticator is **refused at enrolment** by the AAGUID allowlist | S3 matrix, B-vs-C isolates the allowlist; C is the control | **Verified** |
| The authenticator-**attachment restriction** is enforced | S3, D-vs-E isolates attachment; E proves the transport works | **Verified** |
| An authenticator that **declines to attest** is refused, not admitted | S3 row B rejects an all-zero AAGUID | **Verified** |
| Keycloak **exposes the AAGUID** of registered credentials | Read directly out of `credentialData` for a credential we created | **Verified** |
| Keycloak **does not validate AAGUID format** | `"not-a-guid"` was accepted and stored verbatim | **Verified** |
| Keycloak **writes `cnf.jkt`** into DPoP-bound tokens | Inspected the issued token | **Verified** |
| A bound token **without a valid proof is refused** | S1, 6/6 enforcement behaviours against Keycloak's own userinfo endpoint | **Verified** |
| Our own **verifier logic** accepts valid proofs and refuses wrong-key, wrong-method, wrong-URL, missing-`ath`, and wrong-token proofs | S1, 6/6, prototype in `lab/keycloak/scripts/dpop_spike.py` | **Verified** |
| A **bound token must use the `DPoP` scheme**, not `Bearer` | S1: the same token under `Bearer` returns 401, and the challenge names *Bearer* | **Verified** |
| A **resource-server proof must carry `ath`** | S1: omitting it returns a misleading `invalid_token`; adding it returns 200 | **Verified** |
| The browser **keeps its session key across a full quit and relaunch**, and it is the *same* key | S4/S4b, including a control requiring a fresh key to be rejected | **Verified** (Chromium only — see §4) |
| **Keycloak's LoA condition does not gate** the subflow it is attached to | S5 enabled/disabled/enabled test: the prompt tracks the subflow, not the requested level | **Verified** |
| A **CONDITIONAL subflow at the top level of the browser flow breaks it** | S5 bisect: the flow returns HTTP 400 from step 4 onward, and a pristine copy works | **Verified** |
| **`prompt=login` forces a genuine ceremony** even with a live session | S5c T3a: the login form is demanded despite a valid session cookie | **Verified** |
| Reusing a live session **does not** change `auth_time` | S5c T2b — the control that makes the next row meaningful | **Verified** |
| `auth_time` **advances** on re-authentication | S5c T3c: advanced by exactly the deliberate 3-second wait | **Verified** |
| An old token **does not gain freshness** from a later re-authentication | S5c T4/T4b — the old token is refused by a window the new token passes. **The first version of this re-parsed the same token and compared it to itself, which could not fail** | **Verified** |
| `max_age` is honoured **conditionally and correctly** | S5c T5a/T5b: `3600` reuses a 2s-old session; `0` re-authenticates it | **Verified** |
| A freshness policy **refuses** stale tokens | S5c T6b | **Verified** |
| A freshness policy **refuses a token with no `auth_time`** — fail closed | S5c T6c | **Verified** |
| A freshness policy **refuses a future `auth_time`** | S5c T6d | **Verified** |
| A passkey-only browser flow leaves **no password field** and no username field | S5d A1/A2 — the flow is usernameless | **Verified** |
| **A passkey signs in successfully** against the passkey-only flow | S5d B2 — the positive case that makes "refused" meaningful | **Verified** |
| A user with a password but **no passkey is locked out** | S5d C1-C3, **corrected**: the original C1 only counted credentials, and its control user was in `attest-users` — a realm that is not passkey-only. An independent reviewer signed in as that user and got a token while C1 reported PASS. Now a real sign-in is attempted in the correct realm | **Verified** |
| Recovery from a broken flow is **one API call** | S5d D1/D2a/D2b, **corrected**: `D1` used to compare a hard-coded constant against itself and could not fail; `D2` accepted a URL that is true in almost any outcome. D1 now reads the realm's real binding and D2 completes a real sign-in | **Verified** |
| The `flow_tool` backup/restore **detects a broken flow and restores it** | Tested in a scratch realm: passes untouched, detects damage, restores exactly | **Verified** |
| **A passkey-only browser flow does NOT stop direct password grants** | S5d A′ — `admin-cli` had `directAccessGrantsEnabled: true`, so a password still bought a token despite the login page refusing one | **Verified** |
| A bound **client** can use a different flow from the realm default | S5e — the `enrolment` client accepts a password while normal clients stay passkey-only, verified every run as a control | **Verified** |
| A password path can be **closed by default** and opened deliberately | S5e E1/E2 | **Verified** |
| The window **expires and is swept closed**, and the password path is gone afterwards | S5e E7-E9, tested by waiting for a real expiry rather than editing a timestamp | **Verified** |
| The window **records who, when and why** | S5e E10/E11 | **Verified** |
| **Keycloak ships with the event log DISABLED** | S5e — `eventsEnabled: false`, `adminEventsEnabled: false` in this realm. There was **no audit trail of any kind** until it was switched on | **Verified** |
| Keycloak's **`conditional-user-role` gates correctly** — with `negate` as the discriminator | Corrected S5e pass: `negate=false` shows the password only *with* the role; `negate=true` shows it only *without*. Requires identity-first (username split from password) | **Verified** |
| **A conditional that skips the only credential step issues a token** | A real token obtained with **no credential at all**, only a username, against the identity-first arrangement | **Verified** |
| The **shipped S5e design does not have that bypass** | After restoring it: a username-only POST returns HTTP 200, no code, password form still required | **Verified** |
| **Keycloak impersonation is NOT a shareable link** | The endpoint returns `Set-Cookie: KEYCLOAK_IDENTITY` to the **API caller**; opening the redirect with no cookies sets no session. Corroborated by Keycloak PR #40767, open and unmerged, which says the same | **Verified** |
| An **action-token link** can be emailed for one named user, needs no password, and reaches passkey registration | S5f F1-F4, captured through a local SMTP sink | **Verified** |
| That link **completes a real enrolment on the named user**, and on no other | S5f F4b-d — a real passkey registered through the link | **Verified** |
| The link is **invalidated once the action completes** | S5f F5b | **Verified** |
| An **expired link is refused** | S5f F6 | **Verified** |
| The link is a **bearer token**: opening it does not consume it | S5f — re-opening before completion still renders the action. Recorded as a finding, not a gate | **Verified** |
| **A passkey cannot be used through a phishing proxy**, even when the proxy relays the genuine page byte-for-byte | S9 T4 — the browser refuses with `SecurityError: The relying party ID is not a registrable domain suffix of, nor equal to the current domain` | **Verified** |
| The **same credential signs in at the real origin**, so the refusal is a refusal and not a broken harness | S9 T2 — the positive control that makes T4 meaningful | **Verified** |
| The relay is **faithful**: no reference to the real host survives in the served page | S9 T3/T3b — every absolute URL rewritten to the attacker's origin | **Verified** |
| **A BROAD relying-party ID IS exploitable** — the browser produces a valid assertion for the attacker's origin | S9b — **the counter-case**, measured. Same relay, same credential: `app.attest.test` gives `SecurityError`, `attest.test` gives `resolved` | **Verified** |
| **A Cedar permit that does not constrain the PRINCIPAL TYPE grants access to any entity with a matching tenant attribute** | L4 — a principal of type `MysteryActor` was ALLOWED until every permit named the kinds of principal it applies to | **Verified** |
| **Cedar can return `allow` alongside a non-empty `errors` array** | L4 — when a *different* policy fails to evaluate. The PDP treats any error as a denial, because the failing policy may have been a `forbid` | **Verified** |
| **Keycloak marks a DPoP-BOUND access token `typ: "DPoP"`, not `"Bearer"`** | L3 — decoded from live tokens. An L1 check that accepted only `"Bearer"` would have rejected **every** bound token, passing all 70 unit tests, none of which verified a bound token through L1 | **Verified** |
| **Our DPoP proof verifier agrees with a real Keycloak-bound token** | L2 — a genuinely `cnf.jkt`-bound token from the live provider plus a real proof verifies; 13 enforcement points each fail for their own asserted reason | **Verified** |
| **Keycloak's access-token marker is the PAYLOAD `typ` ("Bearer"), not the header's.** The header `typ` is `"JWT"` for access tokens and ID tokens alike, so a header check cannot distinguish them | L1 — decoded from live tokens: access `{header: JWT, payload: Bearer}`, ID `{header: JWT, payload: ID}` | **Verified** |
| **WebAuthn requires a secure context**; `*.localhost` is one over plain HTTP and a real domain is not | S9b — Keycloak reported `WebAuthnUnsupportedBrowser` until Chrome was told to treat the origins as secure. **Not a DNS problem** | **Verified** |
| `http.cookiejar` **cannot drive a Keycloak login** | Cookies stored as `localhost.local` + `Secure`, so never sent over http; error is "Restart login cookie not found" | **Verified** |

## 2. Corroborated — external sources, checked

| Claim | Evidence | Confidence |
|---|---|---|
| **CVE-2026-97176** exists: a user with a low-level session can obtain a token asserting a higher level than they performed | Red Hat record, NVD entry, upstream GHSA-5jw9-cc9v-8h8r, OpenCVE — all four read directly | **Corroborated** |
| The CVE has **no fix and no available mitigation** | Red Hat `FixState: Affected` + mitigation "not available"; upstream advisory lists **no patched version** | **Corroborated** |
| The vulnerable classes are **in the artifact we run** | Extracted `keycloak-services-26.8.0.jar` and found `ConditionalLoaAuthenticator.class`, `...Factory.class`, `LoAUtil.class` | **Verified** (class presence) |

## 2a. The audit that corrected this register

This register previously overstated its own confidence. An independent adversarial review — plus a
re-run of every suite — found **the same class of defect in five more places**: checks that could not
fail, or that were satisfied by a state other than the one they claimed to test.

That class is now named, because it keeps recurring:

| The defect | How it hides |
|---|---|
| **A check that cannot fail** | Compares a constant to itself; re-reads the same value; asserts something true in every outcome |
| **"Denied" vs "broken"** | An absent field, a 400, or a refusal looks identical whether the control worked or the client was disabled |
| **The wrong subject** | The check examines something real, but not the thing the claim names — a different realm, a bygone flow, a session left over from an earlier step |
| **A test of a mock** | The assertion is about a function defined inside the test file, not about any deployed control |
| **Self-vouching** | The tool's own success message is the evidence that it succeeded |

### What changed as a result

- **S5c T4** was a tautology; it now refuses the old token by a window the new token passes.
- **S5c T6** tested a prototype; it is relabelled, not deleted.
- **S5d C1** counted credentials in the wrong realm; it now attempts a real sign-in in the right one.
- **S5d D1** compared a constant to itself; it now reads the realm's actual binding.
- **S5d D2** accepted almost any URL; it now completes a real sign-in.
- **S5d `loginOutcome`** was rewritten twice: first because a successful sign-in for Keycloak's
  `account` client carries **no `code=`**, then because Node's `fetch` keeps no cookies, so a
  multi-step login *always* looked rejected — which made a "must be refused" check pass for the wrong
  reason. It now drives the real browser and clears cookies before every attempt.
- **S5c T7** hard-coded a flow alias and counted a **DISABLED** password form as a live one — so its
  finding was emitted even after the flow had been made passkey-only, and could never be cleared.
- **S5e E1/E9a** discarded the HTTP status; they now assert the **cause** of a refusal, not merely the
  absence of a field.
- **S5e E8** grepped the tool's own success message; it now asserts the client is actually disabled.
- **S5e E10/E11** were self-vouching; **E12** additionally requires Keycloak's own event log to contain
  authentications through the client.

### The standing rule this produced

> **Every suite must include a negative meta-test: deliberately break the property, and confirm the
> suite goes RED.**

Observing a green run proves nothing about whether a check can fail. S5d's meta-test was performed by
neutering the enforcement and re-running: `A'` and `A'2` both went red and the suite exited 1. Three of
the checks above would have been caught immediately by this habit.

**A note on the S5d meta-test itself:** the first attempt re-enabled direct grants and the suite still
passed — because the suite's own setup re-closed them. That is the setup enforcing the property, not
the check failing. The check was validated by breaking the *enforcement*, not the *property*.

## 3. Documented — believed, not tested by us

| Claim | Source | Confidence |
|---|---|---|
| Keycloak 26.4 shipped **official DPoP support** | Keycloak's own announcement | **Documented** |
| Keycloak 26.4 made **passkeys generally available** | Keycloak's own announcement | **Documented** |
| Passkeys require the **WebAuthn Passwordless policy** to be enabled | Keycloak docs | **Documented** |
| Passkeys work through **managed login v2** (and not v1) | Keycloak docs | **Documented** |
| A **"Conditional - credential"** authenticator skips 2FA when a passkey was used | Keycloak's 26.4 announcement | **Documented** |
| Keycloak has **no official risk-based adaptive authentication** | Absence of any such feature in docs or API | **Assumed** — see §5 |
| NIST **SP 800-63Bsup1** exists and concerns syncable authenticators | We read the publication page and abstract, **not the full text** | **Documented** (weakly) — see §6 |
| The exact `acr.loa.map` format and semantics | Used from Keycloak docs; behaviour did not match | **Documented** — and contradicted in practice |

## 4. Unverified — named so they cannot be forgotten

| Not tested | Why it matters | Blocked on |
|---|---|---|
| A **real TLS** environment | S9b satisfies the secure-context requirement with a Chrome flag standing in for the certificate a real deployment has. The origin check does not depend on the certificate, so the conclusion should hold — but that is reasoning | A deployed environment |
| Phishing over **real TLS, DNS and a real certificate** | S9 runs over HTTP on loopback. WebAuthn's origin check does not depend on the certificate, so the conclusion should hold — but that is reasoning, not measurement | A deployed environment |
| The **`DPoP` header survives** CloudFront → ALB → API Gateway | A hop that strips it breaks binding **silently** | AWS |
| **Firefox and Safari** keep the session key | The two non-Chromium engines; Safari is the likeliest to evict | A manual minute each |
| A **physical hardware key** is accepted | Only refusal has been tested; the known failure is lockout, not bypass | A physical key |
| Our **permissions engine accepts our tokens** | It was built for a different issuer | AWS |
| **Revocation latency** is under a minute | Claimed, never measured | AWS |
| The login server **clusters** on Fargate | A single instance is not viable | AWS |
| Freshness over a **real browser and a real user** | S5c drives Keycloak over HTTP with scripted forms; it proves protocol behaviour, not user experience | A browser-driven test |
| Behaviour of `prompt=login` when re-authentication is **impossible** | A user whose only credential was removed. Expected to lock out; unproven, and lockout paths deserve their own test | A lab user with no credential |
| Whether the **privileged flow requires a passkey** | It does **not** today — see §5.8 | S5d |

## 5. Where confidence is genuinely lower than it looks

Recorded because the instruction is explicit: **say when you are not certain.**

1. **"Keycloak has no official risk-based adaptive authentication."** This is an argument from
   absence — we found none in the docs or API. Absence of evidence is weaker than evidence of
   absence, and a feature could exist that we did not find. It drives a real design decision
   (ADR-012), so it deserves scrutiny.

2. **The AAGUID values used in the allowlist are not verified against physical hardware.** The
   YubiKey AAGUID in the lab came from a published list, not from a device we held. If it is wrong,
   the allowlist would refuse a legitimate key — a lockout, not a bypass, but still wrong.

3. **"`navigator.storage.persist()` guards against eviction, not restarts."** This is our
   *interpretation* of why a refused `persist()` still let the key survive. It is consistent with the
   observed behaviour and with how the API is documented — but we did not test eviction, because
   provoking it takes seven days of inactivity or storage pressure.

4. **We have not reproduced CVE-2026-97176.** The advisory describes a silent *bypass*; our S5
   observed *over-enforcement*. Different symptoms of the same component, and no claim here that they
   share a cause. Both are documented as what they are.

5. **Upstream Keycloak's affected version range is not published.** The advisory is filed against
   `keycloak/keycloak`, and the vulnerable classes are in our artifact, but **no version range is
   stated anywhere we could find**. "26.8.0 is affected" is an inference from component presence, not
   a published fact.

6. **NVD has not analysed the CVE** — its status is "Awaiting Analysis". The description is Red
   Hat's. NVD could revise or re-score it.

7. **`max_age` nearly produced a published false finding.** The first S5c run reported that
   `max_age=0` did not force re-authentication. That was a **test error**, not a design flaw: the
   request was made on a session 0 seconds old, and `elapsed > max_age` is `0 > 0` — false. Reusing
   the session was correct. Recorded because the near-miss is more instructive than the result:
   **a failing test is a hypothesis about the code, not a conclusion about it.**

8. **ADR-013's strength argument does not hold as configured.** It claimed re-authentication on the
   privileged realm *is* a hardware-key assertion. S5c read the flow and found a **`Username Password
   Form` still present**, with WebAuthn only as a conditional second factor. So the replacement gives
   verified **freshness** and, today, **no strength**. Corrected in ADR-013 and tracked as S5d.
   Anything user-facing must say *"you signed in again just now"*, never *"you used your key just
   now"*, until that flow work is done.

9. **A passkey-only browser flow is not a passkey-only realm.** The most serious thing S5d found:
   direct grants at the token endpoint bypass the browser flow entirely, so a realm can refuse
   passwords at the login page and still issue tokens for one. `admin-cli` is created by Keycloak in
   **every realm** and is public, so nothing protects it by default. **This is now closed in
   `attest-privileged`, but the same gap exists in `attest-users` and in any realm not yet checked.**
   It is a configuration default, not a one-off mistake.

10. **A negative test can pass for the wrong reason.** S5d's direct-grant check reported **pass** on its
    first run — because the test user's password had not been set to the value the test used. The grant
    failed on bad credentials, not on being refused. It only became a real check once the positive case
    (a passkey signing in) also worked. **A refusal is only evidence when the grant would otherwise
    succeed.**

11. **CORRECTED — the earlier claim that Keycloak's `conditional-user-role` "never gated" was wrong.**
    It does gate, exactly as documented. The tests behind the original claim were invalid twice over:
    the **client was disabled**, so every request returned HTTP 400 `"Client disabled."`; and the
    probe **only read the first page**, whereas with identity-first login the condition is evaluated
    only *after* the username is submitted. Both faults produced "no password field", which is
    indistinguishable from a condition refusing. **A test that cannot tell "denied" from "broken" is
    not a test.**

12. **But gating it that way FAILS OPEN — and that is worse.** With the gate working, skipping the
    credential step does not fail the flow: Keycloak **issues a token anyway**. Verified by obtaining
    a real token while supplying **no credential of any kind, only a username string**.

    > **In Keycloak, a conditional that can skip the only credential step in a flow causes that flow
    > to complete successfully without authentication.**

    `Username Form` identifies a user; it does not authenticate one. Making the subflow `REQUIRED`
    rather than `CONDITIONAL` does not fail closed — it removes the gate instead.

    **The shipped S5e design is not affected** (its credential step is a plain `Username Password
    Form` that no conditional can skip) — verified after the experiment. But the per-user requirement
    remains **unmet**, and the obvious way to build it is unsafe.

12. **Nothing verifies that the sweep actually runs.** The time limit is a sweep, not an enforced
    deadline, so there is a gap between expiry and the sweep. In production it must be a scheduled
    task — and **if that schedule stops, the window stays open silently**. No test covers that.

13. **The enrolment window is still not restricted to one user.** While a window is open, any user in
    the realm can authenticate through the enrolment client with their password — proven by completing
    a real sign-in as a second user (E12). What the window does narrow the hole to: one dedicated
    client, briefly, on the record — rather than the whole realm, indefinitely, silently. The
    candidate replacement is **Keycloak impersonation**, which yields a one-time, per-user,
    time-limited, audited link and removes the password path entirely. **That is untested.**

14. **The enrolment link is a bearer token, and its security is the mailbox's security.** It stays
    live until the action completes or it expires, so anyone who obtains it in that window can
    **complete the enrolment first** and register their own passkey on that account. Bounded, not
    open-ended — emailed reset links behave the same way — but it must be a conscious acceptance with a
    **short** lifespan. See `lab/keycloak/SPIKE-5f-RESULTS.md` §4.

15. **Phishing resistance holds for the passkey — and the soft spots are elsewhere.** S9 proves a
    passkey bound to a narrow domain cannot be used through an attacker's origin, even with a
    byte-for-byte relay of the genuine page. But a phishing proxy could still abuse the paths this
    project deliberately built: the **enrolment window** (S5e) accepts a password while open, and the
    **enrolment link** (S5f) is a bearer token. Neither is phishable *silently* — both are bounded and
    audited — but neither is protected by WebAuthn's origin binding. **The passkey is not the weak
    point; the deliberate exceptions around it are.**

16. **Phishing resistance is a property of the relying-party ID — now measured, not argued.** S9b shows
    the *same* relay, credential and browser being **refused** under a narrow RP ID (`SecurityError`) and
    **answering** under a broad one (`resolved`). So the guidance is a measured result: set the RP ID to a
    domain the attacker cannot serve a matching origin for, and keep it as narrow as the deployment
    allows. The cost is real and should be chosen deliberately — a credential bound to
    `app.example.com` will not answer for `login.example.com`.

17. **WebAuthn requires a secure context, which constrains local testing.** `*.localhost` is treated as
    trustworthy over plain HTTP; any other hostname is not, and `window.PublicKeyCredential` is simply
    undefined. Keycloak reports it as `WebAuthnUnsupportedBrowser`, which reads like a browser problem.
    **A resolvable hostname over HTTP is not enough** — this needs TLS, or Chrome's
    `--unsafely-treat-insecure-origin-as-secure`. It was never a DNS problem, and time was spent on DNS
    before the log said otherwise.

18. **An access-token check in the wrong place is worse than none.** Keycloak marks access
    tokens with payload `typ: "Bearer"` and ID tokens with `typ: "ID"` — but the JOSE **header**
    `typ` is `"JWT"` for both. An early version of the API verifier checked the header. The
    positive control caught it. **The dangerous "fix" would have been to change the expected value
    to `"JWT"`,** which would have made the test pass while the check protected nothing. Asserting
    the *reason* for each rejection is what exposed this; asserting only "it failed" would not have.

19. **The decision to reject LoA step-up does not rest on the CVE.** S5 independently showed by
   experiment that the mechanism does not gate. That finding stands on its own evidence. This is
   recorded deliberately, so the decision cannot be undermined by someone disputing the advisory.

## 6. Things we have read only in summary

Flagged separately because reading an abstract is not reading a document, and this project has
already been wrong once by trusting a summary:

- **NIST SP 800-63Bsup1** — we read the NIST publication page and its abstract, **not the full text**.
  Every claim about how syncable passkeys count toward assurance levels is therefore **weakly
  documented**, and that is exactly why it is Spike #6 and why it requires an independent reviewer.
  **No AAL claim should be made publicly until that is done.**
- **NIST SP 800-207** — referenced for the PDP/PEP principle and "assume breach". The principle is
  correct; we have not verified our mapping against the document clause by clause.
- **OMB M-22-09** — referenced for the phishing-resistant MFA requirement. Not read directly.

## 6a. Is the test harness itself trustworthy?

A result is only as good as the harness that produced it, so the harness is audited too — and this
audit **found real defects in it**.

### Found and fixed: two scripts could not fail

`run-matrix.sh` and `dpop_spike.py` both printed `PASS`/`FAIL` rows but **never changed their exit
code**. Anything automating them — including the CI added in the same change — would have reported
success on a total regression. The gate was decorative.

Both are fixed, and **both fixes were negative-tested**, because an untested fix is just another
unverified claim:

| Test | Command | Expected | Result |
|---|---|---|---|
| Matrix, all rows wrong | stub `node` to report an unmatchable outcome | exit 1 | **exit 1** ✓ |
| Matrix, real run | `bash lab/keycloak/scripts/run-matrix.sh` | exit 0 | **exit 0**, 5/5 ✓ |
| DPoP, one verifier check inverted | throwaway copy with an inverted expectation | exit 1 | **exit 1**, 5/6 ✓ |
| DPoP, real run | `python3 lab/keycloak/scripts/dpop_spike.py` | exit 0 | **exit 0**, 6/6 + 6/6 ✓ |

**What this does and does not mean for the earlier results.** The S1 and S3 findings **stand**: they
were read off the printed rows and confirmed with controls at the time. What was broken was the
ability to *detect a future regression* automatically — not the original observations. The
distinction matters and is not being blurred in either direction.

### Audited: every other script that reports an outcome

| Script | Gates its exit code? |
|---|---|
| `scripts/check_docs.py` | yes |
| `scripts/build_docs.py` | yes |
| `lab/keycloak/scripts/configure-realms.py` | yes (`return 0 if all_ok else 1`) |
| `lab/keycloak/scripts/patch-realm.py` | yes |
| `lab/browser/run.mjs` | yes |
| `lab/browser/run_firefox.py` | yes |
| `lab/keycloak/scripts/spike3-enrolment-test.mjs` | **No, deliberately** — `REJECTED` is often the correct outcome, so the exit code cannot be the verdict. `run-matrix.sh` parses its `OUTCOME` line instead. Now documented in the file, because a script that always exits 0 is a trap for whoever uses it next |

## 6b. Continuous verification

The experiments were originally run by hand, so nothing stopped a later change from quietly
invalidating a result the documentation still asserted. `.github/workflows/verify.yml` now re-runs
them on every push.

**This workflow has been verified**, contrary to the caveat in its own header at the time of writing:

| Job | What it re-runs | First run |
|---|---|---|
| `docs` | link, anchor, offline-safety, staleness and heading checks | **7s, success** |
| `dpop` | the S1 experiment — 6/6 enforcement and 6/6 verifier | **59s, success** |
| `hardware-keys` | the S3 matrix, controls included | **2m12s, success** |

**An unexpected side benefit:** the S3 matrix passed on **Linux**, having been developed on macOS. The
hardware-key findings are therefore not an artifact of one platform.

## 6c. Counts, and why they are not the headline

"12/12" and "14/14" invite the reader to divide one number by another and feel reassured. That is
misleading, and the audit showed it:

- **S5d** reports 18/18, but several are setup scaffolding; the load-bearing enforcement evidence is
  `A'`/`A'2` (direct-grant bypass), `B2` (a passkey really signs in), `C3` (a password really does not),
  and `D2b` (recovery really works).
- **S5c** reports 15/15; six of those are unit tests of a prototype policy.
- **S5e** reports 19/19; `E1`/`E2` and `E9` are the same observation before and after a state change.

**Read the claim, not the ratio.** A suite of nineteen checks of which four are load-bearing is a suite
of four checks with fifteen guards around them — useful, but not nineteen independent findings.

## 7. What would most likely invalidate this work

Ranked, because knowing the failure modes matters more than the summary:

1. **The phishing-proxy test fails.** The project's headline claim. Untested.
2. **The `DPoP` header does not survive the edge.** Silent, and the tempting fix is to disable the
   check — the exact failure the design exists to prevent.
3. **Safari evicts the session key aggressively.** Mitigated by short sessions, but it would make the
   fallback path load-bearing rather than rare.
4. **The step-up replacement does not work either.** Then sensitive actions have no freshness control
   and need a different answer (a second approver, which the plan already wants for the highest-risk
   operations).
5. **A published claim turns out to be wrong.** This register exists to shrink that surface, and any
   place where a claim is stated more strongly than it is recorded here is treated as a bug.

6. **The harness silently stops testing what it claims.** This is not hypothetical — it was found in
   this audit, in two scripts at once. The mitigation is that every gate is now negative-tested, not
   merely observed to pass.

## 8. How to challenge any of this

Every verified claim names the script that produced it. Reproduce it:

```bash
cd lab/keycloak && docker compose up -d
python3 scripts/configure-realms.py        # S3 policy setup
bash scripts/run-matrix.sh                 # S3 matrix
../../.venv/bin/python scripts/dpop_spike.py     # S1
node lab/browser/run.mjs chrome            # S4/S4b
./.venv/bin/python lab/keycloak/scripts/stepup_spike.py   # S5
```

If a result does not reproduce, **that is a finding** — and a more valuable one than a passing test.
