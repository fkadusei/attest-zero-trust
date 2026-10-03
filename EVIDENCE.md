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
| An old token **keeps its old `auth_time`** and does not retroactively update | S5c T4a — otherwise freshness would be faked, not measured | **Verified** |
| `max_age` is honoured **conditionally and correctly** | S5c T5a/T5b: `3600` reuses a 2s-old session; `0` re-authenticates it | **Verified** |
| A freshness policy **refuses** stale tokens | S5c T6b | **Verified** |
| A freshness policy **refuses a token with no `auth_time`** — fail closed | S5c T6c | **Verified** |
| A freshness policy **refuses a future `auth_time`** | S5c T6d | **Verified** |
| A passkey-only browser flow leaves **no password field** and no username field | S5d A1/A2 — the flow is usernameless | **Verified** |
| **A passkey signs in successfully** against the passkey-only flow | S5d B2 — the positive case that makes "refused" meaningful | **Verified** |
| A user with **no passkey is locked out** | S5d C1 — the expected cost, demonstrated | **Verified** |
| Recovery from a broken flow is **one API call** | S5d D1/D2 — the original flow is never edited, only unbound | **Verified** |
| The `flow_tool` backup/restore **detects a broken flow and restores it** | Tested in a scratch realm: passes untouched, detects damage, restores exactly | **Verified** |
| **A passkey-only browser flow does NOT stop direct password grants** | S5d A′ — `admin-cli` had `directAccessGrantsEnabled: true`, so a password still bought a token despite the login page refusing one | **Verified** |
| `http.cookiejar` **cannot drive a Keycloak login** | Cookies stored as `localhost.local` + `Secure`, so never sent over http; error is "Restart login cookie not found" | **Verified** |

## 2. Corroborated — external sources, checked

| Claim | Evidence | Confidence |
|---|---|---|
| **CVE-2026-97176** exists: a user with a low-level session can obtain a token asserting a higher level than they performed | Red Hat record, NVD entry, upstream GHSA-5jw9-cc9v-8h8r, OpenCVE — all four read directly | **Corroborated** |
| The CVE has **no fix and no available mitigation** | Red Hat `FixState: Affected` + mitigation "not available"; upstream advisory lists **no patched version** | **Corroborated** |
| The vulnerable classes are **in the artifact we run** | Extracted `keycloak-services-26.8.0.jar` and found `ConditionalLoaAuthenticator.class`, `...Factory.class`, `LoAUtil.class` | **Verified** (class presence) |

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
| Sign-in survives a **real phishing proxy** | The headline claim of the project | A live relay test |
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

11. **The decision to reject LoA step-up does not rest on the CVE.** S5 independently showed by
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
