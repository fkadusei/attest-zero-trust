# S5d Results — is the privileged realm actually passkey-only?

**Status: RESOLVED — 12/12 checks pass, including four controls.**

S5c found that ADR-013's strength argument did not hold: the privileged browser flow still contained a
`Username Password Form`, so re-authentication could be a password. This slice does the flow surgery,
and finds **a second, more serious way in that the flow surgery alone does not close**.

---

## 1. What "passkey-only" means here

Four separate claims, each of which could be true while the others are false:

| Claim | How it is tested |
|---|---|
| The login page offers no password | no `input[type=password]`, no username field either (it is usernameless) |
| **A password cannot be used at the token endpoint** | a direct grant is attempted. **This is the one that mattered.** |
| A passkey **is** accepted | without this, "refused" would also be satisfied by a flow that refuses everything |
| A user with no passkey is locked out | the expected cost, demonstrated rather than assumed |
| Recovery restores access | a mistake here must be survivable |

## 2. The result

| Check | Result |
|---|---|
| Policy relaxed for enrolment, and read back to confirm it took | **pass** |
| Stale passkeys cleared before enrolling | **pass** |
| A **new** passkey was registered (by id, not by count) | **pass** |
| The **strict** allowlist restored afterwards | **pass** |
| No password field on the login page | **pass** |
| No username field either — usernameless | **pass** |
| The passkey button is offered | **pass** |
| **A direct password grant is refused** | **pass** |
| A passkey button is present at sign-in | **pass** |
| **Signing in with the passkey succeeds** | **pass** |
| **Control:** the test user for "no passkey" really has none | **pass** |
| Recovery: rebinding the original flow restores password access | **pass** |

## 3. The finding that matters: the browser flow was never the only way in

**The first full run failed on exactly one check** — the direct grant — and it is the most important
result in this slice.

A direct grant posts a username and password straight to the token endpoint. **It never touches the
browser flow at all.** So `attest-privileged` was passkey-only at the *login page* while
`admin-cli` — a built-in client with `directAccessGrantsEnabled: true` — would still issue tokens for
a password.

> **A passkey-only browser flow does not make a realm passkey-only. Any client accepting direct
> grants is a password bypass around the entire flow.**

`admin-cli` is created by Keycloak in every realm, and it is `public`, so nothing protected it. It is
now closed by `apply`, and its prior state is recorded so `revert` restores it.

### It passed the first time for the wrong reason

The first run reported this check as **passing**. That was a **false pass**: the test user's password
had not been set to the value the test used, so the grant failed on *bad credentials* rather than on
*being refused*. Once the password was known, the check failed — and the bypass was real.

Worth recording because the shape recurs: a negative test that passes because the input was wrong is
indistinguishable from a control working, unless something makes the positive case succeed too. That
is why check B — a passkey actually signing in — is not optional.

## 4. The bootstrap problem, stated plainly

**A passkey can only be registered by someone who can already authenticate.** Making a realm
passkey-only removes the only way to reach the registration flow.

This is a genuine property of passkey-only realms, not an artefact of the lab. The test's setup step
*is* the bootstrap procedure, and it is why that step runs against the original flow first:

1. bind the original flow (password usable) — for enrolment only
2. register the passkey
3. bind the passkey-only flow
4. close direct grants

**This is the recommendation for production**, with two additions that are not yet built:

- the enrolment window should be **time-boxed and audited**, not an open capability
- **the recovery path is a runbook, not a login page.** Recovery here is one API call against the
  `master` realm — which none of this touches. An organisation needs two named people who can run it,
  and a rehearsal, before this ships.

## 5. What the change actually is

Built with `make_privileged_passkey_only.py`:

| Step | Why |
|---|---|
| **Copy** the built-in `browser` flow | Keycloak refuses to modify built-in flows: *"It is illegal to add execution to a built in flow"* — the same wall S5 hit |
| Add `WebAuthn Passwordless Authenticator` to the copy | passkey as the **first** factor, not a second one |
| Set it `REQUIRED`; set `Username Password Form` `DISABLED` | no password path remains in the flow |
| **Close direct grants** | otherwise the flow is irrelevant — see §3 |
| Bind the copy as `browserFlow` | the realm now uses it |

**Recovery is one call, because the original flow was never edited.** Nothing is rebuilt; the realm is
pointed back at `browser`. That is why the copy-then-modify approach is worth the extra step.

## 6. Three traps, all of which produced no useful error

1. **A partial `PUT` to the realm does not merge.** Sending only the two policy fields replaced the
   representation and the change never applied. Enrolment failed with `invalid cert path`, which
   points at certificates rather than at the policy that was never set. `patch-realm.py` uses
   read-modify-write for this reason; the matrix now does the same.

2. **`AvoidSameAuthenticatorRegister = true` silently refuses a repeat enrolment.** The symptom is
   that the ceremony **completes** — Keycloak even prompts for the passkey's label — and then no
   credential is stored. Nothing in the UI or the API says why. Clear the existing passkeys first.

3. **The registration page does not start the ceremony on its own.** It waits for
   `registerWebAuthn` to be clicked. Tracing the page showed it sitting there indefinitely with no
   error at all.

**In all three cases the only place the real reason appeared was the container log** — for example
`web_authn_registration_error_detail="invalid cert path"`. That is now the third time this project has
learned to check the server log first.

## 7. What this means for ADR-013

ADR-013's corrected text says the privileged realm gives freshness but not strength, because the flow
still accepted a password. **That flow work is now done and tested**, so the argument holds — *when the
passkey-only configuration is applied*.

It is applied on demand rather than left on, deliberately: `attest-privileged` is a shared lab fixture,
and S3's matrix signs in with a password against it. `status` reports which state a realm is in, and
says so loudly when a password bypass is open.

## 8. What was NOT tested

- **A physical security key** signing in. The passkey here is a CDP virtual authenticator, which
  cannot attest — the same limitation as S3.
- **The enrolment window** being time-boxed or audited. It is currently an open capability.
- **Recovery by a second person**, which is a process requirement and not a code path.
- **Existing sessions.** The flow has `Cookie` at the top level, so a session established before the
  change keeps working afterwards. Changing a flow does not revoke anything — that is S8's problem,
  and it should not be assumed to be solved here.
- **Whether `admin-cli` is needed for anything.** It was closed on the basis that nothing in this
  project uses it in `attest-privileged`. If something does, this would break it — loudly, at the
  token endpoint, rather than silently.

## 9. Reproducing

```bash
# apply / inspect / revert the configuration
./.venv/bin/python lab/keycloak/scripts/make_privileged_passkey_only.py status
./.venv/bin/python lab/keycloak/scripts/make_privileged_passkey_only.py apply
./.venv/bin/python lab/keycloak/scripts/make_privileged_passkey_only.py revert

# the enforcement matrix (needs Chrome on port 9222)
cd lab/keycloak && node scripts/spike5d-matrix.mjs

# the safety net, independently tested in a scratch realm
./.venv/bin/python lab/keycloak/scripts/flow_tool.py verify attest-privileged browser
./.venv/bin/python lab/keycloak/scripts/flow_tool.py restore attest-privileged browser
```

The matrix leaves the realm **reverted**, so the shared fixture stays usable. Exits non-zero if any
check fails; negative-tested by inverting one check (12/12 → exit 0; 11/12 → exit 1).
