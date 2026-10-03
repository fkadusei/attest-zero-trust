# S5 Results — does asking for a stronger check force one?

**Status: UNRESOLVED — and it is a negative result.** The mechanism the plan depends on did **not**
work in this configuration. This is written up as a failure because presenting it as anything else
would be dishonest, and because a negative result that is recorded is worth more than a positive one
that is assumed.

Tested against Keycloak **26.8.0**.

---

## 1. What was asked

Some actions should require the user to prove themselves again, right then — exporting a list of who
can see what, or an administrator looking across all customers. The plan assumes this works via
Keycloak's **ACR → Level of Authentication** mapping: the application asks for a higher level, and
Keycloak forces whatever extra credential that level requires.

If Keycloak instead notices the existing session and waves the request through, "step-up" is a button
that does nothing while appearing to work. That is the failure this experiment was built to catch.

## 2. The answer

**It waved the request through.** A subflow configured to require a second factor at level 2 executed
regardless of whether level 1 or level 2 was requested — and regardless of whether anything was
requested at all.

### The decisive test

The clearest measurement was to turn the subflow off and on and watch the same login:

| State of the step-up subflow | Outcome of a normal sign-in |
|---|---|
| Enabled (`CONDITIONAL`) | **Prompted for a second factor** — login does not complete |
| Disabled | **Code issued** — login completes cleanly |
| Enabled again | **Prompted again** |

So the subflow is definitely the thing prompting. It is simply never being *gated*.

### What was ruled out

This was not a configuration typo, which was the first suspicion:

- The condition's configuration **was correct and persisted**, read back from the server as
  `{"loa-condition-level": "2", "loa-max-age": "300"}`.
- The realm's ACR mapping **was correct**: `{"low": "1", "silver": "2"}`.
- Every documented way of asking for a level produced the identical result: no request, `acr_values=low`,
  `acr_values=silver`, and the OIDC `claims` parameter with an essential `acr` of either value.
  **Five request shapes, one outcome.**

### What I could not determine

**Whether this is my flow arrangement or the feature itself.** I have one strong hypothesis and no
proof of it:

> Keycloak's condition is documented as executing "only if the configured LOA **or a higher one has
> been requested**". When no level is requested, that reads as "do not execute" — but Keycloak may
> instead treat an unrequested level as *the maximum*, which would make the condition always
> satisfied. That would explain the no-`acr_values` case. It does **not** explain why requesting the
> *lower* level still triggered it, unless the ACR-name-to-level mapping is silently ignored. I could
> not get far enough to separate those two.

The honest position: **the mechanism does not work as documented here, and I do not know why.**

## 3. Five real hazards found along the way

These cost genuine time and would cost it again. All are recorded in the handoff.

1. **You cannot modify a built-in flow.** Keycloak replies `It is illegal to add sub-flow to a built in
   flow`, so copying is the only route.

2. **A `CONDITIONAL` subflow placed at the top level of the browser flow silently destroys the flow.**
   The auth endpoint returns HTTP 400 with a page reading **"Invalid username or password"** — before
   anyone has typed anything. It looks like bad credentials and is actually a malformed flow. Bisecting
   one change at a time found it; guessing would not have. The subflow must be nested inside the
   existing `forms` subflow.

3. **`http.cookiejar` cannot drive a Keycloak login.** Keycloak marks its login cookies `Secure`, and
   for a bare hostname like `localhost` cookiejar rewrites the domain to `localhost.local` — so over
   plain HTTP the cookies are never sent back. Every login fails with **"Restart login cookie not
   found"**, which reads like an expired session. Managing `name=value` pairs directly fixes it.

4. **The flat executions list mixes every nesting level together.** Matching "an OTP form, at some
   depth" also hit the built-in 2FA subflow's OTP form and demoted it from `ALTERNATIVE` to `REQUIRED`,
   breaking the flow with the same misleading credentials error. Ask each flow for *its own* children.

5. **The LoA condition needs two config keys, not one.** With only `loa-condition-level` set, the
   server logs `ERROR LoAUtil: Invalid max age configured for condition 'loa2'. Fallback to 0`. That
   error appears **only in the container logs** — nothing in the API response or the login page hints
   at it. **Check the server log when a Keycloak flow misbehaves**; it was the only place the real
   problem appeared.

## 4. What this means for the design

The plan's step-up design is not safe to build on as written. Specifically:

- `docs/identity-and-passkeys.md` §8 claims step-up is solved by ACR → LoA mapping and calls this
  "better than the original design" because elevation is IdP-issued rather than a client-reported
  timestamp. **That claim is not supported.** It should be marked unverified.
- Success criterion S6 and the plan's Phase 4 both assume working step-up. They are not blocked, but
  they cannot assume this mechanism.

### Options, none yet chosen

| Option | Notes |
|---|---|
| Keep investigating the LoA arrangement | One more focused session. The hypothesis above is testable: set the condition level to 1 and see whether it *still* always fires. If it does, the condition is simply not evaluated and the search is for the right structural arrangement |
| Force re-authentication instead | `prompt=login` with `max_age=0` re-runs the whole flow. Blunter, definitely works, worse experience — and it proves *freshness* rather than *strength* |
| Do step-up in the application | Require a fresh WebAuthn assertion at the moment of the sensitive action and verify it server-side. Most control, most custom code, and it conflicts with the "let the IdP own the ceremony" principle |
| Accept and document | Treat step-up as unsolved for now and build the sensitive actions with a second approver instead, which the plan already wants for the highest-risk operations |

**Recommendation: one more focused session on the first option**, because the hypothesis is cheap to
test and the payoff — a working, standards-based step-up — is large. If that fails, take the second
option and be explicit that it proves freshness rather than strength.

## 5. What was NOT tested

- Whether re-authenticating satisfies a level once achieved (the "not yet satisfied" half of the
  documented behaviour) — unreachable while the condition never gates.
- Whether the `acr` claim appears in tokens at all under this configuration. It does not appear for
  direct-access-grant tokens, which was itself a finding.
- Any completion of the second factor: **OTP credentials cannot be created through
  `/users/{id}/credentials`** in this build (HTTP 404), so completing a step-up was never reached.

## 6. Reproducing

```bash
./.venv/bin/python lab/keycloak/scripts/stepup_spike.py     # rebuilds the realm from scratch
docker logs attest-lab-keycloak --tail 200 | grep LoAUtil   # the one useful diagnostic
```

The script builds everything in a throwaway realm (`attest-stepup-lab`), so no shared configuration
is disturbed. It currently reports 1/3, which is the honest result.
