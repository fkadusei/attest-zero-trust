# S5b Results — can step-up be made to work?

**Status: RESOLVED — REJECTED. The mechanism must not be used; see ADR-013.**

S5 asked whether Keycloak's step-up could be made to work and left one question open: was the failure
my flow arrangement, or the feature? S5b answers it, and the answer is far more useful than a
configuration fix.

**The component the design depends on has an unpatched security vulnerability with no available
mitigation, published nine days before our test.**

---

## 1. What S5 left open, and the hypothesis it proposed

S5 showed that a subflow configured to demand a second factor at level 2 executed **regardless of
what level was requested** — including nothing at all. The configuration was verified correct, and
five different ways of requesting a level all behaved identically.

S5 recorded one hypothesis: that `loa-max-age` might not be parsed, and a fallback to zero would mean
"always stale", so the condition would always fire.

**That hypothesis is wrong.** The server-side error it predicted
(`Invalid max age configured for condition 'loa2'. Fallback to 0`) is **gone** once both config keys
are set, watched live in the container log during a fresh login attempt — and the condition still
fires unconditionally.

So the fault is not a missing value, and I was not going to guess a third time.

## 2. What the search turned up

Rather than keep guessing at Keycloak's flow semantics, I looked for how this component actually
behaves. That surfaced a vulnerability record describing **exactly this component**, **exactly this
scenario**, and the **exact failure the plan was trying to avoid**.

### CVE-2026-97176

| | |
|---|---|
| **Component** | `keycloak-services` → `ConditionalLoaAuthenticator` — the "Condition - Level of Authentication" authenticator |
| **Published** | **2026-09-23** — nine days before this test |
| **Severity** | Moderate, CVSS 3.1 base **4.2** (`AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N`) |
| **Weakness** | CWE-862, Missing Authorization |
| **Fix state** | **Affected — no fix** |
| **Mitigation** | **"not available"** |

In Red Hat's own words:

> *"The issue occurs when a client specifically requires a higher security level for a user who
> already has an active session at a lower level. Due to a logic error in how session re-evaluations
> are handled, Keycloak may incorrectly issue a token at the lower security level instead of enforcing
> the required higher level."*

And the root cause:

> *"...a failure to register and execute the forced-level validation callback when all LoA-gated
> conditional sub-flows are disabled during session re-evaluation."*

### Why this is the whole answer

**An authenticated user with a low-level session can obtain a token that claims a higher level than
they actually performed.** That is precisely the failure mode S5 was built to detect — the button
that does nothing — and it is not hypothetical, not my misconfiguration, and not fixed.

It also means the question S5 was asking is the wrong one now. Whether I can configure the mechanism
correctly in the happy path is **irrelevant** if an attacker can bypass it in the unhappy path. This
was going to be the control protecting "export who can see what" and "an administrator looking across
all customers".

### It ships in our build

```
/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.8.0.jar
```

`keycloak-services` is the exact package named in the record, and the
`conditional-level-of-authentication` authenticator is present and available in our realms.

## 3. The honest distinction — what I did NOT do

**I did not reproduce the CVE.** This matters and should not be glossed over.

- **What the CVE describes:** the subflow is skipped, and a token is issued asserting a *higher* level
  than was performed. A silent **bypass**.
- **What I observed in S5:** the subflow ran when it should not have. Over-enforcement, the opposite
  direction.

Those are different symptoms of the same component, and I have not shown they share a cause. I found
that the mechanism misbehaves, and separately that its component carries a live, unmitigated
vulnerability of exactly the kind that matters here. **Either finding alone is enough to reject the
mechanism; neither is dressed up as more than it is.**

## 4. The decision

**Reject ACR/LoA-based step-up.** Not "retry later", and not "unverified" — rejected, with a stated
reason, on the same basis as any other rejected dependency.

The concrete rule that follows, and it is the important part:

!!! danger "Never trust the `acr` claim for a step-up decision"

    The vulnerability means a token's `acr` claim can assert a level that was never performed. Any
    application that reads `acr` and concludes "this person proved themselves with a hardware key"
    is trusting an assertion the identity provider may have gotten wrong.

    This is the direct analogue of the DPoP finding in S1: **a claim that the issuer writes is not a
    claim the resource server can rely on without checking.** We already learned that lesson once.

## 5. The replacement

Force a genuine re-authentication and verify **freshness**, not a claimed strength level:

| Mechanism | How |
|---|---|
| Force re-authentication | `prompt=login` with `max_age=0` on the authorization request |
| Evidence of freshness | The **`auth_time`** claim — when authentication actually occurred — **not** `acr` |
| Policy | A sensitive action requires `auth_time` within a short window, evaluated by the policy engine |

**Why `prompt=login` is better here than it first looks.** It was noted in S5 as a weaker option
because it proves freshness rather than strength. For the **privileged** realm that objection mostly
dissolves: the only way to authenticate there is a **hardware security key with user verification**
(S3), so re-running the flow *is* a fresh hardware-key assertion. Freshness and strength come from the
same act.

For the customer realm, where synced passkeys are allowed, `prompt=login` proves freshness and
whatever strength that realm's policy provides — which should be stated plainly rather than implied.

**`auth_time` is not affected by the LoA bug**, because it records when authentication happened rather
than what level was claimed.

## 6. What is still to do

The replacement is a **plan**, not a verified control. It moves to **S5c**, and it is a real test with
a control, not an assumption:

1. Does `prompt=login` with `max_age=0` genuinely force a fresh ceremony, even with a live session?
2. Does `auth_time` update on that re-authentication, and stay put when it should?
3. **Control:** a replayed older token must carry the *older* `auth_time` and be refused by policy.
4. Does the whole thing work on the privileged realm, where re-authentication means a passkey?

Also worth tracking: **an upstream fix for CVE-2026-97176**. If it ships, LoA-based step-up becomes
worth re-evaluating — but only on the evidence of a test that tries to exploit the bypass, not on the
existence of a patch note.

## 7. What this changes in the design

- `docs/identity-and-passkeys.md` §8 goes from "not verified" to **rejected**, with the reason.
- A new decision record supersedes the assumption that elevation would be an IdP-issued fact.
- The plan's Phase 4 step-up work now targets `prompt=login` + `auth_time` instead.
- **A live CVE in a dependency is now part of the risk register**, and the 48-hour patch commitment
  (S11) has its first concrete test case — this one has no fix to deploy yet.

## 8. The wider point

This is the second time in this project that checking a claim found the claim was wrong — and this
time the check found a **security vulnerability in a dependency**, not a mistake of mine.

It is also a reminder that a spike which "fails" can succeed at something more useful than the thing
it was aimed at. S5 was trying to prove a control worked. It ended up proving the control cannot be
trusted, which is worth considerably more than a passing test.

Early is exactly when this is cheap to find. The alternative was discovering it after building
step-up into the product, and after telling customers their sensitive actions were protected by it.

## Sources

- [Red Hat Bugzilla 2539964 — CVE-2026-97176](https://bugzilla.redhat.com/show_bug.cgi?id=2539964)
- [Red Hat CVE data for CVE-2026-97176](https://access.redhat.com/security/cve/cve-2026-97176)
- [Keycloak issue #28341 — ConditionalLoaAuthenticator documentation incorrect](https://github.com/keycloak/keycloak/issues/28341)
