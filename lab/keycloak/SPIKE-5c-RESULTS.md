# S5c Results — does the replacement actually force a fresh check?

**Status: RESOLVED — the replacement works as a control. One premise behind it does not.**

S5b rejected Keycloak's ACR/LoA step-up because of CVE-2026-97176. ADR-013 replaced it with a plan:
force a genuine re-authentication using `prompt=login` and `max_age=0`, then judge **how recently** it
happened using the `auth_time` claim — never `acr`.

A plan is not a control. This experiment asks whether it is one, and the answer is **yes** — with one
important correction to the reasoning that justified it.

---

## 1. Why the controls matter more than the tests here

The failure mode this experiment exists to catch is *"asking an already-signed-in user to sign in
again quietly does nothing"* — which is precisely what S5 found in the mechanism we rejected.

That makes a naive test worthless. Observing "a fresh sign-in happened" proves nothing unless we also
show that a fresh sign-in does **not** happen otherwise. So every claim has a control that must come
out the other way:

| Control | What it rules out |
|---|---|
| Reusing a live session must **not** change `auth_time` | Otherwise "it changed" proves nothing — it might change on every request |
| An old token must keep its **old** `auth_time` | Otherwise freshness is being *faked* rather than measured — the same class of failure as the CVE we rejected |
| `max_age=3600` on a 2-second-old session must **reuse** it | Otherwise "it re-authenticated" would not show `max_age` is read at all, only that it always re-authenticates |
| The policy must **refuse** a stale token | Otherwise a policy that accepts everything makes a present `auth_time` look like proof |
| The policy must **refuse** a token with **no** `auth_time` | Fail closed. A token that cannot demonstrate freshness is not fresh |

## 2. The results

**14/14 checks behaved as expected.**

| Check | Result |
|---|---|
| `auth_time` present in the ID token | yes — and `acr` is present too, reported as `"1"` |
| **Control:** reusing a live session leaves `auth_time` unchanged | **pass** |
| `prompt=login` demands the login form **despite a live session** | **pass** |
| `auth_time` advances after re-authentication | **pass** — before `…181`, after `…184`, delta **3s**, matching the deliberate 3-second wait |
| **Control:** the earlier token still reports its **original** `auth_time` | **pass** — it does not retroactively update |
| `max_age=3600` on a 2-second-old session → reused | **pass** |
| `max_age=0` on a 2-second-old session → re-authenticated | **pass** |
| Policy: fresh token accepted | **pass** |
| Policy: stale token refused | **pass** |
| Policy: token with **no** `auth_time` refused — **fail closed** | **pass** |
| Policy: future `auth_time` refused | **pass** |
| Policy: a real re-authenticated token passes | **pass** |
| Policy: a real token older than the window is refused | **pass** |

**So the replacement is a control, not a hope.** `prompt=login` forces a genuine ceremony even with a
live session, `auth_time` records it truthfully and does not move when it should not, and the policy
that consumes it refuses what it must.

## 3. A false finding I caught before publishing it

**Worth recording, because it nearly went into this document as a real result.**

The first run reported `max_age=0` did **not** force re-authentication — the session was reused. That
looked like a genuine defect, and it very nearly became one: a finding against the mechanism, in a
project whose whole point is not overstating things.

It was wrong. The test signed in and **immediately** requested `max_age=0`. The session was 0 seconds
old, and the condition is `elapsed > max_age` — that is `0 > 0`, which is **false**. Reusing the
session was **correct**.

The fix was to characterise the behaviour instead of accepting the failure:

| Request | Session age | Result |
|---|---|---|
| no `max_age`, no `prompt` | 4s | reused |
| `max_age=3600` | 4s | reused — within the window |
| `max_age=1` | 4s | **re-authenticated** |
| `max_age=0` | 4s | **re-authenticated** |
| `prompt=login` | 4s | **re-authenticated** |

`max_age` is honoured, conditionally and correctly. **The test was wrong, not the design.**

The lesson generalises: *a failing test is a hypothesis about the code, not a conclusion about it.*
Accepting the first failure would have produced a confident, published,
wrong claim about a working mechanism.

## 4. The finding: ADR-013's strength argument does not hold yet

ADR-013 justified the replacement partly on this:

> *"On the privileged realm the objection is smaller than it looks: the only way to sign in there is a
> hardware key with user verification, so re-running the flow **is** a fresh hardware-key assertion —
> freshness and strength from the same act."*

**That is false as the realm is currently configured.** The privileged browser flow is:

```
Cookie, Kerberos, Identity Provider Redirector, Organization, Browser - Conditional Organization,
Condition - user configured, Organization Identity-First Login, forms,
Username Password Form, Browser - Conditional 2FA, Condition - user configured,
Condition - credential, OTP Form, WebAuthn Authenticator, Recovery Authentication Code Form
```

A **`Username Password Form` is present**, and a WebAuthn step is present only as a conditional
second factor. So re-authentication on the privileged realm can be **a password**, not a hardware-key
assertion.

**Consequence:** forcing re-authentication gives us **freshness**, which is real and verified above.
It does **not** currently give us **strength**. The two come from the same act only once the flow
requires a passkey — which is flow work that has not been done.

This is exactly the kind of claim that reads well and is not true, and it was sitting in a decision
record. It is now corrected there.

## 5. What this changes

- **ADR-013 is corrected**, not withdrawn: the mechanism is verified, the strength premise is not.
- **A new slice** covers making the privileged browser flow passkey-only. Until then, a sensitive
  action on the privileged realm proves *"you signed in again just now"* and **not** *"you used your
  hardware key just now"* — and the difference must not be glossed over in anything user-facing.
- `acr` **works** in this configuration (reported as `"1"`), which is worth noting: the problem with
  `acr` was never that it is absent. It is that it is a claim the issuer writes, and CVE-2026-97176
  shows it can assert a level that was never performed. **Use `auth_time` regardless.**

## 6. The gate is negative-tested

Per the rule established during the audit — *a gate that cannot fail is not a gate* — this spike's
exit code was deliberately broken and confirmed to fail:

| Test | Expected | Result |
|---|---|---|
| Real run | exit 0, 14/14 | **exit 0, 14/14** |
| One check inverted in a throwaway copy | exit 1 | **exit 1, 13/14** |

The suite also prints its findings **separately from its gates**, so a green run cannot hide an
unmet premise. `Freshness mechanism: 14/14` is followed by `FINDINGS (1) — these do NOT gate, but must
not be missed`.

## 7. What was NOT tested

- **Freshness across a real browser and a real user.** This drives Keycloak over HTTP with scripted
  forms. It proves the protocol behaviour, not the user experience.
- **`prompt=login` when re-authentication is impossible** — a user whose only credential was removed.
  The expected behaviour is a lockout, but it is unproven, and lockout paths deserve their own test.
- **The privileged realm's passkey-only flow** — because it does not exist yet.
- **Clock skew between the issuer and the resource server.** The policy refuses a `auth_time` more
  than 60 seconds in the future, but that threshold is a guess, not a measurement.

## 8. Reproducing

```bash
./.venv/bin/python lab/keycloak/scripts/freshness_spike.py
```

Builds its own throwaway realm (`attest-freshness-lab`) from scratch, so it disturbs nothing else.
Exits non-zero if any gated check fails. Prints findings separately.
