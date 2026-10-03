# S5f Results — per-user enrolment by shareable link

**Status: RESOLVED — 19/19 checks pass. Impersonation is ruled out with evidence, and the mechanism
that does work is verified end to end. One real property of it is recorded as a finding.**

S5e left the per-user requirement unmet: the enrolment window was bounded and audited, but any user in
the realm could use it. S5f set out to fix that with Keycloak impersonation.

**Impersonation cannot do it.** The mechanism that can is a different one, and it works.

---

## 1. Why impersonation is not the answer

The aim was a one-time link for one named user. Keycloak's impersonation endpoint looked like exactly
that. It is not.

**The endpoint returns the identity cookie TO THE API CALLER:**

```
POST /admin/realms/attest-privileged/users/{id}/impersonation
  -> HTTP 200
     Set-Cookie: KEYCLOAK_IDENTITY=eyJhbGciOiJIUzUxMiIs…
     Set-Cookie: KEYCLOAK_SESSION=ZrszYmo775FYx1_cjyOp…
     {"redirect":"http://localhost:8080/realms/attest-privileged/account"}
```

The session belongs to whoever made the call. Opening the returned URL **with no cookies** produced
HTTP 200 and **set no session at all** — it is not a link that can be handed to another person.

This is confirmed by Keycloak's own words. [PR #40767](https://github.com/keycloak/keycloak/pull/40767),
*"Implement a new impersonation flow that uses action tokens"*, says:

> *"Previously, the impersonation endpoint immediately creates an identity cookie and returns that to
> the Browser... It becomes hard to integrate with the Admin APIs impersonation endpoint as it assumes
> the Endpoint is called from a browser."*

That PR — which would make the returned URI openable anywhere — is **open and unmerged**. So on the
build we run, impersonation is a browser-session mechanism for an administrator, not a shareable link.

**Ruled out, on evidence, with a source that agrees.**

## 2. What works instead

Keycloak's **"execute actions" email** produces a link carrying an **action token**:

```
PUT /admin/realms/{realm}/users/{id}/execute-actions-email?lifespan=300
    ["webauthn-register-passwordless"]
  -> the user is emailed
     /realms/{realm}/login-actions/action-token?key=eyJhbGciOiJIUzUxMiIs…
```

It is everything the requirement asked for:

- **per-user by construction** — the token names one account, rather than a realm-wide client that a
  check hopes to narrow
- **time-limited** — the `lifespan` bounds it
- **shareable** — openable by anyone, on any device, with no admin session and no cookie
- **requires no password** — it lands the user directly on the passkey registration action

Testing it required a mail server, so the lab now has one — `smtp_sink.py`, a dependency-free SMTP sink
that captures messages to disk, running as a **compose service on the same Docker network** as Keycloak.

Three faults were found in that sink, all worth recording because each was silent:

1. **Files were named per-connection**, so two messages in the same second overwrote each other and the
   test waited forever for a file that had already been replaced.
2. **It bound to loopback only.** A connection from a container arrives on the Docker bridge interface,
   not on loopback, so it was refused. This *appeared* to work under Docker Desktop — which proxies
   `host.docker.internal` to the host's loopback — and failed on a Linux runner with no error anywhere.
3. **Reaching it via `host.docker.internal` was the wrong design.** Running the sink on the host and
   adding `extra_hosts` works on Docker Desktop and not reliably on a runner. Putting the sink on the
   same Docker network removes the entire class of problem: Docker's DNS resolves the name, identically
   everywhere, and there is no host networking to get wrong.

## 3. The results

| Check | Result |
|---|---|
| An action-token link is emailed | **pass** |
| The link renders the action page | **pass** |
| It does **not** ask for a password | **pass** |
| The link reaches passkey registration | **pass** |
| **The enrolment is actually COMPLETED through the link** | **pass** |
| **A new passkey appears on the named user** | **pass** |
| **No passkey appears on any other user** | **pass** |
| **The enrolment actually completed** (the required action cleared) | **pass** |
| **Control:** the link dies once the action completes | **pass** |
| **Control:** an expired link is refused | **pass** |
| **Control:** a link for user A creates nothing for user B | **pass** |
| The realm stays bound to the passkey-only flow | **pass** |
| No client accepts direct password grants | **pass** |
| The password-window client stays disabled | **pass** |

**The load-bearing check is the one that completes the enrolment.** Page inspection cannot settle
*whose* account a link acts on; only doing it can. The link drove a real passkey registration through a
virtual authenticator, and the credential landed on the named user and nowhere else.

## 4. The finding: the link is a bearer token

**Opening the link does not consume it.** Measured:

| Step | Result |
|---|---|
| Open the link | `action_page` |
| Open it **again**, before completing | `action_page` — still live |
| Complete the enrolment | credential created |
| Open it again, **after** completing | **`refused`** |

So the link stays live until the action **completes** or it **expires**. Anyone who obtains it during
that window — a mail server, a forwarded message, a shared inbox, a shoulder-surfed screen — can
**complete the enrolment first** and register **their own passkey** on that account.

It is bounded rather than open-ended, and emailed password-reset links share the property. But it must
be a conscious acceptance:

- **keep the lifespan short**, and treat "short" as minutes, not hours
- the link travels by email, so **its security is the mailbox's security**
- an enrolment that completes unexpectedly should be **visible in the audit trail** — the person whose
  account it is will find they cannot sign in, which is a loud failure rather than a quiet one

This is recorded as a **finding, not a gate**: it is a property of the mechanism, not a defect in it.

## 4a. Notes from making this run in CI, because every failure was environmental

Seven CI-only failures, and **all of them were an assumption that held on macOS and nowhere else**.
Recorded because the pattern is the finding, not the individual bugs:

| Assumption | Why it broke elsewhere |
|---|---|
| The interpreter is at `.venv/bin/python` | CI installs into the system interpreter |
| `host.docker.internal` can be fixed in the **runner's** `/etc/hosts` | The container has its own hosts file |
| `extra_hosts` is enough | The sink bound to **loopback**, and a bridge connection is not loopback |
| The mail sink can live on the host | Docker Desktop proxies to host loopback; a Linux runner does not |
| The Node package path is an absolute macOS path | It does not exist in CI |
| Fixture users exist | **They are made by other harnesses.** Third occurrence |
| The AAGUID policy stays relaxed | It is restored after the first enrolment, so the *second* was silently refused |

**Two of these were false results, not just failures.** The last one — F5 passing locally and failing in
CI — was the test reporting a false failure: a silently-refused enrolment left the link alive, which the
check then read as "the link is reusable". It passed locally only by ordering luck. F5 now asserts the
intermediate fact that distinguishes the two states: **that the required action actually cleared.**

The sink is now a **compose service on the same Docker network**, which removes the whole class of host-
networking problems rather than patching each symptom.

## 5. What was NOT tested

- **Email delivery in production.** The lab captures mail; nothing verifies a real provider, bounces,
  or spam filtering. A link that never arrives is an availability problem, and a link that arrives
  somewhere unexpected is this finding again.
- **Whether the link is invalidated by issuing a second one.** Two live links for one account may both
  work; that was not measured.
- **Rate limiting.** Nothing tested how many links can be requested, or how quickly. `execute-actions-email`
  is an admin endpoint, so the exposure is to a compromised admin, not to an anonymous attacker.
- **A physical hardware key** completing the enrolment — virtual only, as everywhere else.
- **What happens if the user has no email address.** The endpoint should refuse; assumed, not checked.

## 6. Why this is better than the window it replaces

| | S5e's window | S5f's link |
|---|---|---|
| Who can use it | **any user in the realm**, while open | **one named user**, by construction |
| Bounded by | a sweep that must keep running | the token's own lifespan |
| Needs a password | **yes** | **no** |
| Needs a client enabled | yes | no |
| Audited | via the event log | via the event log |

The requirement S5e could not meet — *"reachable only for a named user"* — is met here **by the
mechanism itself**, rather than by a check bolted onto it. That is the difference that matters.

## 7. Reproducing

```bash
# the mail sink runs as a compose service on the same Docker network as Keycloak
docker compose -f lab/keycloak/compose.yaml up -d smtp-sink

# the matrix points the realm at it itself:
#   smtpServer: {host: smtp-sink, port: 2525, from: attest-lab@example.test}

./.venv/bin/python lab/keycloak/scripts/spike5f-matrix.py     # 16 checks
```

Negative-tested: one expectation inverted gives 15/16 and exit 1.
