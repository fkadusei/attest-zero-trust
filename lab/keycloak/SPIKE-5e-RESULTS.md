# S5e Results — is the enrolment window time-boxed, gated and audited?

**Status: PARTLY RESOLVED — 14/14 checks pass, but the per-user restriction does NOT work.**

S5d proved the privileged realm passkey-only, and left a hole behind it: the only way to give someone
their first passkey was to revert the **whole realm** to a password flow. That opens a password path
for **every** user, for an **unbounded** time, with **no record**. A worse hole than the one it fixed.

---

## 1. The result

| Check | Result |
|---|---|
| Closed by default: no password on the enrolment client | **pass** |
| Closed: a password grant is refused | **pass** |
| Closed: the normal client is unaffected | **pass** |
| Open: the enrolment client offers a password | **pass** |
| Open: the named user can **complete** a password sign-in | **pass** |
| Open: **control** — the normal client is **still passkey-only** | **pass** |
| **Control:** the sweep does **not** close an unexpired window | **pass** |
| The window reports itself expired | **pass** |
| The sweep closes it | **pass** |
| The password path is gone after the sweep | **pass** |
| A password grant is refused again | **pass** |
| The audit trail records the window opening | **pass** |
| The audit trail records the sweep | **pass** |

**The window is closed by default, bounded, and audited**, and the normal clients are untouched
throughout — that last one is the whole point, and it is a control rather than an afterthought.

## 2. The requirement that was NOT met

> *"A dedicated enrolment flow — reachable only for a named user, so enabling it for one person does
> not open the door for everyone."*

**The per-user restriction does not work.** While a window is open, **any user in the realm can
authenticate through the enrolment client with their password.** Check E12 proves it by completing a
full sign-in as a second user. That check is deliberately a **finding** rather than a gate: it is a
known residual risk, and pinning it as a test means it cannot be quietly forgotten or quietly assumed
to work.

### What was tried, so nobody repeats it

The intended mechanism was Keycloak's `conditional-user-role` — a per-user gate. **Four arrangements
were tested, and none gated:**

| Arrangement | Outcome |
|---|---|
| `conditional-user-role` as a direct `REQUIRED` step alongside the password form | flow loads; password appears **whether or not** the role is granted |
| `CONDITIONAL` subflow containing condition + password form, with a passkey default | flow loads; password **never** appears, even with the role granted |
| Same, with the inner action as `ALTERNATIVE` and the default `REQUIRED` | flow loads; password **never** appears |
| **Exact mirror** of Keycloak's own built-in conditional subflow shape | flow loads; password **never** appears |

The last one is the notable one: the built-in `Browser - Conditional 2FA` uses precisely that shape
and works. A copy of it does not behave the same way. **That looks like a Keycloak behaviour worth
reporting upstream**, and it is not something this project can fix from configuration.

### Two structural traps found along the way

- **An `ALTERNATIVE` subflow whose children are all `CONDITIONAL` or `DISABLED` throws
  `AuthenticationFlowException` at the authorization request** — surfacing as HTTP 400 with the body
  *"Invalid username or password"* on a page nobody has typed into. Keycloak needs at least one
  concrete `REQUIRED` execution to have a path at all. This is the same misleading symptom S5
  diagnosed, from a different cause.
- Once again, **the only place the real reason appeared was the container log** — the fourth time this
  project has learned that.

### The compensating position

The window is **bounded and audited rather than restricted**. Concretely, for the duration of an
enrolment window:

- **Normal clients remain passkey-only** — verified as a control, every run.
- The exposure is limited to the **enrolment client**, which exists only for this purpose.
- The window is **short** and **closed by the sweep**.
- Every authentication through it is **recorded**, and the event log had to be **switched on** for
  that — Keycloak ships with events **disabled**, so before this slice there was no audit trail at all.

That is a real, stated limitation, not a rounding error. The honest summary: **this narrows the hole
from "the whole realm, forever, silently" to "one client, briefly, on the record."** It does not close
it, and it should not be described as if it does.

## 3. What was actually found missing in the lab

**Keycloak had events disabled** (`eventsEnabled: false`, `adminEventsEnabled: false`). So there was
**no audit trail of any kind** — nobody could have answered "who authenticated, when" for any realm.
The window manager refuses to open a window it cannot audit, and switches the event log on. That is a
finding about the baseline, not about this feature.

## 4. How it works

| Piece | Purpose |
|---|---|
| The `enrolment` **client** | Bound to a password-capable flow. Normal clients keep the passkey-only flow, so the password path exists in exactly one place |
| `enrolment_window.py open <user> <min>` | Enables the client, records who it is for, who opened it, and when it expires |
| `... sweep` | Closes any window past its expiry. **This is the time limit** |
| `... close` | Closes immediately |
| `... status` / `... audit` | Current state, and the record of what happened |
| Event log | Turned on, so authentications through the window leave a trace |

**There is a gap between expiry and the sweep running.** It is a sweep, not an enforced deadline. The
gap is bounded by how often the sweep runs, and it is a residual risk that should be scheduled as a
frequent task in production — not left to the next person who remembers.

## 5. What was NOT tested

- **A sweep running on a schedule.** Here it is invoked by hand. In production it needs to be a
  scheduled task, and **nothing verifies that the schedule actually runs** — the window would stay
  open silently if it stopped.
- **A real passkey enrolment end to end** through this window: password → required action → passkey
  registered. S3 and S5d cover both halves separately; the joined-up path is not tested here.
- **Concurrency.** Two windows cannot be open at once (the tool refuses), but nothing prevents a
  second operator from running `close` while someone is mid-enrolment.
- **Clock skew**, which would move the expiry. The tool compares against its own clock, not Keycloak's.
- **Whether `conditional-user-role` could be made to work with more time.** Four arrangements is a
  time-box, not a proof that it is impossible.

## 6. Reproducing

```bash
./.venv/bin/python lab/keycloak/scripts/enrolment_window.py status
./.venv/bin/python lab/keycloak/scripts/enrolment_window.py open spike-attest-privileged 1
./.venv/bin/python lab/keycloak/scripts/enrolment_window.py sweep
./.venv/bin/python lab/keycloak/scripts/enrolment_window.py audit

./.venv/bin/python lab/keycloak/scripts/spike5e-matrix.py    # 14 checks, ~3 minutes
```

The matrix takes about three minutes because the time limit is tested by **waiting for a real
one-minute window to expire**, not by editing a timestamp. Negative-tested: one check inverted gives
13/14 and exit 1.
