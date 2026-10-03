# Work plan — numbered slices

**Repository:** <https://github.com/fkadusei/attest-zero-trust> (public). Commit and push completed
slices; keep the commit message honest about what was and was not established.

**When finishing a slice:** update `EVIDENCE.md` — the claims register — in the same commit. A claim
that is not in there with a confidence level is a claim nobody has checked. Where you are **not**
certain, record the uncertainty rather than rounding it to confidence.


Every piece of remaining work is a numbered **slice**. To tell me what to do next, reply with the
slice number, for example:

```
S4
```

That is the whole protocol.

**Slice numbers are the same as the experiment ("spike") numbers used throughout the documentation.**
So `S4` here and "Spike #4" in the engineering docs are the same piece of work. There is deliberately
only one numbering scheme — two would be a trap for anyone picking this up cold.

A slice suffixed `b` is the second half of a slice whose first half is done.

**Status:** ✅ done · ▶ **next** · ○ ready (nothing blocking) · ⚠ needs AWS · 🔑 needs hardware ·
👤 needs a person

---

## Part 1 — Proving it

Short, focused experiments. Each answers one question that would be expensive to get wrong later.

| Slice | Question, in plain words | Status |
|---|---|---|
| **S1** | If someone steals a login pass, is it useless to them? | ✅ **done** — logic proven |
| **S1b** | Does the proof survive the journey through our network edge? | ⚠ needs AWS |
| **S2** | Does our permissions engine accept passes from our own login server? | ⚠ needs AWS |
| **S3** | Can we stop staff accounts using a "soft" passkey and allow only a real hardware key? | ✅ **done** — refusal proven |
| **S3b** | Is a real hardware key actually *accepted*? | 🔑 needs a key |
| **S4** | Can a browser keep its session key across a restart? | ⚠ **partly done** — **Chrome only** |
| **S4b** | Do the other browsers behave the same way? | ⚠ **Chromium done** — Firefox/Safari manual |
| **S5** | Does asking for a stronger check actually force one? | ❌ **UNRESOLVED** — the condition never gated |
| **S5b** | Can step-up be made to work at all? | ✅ **answered — rejected (ADR-013)** |
| **S5c** | Does the replacement actually force a fresh check? | ✅ **done — 14/14, it works** |
| **S5d** | Make the privileged flow actually require a passkey | ✅ **done — 12/12; found a bypass** |
| **S5e** | Time-box and audit the enrolment window | ▶ **NEXT** |
| **S6** | What do the standards say about "synced" passkeys? | 👤 needs a reviewer |
| **S7** | Can the login server run as more than one copy? | ⚠ needs AWS, **costs money** |
| **S8** | How fast does "sign this person out" actually work? | ⚠ needs AWS |

---

## ✅ S4 — Can a browser keep its session key? — **DONE**

**Result: yes, in Chrome.** A full browser quit and relaunch later, the key was still there, still
worked, and was provably the *same* key rather than a fresh one. Six checks, including a control that
had to fail. Write-up: `lab/browser/SPIKE-4-RESULTS.md`.

In plain words: after you log in, our page makes a secret key and keeps it in the browser's own
storage. The worry was that browsers — Safari especially — throw stored data away, which would mean
signing in constantly, or worse, quietly skipping the check.

**What it settled:**

- The key survives being put away. The design does not need rethinking.
- Asking the browser to protect our storage is **not** required for this. The browser declined, and
  the key survived anyway — because that protection guards against *eviction*, not against restarts.
  So we must not assume we will ever be granted it.
- The safe behaviour when the key is missing is therefore a **required, tested** rule: no key means no
  session, so sign in again. Never fall back to an unchecked pass. That is the exact silent downgrade
  this project exists to prevent.

**Still open:** Safari (the browser most likely to evict) is untested, and so is a full laptop reboot.
`lab/browser/manual.html` makes Safari a one-minute manual job.

---

## ⚠ S4b — Do the other browsers behave the same way? — **CHROMIUM DONE**

**Result:** all three Chromium browsers pass **6/6** each — Chrome, Edge and Brave. A full quit and
relaunch later, the key is still there, still works, is provably the *same* key, and a freshly
generated key is correctly rejected.

| Browser | Engine | Result |
|---|---|---|
| Chrome / Edge / Brave | Chromium | ✅ **6/6 each** |
| **Firefox** | **Gecko** | ⚪ not automated — **manual, ~1 minute** |
| **Safari** | **WebKit** | ⚪ not automated — **manual, ~1 minute** |

**The two that matter are still untested.** Chromium is one engine in three skins; Gecko and WebKit
are genuinely different. So the honest state is **one of three engines automated**, not "browsers
done".

**Firefox automation was attempted and abandoned.** Puppeteer failed with `session.subscribe timed
out` under three configurations; Mozilla's own driver (fetched standalone, since Homebrew is
root-owned here) created a session and then discarded the browsing context. Three attempts across two
tools, then time-boxed — the same discipline applied to S5b.

**Safari is blocked for politeness, not technical reasons:** it is open with the user's windows, a
real restart test means quitting it, and remote automation is a setting for the user to change.

**To close it out** — one command, then a minute per browser:

```bash
python3 -m http.server 8099 --directory lab/browser
# open http://localhost:8099/manual.html — Create, quit the browser, reopen, Check
```

**A trap worth knowing:** Brave reports itself as `Chrome/...` in its user agent, so the browser under
test cannot be identified by parsing it. An early attempt at this slice invoked the runner as `edge`
and it silently ran *Chrome* — reporting a perfect 6/6 that meant nothing. The runner now aborts if
the reported browser does not match the one requested.

Full detail: `lab/browser/SPIKE-4b-RESULTS.md`.

---

## ❌ S5 — Does asking for a stronger check actually force one? — **UNRESOLVED**

**Result: the mechanism did not work.** Asking for a higher authentication level made no difference —
the second factor was demanded whether a higher level was requested, a lower one, or none at all. So
there is currently **no working step-up**, and the plan cannot assume one.

In plain words: we wanted some actions to make you prove yourself again. Keycloak is supposed to
support this through a "level of authentication" setting. Configured as documented, it does not gate
anything — the extra check fires always, or not at all, never conditionally.

Write-up with the full evidence: `lab/keycloak/SPIKE-5-RESULTS.md`.

**What was ruled out:** the configuration was correct and read back from the server; the realm's
level mapping was correct; and **five different ways of requesting a level** produced the identical
result. So it is not a typo.

**What is not known:** whether the fault is my flow arrangement or the feature itself. The one
hypothesis worth testing is in the write-up. It is cheap to test and the payoff is large.

**What it invalidates:** `docs/identity-and-passkeys.md` §8 currently claims step-up is solved by
this mechanism and is "better than the original design". That claim is not supported and is now marked
as such.

**Also found, and worth more than the result:** five separate traps that each cost real time. They are
in `HANDOFF.md` §6, and one generalises — **when a Keycloak flow misbehaves, read the container log.**
The only diagnostic that explained anything appeared there and nowhere else.

---

## ✅ S5b — Can step-up be made to work at all? — **ANSWERED: REJECTED**

**Result: do not use this mechanism.** Not "retry later" — rejected, with a reason.

**The finding.** The component the design depended on — `ConditionalLoaAuthenticator` in
`keycloak-services` — carries **CVE-2026-97176**, published **nine days before our test**:

> An authenticated user with a low-level session can obtain a token asserting a higher authentication
> level than they actually performed.

- Fix state: **Affected**. Mitigation: **"not available"**.
- The affected package (`org.keycloak.keycloak-services-26.8.0.jar`) **ships in our build**.

**Why this is the whole answer.** S5 asked whether step-up could be configured correctly. S5b shows
the question is now irrelevant: a control an attacker can bypass is not a control, however well it is
configured. This was going to protect "export who can see what" and "an administrator looking across
all customers".

**I did not reproduce the CVE, and the write-up says so.** The CVE describes a silent *bypass*; S5
observed *over-enforcement*. Different symptoms of the same component, and I have not shown they share
a cause. Either finding alone is enough to reject it.

**The rule that follows — and it is the important part:** **never trust the `acr` claim for a step-up
decision.** A claim the issuer *writes* is not a claim the resource server can *rely on* without
checking. Same lesson as DPoP in S1, now learned twice.

**Rejected in favour of:** `prompt=login` + `max_age=0` to force a genuine re-authentication, with
freshness judged by the **`auth_time`** claim. See ADR-013.

On the privileged realm this is better than it first looks: the only way to sign in there is a
hardware key with user verification, so re-running the flow *is* a fresh hardware-key assertion —
freshness and strength from the same act.

**Also:** the S5 hypothesis (`loa-max-age` not parsed) was **wrong**. The predicted error disappears
once both config keys are set, and the condition still fires. Recorded so nobody retries it.

Full write-up: `lab/keycloak/SPIKE-5b-RESULTS.md`.

---

## ✅ S5c — Does the replacement actually force a fresh check? — **YES, 14/14**

**Result: the replacement is a working control, not a hope.** With one correction to the reasoning
behind it.

`prompt=login` genuinely forces a ceremony even with a live session. `auth_time` advances on that
re-authentication and — critically — **does not retroactively change** on the earlier token. And the
policy that consumes it refuses stale tokens and tokens with no `auth_time` at all (**fail closed**).

**Every claim had a control that had to come out the other way**, because the failure this experiment
exists to catch is *"asking a signed-in user to sign in again quietly does nothing"* — exactly what
S5 found in the mechanism we rejected. Observing a fresh sign-in proves nothing without showing that
one does not happen otherwise.

**A false finding caught before it was published.** The first run reported `max_age=0` did not force
re-authentication, which looked like a real defect. It was my test that was wrong: it requested
`max_age=0` on a session 0 seconds old, and `elapsed > max_age` is `0 > 0` — false. Reusing the
session was correct. Characterising it properly showed `max_age` is honoured, conditionally and
correctly. **The lesson: a failing test is a hypothesis about the code, not a conclusion about it.**

**The finding: ADR-013's strength argument does not hold.** It claimed re-authentication on the
privileged realm *is* a hardware-key assertion. S5c read the flow: a **`Username Password Form` is
still present**, with WebAuthn only as a conditional second factor. So we get **freshness**, verified —
and **not strength**. Corrected in ADR-013; the flow work is S5d.

**Also worth noting:** `acr` *is* present and works here, reported as `"1"`. The problem with `acr` was
never that it is missing — it is that it is a claim the issuer writes, and CVE-2026-97176 shows it can
assert a level never performed. **Use `auth_time` regardless.**

**The gate is negative-tested**, per the rule from the audit: real run exits 0 at 14/14; one check
inverted exits 1. Findings print separately from gates, so a green run cannot hide an unmet premise.

Full write-up: `lab/keycloak/SPIKE-5c-RESULTS.md`.

---

## ✅ S5d — Make the privileged flow actually require a passkey — **DONE, 12/12**

**Result: the privileged realm is now passkey-only — and getting there found a password bypass that
the login page was hiding.**

**The finding that matters.** The first full run failed on exactly one check: a **direct password
grant** at the token endpoint. Direct grants never touch the browser flow, so `attest-privileged` was
passkey-only at the *login page* while `admin-cli` — a built-in client, created by Keycloak in **every**
realm, and public — would still hand out tokens for a password.

> **A passkey-only browser flow does not make a realm passkey-only.**

That is now closed here. **`attest-users` has not been checked and likely has the same gap.**

**It passed the first time for the wrong reason.** The check reported PASS initially because the test
user's password had not been set to the value the test used — so the grant failed on *bad credentials*
rather than on *being refused*. It only became a real check once the positive case (a passkey actually
signing in) worked too. **A refusal is only evidence when the grant would otherwise succeed.**

**What was built:**
- **Copy** the built-in flow (Keycloak refuses to modify built-in flows — the wall S5 hit), add the
  passwordless authenticator, disable the password form, bind the copy.
- **Recovery is one API call**, because the original flow is never edited, only unbound. Tested.
- A **backup/restore tool**, self-tested in a scratch realm before being relied on.

**The bootstrap problem, stated plainly.** A passkey can only be registered by someone who can already
authenticate, so a passkey-only realm has no way to enrol anyone. The test's setup *is* the procedure:
bind the original flow, enrol, bind the passkey-only flow, close direct grants. **In production the
enrolment window must be time-boxed and audited** — that is S5e.

**Three traps, none of which produced a useful error**, and in all three the only place the real reason
appeared was the container log:
1. A **partial `PUT`** to the realm does not merge, so the policy change silently never applied.
2. **`AvoidSameAuthenticatorRegister = true`** silently refuses a repeat enrolment — the ceremony even
   *completes* and asks for a label, and nothing is stored.
3. The registration page **waits for a click**; it does not start on its own.

Full write-up: `lab/keycloak/SPIKE-5d-RESULTS.md`.

---

## ▶ S5e — Time-box and audit the enrolment window — **NEXT**

**In plain words.** To give someone their first passkey, the password has to work again for a moment.
Right now that window is "whenever an administrator runs the script". If that is left as-is, the
passkey-only realm has a permanent, unaudited password path — which is exactly the bypass S5d just
closed, wearing a different hat.

**What to build and test:**

1. A **dedicated enrolment flow**, not the normal one — reachable only for a named user, so enabling it
   for one person does not open the door for everyone.
2. A **time limit** that closes it automatically. Test that it closes: leave it open, wait, and confirm
   the password no longer works.
3. An **audit record** — who was enrolled, by whom, and when. An enrolment window that leaves no trace
   is indistinguishable from an attacker using it.
4. **Control:** the enrolment flow must be unreachable while closed. Prove it, don't assume it.

**Needs:** nothing. Runs on this machine.
**Time:** half a day.

**The bigger one still waiting:** the **phishing-proxy test** — the project's headline claim, and the
top entry in `EVIDENCE.md` §7. It needs care: WebAuthn's relying-party ID ignores the *port*, so a
proxy on a different localhost port would share the RP ID and the test would show a false bypass. It
needs distinct hostnames, which means editing `/etc/hosts`.

---

## ⚠ S1b — Does the proof survive the journey?

**In plain words.** When your browser makes a request it attaches a small signed note. Our servers sit
behind several layers of plumbing — a content delivery network, a load balancer, an API gateway.

Any one of those could quietly drop that note. If it did, every request would fail, and the tempting
"fix" under pressure would be to switch the check off — exactly the disaster this design exists to
prevent.

**Needs:** AWS access.

**Time:** about a day.

---

## ⚠ S2 — Does our permissions engine accept our own passes?

**In plain words.** We use Amazon's policy engine to answer "is this person allowed to do this thing?".
It was built to accept passes from Amazon's own login service. Ours come from our own login server.

We need to confirm it will take them, or find out how we hand it the information instead.

**Needs:** AWS access.

**Time:** about a day.

---

## 🔑 S3b — Is a real hardware key actually accepted?

**In plain words.** In S3 we proved the system *refuses* the wrong kind of key. What we could not test
is the happy path — that a genuine hardware key is *accepted*.

That is because the test used a simulated key, and a simulated key cannot prove what it is, so it can
only ever be refused. It is a real gap: we may have built a rule so strict it locks legitimate people
out.

**Needs:** an actual hardware security key plugged into this machine.

**Time:** an hour, once the key is here.

---

## 👤 S6 — The standards question about "synced" passkeys

**In plain words.** The two kinds of passkey — one that lives only on a physical device, one that is
copied between your devices by your Apple or Google account — are treated differently by the standards
auditors use. There is a specific document about the copied kind. We need to know exactly what it says
about our configuration before we claim anything publicly.

**Why the delay:** the answer must be checked by **someone other than the person who wrote it**.
Marking your own homework is worth nothing here.

**Needs:** a person — ideally a security or compliance reviewer.

**Time:** half a day of reading, plus however long the review takes.

---

## ⚠ S7 — Can the login server run as more than one copy?

**In plain words.** Right now the login server runs as a single copy on this laptop. If that copy
falls over, nobody can log in. Production needs at least two running side by side, staying in step.

The complication is that the usual way of doing this assumes a kind of hosting we are not using, so we
need to confirm the alternative works.

**Needs:** AWS access, and this is the slice that costs real money — a managed database and a load
balancer. **Put a spending alert in place before running it.**

**Time:** a day or two.

---

## ⚠ S8 — How fast does "sign this person out" actually work?

**In plain words.** When an administrator revokes someone's access we claim it takes effect within a
minute. A pass lasts five minutes on its own, so without extra machinery it could linger.

We should measure it rather than claim it. Something as easily overlooked as a caching setting becomes
the real delay — and those settings tend to get lengthened for performance and never put back.

**Needs:** AWS access (mostly).

**Time:** about a day.

---

## Part 2 — Building it

Not started. These are the phases from the main plan, restated as slices. They are blocked on the
experiments above, because the experiments exist to stop us building the wrong thing.

| Slice | What it is, in plain words | Depends on |
|---|---|---|
| **S20** | The skeleton: automated deployment, so the whole system can be created from scratch by running one command | S1b, S7 |
| **S21** | Logging in with a passkey, working for real | S3b, S20 |
| **S22** | The API checking every request properly | S1b, S20 |
| **S23** | Fine-grained permissions, and keeping customers' data apart | S2, S20 |
| **S24** | Judging whether a device looks trustworthy, and asking for a stronger check when it does not | S5 |
| **S25** | Splitting the system into compartments, so one broken part cannot reach everything | S20 |
| **S26** | Audit trail, monitoring, and rehearsing a disaster recovery | S20 |

---

## What I need from you

None of these block S4 or S5:

1. **A hardware security key** — unlocks S3b.
2. **AWS access** (run `aws login`, tell me the account and region) — unlocks S1b, S2, S7, S8.
3. **A second pair of eyes** for S6.

---

**Next slice: S4.** Reply `S4` to start it.
