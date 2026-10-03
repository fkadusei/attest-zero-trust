# Work plan — numbered slices

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
| **S5b** | Can step-up be made to work at all? | ▶ **NEXT** |
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

## ▶ S5b — Find out whether step-up can be made to work at all — **NEXT**

**In plain words.** S5 failed, but it failed in a way that leaves one specific question open: **is my
flow arrangement wrong, or does the feature simply not work as documented?**

There is one cheap test that separates the two: set the condition's level to **1** instead of 2 and
see whether it *still* fires unconditionally. If it does, the condition is not being evaluated at all,
which points at the structure of the flow rather than the numbers in it — and the search becomes
"find the arrangement Keycloak expects" rather than "guess the right values".

**If the mechanism turns out not to work**, the fallback is to force a full re-authentication
(`prompt=login` with `max_age=0`). That definitely works, but it is honestly weaker: it proves the
check is *fresh*, not that it is *stronger*. That difference needs stating plainly rather than being
quietly glossed over.

**The third option**, if both fail, is to stop using the identity provider for step-up and require a
fresh passkey assertion at the moment of the sensitive action, verified by our own API. More control,
more custom code, and it goes against the principle of letting the identity provider own the ceremony.

**Needs:** nothing. Runs on this machine.
**Time:** half a day, and it should be time-boxed. If it is not resolved in that, take the fallback
and move on — this must not become the project's permanent open question.

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
