# Handoff

**Read this first.** It assumes you know nothing about this project, have no memory of the
conversation that produced it, and are starting fresh. That is the point.

**Recorded:** 2026-10-03. Everything below is checkable — see step 0.

---

## 0. Do this before anything else (about two minutes)

```bash
scripts/status.sh          # prints the *actual* current state, not what this file claims
scripts/docs.sh check      # confirms the documentation still builds clean
```

Then open the documentation, which is the primary way to understand the project:

```bash
scripts/docs.sh serve      # http://localhost:8082  (or open docs/site/index.html directly)
```

If `status.sh` disagrees with this file, **trust the script** and fix this file.

---

## 1. What this project is

**Attest** — a multi-tenant web application that helps companies collect and prove compliance
evidence (the paperwork behind a SOC 2 or ISO 27001 report). It is being built to demonstrate
**Zero Trust** properly, with **passwordless, phishing-resistant sign-in** as the foundation.

Each customer is a *tenant*. Inside a tenant there are contributors, tenant admins, and **external
auditors** — third parties who need narrow, time-boxed read access. Above all of them sits a
**platform admin** console used by our own staff, which can see across every tenant.

That mix — untrusted third parties, a hard tenant boundary, and a high-privilege surface — is why the
security work is substantive rather than decorative.

The full explanation, written for someone with no background, is the Guide part of the documentation
site. Start with `docs/site/index.html`.

---

## 2. State of play, in one paragraph

**The design is complete and written down. Nine experiments have been run: six hold, one holds for
Chromium only, one failed and was resolved by rejecting the mechanism it tested, one verified the
replacement, one proved the privileged realm passkey-only — finding a password bypass — and one
bounded and audited the enrolment window, finding that its per-user restriction does not work.**
No production code has been written yet.

**The most serious open item:** a passkey-only browser flow does not make a realm passkey-only.
Direct grants bypass the flow entirely, and `admin-cli` — created by Keycloak in **every** realm and
public — accepts them by default. Closed in `attest-privileged` (S5d); **`attest-users` has not been
checked.** See `EVIDENCE.md` §5.9. The identity provider (Keycloak) runs locally
in Docker with two realms configured. Everything else is design, not deployment — the documentation is
deliberately explicit about which is which, and you should preserve that distinction.

---

## 3. What is proven, and what is merely designed

**`EVIDENCE.md` is the authoritative record.** It lists every load-bearing claim with its evidence and
a confidence level, and it names the places where we are **not** certain. If any other file states a
claim more strongly than `EVIDENCE.md` records it, **that other file is a bug** — fix it.


This distinction is the most important thing to preserve. Do not let it erode.

**Proven by experiment** (both written up on the *What we tested* page of the docs site):

| Claim | Result |
|---|---|
| Only genuine hardware keys can register for privileged access — the rule actually refuses the wrong kind of key rather than just saving a setting | **Holds** |
| A stolen session pass is inert: no proof, wrong key, wrong address, or a replayed request are all refused | **Holds** |
| A browser keeps its session key across a full quit and relaunch, and it is the same key afterwards | **Holds in Chrome** — Safari untested |

**Failed, then rejected:** step-up authentication. S5 found the mechanism never gated; S5b found the
component carries **CVE-2026-97176** — a user with a low-level session can obtain a token asserting a
higher level than they performed, with **no fix and no mitigation available**, in a package that ships
in our build. **ACR/LoA-based step-up is rejected (ADR-013).** The replacement is `prompt=login` plus
`max_age=0`, with freshness judged by the **`auth_time`** claim.

**The rule this established, and it applies well beyond step-up: a claim the issuer *writes* is not a
claim a resource server can *rely on* without checking.** Same lesson as DPoP (S1). It has now been
learned twice, so treat it as a design principle rather than an incident.

**Designed but untested:** everything else, including sign-in surviving a real phishing proxy, whether
a *physical* hardware key is accepted, whether browsers can hold the session key, revocation speed,
and running the identity provider as more than one copy.

`WORK.md` lists each untested item as a numbered slice with what it needs.

---

## 4. What to do next

**Slice S5d — make the privileged flow actually require a passkey.**

S5c verified the step-up replacement as a working control (14/14, negative-tested). It also found that
**ADR-013's strength argument does not hold**: the privileged browser flow still contains a
`Username Password Form`, with WebAuthn only as a conditional second factor. So re-authentication
there gives verified **freshness** and, today, **no strength**.

S5d does the flow surgery so that a password alone is **refused**. This is the gap between "supports
passkeys" and "requires a passkey", and it is the whole point of the privileged realm.

**⚠️ The risk here is lockout, not bypass.** Get it wrong and privileged administrators cannot sign in
at all. Build and verify the recovery path *before* removing the password form.

**Nothing is blocking it.** Runs on this machine using S3's virtual authenticator.

**Also worth doing whenever convenient — a one-minute manual job:** run the S4 test in Safari, which
is the browser most likely to throw stored data away and the one we could not automate. It needs a
real address rather than a file:

```bash
python3 -m http.server 8099 --directory lab/browser
# open http://localhost:8099/manual.html in Safari
```

Press **Create and store a key**, quit Safari completely, reopen the same address, press **Check the
key**, and report what it says.

Full list and dependencies: `WORK.md`.

> **Note on numbering.** Slice numbers are the same as the experiment ("spike") numbers used
> throughout the engineering documents, so `S5` and "Spike #5" are the same work. An earlier draft of
> this file used a second, separate numbering — that was a trap and has been removed.

---

## 5. How we work here

These are conventions the previous session established. Please keep them.

1. **Plain language in updates to the human.** No unexplained jargon. If a term is unavoidable,
   explain it in the same sentence. The documentation is written for a newcomer; the chat updates
   should match.
2. **Work is numbered.** Every remaining task is a *slice* (`S1`, `S2`, …) in `WORK.md`. The human
   replies with a slice number to choose what is next. Do not make them invent a phrasing.
3. **Never overstate what is proven.** If something has not been tested, say so plainly and put it in
   the "not proven" list. This is the project's main source of credibility — an earlier phase found
   several plausible-sounding claims that turned out to be wrong, and saying so was more valuable than
   being right.
4. **Prefer a controlled test to an assumption.** For any experiment, change **one variable at a
   time** and include a **control** row that must pass. A rejection with no control proves nothing.
5. **Verify with the real thing where possible.** Reading documentation got several details wrong;
   running it found them.
6. **Say when you do not know.** Several entries in the docs are explicitly marked unverified, and
   that is deliberate.

---

## 6. Hard-won facts — things that cost real time to discover

Do not re-learn these the hard way. Each was found by testing, and several contradict what the
documentation implies.

**Identity provider (Keycloak) configuration**

- **It silently ignores unknown configuration keys.** A misspelled setting produces a setting that
  looks applied and does nothing. Always read back after writing, and assert persistence in a test.
- The avoid-duplicate-authenticator field is `...AvoidSameAuthenticatorRegister`, **not**
  `...Registration`. There are also **two** separate resident-key fields with different defaults.
- It performs **no format validation on AAGUID values** — `"not-a-guid"` is stored verbatim. Validate
  format yourself.
- The default sign-in flow **requires a password form** and does not include the passkey authenticator
  at all. Removing passwords from the privileged realm is real configuration work, not a toggle.
- Read-modify-write when updating a realm: these APIs behave like full replacement, so omitting a
  field resets it.

**Token binding (DPoP)**

- A bound token must be sent under the **`DPoP`** authorization scheme, not `Bearer`. Using `Bearer`
  fails with a challenge that names *Bearer*, sending you to the wrong layer entirely.
- A proof for an API request **must carry the `ath` claim** (a hash of the access token). Omitting it
  gives `invalid_token: Token verification failed` — a message that mentions DPoP nowhere. This was
  the hardest thing to diagnose.
- The reference implementation compares the proof's URL at **path level but ignores the query
  string**. Our own check compares the full URL, deliberately stricter.
- Keycloak issues `cnf.jkt` plus a non-standard `kc-jkt-type: DPoP` marker.

**Browser automation**

- `window.prompt()` is called by Keycloak's WebAuthn registration page and **blocks headless Chrome
  indefinitely** unless a dialog handler is registered. Without one, enrolment silently never
  completes — and looks exactly like a policy rejection.
- Chrome's virtual authenticator **cannot set an AAGUID**. It *can* set `transport` and
  backup-eligibility, which is enough to test acceptance/rejection but not arbitrary AAGUIDs.
- It reports an all-zero AAGUID with no attestation — which turns out to be ideal for testing
  whether a non-attesting authenticator is refused.
- Never call `page.evaluate()` after starting a WebAuthn ceremony; the dialog blocks the renderer.
  Poll the Admin API for the result instead.
- A test that only checks "did a credential appear" produces **false positives** if a credential from
  an earlier run is still present. Always require a *new* credential id.
- **Any "is this the same thing as before?" check needs a negative control that must fail.** In S4 the
  comparison was "does the old public key verify the new signature". Without also feeding it a
  *freshly generated* key and requiring rejection, a comparison that always returned true would have
  looked identical to a pass. This applies to any equality/continuity assertion.
- **`navigator.storage.persist()` returning `false` does not mean stored keys are lost.** It guards
  against *eviction* (storage pressure, and Safari's ~7-day no-visit rule), not against a restart. So
  do not treat a `false` here as a failure, and do not build a design that depends on it being granted
  — in testing it was refused and everything still worked.
- **Keycloak flows are a minefield, and the errors lie.** In S5, four separate faults each surfaced
  as the *same* misleading message — "Invalid username or password" on a page nobody had typed into.
  Specifically: (a) you **cannot add a subflow to a built-in flow** — copy it; (b) a `CONDITIONAL`
  subflow at the **top level** of the browser flow silently destroys it, and must be nested inside
  `forms`; (c) the **flat executions list mixes every nesting level**, so matching an authenticator by
  name alone also hits the built-in copies and corrupts them — ask each flow for *its own* children;
  (d) making a conditional subflow's inner authenticator `ALTERNATIVE` breaks the flow outright.
- **When a Keycloak flow misbehaves, read the container log.** The only diagnostic that explained
  anything in S5 — `ERROR LoAUtil: Invalid max age configured for condition 'loa2'. Fallback to 0` —
  appeared **only** in `docker logs`, never in an API response or the rendered page. The LoA condition
  needs **two** config keys, `loa-condition-level` and `loa-max-age`, not one.
- **`http.cookiejar` cannot drive a Keycloak login.** Keycloak marks login cookies `Secure`, and for a
  bare hostname like `localhost` cookiejar rewrites the domain to `localhost.local`, so over plain
  HTTP they are never sent back and every login fails with **"Restart login cookie not found"** — which
  reads like an expired session. Track `name=value` pairs yourself instead.
- **Check the commit SHA, not "the latest run".** After pushing a fix, `gh run list --limit 1` can
  still return the *previous* commit's run for a minute or so. Reading that as "the fix did not work"
  sent this session chasing a solved problem and adding an unnecessary diagnostic step. Always compare
  `headSha` against what was just pushed.
- **A test that cannot tell "denied" from "broken" is not a test.** S5e concluded, and briefly
  published, that Keycloak's `conditional-user-role` "never gated". Both halves of that test were
  broken: the **client was disabled**, so every request returned HTTP 400 `"Client disabled."`, and
  the probe **read only the first page**, whereas with identity-first login the condition is evaluated
  only *after* the username is submitted. Both faults produced "no password field", which looks
  exactly like a condition refusing. **Assert on the HTTP status and complete every step of the flow
  before concluding anything from an absent field.**
- **In Keycloak, a conditional that can skip the only credential step makes the flow fail OPEN.** With
  the gate working, skipping the credential step did not fail the flow — Keycloak **issued a token**.
  A real token was obtained with **no credential at all, only a username string**. `Username Form`
  identifies a user; it does not authenticate one. Making the subflow `REQUIRED` instead of
  `CONDITIONAL` removes the gate rather than closing the hole. **Design conditional flows so some
  authentication step is REQUIRED on every path.**
- **A test that prints FAIL and exits 0 is not a test.** Found in this project: *two* scripts printed
  `PASS`/`FAIL` rows without ever affecting their exit code, so any automation — including the CI
  added alongside them — would have reported success on a total regression. **Every gate must be
  negative-tested**: deliberately break it, and confirm it fails. Observing a green run proves
  nothing about whether the check can go red.
- **A dependency can carry a live CVE in exactly the feature you need.** Before building on a
  third-party security feature, search the CVE databases for the *component*, not just the product.
  S5b found CVE-2026-97176 in `ConditionalLoaAuthenticator` only by looking it up directly — nothing
  in the API, the logs, or the rendered pages mentioned it.
- **Sandbox quirks that cost time:** `find`+`pgrep` output needs care, `timeout` does not exist on
  macOS (use the tool's own timeout), and `UID` is a readonly shell variable — pick another name.

**This environment**

- `~/.npm` and `~/.cache/pip` are **root-owned and not writable**. Both toolchains must redirect to a
  workspace-local cache (`.npm-cache/`) or a workspace venv (`.venv/`). This will bite you on the
  first `npm install`.
- Chrome needs **`--no-sandbox`** when launched from here; its own sandbox cannot initialise.
- `pgrep`/`ps` for general process listing may be **blocked**. There is another project's docs server
  on port 8081 — do not kill it.
- The sandbox writes only inside this workspace.

---

## 7. Where everything lives

**Public repository:** <https://github.com/fkadusei/attest-zero-trust> (MIT licence, `main` branch).
Work here is committed with `git` — the repo was initialised at the design checkpoint, so there is no
history containing anything that predates the security policy.


```
docs/
  src/                    ← SOURCE. The Guide and Evidence pages. Edit these.
  site/                   ← GENERATED. Never edit by hand; see rule below.
  *.md                    ← The engineering documents (also rendered into the site)
lab/keycloak/             ← The test lab: containers, plus both experiment scripts
  SPIKE-1-RESULTS.md      ← token binding experiment, raw write-up
  SPIKE-3-RESULTS.md      ← hardware key experiment, raw write-up
scripts/
  build_docs.py           ← Markdown → the documentation site
  check_docs.py           ← links, anchors, offline-safety, staleness
  docs.sh                 ← build | check | serve | stop | diagrams | all
  serve_docs.py           ← local server that finds a free port
tools/                    ← Node build tools (diagram rendering, screenshots)
HANDOFF.md  WORK.md  README.md
```

**Never hand-edit `docs/site/`.** It is generated from Markdown and a check fails if it drifts. To
change the documentation, edit `docs/src/*.md` (or the engineering docs) and run
`scripts/docs.sh build`.

---

## 8. Roadmap

Numbered slices. `S1`–`S8` prove things; `S20`+ build things. Numbers match the engineering docs.

| Slice | What it is | Needs |
|---|---|---|
| ✅ S1 | Is a stolen session pass useless? | — *done, holds* |
| ✅ S3 | Can we enforce hardware keys for admin accounts? | — *done, holds* |
| ✅ S4 | Can a browser keep its session key across a restart? | — *done; **Chromium only*** |
| ⚠ S4b | The other browser engines | — *Chromium 6/6; **Firefox + Safari manual*** |
| ❌ S5 | Does asking for a stronger check actually force one? | — *ran, did not work* |
| ✅ S5b | Can step-up be made to work at all? | — *answered: **rejected**, live CVE* |
| ✅ S5c | Does the replacement force a fresh check? | — *yes, **14/14** with controls* |
| ✅ S5d | Make the privileged flow require a passkey | — *yes, **12/12**; found a password bypass* |
| ⚠ S5e | Time-box and audit the enrolment window | — *14/14; per-user gate **unmet**, and it fails open* |
| **▶ S5f** | Can enrolment be made per-user with impersonation? | nothing |
| ⚠ S1b | Does the proof survive the network edge? | AWS |
| ⚠ S2 | Does the permissions engine accept our tokens? | AWS |
| 🔑 S3b | Is a real hardware key actually accepted? | **a physical key** |
| 👤 S6 | The standards question about synced passkeys | **a second pair of eyes** |
| ⚠ S7 | Can the login server run as more than one copy? | AWS — **costs money** |
| ⚠ S8 | How fast is "sign this person out"? | AWS |
| S20–S26 | Build it: skeleton, login, API checks, permissions, device checks, segmentation, audit | S1b, S2, S7 |

Detail and time estimates: `WORK.md`.

---

## 9. Decisions taken, and what is still unowned

**Decided:** the identity provider is **self-hosted**, not rented. This was chosen deliberately
because it is the only way to enforce "hardware keys only" as a proven control rather than an
approximation.

**What that commits us to:** a critical security patch must be deployable within **48 hours**, and
disaster recovery must be **rehearsed**, not merely documented. An untested patch procedure is a hope.

**Still unowned:** *who* does that day to day — upgrades, backups, incidents. This is the last open
operational question, and a commitment with no owner is not a commitment. Raise it if the human has
not.

**Unowned prerequisites:** a physical hardware key (needed for S3b) and AWS access (needed for S1b,
S2, S7, S8). **Nothing blocks S5.**

**Do not build on:** ACR-based step-up (`docs/identity-and-passkeys.md` §8 makes a claim about it
that is now known to be unsupported).

**One manual job outstanding:** S4/S4b have only been automated for **Chromium** (Chrome, Edge,
Brave — all 6/6). **Firefox and Safari are untested**, and they are the two different engines.
`lab/browser/manual.html` closes both in about a minute each; instructions are in section 4.

Firefox automation was tried and abandoned after three attempts across two tools — puppeteer
(`session.subscribe timed out`) and geckodriver (`Browsing context has been discarded`). Do not sink
more time into it without a specific reason.

For Safari: `safaridriver` needs *Develop → Allow remote automation*, and a real restart test means
quitting Safari — **do not do that while the user has windows open.**

---

## 10. Keeping this file honest

This file will rot if it is not maintained. Please:

- **Update section 2 and the roadmap table** whenever a slice completes.
- **Add to section 6** whenever you spend more than ~20 minutes discovering something non-obvious.
  That section is the highest-value part of this document.
- **Do not add claims to section 3** unless an experiment actually ran and had a control.
- Re-run `scripts/status.sh` after changes and make sure it agrees.

If you only ever update one file, update this one.
