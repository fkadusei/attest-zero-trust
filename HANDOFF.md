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

**The register was audited and corrected.** An independent adversarial review plus a full re-run found
the "denied vs broken" defect in five more places. Every suite now has stronger assertions, and the
standing rule is a **negative meta-test per suite**. See `EVIDENCE.md` §2a for the full list.

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
- **A reverse proxy makes Keycloak believe it is serving plain HTTP.** Cloudflare terminates
  TLS at its edge and forwards http to the origin, so Keycloak issued
  `http://id.210security.com/...` in its discovery document while the browser was on https://.
  `KC_PROXY_HEADERS: xforwarded` is the fix, and it CANNOT be an empty-string default —
  Keycloak refuses to start: `Invalid value for option 'KC_PROXY_HEADERS': .`. Use an overlay
  file. The failure looks like a misconfigured CLIENT, not a misconfigured proxy.
- **Keycloak separates multiple `post.logout.redirect.uris` with `##`.** Space and newline are
  both rejected with "A post-logout redirect URI is not a valid URI" — an error about the URI,
  never about the separator. Guessing wrong means sign-out appears to work while the SSO
  session survives.
- **A WebAuthn `SecurityError` is an RP ID problem, not a Keycloak or browser problem.** The
  message is "ensure you are on the correct site", which is true and tells you nothing. Check
  the realm's `webAuthnPolicyPasswordlessRpId` is a suffix of the ORIGIN first.
- **Regenerating a credential file ORPHANS every running container.** They hold the credentials
  they were created with; the scripts read the new ones. The symptoms are `invalid_grant` from
  Keycloak and `password authentication failed` from Postgres — which look like an identity-provider
  fault and a database fault, and are neither. Regenerating and rebuilding are one operation, so
  `scripts/lab.sh reset` does both.
- **Removing a variable from a module's registry but leaving an accessor behind fails only when the
  file is ABSENT.** The `KeyError` surfaced in CI and not locally, because locally `lab/.env` already
  existed and the accessor was never reached. **A clean-state run is the only way to test code whose
  job is to create things.**
- **A validator that accepts what the consumer rejects is not a validator.** `yaml.safe_load` was
  perfectly happy with a step that had two `run:` keys; GitHub refused to run the file at all. The
  check in `scripts/check_workflows.py` exists because the obvious one gave a confident wrong answer.
- **A credential literal in a public repository is a credential literal in a public repository.**
  The lab had one placeholder password in twenty-odd files. It protected nothing — a throwaway
  container on localhost — and GitHub's scanner flagged it anyway, correctly: its job is to find
  `password: "..."`, and a scanner that excused a value because it contains "not-a-secret" would be a
  worse scanner. Generating it into a gitignored `lab/.env` fixed the signal without pretending the
  lab became secure. **The scanner now has nothing to say, so its output stays worth reading.**
- **Two loaders for one file will disagree.** The Python and Node credential loaders resolved
  *different paths* to the same `.env`, so one of them silently created a SECOND file with different
  values. The symptom was `invalid_grant` from Keycloak — which looks like an identity-provider
  problem and was a path bug. **Verify that two implementations of one thing agree**, rather than
  assuming they do because both "read the same file".
- **A compose file cannot find `.env` in a directory above it.** Every `docker compose` call needs
  `--env-file`, and a rule that has to be remembered is a rule that gets forgotten — so it lives in
  one wrapper (`scripts/lab.sh`) that nothing else has to know about.
- **Fastify does NOT infer `text/html` for a string payload.** It sends `text/plain`, so a browser
  renders the ESCAPED SOURCE of the page rather than the page. **A unit test that greps the body for a
  word passes anyway**, because the escaped source still contains the word. Assert the
  `Content-Type` HEADER, not the body. Found by a real browser, not by the suite.
- **"Sign out" needs `post.logout.redirect.uris` registered on the OIDC client.** Without it Keycloak
  refuses the end-session request with `HTTP 400`, the console's own session dies, and **the SSO
  session survives** — the next visit signs the user straight back in silently. It LOOKS like it
  worked. The console cannot detect this server-side; the error goes to the browser.
- **A passkey credential with no `userHandle` can never sign anyone in.** Keycloak's passwordless flow
  is a discoverable-credential flow: it identifies the user FROM the handle. The failure reads
  `webauthn-error-user-not-found`, and the credential's `credentialData` will be missing
  `userHandle`. Check that before suspecting the flow.
- **A browser harness must refuse to run when its port is occupied.** A stale server from a failed
  earlier run made the suite silently measure the WRONG configuration — the browser was sent to one
  realm while the script believed it had configured another. Health checks cannot tell one process
  from another; assert on something the process actually serves.
- **A server-rendered console CANNOT use DPoP, and that is a consequence, not a preference.** DPoP
  binds a token to a key the CLIENT holds; for a server-rendered console to prove possession per
  request, the key would have to live in the browser — reintroducing the problem the server-side
  session exists to remove. The console therefore authenticates with a client secret and its tokens
  are NOT sender-constrained. **The user's login is still a passkey**; what is lost is detectable
  token theft at the API for these tokens. A browser-side console would use DPoP.
- **The console must be a CLIENT of the API, never a privileged path into it.** Every page is rendered
  from data fetched over HTTP with the user's own token, so the same `authenticate` → `authorize`
  chain runs. Reading the repository directly would be easier and is exactly how an admin console
  becomes a bypass. **This means the console test must run against a LISTENING server** — `inject`
  opens no socket, so a stub cannot satisfy the console's own HTTP calls.
- **MinIO no longer publishes to Docker Hub.** It moved to quay.io, which the registry proxy on this
  machine refuses with `401 Unauthorized`. `adobe/s3mock` is on Docker Hub, speaks the S3 API, and is
  built for exactly this. Checked by trying four images rather than assuming the first choice would
  work.
- **`adobe/s3mock` ignores `initialBuckets`.** The bucket must be created by the caller — which is the
  standing rule anyway: **the harness creates its own fixtures.** Relying on the env var would have
  made the suite environment-dependent.
- **A test that passes because the target does not exist proves nothing.** The first traversal test
  asked for `/etc/passwd` and saw `undefined`, which looked like a refusal — but the adapter reads a
  `.meta` sidecar that `/etc/passwd` lacks, so the read failed for an unrelated reason. **Plant the
  target so it WOULD be served**: put the victim inside the root but outside the tenant directory,
  with a valid sidecar. Then only the defence stands between the caller and the bytes, and mutation
  testing can tell the difference. Removing both traversal defences left the old test green while a
  real file leaked and a real file was deleted.
- **Row-Level Security is bypassed by SUPERUSERS, always, and by the TABLE OWNER unless `FORCE`.**
  An application connecting as either gets **no RLS at all, silently** — every query succeeds, every
  test passes, and the boundary is absent. The application role must be `NOSUPERUSER NOBYPASSRLS` and
  must not own the tables. **Keep a superuser connection in the tests as the negative control**, or the
  RLS test also passes on a database where RLS does nothing.
- **Use `SET LOCAL`, never `SET`, for a per-request tenant on a pooled connection.** `SET LOCAL` is
  transaction-scoped and reverts; a plain `SET` persists on the connection and leaks the tenant to
  whichever request picks it up next. That is a cross-tenant read caused purely by connection reuse.
- **Check the port before connecting.** Host port 5432 on this machine belongs to an unrelated project
  (`pqcscan-development-postgres-1`), not the lab. The application database uses **55432** so a
  collision is obvious rather than silent.
- **A permit that does not name the PRINCIPAL TYPE grants access to any entity carrying a matching
  attribute.** A Cedar test caught a `MysteryActor` being allowed. Every permit now lists
  `principal is User || principal is ServiceAccount`, so a new entity kind is denied until someone
  deliberately permits it.
- **Cedar can return `allow` WITH a non-empty `errors` array** — when a different policy failed to
  evaluate, and that policy may have been a `forbid`. **Never trust the decision without checking
  `diagnostics.errors`.** The PDP denies on any error.
- **A dead policy rule is worse than no rule.** The `forbid` guarding a resource with no `tenant`
  attribute is UNREACHABLE through the ordinary permits, because every permit already requires the
  attribute. Removing it changes no outcome — so a mutation of it survives, correctly. It is a
  safety net for a future careless permit, and it is tested as one: a deliberately loose permit is
  added and the net must catch what it lets through, with a control proving the net did the work.
- **A scripted edit that silently does nothing looks exactly like success.** An insertion into
  `server.test.ts` used an anchor that no longer existed, so five tests were never added — and the
  suite still reported green. **Assert the edit landed** (`assert "TENANT ISOLATION" in text`) before
  trusting the result. Mutation harnesses have the same failure mode, which is why they assert the
  mutation applied.
- **A surviving mutant is NOT automatically a blind spot.** Removing the server's `if (!proof)`
  check, and removing `assertNotDowngraded` too, both leave the suite GREEN — because
  `verifyDpopProof` independently refuses a missing proof. **The property never broke.** A mutation
  harness that only observes GREEN/RED cannot distinguish "the suite is blind" from "another layer
  compensated", and will cry wolf. Before calling a surviving mutant a defect, **check whether the
  property still holds**.
- **A control that works by crashing is not a control.** The missing-proof case was originally
  satisfied only because `decodeProtectedHeader(undefined)` throws. The property held by accident,
  and a mutation that deleted the caller's own check went unnoticed. It is now an explicit,
  separately-tested guard. If a security property depends on an incidental failure, name it.
- **A suite that passes only because ANOTHER suite ran first is borrowing, not passing.** The L2
  suite called `ensureDpopClient()` but not `ensureLabFixtures()`. It passed locally because an
  earlier session had already created the realm; CI ran `dpop` before `verify` alphabetically, found
  no realm, and failed every test with `HTTP 404 "Realm not found"`. **Reproduce CI ordering locally
  by DELETING the fixture first** — that is the only way this class of bug shows up.
- **Test files that share ONE external service must not run in parallel.** Node runs files
  concurrently by default; two suites creating clients in the same realm race. `--test-concurrency=1`
  is set deliberately, and the reason is recorded in the script rather than left to be rediscovered.
- **A DPoP-bound token needs the `DPoP` authorization scheme, not `Bearer`, and a resource proof
  MUST carry `ath`.** Both were S1 findings; L2 now enforces them in code. Keycloak also demands a
  **nonce** on resource requests, which is stricter than RFC 9449 — a resource server choosing to
  require nonces owes its clients an extra round trip.
- **The DPoP replay check must run LAST.** Consuming the `jti` before the other checks lets a
  malformed proof burn a `jti` that a legitimate request might need. And it must be **atomic** — a
  check-then-set is a race two concurrent replays both win.
- **The expected request URI must come from trusted configuration, never from `X-Forwarded-*` or
  `Host`.** Deriving it from headers lets the attacker choose the value the proof is compared
  against, which makes every `htu` check vacuous while still looking present.
- **Cloud-agnostic is a REQUIREMENT, and it contradicts a decision already made.** ADR-008 chose
  DynamoDB, which exists only on AWS. **ADR-015 now governs**: the domain and its interfaces are
  portable, cloud services appear only behind adapters, and **the portable adapter is the default
  and the one CI tests**. Superseded in practice: DynamoDB (→ PostgreSQL), AVP (→ optional, because
  Cedar is the portable part and the service is not), Lambda/API Gateway (→ containers).
  **The security argument and the portability argument point the same way**: PostgreSQL Row-Level
  Security enforces the tenant boundary *in the database*, whereas a DynamoDB partition key is only
  a convention the application must honour.
- **Keep the core config cloud-free.** `src/config.ts` reads no `AWS_*`, contacts nothing at
  startup, and has a test asserting that supplying AWS variables changes nothing. If a cloud concept
  appears there, the boundary has already leaked.
- **When a mutation fails to APPLY, refuse to report.** The config meta-test initially printed
  "MUTATION FAILED TO APPLY" for one mutant because of a shell-escaping bug — and correctly did not
  claim it was caught. A harness that reports success when it did nothing is worse than no harness.
- **Keycloak puts the token type in TWO places, and they disagree.** Header `typ` is `"JWT"` for
  **every** token; the payload claim `typ` is `"Bearer"` for an access token and `"ID"` for an ID
  token. **Only the payload claim distinguishes them**, and it is trustworthy only after the
  signature verifies. A header check looks like protection and provides none — and the tempting
  "fix" (expect `"JWT"`) makes the test pass while removing the control entirely.
- **Mutation-test the suite, and measure the mutation test by EXIT CODE.** The first attempt at the
  meta-test reported all mutants as "GREEN" because a `grep` for the summary counts did not match —
  the harness was broken, not the mutants undetected. The same "cannot tell denied from broken"
  failure this project keeps hitting. **Deleting the `sub` check really did go undetected** until a
  synthetic issuer was added to mint claims Keycloak will not.
- **WebAuthn only exists in a SECURE CONTEXT, and that constrains every local test.** `*.localhost` is
  treated as trustworthy over plain HTTP; **any other hostname is not**, and `window.PublicKeyCredential`
  is undefined. Keycloak reports it as `WebAuthnUnsupportedBrowser`, which reads like a browser problem
  and is not. A resolvable hostname over HTTP is **not enough**. Use `*.localhost`, or tell Chrome
  `--unsafely-treat-insecure-origin-as-secure=<origin>` (a lab stand-in for the TLS a real deployment
  has). S9 worked because of this; S9b initially failed because of it, and time went into DNS first
  because the symptom did not say so. **When WebAuthn "is not supported" and the browser is fine, check
  whether the origin is a secure context.**
- **Chrome can be told to resolve hostnames itself:**
  `--host-resolver-rules="MAP app.attest.test 127.0.0.1"`. That is how S9b ran on a real registrable
  domain with **no `/etc/hosts` edit** — which mattered, because the file is root-owned and `sudo`
  wanted a password. Combine with `--public host:port` on a proxy that binds `0.0.0.0`, or the rewritten
  URLs point at `0.0.0.0`.
- **Every harness creates the fixtures it depends on.** The S5f CI job died with `no such user:
  spike-attest-privileged` — the user is made by another harness, and a fresh realm has none. **This is
  the third time** the same assumption has broken a job (S5e, its CI job, and S5f). Assume **no user
  exists**; create what you need, and clear required actions so a setup prompt is never mistaken for a
  credential failure.
- **When a container must reach a service, put the service on the same network.** Two attempts at
  host networking failed silently: editing the *runner's* `/etc/hosts` cannot affect a container, and
  `extra_hosts` is useless if the sink binds to loopback only. A compose service on the same network
  has no host networking to get wrong and behaves identically everywhere.
- **Check the commit SHA, not "the latest run".** After pushing a fix, `gh run list --limit 1` can
  still return the *previous* commit's run for a minute or so. Reading that as "the fix did not work"
  sent this session chasing a solved problem and adding an unnecessary diagnostic step. Always compare
  `headSha` against what was just pushed.
- **Keycloak impersonation is not a shareable link.** The endpoint returns `Set-Cookie:
  KEYCLOAK_IDENTITY` **to the API caller**, so the session belongs to whoever called it. Opening the
  returned URL with no cookies sets nothing. Keycloak's own PR #40767 says the same, and the variant
  that would work is unmerged. If a per-user, shareable link is needed, use **`execute-actions-email`**
  — the action token does exactly that, needs no password, and lands on the required action.
- **A test that cannot tell "denied" from "broken" is not a test.** An independent adversarial audit
  found this same defect in **five more places**, three of them rows the register called *Verified*:
  a check comparing a constant to itself (S5d D1); a check re-parsing the same token and comparing it
  to itself (S5c T4); a "lockout" check that only counted credentials, whose control user lived in a
  realm that is not even passkey-only — the reviewer **signed in as that user and got a token** while
  the check reported PASS.
- **Run a NEGATIVE META-TEST on every suite: deliberately break the property, and confirm the suite
  goes RED.** A green run proves nothing about whether a check can fail. Note the trap: the first
  attempt at S5d's meta-test re-enabled direct grants and the suite still passed, because the suite's
  own setup re-closed them. Break the *enforcement*, not the *property*, or you are testing the setup.
- **Check what the subject of a test actually IS.** The audit found checks inspecting a different
  realm, a hard-coded flow alias, and a **DISABLED** execution counted as a live one — the last made a
  finding uncleareable, emitted even after the flow had been fixed.
- **A check that reads the tool's own success message is self-vouching.** S5e's sweep printed "closed"
  whether or not it had closed anything, and the test grepped for that string. Assert the *state*.
- **The counts are not the headline.** S5d reports 18/18; about four are load-bearing. Read the claim,
  not the ratio — see `EVIDENCE.md` §6c.
- **A test that cannot tell "denied" from "broken" is not a test (original note).** S5e concluded, and briefly
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
| ✅ S5f | Can enrolment be made per-user? | — *yes, by emailed link; **impersonation ruled out*** |
| ✅ S9 | Does a phishing proxy actually fail? | — ***YES*, proven with a real relay** |
| ✅ S9b | Is a broad relying-party ID exploitable? | — ***YES*, measured; no `/etc/hosts` needed** |
| **▶ S4b** | Firefox and Safari — the last two engines | **~1 minute at the keyboard** |
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
