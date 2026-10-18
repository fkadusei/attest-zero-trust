# Mutation testing — the uncovered modules, and what it found

**The harness is `scripts/mutate.py`. This round covered the code that had never been mutation-tested:
the console and the Cedar PDP.**

## Why this was needed

`verify.ts`, `dpop.ts`, `config.ts`, the policies, RLS and object storage had all been mutation-tested
by hand. **The console — the newest code, and where three real bugs had already been found — had not.**
Hand-editing a file, running a suite and editing it back is slow enough that modules get skipped, and
it had produced two recorded harness failures: one that grepped for counts that never matched and
therefore measured nothing, and one where a `cp` restore silently failed and left the source mutated.

`scripts/mutate.py` is built so those cannot recur:

- **Exit code, never output parsing.**
- **The restore is verified** by checksum; a failed restore aborts the run.
- **A mutation that does not apply is a FAILURE** — "the suite stayed green" and "the code never
  changed" are otherwise indistinguishable.
- **A green control is required first**, or no result below means anything.

Negative-tested: a spec whose text is not in the file exits **1** and reports `did-not-apply`.

---

## 1. `console/session.ts` — two real gaps, both closed

First run: **0 of 3 caught.**

| Mutation | First run | After |
|---|---|---|
| expired sessions are ACCEPTED | **survived** | **caught** |
| CSRF comparison ALWAYS MATCHES | **survived** | **caught** |
| CSRF length pre-check removed | survived | survived *(correct)* |

**The CSRF gap was the serious one.** The suite had tests named *"sign-out without a CSRF token does
NOT end the session"* and *"creating WITHOUT a valid CSRF token is refused"*. Both send `csrf=wrong` —
**five characters**, against a 43-character token. So they were rejected by the **cheap length
pre-check** and **never reached the constant-time comparison**.

Deleting the constant-time comparison left the whole suite green. **The property — "a well-formed but
wrong token is refused" — genuinely broke, and nothing noticed.** This is the opposite of the
documented `server.ts` case, where a survivor was fine because another layer kept the property intact.

**Fixed:** two tests added. One sends a token of the **correct length with one character changed**, so
only the comparison can refuse it. The other tests expiry directly on the store.

Token length 43 · tests sending the 5-char `"wrong"`: 2 · tests sending a same-length wrong token: **0** → **1**.

## 2. `console/oidc.ts` — a module with NO test coverage at all

First run: **0 of 4 caught.** Every single one survived.

The four included *"the ID-token nonce check always passes"* — the defence against token substitution.
It survived because **the console tests inject a stub `ConsoleOidc`**. The real `OidcClient` — 232
lines: nonce check, discovery, code exchange, logout URL — **was never instantiated by any test.**

That is the most dangerous shape a coverage gap can take: the route tests *look* like they cover
sign-in, and the one component that decides whether a token belongs to this flow was never run.

**Fixed:** `apps/api/test/oidc.test.ts`, 13 tests. The nonce suite alone has seven cases — accepts the
right nonce; refuses a different one; refuses none; refuses a non-string; refuses a missing token;
refuses five kinds of malformed token without throwing; and refuses an empty expected nonce against a
non-matching token. Plus `buildAuthorizationUrl` carrying `state` and `nonce` and **not** leaking the
client secret into a browser-visible URL, and live-provider checks for discovery, logout and a refused
exchange.

**Re-run: 4 of 4 caught.**

## 3. `pdp-cedar.ts` — 3 of 4 caught, and the survivor is correct

| Mutation | Result |
|---|---|
| an `allow` alongside evaluation ERRORS is honoured | **caught** |
| a FAILED evaluation grants access | survived |
| an UNREPRESENTABLE request grants access | **caught** |
| EVERY decision becomes Allow | **caught** |

**The survivor is not a blind spot, and that was checked rather than assumed.** Probed against the real
Cedar wasm:

```
missing attr path   type=success  decision=deny  errors=1     ← the errors path, caught
type mismatch       type=success  decision=deny  errors=1     ← same
no permit           type=success  decision=deny  errors=0
```

**`isAuthorized` does not return non-success for realistic input** — it returns `success` with the
failure in `diagnostics.errors`, which the first mutation proves is guarded. The non-success branch
guards wasm failure or corruption: **fail-closed defence in depth, unreachable through input.**

---

## What this round says about the suites

Two modules out of three had **mutations that survived while a real security property was broken.**
Neither was a broken test — both were tests that stopped short of the interesting case:

- the CSRF tests stopped at the length check
- the console tests stopped at the stub boundary

**A suite can be green, thorough-looking, and still never execute the line that matters.** The only
way to know is to break the line and watch.

## Next round

`jwks.ts` (cache and rotation) and the object-storage adapters have no recorded mutation results.
`server.ts` and `policies` have documented survivors that are already explained.
