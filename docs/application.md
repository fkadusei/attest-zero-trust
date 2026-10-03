# The application

What has actually been built, what it enforces, and — just as importantly — **what does not exist yet**.

This page is about the code in `apps/`, as distinct from the design in
[Architecture and plan](PLAN.md) and the experiments in the lab results. Those describe what we
intended and what we verified. This describes what is running.

---

## 1. Status: read this first

**The API is a running service.** It can be started, it listens, and requests to it are verified
end to end. It is not a complete product.

| | Status |
|---|---|
| Token verification (L1) | ✅ Implemented, tested against real Keycloak |
| DPoP proof verification (L2) | ✅ Implemented, tested against real bound tokens |
| Configuration | ✅ Implemented and validated |
| **An HTTP server** | ✅ **Implemented.** `src/server.ts`, entry point `src/index.ts` |
| **Wiring L1 + L2 into a request path** | ✅ **Implemented.** Every protected route runs the chain |
| **End-to-end HTTP tests** | ✅ **17 of them**, through the real request path |
| Cedar authorization (L3) | ❌ Not started — the port is declared, nothing implements it |
| Persistence, object storage | ❌ Interfaces only — no implementation |
| Customer-facing features | ❌ None |

**The API surface today is two routes:** `GET /health`, unauthenticated, and `GET /v1/session`,
which runs the full verification chain and reports what was verified.

**One finding is worth reading before anything else**, because it is the reason the end-to-end tests
exist at all. Keycloak issues DPoP-bound access tokens with a **different payload `typ`** than
ordinary ones:

| Token | payload `typ` |
|---|---|
| ordinary access token | `"Bearer"` |
| **DPoP-bound access token** | **`"DPoP"`** |
| ID token | `"ID"` |

An earlier version of `verify.ts` accepted only `"Bearer"`. **It would therefore have rejected every
DPoP-bound token — the entire feature — while passing all 70 unit tests**, because no unit test
verified a *bound* token through L1. The end-to-end HTTP test found it in its first run. Both
access-token types are now accepted; `"ID"` is still refused, which is the check's purpose.

---

## 2. How it is structured

The layout follows [ADR-015](decisions.md) — ports and adapters. The rule is simple: **the domain
does not know which cloud it runs on, or whether it runs on one at all.**

```
apps/api/src/
├── config.ts          environment-driven configuration, validated at startup
├── errors.ts          failure reasons — internal only, never returned to a caller
├── verify.ts          L1: access token verification
├── dpop.ts            L2: DPoP proof verification
├── jwks.ts            the provider's signing keys, cached and rotated
└── ports/             what the domain needs, declared but not implemented
    ├── clock.ts           time, injectable so tests can control it
    ├── policy.ts          the policy decision point (Cedar)
    ├── repository.ts      persistence, tenant-scoped by construction
    ├── object-storage.ts  evidence artifacts
    └── replay-cache.ts    single-use claim tracking
```

`ports/` holds **interfaces**. `replay-cache.ts` and `clock.ts` also ship working implementations for
single-process use; `policy.ts`, `repository.ts` and `object-storage.ts` are declarations only, with
no implementation and no test. They are included because the boundaries are worth fixing before
anything is written against them — not because they do something.

---

## 3. L1 — verifying an access token

`verify.ts`. Answers: *was this token issued by our identity provider, for this API, and is it
intact?*

Every check exists because the loose version is exploitable:

| Check | Why it is there |
|---|---|
| **Algorithm allowlist** | The token's own `alg` header is never trusted to decide what is acceptable. Honouring it accepts `none`, or an HMAC signature computed using the public key as the secret. Both are old, both still ship. |
| **Exact issuer match** | Not a prefix or substring. A `startsWith` check on an issuer is a bypass waiting for a cleverly-named host. |
| **Audience** | The token must have been issued for *this* API, not merely by our provider. |
| **Token type, in the payload** | Keycloak marks access tokens `typ: "Bearer"` and ID tokens `typ: "ID"` **in the payload claim**. The JOSE *header* `typ` is `"JWT"` for both, so checking the header cannot distinguish them — see below. |
| **`sub` and `exp` present** | A token without them is malformed and is refused. |
| **Fail closed** | There is no boolean return and no warning branch. Verified, or throws. |

**A finding worth reading.** The first version of this file checked the header's `typ` and expected
`"Bearer"`. Measured against the live provider, Keycloak does this:

| | header `typ` | payload `typ` |
|---|---|---|
| access token | `"JWT"` | `"Bearer"` |
| ID token | `"JWT"` | `"ID"` |

The header is identical for both. **The tempting fix — expect `"JWT"` — would have made the test pass
while the check protected nothing.** Only the payload claim distinguishes the two, and it can be
trusted only *after* the signature verifies. This is why the test suite asserts the **reason** for
every rejection rather than settling for "it failed": a reason assertion caught it, an exit-code
assertion would have hidden it.

**The tenant rule.** `requireTenant(token, claimName)` reads the tenant from verified claims and
nowhere else — never a header, path segment, query parameter or body field. A missing claim is a hard
failure. There is no default tenant, because a defaulted tenant is how one customer's request reads
another customer's data ([ADR-006](decisions.md)).

---

## 4. L2 — verifying a DPoP proof

`dpop.ts`. Answers a different question: *does this caller actually hold the private key the token is
bound to?*

An access token is a **bearer** credential — whoever holds the bytes can use it. DPoP
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)) binds the token to a key pair the client
generates and never transmits. The provider records the public key's fingerprint in the token as
`cnf.jkt`, and every request must carry a proof signed by the matching private key.

| Check | Why it is there |
|---|---|
| `typ` is `dpop+jwt` | Otherwise a token-endpoint artifact can be replayed as a proof. |
| **Asymmetric algorithms only** | The proof **embeds its own public key**. Accepting `HS256` would let anyone sign using that public key as the shared secret — an attack DPoP's own design makes possible. |
| **No private key material** | An honest client never sends a private member. Its presence is refused. |
| Signature, before any claim is read | Nothing inside an unverified payload is trusted. |
| `htm` and `htu` | A proof captured for one endpoint cannot be re-aimed at another. `htu` is compared **without query and fragment**, exactly as the RFC specifies. |
| `iat` within a window | A proof is a one-shot artifact; a long window is a long replay opportunity. |
| **`ath` is mandatory** | Base64url of the SHA-256 of the access token. Without it, a proof for one endpoint works against another with the same token. |
| **The key is the bound key** | The proof key's RFC 7638 thumbprint must equal the token's `cnf.jkt`. **This is what turns a valid signature into a specific credential.** |
| `jti` used exactly once | The only stateful check — and the only thing between a captured proof and a replay. |

**Two things that are easy to get wrong, and are not:**

- **The replay check runs last.** Consuming a `jti` before the other checks lets a malformed proof
  burn an identifier a legitimate request might need. And `consume()` must be **atomic**: a
  check-then-set is a race that two concurrent replays both win.
- **The expected request URI comes from trusted configuration, never from `X-Forwarded-Proto` or
  `Host`.** Deriving it from headers lets the attacker choose the value the proof is compared
  against, which makes every `htu` check vacuous while still appearing to be present.

**What L2 needs that L1 does not:** a place to remember `jti` values. That is the `ReplayCache` port.
The in-memory implementation shipped here is correct for one process and **explicitly wrong for a
fleet** — each replica would keep its own map, and a proof replayed to a different replica would look
fresh. Swapping it is a deployment decision, not a code change.

---

## 5. Configuration

Everything comes from the environment and is validated at startup. Reading it makes no network calls
and contacts no metadata service, so the same image boots anywhere.

| Variable | Required | Notes |
|---|---|---|
| `KEYCLOAK_ISSUER` | yes | Exact expected `iss`. |
| `API_AUDIENCE` | yes | This API's client id. |
| `KEYCLOAK_JWKS_URI` | no | Derived from the issuer. Overridable only for split-horizon DNS. |
| `TENANT_CLAIM` | no | Defaults to `tenant_id`. |
| `CLOCK_TOLERANCE_SEC` | no | Default 5, bounded 0–120. |
| `HTTP_HOST`, `HTTP_PORT` | no | Defaults `0.0.0.0:3000`. |

**There are no cloud-specific variables.** No `AWS_REGION`, no bucket, no table name. Those belong to
adapters, and a test asserts that supplying AWS settings changes nothing.

**One check here is a security control, not a convenience.** A plain-HTTP issuer is refused unless it
is loopback, because off loopback tokens are interceptable in transit and every other control becomes
decorative. `evil-localhost.example.com` is **not** accepted — an `includes()` check there would have
been a bypass.

---

## 6. Testing

```bash
# from the repository root, with the lab running
npm install
npm run typecheck --workspace @attest/api
npm test --workspace @attest/api
```

**91 tests** across four files, all passing:

| File | Tests | What it covers |
|---|---|---|
| `verify.test.ts` | 28 | L1, against real tokens from the running Keycloak |
| `dpop.test.ts` | 26 | L2, against real DPoP-bound tokens |
| `server.test.ts` | 17 | End-to-end HTTP: the request path, scheme handling, opacity, ADR-006 |
| `config.test.ts` | 19 | Configuration, including its three security checks |

### Three habits this suite follows deliberately

**Test against the real provider, not a mock.** A verifier tested against hand-made tokens proves
only that it agrees with our own idea of what a token looks like — and signature verification is
precisely where that assumption is wrong. The suite obtains genuine tokens, and for L2 a genuine
`cnf.jkt`-bound token, from a live Keycloak.

**Assert the reason, not just the failure.** "It threw" is satisfied by a verifier that throws at
everything, including the valid token in the positive control. Every rejection is asserted against a
specific reason.

**Mutation-test the suite itself.** A suite is only trustworthy if it goes **red** when the property
breaks. Each enforcement point was removed one at a time: **7 of 7** in `verify.ts`, **13 of 13** in
`dpop.ts`, **6 of 6** in `config.ts` — with the unmutated control green each time. One of these found
a genuine gap: deleting the `sub` check went undetected, because Keycloak always issues one. A
synthetic issuer now mints the shapes Keycloak will not.

**And a caution about reading mutation results.** In `server.ts`, removing the early no-proof check —
and then removing the downgrade guard as well — leaves the suite **green**. That is not a blind spot:
`verifyDpopProof` independently refuses a missing proof, so **the property never broke**. A harness
that only observes green/red cannot tell "the suite is blind" from "another layer compensated", and
will report defence in depth as a defect. **Before calling a surviving mutant a problem, check whether
the property still holds.**

### Two failure modes the suite itself fell into

Recorded because they are instructive, not embarrassing:

- **The first mutation harness reported every mutant as GREEN.** It was not the mutants surviving: a
  `grep` for the summary counts did not match, so the harness measured nothing. Measuring by exit
  code fixed it. A harness that reports success when it did nothing is worse than no harness.
- **The L2 suite originally borrowed its fixtures instead of creating them.** It passed locally only
  because another suite had already created the realm in an earlier session. In CI, files run
  alphabetically, `dpop` went first, and all 22 tests failed with `HTTP 404 "Realm not found"`. A
  suite that passes only because another suite ran first is not passing.

---

## 7. L3 — the service

`server.ts`. Turns the verifiers into a policy **enforcement point**.

The rule that shapes it: **verification happens in one `authenticate` pre-handler, in a fixed order,
before any handler runs.** A handler cannot opt out, forget a step or reorder them, because it never
sees an unverified request. The failure this avoids is an endpoint added later that reads
`request.headers["x-tenant-id"]` and skips the chain. That header does not exist here, and there is
no route that reaches a handler without passing through.

```
1. Authorization parsed      scheme + credentials
2. Token verified            L1 — nothing is trusted before this
3. Binding established       does the token carry cnf.jkt?
4. Scheme checked            a bound token MUST use DPoP, not Bearer
5. Proof verified            L2 — signature, htu, htm, ath, jti, thumbprint
6. Downgrade guard           fail closed if a bound token had no proof
7. Tenant derived            from VERIFIED claims only (ADR-006)
```

**The expected request URI comes from configuration, not from the request.** DPoP's `htu` check
compares the proof against the URI the request was made to. Deriving that from `X-Forwarded-Proto` or
`Host` would let the attacker choose the value their own proof is compared against, making the check
vacuous while still appearing present. `PUBLIC_BASE_URL` is required for exactly this reason.

**Every rejection returns exactly one body:** `{"error":"unauthorized"}`. A response that
distinguishes "bad signature" from "expired" from "wrong audience" is an oracle telling an attacker
which part of a forgery to fix next. The reason is logged for operators; the caller learns only that
it failed. A test asserts the body contains none of those words.

**A bound token without a proof is refused by three independent layers** — an early check, the
downgrade guard, and the proof verifier's own input validation. Mutation testing reports removing the
first two as "surviving mutants", which reads like a blind spot and is not: the property never broke.
The consequence for anyone reading the mutation results is written down in `HANDOFF.md`.

## 8. What is not built

Stated plainly, because this list is as useful as the rest of the page:

- **No Cedar policy evaluation.** The port exists; nothing implements it. Authorization today is
  authentication only: the API proves who you are, it does not yet decide what you may do.
- **Two routes.** No API surface beyond `/health` and `/v1/session`.
- **No persistence or storage.** Interfaces only.
- **No admin console, no API surface, no customer-facing feature.**
- **No deployment.** Running locally costs nothing; nothing is hosted anywhere.
- **Three ports are declarations**, not working components.

---

## 9. Extending it

The pattern is the same for every capability that varies by environment:

1. **Declare the need as a port** in `src/ports/` — an interface, with a contract written as
   obligations rather than a description of methods.
2. **Ship a portable default.** In-memory, local, or filesystem. This is what tests use, and it must
   work on a laptop.
3. **Add cloud adapters separately**, behind the same interface, reading their own configuration.
   Never let a cloud SDK into the domain.

If a cloud concept appears in `src/config.ts`, the boundary has already leaked.

---

**Related:** [Decision register](decisions.md) · [What we tested](verification.md) ·
[Evidence register](evidence.md) · [Architecture and plan](PLAN.md)
