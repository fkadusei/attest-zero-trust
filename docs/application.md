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
| Cedar authorization (L4) | ✅ **Implemented.** Policies in `policies/attest.cedar`, evaluated in-process |
| Persistence | ✅ **PostgreSQL adapter with Row-Level Security**, plus a portable in-memory default |
| Object storage | ✅ **Three adapters — in-memory, filesystem, and S3-compatible** — all passing one contract |
| Customer-facing features | ❌ None |

**The API surface today:**

| Route | Purpose |
|---|---|
| `GET /health` | Unauthenticated liveness |
| `GET /v1/session` | Authentication only — reports what was verified |
| `GET /v1/evidence` | **Authorized** list, scoped to the caller's tenant |
| `GET /v1/evidence/:id` | **Authorized** read, scoped to the caller's tenant |
| `GET /v1/evidence/:id/content` | **Authorized** artifact download, digest verified against the record |
| `PUT /v1/evidence/:id/content` | **Authorized** artifact upload, requires the `writer` role |

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

**171 tests** across eight files, all passing (4 skipped, with stated reasons).

| File | Tests | What it covers |
|---|---|---|
| `verify.test.ts` | 28 | L1, against real tokens from the running Keycloak |
| `dpop.test.ts` | 26 | L2, against real DPoP-bound tokens |
| `server.test.ts` | 22 | End-to-end HTTP: request path, schemes, opacity, ADR-006, tenant isolation |
| `postgres.test.ts` | 10 | The RLS boundary, with a superuser negative control and a connection-reuse check |
| `object-storage.test.ts` | 32 | **All three adapters** against one contract: tenancy, traversal, integrity |
| `pdp.test.ts` | 16 | The PDP adapter: decisions, fail-closed behaviour, allow-with-errors |
| `policies.test.ts` | 12 | The policy file evaluated directly, against hand-built entities |
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

**Mutation-tested, including the policies themselves.** Removing the tenant `forbid` entirely,
inverting it, dropping the principal-type constraint, removing the writer-role requirement, and
widening a permit to any tenant are **all caught**. One rule survives its own removal — the `forbid`
guarding a resource with no `tenant` attribute — and that is **correct**: every permit already
requires the attribute, so the rule is unreachable and removing it changes no outcome. It is a
**safety net for a future careless permit**, and a dedicated test simulates exactly that: a
deliberately loose permit is added, and the net catches what it lets through, with a control proving
the net is what did the work.

**Mutation-tested against the database too.** Disabling Row-Level Security, dropping the policy,
making the application role a superuser, changing the policy to `USING (true)`, and removing `FORCE`
are **all caught**. One of those is weaker evidence than the others and is recorded as such: removing
`FORCE` is caught by a **configuration assertion**, not by an observed leak, because the application
role is not the table owner today. It guards a future where it is.

**Mutation-tested, and it found a worthless test.** Removing either traversal defence alone leaves
the suite green — each catches what the other misses — but removing **both** now fails, which is the
question that matters. Before the test was rewritten, removing both left it **green**: traversal
genuinely leaked a planted secret and deleted a file outside the tenant directory while the suite
reported success.

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

## 8. L4 — authorization

Authentication answers *who is calling*. Authorization answers *what they may touch*. Keeping those
apart is what stops "authenticated" being mistaken for "allowed".

**The policies are a portable file**, `policies/attest.cedar`, evaluated in-process by `cedar-wasm`.
The same text would go to Amazon Verified Permissions unchanged — the language is portable, the
service is not (ADR-015).

**The structure rests on Cedar's default deny.** Permits are deliberately narrow, so forgetting to
write one produces a denial rather than an opening. Two ways a request can wrongly succeed need two
different defences:

1. **A request matches a permit it should not.** Defended by making every permit require tenant
   equality, so there is no permit to match.
2. **An attribute is missing**, so a condition silently does not fire. `principal.tenant !=
   resource.tenant` is **not** a safe test if either attribute is absent. The tenant boundary is
   therefore a **`forbid`**, which no permit can override — including one added later by someone who
   has not read the file.

**A finding worth recording.** A permit that does not constrain the **principal type** grants access
to *any* entity carrying a matching `tenant` attribute — including one introduced later by an
unrelated feature. A test caught this: a principal of type `MysteryActor` was **allowed**. Every
permit now names the kinds of principal it applies to, so a new entity kind is denied until someone
deliberately permits it.

**Two independent tenant layers guard every evidence route**, and they are deliberately different
kinds of control:

- the **repository** looks records up inside the caller's own tenant — another tenant's record is
  never in scope, rather than filtered out afterwards
- the **policy** would refuse the pair even if the record were handed to it

Either alone would do. Both is what ADR-006 asks for, and it means a bug in one is caught by the
other.

**A missing record and another tenant's record are indistinguishable** — both `404` with the same
body. Otherwise the endpoint is an existence oracle: enumerate ids and learn which ones other tenants
hold. A test asserts the two responses are byte-identical.

## 9. L5 — the tenant boundary, enforced by the database

The in-memory repository enforces tenancy in **application code**: a bug in that file could return
another tenant's rows. The PostgreSQL adapter moves the rule into the **engine**.

`evidence` has Row-Level Security **enabled and forced**, with a policy comparing `tenant_id` against
`app.current_tenant`. A query that forgets its tenant filter — or one written next year by someone who
has not read the file — returns nothing it should not, because the database removes those rows before
the query sees them. That is verified, not assumed:

```
attest_app, tenant=acme, SELECT with NO WHERE clause  →  e-acme             (one row)
superuser,   the same unscoped statement              →  e-acme, e-globex   (both rows)
```

**The difference is the role, and that is the trap this avoids.** Row-Level Security is bypassed by
**superusers, always**, and by the **table owner** unless `FORCE` is set. An application connecting as
either gets *no row-level security at all, silently*: every query succeeds, every test passes, and the
boundary is simply absent. So the schema creates a dedicated **non-superuser, non-owner** role, marks
the table `FORCE`, and the test suite keeps a **superuser connection on purpose** as the control that
proves the policy is doing the work.

**The application database is separate from the Keycloak database** — different data, different blast
radius. Evidence for customers should not share a database with the identity provider that
authenticates them. (It also turned out that port 5432 on the development host belongs to an unrelated
project, so publishing there would have connected these tests to the wrong database.)

**Three details in the adapter are load-bearing:**

1. **A dedicated client per operation.** A `SET` issued through a pool could land on a different
   connection from the query it was meant to scope.
2. **`SET LOCAL`, not `SET`.** Transaction-scoped, so it reverts. A plain `SET` would persist on a
   pooled connection and leak the tenant to whichever request picked it up next — a cross-tenant read
   caused by connection reuse. A test interleaves two tenants across a two-connection pool to prove it
   cannot happen.
3. **An unset tenant matches nothing.** `current_setting(..., true)` returns NULL when unset, and
   `tenant_id = NULL` is never true. A connection with no tenant sees no rows at all — **fail closed**.

## 10. L6 — evidence artifacts

Bytes now have somewhere to live, reached through the same authorized path as the metadata.

**Three adapters, one contract.** In-memory (the default, for tests and a laptop), filesystem, and
**S3-compatible**. All three are run against the *same* contract suite, which is the evidence that
ADR-015's promise is real: **the domain did not change when the storage backend did.**

The S3 adapter speaks to any S3-compatible endpoint — AWS S3, MinIO, Cloudflare R2, GCS
interoperability mode, Ceph — so the endpoint is configured rather than assumed. Tests run it against
`adobe/s3mock`, so the code path exercised is a genuine signed request to an S3 API.

> **MinIO was the first choice and is not used.** MinIO removed its Docker Hub images in 2025 and moved
> to quay.io, which the registry proxy on this machine refuses with `401`. Checked, not assumed —
> three other S3-compatible images were tested and `adobe/s3mock` was the one that worked.

**The digest recorded on the evidence comes from the bytes the storage actually holds**, computed by
the adapter — never from a value the caller supplied. A caller-supplied hash would let someone attest
to content they never uploaded. On download the stored bytes are re-hashed and compared to the
record, so a disagreement between storage and the database is reported rather than papered over.

**No signed URLs, deliberately.** A pre-signed URL is a bearer capability that outlives the
authorization decision that produced it. Reads go through the API so the policy is re-evaluated on
every request.

**Path traversal is the vulnerability this adapter exists to avoid**, and it is guarded three times
over:

1. the tenant directory name is **percent-encoded**, so a tenant id containing `../..` becomes one
   path segment rather than three traversals
2. the ref is validated against a **strict allowlist** before it is used as a path
3. the **resolved path is checked for containment** in the tenant directory — the backstop that holds
   however a traversal was spelled

> **A test defect worth recording.** The first traversal test asked for `/etc/passwd` and got
> `undefined`, which looked like a refusal. It was not: the adapter also reads a `.meta` sidecar,
> which does not exist for `/etc/passwd`, so the read failed for an unrelated reason. **Mutation
> testing exposed it** — removing both traversal defences left the suite green. The test now plants a
> victim *inside* the storage root but *outside* the tenant directory, **with a valid sidecar**, so
> nothing but the traversal defence stands between the caller and the bytes. With both defences
> removed it now fails, as it should.

## 11. What is not built

Stated plainly, because this list is as useful as the rest of the page:

- **The admin console.** The domain has a working API and no product surface. This is the largest
  remaining gap between "verified system" and "usable product".
- **No migrations tooling.** The schema is a container init script, which is fine for a lab and is not
  how schema changes should be managed in production.
- **Four routes.** Still no product surface a customer would recognise.
- **No persistence or storage.** Interfaces only.
- **No admin console, no API surface, no customer-facing feature.**
- **No deployment.** Running locally costs nothing; nothing is hosted anywhere.
- **Three ports are declarations**, not working components.

---

## 12. Extending it

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
