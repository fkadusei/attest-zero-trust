# S1b — does a real proxy chain preserve the `DPoP` header?

**Answered for Cloudflare: yes. Both cases return `200`.**

| Case | Path | Result |
|---|---|---|
| Control | direct to `localhost:3000`, no proxy | **`200`** — proof arrived, request authorised |
| Test | `https://attest.210security.com` through Cloudflare's edge | **`200`** — proof arrived, request authorised |

The Cloudflare run carried `cf-ray` and `cf-cache-status`, so it genuinely traversed the edge rather than
being served locally.

**What this does and does not settle.** S1b was written as *"does the `DPoP` header survive
CloudFront → ALB → API Gateway"*. That chain needs AWS and **this does not answer it.** What it answers
is the question underneath: whether a real CDN/WAF in the path forwards an unfamiliar request header
and an unusual authorization scheme. Cloudflare is exactly that class of hop, and it does.

---

## The control is the whole story here

**The first run failed, and it would have produced a completely wrong conclusion.**

```
through Cloudflare → 401, reason: "malformed"
```

The obvious reading — and the one I was about to write down — is *"Cloudflare mangles the `DPoP`
header."* It is wrong.

**The control failed identically:**

```
direct, no proxy   → 401, reason: "malformed"
```

Same token, same proof, **no proxy in the path**, same failure. The proxy was never involved.

**Without the control, this slice would have ended with a confident, plausible, false finding about
Cloudflare** — and it would have gone into the register as verified.

## What the failure actually was, and why it took three attempts

The log said `{"reason":"malformed"}` and nothing else. `malformed` in this verifier covers an
undecodable header, a missing `sub`, a missing `exp`, an unclassifiable JOSE error, and an unexpected
claim. **The category is not actionable.**

Three attempts to find out:

1. **Read the verifier's source and guessed.** First guess wrong.
2. **Call `jwtVerify` directly** — got `unexpected "typ" JWT header value`. That was **my test
   script's fault**: it passed `typ: 'Bearer'`, and Keycloak sets the *header* `typ` to `"JWT"` for
   access and ID tokens alike. The API does not pass `typ` at all.
3. **Improved the API's logging** to record the verifier's message alongside the reason. One run then
   said exactly what was wrong:

```
detail: malformed: DPoP proof is missing the ath claim required for a resource request
```

**The probe was not binding the proof to the token.** RFC 9449 requires `ath` on a resource request,
the API correctly demanded it, and every failure above was that — a bug in the probe being read as a
bug in the infrastructure.

### Fixed, permanently

`reject()` now takes a `detail` and the two verifier call sites pass the error's message. The
**response body is unchanged** — still opaque, still `{"error":"unauthorized"}` — because
distinguishing reasons *for an attacker* is an oracle telling them which part of a forgery to fix
next. The detail goes to the log, which is where an operator can act on it.

Three rounds were spent because a log recorded a category and not a cause. The same rule this project
keeps relearning, from a different angle:

> **Assert — and log — the CAUSE of a refusal, never just its category.**
