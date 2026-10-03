# Spike #1 Results — DPoP token binding

**Status: RESOLVED for the local half.** The binding is real, it is enforced, and the verification
logic our API must implement has been prototyped and tested. Run against Keycloak **26.8.0**.

The remaining half — whether the `DPoP` header survives CloudFront → ALB → API Gateway — needs
deployed infrastructure and is still open.

---

## 1. The question

The plan asserts that a stolen session token is useless because it is bound to a key the thief does
not have. That claim has two halves, and they fail differently:

1. **Is the binding real?** Does Keycloak actually write the key thumbprint into the token, and does a
   resource server actually refuse a bound token that arrives without a valid proof?
2. **Can we implement the check?** Keycloak verifies the proof when it *issues* a token, but it is not
   in the request path for our API. So our API must verify the proof itself. That is the one piece of
   genuinely custom security code in the system.

Only the second is our code, and it is the one worth prototyping before building around it.

## 2. Method

No browser and no passkeys are needed, which makes this spike much cheaper than #3. A password grant
against a public client with `dpop.bound.access.tokens` enabled exercises exactly the same DPoP
machinery.

Proofs are generated in Python with a real P-256 key: a `dpop+jwt` header carrying the public JWK, a
payload of `jti`/`htm`/`htu`/`iat` (plus `ath` where required), and an ES256 signature in raw `r||s`
form as JWS expects.

Keycloak's own **userinfo** endpoint is used as the reference resource server. Keycloak 26.4+ applies
DPoP to every endpoint accepting a bearer token, which gives us a known-correct implementation to
test against before writing our own.

## 3. Results

### Issuance — the binding is real

```
cnf claim in token : {'jkt': 'EWxxlBSTXQakwn7Pd03fduq28c-cfrFMXtFtqo8LyJI', 'kc-jkt-type': 'DPoP'}
matches our key    : YES
```

The token carries `cnf.jkt`, the RFC 7638 thumbprint of the client's public key. Keycloak adds a
non-standard `kc-jkt-type: DPoP` marker alongside it.

### Enforcement — Keycloak as resource server

| # | Behaviour | Result | Verdict |
|---|---|---|---|
| 1 | Token presented with **no proof at all** | HTTP 401 | Correct |
| 2 | Bound token sent under the **`Bearer`** scheme | HTTP 401 | Correct |
| 3 | Token with a **valid proof** | **HTTP 200** | Correct |
| 4 | Proof signed by a **different key** | HTTP 401 | Correct |
| 5 | Proof whose `htu` names a **different path** | HTTP 401 | Correct |
| 6 | **Replayed** proof (same `jti`) | HTTP 401 | Correct |

**6/6.** A bound token without a matching proof is genuinely inert, and replay is refused.

### Our verifier — the code we would actually ship

A minimal implementation of the checks a Lambda authorizer must perform:

| Behaviour | Result |
|---|---|
| Valid proof accepted | Correct |
| Proof from another key refused (`cnf.jkt` mismatch) | Correct |
| Wrong HTTP method refused | Correct |
| Wrong URL refused | Correct |
| Proof with no `ath` refused | Correct |
| Proof minted for a **different token** refused | Correct |

**6/6.** The authorizer is implementable, and the logic is now proven rather than assumed.

## 4. The findings that matter

Three of these would have cost real debugging time in production, and one of them changes the design.

### (a) A bound token must use the `DPoP` authorization scheme, not `Bearer`

Sending the correct token with a correct proof under `Bearer` returns **401**, and the challenge
`WWW-Authenticate` header even says `Bearer` — pointing the investigation at the wrong layer. RFC 9449
requires the `DPoP` scheme for a sender-constrained token, and Keycloak enforces it.

**Consequence for us:** the DPoP Verifying Authorizer must accept — and arguably require — the `DPoP`
scheme. A client that falls back to `Bearer` must be rejected outright, not quietly downgraded. This
is a legitimate place to be strict, because an unbound token is exactly what the control exists to
prevent.

### (b) A resource-server proof MUST carry the `ath` claim

The first working attempt failed with `error="invalid_token"`, `error_description="Token verification
failed"` — a message that reads like a signature or audience problem and mentions DPoP nowhere.

The cause: RFC 9449 requires a proof for a *resource* request to include `ath`, the base64url SHA-256
of the access token. A proof for a *token* request omits it (and ours did — correctly, for issuance).
Adding `ath` produced HTTP 200 immediately.

**Consequence for us:** this is a mandatory check in our authorizer, and verifying `ath` also closes a
real gap — without it, a proof minted for one token would authorise a different one. Our test suite now
covers both: an absent `ath` and an `ath` for a different token are both refused.

### (c) Keycloak ignores the query string when comparing `htu` *(observation)*

A proof minted for `…/userinfo?decoy=1` and presented to `…/userinfo` was **accepted** (HTTP 200). The
same proof with a different *path* was correctly refused (HTTP 401).

So `htu` is enforced at path level but not query level.

**Consequence for us:** this is not a vulnerability in itself — `jti` replay protection and the `ath`
binding still hold — but it means the query string is not covered by the proof's URL binding. Our own
authorizer compares the **full** URI including the query, which is stricter than the reference
implementation, and deliberately so. This is recorded as an observation rather than a pass/fail.

### (d) The `DPoP-Nonce` challenge was never triggered

The harness implements nonce handling (retry on a `DPoP-Nonce` header), but no nonce was ever
demanded for these endpoints in this configuration. **Nonce behaviour is therefore untested**, and
the authorizer should not assume either way. It is a small, contained thing to establish later.

## 5. What this changes in the design

Nothing structural — and that is the good outcome. The design assumed Keycloak binds tokens and that
our API must verify proofs; both are confirmed. Three implementation details are now pinned:

1. The authorizer must require the **`DPoP`** authorization scheme and reject `Bearer`.
2. It must verify the **`ath`** claim against the presented access token.
3. It should compare `htu` including the query string, being stricter than Keycloak.

The prototype in `lab/keycloak/scripts/dpop_spike.py` is a working reference for the Phase 2
implementation, including the proof-construction side that clients need.

## 6. What this did NOT prove

- **Header survival.** Whether the `DPoP` header survives CloudFront → ALB → API Gateway is
  **untested**. A hop that strips it breaks the binding silently, and the tempting "fix" would be to
  disable verification — precisely the trap this spike exists to prevent. This needs infrastructure.
- **Browser-side key handling.** That a real browser can generate a non-extractable key, persist it in
  IndexedDB, and sign proofs across restarts remains unverified (Spike #4). Everything here used a
  Python key, which is a stronger position than a browser has.
- **Nonce behaviour**, as noted above.
- **The token request path with a real passkey ceremony.** A password grant was used deliberately to
  isolate DPoP; the two mechanisms are independent, but they have not been exercised together.

## 7. Reproducing

```bash
cd lab/keycloak
docker compose up -d
../../.venv/bin/python scripts/dpop_spike.py
```

The script creates its own client and test user, applies the policies, and asserts persistence before
testing, so it is safe to re-run.
