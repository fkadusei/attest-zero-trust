# origin-diff — the passkey works, and the bug is somewhere else

**The passkey was never the problem.**

This slice set out to find what about the `localhost` origin caused the passkey sign-in to fail.
It did not find that, because **there is no such thing**. The passkey works on localhost. It works
on a real hostname. It worked in every configuration tested.

**The console has a different bug**, and it was hiding behind a misdiagnosis.

---

## 1. The passkey works everywhere it was tried

Measured with a fresh virtual authenticator per case, so no case could be helped by another's
credential. The user handle is shown because it was once misread as absent:

| Case | Origin | RP ID | extraOrigins | scope | Outcome |
|---|---|---|---|---|---|
| A | `http://localhost:8080` | `localhost` | `[]` | `openid` | **AUTHENTICATED** |
| B | `http://localhost:8080` | `localhost` | `["http://localhost:3000"]` | `openid` | **AUTHENTICATED** |
| C | `https://id.210security.com` | `id.210security.com` | `[]` | `openid` | **AUTHENTICATED** |
| D | `http://localhost:8080` | `localhost` | `[]` | `openid` | **AUTHENTICATED** |
| E | `http://localhost:8080` | `localhost` | `[]` | `openid profile email` | **AUTHENTICATED** |

Every case registered a resident credential and produced a correct user handle.

**And with the very user the console end-to-end harness uses** — `console-e2e` — localhost still
authenticated. So it is not the user either.

### Every candidate, and its verdict

| Candidate | Verdict | How it was tested |
|---|---|---|
| the origin / scheme | **ruled out** | http and https both authenticate |
| the relying-party ID width | **ruled out** | one label (`localhost`) and three (`id.…`) both work |
| `extraOrigins` | **ruled out** | empty and populated both work (A vs B) |
| the OAuth `scope` | **ruled out** | `openid` and `openid profile email` both work (D vs E) |
| the OIDC client | **ruled out** | both clients authenticate (E2E-3) |
| the user | **ruled out** | the failing harness's own user authenticates here |
| the credential / user handle | **ruled out** | present, resident, and correctly encoded in every case |

---

## 2. What the console actually does

Re-run unchanged, the console end-to-end harness now fails with:

```
ERR_TOO_MANY_REDIRECTS
This page isn't working — localhost redirected you too many times.
```

and the passkey ceremony **succeeds** on the way:

```
authenticator holds: resident=true userHandle="Y2E1NTg2ZDgtN2NmMy00YTQxLTg5MWMtZWU5OTZkMzdlNDM4"
the provider offers the passkey ceremony    PASS
```

The browser is redirected to `/console/callback` and then **bounces between `/console` and the
provider**. The console's session cookie is not surviving the round trip, so every visit to
`/console` looks unauthenticated and starts a new sign-in.

**So the real defect is in the console's session handling, not in WebAuthn at all.**

### What has already been checked and is NOT the cause

- **The flow cookie is correct.** `attest_flow` is set with `Max-Age=600; Path=/console; HttpOnly;
  SameSite=Lax` and **no `Secure`**, so a browser on `http://localhost` will keep it.
- **The callback does not redirect on failure.** Every rejection path in `/console/callback`
  returns a 400 page, so a *failing* callback cannot produce a loop. The loop must therefore be a
  *successful* callback whose session does not stick.
- **The redirect chain is otherwise clean:** `/console` → 302 → `/console/login` → 302 → Keycloak,
  with the flow cookie set correctly on the way.

---

## 3. An honest note on the original diagnosis

For several rounds this project recorded that **"the console's passkey sign-in does not work"**, with
`webauthn-error-user-not-found` as the symptom. **That symptom no longer reproduces.**

What changed in between is not one thing: Keycloak was recreated several times, the credential store
was cleared repeatedly, the realm policy was rewritten many times, and the harness gained a fix that
clears credentials before registering. **The most likely reading is that the original error was an
artefact of stale realm or credential state, and the enduring bug is this redirect loop.**

**That is stated as the most likely reading, not as a finding**, because it was not isolated. What
is a finding is that the passkey ceremony itself works, measured five ways, and that the console's
failure has a different shape.

The lesson is the one this project keeps relearning: **a symptom recorded without the state that
produced it is not reproducible, and an unreproducible symptom is a bad thing to build a theory on.**

---

## 4. What is still open

- **Why the console's session does not survive.** This is the actual defect. It is now precisely
  characterised — a successful callback whose cookie does not stick — and is a much smaller question
  than "passkeys do not work".
- **Whether `origin-diff` case E proves scope is irrelevant in general**, or only for this realm.
- ~~The console end-to-end harness still has to be run to completion against both origins.~~
  **RESOLVED.** The loop was a missing `attest-api` client, and the suite now passes **18/18 on
  localhost and 17/17 on the real origin** — see [SESSION-RESULTS](lab-results-session.html) and
  §9 of [CONSOLE-E2E-RESULTS](lab-results-console-e2e.html). It passes on the passkey path for the
  first time.

---

## 5. Reproducing

```bash
# Both origins must resolve correctly at once. The overlay sets ONLY proxy headers —
# pinning KC_HOSTNAME makes localhost report the public issuer and breaks the comparison.
docker compose --env-file lab/.env \
  -f lab/keycloak/compose.yaml \
  -f lab/keycloak/compose.tunnel.yaml up -d keycloak

# the differential probe: five cases, fresh authenticator each
node lab/browser/origin-diff.mjs

# and with the console harness's own user
E2E_USER=console-e2e E2E_PASSWORD='...' node lab/browser/origin-diff.mjs

# the console end-to-end, which now fails on the redirect loop rather than the passkey
E2E_REALM=attest-privileged E2E_PASSKEY_ONLY=1 node lab/browser/console-e2e.mjs
```
