# SESSION — a redirect loop caused by a missing client in a realm

**Found and fixed. The console's passkey sign-in now completes end to end: 18/18.**

The bug was not in the session code, not in WebAuthn, and not in the origin. It was a **client that
did not exist in the realm**, and the mapper that needed it **fails silently**.

---

## 1. The symptom, and what it actually was

The browser looped:

```
ERR_TOO_MANY_REDIRECTS — localhost redirected you too many times
```

The console's own log made the loop visible — every cycle identical:

```
GET /console/login     → 302
GET /console/callback  → 302        ← the callback SUCCEEDS
GET /console           → GET /v1/evidence → 401
"request rejected"     → 302        ← session destroyed, back to login
```

**14 × 401 in one run.** And the reason, from the API's own log:

```json
{ "reason": "wrong_audience", "msg": "request rejected" }
```

## 2. The chain

```
attest-api client MISSING from the realm
  → the oidc-audience-mapper on attest-console resolves to NOTHING (silently)
  → the access token carries no `aud: attest-api`
  → the API CORRECTLY rejects it: wrong_audience (401)
  → the console treats a 401 as "this session is dead": destroys it, redirects to login
  → Keycloak still holds an SSO session, so it re-authenticates INSTANTLY
  → the callback issues a fresh token, with the same missing audience
  → ERR_TOO_MANY_REDIRECTS
```

**Every step is correct except the first.** Not one of these components is misbehaving: the API is
right to reject a token with the wrong audience, and the console is right to treat a 401 as a dead
session. The system is behaving as designed, around a hole.

## 3. Why it looked like something else entirely

**It happens after a passkey sign-in**, so it looked like a WebAuthn failure. It is not.

**It only failed in some realms.** `attest-api-test` had the client; `attest-privileged` and
`attest-users` did not. That single difference was the whole bug, and it is why the same console
passed 17/17 on one realm and looped forever on another.

**The mapper fails silently.** No warning, no error, no log line. A mapper pointing at a client that
does not exist simply adds nothing — so checking "is the mapper configured?" would have passed while
every single token was still being rejected.

## 4. The fix

`configure-realms.py` now creates the `attest-api` client (`bearerOnly`, so it exists to be an
audience and cannot start a login flow) **before** the console client, in every realm.

And it **asserts the audience actually resolves**:

```
verify_audience_resolves()
```

because the mapper being present is not evidence that it does anything. The check requires **both**
halves — the mapper exists **and** its target client exists — and names which is missing.

**Negative-tested:** with `attest-api` deleted, it returns `False` and prints

> `attest-api client does not exist in this realm, so the mapper adds NOTHING and every token is rejected as wrong_audience`

With it restored, `True`.

## 5. Verified

```
Console end to end: 18/18 behaved as expected
```

Including every check that had never passed on the passkey path: the callback completing, the console
rendering, the session cookie being held by the browser, surviving a fresh navigation, and sign-out
ending the session.

## 6. The lesson

**A silent misconfiguration produces a symptom that describes the wrong subsystem.** Nothing in the
browser's message, the console's log, or the API's response says "a client is missing from a realm".
Each component reported its own correct behaviour, and the fault was an absence.

This is the third diagnosis in this project that had to be withdrawn. The standing rules that would
have caught it faster, all already written down and all violated at least once:

1. **A symptom recorded without the state that produced it is not reproducible.** The earlier
   `webauthn-error-user-not-found` was never reconciled; it stopped appearing and the loop replaced it.
2. **Assert the CAUSE of a refusal, never just its absence.** `wrong_audience` was in the log from the
   first failing run. Reading it immediately would have ended this in one round.
3. **A false-positive control is not a control.** "The mapper is configured" would have passed on a
   system where nothing worked.
