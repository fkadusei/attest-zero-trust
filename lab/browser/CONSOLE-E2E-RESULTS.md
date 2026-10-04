# Console End-to-End Results — a real browser, a real redirect, a real passkey

**Status: 17/17.** The whole console chain is exercised by an actual browser against an actual
Keycloak. Nothing is stubbed except the provider's *redirect dance* in the unit suite — here even that
is real.

**Cost: $0.** No cloud, no deployment, no domain. This is the cheap half of the deployment question,
and it found three things.

---

## 1. What this proves that no unit test could

Every console test in the suite stubs the provider. The flow *logic* is covered; whether a browser can
actually complete the round trip is not. This drives it for real:

```
browser → /console → /console/login → Keycloak → sign-in
        → /console/callback → code exchange → session cookie → /console
```

| Check | Result |
|---|---|
| An unauthenticated visit lands on the provider | **pass** |
| The provider offers its sign-in form | **pass** |
| **The browser is returned to the console** | **pass** |
| **The callback completes and the console renders** | **pass** |
| The session cookie exists in the browser | **pass** |
| It is `HttpOnly` | **pass** |
| It is scoped to `/console` | **pass** |
| Its value is not a JWT | **pass** |
| The session survives a fresh navigation | **pass** |
| The sign-out form is present and submits | **pass** |
| **The session cookie is gone after signing out** | **pass** |
| **Sign-out does not leave the user signed in** | **pass** |

Three of those assert on the **browser's behaviour** rather than a response header: a cookie the
browser stored and sent back, a form the browser submitted, a redirect the browser followed.

---

## 2. Finding: the console was serving HTML as `text/plain`

**This is the one that justifies the whole exercise.**

Fastify does not infer `text/html` for a string payload — it sends `text/plain`. So Chrome rendered the
**escaped source** of every console page inside a `<pre>` instead of rendering the page.

**A unit test did not catch it, and could not have.** The assertion checked that the response body
contained the word "Evidence" — and the escaped source still contains the word "Evidence". The check
passed on a page no human could use.

The browser found it because a browser does not care what the body *says*; it cares what the
`Content-Type` is, and it rendered accordingly. The tell was a `no-form url=/console forms=[]` result:
the string `csrf` was in the page, but no `<form>` element existed — because it was text.

**Fixed:** every page now sets `text/html; charset=utf-8` explicitly, through a single `sendPage`
helper so no route can forget. **15 page sends** were affected.

---

## 3. Finding: "Sign out" did not sign the user out

The console destroyed its own session correctly — the cookie was gone. But the **SSO session at the
provider survived**, so the next visit signed the user straight back in, silently.

Measured before the fix:

```
after logout: url=http://localhost:8080/realms/.../protocol/openid...   (the end-session endpoint)
revisit:      url=http://localhost:3000/console   newSession=yes        ← signed back in
```

The cause is precise and entirely configuration:

```
postLogoutRedirectUris = None   →   Keycloak's end-session endpoint returns HTTP 400
```

**Keycloak refuses the logout unless the post-logout target is registered.** Without it the console's
own session dies and the user *looks* signed out, which on a shared machine is the difference between
safe and not.

Measured after registering `post.logout.redirect.uris`:

```
revisit:      url=http://localhost:8080/realms/.../protocol/openid...   newSession=no
```

**Requirement for any deployment:** the console's client must register
`post.logout.redirect.uris`. There is no way for the console to detect the failure from the server
side — Keycloak returns an error to the browser, which the console never sees.

---

## 4. NOT RESOLVED: passkey sign-in into the console

**The console's passkey sign-in does not work**, and the cause is identified but not fixed.

Against `attest-privileged` with the passkey-only flow, everything works up to and including the
ceremony being offered:

- the provider serves the passkey page (`kc-form-webauthn`) — **pass**
- `#authenticateWebAuthnButton` is found and clicked — **pass**
- the ceremony runs and the assertion is produced — **pass**

Then Keycloak refuses with:

```
Unknown user authenticated by the Passkey.    (webauthn-error-user-not-found)
```

**Cause:** the stored credential has **no `userHandle`**.

```
credential keys   : ['aaguid','attestationStatementFormat','counter','credentialId',
                     'credentialPublicKey','transports']
userHandle present: False
```

Keycloak's passwordless flow is a **discoverable-credential** flow: it identifies the user *from the
user handle*, with no username typed. A credential carrying none can never sign anyone in — and the
realm's policy is correctly configured for it (`ResidentKey = "required"`,
`RequireResidentKey = "Yes"`). So the policy asks for a discoverable credential and the harness's
virtual authenticator is not producing a usable handle.

**What this does and does not mean:**

- It is **not** evidence that passkeys fail. S9 exercises the same realm, the same flow and the same
  virtual-authenticator approach, and its passkey ceremony **succeeds** — through a different client
  and a different origin.
- It **is** an unresolved gap: nobody has yet completed a passkey sign-in **into the console**. The
  console's sign-in is verified with a password path.
- The difference between the working case and this one is worth finding, and it is the next step.

---

## 5. What is still not proven

- **A real domain, real DNS, real TLS.** Everything runs on `localhost` over plain HTTP. That is a
  secure context for WebAuthn, so the ceremony is genuine, but it is not a deployed environment.
- **A real proxy.** No ALB, no CDN, no forwarded headers. The DPoP `htu` question (S1b) is untouched.
- **Multiple processes.** One server, one database, one object store.
- **Restart behaviour.** Sessions and the replay cache are in-memory; nobody has yet restarted the
  service mid-session and watched what happens.

---

## 6. Reproducing

```bash
# the lab, including its application database and S3-compatible store
docker compose -f lab/keycloak/compose.yaml up -d
docker compose -f lab/app/compose.yaml up -d

# a password path, to prove the console chain without the passkey question
E2E_REALM=attest-api-test E2E_PASSKEY_ONLY=0 node lab/browser/console-e2e.mjs    # 17/17

# the passkey path — reaches the ceremony, then fails on the missing user handle
E2E_REALM=attest-privileged E2E_PASSKEY_ONLY=1 node lab/browser/console-e2e.mjs
```

The harness **refuses to run if port 3000 is already occupied**, and proves the server it started is
its own by checking which realm the sign-in redirect points at. Both were added after a stale server
from a previous run silently made the suite measure the wrong configuration.
