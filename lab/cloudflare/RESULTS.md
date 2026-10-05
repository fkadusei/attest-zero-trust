# The real origin — and the answer to the passkey question

**On 2026-10-05 the lab ran on a real domain, under real TLS, through a Cloudflare Tunnel.**

| | |
|---|---|
| Console and API | `https://attest.210security.com` |
| Identity provider | `https://id.210security.com` |
| Tunnel | `attest` — `719e899e-9dcf-432c-a8b7-f6059aee6f17` |
| Certificate | Let's Encrypt, `CN=210security.com`, valid to 2026-12-16 |
| Cost | **$0** — Cloudflare Tunnel is free, nothing was deployed to a cloud |

**This is the first time anything in this project has run anywhere but `localhost`.**

---

## 1. THE ANSWER: the passkey works on a real origin

The question this was meant to settle was whether the console's passkey failure had anything
to do with the **origin**. Everything so far had run on `http://localhost`, where WebAuthn is a
secure context by convention and the origin is not a variable.

Measured against the real hostname, with the same client that fails locally:

```
attest-console (confidential)    registered=1  handles=1  AUTHENTICATED
```

**A passkey registered and signed in successfully at `https://id.210security.com`.**

So the failure is **not** the client, the credential, the user handle, the realm policy, or the
console's code. All of those had already been ruled out individually. **It is specific to the
localhost configuration** — which is a much narrower and more tractable statement than "the
passkey sign-in does not work".

### What this does NOT mean

It does **not** mean "localhost was broken" or "it works in production, so it is fine". The
localhost path is what every test in this repository runs against. A passkey sign-in that fails
there and succeeds elsewhere is still a defect in how the local environment is configured, and
it has not been found yet. What changed is that the search space is now one variable wide.

### The honest summary

**The question was answered, and the answer is that the origin was the cause.** The next step is
to find *what* about the localhost origin differs — not to declare this resolved.

---

## 2. Three real bugs, all found by doing this

### The proxy headers — the step that is always missed

With the hostname forwarded but no proxy settings, Keycloak issued:

```
issuer: http://id.210security.com/realms/master       ← http, not https
```

Cloudflare terminates TLS at its edge and forwards **plain HTTP** to `localhost:8080`. Keycloak
sees `http` and believes it. The OIDC redirect then fails in a way that looks like a
misconfigured **client** rather than a misconfigured **proxy**.

The fix is `KC_PROXY_HEADERS: xforwarded`, and it lives in an overlay file rather than the base
compose file, because:

```
Invalid value for option 'KC_PROXY_HEADERS': .
Expected values are: forwarded, xforwarded
```

**An empty value is invalid**, so it cannot sit in the base file with a `${VAR:-}` default, and
compose cannot omit a key conditionally. `compose.tunnel.yaml` is the only correct answer.

### `post.logout.redirect.uris` uses `##`, not spaces

Keycloak stores this attribute as one string, so multiple URIs need a separator. Every obvious
candidate is wrong:

| Separator | Result |
|---|---|
| space | **HTTP 400** — "A post-logout redirect URI is not a valid URI" |
| newline | **HTTP 400** — same |
| **`##`** | **accepted** |

Every rejection reads as a *malformed URI*, never as a *bad separator*, which is why the wrong
guess is easy to make and hard to read back. Getting it wrong means sign-out appears to work
while the SSO session survives.

### The harness never set the relying-party ID

The first run against the real origin failed with something entirely different from localhost:

```
A security error occurred during the Passkey operation.
Please ensure you are on the correct site and try again.
```

That is a WebAuthn `SecurityError` — an **RP ID / origin mismatch**. The realm's RP ID was still
`localhost` from earlier work, and `localhost` is not a suffix of `id.210security.com`.

The cause was my own edit: I replaced a string that **did not exist in that file** (it was in a
different probe script), the replacement silently did nothing, and **I did not assert it landed**.

> A scripted edit that is not verified is not an edit. This is the second time in this project
> that an unasserted replacement has cost a run.

---

## 3. The security position, stated plainly

**The lab is now publicly reachable, and that is a real change in risk.**

This is not a deployment. It is a lab, exposed deliberately so that WebAuthn could be tested on
a real origin:

- **`start-dev` is not a production mode.** Keycloak says so itself.
- **The admin console is reachable** at `https://id.210security.com/admin`.
- **No rate limiting, no lockout tuning, no brute-force protection.**
- **The hostname says what it is** — `id.210security.com` is discoverable and descriptive.
- The credentials are generated and gitignored, but they are still lab credentials protecting
  nothing.

**If it stays up, put Cloudflare Access in front of it.** That is a few clicks in the Zero Trust
dashboard and removes the entire class of problem. **Do not put real accounts in it.**

---

## 4. Reproducing

```bash
# 1. the tunnel (one-time)
cloudflared tunnel login
cloudflared tunnel create attest
cloudflared tunnel route dns attest attest.210security.com
cloudflared tunnel route dns attest id.210security.com

# 2. run it — the config lives with the project, not in ~/.cloudflared
cloudflared tunnel --config lab/cloudflare/config.yml run

# 3. the labs
scripts/lab.sh up

# 4. Keycloak with its PUBLIC hostname (overlay; local runs omit it)
docker compose --env-file lab/.env \
  -f lab/keycloak/compose.yaml \
  -f lab/keycloak/compose.tunnel.yaml up -d keycloak

# 5. the OIDC client, for BOTH origins — repeated runs must not lose either
CONSOLE_PUBLIC_URL=https://attest.210security.com \
  ./.venv/bin/python lab/keycloak/scripts/configure-realms.py
./.venv/bin/python lab/keycloak/scripts/configure-realms.py
```

---

## 5. What is still not proven

- **The console's own sign-in at the real origin.** The **passkey** works there; the full
  console flow was not completed, because the end-to-end harness hung during registration and
  the question was answered by a narrower probe first.
- **Anything about scale.** One host, one process, one database. The tunnel gives four
  connections to Cloudflare's edge, not a highly available service.
- **Restart behaviour.** Sessions and the replay cache are in-memory.
- **Why localhost differs.** The origin is now known to be the variable. What about it matters
  is not.
