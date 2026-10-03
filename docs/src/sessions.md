# After sign-in

Making sign-in unphishable closes one door. It does nothing at all about what happens next.

Once someone is signed in, the browser holds a **token**: a small block of data, signed by the
identity provider, that it presents with every request to prove who it is. Everything this page
describes is about making that token — and every request carrying it — stand up to scrutiny on its
own, rather than being trusted because it arrived.

## A token works for whoever is holding it

A token issued by a normal sign-in is a **bearer token**. The name is literal: whoever bears it, wins.
The server checks that it is validly signed and has not expired, and then does what it is asked.

There is no connection between the token and the machine using it. Copy the token onto another
computer and it works exactly as well there. This is not a bug in any particular product; it is how
almost all web sessions work.

The practical consequence is uncomfortable:

!!! danger "Phishing-resistant sign-in does not stop token theft"

    We spent a great deal of effort making sure an attacker cannot phish a credential. If they can
    instead steal the token that sign-in produces, **that effort buys nothing at all**. They skip the
    front door entirely, because the door is already open and the token is the key.

Tokens leak through mundane routes rather than dramatic ones:

- **Logs.** A proxy, a debugging session, or an error reporter captures a request header by accident.
- **Injected script.** A cross-site scripting flaw — usually shortened to **XSS** — lets an attacker
  run their own code inside our page, in the user's session, with full access to the session.
- **Browser extensions.** An extension runs inside the same browser and reads the same pages.
- **A shared or stolen laptop**, where the session is simply already open.
- **Support tooling**, where a well-meaning engineer pastes a request into a ticket to debug it.

Every one of these produces the same outcome: a fully authenticated session in the wrong hands. So
the question after sign-in is not "is this token real?" but "**is this the machine the token was
issued to?**"

## DPoP, in plain language

**DPoP** stands for Demonstrating Proof-of-Possession, and it answers that question. (The name comes
from a formal specification, RFC 9449, if you ever need to look it up.)

!!! info "There are two different keys in this design, and they live in different places"

    This trips people up, so it is worth stating plainly.

    **The passkey** is what you log in with. **We never store it and never see it.** It lives on the
    user's own device — in iCloud Keychain or another password manager if it is a "synced" passkey, or
    on a hardware security key. Our server keeps only the *public* half, which is useless for
    impersonating anyone.

    **The session key** is created by our own web page *after* you log in, and it is stored by us in
    the browser's own storage for our site. It is not a passkey and it is not in any password manager.
    It exists only to protect the session, and it is thrown away with the session.

    So "where is the key stored?" has two different answers depending on which key is meant, and
    neither answer involves us holding anything secret.

The mechanism has three parts:

1. **The browser generates a second key pair.** This is separate from the passkey used to sign in. It
   exists only for talking to our API. As with the passkey, the private half never leaves the browser.
2. **The token records which key it belongs to.** When the identity provider issues the token, it
   writes in the fingerprint — called a **thumbprint** — of that browser's public key.
3. **Every request carries a small signed voucher.** Alongside the token, the browser sends a tiny
   signed statement proving it holds the matching private key. The statement is tied to that exact
   request: the HTTP method and the full URL are inside it, and it carries a one-time identifier so
   the same voucher cannot be used twice.

Now a stolen token is inert. The attacker has the token, but not the private key, so they cannot
produce a valid voucher. They can replay the token as many times as they like; every request fails
the proof check.

There is one more detail that makes this worth the trouble. The browser key is created as
**non-extractable**:

```ts
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,                       // extractable = false
  ['sign', 'verify'],
);
```

That single `false` means JavaScript can *use* the key but can never *read it out*. So even code
running inside our own page — including an attacker's injected script — cannot copy the key
elsewhere. It converts "steal the token" into the far harder "steal the token *and* run code in the
same browser, in the same profile, at the same moment".

## The mistake that makes all of this worthless

This is the single most important paragraph on the page, and it is a trap that a competent engineer
walks into naturally.

!!! danger "The identity provider is not in the path of your API"

    Keycloak verifies the DPoP voucher when it **issues** the token, and it is entirely correct to
    describe that as "Keycloak supports DPoP".

    But Keycloak is not sitting in front of our API. When a browser calls our application, that
    request goes to our API and never touches Keycloak at all. So **our API must verify the voucher
    itself, on every single request.**

    Skip that step and you get the worst possible outcome: tokens that *advertise* a binding nobody
    ever checks, and an API that accepts a stolen token from anywhere. **That is worse than not
    having DPoP at all**, because it produces confident answers to security questionnaires while
    providing no protection.

This is why we build a small, deliberately narrow component — a **DPoP verifying authoriser** — that
does nothing but check these proofs. It is the one piece of genuinely custom security code in the
system. Keeping it small is the point: small security code can be read carefully by a human, and code
that cannot be read carefully is not really reviewed.

## Every request, layer by layer

A request to our API passes through all of the following. Each layer can reject it independently,
and that redundancy is deliberate — a failure in one should be an incident, not an outage.

| # | Layer | The question it asks |
|---|---|---|
| 1 | Edge filtering | Is this request plausible at all, or is it part of a flood or a known attack pattern? |
| 2 | Token validity | Is the token genuinely signed by us, and unexpired? |
| 3 | Key possession | Does the caller hold the private key the token was issued to? |
| 4 | Revocation | Has this session been cancelled since the token was issued? |
| 5 | Device posture | How much do we trust the device making the request? |
| 6 | Policy decision | Is this specific action, on this specific resource, allowed for this person? |
| 7 | Tenant scoping | Does the database query itself refuse to cross a tenant boundary? |
| 8 | Audit | Is the decision recorded where it cannot be altered afterwards? |

**Layers 2 and 6 answer completely different questions**, and confusing them is the classic mistake
in this kind of system:

- Layer 2 asks **"is this token valid?"** — a question about identity.
- Layer 6 asks **"is this action allowed?"** — a question about entitlement.

A valid token is not a permission slip. It tells you who is calling. It says nothing whatsoever about
what they should be permitted to do. A system that treats a valid token as sufficient has no
authorisation at all; it has authentication wearing a disguise.

## Policy, written down and tested

Layer 6 is not implemented as `if` statements scattered through our code. It is a set of rules in
**Cedar**, a policy language, evaluated by a separate service (Amazon Verified Permissions). We call
that service the **policy decision point**: the one place that decides, and a place our application
code cannot quietly overrule.

The most important rule is the one that keeps tenants apart:

```cedar
// Baseline: no cross-tenant access, ever. A FORBID, so no later permit can override it.
forbid (
  principal,
  action,
  resource
)
when {
  principal has tenant_id &&
  resource has tenant_id &&
  principal.tenant_id != resource.tenant_id
};
```

`principal` is who is asking, `action` is what they are trying to do, `resource` is what they are
trying to do it to.

The choice of `forbid` here is deliberate and worth understanding. In Cedar, **a `forbid` always wins
over any `permit`**, no matter which order they are written in or how many permits exist. That means
a developer who later adds a broad, generous `permit` rule cannot accidentally open the tenant
boundary, because the `forbid` still overrides it.

Writing the same rule as a condition on each `permit` instead would work today and break the first
time somebody added a new permit without remembering. **Do not rewrite it.** A rule that depends on
every future author remembering it is not a control; it is a convention.

Policies live in the repository and are checked by the build, so a route with no policy fails before
it reaches anyone.

## Keeping tenants apart

If one customer can read another customer's evidence, the product is finished. There is no partial
credit. So tenant separation is enforced in four independent places, on the assumption that any one
of them will eventually have a bug:

| Layer | Mechanism | How it can fail |
|---|---|---|
| 1 — Policy | The Cedar `forbid` above | Somebody writes the policy incorrectly |
| 2 — Data access | Every database query is keyed by the tenant | A developer forgets the key |
| 3 — Permissions | Cloud permissions scoped to the tenant's data | A role is configured too broadly |
| 4 — Tests | A suite that actively attempts cross-tenant reads on every change | The test suite has a gap |

If you remember one rule from this page, remember this one:

!!! tip "Tenant identity comes from the token, never from the request"

    The tenant a request belongs to is taken **only** from the cryptographically verified token.
    It is never read from a request body, a URL, or a query parameter.

    Any code path that accepts a tenant identifier from the caller is a bug by definition — because
    the caller can simply supply someone else's. An entire family of well-known vulnerabilities
    (changing an ID in a URL to reach another customer's record) exists purely because software
    trusted an identifier that arrived from outside.

## Revocation, or making "sign out" mean something

Tokens expire, but they expire slowly by design: five minutes for an access token. That is fine for
ordinary life and far too slow for an incident. If an administrator revokes someone's access at
09:00, "it will stop working by 09:05" is not an answer anyone wants during a breach.

So revocation is its own subsystem. When a session is cancelled, the identity provider emits an
event; that event is turned into an entry in a small, fast store; and every request checks that store
before proceeding.

Two details matter more than they look:

- **The cache is the real revocation time.** We check the store through a short-lived cache for
  performance. Whatever that cache is set to *becomes* the revocation delay, silently. It is written
  down in the runbook and asserted in a test, because caches have a habit of being lengthened during
  a performance incident and never shortened again.
- **A failed proof should raise an alarm, not just a rejection.** A DPoP failure means somebody
  presented a token without the key it belongs to. There is no innocent explanation for that. It is
  high-confidence evidence of token theft, so it should page a human — not quietly return a 401 (the
  standard "unauthorized" error) that nobody ever looks at.

## What DPoP does not fix

Being honest about the edges of a control is part of using it well. DPoP removes token theft as an
attack, and it does nothing about the following.

| Attack | Effect of DPoP |
|---|---|
| Token stolen from a log, proxy, or ticket | **Defeated** — the attacker has no private key |
| Token replayed from a different machine | **Defeated** — the proof signature fails |
| Token stolen via XSS in our own pages | **Only partly mitigated** — the attacker's script runs inside our page and can *use* the non-extractable key, even though it cannot copy it |
| Malicious browser extension | **Not mitigated** — it shares the browser's context |
| A fully compromised device | **Not mitigated** |

The third row is the one to sit with. DPoP raises the bar from "steal a string" to "execute code in
the right place at the right time". That is a large improvement, and it is not immunity. It is why
short token lifetimes, strict browser security headers, and device posture checks still earn their
place rather than being redundant.

## What is still unproven

The design above is complete. Not all of it has been demonstrated, and it would be dishonest to
imply otherwise:

- The **end-to-end proof check** — that a real token and voucher survive the journey through our edge
  and are correctly verified at the API — has **not been tested yet**. This is the highest-priority
  experiment outstanding, because a header silently dropped in transit would break the binding
  without breaking anything visible.
- Whether the browser can **reliably keep a non-extractable key** across restarts in all major
  browsers is **untested**. Safari is the one to watch.
- The **revocation delay** has not been measured end to end. Target: under sixty seconds.

The [verification page](verification.md) tracks these, and the [authorisation reference](../authorization-and-sessions.md)
carries the precise configuration. What *has* been proven is the hardware-key enforcement at sign-in —
see [what we tested](verification.md) and the [raw lab results](../../lab/keycloak/SPIKE-3-RESULTS.md).
