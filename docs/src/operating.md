# Running the identity provider

The **identity provider** is the service that holds everyone's credentials and issues the tokens
described in [the previous page](sessions.md). It is the component that, if it falls over, nobody can
sign in; and if it is breached, the attacker can mint a token for anybody.

We chose to run that service ourselves rather than buy it. This page is the bill for that decision,
written down honestly, including the parts that are permanent.

## The choice, and the alternative

The identity provider is **Keycloak**, an open-source product, running on infrastructure we control:
containers on AWS Fargate behind a load balancer, with its database on Amazon RDS.

The obvious alternative was to use a managed identity service that somebody else operates. We
deliberately did not, for reasons set out below — and the alternative remains available as a
documented escape hatch if the operational reality turns out worse than the security gain is worth.

## What self-hosting bought us

Three things, and the third is the one that actually decided it.

**Native proof-of-possession.** Keycloak supports DPoP directly, which removed the single largest
piece of custom security code from the earlier design. That earlier design needed us to build a
component that issued its own tokens in order to bind them to a key. Writing token-issuing code is
exactly the kind of work a small team should avoid: it is subtle, it is security-critical, and it is
easy to get almost right. Buying that capability instead of building it is a straightforward win.
(It is not a complete win — the [API still has to check the proofs](sessions.md), which is the trap
described there.)

**Passkeys with no extra tier.** Passkeys are supported natively, with no separate commercial plan
required to switch them on.

**Provable hardware-key enforcement.** This is the important one. For our most powerful accounts we
insist on a physical hardware security key, and we need to be able to *prove* that only genuine
hardware can register. Keycloak exposes the **AAGUID** — an identifier that says which model of
authenticator a credential came from — and can be configured with a list of approved models.

The previous managed option did not expose that identifier at all. Under it, we could only
*approximate* the rule by looking at looser clues. So this is not merely a simplification: **the move
made the security design stronger, by turning an approximation into something enforceable.** That
claim was then tested rather than assumed, in the experiment recorded on
[what we tested](verification.md) and in the [raw lab results](../../lab/keycloak/SPIKE-3-RESULTS.md).

## What it costs

Everything that a managed service was quietly doing for us. Concretely, we now own:

- **Availability.** Two or more running instances, health checks, and failover that actually works.
- **Backups and restore.** Somebody must be able to restore the database, and must have practised it.
- **Disaster recovery.** A written procedure, rehearsed on a real clone, not a paragraph in a wiki.
- **Patching an internet-facing authentication service, promptly, forever.**

That last item is the one that deserves the most respect.

!!! warning "The vulnerability treadmill is not optional"

    Keycloak releases frequently, and like every authentication product it has had serious
    vulnerabilities in its history — including flaws that allow authentication to be bypassed
    entirely. A publicly catalogued vulnerability of that kind is usually shortened to a **CVE**.

    Running this ourselves means **we** find out about those, **we** assess them, and **we** deploy
    the fix. Nobody emails us to say a patch is available.

Our commitment is a **critical patch deployed within 48 hours** of a fix being available. That number
is a promise about people and process, not about technology.

!!! danger "An unrehearsed patch procedure is a hope, not a control"

    It is easy to write "48 hours" in a document. It is much harder to have genuinely done it: to
    know the upgrade works against a restored copy of the real database, that our custom extensions
    still load, and that the person on call this weekend has the access and the instructions to do it
    at two in the morning.

    Until the procedure has been executed end to end at least once, **the commitment is an
    aspiration**. It should be treated as untested work, in the same category as the experiments on
    [the verification page](verification.md).

Being honest about which way this cuts: the cost is not licence fees. It is **engineering time, every
month, indefinitely** — and a recurring cost that nobody is assigned to is a cost that surfaces later
as an outage.

## The capability we lost

The managed service we moved away from included, on its higher tier, two features we now have to
build ourselves:

- **Breached-credential blocking** — refusing passwords known to appear in public breach data.
- **Risk-based adaptive authentication** — noticing that a sign-in looks unusual (a new country, an
  unfamiliar device) and demanding extra proof before allowing it.

**Keycloak provides no official equivalent of either.** This is the genuine downside of the move, and
the decision record commits us to replacing both rather than pretending the gap does not exist:

| Capability lost | Our replacement |
|---|---|
| Breached-credential blocking | A custom check against a breached-password list, at registration and at password change |
| Risk-based step-up | A custom check that consults our own risk service and demands a fresh, stronger sign-in — or refuses |
| Brute-force protection | Keycloak's built-in lockout, enabled and tuned strictly |
| Threat detection | Keycloak's event stream, forwarded into our monitoring so we can write alerting rules on it |

Two honest notes on that table.

First, this is **the main added build cost** of the whole approach, and it lands late — in the phase
where teams are typically running out of momentum. It must be treated as security-critical code with
its own review and tests, not as ordinary application features.

Second, there is a real consolation. Keycloak's event system reports **more** raw detail about
authentication than the managed service's threat protection did. So it is entirely possible to end up
with *better* detection than we would have had, while also having *worse* risk scoring to begin with.
Both statements are true, and neither cancels the other.

Note also that part of the loss is self-cancelling: breached-password blocking only matters where
passwords exist, and our privileged accounts have no password at all. The gap is real for ordinary
customer accounts, and largely irrelevant for the ones that can reach every tenant.

## Configuration is code, never console clicks

**Realm configuration** — the settings that describe who can sign in, with what, and under which
rules — is applied by our build pipeline, from a file in the repository. It is never typed into the
product's web console.

The reason is reproducibility. A setting clicked into a console exists only on that running system.
It is invisible in review, absent from a new environment, and impossible to roll back. If the
environment has to be rebuilt — after a disaster, or for a test — a console-configured system cannot
be rebuilt faithfully, and nobody can say for certain what changed or when.

Configuration-as-code also **shrinks the attack surface**, because no human needs routine
administrative access to the identity provider. The credentials that can reconfigure it belong to an
automated pipeline, not to a person with a browser.

The build then **asserts the things that must stay true**. These guards exist because each one has
already been broken once, or could be broken by a single careless change:

```text
1. The privileged realm has NO password authenticator.
2. The hardware-key allowlist is NOT empty.
3. Every client requires proof-of-possession (DPoP).
```

!!! caution "The first guard is not theoretical"

    It is tempting to read "assert there is no password authenticator" as paranoia. It is not.

    Out of the box, the default sign-in flow for a new realm **includes a password form**, and the
    passkey option is not wired into the flow at all. During the lab work, a password sign-in to the
    privileged realm **succeeded** — as it would for anyone else using the defaults. Achieving "no
    password path exists for staff" is therefore real configuration work, and the guard is what stops
    it silently reverting the next time somebody edits a flow.

    One further wrinkle worth knowing: the product does **not** validate the format of entries in the
    hardware-key allowlist. It accepted `not-a-guid` without complaint, which means a typo creates an
    allowlist entry that can never match anything. Our build has to check that format itself.

This is the honest version of "configuration as code": it works well, and it depends on discipline.
A single console click breaks the guarantee, which is exactly why the console is not part of the
process.

## The shape of the deployment

The pieces, and the reasoning behind each:

- **At least two running instances**, because one instance is a single point of failure for all
  authentication. Instances live in private networking and accept traffic only from the load
  balancer.
- **Clustering between those instances**, so a session created on one is valid on the other. This is
  the least certain part of the design. The usual clustering mechanism for this product assumes a
  Kubernetes environment for service discovery, and our platform (Fargate) has no such thing, so we
  need a database-based approach instead. **This is an untested experiment**, and it is tracked as
  such — a single-instance deployment would hide the problem until the first failover.
- **A managed PostgreSQL database** running in two availability zones, so losing a data centre does
  not lose the identity system. Reached through a connection pool, because containers are created and
  destroyed regularly and would otherwise exhaust the database's connection limit.
- **Credentials in a secrets manager**, not in configuration files, deployment templates, or anyone's
  notes.
- **Health endpoints** exposed to the load balancer, so an instance that is running but broken is
  taken out of service rather than sent traffic.
- **Correct reverse-proxy and hostname settings.** This deserves a sentence of its own, because it is
  the most common way a self-hosted identity provider breaks in a confusing manner. The address the
  service believes it lives at is written into every token it issues. Configure it wrongly and
  everything appears healthy while every token is rejected with an error that points nowhere useful.

## What the deployment looks like when it is real, if only for a day

The design above is a plan. **It has now been partly exercised**, not by deploying to a cloud but by
putting the lab on a real domain through a **Cloudflare Tunnel**: `attest.210security.com` for the
console and `id.210security.com` for the identity provider, with a real certificate and no cloud
compute at all. It cost **nothing**, and it settled things that reasoning had only guessed at.

**Two hostnames, deliberately.** The identity provider gets its own because the passkey ceremony
happens on *its* page, so the relying-party ID is *its* hostname. That keeps the ID **narrow** —
`id.210security.com` rather than `210security.com` — and a broad one is usable from every subdomain,
which has been measured as exploitable and is recorded in the evidence register. Putting the identity
provider on its own hostname is a security decision, not tidiness.

**The paragraph above about reverse-proxy settings is not theoretical, and here is the measurement.**
With the hostname forwarded but no proxy configuration, the identity provider issued:

```text
issuer: http://id.210security.com/realms/master      ← http, not https
```

It had learned the *hostname* and not the *scheme*, because TLS terminates at Cloudflare's edge and
plain HTTP arrives at the origin. **Everything looked healthy while every redirect failed** — and the
failure reads as a misconfigured *client*, not a misconfigured *proxy*, which is exactly the trap the
paragraph warns about.

The fix is one setting, and it cannot be applied the obvious way:

```text
Invalid value for option 'KC_PROXY_HEADERS': .
Expected values are: forwarded, xforwarded
```

**An empty value is invalid**, so it cannot sit in a base configuration with a `${VAR:-}` default, and
the obvious alternatives have no way to express "not set". It belongs in a separate overlay file
applied only when the tunnel is in use — which has the useful side effect of making *"local runs are
local-only"* true by construction rather than by convention.

!!! danger "Exposing an identity provider is not the same as exposing a web app"

    **This is the part to take seriously.** The tunnel put the identity provider on the public
    internet, and a measurement — not a review — found that the master realm's **password grant was
    reachable and accepting password attempts**, on a server running in a development mode with no
    rate limiting and no lockout.

    That is an unlimited guessing surface against an administrative account. It was closed by refusing
    `/admin` and `/realms/master` **at the tunnel edge**, before traffic reaches the provider at all,
    and verified: those paths now return `404` while the sign-in paths still return `200`. Both halves
    were asserted, because closing the admin path without breaking the sign-in path is the whole
    difficulty.

    **If you expose an identity provider for testing: put an identity-aware proxy in front of it, or
    refuse the administrative paths at the edge, and verify both that the admin surface is closed and
    that sign-in still works.** A lab that is reachable is not a lab any more.

## Patching, and the promise that decides this

The single question that determines whether self-hosting is sustainable is not technical:

!!! quote "The question to answer honestly"

    **Can we commit to deploying a critical security fix within 48 hours, and do we have a named
    person who owns upgrades, backups, and incidents?**

If the answer is yes, self-hosting is a good trade: we get stronger enforcement of the hardware-key
rule and pay for it in engineering time.

If the answer is no, or if it is "somebody, probably" — then the correct decision is to use a managed
identity service instead, and this page's reasoning does not change that. An unpatched, undocumented,
unowned authentication service is **worse than every limitation of the managed option we moved away
from**. The cost of discovering that in production is far higher than the cost of deciding it now.

Two further commitments follow from the same logic: version numbers are pinned exactly, never
floating; and custom extensions are kept deliberately few and checked for compatibility on every
upgrade, because a custom extension that breaks during an emergency patch converts a routine fix into
an outage.

## The escape hatch

**Self-hosting is the decision, and it was taken deliberately.** This section is kept because the
alternative should stay visible rather than quietly forgotten: if the patch commitment cannot be met
in practice, or if operating the identity provider proves unsustainable, the documented fallback is a
**managed Keycloak service** — the same software, operated by a vendor, with the operational burden
transferred along with the cost. Keeping the hatch documented is not indecision; it is what stops the
decision becoming irreversible by accident.

The migration is tractable, and it is worth being precise about which part is painful:

- **The good news.** Keycloak is a standard implementation of OpenID Connect, the same protocol every
  managed identity service speaks. Our applications are pointed at the address that identifies the
  provider as the source of their tokens, rather than being tied to one vendor's proprietary
  interface. Because realm configuration is already a file in the repository, it can be imported into
  the new service largely as-is.
- **The painful part.** Passkeys are bound to a web address. Moving to a new address means
  **every user must register their passkeys again.** That is a genuine, unavoidable piece of work
  affecting every person who uses the system. It should be factored into any migration estimate
  rather than discovered halfway through.

## The honest summary

Both of the following are true, and neither one wins:

**Self-hosting made the security design stronger.** It removed a large piece of custom token-issuing
code, and — more importantly — it replaced an approximation of the hardware-key rule with something
provable. That is a real gain, and it is the reason the decision was made.

**Self-hosting made the operations permanently harder.** We now run an internet-facing authentication
service and carry a standing obligation to patch it quickly, back it up, and be able to restore it.
That obligation does not end, and it is measured in people rather than in money.

If that trade is unacceptable, the alternative is documented, tested against, and reversible — at the
cost of making every user re-register their passkeys. What is not acceptable is accepting the trade
in principle and then not resourcing it in practice, because that produces the worst outcome
available: the operational risk of running the service, without the discipline that makes it safe.

For the risks this creates and which we accept, see [limits and non-goals](limits.md); for the
reasoning in full, the [decision register](../decisions.md) and the
[plan](../PLAN.md).
