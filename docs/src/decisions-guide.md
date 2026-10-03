# Decisions and why

This page explains the significant choices behind Attest: what was chosen, what the alternative was,
and what the choice costs. [The formal decision register](adr.md) holds the same decisions in
structured form.

## Why decisions are written down

A decision that exists only in someone's head cannot be revisited — only drifted away from. Six months
later nobody can tell whether a constraint is load-bearing or was a passing preference, so it gets
removed, and the reason it existed is rediscovered the hard way.

Two motives matter more than tidiness. **Every choice has a cost, and the cost should be visible at
the moment of choosing.** And **a decision records what was rejected, and why**: "we preferred
Keycloak" is not something anyone can act on, whereas "we rejected the managed provider because it
could not enforce hardware-only authenticators" tells a future reader what would have to change.

!!! note "A recurring theme"

    Several decisions below are the same idea in different places: **put the rule in configuration
    rather than in application code**, because configuration is inspected and application code is
    where rules quietly rot.

## Choosing to run our own identity provider

An **identity provider** holds accounts, checks credentials, and issues the tokens that prove who
someone is. It is the component everything else trusts. We run **Keycloak**, an open-source identity
provider, on our own infrastructure.

**The alternative** was Amazon Cognito, which the design originally targeted: less to operate, patched
by somebody else, with the database abstracted away.

**Why it was rejected.** Two limitations, both found by reading the API surface rather than assuming
it. First, **Cognito could not tell us what kind of authenticator a user had registered.** There is an
identifier for an authenticator's make and model — the **AAGUID** — and for the privileged realm that
identifier *is* the control; without it, "privileged users must use hardware" could only be
*approximated*. Second, **Cognito had no support for binding a token to a key** — a mechanism called
**DPoP** (see [the sessions page](sessions.md)) — which would have forced us to build our own
token-issuing service, the largest and riskiest piece of custom code in the original plan.

**What it cost.** We now own high availability, backups, and security patching for an internet-facing
authentication service. The patching obligation is a standing commitment — a documented 48-hour window
for critical vulnerabilities, rehearsed at least once — fulfilled by attention, not architecture.

!!! warning "The honest summary"

    This traded a recurring operational burden for a stronger, simpler security design. It is a good
    trade **only if** somebody genuinely owns the operational half — still an open question, and the
    first of the two decisive ones below.

## Two separate realms rather than one with roles

A **realm** in Keycloak is an isolated identity environment: its own users, credentials,
configuration and signing keys. We run two — one for customers, one for our own staff.

**The alternative** was a single realm with privileges assigned by role.

**Why it was rejected.** With one realm, the difference between customer-grade and
platform-admin-grade assurance would be conditional logic in application code — precisely where such
rules regress silently. A mistake would mean a platform admin authenticating at the customer grade
without anyone noticing. With two realms the difference lives in configuration, so a regression becomes
a visible change a test can assert against.

**What it cost.** Staff who are also customers hold two identities, and there are two configurations
and two recovery procedures to maintain. The staff population is small, and the separation is the
point.

## Hardware-only authenticators for privileged accounts

**What was chosen.** On the privileged realm, enrolment is restricted to genuine hardware
authenticators using two settings together: a restriction on the *kind* of authenticator (**platform**
authenticators are built into a device; **cross-platform** ones are separate objects like a security
key), and an allowlist of approved AAGUIDs.

**The alternative** was accepting synced passkeys — those copied between devices by a cloud service —
for everyone, since they remain phishing-resistant.

**Why it was rejected.** Syncing moves the trust root from a physical object the user holds to the
user's cloud account. That is reasonable for a customer's contributor, but not for an account that can
read every tenant's data, because it bounds the platform's security by the security of a personal
cloud account.

**What it cost.** Staff must carry a security key and can be locked out if their model is not listed,
and an allowlist "fixed" under pressure with a wildcard would silently void the control.

!!! tip "What testing changed about this decision"

    Under **no-attestation** — where an authenticator declines to provide cryptographic evidence of
    what it is — the AAGUID is merely *self-declared*, so a software authenticator could claim any
    value it liked.

    The allowlist is therefore only meaningful when **attestation is required**. The two settings are
    not redundant: requiring attestation is what gives the allowlist meaning. We kept the requirement
    knowing it excludes some legitimate authenticators, because the alternative is an allowlist that
    appears to work and does not.

## No custom token-issuing service

A **bearer token** is the naive kind of token: whoever holds it is treated as its owner, so stealing
it is as good as stealing the session.

**What was chosen.** Let Keycloak issue tokens bound to a private key the client controls, and build
only a narrow component at our own API that *checks* that binding on each request.

**The alternative** was running our own token-issuing service — unavoidable under the previous
identity provider, and the biggest piece of bespoke security code in the original plan. With bound
tokens now issued natively, it would have reimplemented a solved problem and kept the risk for no
benefit.

**What it cost** — and this is worth reading twice:

!!! danger "The trap this decision creates"

    **"Our identity provider does proof-of-possession" does not mean our API is protected.**

    The provider checks the proof when it *issues* a token. It is not in the path of requests to our
    API. Unless our API checks the proof on every request, it will accept a stolen token that merely
    *advertises* a binding nobody verifies — **worse than having no binding at all**, because it
    creates confidence that is not earned. This is one of the highest-likelihood risks in the plan,
    and why verifying the binding at our API is an explicit deliverable with its own test.

## Keeping a separate policy engine

A **policy engine** answers "may this person do this thing to this record?" It is separate from the
identity provider, which only answers "who is this?"

**What was chosen.** Amazon Verified Permissions, which evaluates policies written in **Cedar** — a
language designed so policies can be reasoned about rather than merely executed.

**The alternative** was the identity provider's built-in authorization features: one system instead of
two.

**Why it was rejected.** Cedar's design supports formal analysis, which is what a tenant-isolation
boundary deserves; "it looked right in review" is weak assurance for the rule we cannot get wrong.
More practically, **decoupling the policy engine from the identity provider means an identity change
does not rewrite authorization** — a lesson learned cheaply here, because when the identity provider
changed, every authorization decision survived untouched.

**What it cost.** A second system to operate against, plus integration work, because the policy engine
may not accept our provider's tokens directly — an open question listed below.

## Tenant isolation as a rule that fails closed

**Tenant isolation** means one customer can never read another's data.

**What was chosen.** Two rules together. First, isolation is written as a **`forbid`** — a rule that
denies, and which in Cedar cannot be overridden by any permission granted elsewhere. Second, tenant
identity comes **only** from the cryptographically verified token, never from the request.

**The alternative** was writing isolation into each permission: "allow this, provided the tenant
matches".

**Why it was rejected.** A permission with a condition is only as good as the last person who edited
it; one careless new permission omitting the condition reopens the boundary. A `forbid` fails
**closed** — the default is denial, and access must be affirmatively granted. The second rule closes
the most common class of this bug entirely: an **IDOR** (insecure direct object reference, where an
identifier in a request is changed to reach somebody else's record) only works if the server trusts
something the caller supplied. Ours never does.

**What it cost.** Administrative work that genuinely spans tenants now requires an explicit, audited
action instead of falling out of a general permission — friction that is intended.

## A shared data model rather than a stack per tenant

**What was chosen.** One set of infrastructure and one database table shared by all tenants, with
every record keyed by the tenant it belongs to.

**The alternative** was separate storage and infrastructure per tenant.

**Why it was rejected.** Onboarding a customer becomes a data operation rather than an infrastructure
deployment, and cost scales with usage rather than with customer count. At hundreds of tenants,
separate stacks become painful to operate.

**What it cost** — stated plainly rather than buried:

!!! warning "The boundary is logical, not physical"

    With a shared model, **nothing in the infrastructure itself stops one tenant's data reaching
    another's.** Separation is enforced by policy and by code — weaker than physical separation, and
    the reason isolation is defended by **four independent layers**: the `forbid` rule; tenant
    identity coming only from the token; access controls on the cloud resources; and an automated
    suite that attempts cross-tenant access on every change. If a customer ever contracts for physical
    isolation, the highest-value tenants can be given their own storage.

## Keeping cloud management access out of the identity provider

**What was chosen.** Access to our cloud infrastructure is governed by a completely separate system
with its own hardware-key requirement — not by the identity provider that runs the application.

**The alternative** was treating the identity provider as the single source of identity for
everything, which is tidier.

**Why it was rejected.** The cloud account is the real crown jewel: it holds every tenant's data *and*
the identity provider itself. If the provider also governed access to that account, compromising it
would be a direct path to everything — collapsing two independent boundaries into one. This became
**more** important when we took on running the provider ourselves, and it is now one of the few
controls limiting the blast radius of a compromised identity provider.

**What it cost.** Two identity systems to operate and explain, and staff who need hardware keys for
both. The awkwardness is the point.

## Configuration as code, not console clicks

**What was chosen.** Every identity provider setting — realms, allowed authenticator models,
authentication flows — is written as a file in the source repository and applied automatically by the
build pipeline. Changing it by clicking in the administrative console is prohibited.

**The alternative** was configuring the provider through its web interface, which is how most people
use it, at least at first.

**Why it was rejected.** A console change is invisible: no diff, no review, no record of intent, and
no way back other than memory. Worse, it can silently undo a security control — for instance by
re-enabling a password sign-in path on the privileged realm, a serious regression nothing would
announce. There is a second benefit that was not obvious at the time: **no human routinely needs
administrative access to the identity provider**, because the credentials are used by automation
rather than people.

**What it cost.** A learning curve, some settings awkward to express as files, and a bootstrap problem
— the pipeline needs administrative credentials to configure the very system it is hardening. It also
requires discipline: one console click breaks the guarantee.

## Replacing managed threat protection ourselves

**What was chosen.** Building substitutes for the risk-detection features the managed provider used to
supply: a check against known-breached passwords, a check on request risk that can force a stronger
authentication, tuned lockout rules, and detection rules fed by the provider's event stream.

**The alternative** was accepting the loss and relying on built-in lockout protection alone.

**Why it was rejected.** The customer realm still has passwords, so the risk signals those features
covered still exist there. Accepting the loss would leave a real gap in the one place passwords
remain.

**What it cost.** This is the main *added* build cost of running our own provider, and it lands late
in the plan — precisely when teams run short of momentum. Extensions must be re-checked on every
upgrade, and our risk scoring will start out worse than a mature managed engine, so it must be treated
as security-critical code with its own review. There is a genuine consolation: the provider's event
stream exposes **more** authentication detail than the managed service did, so detection can end up
better even where risk scoring is worse. Both statements are true.

## Rejecting the identity provider's step-up mechanism

**The decision:** sensitive actions do not use the identity provider's "level of authentication"
step-up. Instead we force a genuine re-authentication and judge **how recently** it happened, using
the `auth_time` claim — never the `acr` claim.

**Why.** The plan assumed step-up would work through the provider's level mapping, with elevation
becoming a fact the provider stamps into the token. An experiment could not make it gate at all: a
subflow demanding a second factor fired regardless of what level was requested, or of nothing being
requested.

Rather than keep guessing at the configuration, we looked up how the component actually behaves. That
found **CVE-2026-97176**, published nine days earlier: *a user with a low-level session can obtain a
token asserting a higher level than they performed.* No fix, and no available mitigation, in a
package that ships in our build.

**Why that settles it.** The question "can we configure this correctly?" became irrelevant. A control
an attacker can bypass is not a control, however well configured — and this one was going to protect
"export who can see what" and "an administrator looking across all customers".

**The principle it produced, which outlives step-up:** *a claim the issuer writes is not a claim the
resource server can rely on without checking.* We learned this once already, with token binding, where
the provider bound a token but our own API still had to verify it. Learning it twice is why it is
written down as a principle rather than an incident.

**What it costs.** A full re-authentication is blunter than a targeted step-up, and it is work the
provider would otherwise have owned. On the privileged realm the objection is smaller than it looks:
the only way to sign in there is a hardware key, so re-running the flow *is* a fresh hardware-key
assertion — freshness and strength from the same act.

**Revisit only if** an upstream fix ships — and only on the evidence of a test that **tries to exploit
the bypass**, never on the strength of a patch note.

## The operating decision, and the one question left

Running our own identity provider was the decision that shaped everything else here, and it has been
taken deliberately rather than drifted into.

**We self-host.** That makes the 48-hour critical-patch commitment a **standing obligation**, not an
aspiration, and it means the upgrade path has to be rehearsed rather than merely documented. An
untested patch procedure is a hope, and hoping is not a security control. It also means a disaster
recovery drill is part of the work, not preparation for the work.

One question remains open, and it is the one that decides whether the commitment survives contact with
a busy week:

**Who owns the identity provider day to day** — upgrades, backups, incident response? Self-hosting
without a named owner degrades into an unpatched, undocumented authentication service, which is
strictly worse than the managed limitations we set out to avoid. "Everyone" is not an answer, and
neither is a team name. It needs a person.

The escape hatch is kept documented rather than deleted: because this is standard OIDC with
declarative realm configuration, migrating to a managed Keycloak service later would mean pointing
clients at a new issuer and re-importing configuration. The painful part would be every user
re-registering their passkeys, which is worth knowing before it becomes urgent.

The full list of open questions is in [the register](adr.md), and every claim's evidence and
confidence is in [the evidence register](evidence.md).

## Verification work not yet done

**`EVIDENCE.md` is the authoritative record** of every claim, its evidence and its confidence level.
Reach for it before repeating anything from this page as fact.

Several claims are tested; several are not, and the untested ones could change a decision rather than
merely confirm one. In summary:

| Not yet verified | Why it could change the design |
|---|---|
| The **acceptance path with a physical hardware key** | The experiment exercised rejection only. Until a real key enrols successfully, the known failure mode is a user wrongly locked out rather than an attacker let in. |
| **Proof-of-possession end to end**, including whether the required header survives every network hop | If any hop strips it, the control fails — and the tempting "fix" would be to disable the check, precisely the trap described above. |
| **Running the identity provider as more than one instance** | A single instance is not a viable production target. The discovery mechanism is non-obvious on our chosen platform and could force a hosting change. |
| **How quickly a revoked session actually stops working** | The target is under a minute. The mechanism involves a cache whose lifetime silently becomes the real figure, and caches drift. |
| **A real phishing-proxy test** against our own sign-in flow | This is the attack the whole project exists to defeat. It should be demonstrated, not assumed. |
| **The regulatory position on synced versus device-bound passkeys** | Determines whether a formal assurance-level claim can be made at all, or only the broader "phishing-resistant" claim. The source is read only in summary so far, which is not enough to claim anything publicly. |
| **Whether the replacement for step-up actually forces a fresh check** | It is a plan, not a control. If it does not work either, sensitive actions have no freshness control at all. |
| **Whether Firefox and Safari keep the session key** | Only Chromium has been tested, and it is one engine in three skins. Safari is the likeliest to evict stored data. |

## Where to go next

[The decision register](adr.md) has the formal records. [What we tested](verification.md) has what has
actually been demonstrated, including the result that reshaped the authenticator decision.
[Limits and non-goals](limits.md) has the boundaries this design accepts.
