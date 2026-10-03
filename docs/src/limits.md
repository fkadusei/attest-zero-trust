# Limits and non-goals

Every security document contains a list of things it defends against. This page is the other list:
what this system deliberately does not do, the risks it accepts with its eyes open, and what the word
"verified" does and does not mean here.

A claim of security that has never been bounded is not a claim anybody can evaluate. A reader who
knows where the walls are is far better placed than one who is told there are none.

**This page is the narrative version.** The authoritative record — every claim, its evidence, and its
confidence level, including the places where we are **not certain** — is the
[evidence register](evidence.md). Where this page and that one disagree, that one is right.

## Why write this down at all

A non-goal is a decision not to spend effort. Left unwritten, those decisions get made accidentally —
usually at the worst moment, by whoever is under pressure to close a deal or fix an incident. Written
down, they can be renegotiated deliberately, with the cost visible.

The accepted risks are recorded for the same reason. A risk nobody has written down is not an
accepted risk; it is an unexamined one.

## It does not implement passkeys itself

We run an established identity provider ([Keycloak](operating.md)) rather than writing our own
implementation of **WebAuthn**, the browser standard behind passkeys, or **FIDO2**, the specification
family it belongs to.

The reason is not difficulty. It is that **a subtle mistake here degrades security silently, and that
is the worst possible failure mode.**

Passkeys work because the signature a device produces is bound to the address of the site that asked
for it. That site is called the **relying party**, and the check that the signature covers the correct
relying party is what makes a passkey phishing-resistant. Get it subtly wrong and everything still
appears to work: users register, sign in, and see no error. The only difference is that the credential
would also work at an attacker's lookalike site — precisely the outcome passkeys exist to prevent.

!!! note "The general principle"

    When a component's failure mode is *invisible but total*, prefer a well-used implementation over
    a bespoke one. Novelty is a cost, and here it would be paid in the one place we can least afford
    it.

## It is not an identity product

We operate an identity provider for one application: this one. We are not offering
identity-as-a-service, not hosting separate identity environments for customers, and not letting
customers run their own identity provider inside our deployment.

Federation *inward* is a different matter and is plausible later: Keycloak supports signing in
through a customer's own corporate identity provider. Federation *outward* — becoming the identity
provider for a customer's other systems — is not on the table.

## It is not multi-region active-active

The target is a single region with a database replicated across availability zones, plus a rehearsed
restore procedure. **Active-active** — running live copies in two places at once and accepting writes
in both — is a substantially larger project, out of scope until a contract requires it.

The honest consequence: a regional cloud outage takes sign-in down for its duration. We treat that as
an availability risk rather than a security one, and we would rather have a restore we have rehearsed
than a failover we have never tested.

## The login pages are not custom-themed

We use the identity provider's stock sign-in screens. A **theme** is the visual layer — logos, fonts,
colours — layered over those screens.

Themes are cosmetic work with a real recurring cost: they hook into markup that changes between
versions, so every security upgrade becomes a small front-end project. **We are not willing to let a
font choice slow down a security patch**, which is exactly the trade a theme asks for. The risk this
avoids is not hypothetical; see [T16](threat-model.md) on unpatched vulnerabilities.

## Keycloak is extended, never forked

A **fork** means copying the project's source and maintaining our own version. Every extension we
build uses the documented plugin hooks, called **SPIs**.

The moment we fork, we own every future security fix ourselves: upstream patches stop applying
cleanly, and the effort to stay current stops being bounded. That converts a manageable patching
obligation into an unbounded one.

## It does not defend against a compromised device

This is the most important boundary here, and the one most often glossed over.

A web application runs inside a browser, on a device it does not control. If that browser is
compromised — by a malicious extension, by malware with equivalent access, or because the device
itself is owned — then **there is no technical control available from inside the page.**

Consider the session-binding mechanism ([described on its own page](sessions.md)). Each session is
tied to a private key the browser generates and will not reveal. A malicious extension runs inside the
same browser context. It cannot steal that key, and it does not need to: it can ask the browser to use
it, and the browser will, because from its point of view the request is legitimate.

Mitigation here is organisational, not technical. Our own staff, who hold the most powerful accounts,
work on managed devices. We cannot demand that of customers and do not pretend to.

## It does not defend against physical coercion

If someone is physically compelled to unlock their device and authenticate, no cryptography in this
system intervenes. This is out of scope for a compliance product's risk profile.

It would not be out of scope for a system holding, say, dissident identities. A reader from that world
should treat this page as a list of reasons not to reuse this design unmodified.

## It is not certified by anyone

The design maps onto recognised frameworks: NIST SP 800-207 for Zero Trust architecture, NIST SP
800-63B for authenticator assurance, OMB M-22-09 for phishing-resistant multi-factor authentication,
and the CISA Zero Trust Maturity Model.

**Mapping is not certification.** A mapping argues that a design *intends* to satisfy a requirement.
Certification is an independent party examining evidence and agreeing. **No external auditor has
reviewed any of this.** A procurement process needing a certified claim will not be satisfied by these
pages, and should not be.

## There is no device agent

A **device agent** is installed software reporting on a machine's health: whether it is patched,
whether disk encryption is on, whether it is enrolled in mobile device management. Real device posture
needs one.

We have deferred it until a customer asks. What we have instead is much weaker, as the next section
explains.

## Accepted risk: synced passkeys for standard users

A passkey can live in two quite different places. A **device-bound** passkey never leaves a piece of
hardware, such as a security key on a keyring. A **synced** passkey is copied between a person's
devices by a cloud service — iCloud Keychain, Google Password Manager and similar.

Syncing is far better for ordinary people: losing a phone no longer means losing the account. But it
moves the trust root, because the credential is now protected by **the user's cloud account** rather
than by a physical object they hold.

For a customer's contributor account we consider that an acceptable trade. For a **platform admin**,
who can reach every tenant's data at once, we do not — which is exactly why privileged accounts are
configured differently, restricted to genuine hardware. [The passkey page](passwordless.md) covers how
that restriction is enforced.

!!! warning "What this means in plain terms"

    For standard users, the security of their Attest account is now bounded by the security of their
    personal cloud account. If that is compromised, so is their access here. We have accepted that
    consciously rather than inherited it by accident.

## Accepted risk: browser posture is weak evidence

**Device posture** is an assessment of how trustworthy the device making a request is.

A web application learns about a device only from what the page in front of it reports. That page runs
on the device under assessment, so **anything it claims is attacker-controlled** — a compromised
device simply reports that it is healthy.

We therefore lean on signals the server observes for itself: the network characteristics of the
connection, the reputation of the address it came from, the properties of the authenticator used.
Client-reported signals are hints, never evidence. This is why a real device agent stays on the list
above.

## Accepted risk: cross-site scripting

**Cross-site scripting**, or XSS, is where an attacker gets their own code to run inside our pages. It
is among the most common ways web applications are compromised, and our defences — a strict content
security policy, dependency review, careful output encoding — reduce it without eliminating it.

It matters here because **session binding does not fix XSS.** Binding a session to a key the browser
defends stops a *stolen* token being used elsewhere. It does not stop code running in our own page
from using that key. The key was designed so it cannot be copied out; that does not stop it being
*used* while the attacker is present.

This is the honest limit of the design, and it is why shorter session lifetimes and posture signals
are not redundant.

## Accepted risk: supply chain

We depend on software written by others, including the identity provider's container image.

We pin exact versions, prefer official images, and use short-lived credentials in our build pipeline
rather than long-lived keys. None of that makes the risk zero. A compromised dependency or upstream
image remains a genuine path to compromise — reduced, not closed.

## Accepted risk: we operate the identity provider

This is the largest accepted risk in the system, and the one with the clearest ongoing cost.

By running Keycloak ourselves instead of paying a provider to run it, we took ownership of high
availability, database backups, disaster recovery, and **prompt patching of security vulnerabilities
in an internet-facing authentication service.**

That last item is the sharp one. Keycloak has a history of serious authentication-bypass
vulnerabilities and releases frequently. Our commitment is a documented **48-hour patch window for
critical issues, rehearsed at least once.** It is fulfilled by process, not by architecture — which
means **it degrades silently if attention slips.**

If the team cannot sustain that commitment, the correct answer is to migrate to a managed Keycloak
service. That option is deliberately kept open; see [operating](operating.md) and
[decisions and why](decisions-guide.md).

## What "verified" means here, and what it does not

One claim in this documentation has been tested rather than argued. The central claim about privileged
access — that only genuine hardware keys can register, enforced by an allowlist of approved
authenticator models — was checked in a **controlled experiment**: a series of enrolment attempts in
which exactly one setting changed at a time, with control runs confirming that each rejection came
from the setting under test rather than something incidental.

**That result is real.** It is reported in full on [the verification page](verification.md), including
a false positive that was caught and corrected.

What it does not mean:

| Not proven | Why it matters |
|---|---|
| That a **physical hardware key** enrols successfully | The experiment used a simulated authenticator, which can only exercise the *rejection* path. The known failure mode is a user wrongly locked out, not an attacker let in. |
| That the recorded device model identifiers are correct | Those values came from published vendor documentation and were never confirmed against physical hardware. |
| That real platform passkeys behave as assumed | Whether the major password managers and operating systems report an identifiable model is unverified, and it determines which of the two controls is actually doing the rejecting. |

Everything else here is **design**. Design is not nothing — it is where the thinking is exposed to
challenge — but "we will" is an intention, not a result. The
[verification page](verification.md) tracks what remains untested; the
[decisions page](decisions-guide.md) lists what still needs a human answer.

## The most likely way this project fails

Not a clever attack. Not a flaw in the cryptography. Not even a mistake in the policy engine.

**The most likely way this project fails is that the list on this page gets quietly shortened.**

It will not look like a compromise. It will look like a reasonable request at a moment when something
else is more urgent:

- A prospective customer asks for single sign-on, and federation inward becomes federation outward.
- A sales deck looks unfinished without our logo on the sign-in screen, so a theme gets built.
- A security patch is awkward to apply because of a local change, and the change gets carried
  "temporarily" instead of removed.
- An identity vendor's contract lapses, and running our own identity provider "for a while" becomes
  permanent — with nobody owning the patching.
- The 48-hour patch window slips once, then again, and nobody notices because nothing has gone wrong
  yet.

Each is defensible in isolation. Together they are how a careful design becomes an ordinary one. This
page exists to be quoted in those conversations — not to win them automatically, but to make sure the
cost is stated aloud before it is paid.

!!! danger "The one to watch"

    **Patching.** Every other limit here fails loudly or not at all. A missed patch fails silently,
    for months, and then all at once. If attention is spent anywhere on this page, spend it there.
