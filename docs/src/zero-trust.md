# The big picture

This page is the shape of the system: what Zero Trust actually means here, how the pieces divide up,
and which boundaries we treat as hostile.

## Zero Trust in one sentence

**No request is trusted because of where it came from.**

That is the whole idea. There is no "inside the network" where things are safe by default. There is
no VPN that makes you trustworthy, and no IP address that substitutes for a decision. Every request
must prove who it is, and then be judged on its own merits.

!!! note "Why the name is slightly misleading"

    "Zero Trust" does not mean trusting nothing and blocking everything. It means trust is never
    *assumed* from context — it is earned per request, from evidence, every time. A user who signed in
    perfectly thirty seconds ago still has to pass every check on their next call.

## Why "we turned on MFA" is not Zero Trust

Multi-factor authentication answers one question: *is this person who they say they are, at the
moment they sign in?*

It says nothing about:

- Whether the token they are now carrying has been stolen.
- Whether their laptop is healthy.
- Whether they are entitled to **this particular record**.
- Whether access granted six hours ago should still be live now.

A system that authenticates strongly and then trusts everything afterwards has a strong front door
and no interior walls. Zero Trust is mostly about the interior walls.

## The idea that makes it work: separating the decision from the enforcement

The most useful concept in Zero Trust, formalised in NIST SP 800-207, is that the thing which
**makes** an access decision and the thing which **enforces** it should be different components.

<div class="grid" markdown>

<div class="card" markdown>
**The decision point**

Given a who, a what, which object, and the current circumstances, is this allowed? It holds the rules
and nothing else. Here that is **Amazon Verified Permissions**, evaluating policies written in a
language called **Cedar**.
</div>

<div class="card" markdown>
**The enforcement point**

Sits on the path of every request and refuses anything the decision point did not approve. It holds
no rules of its own. Here that is **API Gateway** plus a small function that checks token binding.
</div>

</div>

Keeping these apart buys two things. Authorization rules can change without deploying application
code, because they are data. And a single compromised component does not gain both the ability to
*decide* and the ability to *permit*.

## Three planes

Everything in the system belongs to one of three planes. Each has a different job, a different
failure mode, and a different reason to exist.

| Plane | Job | Failure looks like | Built from |
|---|---|---|---|
| **Identity** | Prove who is asking, and issue tokens | Nobody can sign in; or the wrong person can | Keycloak, run by us, in two separate realms |
| **Decision** | Decide whether a proven identity may do a specific thing to a specific object, right now | The wrong access is allowed, or the right access is blocked | Verified Permissions, plus posture and revocation signals |
| **Data** | Hold the evidence, and enforce tenant scope a second time | One customer sees another's data | DynamoDB and S3, with per-request scoping |

The separation matters because each plane can fail independently. If the policy engine is
misconfigured, the data layer still constrains the query. If a token is stolen, the binding check
still refuses it. Redundancy here is not waste — any one of these failing is a security incident
rather than an outage, so they must not share a fate.

## The boundaries we assume are hostile

Every arrow below is somewhere an attacker can stand. Nothing is trusted for being on the "inside",
because there is no inside.

| # | Boundary | The rule at that boundary |
|---|---|---|
| B1 | Internet → content delivery | Filtered by a web application firewall. Reaching this point confers no trust. |
| B2 | Content delivery → load balancer and API | Only our own distribution may call the origin. |
| B3 | Load balancer → identity provider | The identity provider accepts traffic only from the load balancer, never directly. |
| B4 | API → application code | Both the token-binding check **and** the policy decision must pass. Either one failing denies the request. |
| B5 | Application code → data stores | Least privilege per function, and tenant scope re-applied inside the query itself. |
| B6 | Tenant ↔ tenant | Enforced twice, independently: in policy, and in the data layer. |
| B7 | Customer realm ↔ privileged realm | Separate realms with separate signing keys. No credential or session crosses. |
| B8 | Human ↔ machine identity | Different mechanisms entirely, and no shared secrets. |
| B9 | Our code ↔ administering the identity provider | Configuration is declarative, so no human needs routine administrative access. |

!!! info "The consequence people find surprising"

    Because the network is assumed hostile, there is no VPN and no IP allowlist anywhere as a
    security control. Access is granted to a *person and a device*, not to an *address*. An employee
    on the corporate network gets no more trust than an auditor on a train, and that is the point.

## A decision we made deliberately, and its price

We run the identity provider ourselves rather than buying a managed service.

That is not the easy option. It makes us responsible for high availability and for patching an
internet-facing authentication service quickly, forever. We chose it because it was the only way to
make one specific requirement genuinely enforceable rather than approximately enforceable: that
platform admins must hold **physical hardware keys whose genuineness the server can check**.

The [passwordless](passwordless.md) page explains why that requirement needs something the managed
service we originally used could not provide, and the
[operating](operating.md) page is honest about what running it costs us.
