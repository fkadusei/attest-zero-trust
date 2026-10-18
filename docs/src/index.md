# Start here

**Attest** is a multi-tenant web application that helps companies collect and prove compliance
evidence — the paperwork behind a SOC 2 or ISO 27001 report. This documentation explains how it
authenticates people and decides what they may do, and why it does those things the hard way.

You do not need to know anything about passkeys, Zero Trust, or policy engines to read this. Every
term is explained where it first appears, and collected in the [glossary](#glossary).

!!! warning "Where this project actually stands"

    **There is a working implementation, and its security claims are evidenced rather than asserted.
    It is not a production deployment.**

    That distinction is the honest one, and it cuts both ways, so both halves are stated plainly.

    **What exists.** A running API and admin console — 21 source modules, about 3,700 lines, behind
    216 tests — enforcing DPoP-bound tokens, per-request Cedar authorization, and PostgreSQL
    row-level security. It runs locally and behind a real domain with TLS. Eighteen controlled
    experiments have been run against it, and **39 claims are recorded as Verified** in the
    [evidence register](evidence.md) — meaning each one came from an experiment that had a working
    control, not from reading documentation.

    **What does not exist.** Any deployment to a cloud provider, any redundancy, any monitoring, any
    restore-from-backup drill. It is one node on one machine, and the [limits](limits.md) page is
    explicit about what that leaves out. Nothing here has faced a penetration test or an independent
    reviewer.

    So: read the [what we tested](verification.md) page as evidence about specific mechanisms, not as
    a claim that the system is secure. **Ten things are listed there as explicitly Unverified**, and
    those are the ones most likely to be wrong.

## What the application does

Each customer is a **tenant**: an isolated slice of the system holding that customer's evidence.
Inside a tenant there are contributors who upload evidence, tenant administrators who manage people,
and — importantly — **external auditors**. An auditor does not work for the customer. They need to
read a narrow slice of data for a few weeks, and then their access must expire on its own.

Above all of that sits a **platform admin** console used by our own staff, which can see across
every tenant at once.

That combination is why the security work here is interesting rather than ceremonial:

<div class="grid" markdown>

<div class="card" markdown>
**Untrusted insiders**

Third-party auditors hold real credentials but sit outside the customer's network and outside their
management. Nobody can vouch for the laptop they are using.
</div>

<div class="card" markdown>
**A boundary that must not break**

If one tenant can read another tenant's evidence, the product is finished as a business. There is no
partial credit for this failure.
</div>

<div class="card" markdown>
**A genuinely high-value target**

Platform admins can reach every tenant at once. Their accounts deserve a different standard from
everyone else's, and they get one.
</div>

</div>

## The one-sentence version

> Sign-in is replaced with passkeys so that phishing stops working; every request afterwards is
> judged on its own merits by a policy engine rather than trusted because it arrived with a valid
> token; and the keys protecting the most powerful accounts must be physical hardware whose
> genuineness the server can actually check.

## How to read this

The pages are in reading order. If you read them top to bottom you will have the whole picture
without following a single link.

| Page | What it covers |
|---|---|
| [The problem it removes](problem.md) | Why passwords fail, and why most multi-factor authentication does not fix it |
| [The big picture](zero-trust.md) | What Zero Trust means here, and how the system is divided |
| [Sign-in, end to end](passwordless.md) | The passkey ceremony, and how we require real hardware keys |
| [After sign-in](sessions.md) | Token binding, per-request policy, and keeping tenants apart |
| [Recovery, the weak link](recovery.md) | Where attackers go once the front door is locked |
| [Running the identity provider](operating.md) | The operational burden we deliberately took on |
| [Limits and non-goals](limits.md) | What this does not do, and the risks we accept |

Then, for the parts that separate design from wishful thinking:

| Page | What it covers |
|---|---|
| [What we tested](verification.md) | The experiments, the results, and what is still unproven |
| [Decisions and why](decisions-guide.md) | Each significant choice, the alternatives rejected, and its cost |

And for reviewers who need precision rather than narrative, the engineering documents are rendered
here in full under **Reference**: the [plan](plan.md), the
[identity configuration](identity.md), [sessions and authorization](authorization.md), the
[threat model](threat-model.md), and the [decision register](adr.md).

## A note on how these pages are built

They are generated from Markdown by `scripts/build_docs.py`, and the output is committed. That means
the prose you are reading and the engineering documents are the same source of truth rather than two
copies that drift apart. The pages are self-contained: no server, no build step, no network. You can
open one from a folder, email it, or read it years from now.

Search works offline too. It uses a small index generated from these pages and committed alongside
them; a check fails the build if that index ever goes stale.
