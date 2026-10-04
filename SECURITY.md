# Security policy

## Status: pre-production

**There is no deployed system.** This repository contains a design, a documentation site, and a local
verification lab. Nothing here is running in production, and no customer data exists.

That matters for how you read anything you find: a weakness in the *design* is useful and welcome. A
weakness in *running code* is not applicable yet, because there is no running code.

## Reporting something

Please open a [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
rather than a public issue, so it can be looked at before it is widely known.

Because this is a design document as much as a codebase, reports are just as welcome in the form of
*"this claim is wrong"* or *"this control does not do what the documentation says"*. Several of the
findings already recorded in `lab/*/SPIKE-*-RESULTS.md` came from exactly that.

## What is NOT a vulnerability

### The lab credentials are generated, not secrets

The lab needs credentials, and they are **generated on first use** rather than committed. They live in
`lab/.env`, which is gitignored:

```
LAB_KEYCLOAK_ADMIN_PASSWORD=<generated>
LAB_POSTGRES_PASSWORD=<generated>
LAB_APP_DB_APP_PASSWORD=<generated>
```

The compose files read them through `scripts/lab.sh`, which is the only thing that knows where the
file is.

**This changed, and the reason is worth stating.** The lab previously hardcoded a single placeholder
password in twenty-odd files. It was not a secret — it belonged to a Keycloak container that lived for
one test run on `localhost` — but **a password literal in a public repository is a password literal in
a public repository**, and GitHub's secret scanning flagged it. The scanner was right: its job is to
find `password: "..."`, and a scanner that excused a value because it contains the words "not a
secret" would be a worse scanner.

Generating the value removes the literal, gives each checkout a unique credential, and keeps the
scanner's output worth reading.

**None of this makes the lab secure, and it is not claimed to.** The credential still travels over
plain HTTP on loopback, is still shared by every process in the lab, and is still not worth
protecting. It is now *generated* rather than *published* — a hygiene fix, not a security one.

**Please do not report lab credentials.** If you find a credential that is *not* covered by this
section — one that looks like it could work against a real system — that is worth reporting
immediately.

### The threat model lists real weaknesses

`docs/threat-model.md` and the *What we tested* page document attacks that are **not** defended
against, and claims that are **not** verified. That openness is the point of the project, not an
oversight. A documented gap is a known gap.

The most useful example: `lab/keycloak/SPIKE-5-RESULTS.md` records an experiment that **failed** —
the step-up mechanism did not work — and the documentation says so plainly, everywhere it is
relevant.

## How this project tries to earn trust

The convention throughout is that a claim is only stated as fact once an experiment has demonstrated
it, and that experiments include a **control** that must fail for the result to mean anything. Where
something is designed but untested, the documentation says so in the same sentence.

If you find a place where that convention has slipped — a claim stated as settled that no experiment
supports — that is a genuine and useful report.
