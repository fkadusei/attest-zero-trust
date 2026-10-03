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

### The lab credentials are deliberate, and are not secrets

You will find hardcoded credentials in the lab, such as:

```yaml
# lab/keycloak/compose.yaml
KC_BOOTSTRAP_ADMIN_PASSWORD: lab-only-not-a-secret
```

These are **intentionally** hardcoded and **intentionally** obvious. The lab is a throwaway
environment that binds to `localhost` only, it is recreated from scratch by the scripts that use it,
and its whole purpose is to be torn down and rebuilt. Managing them as real secrets would add setup
friction and hide the fact that they are not real.

**Please do not report them.** If you find a credential that is *not* obviously a lab placeholder —
that is, one that looks like it could work against a real system — that is worth reporting
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
