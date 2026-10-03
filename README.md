# Attest — Zero Trust Compliance Evidence Platform

A multi-tenant B2B SaaS application built on Zero Trust principles, with **passwordless,
phishing-resistant authentication** (FIDO2/WebAuthn passkeys) as its identity foundation.

> **Status: design complete. Six verification experiments run — three hold, one holds for Chromium
> only, one failed, and one resolved by rejecting the mechanism it tested. No production code yet.**
> MIT licensed.
>
> **The authoritative summary of what is and is not established is [EVIDENCE.md](EVIDENCE.md).** It
> records every load-bearing claim with its evidence and a confidence level, and names the places
> where we are **not** certain. Where any other document states something more strongly than that one
> records it, that one is right.

> ### 🔄 Starting a fresh session, or picking this up cold?
>
> Read **[HANDOFF.md](HANDOFF.md)** first, then run **`scripts/status.sh`**.
>
> The handoff explains what the project is, what is *proven* versus merely *designed*, what to do
> next, the conventions to follow, and a list of hard-won facts that will otherwise cost you real
> time. The status script prints the actual current state, so you do not have to take the document's
> word for it.
>
> Work is split into numbered slices in **[WORK.md](WORK.md)**. To choose what happens next, reply
> with a slice number (for example `S4`) — nothing else is needed.

## 📖 Start with the documentation site

Open **[`docs/site/index.html`](docs/site/index.html)** in a browser — no server, no build step, no
network required. Or serve it:

```bash
scripts/docs.sh serve        # http://localhost:8082
```

The site is the primary way to read this project. It has offline search, a light and dark theme, and
is organised into three parts:

| Part | Pages | For |
|---|---|---|
| **Guide** | What this is · The problem it removes · The big picture · Sign-in, end to end · After sign-in · Recovery, the weak link · Running the identity provider · Limits and non-goals | Anyone. Written in plain language, no prior knowledge assumed. |
| **Evidence** | What we tested · Decisions and why | Reviewers who need to know what has actually been demonstrated. |
| **Reference** | Architecture and plan · Identity in detail · Sessions and authorization · Threat model · Decision register · Lab results | Engineers who need precision. |

If you read one page, read **[What we tested](docs/site/verification.md)** — it is where the security
claims are either supported by an experiment or explicitly marked as unproven.

## The product, in one paragraph

**Attest** lets regulated companies collect, review, and prove compliance evidence (SOC 2,
ISO 27001, etc.). Each customer is a **tenant**. Inside a tenant there are contributors, tenant
admins, and — importantly — **external auditors** who get time-boxed, read-only access scoped to
a single engagement. Attest staff hold a separate, far more privileged **platform admin**
console. That mix (untrusted third parties, cross-tenant boundaries, and a high-privilege
operations surface) is exactly the shape where Zero Trust earns its keep rather than being
architecture theatre.

## Stack

| Layer | Choice | Why |
|---|---|---|
| **Identity** | **Keycloak 26.8**, self-hosted on ECS Fargate + RDS Postgres Multi-AZ | Native DPoP, native passkeys, and an **AAGUID allowlist** — the capability that makes hardware-key enforcement real rather than approximate. See [ADR-001](docs/decisions.md) |
| **Edge** | CloudFront + AWS WAF + ALB | WAF in front of the identity provider; TLS termination |
| **API** | API Gateway HTTP API + Lambda authorizer | DPoP proof verification happens here — Keycloak is not in the request path for our API |
| **Policy** | Amazon Verified Permissions (Cedar) | Fine-grained, auditable, policy-as-code tenant isolation |
| **Data** | DynamoDB (tenant-partitioned) + S3 with Object Lock | Evidence storage and tamper-evident audit |
| **AWS control plane** | IAM Identity Center + FIDO2 security keys | Deliberately **outside** Keycloak — see ADR-009 |

**Why Keycloak rather than a managed cloud IdP:** Keycloak 26.4 shipped official support for both
[DPoP](https://www.keycloak.org/2025/10/dpop-support-26-4) and
[passkeys](https://www.keycloak.org/2025/09/passkeys-support-26-4), and its realms support an
**acceptable-AAGUID list** — the exact capability the managed provider lacked. That removes the
largest piece of custom code and upgrades the privileged-access guarantee from an unverified
heuristic to an enforced control. The price is that **we operate the identity provider**; see
[Running the identity provider](docs/src/operating.md) and risk R1 in the plan.

## Repository layout

```
docs/
  src/            Markdown sources for the Guide and Evidence pages  ← edit these
  site/           GENERATED documentation site (committed, do not edit by hand)
  *.md            The engineering documents (also rendered into the site)
  decisions/…     ADR sources
lab/keycloak/     Verification lab: Keycloak + Postgres in containers, plus the test scripts
scripts/          build_docs.py, check_docs.py, docs.sh
tools/            Build-time Node helpers (Mermaid → SVG, screenshots)
```

## Working on the documentation

The site is **generated from Markdown and committed**, so reading it never requires a toolchain. The
same discipline as a generated lockfile: the artifact is checked in, and a check fails if it drifts.

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements-docs.txt

scripts/docs.sh build        # regenerate docs/site/ from the Markdown
scripts/docs.sh check        # links, anchors, offline-safety, freshness
scripts/docs.sh all          # diagrams + build + check
```

Diagrams are rendered at build time to inline SVG, so readers download no JavaScript. That step needs
Node:

```bash
cd tools && npm install      # mermaid + puppeteer-core (uses your system Chrome)
node tools/render_diagrams.mjs
```

If diagrams have not been rendered the build still succeeds, showing a visible notice in place of the
diagram rather than failing.

## Environment notes

Verified on this machine:

| Tool | Version / status |
|---|---|
| Node | v24.20.0 |
| Python | 3.14.7 |
| AWS CLI | 2.36.24 — **credentials expired** (`aws login` required) |
| Docker | 29.7.2 — required for the verification lab and CDK Lambda bundling |
| Keycloak | lab running locally: `quay.io/keycloak/keycloak:26.8.0` + Postgres 17 |

Three environment quirks worth knowing before you start:

- **`~/.npm` and `~/.cache/pip` are root-owned** and not writable here. Both toolchains redirect to
  a workspace-local cache (`.npm-cache/`) or a workspace venv. If you install packages, expect to do
  the same.
- **Chrome needs `--no-sandbox`** when launched from this environment, because its own sandbox cannot
  initialise. The tools here already pass that flag.
- **Keycloak 26.8.0 is current**, not the 26.6 the plan originally pinned. Version drift is real;
  re-check before each deploy.

## The verification lab

The credentials in the lab are **intentionally obvious and hardcoded** (`lab-only-not-a-secret`). It
is a throwaway environment on `localhost` that is recreated from scratch by the scripts that use it,
so managing them as real secrets would add setup friction and hide the fact that they are not real.
See [SECURITY.md](SECURITY.md) before reporting anything.

```bash
cd lab/keycloak
docker compose up -d
python3 scripts/configure-realms.py    # apply WebAuthn policies, and assert they persisted
bash scripts/run-matrix.sh             # the enforcement matrix
```

Results and method: [Lab results](lab/keycloak/SPIKE-3-RESULTS.md) or the
[rendered version](docs/site/lab-results.html).
