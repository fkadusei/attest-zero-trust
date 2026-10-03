# Decisions, Open Questions, and Verification Spikes

**Read this document first, even though it is listed last.** It contains the things that must be
tested before the design is frozen, and several of them can change the architecture.

> **Revision note:** ADR-001 has been superseded — the identity plane moved from Amazon Cognito to
> self-hosted Keycloak. One spike from the previous revision is now **dissolved** (see Part 3), and
> four new ones were added.

---

## Part 1 — Architecture Decision Records

### ADR-001 — Use self-hosted Keycloak as the identity provider (supersedes Cognito)

**Status:** Accepted — **supersedes** the original "use Cognito" decision

**Context:** The plan originally targeted Amazon Cognito. Verification against the Cognito API
surface surfaced two limitations that drove real cost and real weakness:

1. **No DPoP support.** Cognito issues bearer tokens, and its pre-token-generation Lambda trigger
   cannot see the `DPoP` header, so sender-constraining could not be retrofitted
   ([AWS re:Post](https://repost.aws/ko/questions/QUBR16XQUAQZiFg1lpp0EDcA/dpop-support-for-aws-cognito)).
   This forced a custom token-issuing Session Broker — the largest and riskiest component in the
   plan.
2. **No AAGUID exposure.** `ListWebAuthnCredentials` returns `AuthenticatorAttachment` and
   `AuthenticatorTransports` but never the AAGUID
   ([API reference](https://awscli.amazonaws.com/v2/documentation/api/2.32.18/reference/cognito-idp/list-web-authn-credentials.html)).
   Device-bound enforcement for privileged users could therefore only be *approximated*.

Keycloak 26.4 shipped official support for both [DPoP](https://www.keycloak.org/2025/10/dpop-support-26-4)
and [passkeys](https://www.keycloak.org/2025/09/passkeys-support-26-4), and its WebAuthn policies
expose an **acceptable-AAGUID list**.

**Decision:** Self-host **Keycloak 26.4+** as the identity provider, replacing Cognito.

**Consequences — good:**

- Native DPoP removes the token-issuing broker — the original plan's single largest risk.
- The AAGUID allowlist turns privileged device-bound enforcement from an unverified heuristic into a
  control **enforced at registration**. This is a genuine security improvement, not just a
  simplification, and it is the strongest single argument for the switch.
- Passkeys are GA with no tier gating, plus a "Conditional - credential" authenticator that
  implements correct AAL reasoning.
- ACR → Level of Authentication mapping makes step-up standards-based and IdP-issued, resolving an
  open question in the original plan.
- Cost becomes **fixed and MAU-independent** rather than per-user.
- Keycloak's federation support makes customer SAML/OIDC federation nearly free (open question Q2).

**Consequences — bad:** *(this is the honest half)*

- **We operate the identity provider.** HA, Postgres backups, disaster recovery, and prompt CVE
  patching of an internet-facing authentication service become our ongoing responsibility (T15, T16,
  R1). Budgeting engineering time for this is not optional.
- **We lose managed risk-based adaptive authentication.** Cognito Plus provided breached-credential
  blocking and adaptive MFA; Keycloak has no official equivalent (ADR-012 replaces it).
- Custom SPIs become an upgrade-compatibility liability (R6).
- Compliance claims must be re-derived; Cognito's shared-responsibility posture was simpler to
  evidence.

**Alternatives rejected:** Stay on Cognito (rejected: would keep the custom broker and the
approximate authenticator policy). Build a FIDO2 server directly (rejected: larger and riskier
custom surface, and a relying-party-validation bug degrades phishing resistance silently). Use
another OSS IdP such as Ory or Authentik (rejected: Keycloak has the specific combination we need —
GA DPoP, passkeys, and AAGUID allowlist — plus the largest operational community).

---

### ADR-002 — Two realms, split by assurance level

**Status:** Accepted

**Context:** Platform admins need stronger authentication than customers, and their accounts are far
more valuable.

**Decision:** `attest-users` (password + passkey, unrestricted authenticators) and
`attest-privileged` (passkey only, AAGUID allowlist, `userVerification: required`), with different
relying party IDs.

**Consequences — good:** Distinct assurance policies enforced by realm *configuration* rather than
by conditional application logic — and application logic is where such rules silently regress. A
regression here would mean a platform admin authenticating at the customer assurance level unnoticed
(T17). Separate realms also mean separate signing keys and session state, so compromising the
customer realm grants nothing in the privileged realm (B7).

**Consequences — bad:** Staff who are also customers hold two identities. Two realm configurations
to maintain and keep in sync. Two recovery procedures.

**Alternatives rejected:** One realm with roles and conditional flows (rejected: assurance becomes
application logic). Three or more realms per customer tier (rejected: operational cost without a
corresponding threat).

---

### ADR-003 — AAGUID allowlist and cross-platform attachment for privileged enrolment

**Status:** Accepted — **VERIFIED by Spike #3** against Keycloak 26.8.0
([results](../lab/keycloak/SPIKE-3-RESULTS.md)). Enforcement is real, not aspirational.

**Context:** A synced passkey is phishing-resistant but moves the trust root from the device to the
user's cloud account. NIST SP 800-63Bsup1 exists precisely because syncable authenticators change the
assurance calculus. Privileged users must not be reachable via a synced credential.

**Decision:** On `attest-privileged`, set `authenticatorAttachment: cross-platform`,
`attestationConveyancePreference: direct`, and a non-empty **`acceptableAaguids`** allowlist of
approved hardware authenticators. Synced platform passkeys **cannot be registered**.

**Consequences — good:** Enforcement at registration rather than inference after the fact. It also
makes passkey-only sign-in a defensible claim of genuine multi-factor authentication for privileged
users: possession of the hardware authenticator *plus* user verification. Combining attachment and
AAGUID is stronger than either alone — attachment alone admits some non-hardware cross-platform
authenticators, and AAGUID alone would require enumerating every model we reject.

**Consequences — bad:** **Allowlist maintenance is an operational duty.** New hardware models have
new AAGUIDs; an unmaintained allowlist locks users out, and an allowlist "fixed" under pressure with
a wildcard silently voids the control. Staff must carry a security key. We also trust Keycloak's
enforcement and the authenticator's attestation statement rather than independently validating FIDO
metadata — a plausible future enhancement, but out of scope, and the assurance claim must not imply
it.

**Alternatives rejected:** Synced passkeys for everyone (rejected: weakens the highest-value accounts
to the level of a consumer cloud account). Device-bound for all users (rejected: unacceptable UX and
support cost for customers). **Fallback if Spike #3 fails:** fall back to attachment restriction and
document the weakened claim — or, better, treat a failed allowlist as a blocker rather than shipping
a privileged-access claim resting on a control that does not enforce.

---

### ADR-004 — No custom token-issuing broker; a thin DPoP Verifying Authorizer at the API

**Status:** Accepted

**Context:** Under Cognito we had to issue our own DPoP-bound tokens. Keycloak issues bound tokens
natively, which raises the question of whether any custom component remains.

**Decision:** Let Keycloak issue and bind tokens. Build a **narrow API Gateway Lambda authorizer**
that verifies DPoP proofs on requests to **our** API, and nothing else.

**Consequences — good:** The largest and riskiest component of the original plan (the Session
Broker) is largely eliminated. What remains is small, well-specified, testable, and — critically —
**not novel cryptography**: verification of an existing RFC, with libraries available. Removed
entirely: token issuance, session storage, refresh rotation, nonce management, and key distribution.

**Consequences — bad:** A subtle and serious failure mode is now available: **believing Keycloak's
DPoP support secures our API.** Keycloak verifies proofs at *its own* token endpoint and is not in
the request path for our API. Without resource-server verification, our API accepts a stolen token
that merely *advertises* a binding nobody checks — worse than no DPoP, because it creates false
confidence. This is risk R2 and the reason Phase 2 exists as an explicit deliverable with a replay
test (S3).

**Alternatives rejected:** Rely on Keycloak's DPoP alone (rejected: verifies nothing about our API's
requests). Keep the full Session Broker anyway (rejected: reimplements a solved problem and keeps the
risk for no benefit). Token introspection per request instead of DPoP (rejected as a *substitute*:
introspection proves the token is live, not that the caller holds the key; it remains useful for
revocation).

---

### ADR-005 — Retain Amazon Verified Permissions (Cedar); reject Keycloak Authorization Services

**Status:** Accepted, **pending Spike #2**

**Context:** With Keycloak in place, its built-in Authorization Services (UMA 2.0) become an option,
raising the question of whether to consolidate on one system.

**Decision:** Keep Cedar policies in Amazon Verified Permissions. Do not adopt Keycloak
Authorization Services.

**Consequences — good:** Cedar was designed for formal analysis, which is what a tenant-isolation
boundary deserves. We retain policies-as-code, a CI coverage gate, and an auditable decision log.
Most importantly, **the PDP is decoupled from the IdP**, so a future identity migration does not
rewrite authorization — a lesson that just paid off once already.

**Consequences — bad:** A second system to operate and authenticate against. `IsAuthorizedWithToken`
may not accept Keycloak tokens (Spike #2), requiring an explicit-principal call path. Slightly more
integration glue than a consolidated IdP-plus-authorization stack.

**Alternatives rejected:** Keycloak Authorization Services (rejected: UMA 2.0 is widely regarded as
clunky, and its policy model is weaker for per-resource tenant isolation — the one thing we cannot
get wrong). OpenFGA (rejected for now: genuinely attractive and portable, but adds a new PDP to learn
and operate without a compelling advantage over a working Cedar design).

---

### ADR-006 — Tenant isolation as a fail-closed `forbid`, with tenant ID sourced only from the token

**Status:** Accepted

**Context:** Cross-tenant access (A1) is the catastrophic outcome. A single policy error must not be
sufficient to cause it.

**Decision:** Two rules. (1) A Cedar `forbid` on tenant mismatch, which cannot be overridden by any
`permit`. (2) The tenant ID is read **only** from cryptographically verified token claims, never from
request input.

**Consequences — good:** Fails closed by construction. A future developer cannot accidentally open the
boundary by adding a broad `permit` — `forbid` always wins in Cedar. Rule (2) eliminates the whole
class of "IDOR by trusting a parameter".

**Consequences — bad:** Legitimate administrative cross-tenant flows require an explicit audited
action rather than falling out of a general permit. Intentional friction.

**Alternatives rejected:** Tenant isolation as a `when` clause on each `permit` (rejected: one
careless new policy reopens the boundary). Row-level security in the data layer only (rejected: S5
requires two independent layers).

---

### ADR-007 — Native Keycloak passkeys with conditional UI; no custom ceremony

**Status:** Accepted

**Context:** Passkeys can be driven through Keycloak's built-in flows or implemented against the
`USER_AUTH`-equivalent surface with a custom UI.

**Decision:** Use Keycloak's native passkeys with both **conditional UI** (autofill) and **modal UI**,
and rely on the built-in **"Conditional - credential"** authenticator to skip a second factor when a
passkey was the primary credential.

**Consequences — good:** No browser-flow changes are required, and the subtle AAL logic — including
the case where the user authenticated with a password instead — is owned by the IdP rather than by
us. Hand-rolling a WebAuthn ceremony is the classic way to introduce a relying-party-validation bug
that silently degrades phishing resistance while appearing to work. Both UI modes supported maximises
compatibility: conditional UI for modern password managers, modal UI for hardware keys requiring a
PIN or touch.

**Consequences — bad:** Less control over branding and layout. Stock login screens are recommended
anyway (custom themes carry real upgrade cost and are a non-goal).

**Alternatives rejected:** Custom passkey UI (rejected: reimplements a ceremony we would have to
maintain across Keycloak upgrades). Conditional UI only (rejected: hardware keys need the modal
path).

---

### ADR-008 — Single DynamoDB table with a tenant partition key (pool model)

**Status:** Accepted — unchanged from the original plan

**Context:** Tenant isolation can be siloed (per-tenant tables/stacks) or pooled (shared tables with
tenant-keyed access).

**Decision:** Pooled — a single table with `tenant_id` in the partition key, isolation enforced by
Cedar and the data-access layer.

**Consequences — good:** Operationally tractable at scale. Onboarding a tenant is a data operation,
not an infrastructure deployment. Cost scales with usage rather than tenant count.

**Consequences — bad:** Isolation is a **logical** boundary enforced by code and policy, not a
physical one. There is no infrastructure-level guarantee that a bug cannot cross tenants. This makes
ADR-006's two rules and the L4 test suite load-bearing rather than belt-and-braces.

**Alternatives rejected:** Silo per tenant (rejected for now: strong isolation, operationally and
financially painful at hundreds of tenants). **Revisit trigger:** a contractual requirement for
physical isolation — then silo the highest-value tenants individually while the rest stay pooled.

---

### ADR-009 — AWS management plane uses IAM Identity Center, entirely outside Keycloak

**Status:** Accepted — unchanged from the original plan, and now more important

**Context:** The AWS account is the true crown jewel — it contains all tenants' data and, now, the
Keycloak deployment itself. Keycloak governs access to *Attest's application*; it does not govern
access to *AWS*.

**Decision:** Human AWS access via IAM Identity Center with FIDO2 security keys and no password
fallback. Programmatic access via OIDC role assumption. No IAM users, no long-lived keys.

**Consequences — good:** The crown jewel is protected by a control independent of our own IdP. There
is no path from a compromised Attest session — **or a compromised Keycloak** — to AWS infrastructure.
This separation now also limits the blast radius of T15.

**Consequences — bad:** Two identity systems to operate and explain. Staff need security keys for
both. Break-glass must be provisioned and tested separately.

**Note:** Conflating these planes is a serious architectural error — "we have passkeys, so our
infrastructure is protected" is false, and it is now false in a more dangerous way, because a
compromised Keycloak would otherwise be a path to the AWS account.

---

### ADR-010 — Self-host Keycloak on ECS Fargate + RDS Postgres Multi-AZ

**Status:** Accepted, with a documented fallback

**Context:** Keycloak can be self-hosted (ECS, EKS, EC2), consumed as a managed service (Phase Two,
Cloud-IAM, Skycloak), or deployed on-premises.

**Decision:** Self-host on **ECS Fargate + RDS Postgres Multi-AZ + ALB**, with RDS Proxy, secrets in
Secrets Manager, and tasks in private subnets behind an ALB security group.

**Consequences — good:** Everything stays in one AWS account and one IaC codebase. No per-MAU cost —
cost is fixed and predictable. Full control over version, extensions, and tuning. Avoids introducing
Kubernetes purely to run one stateful service.

**Consequences — bad:** **We own HA, backups, DR, and CVE patching** (T15, T16). Fargate has no
Kubernetes DNS, so Keycloak's Infinispan clustering needs a JDBC-based discovery stack (Spike #7) —
this is a real, non-obvious operational detail. ALB idle timeouts and reverse-proxy configuration
must be right or issuer URLs break confusingly. RDS is a single point of failure if Multi-AZ
failover is untested.

**Alternatives rejected:** Managed Keycloak (rejected **for now**: recurring cost, and the
reference-implementation goal favours a self-contained deployment — **but this is the documented
escape hatch**). EKS (rejected: adds significant platform surface to run one service). On-premises
(rejected: no requirement, and it would add a second operating environment).

**Revisit trigger:** inability to meet the 48-hour patch SLA (S11), or sustained IdP operational
incidents → migrate to managed Keycloak. Because Keycloak is a standard OIDC provider and realm
config is declarative (ADR-011), this migration is tractable: point the clients at a new issuer,
import the realm, and re-register passkeys. Passkey re-registration is the painful part and should be
factored into any migration estimate.

---

### ADR-011 — Realm configuration as code, applied by CI

**Status:** Accepted

**Context:** Keycloak realm configuration (realms, clients, WebAuthn policies, flows, required
actions, AAGUID allowlist, DPoP flags) can be managed via the Admin Console, the Admin REST API, or
declaratively.

**Decision:** All realm configuration is declarative and applied by **keycloak-config-cli** in CI.
Console-only changes are prohibited (S12, threat T17).

**Consequences — good:** The environment is reproducible from an empty realm. Configuration changes
are reviewable, diffable, and revertible. **It substantially reduces the admin-API attack surface**,
because no human has routine administrative need (B9, T15). It enables the CI regression guards that
keep S1 and ADR-003 from silently regressing.

**Consequences — bad:** A learning curve, and some settings are awkward to express declaratively. It
requires discipline: one console click breaks the guarantee. It also introduces a bootstrap ordering
problem — CI needs admin credentials to configure the realm it is hardening, so those credentials
must be tightly scoped and rotated.

**Alternatives rejected:** Admin Console only (rejected: unreproducible, and the most likely route to
T17). Keycloak Terraform provider (a reasonable alternative — Terraform is already installed locally
— at the cost of running two IaC tools alongside CDK). Realm export/import snapshots in git
(rejected: coarse, not diff-friendly, poor at incremental change).

---

### ADR-012 — Replace managed threat protection with custom authenticators and native events

**Status:** Accepted

**Context:** Cognito's Plus tier provided breached-credential blocking and risk-based adaptive
authentication as managed features. Keycloak provides **neither** as an official capability. This is
the principal capability lost by the OSS switch.

**Decision:** Build the substitute:
1. **Breached-password check** via a custom Authenticator SPI at registration and password change
2. **Risk-based step-up** via a custom Conditional authenticator that consults our Risk service and
   forces an elevated `acr` or denies
3. **Native brute-force detection**, enabled and tuned strictly
4. **Keycloak events** shipped to CloudWatch/EventBridge for detection rules

**Consequences — good:** Java SPI work is real but bounded, and it is *our* policy rather than a
vendor's opaque scoring — we can see and tune exactly why a login was challenged. Keycloak's event
system exposes **more** raw authentication detail than Cognito's managed threat protection did, so
detection can end up genuinely better.

**Consequences — bad:** This is the main **added build cost** of the OSS route, and it lands in
Phase 4 — precisely when teams are running out of momentum. Custom SPIs must be compatibility-checked
on every upgrade (R6). Our risk scoring will initially be worse than a mature managed engine, and it
must be treated as a security-critical component with its own review and tests, not as application
code.

**Alternatives rejected:** Accept the loss and rely on brute-force detection alone (rejected: leaves
T2-adjacent risk signals unaddressed for the customer realm, which still has passwords). Buy a
third-party risk engine (deferred: plausible once scale justifies it; the SPI boundary keeps that
option open, which is itself an argument for building the integration behind an interface).

---

### ADR-013 — Reject ACR/LoA-based step-up; force re-authentication and verify `auth_time`

**Status:** Accepted

**Context:** The plan assumed step-up authentication would work through Keycloak's ACR → Level of
Authentication mapping, with elevation becoming an IdP-issued, token-carried fact. S5 tested that
assumption and it failed: a subflow configured to require a second factor at level 2 executed
regardless of the level requested, or of nothing being requested.

S5b then found the decisive fact. The component involved — `ConditionalLoaAuthenticator` in
`keycloak-services` — carries **CVE-2026-97176**, published 2026-09-23, nine days before our test:

- **An authenticated user with a low-level session can obtain a token asserting a higher level than
  they actually performed.**
- Fix state: **Affected**. Mitigation: **"not available"**.
- The exact package (`org.keycloak.keycloak-services-26.8.0.jar`) ships in our build.

**Decision:** Do **not** build step-up on ACR/LoA. Force a genuine re-authentication with
`prompt=login` plus `max_age=0`, and evaluate **freshness** using the `auth_time` claim — never the
`acr` claim.

**Consequences — good:** The bypass is avoided entirely rather than mitigated. `auth_time` records
when authentication actually happened, so it is unaffected by a flaw in how a *level* was computed.

!!! warning "Corrected by S5c — the strength argument does not hold yet"

    This record originally claimed that *"for the privileged realm, re-authentication means a fresh
    hardware-key assertion, so freshness and strength come from the same act."*

    **That is false as the realm is currently configured.** S5c read the privileged browser flow and
    found a `Username Password Form` still present, with WebAuthn only as a conditional second
    factor. So re-authentication there can be **a password**, not a hardware-key assertion.

    Forcing re-authentication therefore gives us **freshness** — which S5c verified as a working
    control, 14/14 with its controls — and **not strength**. The two come from the same act only once
    the flow requires a passkey.

    **S5d did that flow work and tested it (12/12).** The privileged realm is passkey-only *when the
    configuration is applied*: it is applied on demand, because `attest-privileged` is a shared lab
    fixture that S3's matrix signs into with a password.

**The generalisable finding from S5d — and it is not specific to step-up:**

> **A passkey-only browser flow does not make a realm passkey-only.** Direct grants at the token
> endpoint bypass the browser flow entirely. `admin-cli` is created by Keycloak in **every** realm,
> is public, and accepts them by default — so a realm can refuse passwords at the login page and still
> issue tokens for one.

It was found only because a negative test was paired with its positive: the bypass check passed at
first, but only because the password was unknown. See `EVIDENCE.md` §5.9 and §5.10.

**Consequences — bad:** A full re-authentication is a blunter experience than a targeted step-up, and
on the customer realm it proves freshness plus whatever strength that realm's policy provides — which
must be stated plainly rather than implied. This is custom work the IdP would otherwise have owned.

**The rule this establishes:** a claim the issuer *writes* is not a claim the resource server can
*rely on* without checking. This is the same lesson as DPoP in S1, and it is now written down twice
because we have now learned it twice.

**Verified by:** S5c — `prompt=login` forces a genuine ceremony despite a live session, `auth_time`
advances and does not retroactively change, and the freshness policy refuses stale and
freshness-less tokens. 14/14 checks, and the gate is negative-tested.

**Alternatives rejected:** LoA-based step-up (rejected: live unmitigated CVE, and the mechanism did
not gate in testing either). Application-side step-up with a fresh WebAuthn assertion verified by our
own API (rejected *for now*: more custom security code, and `prompt=login` already yields a fresh
passkey assertion on the privileged realm). Second-approver workflow instead of step-up (still used
for the highest-risk operations, but it answers a different question).

**Revisit trigger:** an upstream fix for CVE-2026-97176 — and only on the evidence of a test that
**tries to exploit the bypass**, not on the existence of a patch note.

---

## Part 2 — Open questions requiring a human decision

These are not research tasks. They need a stakeholder decision, and several affect cost or scope.

| # | Question | Why it matters | Default if unanswered |
|---|---|---|---|
| Q1 | Which AWS region(s), and is data residency (EU/UK) required? | Determines RDS, AVP, and data topology. Retrofitting residency is expensive, and self-hosted Keycloak makes it *easier* than a managed IdP would | Single region, `us-east-1` |
| Q2 | Must customers federate their own SAML/OIDC IdP? | Now nearly free with Keycloak — a genuine benefit of the switch. Changes the principal model | No federation in v1, but design for it |
| Q3 | Is device-bound required for **all** users, or only privileged? | Large UX and support-cost difference; follows ADR-003 | Privileged only |
| Q4 | Is a formal AAL2/AAL3 claim needed for procurement, or is "phishing-resistant MFA" sufficient? | Determines how hard Spike #6 must be pushed | Phishing-resistant MFA as the claim |
| Q5 | Target MAU at 12 and 36 months? | Needed to answer the break-even question against Cognito's per-MAU pricing | Unknown — cost comparison unmodelled |
| Q6 | Do human users need non-browser access (CLI, scripts)? | DPoP in a CLI is a different key-storage problem | Browser only |
| Q7 | Who performs identity proofing for a locked-out external auditor? | Recovery is the most likely bypass (T8); auditors have no HR relationship with us | Tenant admin vouches, Attest verifies |
| Q8 | Is platform-admin impersonation required at all? | Highest-risk feature in the product | Not in v1 |
| **Q9** | ~~Can the team commit to a 48-hour critical-CVE patch SLA (S11) and a rehearsed DR drill cadence?~~ | **DECIDED — self-hosting is the chosen path.** The 48-hour patch SLA (S11) and a rehearsed DR cadence are therefore accepted as **standing commitments**, not open questions | **Settled** |
| **Q10** | **Who owns Keycloak operations day to day (upgrades, backups, incidents)?** | Still open. This is the last thing standing between the plan and an unpatched, undocumented authentication service | **Must be named before go-live** |

**Q9 is settled: we self-host Keycloak.** That resolves the architecture — ADR-010 stands, and the
managed-service fallback is retained only as a documented escape hatch, not as a live alternative.

It also converts S11 from an aspiration into a standing commitment. A critical advisory must be
deployable within 48 hours, which means the upgrade path has to be **rehearsed**, not merely written
down; an untested patch procedure is a hope. **Q10 is now the only operational question left**, and it
matters because a commitment with no owner is not a commitment — it is an intention that decays
silently under the first week of pressure.

---

## Part 3 — Verification spikes

**These are unknown-unknowns, not implementation details.** Each must be tested before the design is
frozen. If a spike fails, an ADR changes.

> **Prerequisite:** `aws login` (credentials are expired), Docker running, and a local Keycloak
> container for spikes #3, #5, and #8.

### Dissolved since the previous revision

**~~Cognito feature-plan matrix and pricing (#7)~~ — DISSOLVED.** Keycloak has no feature tiers,
so the question "which plan enables passkeys / threat protection, and at what per-MAU price?"
no longer exists. The cost question is now a hosting-capacity question (PLAN §11) rather than a
tier-selection one. This is a genuine simplification of the plan.

---

### Spike #1 — DPoP end-to-end: issuance, verification, and header survival — **LOCAL HALF RESOLVED**

**Result: the binding is real, it is enforced, and the verification logic is prototyped and tested.**
Full write-up in [SPIKE-1-RESULTS.md](../lab/keycloak/SPIKE-1-RESULTS.md).

Established against Keycloak 26.8.0, using its own userinfo endpoint as a reference resource server:

- Keycloak writes `cnf.jkt` (plus a `kc-jkt-type: DPoP` marker) into bound tokens.
- **6/6 enforcement behaviours correct**: no proof → 401; `Bearer` scheme → 401; valid proof → 200;
  different key → 401; different path → 401; replayed `jti` → 401.
- **6/6 checks in our own verifier correct**, including refusing a proof minted for a different token.

Three implementation traps found, all of which would cost real debugging time:

1. **A bound token must use the `DPoP` authorization scheme, not `Bearer`.** The failure returns a
   `Bearer` challenge, pointing the investigation at the wrong layer entirely.
2. **A resource-server proof must carry the `ath` claim** (RFC 9449 §7.1). Omitting it yields
   `invalid_token: Token verification failed`, a message that mentions DPoP nowhere. Checking `ath`
   also closes a real gap: without it, a proof for one token would authorise another.
3. **Keycloak ignores the query string when comparing `htu`** *(observation)* — a proof for
   `…/userinfo?decoy=1` was accepted at `…/userinfo`. Our authorizer compares the full URI, which is
   deliberately stricter.

**Still open:** whether the `DPoP` header survives CloudFront → ALB → API Gateway. That needs
infrastructure, and a hop that strips it would break the binding silently — the exact trap this spike
exists to prevent. Browser-side key handling (Spike #4) and nonce behaviour are also unverified.

**Effort spent:** ~1 day.

---

### Spike #2 — Does AVP accept Keycloak-issued tokens?

**Question:** Will `IsAuthorizedWithToken` accept a **Keycloak** access/identity token, or must we use
`IsAuthorized` with an explicit principal built from verified claims?

**Why it matters:** Determines the whole Phase 3 integration shape, including how dynamic context
(`acr`, `step_up_age_seconds`, posture) reaches policy. This question existed in the Cognito plan and
remains unanswered — the issuer changed, not the uncertainty.

**How to test:** Create a policy store and a trivial schema. Register Keycloak as a supported OIDC
issuer and attempt `IsAuthorizedWithToken` with a real Keycloak token. Then implement the
`IsAuthorized` path with an explicit principal and confirm attributes flow into `context` and
`principal`.

**If it fails:** Use `IsAuthorized` with explicit principal and context — slightly more glue, no
change to the Cedar model. Note this is the *likely* outcome given our custom DPoP verification sits
in front.

**Effort:** 1 day. **Blocks:** Phase 3.

---

### Spike #3 — AAGUID allowlist enforcement semantics — **RESOLVED**

**Result: the control is genuinely enforced, and `direct` attestation is what makes it meaningful.**
Full matrix and method in [SPIKE-3-RESULTS.md](../lab/keycloak/SPIKE-3-RESULTS.md).

Established, in a controlled matrix with two controls:

- The **allowlist is enforced at enrolment** — a non-approved authenticator is rejected (B vs C).
- The **attachment restriction is enforced** (D vs E).
- **An authenticator that declines to attest is rejected**, not silently admitted — its all-zeros
  AAGUID does not match. This **disproves** the silent-bypass risk previously recorded in T3.
- **Keycloak exposes the AAGUID**, nested in `credentialData` — unlike Cognito, which exposed nothing.
- **Keycloak does not validate AAGUID format** (`"not-a-guid"` stored verbatim) → S12's CI gate must
  validate it.

**Unplanned and more important:** with `attestationConveyancePreference: "none"`, the AAGUID is
**self-asserted** (no attestation statement exists to verify it), so an allowlist under `none` is
weaker than it appears. Isolating the variable showed `direct` alone blocks enrolment for
non-attesting authenticators — an active requirement, not a preference. **Decision: keep `direct`
on `attest-privileged`**; it is the only configuration where the allowlist means what ADR-003 claims.

**Residual:** the acceptance path with a *physical* allowlisted key remains unproven, because a
virtual authenticator cannot attest. A hardware security key is still required to confirm the happy
path. Known failure mode is lockout, not bypass.

**Effort spent:** ~half a day.

---

### Spike #4 — Browser persistence of non-extractable DPoP keys

**Question:** Do non-extractable `CryptoKey` objects reliably survive in IndexedDB across browser
restarts in Safari, Chrome, and Firefox?

**Why it matters:** If key persistence is unreliable, users are signed out or forced to re-register a
key every session, and DPoP becomes a UX tax rather than a control. Safari's storage eviction policy
(7-day cap on script-writable storage in some contexts) is the specific concern.

**How to test:** Minimal page: generate a non-extractable P-256 key, store it in IndexedDB, restart
the browser, sign a proof. Test current Safari, Chrome, and Firefox on macOS, plus Chrome on Windows.
Test after clearing site data, in private mode, and after several days of inactivity in Safari.

**If it fails:** Define an explicit degraded mode — shorter session TTLs, stricter posture, more
frequent re-authentication — and document it. **Do not** silently fall back to unbound tokens, which
would quietly remove the S3 control while appearing to work.

**Effort:** 1 day. **Blocks:** Phase 2.

---

### Spike #5 — ACR step-up forces a fresh assertion

**Question:** Does requesting an elevated `acr_values` genuinely force a **fresh passkey assertion**,
or is the existing session accepted as already sufficient?

**Why it matters:** If the existing session satisfies the elevated ACR, step-up is a UI gesture and
elevation is not cryptographically meaningful — the same concern that made this an open question
under Cognito. It now has a better answer available (IdP-issued `acr`), but only if Keycloak actually
re-prompts.

**How to test:** Configure ACR → LoA mapping with two levels. Sign in at the base level, then request
the elevated level with `acr_values`. Observe whether Keycloak re-prompts for a passkey or returns
immediately. Confirm the resulting token's `acr` claim differs, and confirm the behaviour is the same
in the privileged realm.

**If it fails:** Step-up becomes a full re-authentication (log out and back in) — stronger but
slower. The UX consequence must be accepted explicitly rather than discovered in Phase 4.

**Effort:** 1 day. **Blocks:** Phase 4.

---

### Spike #6 — NIST SP 800-63Bsup1: exact consequence for our configuration

**Question:** What does [SP 800-63Bsup1](https://www.nist.gov/publications/incorporating-syncable-authenticators-nist-sp-800-63b)
require for a synced passkey used as a first factor, and does our `userVerification` setting change
the answer? Specifically: is passkey-only sign-in on the **privileged** realm (device-bound +
`userVerification: required`) defensible as multi-factor?

**Why it matters:** Determines whether we may claim AAL2 for standard users on synced passkeys, and
whether the privileged realm's passwordless design is defensible (Q4). This is the difference between
a compliance claim we can support and one we cannot.

**How to test:** Read the supplement against the current SP 800-63B-4 text; trace the clauses
governing syncable authenticators and user verification; map them to our exact configuration. **Then
have the conclusion reviewed by someone independent** — a compliance or security reviewer, not the
person who wrote the analysis.

**If it constrains us:** Either add a second factor for standard users on synced passkeys, or narrow
the public claim to "phishing-resistant MFA" without an AAL assertion. The privileged realm's
device-bound + UV configuration is the stronger position and should survive either way — which is
precisely why ADR-003 is worth the operational cost.

**Effort:** 0.5 day reading + 0.5 day independent review. **Blocks:** any compliance claim; not
implementation.

---

### Spike #7 — Keycloak clustering and session replication on ECS Fargate

**Question:** Can two or more Keycloak tasks form a working cluster on Fargate, given there is no
Kubernetes DNS for discovery? Does a JDBC-based ping stack work, and do sessions survive a task
replacement?

**Why it matters:** A single-task Keycloak is not a viable production target — it is a
single point of failure for all authentication. If clustering cannot be made to work on Fargate, the
hosting decision (ADR-010) changes. This is a **new** risk created by the self-hosting choice and it
has no analogue in the Cognito plan.

**How to test:** Deploy two Fargate tasks with a JDBC-based cache/discovery stack against RDS.
Verify: both nodes appear in the cluster; a session created on node A is usable on node B; killing
node A does not log users out; ALB health checks correctly drain an unhealthy node. Test with and
without ALB stickiness.

**If it fails:** Options include ALB sticky sessions (masks rather than solves), a shared external
cache, or revisiting the hosting decision toward managed Keycloak or EKS.

**Effort:** 1–1.5 days. **Blocks:** Phase 0/1. Must be resolved before Phase 1.

---

### Spike #8 — Revocation latency under 60 seconds

**Question:** Does the Keycloak event listener → EventBridge → DynamoDB revocation-set path deliver
end-to-end revocation in under 60 seconds, including cache TTLs?

**Why it matters:** Success criterion S6. Our authorizer validates JWTs statelessly, so without this
path, revocation is invisible to our API until the token expires. The read-through cache TTL
silently becomes the real revocation SLA, and caches tend to drift upward over time.

**How to test:** Implement a minimal event listener publishing logout/revocation events. Revoke a
session via the Keycloak admin API. Measure the time until a request with the revoked token is
denied by the authorizer, including cache behaviour. Test both the user-wide and single-session
revocation paths, and confirm the DPoP-failure alert path fires.

**If it fails:** Reduce cache TTL, switch to token introspection with a short cache for privileged
sessions, or accept and document a higher-than-60-second figure — but do not leave the actual number
unmeasured, because it will be assumed to be fast.

**Effort:** 1 day. **Blocks:** Phase 2.

---

## Part 4 — Spike summary

| # | Spike | Blocks | Effort | If it fails |
|---|---|---|---|---|
| 1 | DPoP end-to-end + header survival + issuer | ~~Phase 2~~ **part done** | ~1 d | **LOCAL HALF RESOLVED.** Still open: whether the `DPoP` header survives the edge |
| 2 | AVP accepts Keycloak tokens | Phase 3 | 1 d | Use `IsAuthorized` with explicit principal |
| 3 | AAGUID allowlist enforcement | ~~Phase 1~~ **DONE** | ~0.5 d | **RESOLVED — enforced.** Residual: physical-key happy path unproven |
| 4 | Browser key persistence | Phase 2 | 1 d | Documented degraded mode, shorter TTLs |
| 5 | ACR step-up forces fresh assertion | Phase 4 | ~1 d | **RESOLVED — does not work, and the component has an unmitigated CVE. See ADR-013** |
| 6 | NIST sup1 consequence | Compliance claim | 1 d | Second factor, or narrower public claim |
| 7 | Keycloak clustering on Fargate | Phase 0/1 | 1–1.5 d | Stickiness, external cache, or revisit hosting |
| 8 | Revocation latency < 60s | Phase 2 | 1 d | Shorter cache, introspection, or documented higher figure |

**Total: ~8–9 focused days.** Cheap relative to discovering any of these in production — and note
that three of the eight (#1, #7, #8) exist *because* we chose to self-host.

**Highest priority: #1, #7, and #3.** #1 and #7 are cheap to test and have severe failure modes
(silently broken binding; a single-point-of-failure IdP). #3 is the control the privileged-access
claim rests on.

**Dissolved:** the previous revision's #7 (Cognito feature-plan matrix and pricing) — Keycloak has no
tiers.

---

## Part 5 — What I could not verify

Stated explicitly so no one mistakes an assumption for a fact.

| Claim in this plan | Status |
|---|---|
| DPoP is officially supported in Keycloak 26.4+ | **Verified** — [Keycloak announcement](https://www.keycloak.org/2025/10/dpop-support-26-4); was preview since 23.0 |
| Passkeys are GA in Keycloak 26.4 with conditional + modal UI | **Verified** — [Keycloak announcement](https://www.keycloak.org/2025/09/passkeys-support-26-4) |
| A **"Conditional - credential"** authenticator skips 2FA when a passkey was used | **Verified** — stated in the 26.4 passkey announcement |
| Keycloak realms support an **acceptable-AAGUID list** | **Verified in the provider API surface** (a realm exposes "a set of AAGUIDs for which an authenticator can be registered"). **Enforcement semantics unverified — Spike #3** |
| Keycloak supports ACR → LoA mapping for step-up | **Verified as a documented server-administration capability**; whether it forces a *fresh* assertion is **Spike #5** |
| WebAuthn policy exposes attachment, user verification, and attestation conveyance | **Verified as the documented policy surface**; exact key names confirmed in Phase 0 |
| Keycloak has no official risk-based adaptive authentication equivalent to Cognito Plus | **Verified by absence** — no official feature found. Treated as a capability gap and mitigated by ADR-012 |
| Keycloak clustering on Fargate works via a JDBC ping stack | **Unknown — Spike #7.** Keycloak's cache configuration changed across 26.x releases |
| Keycloak revocation events reach our API in < 60s | **Unknown — Spike #8** |
| AVP accepts Keycloak-issued tokens | **Unknown — Spike #2** |
| Browser non-extractable key persistence across all three engines | **Unknown — Spike #4** |
| NIST AAL2 conclusion for synced vs device-bound passkeys | **Not verified — Spike #6** |
| Exact Keycloak env var and config key names, cluster sizing, and ECS task counts | **Not verified.** Presented conceptually; confirmed in Phase 0 |
| All cost figures | **Not verified.** PLAN §11 is a driver structure only. No hosting or Cognito figures were obtained |

---

### ADR-014 — TypeScript on Node for the application stack

**Status:** Accepted — **proposed during the build, not in the original plan.** The plan named AWS
services but never named a language or framework. That gap was invisible while every slice was an
experiment; it becomes a decision the moment application code starts.

**Context:** Three constraints, already fixed by earlier decisions, pull in the same direction:

1. **Cedar is committed** (ADR-005). AWS publishes `@cedar-policy/cedar-wasm`, which evaluates the
   *same* policy language locally. Policies written and tested against the lab therefore port to
   Amazon Verified Permissions **unchanged** — no rewrite, no divergence between what was tested and
   what runs. Without that, local policy testing tests something other than what ships.

2. **Infrastructure will be code.** The CDK for the deployment is TypeScript-first. One language
   across application, policy, tests and infrastructure is one toolchain, one version pinning
   problem, one set of CI caches.

3. **DPoP is committed** (ADR-004), which means verifying JWS signatures, JWK thumbprints (RFC 7638)
   for the `cnf.jkt` claim, and `ath` bindings. **JOSE verification is exactly the kind of code that
   must not be hand-rolled** — the failure modes are silent, and a subtly wrong verifier accepts
   forged tokens. `jose` is mature, widely reviewed, and implements the primitives directly.

The lab's browser harnesses are already Node (puppeteer), so tests and application share a runtime.

**Decision:** **TypeScript (strict) on Node**, with:

| Concern | Choice |
|---|---|
| HTTP | **Fastify** — schema validation at the boundary, low overhead |
| JOSE / DPoP | **`jose`** — never hand-rolled |
| Policy | **`@cedar-policy/cedar-wasm`** locally, Amazon Verified Permissions deployed |
| Infrastructure | **AWS CDK (TypeScript)** |
| Tests | **`node:test`** — no extra runner |

**Consequences — good:**

- Policies tested locally are the policies deployed. This is the single biggest reason.
- One language for application, policy, tests and infrastructure.
- Crypto comes from a reviewed library rather than from us. Given that this project's headline claim
  rests on token binding, a hand-rolled verifier would be the most dangerous code in the repository.
- Strict mode plus explicit schema validation at every trust boundary.

**Consequences — bad:**

- **Node's memory and cold-start profile on Lambda is worse than Rust or Go.** Accepted because the
  API is deliberately thin (ADR-004 rejects a custom token broker) and this is not a
  high-throughput data plane.
- **`cedar-wasm` crosses a WASM boundary**, so policy evaluation is slower than native. Accepted;
  policy decisions here are per-request, not per-byte.
- **TypeScript types vanish at runtime.** The compiler proves nothing about data from the network.
  Validation must be explicit and must live at trust boundaries — noted here because the entire
  premise of this project is *not trusting inputs*, and a type annotation is not a check.

**Alternatives considered:**

- **Python / FastAPI** — excellent framework, and the lab tooling is Python. Rejected because the
  Cedar story is weaker, the CDK story is weaker, and it would split the project across two
  toolchains for no gain.
- **Go** — best runtime profile and a strong crypto story. Rejected because the CDK and Cedar
  ergonomics are worse and the team-of-one velocity is lower. Revisit if the API ever becomes
  throughput-bound.
- **Java / Quarkus** — the natural neighbour to Keycloak. Rejected as heaviest for the least benefit
  at this size.
