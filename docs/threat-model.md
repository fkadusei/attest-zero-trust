# Threat Model

What Attest defends against, how, and — just as importantly — what it does not.

> **Revision note:** updated for the self-hosted Keycloak identity plane. This revision **adds**
> threats T15–T17, which are the risks you inherit by operating the identity provider yourself.
> They did not exist when AWS ran it for us.

---

## 1. Method and scope

**Approach:** STRIDE-style enumeration over the authentication and authorization paths, plus explicit
attack trees for the attacks that matter most for this product. Written before implementation, to be
revised after the Phase 6 red-team exercise.

**In scope:** the Attest application, its AWS infrastructure, its Keycloak deployment and realm
configuration, and its build/deploy pipeline.

**Explicitly out of scope:** the security of AWS itself; the customer's own network; the security of
the sync provider behind a synced passkey (treated as a trust assumption, see T3); the security of
Keycloak's own codebase (we consume it, we do not audit it — but see T16).

**Core assumption (NIST SP 800-207 tenet 2):** the network is hostile. No request is trusted because
of where it came from. There is no "internal" network. This is why the architecture has no VPN and
no IP allowlist as a security control.

---

## 2. Assets, in priority order

| # | Asset | Why an attacker wants it | Impact if lost |
|---|---|---|---|
| A1 | Cross-tenant evidence data | Sell to competitors; extort multiple victims at once | Existential |
| A2 | Platform admin capability | Path to A1 at scale | Existential |
| A3 | Auditor credentials | Externally held, often weakest personal security | Severe |
| A4 | Evidence integrity | Fraudulent compliance attestation | Severe |
| A5 | Audit log | Cover tracks; find other victims | Severe |
| A6 | Tenant admin capability | Escalate within one tenant | High |
| A7 | Session/refresh tokens | Impersonate users without breaking in again | High |
| **A8** | **The Keycloak deployment and its database** *(new)* | **Every credential and every token; direct path to A1 and A2** | **Existential** |

A8 is new and is the structural consequence of self-hosting. When AWS ran the IdP, the identity
provider was not part of our attack surface. Now it is the highest-value target we operate.

## 3. Adversaries

| Adversary | Capability | Primary interest |
|---|---|---|
| **External opportunistic** | Credential stuffing, phishing kits, commodity tooling | A1, A3 |
| **Phishing-as-a-service operator** | Real-time AiTM reverse proxy, MFA relay, convincing clones | A1, A3 |
| **Malicious insider (customer)** | Legitimate but over-scoped access | A1, A4 |
| **Malicious insider (Attest staff)** | Platform admin access | A1, A5, A8 |
| **Compromised integration** | Valid service credentials | A1, A6 |
| **Nation-state / targeted** | Full toolchain, supply chain, patient | A1, A2, A5, **A8** |

The **phishing-as-a-service** row justifies the entire passwordless programme: those kits are built
to defeat TOTP and push MFA in real time, and passkeys break their business model. The **nation-state**
row is the one that becomes more worrying under self-hosting, because a self-hosted IdP is a
reachable, patchable target that we must defend continuously.

---

## 4. Attack analysis

Legend: **Stopped** = control is effective · **Mitigated** = materially harder, not eliminated ·
**Out of scope** = accepted risk, stated openly.

### T1 — Credential phishing (static clone)

| | |
|---|---|
| **Attack** | Clone the login page, harvest credentials |
| **Against passwords** | Stopped only if MFA is present and not phishable |
| **Against passkeys** | **Stopped.** The signature covers the origin; it will not verify at the attacker's domain |
| **Control** | WebAuthn origin binding (Phase 1) |
| **Residual** | None for the credential itself; the attacker may pivot to T4 |

### T2 — Adversary-in-the-middle phishing (real-time reverse proxy)

| | |
|---|---|
| **Attack** | Evilginx-class proxy relays the real login in real time, capturing the session *after* MFA succeeds |
| **Against TOTP / SMS / push** | **Defeated** — the proxy relays the code. This is the attack that kills conventional MFA |
| **Against passkeys** | **Stopped at the ceremony.** WebAuthn binds the assertion to the relying party ID, so the browser will not produce a valid assertion for the proxy's domain |
| **Control** | WebAuthn origin binding + `userVerification: required` on `attest-privileged` (Phase 1) |
| **Verification** | Success criterion S2 — run a real AiTM kit against our flow and confirm it fails |
| **Residual** | If the proxy forwards the *token* rather than the ceremony, it still lacks the DPoP key. See T5 |

**This is the attack the project exists to defeat.** It is the reason "passwordless" here means
FIDO2/WebAuthn and not "password + a code from an app".

### T3 — Sync-provider compromise

| | |
|---|---|
| **Attack** | Compromise the consumer cloud account or the provider that syncs passkeys |
| **Impact** | Yields the user's synced passkey material — a complete authentication bypass |
| **Control** | `attest-privileged` enforces `authenticatorAttachment: cross-platform` **plus an AAGUID allowlist**, so synced passkeys **cannot be registered at all** ([identity doc §7](identity-and-passkeys.md)) |
| **Residual for standard users** | **Accepted.** A synced passkey's trust root is the sync provider account. Deliberate UX/security trade on the customer realm |
| **Residual for privileged users** | **Low.** This is the control that Cognito could not provide — enforcement is at registration, not inference after the fact |

Stated plainly because it is the most important accepted risk in the system: **for standard users, we
have moved the trust root from "the user's device" to "the user's cloud account", and we consider
that an acceptable trade at that privilege level.** For privileged users we have not, and that is a
real security improvement over the previous design.

**Residual caveat — NOW RESOLVED BY SPIKE #3.** The earlier concern was that an authenticator which
*declines to attest* (reporting an all-zeros AAGUID) might be silently admitted, defeating the
allowlist. **It is not admitted — it is rejected.** Verified in a controlled matrix
([SPIKE-3-RESULTS.md](../lab/keycloak/SPIKE-3-RESULTS.md)). The remaining caveat is the inverse:
because enforcement is real, a legitimate user whose authenticator cannot attest will be *locked
out*, so the failure mode is availability rather than bypass. And note that the allowlist is only
meaningful under `attestationConveyancePreference: direct` — under `none` the AAGUID is self-asserted
and an allowlist can be spoofed. See [identity doc §7.3](identity-and-passkeys.md).

### T4 — MFA fatigue / push bombing / SIM swap

| | |
|---|---|
| **Attack** | Spam push notifications; or SIM-swap to intercept SMS |
| **Against Attest** | **Not applicable.** No push approval and no SMS factor is configured on either realm |
| **Control** | Factor choice by design — we never deployed the vulnerable factors |
| **Note** | The cheapest way to prevent an attack class is to not have the attack surface. Resist future requests to "just add SMS as a backup" |

### T5 — Session token theft

| | |
|---|---|
| **Attack** | Steal an access token via XSS, a leaked log, a misconfigured proxy, or a shared machine |
| **Against bearer tokens** | **Not mitigated** — possession is authorization |
| **Against Attest** | **Mitigated.** Keycloak binds tokens to `cnf.jkt`; our DPoP Verifying Authorizer rejects proofs that do not match ([authorization doc §3](authorization-and-sessions.md)) |
| **Control** | Keycloak DPoP + resource-server verification (Phase 2), 5-minute access tokens, `HttpOnly` cookies, CSP |
| **Detection** | A DPoP proof failure is a **high-confidence token-theft signal** — alerts, not just 401s |
| **Residual** | See T6 |
| **Critical caveat** | This control is **only** real if our API verifies proofs. Keycloak binding the token is not sufficient. See T15 and risk R2 |

### T6 — XSS in the Attest origin

| | |
|---|---|
| **Attack** | Inject script into the app; use the victim's session |
| **Impact** | **DPoP does not stop this.** The script runs in the origin and can *use* the non-extractable key to sign valid proofs. `extractable: false` prevents key exfiltration, not key abuse |
| **Control** | Strict CSP (no `unsafe-inline`, nonce-based), SRI on third-party scripts, dependency review, no `localStorage` for tokens, aggressive output encoding |
| **Residual** | **Real and non-trivial.** Framework-level XSS is the most likely route to session compromise |
| **Note** | This is the honest limit of DPoP and the reason Phase 4 posture and short TTLs are not redundant |

### T7 — Malicious browser extension / fully compromised device

| | |
|---|---|
| **Attack** | Extension reads the DOM, calls the app's APIs in the user's context, or exfiltrates the key |
| **Impact** | Full session compromise |
| **Control** | **Largely none from the browser.** This is why real device posture needs an agent |
| **Residual** | **Out of scope by design** ([PLAN.md §10](PLAN.md)). Mitigations are organisational (MDM for privileged staff) rather than technical in the web app |

### T8 — Recovery-flow downgrade

| | |
|---|---|
| **Attack** | Do not attack the passkey — attack the reset. Request account recovery, take over the mailbox, enrol a fresh passkey |
| **Impact** | Complete bypass of phishing-resistant MFA |
| **Control** | Recovery never issues a session from an email link alone; **Keycloak required action** forces new-passkey enrolment rather than a credential reset; owner notification; hold-for-review on low-confidence signals; **no self-service recovery for privileged users** ([identity doc §9](identity-and-passkeys.md)) |
| **Residual** | Medium. The most likely real-world bypass; needs telemetry from day one |
| **Note** | Keycloak will happily perform a plain credential reset if asked. The control is that our recovery flow uses a required action, and that distinction must be asserted in configuration, not assumed |

### T9 — Help-desk social engineering

| | |
|---|---|
| **Attack** | Persuade support to reset credentials or grant access |
| **Control** | Quorum approval for privileged recovery; support staff cannot self-authorize; out-of-band verification; every recovery logged and owner-notified |
| **Residual** | Medium — depends on process discipline, not code. Needs periodic tabletop testing |

### T10 — Cross-tenant access (IDOR / BOLA)

| | |
|---|---|
| **Attack** | Use a valid session in tenant A to read tenant B's data — by changing an ID, a path, or a body parameter |
| **Impact** | **A1 — the catastrophic outcome** |
| **Control** | Four independent layers ([authorization doc §4.5](authorization-and-sessions.md)): Cedar `forbid` failing closed; tenant ID sourced only from verified token claims; IAM scoping; CI-hosted cross-tenant IDOR suite |
| **Verification** | Success criterion S5 — an automated suite that must fail to breach on every deploy |
| **Residual** | Low, **provided no code path ever accepts a tenant ID from request input.** That single rule is the control; everything else is backup |

### T11 — Auditor over-reach

| | |
|---|---|
| **Attack** | An auditor (legitimate third party) accesses engagements beyond their scope, or retains access after the engagement closes |
| **Control** | Cedar scoping to `engagement_ids`; `access_expires_at` evaluated per request; access expires on engagement close with **no manual step** (S7); auditor actions fully audited and tenant-visible |
| **Residual** | Low. The auditor is *supposed* to see the engagement — the control is boundary and time |

### T12 — CI/CD and supply chain compromise

| | |
|---|---|
| **Attack** | Steal deployment credentials; inject code into the pipeline; compromise a dependency **or the Keycloak image itself** |
| **Control** | GitHub OIDC → scoped IAM role per job (no static keys, S9); `cdk-nag` in CI; pinned dependencies and **pinned, digest-referenced container images**; branch protection and required review on infra and realm-config changes |
| **Residual** | Medium — supply chain risk is genuinely hard. Under self-hosting the Keycloak image is now an explicit supply-chain dependency: pin by digest, and prefer building from an official `quay.io` image rather than a third-party rebuild |

### T13 — Platform admin abuse (insider)

| | |
|---|---|
| **Attack** | An Attest staff member uses platform access to read customer data, or their credentials are compromised |
| **Control** | Device-bound hardware key enforced by AAGUID allowlist; **no blanket cross-tenant permit** — access is a distinct audited action; ACR-based fresh step-up (< 5 min, bounded in policy); business justification recorded; tenant-visible audit; impersonation requires tenant consent and is time-boxed; quorum-approval break-glass with session recording |
| **Residual** | Low-medium. The audit trail creates accountability rather than prevention — the realistic goal for privileged insiders |

### T14 — Evidence tampering

| | |
|---|---|
| **Attack** | Insider alters evidence to fake compliance |
| **Control** | S3 Object Lock (WORM) on evidence and audit buckets; KMS CMK; CloudTrail data events; cryptographic hash of each artifact recorded at upload |
| **Residual** | Low. Note this is a **product integrity** control as much as a security one |

---

### T15 — Compromise of the Keycloak deployment *(new)*

| | |
|---|---|
| **Attack** | Exploit a Keycloak vulnerability, steal admin credentials, or reach the database directly. Yields the ability to mint tokens for any user, read all credentials, or bypass authentication entirely |
| **Impact** | **A8 — existential.** This is a bigger blast radius than any single tenant's data |
| **Control** | Keycloak tasks in private subnets accepting traffic **only** from the ALB security group (B3); admin API never exposed publicly; RDS in private subnets, encrypted, `No public access`; DB credentials in Secrets Manager with rotation; **no routine human use of the admin API** because realm config is declarative (S12, B9); least-privilege IAM for the ECS task role; CloudTrail + Keycloak admin events to the immutable audit log |
| **Detection** | Keycloak admin events (realm/client/user creation, credential resets); unexpected `LOGIN` events for staff accounts; anomalous admin API access |
| **Residual** | Medium. We are now a target that must be actively defended. This is the honest cost of the OSS route |
| **Note** | The strongest structural mitigation is that **no human has routine admin need**: configuration is applied by CI, so admin-API credentials are used by a small number of automated systems rather than by people |

### T16 — Unpatched Keycloak vulnerability *(new)*

| | |
|---|---|
| **Attack** | Exploit a publicly disclosed CVE in an internet-facing Keycloak version. Keycloak has a history of serious authentication-bypass CVEs and ships releases frequently |
| **Impact** | Potentially A8 — full authentication bypass |
| **Control** | Version pinning so the running version is always known; **48-hour patch SLA for critical CVEs** (S11); subscribed to Keycloak security advisories; rehearsed upgrade runbook; custom SPIs kept upgrade-compatible; **no fork** of Keycloak, so upstream patches apply cleanly |
| **Verification** | S11 — rehearse a patch end-to-end and measure the time |
| **Residual** | **Medium-High, and accepted.** This is the single largest risk introduced by self-hosting. It is mitigated by process, not by architecture — which means it degrades silently if the process slips. If the team cannot commit to the SLA, managed Keycloak (ADR-010) is the correct answer |
| **Note** | A fork would make this unbounded. That is why forking is a non-goal ([PLAN.md §10](PLAN.md)) |

### T17 — Realm misconfiguration and configuration drift *(new)*

| | |
|---|---|
| **Attack** | Not an attacker-initiated attack but an attacker-exploitable condition: a console change weakens a WebAuthn policy, re-enables a password authenticator on the privileged realm, empties the AAGUID allowlist, or disables DPoP enforcement on a client |
| **Impact** | Silent loss of the controls the whole design rests on. **Worst case: a platform admin authenticates with a password** and nobody notices |
| **Control** | Declarative realm config in CI (S12, ADR-011); admin access restricted and audited (B9); **regression guards in CI** asserting: no password authenticator on `attest-privileged`, non-empty AAGUID allowlist, DPoP required on all clients |
| **Residual** | Low if the CI gates exist and are taken seriously; High if they do not |
| **Note** | This threat is easy to dismiss because no attacker appears in it. It is nevertheless the most likely way the privileged-access guarantee is actually lost in practice — not through a clever exploit, but through a well-intentioned console click or an urgent production fix |

---

## 5. Explicitly accepted risks

Recorded so they are decisions rather than oversights.

| # | Accepted risk | Why acceptable | Revisit if |
|---|---|---|---|
| AR1 | Synced passkeys for standard users (T3) | Trust moves to the sync provider account; acceptable at that privilege level | Customers demand device-bound for all users |
| AR2 | Browser posture is weak evidence (T7) | Cannot attest to a device we do not control | Phase 4b device agent is funded |
| AR3 | XSS is the primary residual session risk (T6) | DPoP cannot defend against same-origin script abuse | CSP is bypassed in production |
| AR4 | Malicious extensions / compromised endpoints | Out of technical scope for a web application | Privileged staff lack MDM |
| AR5 | Supply chain risk (T12) | Mitigated, not eliminated; Keycloak image pinned by digest | A dependency or image incident occurs |
| AR6 | Physical coercion | Outside this threat model | Product moves into a higher-risk vertical |
| AR7 | AWS and the passkey sync provider as trust roots | We are a relying party | A relevant incident occurs |
| **AR8** | **We operate the identity provider (T15, T16)** | **Chosen deliberately: native DPoP, AAGUID allowlist, and no per-MAU cost were worth the operational burden** | **The 48-hour patch SLA cannot be met, or the team lacks IdP operational capacity → migrate to managed Keycloak (ADR-010)** |
| **AR9** | **Loss of managed adaptive/risk-based authentication** | Keycloak has no official equivalent to Cognito Plus threat protection. Partly self-mitigating because the privileged realm has no passwords; replaced by ADR-012 | Risk detection proves materially weaker in practice |

**AR8 and AR9 are the real price of the switch, written down so they cannot be forgotten.** AR8 in
particular is a commitment to ongoing engineering work, not a one-time setup cost.

---

## 6. Detection and response

"Assume breach" is only meaningful if you can **detect** the breach. Under Zero Trust, logging is a
security control, not an observability nice-to-have.

**High-signal detections to build in Phase 6:**

| Detection | Signal | Severity |
|---|---|---|
| DPoP proof failure | Token held without its key → **token theft** | Critical |
| Cross-tenant authorization denial spike | Probing, or a broken policy | High |
| Passkey enrolment immediately after recovery | Likely account takeover in progress | High |
| Impossible travel on a privileged session | Credential compromise | Critical |
| Revoked credential reuse | Token replay after revocation | Critical |
| **Keycloak admin event outside CI** *(new)* | Manual realm change — drift, or an attacker | High |
| **Keycloak admin event burst** *(new)* | Attempted mass credential or client manipulation | Critical |
| **Brute-force lockout surge** *(new)* | Distributed password attack on `attest-users` | Medium |
| **Unexpected `attest-privileged` login** *(new)* | Staff login outside change windows | High |
| Posture downgrade followed by sensitive action | Compromised endpoint | High |
| Platform admin cross-tenant burst | Insider exfiltration | Critical |
| Cedar `forbid` on tenant isolation | Active attack **or** policy deployment bug | Critical |

**Response principles:**

- **Revocation must be one action**, not a runbook of twelve console clicks. Build the kill switch
  before the incident.
- **Keycloak's event system is a detection asset.** It exposes more authentication detail than
  Cognito's managed threat protection did, so detection can end up *better* even though the managed
  risk scoring was better. Both statements are true, and the first is worth exploiting.
- **Break-glass is pre-provisioned and tested.** An untested break-glass procedure is not a control.
- **Every auth/authz decision is retained** (S8) in tamper-evident storage.
- **The audit log is a target.** S3 Object Lock, separate KMS key, restricted write access.
- **A patch SLA that has never been exercised is a hope.** Rehearsing the upgrade (S11) is part of
  the control, not preparation for it.

## 7. Threat model maintenance

This document is a living artifact with explicit revision triggers:

- After every red-team exercise (Phase 6, and annually thereafter)
- On any change to the authentication flow or realm configuration
- **On every Keycloak version upgrade** — the CVE-patching cadence under self-hosting means this
  document should be reviewed more often than it was under a managed IdP
- On any new integration or service identity
- On a relevant CVE in Keycloak, AVP, or a browser's WebAuthn implementation
- On any incident, regardless of severity

**A threat model that is not revised after an incident is documentation, not security.**
