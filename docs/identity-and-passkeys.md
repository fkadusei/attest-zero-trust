# Identity and Passwordless Authentication (Keycloak)

How Attest implements phishing-resistant, passwordless authentication on self-hosted Keycloak.
Companion to [PLAN.md](PLAN.md) and [decisions.md](decisions.md).

---

## 1. The assurance claim

Be precise about what is being claimed, because "phishing-resistant MFA" is used loosely and the
distinctions drive real design work.

**What we claim:** interactive sign-in to Attest uses FIDO2/WebAuthn public-key credentials, which
are **phishing-resistant** because the credential is cryptographically bound to the relying party
ID. A credential registered for `attest.example.com` cannot be replayed to `attest-example.evil.com`,
even by a perfect reverse proxy. This is the property that TOTP, SMS, and push-approval MFA do
**not** have, and it is the specific thing OMB M-22-09 asks for.

**What we claim for privileged users specifically:** because the privileged realm enforces a
**device-bound authenticator allowlist** and requires **user verification**, passkey-only sign-in
there is a genuine multi-factor authentication — possession of the hardware authenticator *plus*
inherence or knowledge to unlock it. Section 7 explains why this is the argument that makes a
passwordless realm defensible rather than merely convenient.

**The important corollary:** phishing resistance protects the *login ceremony*. It does nothing for
a token stolen *after* login. That is Phase 2's job
([authorization-and-sessions.md](authorization-and-sessions.md)) and it is why Phase 1 alone does
not satisfy success criterion S3.

---

## 2. Passkey taxonomy, and why it decides the realm design

Not all passkeys are equivalent, and the difference determines whether a passwordless realm is
actually multi-factor.

| | **Synced passkey** | **Device-bound passkey** |
|---|---|---|
| Example | iCloud Keychain, Google Password Manager, 1Password, Windows Hello synced | YubiKey, TPM-bound platform credential |
| Private key | Replicated across the user's devices via a cloud sync provider | Never leaves the secure element |
| UX | Excellent — survives device loss automatically | Requires carrying a key; loss means re-enrolment |
| Phishing-resistant | Yes | Yes |
| Recovery model | Sync provider account becomes the trust root | Physical possession is the trust root |
| NIST treatment | Governed by SP 800-63Bsup1 — a **syncable authenticator**, which changes the assurance calculus | Conventional hardware authenticator, counts as possession |

**Why this is the crux:** a synced passkey moves the trust root from the device to the sync provider
account. That is usually a good trade for a consumer account. For platform admins — who can read
every tenant's data — it is a meaningful weakening, because compromise of one consumer cloud account
(or of the sync provider) yields a credential that walks straight into the highest privilege level in
the system.

**Design decision (ADR-003):** synced passkeys are accepted on `attest-users`. On
`attest-privileged`, registration is **restricted by AAGUID allowlist and authenticator attachment**,
so only device-bound hardware authenticators can be enrolled. Section 7 covers the enforcement.

> **The upgrade from the Cognito design:** under Cognito this policy could only be *approximated*,
> because Cognito never exposed the AAGUID. Keycloak enforces it at registration. Same intent,
> materially stronger control — and it is the single strongest argument for the switch.

> **Compliance note worth verifying before certification:** NIST SP 800-63Bsup1
> ([NIST](https://www.nist.gov/publications/incorporating-syncable-authenticators-nist-sp-800-63b))
> addresses how syncable authenticators count toward assurance. The precise clause-level consequence
> for our configuration is Spike #6 — do not make a compliance claim in marketing material until it
> is confirmed against the current text.

---

## 3. Why Keycloak: the four capabilities

The original plan targeted Cognito and hit four limitations. Keycloak 26.4+ addresses all four.

| Capability | Cognito | Keycloak 26.4+ | Consequence for us |
|---|---|---|---|
| **Sender-constrained tokens** | Absent — no DPoP, and Lambda triggers cannot see the `DPoP` header | **DPoP officially supported**; binds access and refresh tokens; `dpop_jkt` on authorization requests | Removes the token-issuing Session Broker (the original plan's largest risk) |
| **Authenticator identity** | No AAGUID exposed — only attachment and transports | **Acceptable AAGUIDs** in the WebAuthn policy, alongside attachment and attestation conveyance | Device-bound enforcement becomes real rather than heuristic |
| **Passkeys** | Paid tier; managed login v2 only; v1 unsupported | **GA**, conditional and modal UI, no browser-flow changes required | No tier gating; better UX |
| **Step-up** | Cryptographic verifiability was an open question | **ACR → Level of Authentication mapping** | Standards-based elevation via `acr_values` |

Source: [DPoP in 26.4](https://www.keycloak.org/2025/10/dpop-support-26-4),
[passkeys in 26.4](https://www.keycloak.org/2025/09/passkeys-support-26-4).

**What Keycloak does not provide:** a managed risk-based adaptive authentication engine. Cognito's
Plus tier did. Losing it is the main *added build cost* of this route — see
[PLAN.md §7.1](PLAN.md) and ADR-012.

---

## 4. Realm design

Realms are the identity isolation unit, and they are a direct analogue of the two-pool design: each
realm has its own signing keys, user store, WebAuthn policy, and session state. Nothing crosses.

| | `attest-users` | `attest-privileged` |
|---|---|---|
| Population | Customers (tenants' employees, external auditors) | Attest staff |
| Password authenticator | **Enabled** (migration affordance) | **Not configured at all** |
| Passkeys | Enabled | Enabled — the only interactive path |
| Authenticator attachment | Not restricted | **Cross-platform only** |
| Acceptable AAGUIDs | Not restricted | **Allowlist of hardware authenticators** |
| User verification | `preferred` | **`required`** |
| Attestation conveyance | `none` | **`direct`** (so attestation is available for enforcement) |
| DPoP | Required on clients | Required on clients |
| Brute-force protection | Enabled, tuned | Enabled, tuned more strictly |
| Federation | Available for customer SAML/OIDC | None — staff accounts are local |

**Why separate realms rather than one realm with roles:** assurance policy is enforced by realm
*configuration* rather than by conditional logic in application code. Application logic is where such
rules silently regress, and a regression here would mean a platform admin authenticated at the
customer assurance level without anyone noticing. Separate realms also mean a compromise of the
customer realm grants nothing in the privileged realm (trust boundary B7).

**Cost of the choice:** staff who are also customers hold two identities, and there are two realm
configurations to keep in sync. Both are accepted; the population is small and the separation is the
point (ADR-002).

---

## 5. Authentication flows and policy configuration

### 5.1 Enabling passkeys

Passkeys in Keycloak **are not enabled by default**. Per the Keycloak 26.4 announcement, the
WebAuthn Passwordless policy must be enabled under **Authentication → Policies → WebAuthn
Passwordless Policy**. After that, the default browser flow works without modification, which is the
main advantage over hand-rolling the ceremony.

Two UI modes are supported and both should be enabled:

- **Conditional UI** — passkey autofill in the username field. Best UX; depends on browser and
  password-manager support.
- **Modal UI** — a "Sign in with Passkey" button. Always available; the reliable path for hardware
  keys requiring a PIN or touch.

### 5.2 The "Conditional - credential" authenticator

This is the piece that implements correct AAL reasoning for us. Keycloak 26.4 adds a
**Conditional - credential** authenticator to the default browser flow that detects whether a
specific credential type (a passkey) was used as the primary credential, and **skips the second
factor** when it was.

The logic is right: a passkey with user verification is inherently multi-factor, so demanding a
TOTP code on top is security theatre that trains users to expect friction. Implementing this
correctly by hand — including the case where the user authenticated with a password instead — is
exactly the kind of subtle flow bug the IdP should own.

**Our configuration:**

| Realm | Flow behaviour |
|---|---|
| `attest-users` | Password **or** passkey as first factor; passkey short-circuits 2FA; password path still requires 2FA |
| `attest-privileged` | Passkey only; no 2FA layer because there is no weaker first factor to compensate for |

### 5.3 WebAuthn policy settings

Presented as declarative realm configuration. Exact keys are confirmed in Phase 0 (S12).

```yaml
# Field names below were VERIFIED against a live Keycloak 26.8.0 realm.
# This matters: Keycloak SILENTLY IGNORES unknown keys on realm import, so a
# guessed name is a setting that appears configured and does nothing.
# See lab/keycloak/SPIKE-3-RESULTS.md section 5.

attest-users:
  webAuthnPolicyPasswordlessRpEntityName: "Attest"
  webAuthnPolicyPasswordlessRpId: "attest.example.com"   # MUST match served origin
  webAuthnPolicyPasswordlessAttestationConveyancePreference: "none"
  webAuthnPolicyPasswordlessAuthenticatorAttachment: "not specified"
  webAuthnPolicyPasswordlessRequireResidentKey: "Yes"
  webAuthnPolicyPasswordlessResidentKey: "required"      # TWO resident-key fields exist
  webAuthnPolicyPasswordlessUserVerificationRequirement: "preferred"  # default is "required"
  webAuthnPolicyPasswordlessAcceptableAaguids: []        # unrestricted
  webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: true
  webAuthnPolicyPasswordlessExtraOrigins: []

attest-privileged:
  webAuthnPolicyPasswordlessRpEntityName: "Attest Admin"
  webAuthnPolicyPasswordlessRpId: "admin.attest.example.com"  # SEPARATE origin
  webAuthnPolicyPasswordlessAttestationConveyancePreference: "direct"
  webAuthnPolicyPasswordlessAuthenticatorAttachment: "cross-platform"
  webAuthnPolicyPasswordlessRequireResidentKey: "Yes"
  webAuthnPolicyPasswordlessResidentKey: "required"
  webAuthnPolicyPasswordlessUserVerificationRequirement: "required"
  webAuthnPolicyPasswordlessAcceptableAaguids:            # device-bound hardware only
    - "<YubiKey 5 series AAGUID>"                         # VERIFY against Yubico's list
    - "<other approved hardware AAGUID>"
  webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister: true
  webAuthnPolicyPasswordlessExtraOrigins: []
```

Note the spelling: **`...AvoidSameAuthenticatorRegister`**, not `...Registration`. The plan
originally had the wrong name, which Keycloak would have ignored without complaint.

Two settings carry most of the weight:

- **`rpId` differs between realms** (`admin.attest.example.com` vs `attest.example.com`). Passkey
  credentials are origin-bound, so a credential registered for the standard realm **cannot** be used
  against the admin realm and vice versa. That gives origin-level separation enforced by the
  browser's own security model rather than by our application logic. The admin console must
  genuinely be served from that origin for this to hold.
- **`authenticatorAttachment: cross-platform` plus an AAGUID allowlist** is what excludes synced
  platform passkeys. Either alone is weaker: attachment alone still admits some non-hardware
  cross-platform authenticators, and AAGUID alone requires us to have enumerated every model we
  reject. Together they are a real control.

### 5.4 Enrolment

Two supported paths, both native:

- **Required action** — set **Webauthn Register Passwordless** as a default required action for new
  users in a realm; users are forced to enrol at first login.
- **Account Console** — users self-enrol via Account Console → Signing In → Passkeys.

**Enrolment policy:** users must register **at least two** credentials before the second is trusted
for recovery purposes. One passkey plus a lost device equals a locked account and a support ticket,
which is how organisations end up re-introducing SMS. Two credentials, ideally of different types,
is the cheapest structural fix. `avoidSameAuthenticatorRegistration` prevents the degenerate case of
the same key being registered twice to satisfy a count.

---

## 6. DPoP configuration

DPoP is enabled per client. In the Admin Console it is the **"Require DPoP bound tokens"** switch in
the client's Settings tab under Capability config. Keycloak 26.4 also supports binding **only
refresh tokens** for public clients while leaving access tokens as bearer.

**For Attest we bind both**, because our API is a resource server that must reject a stolen access
token:

```yaml
attest-spa:
  clientId: "attest-spa"
  publicClient: true          # browser SPA: no client secret
  standardFlowEnabled: true
  directAccessGrantsEnabled: false
  attributes:
    pkce.code.challenge.method: "S256"
    dpop.bound.access.tokens: true    # bind access tokens, not just refresh
```

The browser holds a **non-extractable** P-256 key generated with WebCrypto and stored in IndexedDB,
so injected JavaScript can *use* the key but cannot *export* it.

**The boundary to keep in mind (this is the most important paragraph in this document):** Keycloak
verifies the DPoP proof at **its own token endpoint** and issues a token carrying `cnf.jkt`.
Keycloak is **not in the request path for our API**. Our resource server must therefore verify the
proof on every call. Keycloak binding the token without our API checking the binding would give us a
token that *looks* sender-constrained and is not — the worst possible outcome, because it would
satisfy a checklist while failing in practice. Phase 2 exists to prevent exactly this
([authorization-and-sessions.md §3](authorization-and-sessions.md)).

---

## 7. AAGUID enforcement — the capability Cognito lacked

### 7.1 How it works

The privileged realm combines three policy settings, all enforced **at registration**:

| Setting | Value | Excludes |
|---|---|---|
| `authenticatorAttachment` | `cross-platform` | Platform-resident credentials (Touch ID, Windows Hello, most synced passkeys) |
| `acceptableAaguids` | Hardware-authenticator allowlist | Any authenticator model not explicitly approved |
| `attestationConveyancePreference` | `direct` | Nothing directly — but makes attestation data available, which is what makes the allowlist trustworthy |

Because enforcement is at registration, a user cannot enrol a synced passkey and then use it — a
meaningfully stronger position than the Cognito design, which could only inspect credentials *after*
they existed and reject them on use.

### 7.2 Verified by Spike #3

Enforcement was tested against a live Keycloak 26.8.0 realm using a Chrome CDP virtual
authenticator. Full matrix in [SPIKE-3-RESULTS.md](../lab/keycloak/SPIKE-3-RESULTS.md). Summary:

- **The allowlist is genuinely enforced at enrolment.** A non-approved authenticator is rejected, not
  silently admitted.
- **The attachment restriction is genuinely enforced.** An `internal` (platform) transport was
  rejected under `cross-platform` and accepted when unrestricted — with both controls passing, so the
  rejection is attributable.
- **An authenticator that declines to attest is rejected, not admitted.** Its AAGUID is all-zeros,
  which does not match the allowlist. This disproves the silent-bypass risk recorded in the threat
  model.
- **Keycloak does not validate AAGUID format** — `"not-a-guid"` was stored verbatim. A typo creates a
  silently dead entry that fails *closed* (lockout), not open. **S12's CI gate must therefore validate
  AAGUID format itself.**
- **Keycloak *does* expose the AAGUID** — nested in `credentialData` as a JSON string, not as a
  top-level field. Cognito exposed nothing comparable, so this is a genuine improvement and enables
  later attestation auditing.

### 7.3 The attestation-conveyance trap

**The single most important finding.** An allowlist evaluated under
`attestationConveyancePreference: "none"` is weaker than it looks.

With `none`, there is **no attestation statement to verify**. The AAGUID then travels in the
authenticator data signed only by the credential's own key — it is **self-asserted**. A software
authenticator can claim any AAGUID, including an allowlisted one.

Spike #3 isolated the variable: with the allowlist empty and attachment unrestricted, changing
`none` → `direct` **alone** caused enrolment to fail for a non-attesting authenticator. So `direct`
is an active requirement, not a passive preference. That is a cost — it excludes any authenticator
that cannot attest — but it is the **only** configuration in which the AAGUID is trustworthy, because
attestation is what binds the AAGUID to genuine hardware.

| Configuration | Rejects synced/platform passkeys | AAGUID trustworthy | Cost |
|---|---|---|---|
| Allowlist + `none` | Yes | **No — self-asserted** | None |
| Allowlist + `direct` | Yes | **Yes** | Excludes non-attesting authenticators |
| `direct` only | Yes | Yes | No per-model control |

**Decision: keep `direct` on `attest-privileged`.** The population is small and hardware-key-bearing
by policy, so excluding non-attesting authenticators is acceptable — and it is the only setting under
which the allowlist means what ADR-003 claims. The availability cost is accepted deliberately, and
the enrolment failure message must be intelligible to a user whose key was refused.

### 7.4 What still requires care

- **Allowlist maintenance is an operational duty.** New hardware models have new AAGUIDs. An
  unmaintained allowlist silently locks users out (discoverable, recoverable) or, worse, gets a
  wildcard entry added under pressure (not discoverable). Treat it as reviewed configuration with a
  documented change process and format validation in CI.
- **The acceptance path is still unproven.** No test has shown a genuine allowlisted YubiKey
  enrolling successfully under `direct` + allowlist, because a virtual authenticator cannot attest.
  **A physical security key is still required** to validate the happy path. Until then the known
  failure mode is lockout, not bypass.
- **Real platform-authenticator AAGUIDs are unverified.** Whether iCloud Keychain, Google Password
  Manager, and Windows Hello report all-zeros or a real AAGUID determines which control is actually
  doing the rejecting in production.
- **The AAGUID values themselves are unverified** against physical hardware.

### 7.3 Residual limitation, stated honestly

Even with an allowlist, we are trusting:
1. the authenticator's attestation statement, and
2. Keycloak's enforcement of the allowlist.

We are not independently verifying attestation chains against FIDO metadata. That would be a
meaningful additional control (and is a plausible future enhancement via FIDO MDS), but it is not in
scope, and the assurance claim should not imply it.

---

## 8. Step-up authentication via ACR

!!! danger "REJECTED — do not use this mechanism (ADR-013)"

    **S5 tested exactly this and it failed.** Asking for a higher authentication level made no
    difference: the second factor was demanded whether a higher level was requested, a lower one, or
    nothing at all. The configuration was confirmed correct and read back from the server, and five
    different ways of requesting a level all behaved identically.

    S5b found the decisive fact: the component involved carries **CVE-2026-97176** (published
    2026-09-23), in which a user with a low-level session can obtain a token asserting a higher level
    than they performed. Fix state **Affected**; mitigation **"not available"**; and the affected
    package ships in our build.

    **Never trust the `acr` claim for a step-up decision.** Use `prompt=login` with `max_age=0` to
    force a genuine re-authentication, and evaluate freshness through the **`auth_time`** claim.

    Everything below describes the **intended** design. Read it as a plan, not as a description of
    working behaviour. Full evidence: `lab/keycloak/SPIKE-5-RESULTS.md`.


Continuous verification (Phase 4) requires that a session can be **upgraded** for a sensitive action
without forcing a full re-login. Keycloak supports this natively through **ACR → Level of
Authentication (LoA) mapping**: authentication flows carry an LoA, and a client can request a
specific level with the `acr_values` parameter (or an essential `acr` claim), causing Keycloak to
force whatever additional authentication that level requires.

| Action | Base requirement | Step-up requirement |
|---|---|---|
| Read own tenant evidence | Standard session | — |
| Export tenant-wide access report | Standard session | LoA requiring fresh passkey assertion |
| Invite or remove a tenant admin | Standard session | Fresh assertion + second approver |
| Platform admin: cross-tenant view | Privileged session | Fresh assertion + recorded business justification |
| Platform admin: impersonate user | Privileged session | Fresh assertion + **tenant-consented** + full audit |
| Break-glass AWS access | Not a Keycloak flow | Quorum approval + hardware key + session recording |

**Mechanism:** request with an elevated LoA, Keycloak re-prompts for a passkey assertion (the
re-authentication form supports passkeys), and the resulting token carries the higher `acr` value.
Our DPoP Verifying Authorizer maps `acr` into `context.assurance`, and Cedar policies evaluate it.

**This was expected to be better than the original design** — elevation as an IdP-issued,
token-carried fact rather than a client-reported timestamp. **S5 showed it does not work in practice,
so that comparison is void until S5b resolves it.**

**Bound the freshness in policy, not in the UI.** A high `acr` value must not be treated as
permanently valid for the session; Cedar policies that care about freshness must also evaluate a
recency signal. An elevated token that stays elevated all day is a weaker control than one that
expires.

**Impersonation is the highest-risk feature in the product** and is treated accordingly: it requires
tenant consent, writes an immutable audit entry visible to the tenant, is time-boxed, and cannot be
used to reach other tenants. If it cannot be built to that standard, it should be cut.

---

## 9. Account recovery — the weakest link

Every strong authentication system is eventually defeated through its recovery path. It is worth
stating plainly: **a phishing-resistant primary factor plus an email-OTP recovery path is a
phishing-vulnerable system.** Attackers will not attack the passkey; they will attack the reset.

Keycloak provides credential reset and required-action machinery, but **not a recovery policy** —
that is ours to design.

### 9.1 Standard realm (`attest-users`)

| Scenario | Recovery path | Rationale |
|---|---|---|
| Second passkey registered | Self-service via remaining passkey | No support involvement, no downgrade |
| All passkeys lost, email verified | **Enrolment-link flow with identity proofing** — see below | Must not silently downgrade |
| Suspicious recovery request | Support-assisted with out-of-band verification | Manual by design |

The self-service "lost everything" flow **must not** issue a session directly from an email link. An
email link is a bearer credential in a mailbox, and treating it as sufficient would make every
passkey in the system decorative. Instead:

1. Request → email link to **begin** recovery (not to complete it)
2. Link opens a fresh enrolment ceremony via a Keycloak required action, requiring a *new* passkey
3. Device and network signals captured and scored
4. If signals are low-confidence → hold for support review rather than auto-approve
5. Recovery event written to the immutable audit log **and emailed to the account owner**, so an
   attacker with mailbox access cannot act silently

**Implementation note:** this must be driven by a required action rather than by a direct
credential-reset API call. A reset that sets a password would defeat the purpose, and Keycloak will
happily do that if asked.

### 9.2 Privileged realm (`attest-privileged`)

**No self-service recovery. Full stop.** Recovery requires:

- Out-of-band verification with the security team (video + manager confirmation)
- A second privileged admin approving (quorum — no single-person recovery)
- A new hardware security key enrolled in person or via a verified channel
- Break-glass session, time-boxed, fully recorded

The asymmetry is intentional. Recovery cost for staff is real but bounded; the cost of a compromised
platform admin is unbounded.

---

## 10. Password deprecation path

Passwords exist only on `attest-users`, and only as a migration affordance. `attest-privileged` has
no password authenticator configured from day one.

| Stage | `attest-users` | `attest-privileged` |
|---|---|---|
| Phase 1 | Password + passkey coexist | Passkey only |
| Phase 1 + 90 days | Nudge users with passkeys to remove the password; password becomes step-up-only | unchanged |
| Phase 3 | Password disabled for users with ≥ 2 passkeys | unchanged |
| Phase 5 (target) | Password disabled realm-wide, pending customer migration data | unchanged |

**Gate on data, not dates:** do not disable passwords until telemetry shows ≥ 95% of active users
have two or more passkeys registered. Disabling early produces support load, and support load is what
produces a weak recovery flow, which is what undoes the whole project.

---

## 11. Realm configuration as code

**Realm configuration is not infrastructure and must not be console-clicked** (S12, ADR-011).

- **AWS infrastructure** (ECS, RDS, ALB, security groups, Secrets Manager) is **CDK**.
- **Realm configuration** (realms, clients, WebAuthn policies, flows, required actions, AAGUID
  allowlist) is applied by **keycloak-config-cli** in CI — purpose-built, idempotent, and it consumes
  the realm export format directly.

Using the Keycloak Terraform provider is a reasonable alternative given Terraform is already
installed locally, at the cost of running two IaC tools. Either is acceptable; **console-only changes
are not**, because they make the environment unreproducible and make S12 unverifiable.

CI gates:

```text
1. keycloak-config-cli validate + apply to an ephemeral realm
2. export the realm and assert the WebAuthn policy matches expectations
3. assert attest-privileged has NO password authenticator in its browser flow   <- S1
4. assert acceptableAaguids is non-empty on attest-privileged                   <- ADR-003
5. assert dpop.bound.access.tokens is true on all realm clients                 <- S3 prerequisite
```

Gates 3–5 are the regression guards. **Configuration that is not asserted in a test is configuration
that will be silently reverted by a future change** — and for realm 3 the consequence would be a
platform admin able to authenticate with a password.

---

## 12. Operating the identity provider

Self-hosting means these are ongoing obligations, not setup steps. They are the price of the OSS
route and they are why S11 exists.

| Concern | Approach |
|---|---|
| **Version pinning** | Pin the image tag (`quay.io/keycloak/keycloak:26.8.0`). Never track `latest`. Drift check: the plan originally pinned 26.6, but 26.8 was current at spike time — **re-check before every deploy**, and prefer the most-patched minor. |
| **CVE patching** | 48-hour SLA for critical CVEs (S11). Subscribe to Keycloak security advisories; rehearse the upgrade. |
| **Image build** | Run `kc.sh build` at image build time and start with `--optimized` — avoids build cost on every task start. |
| **Clustering** | ≥ 2 ECS tasks. Keycloak's embedded Infinispan needs a discovery mechanism; on Fargate there is no Kubernetes DNS, so a JDBC-based ping stack is the likely answer. **Spike #7 — resolve before Phase 1.** |
| **Sessions/cache** | Verify session replication across tasks; ALB stickiness may be required to mask misconfiguration. |
| **Database** | RDS Postgres Multi-AZ, encrypted, automated backups, deletion protection, **RDS Proxy** so task churn does not exhaust connections. |
| **Secrets** | DB credentials and bootstrap admin in Secrets Manager with rotation. |
| **Health checks** | Enable health endpoints (`KC_HEALTH_ENABLED=true`) and target the readiness endpoint on the management port; keep the management port off the ALB. |
| **Reverse proxy** | Keycloak must be told it is behind a proxy and what its public hostname is, or issuer URLs and redirects break in confusing ways. Verify the issuer in a token matches the configured hostname. |
| **DR** | Documented and **rehearsed** restore from snapshot. An untested backup is not a backup. |
| **Upgrades** | Rehearsed on a clone against a restored snapshot before production. Custom SPIs must be compatibility-checked (R6). |
| **Escape hatch** | Managed Keycloak (Phase Two / Cloud-IAM / Skycloak) is the documented fallback if operating the IdP proves unsustainable (ADR-010). |

---

## 13. Verification spikes owned by this document

Spikes #3, #5, #6, and #7 in [decisions.md](decisions.md). Summarised:

1. **AAGUID allowlist enforcement semantics** (#3) — does a non-allowlisted authenticator actually
   get rejected, and at what stage? This is the control the whole privileged-access argument rests on.
2. **ACR step-up forces a fresh assertion** (#5) — confirm `acr_values` genuinely re-prompts rather
   than being satisfied by the existing session.
3. **NIST sup1 clause-level consequence** (#6) for our exact configuration.
4. **Keycloak clustering on Fargate** (#7) — jdbc-ping discovery and session replication across tasks.
