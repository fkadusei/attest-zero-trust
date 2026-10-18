# S6 — Syncable authenticators, and what we may claim

**Status: ANALYSIS COMPLETE AND MATERIALLY CORRECTED — awaiting independent HUMAN review.**

S6 asked what the standards say about *synced* passkeys, and what we may claim publicly. This is the
analysis.

**An earlier draft of it overclaimed in several places, and a hostile review caught it.** Section 7
records what the review found and what changed, because the correction is the most useful part of the
document. The short version: the analysis audited itself against NIST and **not** against this
project's own list of failure patterns, and it repeated three of them.

Every quotation is traced to the primary source so a reviewer can check it without trusting the
author. **This is not an assessment.** It is the input to one.

---

## 1. The primary source

**NIST SP 800-63B-4**, *Digital Identity Guidelines: Authentication and Lifecycle Management*,
2025-08-26.

- **§2.3** AAL3; **§2.3.2** "Authenticator and Verifier Requirements"; **§2.3.3** Reauthentication.
- **§3.1.6.1** Single-Factor Cryptographic Authenticators; **§3.1.7.1** Multi-Factor Cryptographic
  Authenticators; **§3.1.7.2** Multi-Factor Cryptographic Verifiers.
- **Appendix B, "Syncable Authenticators"** — **normative**.

Sources: <https://pages.nist.gov/800-63-4/sp800-63b.html> and
<https://pages.nist.gov/800-63-4/sp800-63b/syncable/>.

> Scope. SP 800-63B is written for US federal agencies. It is the reference auditors reach for outside
> government too, but nothing here is a certification and this document does not claim compliance.

---

## 2. What the standard says about syncing

**§2.3.2, on AAL3 — the clearest statement:**

> "Since syncable authenticators (described in Appendix B) require the private key to be exportable,
> syncable authenticators **SHALL NOT** be used at AAL3."

The same section, positively:

> "The cryptographic authenticator used at AAL3 **SHALL** have a non-exportable private key and
> **SHALL** provide phishing resistance…"

**Appendix B.2, "Cloning Authentication Keys":**

> "Syncing authentication keys inherently means that the key can be exported. Authentication at AAL2
> may be supported subject to the above requirements. However, syncing violates the non-exportability
> requirements of AAL3. Similar protocols using keys not stored in an exportable manner that meet the
> other requirements of AAL3 may be used."

**§3.1.6.1 (single-factor)** and **§3.1.7.1 (multi-factor)**, quoted separately rather than stitched:

> **§3.1.6.1:** "Exportable authentication keys (usable at AAL2 or below) **SHOULD** be stored in
> appropriate storage… Non-exportable authentication keys (usable at AAL3 or below) **SHALL** be
> stored in an isolated execution environment that is protected by hardware…"

> **§3.1.7.1:** "Non-exportable authentication keys, suitable for use at AAL3, **SHALL** be stored in
> an isolated execution environment that is protected by hardware…"

**So a synced passkey cannot be an AAL3 authenticator.** Not because it is weak — because sync is
export by definition. That part is unambiguous and does not depend on our configuration.

**But `subject to the above requirements` is doing real work, and the earlier draft dropped it.**
Appendix B.2 imposes seven obligations on an AAL2 syncable deployment: approved cryptography; keys
encrypted at 112-bit strength in the sync fabric; private-key operations performed on-device; access
control so only the authenticated user reaches the keys; **AAL2-equivalent MFA gating access to the
sync fabric**; the requirements **documented and communicated, including on public-facing websites**;
and a UI showing what is synced where.

**We satisfy none of these deliberately, because we are not the sync fabric.** "The standard permits
synced passkeys at AAL2" is therefore a statement about *what the standard permits*, **not** about what
we have built. The distinction matters because that sentence is exactly what a DPO will read as an
AAL2 claim.

---

## 3. What our configuration actually is

Read from `lab/keycloak/scripts/configure-realms.py`, which asserts each setting persisted. **These are
the `webAuthnPolicyPasswordless*` keys only — see F3.**

| Setting | Customer realm (`attest-users`) | Privileged realm (`attest-privileged`) |
|---|---|---|
| Attestation conveyance | `none` | `direct` |
| Authenticator attachment | *not specified* | `cross-platform` |
| User verification | `preferred` | `required` |
| Discoverable credential | required | required |
| AAGUID allowlist | `[]` — any authenticator | YubiKey 5 series |
| Synced passkey possible? | **Yes, by design** | **Intended: no** |
| RP ID | `localhost` (hardcoded; production value only in a comment) | same |

The privileged realm asks for a **cross-platform** authenticator matching a **hardware AAGUID**, with
**attestation**, and **user verification required**. As a *request to an honest browser*, that is what
the design intends.

**As an enforced control it is weaker than it looks** — and that is what the review found. F1 and F2.

---

## 4. What we may claim — CORRECTED

An earlier draft said "privileged access requires a hardware-bound authenticator… This is tested
(S3)". **That was wrong, and wrong in the direction that matters most.** What the evidence supports:

### We may say

- **"Enrolment into the privileged realm refuses an authenticator whose AAGUID is not on the allowlist,
  and refuses a built-in authenticator."** Tested (S3), with controls. **Note what it is not: a
  statement about enrolment, not about access.**
- **"Privileged sign-in is passkey-only."** Tested (S5d), by policy and by test.
- **"Synced passkeys are permitted for customer accounts, where the assurance target is AAL2"** — but
  read §2 above: the standard permits this *conditionally*, and we are not the party satisfying those
  conditions.
- **"WebAuthn credentials are scoped to the relying-party origin, which is the mechanism behind
  phishing resistance."** Structural, and tested on loopback (S9).

### We must NOT say

- **"Privileged access requires a hardware key", or "you used your key just now".** EVIDENCE §5.8
  records that the privileged **step-up** flow is password plus WebAuthn as a **conditional second
  factor**, and yields *"verified freshness and, today, no strength"*. **No physical hardware key has
  ever completed a sign-in in this lab** — EVIDENCE lists acceptance of a real key as Unverified.
- **"AAL3 compliant", "AAL3-shaped", or "NIST AAL3".** See F5 for the four separate reasons.
- **"A physical hardware key is accepted."** Only refusal has been tested.
- **"Sign-in is phishing-resistant"** unqualified. S9 ran on **loopback**; real-TLS phishing is
  Unverified; the property depends on **RP-ID width**, and the RP ID is hardcoded to `localhost`. The
  enrolment link (bearer token) and enrolment window (password) are not origin-bound at all.
- **"Verified by search."** EVIDENCE reserves **Verified** for an experiment with a control. A grep is
  neither. A claim resting on one is at best **Documented**.

---

## 5. Findings

### F1 — The AAGUID allowlist has no attestation trust anchor

Keycloak treats the AAGUID as meaningful only after requiring a non-`none` attestation statement, and
it validates the chain against a **truststore** (`WebAuthnRegisterFactory` →
`KeycloakTrustAnchorRepository`). With none configured it falls back to
`NullCertPathTrustworthinessVerifier`.

**This repository configures no truststore: grep across `lab/keycloak/` finds `AcceptableAaguids` and
zero hits for trust store, trust anchor, or truststore.** Yubico's FIDO attestation root is not in the
JRE `cacerts`.

So the control is either **unanchored** (a fabricated `x5c` chain would satisfy it) or it **rejects
genuine YubiKeys** — which matches the lockout failure mode EVIDENCE already names. **We do not know
which.**

This is the same class as **CVE-2026-6856**, where packed self-attestation bypassed `AcceptableAaguids`
(fixed in 26.6.2; this lab runs 26.8.0 and is not exposed) — that CVE is not a live risk here, but it
is proof the failure mode is real.

**State: unestablished, and it is the load-bearing part of the only enrolment control we have.** This
cannot be closed by configuration alone; it needs a pinned Yubico FIDO root **and** a demonstration
that a forged chain fails.

### F2 — `cross-platform` is not enforcement

Keycloak's own source says `authenticatorAttachment` is **client-reported and not cryptographically
verified** — it is not in the attestation object. The privileged policy's `cross-platform` requirement
is a request to an honest browser, not a control.

**What this changes:** the earlier draft's "refused if either is not satisfied" was wrong. Only the
AAGUID comparison has server-side enforcement, and F1 is about whether *that* is anchored.

### F3 — We configured one of two policy surfaces

`webAuthnPolicyPasswordless*` governs **passwordless** sign-in. Keycloak also has `webAuthnPolicy*`,
which governs a **`webauthn`-type credential used as a second factor**. **This repository sets zero
non-passwordless `webAuthnPolicy*` keys**, so that surface keeps Keycloak's defaults — including an
**empty acceptable-AAGUID list**.

Two consequences. Any path accepting a `webauthn`-type credential **bypasses the allowlist**. And an
allowlist is a **registration-time filter**: tightening it does not retroactively revoke credentials
already stored.

Whether such a path is reachable today depends on which flows are enabled, which this analysis has
**not** established.

### F4 — NIST's actual threat table is what this document should discuss

Appendix B.6 ships **Table 5**. The earlier draft examined only the two optional WebAuthn flags (BE/BS)
and declared a non-finding — the wrong artefact. The real threats, and why they matter **for this
product specifically**:

| Threat (Appendix B.6) | Why it matters here |
|---|---|
| **Unauthorized key use, or loss of control** — syncable authenticators may be **shared** between users | An approval trail that says "Alice approved" can be produced by anyone Alice shares her key with. **Undetectable by the relying party** |
| **Sync fabric compromise** | Our customers' Apple/Google account security becomes part of our authentication chain, invisibly |
| **Unauthorized access to the sync fabric and recovery** — synced keys are reachable via cloud account recovery, "which represent a potential weakness" | **The sharpest problem.** An attacker who recovers a customer's iCloud or Google account produces a valid, phishing-resistant, user-verified assertion. **Our log says "Alice signed in".** A passkey event is evidence that *that account* authenticated, not that the named human did. **Nothing in this design addresses attribution** |
| **Revocation** — RP-specific keys cannot be centrally revoked like PKI certificates | We cannot revoke at the sync fabric; we can revoke our credential record and wait for token expiry — which S8 records as **unmeasured** |

**This is the section a compliance reviewer reads first.** For a product whose value is the integrity
of "who did what", F4's third row is more serious than everything else in this document.

### F5 — "AAL3-shaped" is not shape-accurate

Even granting the allowlist, AAL3 also requires:

- **FIPS 140 L1+ for authenticators.** An AAGUID encodes a *model*, not a validation status. The
  FIPS-series key has **its own AAGUID**, so unless the allowlisted value is the FIPS variant, the realm
  may be configured to reject the only AAL3-eligible keys.
- **FIPS 140 L1+ for verifiers.** This document's earlier draft discussed only authenticator FIPS. AAL3
  constrains the *verifier's* cryptography too — self-hosted Keycloak on a stock JVM.
- **Authentication intent.** The User Present flag is client-asserted, exactly like UV.
- **12h overall / 15m inactivity reauthentication.** Never checked; Keycloak's default idle is 30m.

**"AAL3-flavoured authenticator selection"** is the most this configuration supports. "AAL3-shaped"
implies the shape is right and one corner is wrong. **Four corners are wrong.**

### F6 — User verification: real mechanism, wrong layer, and one fix that is impossible

The customer realm sets user verification to `preferred`. Appendix B.3:

> "Verifiers **SHALL** indicate that UV is preferred and **SHALL** inspect responses to confirm the
> value of the UV flag. This indicates whether the authenticator can be treated as a multi-factor
> cryptographic authenticator. **If the user is not verified, agencies SHALL treat the authenticator as
> a single-factor cryptographic authenticator.**"

and §3.1.7.2:

> "If such a flag is present and indicates that an activation factor was not used, the authentication
> **SHALL** be treated as single-factor."

**The mechanism is real, and it is stronger than the earlier draft knew.** In Keycloak's
`WebAuthnAuthenticator`, `isUVFlagChecked` is set only when the policy is `required`. Under `preferred`
the server **accepts a `UV=0` assertion and does not act on it.** A customer may therefore authenticate
with **one factor** while the system treats the sign-in as multi-factor.

**But three things in the earlier draft were wrong:**

1. **Wrong layer.** The UV flag exists in the WebAuthn assertion, which only Keycloak sees. **It is not
   in the access token**, so "inspect the UV flag in the access token" was **impossible to implement**,
   and checking `apps/api/src` was checking the wrong place.
2. **Wrong remedy framing.** NIST **requires** `preferred` — *"Verifiers SHALL indicate that UV is
   preferred"*. The deviation is the **missing inspection**, not the setting. Setting `required` would
   be a departure from prescribed behaviour, not an implementation of it. It is also the only
   server-side enforcement Keycloak offers, so calling it "cheap" understated it.
3. **Wrong strength of claim.** Nothing has shown a real authenticator returning `UV=0` in a
   `residentKey: required` flow. Honest browsers usually *do* UV under `preferred`; the live threat is a
   **hostile client that suppresses it**. The earlier draft's "evidenced risk" was **Assumed**.

**State: a real gap at the Keycloak layer, conditional, unmeasured.**

### F7 — The configuration script can brick the admin realm mid-run

`configure-realms.py` writes `["not-a-guid"]` into the **live** privileged realm's allowlist to prove
the setting is writable, then restores it. An interruption between those two points leaves a realm that
accepts **no authenticator at all**. **Undisclosed until now** — and worth fixing regardless of what
the standards say.

---

## 6. What the review did not overturn

Recorded so a reviewer knows what survived: the AAL3/exportability reading in §2 is correct and
well-cited; refusing to claim AAL3 or a blanket AAL2 is right; and the **two-realm architecture itself
is sound**. The objection is to the *evidence* for calling it AAL3-shaped, not to the split.

---

## 7. What the review changed, and the pattern behind it

Two independent adversarial passes ran. The first checked every quotation against the source; the
second attacked the reasoning and then checked **Keycloak's source**, which this document should have
done itself instead of grepping `apps/api/src`.

**Quotation defects fixed:** §2.3.3 cited where §2.3.2 was meant; a "§3.1.7.1" quote that was actually
§3.1.6.1, reordered across an ellipsis; a Backup Eligible quote truncated mid-sentence.

**Substantive defects fixed:** the §4 hardware-key claim (→ §4, F1–F2); the missing attestation trust
anchor (F1); the second policy surface (F3); the absent threat table (F4); "AAL3-shaped" (F5); the
mislocated and over-strong user-verification finding (F6); the undisclosed script behaviour (F7).

**The pattern is the important part.** Each substantive defect is one this project has **already
named** in EVIDENCE §2a, and the document repeated three of them:

| EVIDENCE §2a pattern | How this document repeated it |
|---|---|
| **A check that cannot fail** | "Verified by search" — a grep presented at experiment strength |
| **The wrong subject** | Enrolment tested, **access** claimed; the passwordless policy described, **the realm** claimed |
| **Self-vouching** | The configuration script's success message treated as evidence of a security property |

**The document was audited against NIST. It was not audited against that list.** That is the finding
worth keeping, and it applies to the next document too.

---

## 8. What remains for a human reviewer

1. **Establish the trust-anchor position (F1).** Until it is resolved, "hardware key required" cannot
   be said. Needs a pinned Yubico root and a forged-chain test.
2. **Decide F6.** Accept and downgrade the wording to "phishing-resistant"; investigate what can be
   enforced at the verifier; or treat customer sign-in as single-factor and say so. **The author should
   not choose, because the author set `preferred`.**
3. **Determine whether the `webauthn` credential surface (F3) is reachable**, then configure or disable
   it.
4. **Answer F4's attribution question.** An evidence system whose log says "Alice did this" when the
   actor may be whoever holds Alice's sync fabric is a product problem before it is a standards
   problem. **This document does not solve it.**
5. **Confirm the quotations against the PDF of record**, and whether an auditor accepts the AAL framing
   at all.

## 9. What changed in the code as a result of S6

**Nothing.** S6 produces a claim boundary. The one code-adjacent consequence is **F7**, which is a bug
worth fixing regardless.
