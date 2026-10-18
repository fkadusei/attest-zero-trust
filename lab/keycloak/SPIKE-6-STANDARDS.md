# S6 — Syncable authenticators, and what we may claim

**Status: ANALYSIS COMPLETE — awaiting independent review. This document is the reviewer's input.**

S6 asked a precise question: the standards treat device-bound and synced passkeys differently, there
is a specific document about the synced kind, and we need to know what it says about **our
configuration** before claiming anything publicly.

This is that analysis. Every claim is traced to a quotation from the primary source, so a reviewer can
check it without trusting the author. **It has not been independently reviewed, and until it has, the
claims below are ours and not an assessment.** That is the whole point of the slice.

---

## 1. The primary source

**NIST SP 800-63B-4**, *Digital Identity Guidelines: Authentication and Lifecycle Management*, published
2025-08-26. Two parts matter:

- **§2 (AAL)** — what each assurance level requires of an authenticator.
- **Appendix B, "Syncable Authenticators"** — marked **normative**, and the document S6 was about.

Retrieved from <https://pages.nist.gov/800-63-4/sp800-63b.html> and
<https://pages.nist.gov/800-63-4/sp800-63b/syncable/>.

> A note on scope. SP 800-63B is written for US federal agencies, but it is the reference auditors
> reach for outside government too. Nothing here is a certification, and this document does not
> claim compliance.

---

## 2. The decisive sentence

From Appendix B, "Cloning Authentication Keys":

> "Syncing authentication keys inherently means that the key can be exported. **Authentication at AAL2
> may be supported subject to the above requirements. However, syncing violates the non-exportability
> requirements of AAL3.** Similar protocols using keys not stored in an exportable manner that meet
> the other requirements of AAL3 may be used."

Read with §2.3.3 (AAL3 requirements):

> "The cryptographic authenticator used at AAL3 **SHALL** have a non-exportable private key and
> **SHALL** provide phishing resistance…"

and §3.1.7.1 (multi-factor cryptographic authenticators):

> "Exportable authentication keys (usable at AAL2 or below) **SHOULD** be stored in appropriate
> storage… Non-exportable authentication keys (usable at AAL3 or below) **SHALL** be stored in an
> isolated execution environment that is protected by hardware…"

**The conclusion is not ambiguous: a synced passkey can never be an AAL3 authenticator.** Not because
it is weak, but because sync is export by definition.

This is the single most important fact for our claims, and it is the reason the two-realm split is
worth having.

---

## 3. What our configuration actually is

Read from `lab/keycloak/scripts/configure-realms.py`, which asserts each setting persisted:

| Setting | Customer realm (`attest-users`) | Privileged realm (`attest-privileged`) |
|---|---|---|
| Attestation conveyance | `none` | **`direct`** |
| Authenticator attachment | *not specified* | **`cross-platform`** |
| User verification | `preferred` | **`required`** |
| Discoverable credential | required | required |
| AAGUID allowlist | `[]` — any authenticator | **YubiKey 5 series only** |
| Synced passkey possible? | **Yes, by design** | **No** |

The privileged realm asks for a **cross-platform** authenticator matching a **hardware AAGUID**, with
**attestation** and **user verification required**. That is a device-bound key from a known
manufacturer. The customer realm asks for almost nothing, deliberately, so that ordinary people can
enrol the passkey their phone or laptop already provides.

**So the split is aligned with the standard's own boundary**, and not by accident: the privileged
realm is where we can make an AAL3-shaped claim, and the customer realm is where we must not.

---

## 4. What we may claim, and what we may not

### We may say

- "**Privileged access requires a hardware-bound authenticator**, enforced by an AAGUID allowlist and
  an attachment restriction, and the enrolment is refused if either is not satisfied." — *This is
  tested (S3), and it is what the standard asks for at AAL3.*
- "**Synced passkeys are permitted only for customer accounts**, where the assurance target is AAL2.
  The standard explicitly permits synced authenticators up to AAL2."
- "**Sign-in is phishing-resistant** in both realms." *Attested by S9, and structural: WebAuthn
  credentials are scoped to the relying-party origin.*

### We must not say

- "**AAL3 compliant**", "NIST AAL3 certified", or anything similar. We have not performed a FIPS 140
  validation of the authenticators we accept, we have not had the configuration assessed, and AAL3
  requires more than WebAuthn settings. **This remains true even though our WebAuthn configuration is
  consistent with AAL3's authenticator requirements.**
- "**AAL2 compliant**" as a blanket statement about the system, for the reason in the next section.
- Anything at all about the *device the customer uses*, because we do not inspect it.

---

## 5. Two findings that a reviewer should attack first

These are the parts most likely to be wrong, and they are the reason this document exists.

### Finding 1 — `preferred` user verification means we may be accepting single factor without knowing

SP 800-63B Appendix B, "Implementation Requirements", on the WebAuthn **User Verified (UV)** flag:

> "Verifiers **SHALL** indicate that UV is preferred and **SHALL** inspect responses to confirm the
> value of the UV flag. This indicates whether the authenticator can be treated as a multi-factor
> cryptographic authenticator. **If the user is not verified, agencies SHALL treat the authenticator
> as a single-factor cryptographic authenticator.**"

Our customer realm sets user verification to **`preferred`**, and **nothing in `apps/api/src/` inspects
UV, `amr`, or any equivalent claim.** Verified by search: there are no references.

What that means in the worst case: a customer whose authenticator does not perform user verification
may be authenticating with **one factor**, and we have no way to tell. NIST says such an assertion
**SHALL** be treated as single-factor. AAL2 requires two distinct factors. **We may therefore be
presenting a single-factor sign-in as AAL2-equivalent.**

**This does not affect the privileged realm**, where UV is `required` and the authenticator is
hardware.

**Two pieces of our own evidence make this stronger, not weaker.**

First, the S3 spike explicitly recorded that *"the passwordless policy already defaults to
`required`"* — and the customer realm **overrides that default down to `preferred`**. So this is not
an unexamined Keycloak default; it is a choice we made, and the spike noted the default being
departed from.

Second, **every virtual authenticator in this project's harnesses is created with
`isUserVerified: true`** (`console-e2e.mjs`, `client-isolation.mjs`, `userhandle-probe.mjs`). The
non-verified path has therefore **never been exercised by any experiment we have run**. We do not know
whether a UV-less assertion completes sign-in in this configuration — we know only that the
configuration permits it and that we would not be able to tell.

That is the honest state: **permitted, unexercised, undetected.**

**What would fix it**, in increasing order of effort:

1. Set the customer realm's user verification to `required`. Cheap, but it locks out authenticators
   that cannot verify — which is a real usability cost and may be why it was set to `preferred`.
2. Inspect the `amr` claim or the UV flag in the access token and **refuse AAL2-shaped operations**
   when verification did not happen. Requires knowing what Keycloak actually emits.
3. Accept it, and downgrade the claim: "sign-in is phishing-resistant" rather than "sign-in is
   multi-factor". This is honest and may be enough for the product.

**This analysis does not choose between them.** That is a decision, not a finding.

### Finding 2 — we do not use the Backup Eligible flag, and that is probably right

SP 800-63B Appendix B on **Backup Eligible (BE)**:

> "The Backup Eligible flag indicates whether the authenticator can be synced… Verifiers **MAY** use
> this flag to establish policies that restrict the use of syncable authenticators. This flag is
> necessary to distinguish authenticators that are device-bound from those that may be cloned."

and on **Backup State (BS)**:

> "Agencies **SHOULD NOT** condition acceptance based on this flag for public-facing applications due
> to user experience concerns."

We inspect **neither**. For the privileged realm that is fine, and arguably deliberate: an AAGUID
allowlist plus `cross-platform` is **stronger** than a BE check, because it constrains *which*
authenticator rather than merely whether it can sync. For the customer realm, BE would be the wrong
tool — the standard permits syncing there.

**So this is a non-finding, recorded so a reviewer can see it was considered rather than missed.**

---

## 6. What remains for a human reviewer

The things this document cannot do for itself:

1. **Check the quotations against the source.** They were copied from the HTML edition; a reviewer
   should confirm they match the PDF of record, and that the section numbering is right.
2. **Decide Finding 1.** Set UV to `required`, inspect the claim, or downgrade the wording. The
   author should not make this call alone, because the author is the one who chose `preferred`.
3. **Confirm the AAL framing is one an auditor would accept.** SP 800-63B is a US federal document;
   whether a SOC 2 or ISO 27001 assessor treats it as the reference is a question about *them*, not
   about the standard.
4. **Check the FIPS 140 position.** AAL3 requires validated cryptographic modules. Whether the YubiKey
   5 series we allowlist is validated in the configuration we permit is **not established here**, and
   it is a prerequisite for any AAL3 claim.

## 7. What changed as a result of this analysis

Nothing in the code. This slice produces a claim boundary, not a fix — with one exception to consider
as a follow-up: **the `preferred` UV setting in the customer realm is now a named, evidenced risk**
rather than an unexamined default, and it is recorded in `EVIDENCE.md` so it cannot be forgotten.
