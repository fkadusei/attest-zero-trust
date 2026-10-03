# Spike #3 Results — AAGUID allowlist and attachment enforcement

**Status: RESOLVED — the control works, and it works for a subtler reason than assumed.**
Run against Keycloak **26.8.0** (not 26.6 as the plan pinned), local Docker lab.

---

## 1. The question

[ADR-003](../../docs/decisions.md) rests on a claim: that Keycloak's realm-level
`webAuthnPolicyPasswordlessAcceptableAaguids` allowlist actually **rejects** a non-approved
authenticator at enrolment, rather than merely storing the setting. Config persistence is not
enforcement. This spike tests enforcement.

## 2. Method

Chrome 154 driven over CDP by `puppeteer-core`, using a **CDP virtual authenticator** to complete
real WebAuthn ceremonies against Keycloak's `webauthn-register-passwordless` required action.

A virtual authenticator lets us vary `transport` and backup-eligibility, but **not** the AAGUID
(`VirtualAuthenticatorOptions` has no `aaguid` field). That constraint turned out to be ideal: the
virtual authenticator reports `aaguid: 00000000-0000-0000-0000-000000000000` with
`attestationStatementFormat: none` — i.e. **an authenticator that declines to attest**, which is
precisely the bypass case the threat model worried about.

Every test changes exactly one variable, and **two of the five are controls**. Controls are what make
the rejections attributable rather than coincidental.

## 3. Results

| # | Realm | Allowlist | Attachment | Conveyance | Transport | Result | Expected |
|---|---|---|---|---|---|---|---|
| A | `attest-users` | `[]` | not specified | none | usb | **ACCEPTED** | ACCEPT |
| B | `attest-privileged` | `[YubiKey]` | cross-platform | none | usb | **REJECTED** | REJECT |
| C | `attest-privileged` | `[]` | cross-platform | none | usb | **ACCEPTED** | ACCEPT |
| D | `attest-privileged` | `[]` | cross-platform | none | **internal** | **REJECTED** | REJECT |
| E | `attest-privileged` | `[]` | not specified | none | **internal** | **ACCEPTED** | ACCEPT |
| F | `attest-privileged` | `[]` | not specified | **direct** | usb | **REJECTED** | (unexpected) |

**All five predictions passed. Test F was the surprise.**

### What each result establishes

- **B vs C** — same realm, same attachment, same conveyance, same transport, same authenticator. The
  only difference is the allowlist contents. B rejected, C accepted ⇒ **the AAGUID allowlist is
  genuinely enforced at enrolment.**
- **D vs E** — identical except `authenticatorAttachment`. D rejected, E accepted ⇒ **the
  attachment restriction is genuinely enforced.** E also proves the `internal` transport works in
  this harness, so D's rejection cannot be an artefact of the transport.
- **B also rejects the all-zeros AAGUID.** An authenticator that *declines to attest* is **not**
  silently admitted. This **falsifies** the risk recorded in
  [threat-model.md T3](../../docs/threat-model.md) that "if a client declines to send attestation and
  Keycloak admits the enrolment with an empty AAGUID rather than rejecting it, this control fails
  silently." It does not fail silently. The control holds.

### Test F — requiring attestation blocks enrolment

F differs from A only in `attestationConveyancePreference` (`direct` vs `none`), with the allowlist
empty and attachment unrestricted. It **rejected**.

So `direct` is not a passive preference. Requesting it causes enrolment to fail for any authenticator
that cannot produce an attestation statement — which includes the majority of platform authenticators
and anything reporting `attestationStatementFormat: none`.

## 4. The design consequence — a false sense of strength

This is the most valuable outcome of the spike, and it inverts a naive reading of the results.

With `conveyance = none`, **there is no attestation statement to verify.** The AAGUID then travels in
the authenticator data signed only by the credential's own private key — meaning it is
**self-asserted**. A software authenticator can claim any AAGUID it likes. So:

> **An allowlist evaluated under `conveyance: none` is weaker than it appears.** It reliably rejects
> honest authenticators, but a determined attacker using a software authenticator could assert an
> allowlisted AAGUID and pass.

`conveyance: direct` is what makes the AAGUID *trustworthy*, because attestation is what
cryptographically binds the AAGUID to a genuine hardware authenticator. The allowlist and `direct`
are therefore **not redundant** — they are complementary:

| Configuration | Rejects synced/platform passkeys | AAGUID is trustworthy | Cost |
|---|---|---|---|
| Allowlist + `none` | Yes | **No — self-asserted** | None |
| Allowlist + `direct` | Yes | **Yes** | Excludes non-attesting authenticators |
| `direct` only | Yes | Yes | No per-model control |

**Recommendation: keep `direct` on `attest-privileged`.** The population is small and holds hardware
keys by policy anyway, so excluding non-attesting authenticators is acceptable — and it is the only
configuration in which the allowlist means what it claims. The availability cost must be *accepted
deliberately* and the enrolment error must be intelligible to a user whose key was refused.

## 5. Corrections to the plan (verified against the live realm, not documentation)

The plan's WebAuthn configuration was written from documentation. Several details were wrong:

| Plan said | Reality | Impact |
|---|---|---|
| `avoidSameAuthenticatorRegistration` | **`webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister`** (no "‑ion") | The documented setting would have been **silently ignored on import** |
| `requireResidentKey` (one field) | **Two fields**: `...RequireResidentKey` (default `not specified`) and `...ResidentKey` (default `required`) | Ambiguous; both must be set deliberately |
| UV defaults to be overridden | Passwordless policy **already defaults to `required`** | The standard realm must be *lowered* to `preferred`, not raised |
| `rpId` set explicitly | Defaults to `''` (derived from request host); `rpEntityName` defaults to `keycloak` | Explicit values are a real change from default — fine, but worth knowing |
| Attestation defaults to `none` | Defaults to `not specified` | Must be set explicitly |
| Pin Keycloak 26.6 | Current is **26.8.0** | Update the pin and the patch policy |

### Two further findings

- **Keycloak does not validate AAGUID format.** `"not-a-guid"` was accepted and stored verbatim. A
  typo therefore creates a silently dead allowlist entry. Under an exact-match allowlist this fails
  *closed* (lockout — discoverable), not open, but it means **S12's CI gate must validate AAGUID
  format itself**, since Keycloak will not.
- **The default browser flow has `Username Password Form` set to `REQUIRED`, and
  `webauthn-authenticator-passwordless` is not in the flow at all.** Success criterion S1 ("no
  password path exists on the privileged realm") is therefore **not satisfied by realm
  configuration**. During this spike I authenticated to `attest-privileged` **with a password**
  — proof that S1 requires real flow surgery, not a toggle.

## 6. Automation gotcha worth recording

Keycloak's `webauthnRegister.js` calls **`window.prompt()`** to ask for the credential label
(`returnSuccess()`). In headless Chrome an unhandled prompt **blocks the renderer indefinitely**, so
the ceremony never completes and *no* credential is ever created — which initially looked like a
policy rejection. Any E2E test for passkey registration must register a dialog handler (this harness
accepts with a label). This cost the most time in the spike and is worth an hour for anyone else.

## 7. Residual risk — what this spike did NOT prove

Stated explicitly so it is not mistaken for a green light.

1. **The acceptance path with real hardware is unproven.** No test demonstrated that a genuine,
   allowlisted YubiKey successfully enrols under `direct` + allowlist. The virtual authenticator
   cannot attest, so it can only exercise rejection. **A physical security key is still required**
   to validate the happy path. Until then, the failure mode we know about is *lockout*, not bypass.
2. **Real platform-authenticator AAGUIDs are unverified.** Whether iCloud Keychain, Google Password
   Manager, and Windows Hello report all-zeros or a real AAGUID under `none`/`direct` is unknown.
   This determines whether the allowlist or the `direct` requirement is doing the rejecting in
   production.
3. **The AAGUID allowlist values themselves are unverified.** `fa2b99dc-...` came from Yubico's
   published list and was not confirmed against a physical device.
4. **Single-node `start-dev` only.** Clustering, session replication, and behaviour behind a real
   reverse proxy are unaddressed here — that is Spike #7.

## 8. Reproducing

```bash
cd lab/keycloak
docker compose up -d
python3 scripts/configure-realms.py     # apply + assert policies persist
bash scripts/run-matrix.sh              # the A–F matrix above
```

Requires Chrome on `--remote-debugging-port=9222`. Note that Chrome needs `--no-sandbox` when
launched from the DSH sandbox, because its own sandbox initialisation is blocked.
