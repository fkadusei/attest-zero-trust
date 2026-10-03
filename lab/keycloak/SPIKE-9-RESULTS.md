# S9 Results — does a phishing proxy actually fail?

**Status: RESOLVED for the claim. PROVEN — with the counter-case recorded as NOT RUN and the reason
stated.**

This is the claim the whole project rests on: *a user can be tricked into visiting an attacker's copy
of the sign-in page, hand over everything they are able to, and still not get in.*

Everything else in this repository tests parts. **This tests that, and it holds.**

---

## 1. What was built

**Not a mock-up of a phishing site.** A fake login page proves nothing — nobody types a passkey into an
obvious fake. The phishing site is a **real reverse proxy relaying to the real Keycloak**:

```
victim's browser  ->  evil.localhost:9001  ->  (relay)  ->  localhost:8080 Keycloak
```

The victim sees exactly what the genuine site serves — the same markup, the same title, the same
everything. **The only difference is the origin.**

Verified properties of the relay:

- the login page is served, and `#authenticateWebAuthnButton` is present
- **zero references to the real host survive in the page** — every absolute URL is rewritten to the
  attacker's origin, so the browser never escapes it

## 2. Why hostnames, and not ports

**WebAuthn's relying-party ID ignores the port.** A proxy on `localhost:9001` relaying to
`localhost:8080` shares the RP ID `localhost`, so the credential *would* answer and the test would
report a **false bypass**.

`app.localhost` and `evil.localhost` are genuinely different registrable domains, and `*.localhost`
resolves to loopback by convention — so **no `/etc/hosts` edit was needed** for this part.

## 3. The results

| Check | Result |
|---|---|
| The phishing-lab client and test user exist | **pass** |
| A passkey is registered at the real origin | **pass** |
| **Control:** the passkey signs in at the **real** origin | **pass** |
| **Control:** the proxy relays a faithful login page | **pass** |
| **Control:** the relayed page points nothing back at the real host | **pass** |
| **THE CLAIM: the phishing origin does NOT authenticate** | **pass** |

### The decisive evidence is the browser's own words

When the victim clicks "sign in with passkey" on the attacker's page, the browser refuses, and
Keycloak records exactly why:

```
SecurityError: The relying party ID is not a registrable domain suffix of, nor equal to the
current domain. Subsequently, an attempt to fetch the .well-known/webauthn resource of the
claimed RP ID failed.
```

**The credential does not answer.** Neither the password nor the passkey can be phished, because the
assertion is bound to a domain the attacker does not control.

### Why this is not a false pass

A test that always fails proves nothing. **T2 is the control**: the *same* credential, the *same*
browser, the *same session* signs in successfully at the real origin. So the harness demonstrably
**can** observe a successful assertion — T4's failure is a refusal, not a broken harness.

## 4. NOT RUN: the counter-case, and exactly why

The intended **meta-test** was to widen the relying-party ID to the shared parent `localhost` — a
realistic misconfiguration — and show the **same attack succeeding**. That would prove both that the
harness can detect a bypass and precisely which setting the property rests on.

**It cannot be run with these hostnames.** Chrome refuses a broad RP ID over `.localhost` outright,
with the same `SecurityError` — because `.localhost` is **not in the public suffix list**, so
`app.localhost` and `evil.localhost` do not share a registrable parent.

That is the same fact that makes the claim demonstrable here, and it is also what blocks the
counter-case.

**To run it** needs two hostnames under a real registrable domain — for example `app.attest.test` and
`evil.attest.test`, with the RP ID set to `attest.test`. `.test` **is** a reserved TLD treated as
registrable, so the broad RP ID would be accepted and the attack should succeed.

**That requires editing `/etc/hosts`**, which is outside the workspace and awaits the operator's
approval.

> **Until then:** the claim that a *broad* relying-party ID is exploitable rests on reasoning and on
> Chrome's own error message — **not on a measurement.** It is recorded as a finding, not as a pass.

## 5. What this does and does not establish

**Established by measurement:**

- A passkey bound to a narrow domain **cannot** be used through an origin the attacker controls, even
  when the attacker relays the genuine page byte-for-byte.
- The relay is faithful — the victim cannot distinguish the page.
- Both directions work in the harness: a matching origin succeeds, a mismatched one is refused.

**Not established:**

- That a **broad** RP ID is exploitable — see §4. It is the reason the guidance below is stated as
  guidance and not as a measured result.
- **Phishing of the password**, on realms that still have one. The S5d work makes the privileged realm
  passkey-only, but the enrolment window (S5e) and the enrolment link (S5f) are deliberate password and
  bearer-token paths that a proxy could still abuse. **Those are the soft spots, not the passkey.**
- Real-world network conditions: TLS, real DNS, a real certificate. This runs over HTTP on loopback,
  which is a legitimate lab simplification but is **not** what a real attacker faces. A real phishing
  site needs a valid certificate for a domain it controls; WebAuthn's origin check does not depend on
  the certificate, so the conclusion should hold — but that inference is reasoning, not measurement.
- Attestation-based defences, which were deliberately relaxed here so a virtual authenticator could
  enrol. In production a YubiKey allowlist is an *additional* layer.

## 6. What this means for the design

The property that makes it work is narrow and specific: **the relying-party ID.**

- it must be a **domain the attacker cannot obtain a matching origin for**
- it must be as **narrow as the deployment allows** — the broader the RP ID, the more hosts can obtain
  assertions for the credential (see §4)
- and it must **never** be a value the application does not actually control

This is the one control in the whole design that does not depend on our code being correct. It is
enforced by the browser, against the origin, before any of our logic runs.

## 7. Reproducing

```bash
# the adversary-in-the-middle relay
./.venv/bin/python lab/keycloak/scripts/phishing_proxy.py --listen evil.localhost:9001 \
                                                          --upstream localhost:8080

./.venv/bin/python lab/keycloak/scripts/spike9-matrix.py     # 7 checks
```

`*.localhost` resolves to loopback on this platform, so no `/etc/hosts` edit is required for the
claim itself. The meta-test would require one.
