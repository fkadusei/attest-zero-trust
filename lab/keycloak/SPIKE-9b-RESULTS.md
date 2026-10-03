# S9b Results — is a BROAD relying-party ID actually exploitable?

**Status: RESOLVED — CONFIRMED BY MEASUREMENT. 7/7.**

S9 proved a passkey cannot be used through a phishing proxy. What it could not show was the
**counter-case**: that this depends on the relying-party ID being narrow, rather than on something else
entirely.

**It does, and here is the measurement.**

---

## 1. The result

| Check | Result |
|---|---|
| The suite creates its own fixtures, with a working password | **pass** |
| **Narrow** RP ID: a passkey registers | **pass** |
| **Narrow**: signs in at the real origin | **pass** |
| **Narrow CONTROL: the phishing origin is REFUSED** | **pass** — `rejected:SecurityError` |
| **Broad** RP ID: a passkey registers | **pass** |
| **Broad**: signs in at the real origin | **pass** |
| **THE COUNTER-CASE: the credential ANSWERS at the phishing origin** | **pass** — `resolved` |

The two rows that matter, side by side, same relay, same browser, same credential type — **only the
relying-party ID differs**:

| RP ID | Origin attempted | What the browser did |
|---|---|---|
| `app.attest.test` (narrow) | `evil.attest.test` | **`SecurityError`** — no assertion |
| `attest.test` (broad) | `evil.attest.test` | **`resolved`** — **a valid assertion** |

**That is the whole finding.** Phishing resistance is not a property of passkeys in the abstract. It is
a property of the **relying-party ID**, and the same relay succeeds or fails depending on how wide it
is set.

## 2. Stated precisely — what was and was not measured

**Measured:** under a broad RP ID the **browser produced a valid assertion for the attacker's origin.**
Under a narrow RP ID the same origin got `SecurityError` and produced nothing.

**Not measured:** the full session completing end to end through this hand-rolled relay. Our proxy did
not complete it — irrelevant to the security question, because an attacker with a real site relays the
assertion to the genuine server, and *the assertion is the thing that must not exist*. Its existence is
the finding.

The prose here is deliberately narrower than "the attacker signs in", because a relay completing a
session is plumbing while producing an assertion is the security boundary.

## 3. The blocker that turned out to be the real lesson

Two things had to be solved, and the second is worth more than the test.

**DNS.** The test needs two hostnames under a **real registrable domain**. `/etc/hosts` is the obvious
route and it is root-owned here, with `sudo` wanting a password this environment does not have. Chrome
can resolve them for itself:

```
--host-resolver-rules="MAP app.attest.test 127.0.0.1,MAP evil.attest.test 127.0.0.1"
```

`.test` **is** a reserved TLD treated as registrable, so a broad RP ID of `attest.test` is accepted.
**No system change was made — `/etc/hosts` was verified unchanged.** The offer to edit it was
appreciated and turned out not to be needed.

**Secure context — and this is the finding.** The first attempts failed with Keycloak reporting:

```
web_authn_registration_error_detail="WebAuthnUnsupportedBrowser"
```

**WebAuthn only exists in a secure context.** `*.localhost` is treated as trustworthy over plain HTTP,
which is exactly why S9 worked. A real domain over HTTP is **not**, so `window.PublicKeyCredential` is
undefined and the browser cannot do WebAuthn at all.

> **Resolvable hostnames would not have fixed this.** It was never a DNS problem. It needs TLS — or, in
> a lab, this flag:
>
> ```
> --unsafely-treat-insecure-origin-as-secure=http://app.attest.test:8080,http://evil.attest.test:9001
> ```

**This constrains anyone testing WebAuthn locally**, and it is recorded because it cost real time and
would cost it again.

## 4. What this means for the design

Phishing resistance rests on one setting, and it is now measured rather than argued:

- **The relying-party ID must be a domain the attacker cannot serve a matching origin for.** Set it to
  a shared parent and every host under that parent can obtain assertions for the credential.
- **It must be as narrow as the deployment allows.** A wider RP ID is a wider attack surface, and the
  measurement above is what that costs.
- **Never** point it at a value the application does not control.

The honest trade-off: a narrow RP ID means a credential registered on one host will not work on
another. `app.example.com` and `login.example.com` are different origins, and a credential bound to
one does not answer for the other. That is the price of the property, and it is a design decision to
make deliberately rather than by default.

## 5. What was NOT tested

- **A real TLS environment.** The secure-context requirement is satisfied here by a Chrome flag
  standing in for the certificate a real deployment would have. The WebAuthn origin check does not
  depend on the certificate, so the conclusion should hold — but that is reasoning.
- **The full session through the relay**, for the reason in §2.
- **Whether real attackers would choose this path.** Phishing the passkey fails; phishing the
  *enrolment* paths the project built deliberately (S5e's window, S5f's link) does not depend on RP ID
  at all. **Those remain the soft spots.**

## 6. Reproducing

```bash
./.venv/bin/python lab/keycloak/scripts/spike9b-meta.py    # 7 checks, ~3 minutes
```

Chrome is launched by the script with both flags; the relay runs on `0.0.0.0:9001` and rewrites URLs
to `evil.attest.test:9001`, never to the address it binds. Negative-tested: inverting the counter-case
check gives 5/6 and exit 1.
