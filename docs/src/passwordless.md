# Sign-in, end to end

This page follows one sign-in from start to finish, then explains the part that took the longest to
get right: proving that the key being registered is genuinely a piece of hardware.

## The ceremony

A passkey sign-in is called a *ceremony* because it is a fixed sequence of steps that both sides
must perform in order. Skipping or reordering them breaks the security property.

| Step | What happens | Why it is there |
|---|---|---|
| 1 | The browser loads our sign-in page and begins a WebAuthn ceremony | Establishes that a real browser is involved |
| 2 | The page declares **which web address** the credential must be bound to | This is the anchor for everything that follows |
| 3 | The device is asked to authorise: a fingerprint, a face, a PIN, or a touch on a security key | Proves a person is present, not just a device |
| 4 | The device signs a fresh random challenge — and the signature covers the address from step 2 | Makes the signature useless anywhere else |
| 5 | The identity provider checks that signature against the public key it stored at registration | Confirms this is the right credential |
| 6 | Short-lived tokens are issued, bound to a second key held by this browser | So a stolen token is useless — see [after sign-in](sessions.md) |

## Why step 2 is the whole trick

A phishing relay wants the victim to believe they are at `attest.example.com` while actually being
at `attest-example.evil.test`. With a password, that works, because a password is just characters and
characters do not check addresses.

A passkey does check. The data the device signs includes the address the browser believes it is
talking to, and the device will only produce that signature if the address matches the credential's
recorded **relying party ID** — the permanent binding between a credential and one website.

At the relay's address, one of two things happens: the device refuses outright, or it produces a
signature covering the wrong address, which the real server rejects. Either way the attacker gets
nothing usable.

!!! info "There is no secret to steal"

    This is the part that is genuinely different from every code-based method. A password, a text
    message code, and a push approval are all *values the user can be persuaded to hand over*.
    A passkey is not a value. What the device produces is only valid for the address that asked, so
    there is nothing worth handing over.

## What is stored, and what is not

After a registration, the server holds a **public** key. It cannot be used to impersonate anyone.
The private key never leaves the device — not to the server, not to us, and not to a backup we
control. The worst outcome of our credential database being stolen is that the attacker learns a list
of public keys.

## Two kinds of passkey, and why the difference decides the design

"Passkey" covers two things that behave very differently.

<div class="grid" markdown>

<div class="card" markdown>
**A synced passkey**

The key is copied between your devices by a cloud account — iCloud Keychain, Google Password Manager,
and similar. Lose a device and you have lost nothing, which is why it is the right default for most
people.

The catch: what protects the account is now **your cloud account**, not the device in your pocket.
Compromise that one account and the attacker holds a working credential.
</div>

<div class="card" markdown>
**A device-bound passkey**

The key is generated inside a secure chip and never leaves it. A physical security key, or a laptop's
secure enclave. There is no cloud copy to steal, because there is no copy.

The catch: lose the key and you have lost the credential. And it means carrying something.
</div>

</div>

For a customer's account that trade is obviously worth it. For an account that can read every
tenant's data at once, it is not: it would reduce the most powerful account in the system to the
security of a consumer cloud login.

!!! note "This is not just our opinion"

    NIST publishes a supplement to SP 800-63B specifically about *syncable authenticators* —
    credentials that get copied between devices. Its existence is the acknowledgement that a synced
    passkey changes the assurance calculation. The precise clause-level consequence for our
    configuration is still an open item we intend to have reviewed independently rather than
    self-certified — see [what we tested](verification.md).

## How the two realms differ

The system runs two separate identity worlds, so the strict rules apply only where they are needed.

| | Customer realm | Privileged realm |
|---|---|---|
| Who uses it | Customers, their staff, external auditors | Our own staff |
| Password sign-in | Yes, during migration | **Not configured at all** |
| Passkeys | Yes | Yes — the only way in |
| Which authenticators | Anything reasonable | Hardware only, by explicit allowlist |
| User verification | Preferred | Required |
| Attestation | Not requested | **Required** |
| Web address | `attest.example.com` | `admin.attest.example.com` |

The separate web address is doing real work. Because a passkey is bound to an address, a credential
registered for the customer system physically cannot be used against the admin system. That
separation is enforced by the browser's own security model, not by our code.

## The hard part: proving the key is real

Suppose you decide platform admins must use a hardware security key. You write that down. Now the
difficult question: **how does the server know?**

When someone registers a passkey, the server receives a public key. A public key generated by a
physical security key and one generated by a software authenticator look identical.

The answer is a field called the **AAGUID** — a small identifier that says which *model* of
authenticator created the credential. If you know the AAGUIDs of approved hardware keys, you can keep
a list and refuse everything else.

### But a claim is not proof

The AAGUID arrives inside data signed by the credential. That proves the credential is *saying* it,
not that it is true. A software authenticator can put any AAGUID it likes in there.

What turns the claim into proof is **attestation**: a manufacturer's signature over the
authenticator's properties, vouching for them. An authenticator can be asked to provide this, or
asked not to. That request is called the **attestation conveyance preference**, and it turned out to
be the difference between a control that works and one that only looks like it does.

!!! danger "The trap, and why testing found it"

    With attestation *not* requested, the AAGUID is a self-declared claim. An allowlist evaluated that
    way still turns away honest authenticators — but a determined attacker using a software
    authenticator could simply declare an approved AAGUID and walk in. The allowlist would look
    configured and be worthless.

    **Requesting attestation is what gives the allowlist meaning**, because it is what makes the
    AAGUID something the server can actually trust.

The cost of requiring attestation is real: any authenticator that cannot produce it will be refused,
including many platform passkeys. For a realm whose users all hold hardware keys by policy anyway,
that cost is acceptable — and it buys the only configuration where the requirement means what it
says.

| Configuration | Turns away synced passkeys | Is the AAGUID trustworthy? | Cost |
|---|---|---|---|
| Allowlist, no attestation | Yes | **No — self-declared** | None |
| **Allowlist + attestation** | Yes | **Yes** | Refuses authenticators that cannot attest |
| Attestation only | Yes | Yes | No per-model control |

**Our choice: allowlist plus required attestation, on the privileged realm only.** The customer realm
keeps the friendlier setting, where convenience matters more than proof.

## Ending enrolment: two keys, not one

Users are asked to register **at least two** credentials before the second counts for recovery
purposes. One passkey plus a lost device equals a locked-out user and a support ticket — and support
tickets are what eventually pressure an organisation into re-introducing text-message codes, undoing
everything. Two credentials is the cheapest structural fix.

## What this stops, and what it does not

!!! success "Stopped"

    A copied password. A live relay that forwards the real login in real time. A stolen passkey from a
    cloud sync account, for privileged accounts specifically. Push-notification spam and SIM swapping,
    because neither mechanism is offered anywhere in this system.

!!! warning "Not stopped"

    A stolen session token — mitigated separately by [token binding](sessions.md), not by the passkey.
    Script injected into our own page. A malicious browser extension. A fully compromised device.
    Recovery, if that path is weak — which is why it has [its own page](recovery.md).
