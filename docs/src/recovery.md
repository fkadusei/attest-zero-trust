# Recovery, the weak link

Every strong authentication system is eventually attacked through its reset path. This page is short
because the principle is simple, and uncomfortable.

## The shape of the problem

An attacker who cannot phish a passkey does not give up. They request an account recovery, take over
the mailbox, and enrol a fresh credential. If that works, the passkey protected nothing at all.

!!! danger "Stated plainly"

    A phishing-resistant sign-in combined with an emailed-code reset is a phishing-vulnerable system.
    The strength of the front door is irrelevant if there is an unlocked side door with a sign on it.

This is not a hypothetical weakness. It is the most likely way this system is actually compromised in
practice, because it requires no flaw in the cryptography and no clever exploit — only a support
process that was designed for convenience under pressure.

## What we do instead

The rule is that **a recovery email never produces a logged-in session.** It produces permission to
*begin* enrolling a new passkey, and the person still has to complete a real ceremony on a real
device.

1. The request sends a link that opens a fresh enrolment, not a session.
2. A **brand-new passkey** must be created. A reset that sets a password would defeat the entire
   point, and the identity provider will happily do exactly that if asked — so the flow must use an
   enrolment action, not a credential reset.
3. Signals about the device and the network are gathered and scored.
4. If those signals look wrong, the request is **held for a human** rather than approved
   automatically.
5. The account owner is told. An attacker who already controls the mailbox therefore cannot act
   unnoticed, which is the specific case this step exists for.

## Scenarios, and what happens

| Scenario | What happens | Why |
|---|---|---|
| A second passkey is registered | Self-service using the remaining passkey | No support involvement, and no downgrade in assurance |
| All passkeys lost, email still works | Enrolment link with identity proofing, and a hold for review if signals are weak | Must not silently become an email-only login |
| The request looks suspicious | Support-assisted, with out-of-band verification | Deliberately manual |
| A privileged account needs recovery | Second admin approval, out-of-band verification, in-person key enrolment | See below |

## For privileged accounts: no self-service at all

Recovery for a platform admin requires:

- Out-of-band verification with the security team, not a support ticket.
- A **second** privileged admin approving the request. No single person can recover an account.
- A new hardware security key enrolled through a verified channel.
- The whole episode recorded in the tamper-evident audit log.

The asymmetry is deliberate. For staff, recovery being slow and awkward is a cost measured in
minutes. For the system, a compromised platform admin is a cost measured in the company.

!!! note "Why the asymmetry is worth the friction"

    A common objection is that this is too much process for a small team. The counter is that
    privileged recovery is rare, and the cost of getting it wrong once is unbounded, while the cost of
    getting it right is a few hours of two people's time. The two are not comparable.

## Detection matters as much as prevention

Recovery is the path most likely to be abused, so it needs telemetry from the first day rather than
as a later hardening step. Two signals in particular are worth alerting on:

- **A passkey enrolled shortly after a recovery.** This is what an account takeover in progress looks
  like, and it is far more informative than a failed sign-in.
- **A recovery request followed by a device that has never been seen on that account**, especially
  from a new network.

Neither prevents anything on its own. Both turn a silent takeover into a detected one, which is the
difference between an incident and a mystery.

## The uncomfortable summary

Passkeys remove an entire class of attack, and they are worth the effort. But they move the attacker
rather than eliminating them, and this is where they move to. A project that implements passkeys
beautifully and then ships a one-click reset link has done the hard part and skipped the important
part.
