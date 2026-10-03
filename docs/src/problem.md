# The problem it removes

Every control in this system exists because of a specific failure. This page explains those
failures, because a control whose purpose you cannot state is a control you will eventually remove.

## Passwords fail in one predictable way

A password is a secret you type into a page. That single fact creates everything that follows:

- People reuse them, so a breach anywhere becomes a breach here.
- They leak in bulk, and attackers try them everywhere at once.
- Most importantly: **a page can ask you for one, and you cannot tell whether the page is real.**

A convincing copy of a login screen collects the password, and the attacker simply logs in. No
cryptography has been broken. The login worked exactly as designed, for the wrong person.

## Adding a code was supposed to fix this. It does not.

The obvious fix is a second factor: something you have, as well as something you know. A one-time
code from an app or a text message. This does stop a stale password from a breach being useful on
its own, which is real progress.

But it does not stop a **live relay**, usually called an *adversary-in-the-middle* attack, or AiTM.

Here is the shape of it:

1. The victim receives a link to a convincing copy of the real sign-in page.
2. That copy is not a static fake. It is a proxy. It forwards everything to the real site, live.
3. The real site asks for a one-time code. The victim types it into the fake page.
4. The proxy relays the code instantly, and the real site accepts it.
5. The attacker now holds a fully authenticated session.

**The victim's multi-factor authentication worked perfectly throughout.** Nothing was bypassed.
Nothing was broken. The code was simply carried from one place to another by the attacker, exactly
as the victim intended it to be carried — just to the wrong destination.

This is not a theoretical attack. Kits that do this are sold commercially as a service.

!!! danger "The uncomfortable conclusion"

    Anything the user can be persuaded to *tell* the attacker will eventually be told to the
    attacker. Codes, approvals, and passwords all share that property. Security that depends on a
    person noticing a fake address is security that fails on a bad day.

## What actually stops it

A **passkey** — a credential based on public-key cryptography — stops it, and it stops it for a
structural reason rather than because users got better at spotting fakes.

A passkey is not a better password. It is a **key pair**:

- The **private half** is generated on your device and never leaves it. It is not sent to the server,
  not stored in a backup we control, and not typed anywhere.
- The **public half** is given to the website, where it is useless for impersonating you.
- When you sign in, the device signs a fresh random challenge — and critically, the data it signs
  includes **the address of the site that asked**.

That last point is the whole trick. A proxy pretending to be `attest.example.com` is not at
`attest.example.com`. The device either refuses to produce a signature for the wrong address, or
produces one that covers the wrong address, which the real site rejects. **There is no reusable
secret to relay, so there is nothing to phish.**

!!! info "The phrase to remember"

    This property is called being **phishing-resistant**, and it is a specific technical claim, not a
    compliment. It means the method survives a user being successfully tricked. Of the common
    authentication methods, only passkeys and hardware security keys qualify.

## The comparison

| Sign-in method | Stops a copied password? | Stops a live relay? | Why |
|---|---|---|---|
| Password alone | **No** | **No** | The secret is typed into whatever page asks for it |
| Password + SMS code | Partly | **No** | The code is relayed in real time; SMS can also be intercepted |
| Password + authenticator app | Partly | **No** | Exactly as relayable as SMS |
| Password + push approval | Partly | **No** | The relay triggers a genuine prompt, which the victim approves |
| One-time code with number matching | Partly | **No** | Better, but still a value the user can be persuaded to hand over |
| **Passkey** | **Yes** | **Yes** | The signature is bound to the real site's address |

## Where attackers go instead

Making sign-in unphishable does not end the attack. It moves it.

The usual next target is **account recovery**. If "I have lost my phone, email me a link" ends with
someone logged in, then the strongest credential in the world protected nothing. The attacker does
not break the lock; they use the door marked *reset*.

!!! danger "The most likely way this system is broken in practice"

    Not a clever attack on the cryptography, and not a flaw in the passkey standard. A recovery
    process that quietly reintroduces everything the passkey removed. This is why it has
    [its own page](recovery.md) rather than a bullet point.

## Why this matters specifically for Attest

The threat is not abstract for a compliance product, for three reasons.

**The data is concentrated.** A compliance platform holds evidence about how every customer's
business operates — the internal detail companies are most careful about. One breach is a breach of
every customer at once.

**There is a natural third party.** External auditors have legitimate access, hold real credentials,
and sit outside the customer's management. They are both authorised and untrusted, which is exactly
the situation Zero Trust exists for.

**The audit trail is a product feature.** Customers ask who could see their data and when. A system
that cannot answer that convincingly is not sellable, regardless of how strong its cryptography is.

That combination is why the next page is about architecture rather than about a login screen.
