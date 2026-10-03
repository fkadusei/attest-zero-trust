# What we tested

A design document that claims a control works is worth very little until something has tried to break
it. This page records what has actually been run, what it proved, and — just as importantly — what it
did not.

!!! warning "Four experiments are done. One of them failed."

    It would be easy to read this page as "the security is verified". It is not. Two specific claims —
    that hardware keys can be enforced, and that token binding is real and implementable — have been
    demonstrated with controlled experiments. Everything in the list further down is not, and that
    list is longer.

## How verification works here

The project runs **verification spikes**: short, focused experiments that each answer one question
before the design is frozen. A spike is deliberately cheap and deliberately bounded — the goal is to
be wrong early, when being wrong is inexpensive.

The reasoning is simple. Some assumptions, if wrong, force a redesign. Those are worth testing before
any code is written, not after. Others are cheap to change later and can wait.

## The first: can we actually enforce hardware keys?

### The question

The design says privileged accounts must use hardware security keys. Does the identity provider
actually **reject** a non-approved authenticator at registration — or does it merely store the setting
and do nothing with it?

This matters because a saved setting is not an enforced control, and the difference is invisible from
the configuration screen. It would have been easy to configure the allowlist, see it persist, and
declare the requirement met.

### How it was tested

A local Keycloak instance, a real Postgres database, and a browser driven by automation using a
**virtual authenticator** — a simulated security key that completes genuine WebAuthn ceremonies and
whose properties we control.

The critical detail: a virtual authenticator reports an **all-zero AAGUID** and **no attestation**.
That makes it behave exactly like the case we were most worried about — an authenticator that
declines to prove what it is.

### The results

Each row changes exactly one thing, so every rejection has exactly one possible cause. Two of the six
are **controls**, and they are the reason the others mean anything.

| # | Realm | Allowlist | Authenticator type | Attestation | Result |
|---|---|---|---|---|---|
| A | Customer | empty | external | not requested | Accepted |
| B | Privileged | hardware only | external | not requested | **Refused** |
| C | Privileged | **empty** | external | not requested | Accepted *(control)* |
| D | Privileged | empty | **built-in** | not requested | **Refused** |
| E | Privileged | empty | **built-in** | not requested | Accepted *(control)* |
| F | Privileged | empty | external | **required** | **Refused** |

**B against C isolates the allowlist.** Both rows are the same realm, the same authenticator type, the
same attestation setting and the same transport. Only the allowlist contents differ, and only the
allowlist changed the outcome. The allowlist is genuinely enforced.

**D against E isolates the authenticator-type restriction** the same way. Row E proves that the
built-in authenticator type works at all in this setup, so row D's refusal cannot be an artefact of
the test harness.

### What it proved

!!! success "Established by experiment"

    - The AAGUID allowlist is **enforced at registration**, not merely stored.
    - The authenticator-type restriction is **enforced**.
    - An authenticator that **declines to attest is refused**, not quietly admitted. Its all-zero
      AAGUID does not match the allowlist. This disproves the silent-bypass risk we had recorded in
      the threat model.
    - The identity provider **does expose the AAGUID** of registered credentials, so this can be
      audited after the fact rather than only enforced at the door.

### The unexpected result, which mattered most

Row F differs from row A in exactly one setting: attestation is *required* rather than not requested.
It was refused.

That showed requiring attestation is an **active requirement**, not a passive preference — it will
refuse anything that cannot provide proof. On its own that is a cost.

But combined with the reasoning above, it is also the finding that changed the design. Without
attestation, the AAGUID is a self-declared claim and an allowlist built on it can be spoofed by a
software authenticator. Requiring attestation is what makes the allowlist meaningful rather than
decorative.

!!! info "This is what a spike is for"

    We set out to test whether the allowlist works. The more valuable result was discovering *why it
    works when it works*, and therefore which configuration is the one worth shipping. That would not
    have come out of reading documentation.

### Corrections the spike forced

Testing found several things that reading documentation had got wrong. They are listed because the
pattern matters more than the specifics: **the identity provider silently ignores setting names it
does not recognise**, so a wrong name produces configuration that looks applied and does nothing.

- Three setting names in the original design were wrong, including one that would have been ignored
  without complaint.
- There are **two** separate resident-key settings with different defaults, not one.
- The default user-verification level for the passwordless policy is already the stricter value, so
  the customer realm has to *lower* it rather than raise it.
- The identity provider **does not validate AAGUID format**. A typo is accepted verbatim, producing a
  silently dead allowlist entry that fails closed — a lockout rather than a bypass, but a real
  operational hazard. The build checks now validate the format themselves.
- The default sign-in flow **requires a password form**, and the passkey authenticator is not in it at
  all. Removing the password from the privileged realm is therefore real configuration work, not a
  toggle — and during testing a password login to the privileged realm succeeded, confirming it.

## The second: is a stolen token really useless?

Sign-in being unphishable closes one door. This experiment tests the other one: that a session token
stolen afterwards cannot be used.

### The question

We claim a stolen token is inert because it is bound to a key the thief does not have. Two halves, and
they fail differently:

1. **Is the binding real?** Does the identity provider actually write the key's fingerprint into the
   token, and does a resource server actually refuse a bound token that arrives without a valid proof?
2. **Can we implement the check?** The identity provider verifies the proof when it *issues* a token,
   but it is not in the request path for our own API — so our API has to verify the proof itself. That
   is the one piece of genuinely custom security code in the whole system.

### How it was tested

No browser and no passkeys were needed, which made this much cheaper than the first experiment. A
password grant against a client configured to require bound tokens exercises the same machinery.

Proofs were generated with a real P-256 key — a small signed statement carrying the request method,
the URL, a one-time identifier, and a hash of the access token. The identity provider's own user
information endpoint was then used as a **reference resource server**: because it implements the
standard correctly, it gives us something known-good to test our own logic against.

### The results

| Behaviour | Expected | Result |
|---|---|---|
| Token presented with no proof at all | Refused | **Correct** |
| Bound token sent the ordinary bearer way | Refused | **Correct** |
| Token with a valid proof | Accepted | **Correct** |
| Proof signed by a different key | Refused | **Correct** |
| Proof naming a different URL path | Refused | **Correct** |
| The same proof replayed | Refused | **Correct** |

**Six of six.** A bound token without a matching proof is genuinely inert, and replay is refused.

Our own verification logic — the code that would actually ship — was then tested against the same
cases plus two of its own, and passed all six. So the authorizer is not merely designed; the logic is
demonstrated, including the cases that matter most: a proof for a *different* token is refused, and a
proof with the token binding missing entirely is refused.

### The three traps, and why they are worth writing down

!!! warning "These would each have cost real debugging time in production"

    **A bound token must be sent a different way.** Presenting it the ordinary way — the
    `Authorization: Bearer` scheme everyone knows — fails, and the error the server returns points at
    the *bearer* mechanism, sending you to investigate the wrong layer entirely. The standard requires
    a distinct `DPoP` scheme for bound tokens, and it is enforced. Our authorizer must require that
    scheme and refuse the ordinary one rather than quietly accepting it, because an unbound token is
    exactly what this control exists to prevent.

    **The proof must carry a hash of the token it is for.** Without it, the server returns
    "token verification failed" — a message that mentions neither the proof nor the missing field. This
    was the single hardest thing to diagnose in the experiment. The silver lining is that checking the
    hash closes a real gap: otherwise a proof captured for one token could authorise a different one.

    **The reference implementation is slightly more relaxed than we will be.** It compares the proof's
    URL at path level but ignores the query string, so a proof minted for one query was accepted for
    another. That is not a hole on its own, because replay and the token hash still hold, but it means
    the query string is not covered by the binding. Our authorizer compares the full URL, and does so
    deliberately.

### What this changes

Nothing structural, which is the good outcome. The design assumed the identity provider binds tokens
and that our API must verify proofs; both are now confirmed rather than assumed. Three implementation
details are pinned down, and the working prototype becomes the reference for the real implementation.

## The third: does the browser keep the key?

Two keys exist in this design, and they live in different places. **The passkey** — what you log in
with — lives on the user's own device and we never see it. **The session key** is made by our page
after login and kept in the browser's own storage, and it is what signs every later request.

This experiment is about the second one. If the browser throws it away, either the user signs in
repeatedly, or — much worse — the check quietly stops being enforced, because a check that always
fails is a check somebody eventually disables.

### How it was tested

Two steps against a real browser with a real profile on disk: create the keys and store them, then
**quit the browser completely**, then relaunch and look for them. The quit in between is the whole
point — anything held only in memory is gone, so whatever still works genuinely came off disk.

Two keys were stored, differing in one respect only. The real one is **non-extractable**: the page can
use it but no script can ever read it out. That is the right thing to ship, and it also means we cannot
read it back to prove it is the *same* key. So a second, readable twin was stored alongside purely so
its public half could be recorded before the restart and compared after.

### The results

| Check | Result |
|---|---|
| The session key survived the restart | **Correct** |
| It still works — produced a signature | **Correct** |
| It is the **same** key, not a freshly generated one | **Correct** |
| **Control:** a brand-new key is correctly rejected | **Correct** |

**All four.** The control matters: without also feeding a *fresh* key through the same comparison and
requiring it to fail, a check that always answered "same" would have looked exactly like a pass.

### What it settled, and the surprise

!!! info "Asking the browser to protect our storage is not what keeps the key safe"

    The browser **declined** to mark our storage as protected — and the key survived anyway.

    Those two facts are not in conflict once you see what that protection is actually for. Closing and
    reopening a browser is not an eviction event, so nothing was ever at risk. The protection guards
    against the things that *do* evict: storage pressure, and Safari's rule of deleting site data
    after roughly seven days without a visit.

    The practical conclusion is therefore narrower and more useful: **we do not need that protection
    for this to work, and we must not assume we will ever be granted it.**

That leads directly to a rule the software must enforce and test:

!!! warning "If the key is missing, the session is over"

    The only safe behaviour is to treat a missing key as *no session* and ask the user to sign in
    again, which creates a fresh key. The unsafe behaviour — quietly falling back to an unprotected
    pass so as not to inconvenience anyone — is precisely the silent downgrade this project exists to
    prevent. Sessions are short by design, so the cost is a sign-in rather than a support ticket.

**Not yet done:** the same test in **Safari**, which is the browser most likely to evict stored data,
and a full laptop restart. Both are manual jobs; a page is provided that makes the Safari one a
one-minute task.

## The one that failed: requiring a stronger check

Not every experiment succeeds, and this page would be misleading if it only listed the ones that did.

**The claim:** for sensitive actions — exporting who can see what, or an administrator looking across
all customers — the user should be made to prove themselves again, right then. The plan assumed the
identity provider could enforce this through an "authentication level": the application asks for a
higher level, and the provider demands whatever extra credential that level requires.

**The result: it did not work.** The extra check fired regardless of the level requested — a higher
one, a lower one, or none at all. So there is currently no working step-up.

This was not a configuration mistake. The setting was verified by reading it back from the server, and
**five different ways of requesting a level** all behaved identically. What is *not* known is whether
the fault lies in the flow arrangement or in the feature itself; there is one cheap test left that
would tell the two apart.

### A follow-up found something worse

Rather than keep guessing at the flow configuration, we looked up how the component actually behaves.
That surfaced a vulnerability record describing **the same component, the same scenario, and exactly
the failure this control was meant to prevent**:

> **CVE-2026-97176**, published nine days before our test. An authenticated user with a low-level
> session can obtain a token asserting a **higher** level than they actually performed.

- **Fix state: affected. Mitigation: "not available".**
- The affected package ships in our build.

So the mechanism is rejected rather than merely unverified. Whether it can be configured correctly is
now beside the point: **a control an attacker can bypass is not a control, however well configured.**

!!! danger "The rule this establishes, which outlives step-up"

    **Never trust the `acr` claim for a step-up decision** — or any claim of this shape.

    A claim the issuer *writes* is not a claim a resource server can *rely on* without checking. This
    is the same lesson as the token-binding experiment, where the identity provider bound a token but
    our own API still had to verify it. We have now learned it twice, so it is written down as a
    principle rather than an incident.

!!! warning "What replaced it"

    Force a genuine re-authentication, and judge **how recently** it happened rather than what level
    was claimed: `prompt=login` with `max_age=0`, and the **`auth_time`** claim — which records when
    authentication actually occurred and is unaffected by a flaw in how a *level* was computed.

    That is a plan, not yet a proven control, and it has its own test outstanding.

## What is NOT yet proven

This list is the honest counterpart to the section above. None of it is a surprise or a defect; it is
simply work that has not been done.

| Not proven | Why it matters | What it needs |
|---|---|---|
| That a **real** approved hardware key registers successfully | The virtual authenticator can only demonstrate refusal, because it cannot attest. The failure mode we know about is lockout, not bypass — but the happy path is unconfirmed | A physical security key |
| What AAGUIDs real platform passkeys report | Determines which control is actually doing the rejecting in production | Testing across iCloud Keychain, Google Password Manager, Windows Hello |
| That sign-in survives a **phishing proxy** | This is the headline claim of the whole project | A live relay test against the real flow |
| That token binding works **end to end** | The *logic* is now proven, but not that the required header survives every network hop. A hop that strips it breaks the binding silently — and the tempting "fix" would be to disable the check | A header-survival test through the real edge, plus deployed infrastructure |
| That **Firefox** and **Safari** keep the key — the two non-Chromium engines | Chromium (Chrome, Edge, Brave) is automated and passes 6/6, but all three share one engine, so that says nothing about Gecko or WebKit | A one-minute manual test each; a page is provided |
| That a **browser** keeps its key across a full laptop restart | Chrome holds it correctly, but Safari is the browser most likely to throw stored data away, and it is widely used. If it evicts, users sign in more often — annoying, but safe, provided the safe fallback is actually implemented | A one-minute manual test; a page is provided |
| That revocation takes effect in under a minute | Token expiry alone is far too slow to be the answer | A revocation-latency measurement |
| That the identity provider **clusters** on our chosen platform | A single instance is not a viable production target | Two instances, session replication, failover |
| The NIST analysis for syncable authenticators | Determines whether an assurance claim can be made publicly | Independent review, not self-certification |

!!! note "Why the first row is the important one"

    Every other gap is engineering that can be scheduled. The first is the one where a wrong
    assumption would mean the privileged-access requirement does not work as intended for real users,
    and it needs hardware rather than more code.

## How this is reproducible

The lab lives in `lab/keycloak/` and runs in containers. The results above were produced by scripts
committed alongside it, so anyone who doubts the conclusion can re-run it:

```bash
cd lab/keycloak
docker compose up -d                            # identity provider + database
python3 scripts/configure-realms.py             # apply WebAuthn policies, assert they persisted
bash scripts/run-matrix.sh                      # the hardware-key matrix
../../.venv/bin/python scripts/dpop_spike.py    # token binding, and our own verifier
```

The same directory holds the raw write-ups for both experiments, including the automation details and
the workarounds required to drive a browser through a real WebAuthn ceremony.

## What this means for the rest of these pages

Read the other pages as **design**: considered, documented, and in three important places demonstrated.
Read this page as **evidence**, and take the unproven list seriously.

When someone asks whether the system is secure, the honest answer is that two of its load-bearing
claims have been tested and hold, that the failures we were most worried about turned out not to
exist, and that roughly a dozen other claims remain design work. That is a better position than most
projects at this stage, and it is not the same as being finished.
