# S4 Results — browser session key persistence

**Status: RESOLVED for Chrome.** The key survives a full browser quit and comes back as the *same*
key. **Safari is untested** — see section 6, which explains why and how to close it in a minute.

Tested against **Chrome 154.0.8037.95** on macOS.

---

## 1. The question

After sign-in our page creates a secret key and stores it in the browser's own storage. Every request
afterwards is signed with it. That is what makes a stolen session pass useless.

If the browser throws that key away, then either the user signs in again on every visit, or — far
worse — we quietly stop checking, because a check that always fails is a check somebody disables. The
second outcome is the failure this whole design exists to prevent.

## 2. First, which key

There are two keys in this design and they are stored in completely different places. Confusing them
makes this experiment look like it is about passkeys, and it is not.

| | The passkey | The session key |
|---|---|---|
| What it is for | Logging in | Protecting the session afterwards |
| Who stores it | The user's device — iCloud Keychain, another password manager, or a hardware key | **Us**, in the browser's IndexedDB for our site |
| Do we ever see it | **No.** We keep only the public half | Yes, in the sense that our page reads it back |
| This experiment | not covered | **this is what was tested** |

## 3. Method

Two phases against a real Chrome with a real profile directory on disk:

1. **Phase 1** — create the keys, store them, confirm they work, then **quit the browser entirely**.
2. **Phase 2** — relaunch with the *same* profile, look for the keys, and use them.

The quit in between is the whole point. Anything held only in memory is gone, so whatever still works
in phase 2 genuinely came off disk.

**Two keys are stored, and the difference between them is the only variable.** The real design uses a
*non-extractable* key — the page can use it but no script can ever read it out. That is the right thing
to ship, and it also means we cannot read it back to prove it is the *same* key. So:

- `session-key` — non-extractable, faithful to the design. Proves it persists and still works.
- `probe-key` — extractable, so its public half can be recorded before the restart and compared after.
  Persistence behaviour is identical; only exportability differs. Proves it is the same key.

## 4. Results

| Check | Result |
|---|---|
| The session key survived the restart | **PASS** |
| It still works — produced a signature | **PASS** |
| The probe key survived | **PASS** |
| The probe key still works | **PASS** |
| It is the **same** key, not a freshly generated one | **PASS** |
| **Control:** a brand-new key is correctly rejected | **PASS** |

**6 of 6.**

The control is not decoration. Without it, a comparison that always returned "same" would have looked
exactly like a pass. Forcing a freshly generated key through the same comparison and requiring it to
*fail* is what makes the "same key" result mean anything.

Storage reported `persist() → false`, `persisted() → false`, with roughly 3 KB used of a ~10 GB quota.

## 5. Findings

### The non-extractable key survives a full restart, and it is the same key

This was the main risk and it does not exist. A key that no script can read is still written to disk
and read back by the browser, intact, across a complete application quit.

### `persist()` returning false did not matter — and knowing why matters

The browser **declined** to mark our storage as persistent, and the key survived anyway.

Those two facts are not in tension once you see what the API is actually for. A normal quit-and-relaunch
is not an eviction event, so nothing was at risk. Persistent storage protects against the things that
*do* evict:

- storage pressure, when the browser reclaims space
- Safari's rule of deleting site data after roughly seven days without a visit

So the practical conclusion is narrower and more useful than "we need `persist()` to succeed":
**persistent storage is not required for the key to survive a restart, and we should not assume we
will ever be granted it.** The design has to tolerate the key disappearing — which brings us to the
next point.

### The design must define what happens when the key is missing

If the key is gone, the only safe behaviour is to treat it as **no session** and ask the user to sign
in again with their passkey, which creates a fresh key. The unsafe behaviour — falling back to
unbound tokens so the user is not inconvenienced — is exactly the silent downgrade this project exists
to prevent, and it must be explicitly forbidden in the code and in a test.

Sessions are short by design (30 minutes idle, 10 hours maximum), so this is a rare event, and the
cost of it is a sign-in rather than a support ticket.

## 6. What was NOT proven

**Only one browser was tested: Chrome.** S4b later extended this to Edge and Brave — all three
Chromium browsers pass 6/6 — leaving Firefox and Safari manual. See
[SPIKE-4b-RESULTS.md](SPIKE-4b-RESULTS.md). That is the honest headline. Everything else on this
machine — Firefox, Edge, Brave and Safari — is untested. An earlier draft of this section mentioned
only Safari, which understated the gap.

| Browser | Engine | Status | How to close it |
|---|---|---|---|
| **Chrome** 154 | Chromium | ✅ **tested, 6/6** | done |
| **Edge** 154 | Chromium | ⚪ untested | Automated. *Same engine as Chrome*, so this adds little beyond confirming it |
| **Brave** 154 | Chromium | ⚪ untested | As above |
| **Firefox** 156 | Gecko | ⚪ **untested — a genuinely different engine** | Not automatable with the tools here (see below). Manual, or a different driver |
| **Safari** 26 | WebKit | ⚪ **untested — a genuinely different engine** | Manual — see below |

The two that matter are **Firefox and Safari**, because they are the only ones that are not Chromium.
Chrome passing tells us about Chrome's storage engine, not about Gecko or WebKit.

| Not proven | Why it matters | How to close it |
|---|---|---|
| **Firefox** (Gecko) | A different engine with its own storage and eviction behaviour | Manual, or `geckodriver` — puppeteer cannot drive it here |
| **Safari** (WebKit) | The browser most likely to evict storage, and widely used by the customers this product targets | A one-minute manual test — see below |
| A full **laptop reboot** | A clean application quit is a good proxy, but not the same thing | Needs a machine restart, so it is a manual step |
| Behaviour after **7+ days** idle | Safari's eviction rule fires on elapsed time, which cannot be simulated quickly | Leave a tab and return next week, or trust the rule's documentation |
| **Private / incognito** windows | Users may expect to sign in every time there; worth confirming it degrades safely rather than silently | Quick manual check |
| Eviction **under storage pressure** | Hard to provoke deliberately | Not planned |

**Firefox could not be automated.** Puppeteer's Firefox support failed on every attempt —
`session.subscribe timed out` — with three different launch configurations. Driving it would mean a
different tool (`geckodriver`), which is a dependency to add rather than a setting to change.

**Safari was not tested because it could not be tested safely.** Safari was open with the user's own
windows, and a meaningful test requires quitting it completely. Its automation setting was also
disabled. Closing someone's browser to satisfy an experiment is not a reasonable thing to do, so the
test was left to a manual step instead.

### Closing Safari out

`lab/browser/manual.html` is a self-contained page that runs the same two-phase test with two buttons,
and it works in **any** browser — so it closes Firefox, Edge, Brave and Safari in one pass. It needs a
real web address rather than a file, because browsers keep storage per address:

```bash
python3 -m http.server 8099 --directory lab/browser
# then open http://localhost:8099/manual.html in Safari
```

Press **Create and store a key**, quit Safari completely, reopen the same address, and press
**Check the key**. It reports whether the key survived, whether it is the same key, and includes the
same negative control.

## 7. What this changes in the design

Nothing structural. The design assumed the key persists across a restart and must be regenerated from
a fresh sign-in if it does not; both are now confirmed as workable. Two things are pinned down:

1. **The safe fallback is mandatory and must be tested.** Key missing ⇒ no session ⇒ sign in again.
   Never fall back to an unbound token.
2. **We cannot rely on being granted persistent storage**, so the design must be correct without it.
   If we ever want longer-lived sessions, that becomes a question worth revisiting — and it would make
   Safari's eviction rule matter for the first time.

## 8. Reproducing

```bash
node lab/browser/run.mjs                  # Chrome, fully automated, ~30 seconds
python3 -m http.server 8099 --directory lab/browser   # then Safari, by hand
```

The script deletes its profile directory first, so a pass cannot be a leftover from a previous run.
