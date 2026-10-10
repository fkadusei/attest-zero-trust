# S4b Results — other browsers

**Status: 2 of 3 engines resolved. Chromium (3 browsers, 6/6) and Gecko (manual, PASS). Safari remains.**

This slice exists because S4 was reported as "resolved" when **only Chrome** had been tested. That
deserved correcting: Chrome, Edge and Brave share one engine, so one engine had been tested and the
result was being described as browser behaviour.

---

## 1. The results

| Browser | Engine | Method | Result |
|---|---|---|---|
| **Chrome** 154.0.8037.95 | Chromium | automated | **6/6** |
| **Edge** 154.0.4258.53 | Chromium | automated | **6/6** |
| **Brave** 154.0.8037.58 | Chromium | automated | **6/6** |
| **Firefox** 157.0.1 | **Gecko** | **manual** (`manual.html`) | ✅ **PASS — key survived, same key, control passed** |
| **Safari** 26.6.2 | **WebKit** | — | ⚪ **not automated — manual** |

Every check in each run: the key survives a full quit and relaunch, still works, is provably the
**same** key rather than a fresh one, and the **control** — a newly generated key — is correctly
rejected.

### Gecko behaves the same way, and that is the point

Firefox was tested manually through `manual.html` — automating it is a project, not a step, and the
tooling gap is real: **`geckodriver 0.37.1` is the latest release and cannot drive Firefox 157.** It
fails to parse the version string (`Failed to get binary version`, `Invalid symbol 45, offset 11`).
Puppeteer was abandoned earlier for the same task with `session.subscribe timed out`.

The manual run, at `http://localhost:8099/manual.html`, reported:

```
The session key survived.
It still works: produced a 64-byte signature.
It is the SAME key, not a fresh one — so it genuinely came off disk.
Control passed: a fresh key is correctly rejected.
```

**Firefox 157.0, Gecko.** The key survived a full quit and relaunch, it is provably the *same* key
rather than a freshly generated one, and the control held.

**This is the finding that matters, and it is not "Firefox also passes".** Chrome, Edge and Brave all
run Chromium, so testing three of them says very little. **Gecko is a genuinely different engine with
its own storage and eviction behaviour** — and it behaves the same way. That is the first evidence
this behaviour is a property of browser storage generally rather than of one implementation.

The manual page is the record: it reports the browser's own `User-Agent`, so the claim is tied to a
version rather than to whatever happened to be installed.

Across all three Chromium browsers, `persist()` was refused (`false`) and the key survived anyway,
which is the same finding as S4: **that API guards against eviction, not against restarts.**

### The two engines that actually matter are still untested

Chromium is one engine in three skins. Gecko and WebKit are genuinely different, with their own
storage and eviction behaviour — so **Chrome passing tells us nothing about either.**

That remains the honest state: **one of three engines is automated.** Firefox and Safari are covered
by `manual.html`, which takes about a minute each.

## 2. Why Firefox could not be automated

Two separate toolchains were tried, and both failed in ways that are worth recording so nobody
repeats the attempt.

**Puppeteer** (which drives Chrome well) failed with:

```
session.subscribe timed out
```

under three different launch configurations — with a remote debugging port, with the remote-agent
preference set explicitly, and plain with a 90-second timeout. This is a WebDriver-BiDi handshake
problem between this puppeteer and this Firefox, not something a longer timeout fixes.

**geckodriver** (Mozilla's own driver) was then fetched as a standalone binary into `tools/bin`, since
Homebrew is root-owned here and could not install it. It started correctly and created a session —
and then failed:

```
POST /session/.../execute/async -> 404
{"error":"no such window","message":"Browsing context has been discarded"}
```

So Firefox launched, the session existed, and the browsing context was thrown away before any script
could run. A follow-up probe that tried the same thing with and without a fixed profile then **hung**
on session creation.

**Time-boxed and abandoned.** Three attempts across two tools is enough to conclude that automating
Firefox is a project, not a step. The manual page exists precisely for this, and the discipline of
time-boxing was written down after S5 for exactly this reason.

### Why a fixed profile was needed at all

WebDriver creates a **throwaway profile per session** by default. That would have made the test
meaningless in the most dangerous way: the key would appear "gone" in phase 2 simply because it was a
different browser, and the result would have been reported as *"Firefox evicts storage"* — a wrong
finding that looks like a real one.

So `run_firefox.py` pins the profile directory and writes a **marker file** into it before phase 1,
checking it in phase 2. If the profile had not persisted, the script aborts rather than reporting a
false negative. That guard was never reached, but it is the right guard to have.

## 3. Why Safari is not automated

Unchanged from S4, and both reasons are about not doing something intrusive:

- **Safari is open with the user's own windows**, and a meaningful restart test means quitting it.
  Closing somebody's browser to satisfy an experiment is not a reasonable thing to do.
- **Remote automation is disabled**, and enabling it is a settings change for the user to make, not
  for a test script.

`safaridriver` itself is present and responds, so this is a permissions and politeness boundary, not a
technical one.

## 4. Closing Firefox and Safari out — about a minute each

`lab/browser/manual.html` runs the identical two-phase test with two buttons and works in **any**
browser. It needs a real address rather than a file, because browsers keep storage per address:

```bash
python3 -m http.server 8099 --directory lab/browser
# open http://localhost:8099/manual.html
```

For each browser:

1. Press **Create and store a key**.
2. **Quit the browser completely** — not just the tab.
3. Reopen the same address and press **Check the key**.

It reports whether the key survived, whether it is the *same* key, and includes the same negative
control. One pass each for Firefox and Safari closes out the last two engines.

## 5. A note on identifying browsers

**Brave reports itself as `Chrome/154.0.8037.58`** in its user-agent string. The version string cannot
be used to tell Brave from Chrome — only the binary path can. Any future test that identifies the
browser under test by parsing the user agent will silently mislabel Brave as Chrome.

The runner therefore also **aborts if the reported browser does not match the one requested**, so a
mis-wired run fails loudly instead of producing a result attributed to the wrong browser. That guard
was added after an early attempt at this slice ran the *Chrome* binary while being invoked as `edge` —
it reported a perfect 6/6, and it was worthless.

## 6. Reproducing

```bash
node lab/browser/run.mjs chrome      # or: edge, brave
./.venv/bin/python lab/browser/run_firefox.py   # attempted; currently fails
python3 -m http.server 8099 --directory lab/browser   # then manual.html, any browser
```

Each browser gets its own profile directory (`/tmp/attest-s4-profile-<browser>`), deleted before the
run, so a pass cannot be a leftover from a previous one.
