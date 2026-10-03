#!/usr/bin/env python3
"""S4b — Firefox (Gecko): does it keep the session key across a restart?

WHY THIS IS A SEPARATE SCRIPT
    Chrome, Edge and Brave all run Chromium, so testing them says nothing about
    Firefox — a genuinely different engine with its own storage and eviction
    behaviour. That makes it the most valuable untested browser alongside Safari.

WHY NOT PUPPETEER
    Puppeteer's Firefox support failed on every attempt here with
    `session.subscribe timed out`. Firefox is driven through geckodriver
    instead, over plain WebDriver HTTP, using a standalone binary fetched into
    tools/bin so nothing is installed system-wide.

THE AWKWARD PART
    WebDriver normally creates a THROWAWAY profile per session, which would
    defeat a restart test entirely — the key would look "gone" because the
    browser is a different browser. So the profile directory is fixed and passed
    through to Firefox explicitly.

    Phase 1 also writes a marker file into the profile directory, and phase 2
    checks it is still there. Without that, a failing profile hand-off would be
    indistinguishable from a browser that evicts storage — and we would report
    the wrong finding.

Usage:
    python3 lab/browser/run_firefox.py
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
GECKODRIVER = ROOT / "tools" / "bin" / "geckodriver"
FIREFOX = Path("/Applications/Firefox.app/Contents/MacOS/firefox")
PROFILE = Path("/tmp/attest-s4-firefox-profile")
PORT = 8099
WD_PORT = 4445
ORIGIN = f"http://localhost:{PORT}"
WD = f"http://127.0.0.1:{WD_PORT}"


# --------------------------------------------------------------------------
# A minimal origin. IndexedDB is unavailable on opaque origins such as
# file://, so the test needs a real http origin to be meaningful.
# --------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = (b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                b"<title>S4b Firefox</title></head><body><h1>S4b</h1></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # keep the output clean
        pass


def wait_for_port(port: int, timeout: float = 30) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.3)
    return False


class Driver:
    """A very small WebDriver client — enough for this experiment."""

    def __init__(self) -> None:
        self.session: str | None = None

    def _call(self, method: str, path: str, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{WD}{path}", data=data, method=method)
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{method} {path} -> {e.code} {e.read().decode()[:300]}")

    def start(self) -> None:
        caps = {
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "firefox",
                    "moz:firefoxOptions": {
                        "binary": str(FIREFOX),
                        "args": ["-headless", "-profile", str(PROFILE)],
                        "prefs": {
                            # Keep the test honest: no privacy mode, normal storage.
                            "browser.privatebrowsing.autostart": False,
                        },
                    },
                }
            }
        }
        resp = self._call("POST", "/session", caps)
        self.session = resp["value"]["sessionId"]

    def quit(self) -> None:
        if self.session:
            try:
                self._call("DELETE", f"/session/{self.session}")
            except Exception:
                pass
            self.session = None

    def get(self, url: str) -> None:
        self._call("POST", f"/session/{self.session}/url", {"url": url})

    def js(self, script: str):
        # execute/async, because the in-page work is promise-based: WebDriver
        # passes a completion callback as the final argument.
        resp = self._call("POST", f"/session/{self.session}/execute/async",
                          {"script": script, "args": []})
        return resp.get("value")


# --------------------------------------------------------------------------
# The in-page work. Same two keys as the Chromium run: one non-extractable (the
# real design) and one readable twin, so continuity can be proven and not merely
# assumed.
# --------------------------------------------------------------------------
IDB_HELPERS = """
function idb() {
  return new Promise(function (res, rej) {
    var r = indexedDB.open('attest-s4', 1);
    r.onupgradeneeded = function () { r.result.createObjectStore('keys'); };
    r.onsuccess = function () { res(r.result); };
    r.onerror = function () { rej(r.error); };
  });
}
function put(k, v) {
  return idb().then(function (db) {
    return new Promise(function (res, rej) {
      var tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').put(v, k);
      tx.oncomplete = function () { res(true); };
      tx.onerror = function () { rej(tx.error); };
    });
  });
}
function get(k) {
  return idb().then(function (db) {
    return new Promise(function (res, rej) {
      var tx = db.transaction('keys', 'readonly');
      var rq = tx.objectStore('keys').get(k);
      rq.onsuccess = function () { res(rq.result === undefined ? null : rq.result); };
      rq.onerror = function () { rej(rq.error); };
    });
  });
}
var ALG = { name: 'ECDSA', namedCurve: 'P-256' };
var SIGN = { name: 'ECDSA', hash: 'SHA-256' };
var MSG = new TextEncoder().encode('attest-s4-fixed-message');
"""

PHASE1 = IDB_HELPERS + """
var done = arguments[arguments.length - 1];
(async function () {
  try {
    var session = await crypto.subtle.generateKey(ALG, false, ['sign', 'verify']);
    await put('session-key', session.privateKey);
    var probe = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
    await put('probe-key', probe.privateKey);
    var jwk = await crypto.subtle.exportKey('jwk', probe.publicKey);
    await put('probe-jwk', JSON.stringify(jwk));
    var sig = await crypto.subtle.sign(SIGN, probe.privateKey, MSG);
    var ok = await crypto.subtle.verify(SIGN, probe.publicKey, sig, MSG);
    var persist = 'unsupported';
    if (navigator.storage && navigator.storage.persist) {
      persist = await navigator.storage.persist().catch(function () { return 'error'; });
    }
    done({ stored: true, usable: ok, extractable: session.privateKey.extractable,
           persist: persist, ua: navigator.userAgent });
  } catch (e) { done({ stored: false, error: e.name + ': ' + e.message }); }
})();
"""

PHASE2 = IDB_HELPERS + """
var done = arguments[arguments.length - 1];
(async function () {
  try {
    var out = { sessionFound: false, sessionUsable: false, probeFound: false,
                sameKey: null, controlRejected: null };
    var session = await get('session-key');
    if (session) {
      out.sessionFound = true;
      var s1 = await crypto.subtle.sign(SIGN, session, MSG);
      out.sessionUsable = s1.byteLength > 0;
    }
    var probe = await get('probe-key');
    var pubStored = await get('probe-jwk');
    if (probe && pubStored) {
      out.probeFound = true;
      var storedPub = await crypto.subtle.importKey('jwk', JSON.parse(pubStored), ALG, true, ['verify']);
      var sig = await crypto.subtle.sign(SIGN, probe, MSG);
      out.sameKey = await crypto.subtle.verify(SIGN, storedPub, sig, MSG);
      // Negative control: a fresh key must NOT satisfy the stored public key,
      // or a check that always returns true would look like a pass.
      var fresh = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
      var fs = await crypto.subtle.sign(SIGN, fresh.privateKey, MSG);
      out.controlRejected = !(await crypto.subtle.verify(SIGN, storedPub, fs, MSG));
    }
    done(out);
  } catch (e) { done({ error: e.name + ': ' + e.message }); }
})();
"""


def main() -> int:
    print("=" * 72)
    print("S4b — Firefox (Gecko): does it keep the session key across a restart?")
    print("=" * 72)

    if not GECKODRIVER.exists():
        print(f"geckodriver not found at {GECKODRIVER}")
        print("Fetch it with:")
        print("  curl -sL https://github.com/mozilla/geckodriver/releases/download/"
              "v0.37.1/geckodriver-v0.37.1-macos-aarch64.tar.gz \\")
        print("    | tar -xz -C tools/bin")
        return 1
    print(f"geckodriver {GECKODRIVER}")
    print(f"firefox     {FIREFOX}")
    print(f"profile     {PROFILE}")

    # Fresh profile, so "it persisted" cannot be a leftover from an earlier run.
    shutil.rmtree(PROFILE, ignore_errors=True)
    PROFILE.mkdir(parents=True, exist_ok=True)
    marker = PROFILE / "profile-marker.txt"
    marker.write_text("written before phase 1\n")

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    gd = subprocess.Popen([str(GECKODRIVER), "--port", str(WD_PORT)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_for_port(WD_PORT):
            print("geckodriver did not start")
            return 1

        d = Driver()
        print("\n[phase 1] create the keys, store them, then QUIT the browser")
        d.start()
        d.get(ORIGIN)
        p1 = d.js(PHASE1)
        print(f"  firefox reports    : {p1.get('ua')}")
        print(f"  session key extractable: {p1.get('extractable')}  (false is the design)")
        print(f"  keys usable        : {p1.get('usable')}")
        print(f"  persist() returned : {p1.get('persist')}")
        d.quit()          # closes the browser
        time.sleep(2)     # let it flush to disk

        profile_survived = marker.exists()
        print(f"\n  profile directory survived: {profile_survived}")
        if not profile_survived:
            print("  ABORT: the profile directory did not survive, so this run cannot")
            print("  distinguish 'browser evicted the key' from 'the browser is different'.")
            return 1

        print("\n[phase 2] relaunch with the SAME profile and look for the keys")
        d.start()
        d.get(ORIGIN)
        p2 = d.js(PHASE2)
        d.quit()

        rows = [
            ("session key survived", p2.get("sessionFound"), True),
            ("session key still works", p2.get("sessionUsable"), True),
            ("probe key survived", p2.get("probeFound"), True),
            ("it is the SAME key, not a new one", p2.get("sameKey"), True),
            ("control: a fresh key is rejected", p2.get("controlRejected"), True),
        ]
        print("")
        passed = 0
        for label, got, want in rows:
            ok = got == want
            passed += ok
            print(f"  {label:36s} {str(got):6s} {'PASS' if ok else 'FAIL'}")
        print("\n" + "=" * 72)
        print(f"Firefox (Gecko): {passed}/{len(rows)} checks passed")
        print("=" * 72)
        return 0 if passed == len(rows) else 1
    finally:
        gd.terminate()
        httpd.shutdown()


if __name__ == "__main__":
    sys.exit(main())
