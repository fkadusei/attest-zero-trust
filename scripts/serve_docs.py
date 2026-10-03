#!/usr/bin/env python3
"""Serve the generated documentation site locally.

Python's `http.server` exits with a raw traceback when the port is taken, which
is a poor thing to hand someone who only wanted to read the docs. This instead:

  * rebuilds the site first, so what you read is current
  * picks the next free port and says so, rather than dying
  * records its own process so `scripts/docs.sh stop` can end it
  * prints the URL that actually works

The pages also open directly from disk; this is only a convenience.

Usage:
    python3 scripts/serve_docs.py [--port 8082]
"""
from __future__ import annotations

import argparse
import functools
import http.server
import os
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "docs" / "site"
PIDFILE = ROOT / ".docs-server.pid"


def port_is_free(port: int) -> bool:
    """Whether we could actually bind here.

    Sets SO_REUSEADDR because http.server's own handler does (HTTPServer sets
    allow_reuse_address). Without it, a port left in TIME_WAIT by a stopped
    server reads as busy, and `serve` would silently drift to a different port
    every time it was restarted.
    """
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def read_pidfile() -> tuple[int, int] | None:
    """The (pid, port) of a live recorded server, or None."""
    if not PIDFILE.exists():
        return None
    try:
        pid_s, port_s = PIDFILE.read_text().split()
        pid, port = int(pid_s), int(port_s)
    except (ValueError, OSError):
        PIDFILE.unlink(missing_ok=True)
        return None
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        PIDFILE.unlink(missing_ok=True)
        return None
    return pid, port


def main() -> int:
    # Print the URL promptly even when piped or behind nohup — it is the one
    # piece of output anyone actually wants.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8082)
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="start even if a docs server is already running")
    args = ap.parse_args()

    # Serving the same directory twice helps nobody, and it is exactly how a
    # stale copy ends up in front of someone. Say where the live one is.
    live = read_pidfile()
    if live and not args.force:
        pid, port = live
        print(f"a docs server is already running at http://localhost:{port}/ (pid {pid})")
        print("  scripts/docs.sh stop     to stop it")
        print("  scripts/docs.sh serve --force   to start another anyway")
        return 0

    if not args.no_build:
        rc = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_docs.py")],
                            capture_output=True, text=True)
        if rc.returncode != 0:
            print(rc.stdout + rc.stderr, file=sys.stderr)
            return rc.returncode

    if not (SITE / "index.html").exists():
        print(f"nothing to serve: {SITE}/index.html is missing.", file=sys.stderr)
        print("Run:  python3 scripts/build_docs.py", file=sys.stderr)
        return 1

    start = args.port
    port = 0
    for candidate in range(start, start + 20):
        if port_is_free(candidate):
            port = candidate
            break
    if not port:
        print(f"no free port in {start}-{start + 19}", file=sys.stderr)
        return 1
    if port != start:
        print(f"port {start} is in use by something else; using {port} instead")

    handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                               directory=str(SITE))
    try:
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError as e:
        print(f"could not bind port {port}: {e}", file=sys.stderr)
        return 1

    PIDFILE.write_text(f"{os.getpid()} {port}")
    url = f"http://localhost:{port}/"
    print(f"serving docs/site at {url}")
    print("  (the pages also work by opening docs/site/index.html directly)")
    print("  Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
        PIDFILE.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
