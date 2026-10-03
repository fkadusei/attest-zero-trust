#!/usr/bin/env python3
"""A minimal SMTP sink, so Keycloak's emails can be captured and inspected.

WHY THIS EXISTS
    Keycloak's "execute actions email" is the only mechanism that produces a
    genuinely SHAREABLE, per-user, time-limited link — the thing impersonation
    turned out not to be (its session cookie comes back to the API caller, not to
    the person who needs it).

    Testing that link means reading the email. The lab has no mail server, so this
    is one: it accepts a message, writes it to disk, and holds it for inspection.

    Deliberately dependency-free — a few dozen lines of the SMTP dialogue is less
    risk than another package in a security lab, and it does exactly one thing.

EXPOSURE — read this before changing the default
    By default the sink listens on 127.0.0.1 only, so nothing off the machine can
    reach it.

    That is not enough when the sender is a CONTAINER. A container reaching the
    host over the Docker bridge arrives on the bridge interface, not on loopback,
    so a loopback-only listener REFUSES it. (It appears to work under Docker
    Desktop because that proxies host.docker.internal to the host's loopback —
    which hides the problem until the same job runs on a Linux runner.)

    Use --host 0.0.0.0 when a container must reach it, and understand that this
    then accepts mail from anything that can route to the machine.

Usage:
    python3 smtp_sink.py [port] [outdir]          # default 2525 / /tmp/attest-mail
    python3 smtp_sink.py --host 0.0.0.0 [port]    # reachable from a container
    python3 smtp_sink.py --once [port] ...        # capture one message and exit
"""
from __future__ import annotations

import itertools
import pathlib
import socket
import sys
import threading
import time

PORT = 2525
OUTDIR = pathlib.Path("/tmp/attest-mail")

# A GLOBAL, monotonic message counter.
#
# The first version named files f"{stamp}-{len(outbox)}" where outbox was
# per-CONNECTION. Two messages delivered in the same second — which is normal,
# and happens on every retry — both got `-1` and the second OVERWROTE the first.
# The test then waited forever for a new file that had already been replaced.
_COUNT = itertools.count(1)
_LOCK = threading.Lock()


def handle(conn: socket.socket, addr, outdir: pathlib.Path, once: bool, done: threading.Event) -> None:
    f = conn.makefile("rwb")
    outbox: list[bytes] = []

    def say(line: str) -> None:
        f.write((line + "\r\n").encode())
        f.flush()

    say("220 attest-smtp-sink ready")
    while True:
        raw = f.readline()
        if not raw:
            break
        cmd = raw.decode("utf-8", "replace").strip()
        upper = cmd.upper()

        if upper.startswith("EHLO") or upper.startswith("HELO"):
            say("250-attest-smtp-sink")
            say("250 SIZE 10485760")
        elif upper.startswith("MAIL FROM"):
            say("250 OK")
        elif upper.startswith("RCPT TO"):
            say("250 OK")
        elif upper.startswith("DATA"):
            say("354 End data with <CR><LF>.<CR><LF>")
            body = bytearray()
            while True:
                line = f.readline()
                if not line or line.strip() == b".":
                    break
                body += line
            outbox.append(bytes(body))
            # Write immediately so a test can read it without waiting for QUIT.
            outdir.mkdir(parents=True, exist_ok=True)
            with _LOCK:
                path = outdir / f"{time.time_ns()}-{next(_COUNT)}.eml"
                path.write_bytes(bytes(body))
            print(f"  [smtp] captured {len(body)} bytes -> {path}", flush=True)
            say("250 OK queued")
            if once:
                done.set()
        elif upper.startswith("QUIT"):
            say("221 Bye")
            break
        elif upper.startswith("RSET") or upper.startswith("NOOP"):
            say("250 OK")
        else:
            say("250 OK")
    try:
        f.close()
        conn.close()
    except Exception:
        pass


def main() -> int:
    argv = sys.argv[1:]
    once = "--once" in argv
    host = "127.0.0.1"
    if "--host" in argv:
        i = argv.index("--host")
        host = argv[i + 1]
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    port = int(args[0]) if args else PORT
    outdir = pathlib.Path(args[1]) if len(args) > 1 else OUTDIR
    outdir.mkdir(parents=True, exist_ok=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    print(f"  [smtp] listening on {host}:{port}, writing to {outdir}", flush=True)

    done = threading.Event()
    srv.settimeout(1.0)
    try:
        while not done.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn, addr, outdir, once, done), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            srv.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
