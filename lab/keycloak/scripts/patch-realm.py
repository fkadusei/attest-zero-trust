#!/usr/bin/env python3
"""Patch a single field (or several) on a live realm via read-modify-write.

Usage: patch-realm.py <realm> '<json-object-of-updates>'
Prints the before/after for each field so the change is visible.
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

KC = "http://localhost:8080"


def token():
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "admin-cli",
        "username": "admin", "password": "lab-only-not-a-secret",
    }).encode()
    req = urllib.request.Request(
        f"{KC}/realms/master/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]


def main():
    realm, updates = sys.argv[1], json.loads(sys.argv[2])
    tok = token()

    req = urllib.request.Request(f"{KC}/admin/realms/{realm}")
    req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req) as r:
        cur = json.load(r)

    for k, v in updates.items():
        print(f"  {k}: {cur.get(k)!r} -> {v!r}")
        cur[k] = v

    body = json.dumps(cur).encode()
    req = urllib.request.Request(f"{KC}/admin/realms/{realm}", data=body, method="PUT")
    req.add_header("Authorization", f"Bearer {tok}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            print(f"  PUT -> {r.status}")
    except urllib.error.HTTPError as e:
        print(f"  PUT FAILED {e.code}: {e.read().decode()[:300]}")
        return 1

    # read back
    req = urllib.request.Request(f"{KC}/admin/realms/{realm}")
    req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req) as r:
        after = json.load(r)
    for k in updates:
        ok = "OK " if after.get(k) == updates[k] else "FAIL"
        print(f"    [{ok}] {k} = {after.get(k)!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
