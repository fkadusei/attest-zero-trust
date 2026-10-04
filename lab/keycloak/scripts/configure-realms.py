#!/usr/bin/env python3
"""
Spike #3 — configure the WebAuthn passwordless policy on both realms and prove
the settings PERSIST (i.e. Keycloak did not silently ignore them).

Keycloak's realm import silently ignores unknown JSON keys, so "I set it in the
config file" is not evidence. This script does read-modify-write against the
live Admin REST API and then asserts the values came back.

Stdlib only, so it runs anywhere Python 3 does.
"""

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from lab_env import KEYCLOAK_ADMIN_PASSWORD

KC = "http://localhost:8080"
ADMIN_USER = "admin"
ADMIN_PASS = KEYCLOAK_ADMIN_PASSWORD

# YubiKey 5 Series AAGUID, as published by Yubico.
# VERIFY against Yubico's current AAGUID list before relying on it.
YUBIKEY_5_SERIES = "fa2b99dc-9e39-4257-8f92-4a30d23c4118"

# A well-formed GUID that no real authenticator uses. Used to prove the
# REJECTION path without needing a hardware key: if the allowlist is enforced,
# every authenticator must fail enrolment.
BOGUS_AAGUID = "00000000-0000-0000-0000-0000000000ff"


def token():
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
    }).encode()
    req = urllib.request.Request(
        f"{KC}/realms/master/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(req) as r:
        return json.load(r)["access_token"]


def api(tok, method, path, body=None):
    url = f"{KC}/admin/realms{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {tok}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]


# Field names below were DISCOVERED from the live realm representation, not
# guessed. Note two distinct resident-key fields exist.
PRIVILEGED_POLICY = {
    "webAuthnPolicyPasswordlessRpEntityName": "Attest Admin",
    "webAuthnPolicyPasswordlessRpId": "localhost",  # prod: admin.attest.example.com
    "webAuthnPolicyPasswordlessAttestationConveyancePreference": "direct",
    "webAuthnPolicyPasswordlessAuthenticatorAttachment": "cross-platform",
    "webAuthnPolicyPasswordlessUserVerificationRequirement": "required",
    "webAuthnPolicyPasswordlessResidentKey": "required",
    "webAuthnPolicyPasswordlessRequireResidentKey": "Yes",
    "webAuthnPolicyPasswordlessAcceptableAaguids": [YUBIKEY_5_SERIES],
    # NOTE the spelling: "...Register", NOT "...Registration".
    "webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister": True,
}

USERS_POLICY = {
    "webAuthnPolicyPasswordlessRpEntityName": "Attest",
    "webAuthnPolicyPasswordlessRpId": "localhost",
    "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none",
    "webAuthnPolicyPasswordlessAuthenticatorAttachment": "not specified",
    "webAuthnPolicyPasswordlessUserVerificationRequirement": "preferred",
    "webAuthnPolicyPasswordlessResidentKey": "required",
    "webAuthnPolicyPasswordlessRequireResidentKey": "Yes",
    "webAuthnPolicyPasswordlessAcceptableAaguids": [],
    "webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister": True,
}


def apply(tok, realm, policy):
    """Read-modify-write: fetch the realm, patch fields, PUT it back."""
    status, current = api(tok, "GET", f"/{realm}")
    if status != 200:
        print(f"  !! could not read realm {realm}: {status} {current}")
        return False
    changed = {k: v for k, v in policy.items() if current.get(k) != v}
    print(f"  {realm}: {len(changed)} field(s) to change")
    for k, v in changed.items():
        print(f"      {k}: {current.get(k)!r} -> {v!r}")
    if not changed:
        print("  already configured")
        return True
    current.update(policy)
    status, err = api(tok, "PUT", f"/{realm}", current)
    if status not in (204, 200):
        print(f"  !! PUT failed: {status} {err}")
        return False
    return True


def verify(tok, realm, policy):
    """Re-read and assert every field came back exactly as set."""
    _, got = api(tok, "GET", f"/{realm}")
    ok = True
    for k, want in policy.items():
        actual = got.get(k)
        mark = "OK " if actual == want else "FAIL"
        if actual != want:
            ok = False
        print(f"    [{mark}] {k} = {actual!r}")
    return ok


def main():
    tok = token()
    print("Authenticated to Keycloak Admin API.\n")

    all_ok = True
    for realm, policy in (("attest-privileged", PRIVILEGED_POLICY),
                          ("attest-users", USERS_POLICY)):
        print(f"=== {realm} ===")
        if not apply(tok, realm, policy):
            all_ok = False
            continue
        print("  verifying persistence:")
        if not verify(tok, realm, policy):
            all_ok = False
        print()

    # Does Keycloak reject a malformed AAGUID, or accept anything?
    print("=== AAGUID format validation probe ===")
    _, realm_repr = api(tok, "GET", "/attest-privileged")
    realm_repr["webAuthnPolicyPasswordlessAcceptableAaguids"] = ["not-a-guid"]
    status, err = api(tok, "PUT", "/attest-privileged", realm_repr)
    if status in (204, 200):
        _, back = api(tok, "GET", "/attest-privileged")
        stored = back.get("webAuthnPolicyPasswordlessAcceptableAaguids")
        print(f"  malformed AAGUID ACCEPTED (no validation). Stored as: {stored!r}")
        print("  -> allowlist entries are not format-checked; typos fail OPEN or silently")
        # restore
        realm_repr["webAuthnPolicyPasswordlessAcceptableAaguids"] = [YUBIKEY_5_SERIES]
        api(tok, "PUT", "/attest-privileged", realm_repr)
        print("  (restored valid allowlist)")
    else:
        print(f"  malformed AAGUID REJECTED: {status} {err}")

    print()
    print("RESULT:", "PASS — settings persist" if all_ok else "FAIL — see above")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
