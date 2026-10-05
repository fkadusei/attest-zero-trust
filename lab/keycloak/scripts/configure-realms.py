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
import os
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


def ensure_console_client(tok, realm, public_base):
    """Create or update the console's OIDC client.

    THIS BELONGS IN A SCRIPT. It was originally created ad-hoc with a one-off snippet,
    so when the Keycloak volumes were destroyed during the credential work the client
    vanished with them — and the failure surfaced much later as "attest-console client
    missing" while wiring up a tunnel. Setup that exists only in a shell history is
    setup that will be lost.

    `public_base` is where the console is reachable. Local runs use http://localhost:3000;
    a tunnel run uses the real hostname. BOTH redirect URIs are registered rather than
    replaced, so switching between them does not require re-running anything.

    The post-logout URI is not optional. Without it Keycloak's end-session endpoint
    returns HTTP 400, the console's own session is destroyed, and the SSO session at the
    provider SURVIVES — so the next visit signs the user straight back in. It looks like
    sign-out worked. The browser end-to-end test is what found that.
    """
    redirects = [f"{public_base}/console/callback"]
    post_logout = f"{public_base}/console/login"

    clients = api(tok, "GET", f"/{realm}/clients?clientId=attest-console")[1]
    if clients:
        client = clients[0]
        merged = sorted(set(client.get("redirectUris", []) + redirects))
        # MERGE the post-logout URIs, do not replace them.
        #
        # THE SEPARATOR IS `##`, AND THAT WAS MEASURED RATHER THAN GUESSED. Keycloak
        # stores this attribute as a single string, so more than one URI needs a
        # separator — and the obvious candidates are all wrong:
        #
        #     space-separated   -> HTTP 400 "A post-logout redirect URI is not a valid URI"
        #     newline-separated -> HTTP 400, same
        #     `##`-separated    -> ACCEPTED
        #
        # Every rejection reads as a malformed URI rather than as a bad separator, which
        # is why the wrong guess is easy to make and hard to read back.
        #
        # The consequence of getting it wrong is not cosmetic: with no post-logout URI
        # registered, Keycloak's end-session endpoint returns 400, the console's own
        # session is destroyed, and the SSO session SURVIVES — so the next visit signs
        # the user straight back in and it looks like sign-out worked.
        existing_post = (client.get("attributes", {})
                         .get("post.logout.redirect.uris", "").split("##"))
        existing_post = [u for u in (u.strip() for u in existing_post) if u]
        attributes = {**client.get("attributes", {}),
                      "post.logout.redirect.uris":
                          "##".join(sorted(set(existing_post + [post_logout])))}
        status, err = api(tok, "PUT", f"/{realm}/clients/{client['id']}",
                          {**client, "redirectUris": merged, "attributes": attributes})
        if status not in (204, 200):
            print(f"  console client update FAILED: {status} {err}")
            return False
        print(f"  console client updated")
        print(f"    redirectUris : {merged}")
        print(f"    post-logout  : {attributes['post.logout.redirect.uris']}")
        return True

    spec = {
        "clientId": "attest-console",
        "enabled": True,
        # Confidential: a server-rendered console holds a secret. It CANNOT use DPoP —
        # its tokens are not sender-constrained. The user's SIGN-IN is still a passkey;
        # what the console holds afterwards is an ordinary confidential-client session.
        "publicClient": False,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": redirects,
        "webOrigins": [public_base],
        "attributes": {"post.logout.redirect.uris": post_logout},
        "protocolMappers": [
            {"name": "audience-attest-api", "protocol": "openid-connect",
             "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
             "config": {"included.client.audience": "attest-api",
                        "id.token.claim": "false", "access.token.claim": "true"}},
            {"name": "tenant_id", "protocol": "openid-connect",
             "protocolMapper": "oidc-hardcoded-claim-mapper", "consentRequired": False,
             "config": {"claim.name": "tenant_id", "claim.value": "acme",
                        "jsonType.label": "String",
                        "id.token.claim": "false", "access.token.claim": "true"}},
            {"name": "realm-roles", "protocol": "openid-connect",
             "protocolMapper": "oidc-hardcoded-claim-mapper", "consentRequired": False,
             "config": {"claim.name": "realm_access.roles",
                        "claim.value": '["writer"]', "jsonType.label": "JSON",
                        "id.token.claim": "false", "access.token.claim": "true"}},
        ],
    }
    status, err = api(tok, "POST", f"/{realm}/clients", spec)
    if status not in (201, 204):
        print(f"  console client creation FAILED: {status} {err}")
        return False
    print(f"  console client created (redirectUris={redirects})")
    return True


def main():
    tok = token()
    print("Authenticated to Keycloak Admin API.\n")

    # Where the console is reachable. Local by default; set CONSOLE_PUBLIC_URL when the
    # lab is exposed through a tunnel, so the redirect URIs match what the browser uses.
    public_base = os.environ.get("CONSOLE_PUBLIC_URL", "http://localhost:3000").rstrip("/")
    print(f"Console public URL: {public_base}\n")

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
        if not ensure_console_client(tok, realm, public_base):
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
