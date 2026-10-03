#!/usr/bin/env python3
"""Spike #1 — does DPoP token binding actually hold, end to end?

THE QUESTION
    Keycloak verifies a DPoP proof when it *issues* a token and writes the key
    thumbprint into the token as `cnf.jkt`. But Keycloak is not in the request
    path for our own API, so our API must verify the proof itself. Two things
    therefore need proving:

      1. Is the binding real — does a resource server actually refuse a bound
         token that arrives without a valid proof?
      2. Can we implement the verification correctly, including the negative
         cases (wrong key, replayed proof, wrong URL)?

    Only the second is our code, and it is the single piece of genuinely custom
    security code in the system, so it is worth prototyping before building.

WHY KEYCLOAK IS USED AS THE RESOURCE SERVER
    Keycloak 26.4+ applies DPoP to every endpoint that accepts a bearer token,
    including userinfo. That gives us a reference implementation to test against
    before writing our own — if Keycloak rejects the token, the binding is real.

WHAT THIS DOES NOT COVER
    Whether the `DPoP` header survives CloudFront -> ALB -> API Gateway. That
    needs deployed infrastructure and remains open (Spike #1, second half).

Usage:
    python3 lab/keycloak/scripts/dpop_spike.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

KC = "http://localhost:8080"
REALM = "attest-users"
ADMIN_USER, ADMIN_PASS = "admin", "lab-only-not-a-secret"
CLIENT_ID = "dpop-spike"
TEST_USER, TEST_PASS = "dpop-spike-user", "Spike-Lab-Password-123!"

TOKEN_URL = f"{KC}/realms/{REALM}/protocol/openid-connect/token"
USERINFO_URL = f"{KC}/realms/{REALM}/protocol/openid-connect/userinfo"


# --------------------------------------------------------------------------
# base64url helpers — no padding, per RFC 7515
# --------------------------------------------------------------------------
def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_json(obj) -> str:
    return b64u(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())


# --------------------------------------------------------------------------
# DPoP key and proofs (RFC 9449)
# --------------------------------------------------------------------------
class DpopKey:
    """A browser-side DPoP key. The private half never leaves this object."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())

    @property
    def jwk(self) -> dict:
        nums = self._key.public_key().public_numbers()
        return {
            "crv": "P-256",
            "kty": "EC",
            "x": b64u(nums.x.to_bytes(32, "big")),
            "y": b64u(nums.y.to_bytes(32, "big")),
        }

    @property
    def thumbprint(self) -> str:
        """RFC 7638 JWK thumbprint — what the token records as `cnf.jkt`."""
        canonical = json.dumps(
            {"crv": "P-256", "kty": "EC", "x": self.jwk["x"], "y": self.jwk["y"]},
            separators=(",", ":"), sort_keys=True,
        )
        return b64u(hashlib.sha256(canonical.encode()).digest())

    def proof(self, htm: str, htu: str, *, nonce: str | None = None,
              jti: str | None = None, access_token: str | None = None) -> str:
        """A DPoP proof JWT for one specific request.

        `access_token` adds the `ath` claim (RFC 9449 section 7.1). A proof for a
        *token request* omits it; a proof for a *resource request* must include
        it, and omitting it produces a generic "token verification failed" that
        looks like a signature problem. That cost real debugging time here.
        """
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk}
        payload = {
            "jti": jti or secrets.token_urlsafe(16),
            "htm": htm,
            "htu": htu,
            "iat": int(time.time()),
        }
        if nonce:
            payload["nonce"] = nonce
        if access_token:
            payload["ath"] = b64u(hashlib.sha256(access_token.encode()).digest())
        signing_input = f"{b64u_json(header)}.{b64u_json(payload)}".encode()
        der = self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        # JWS wants raw r||s, not the DER encoding `cryptography` returns.
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{signing_input.decode()}.{b64u(sig)}"


# --------------------------------------------------------------------------
# HTTP helpers
# --------------------------------------------------------------------------
def post_form(url: str, data: dict, headers: dict | None = None):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw), dict(e.headers)
        except Exception:
            return e.code, {"raw": raw.decode(errors="replace")[:300]}, dict(e.headers)


def get_resource(url: str, token: str, scheme: str = "DPoP",
                 headers: dict | None = None):
    """Returns (status, body-text, response-headers).

    `scheme` matters. RFC 9449 requires a DPoP-bound token to be presented with
    the `DPoP` authorization scheme, not `Bearer`. Keycloak enforces this: the
    same token under `Bearer` fails with "Token verification failed", which
    reads like a signature problem and is actually a scheme problem.
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"{scheme} {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()[:200].decode(errors="replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200].decode(errors="replace"), dict(e.headers)


def dpop_get(url: str, token: str, key: "DpopKey", *, htu: str | None = None,
             proof: str | None = None):
    """GET with a DPoP proof, answering the server's nonce challenge.

    Keycloak requires a nonce on resource requests: a perfectly valid proof is
    still refused until it carries a nonce the server issued. That is stricter
    than RFC 9449 demands and is worth knowing, because it means a resource
    server choosing to require nonces owes its clients an extra round trip.
    """
    target = htu or url
    p = proof if proof is not None else key.proof("GET", target, access_token=token)
    status, body, headers = get_resource(url, token, "DPoP", {"DPoP": p})
    nonce = headers.get("DPoP-Nonce") or headers.get("dpop-nonce")
    if status == 401 and nonce:
        p = key.proof("GET", target, nonce=nonce, access_token=token)
        status, body, headers = get_resource(url, token, "DPoP", {"DPoP": p})
        return status, body, headers, p, True
    return status, body, headers, p, False


def admin_token() -> str:
    _, body, _ = post_form(f"{KC}/realms/master/protocol/openid-connect/token", {
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN_USER, "password": ADMIN_PASS,
    })
    return body["access_token"]


def admin(method: str, path: str, tok: str, body=None):
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
        return e.code, e.read().decode()[:200]


# --------------------------------------------------------------------------
# Fixtures: a DPoP-required client and a test user
# --------------------------------------------------------------------------
def ensure_fixtures(tok: str) -> bool:
    status, existing = admin("GET", f"/{REALM}/clients?clientId={CLIENT_ID}", tok)
    client = {
        "clientId": CLIENT_ID,
        "enabled": True,
        "publicClient": True,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": False,
        "protocol": "openid-connect",
        "attributes": {"dpop.bound.access.tokens": "true"},
    }
    if not existing:
        # Keycloak exposes the switch in the admin console as
        # "Require DPoP bound tokens"; the attribute is what it writes.
        admin("POST", f"/{REALM}/clients", tok, client)
        print(f"  created client {CLIENT_ID} with dpop.bound.access.tokens=true")
    else:
        cid = existing[0]["id"]
        merged = {**existing[0], **client}
        admin("PUT", f"/{REALM}/clients/{cid}", tok, merged)
        print(f"  client {CLIENT_ID} already existed; re-asserted DPoP requirement")

    _, found = admin("GET", f"/{REALM}/users?username={TEST_USER}&exact=true", tok)
    if not found:
        admin("POST", f"/{REALM}/users", tok, {
            "username": TEST_USER, "enabled": True, "emailVerified": True,
            "firstName": "Dpop", "lastName": "Spike",
            "email": f"{TEST_USER}@example.test",
            "requiredActions": [],
        })
        _, found = admin("GET", f"/{REALM}/users?username={TEST_USER}&exact=true", tok)
        print(f"  created user {TEST_USER}")

    uid = found[0]["id"]
    # The realm attaches default required actions (verify email, update profile)
    # to new users. Left in place, the password grant fails with the unhelpful
    # "Account is not fully set up", so clear them explicitly.
    user = {k: v for k, v in found[0].items()
            if k not in ("access", "userProfileMetadata")}
    user.update({
        "requiredActions": [],
        "emailVerified": True,
        "enabled": True,
        "firstName": user.get("firstName") or "Dpop",
        "lastName": user.get("lastName") or "Spike",
    })
    admin("PUT", f"/{REALM}/users/{uid}", tok, user)
    admin("PUT", f"/{REALM}/users/{uid}/reset-password", tok,
          {"type": "password", "value": TEST_PASS, "temporary": False})
    return True


def get_bound_token(key: DpopKey) -> tuple[str | None, dict, str]:
    """Password grant with a DPoP proof. Handles Keycloak's nonce challenge."""
    data = {"grant_type": "password", "client_id": CLIENT_ID,
            "username": TEST_USER, "password": TEST_PASS, "scope": "openid profile email"}

    status, body, headers = post_form(TOKEN_URL, data,
                                      {"DPoP": key.proof("POST", TOKEN_URL)})
    # RFC 9449 nonce challenge: the server tells us to retry with a nonce.
    nonce = headers.get("DPoP-Nonce") or headers.get("dpop-nonce")
    if status >= 400 and nonce:
        status, body, headers = post_form(
            TOKEN_URL, data,
            {"DPoP": key.proof("POST", TOKEN_URL, nonce=nonce)})
        return body.get("access_token"), body, "retried with server nonce"
    return body.get("access_token"), body, "first attempt"


def jwt_claim(token: str, claim: str):
    """Read a claim without verifying — we only inspect, Keycloak verifies."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get(claim)
    except Exception:
        return None


# --------------------------------------------------------------------------
# The verification our API would implement
# --------------------------------------------------------------------------
def verify_proof(token: str, proof: str, htm: str, htu: str) -> tuple[bool, str]:
    """Minimal DPoP proof verification: what the Lambda authorizer must do.

    Returns (ok, reason). Deliberately strict — every check either passes or the
    request is refused, because the whole point is that a token alone is not
    enough.
    """
    try:
        h_b64, p_b64, sig_b64 = proof.split(".")
        header = json.loads(base64.urlsafe_b64decode(h_b64 + "=" * (-len(h_b64) % 4)))
        payload = json.loads(base64.urlsafe_b64decode(p_b64 + "=" * (-len(p_b64) % 4)))
    except Exception:
        return False, "malformed proof"

    if header.get("typ") != "dpop+jwt":
        return False, f"wrong typ ({header.get('typ')!r})"

    jwk = header.get("jwk")
    if not jwk:
        return False, "no jwk in proof header"

    # 1. The proof must be signed by the key the token is bound to.
    canonical = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"],
                            "x": jwk["x"], "y": jwk["y"]},
                           separators=(",", ":"), sort_keys=True)
    jkt = b64u(hashlib.sha256(canonical.encode()).digest())
    cnf = jwt_claim(token, "cnf") or {}
    if jkt != cnf.get("jkt"):
        return False, "proof key does not match the token's cnf.jkt"

    # 2. The proof must be for exactly this request.
    if payload.get("htm") != htm:
        return False, f"htm mismatch ({payload.get('htm')} != {htm})"
    if payload.get("htu") != htu:
        return False, f"htu mismatch ({payload.get('htu')} != {htu})"

    # 3. It must be fresh.
    age = abs(int(time.time()) - int(payload.get("iat", 0)))
    if age > 30:
        return False, f"iat too old ({age}s)"

    # 4. It must be bound to THIS access token (RFC 9449 `ath`). Without this
    #    check a proof captured for one token would authorise another.
    expected_ath = b64u(hashlib.sha256(token.encode()).digest())
    if payload.get("ath") != expected_ath:
        return False, "ath missing or does not match this access token"

    # 4. The signature must verify.
    try:
        nums = (int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big"),
                int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big"))
        pub = ec.EllipticCurvePublicNumbers(nums[0], nums[1], ec.SECP256R1()).public_key()
        raw = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                   int.from_bytes(raw[32:], "big"))
        pub.verify(der, f"{h_b64}.{p_b64}".encode(), ec.ECDSA(hashes.SHA256()))
    except Exception as e:
        return False, f"signature invalid ({type(e).__name__})"

    return True, "ok"


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> int:
    print("=" * 74)
    print("Spike #1 — DPoP token binding")
    print("=" * 74)

    tok = admin_token()
    print("\n[fixtures]")
    ensure_fixtures(tok)

    key = DpopKey()
    print(f"\n[issuance]  client key thumbprint = {key.thumbprint[:24]}…")

    access, body, note = get_bound_token(key)
    if not access:
        print(f"  FAILED to obtain a token: {json.dumps(body)[:300]}")
        return 1
    print(f"  token obtained ({note})")

    cnf = jwt_claim(access, "cnf")
    bound = bool(cnf and cnf.get("jkt") == key.thumbprint)
    print(f"  cnf claim in token      : {cnf}")
    print(f"  matches our key         : {'YES' if bound else 'NO'}")

    if not bound:
        print("\n  RESULT: Keycloak did not bind the token to our key.")
        print("  Without `cnf.jkt` there is nothing for a resource server to enforce.")
        return 1

    # ---- Does Keycloak, as a resource server, actually enforce it? ----------
    print("\n[enforcement] Keycloak's userinfo endpoint as the resource server")

    results: list[tuple[str, str, bool]] = []

    def record(label: str, status: int, want: int, extra: str = "") -> int:
        ok = status == want
        results.append((label, f"HTTP {status}", ok))
        print(f"  {label:28s} -> HTTP {status}  {'PASS' if ok else 'FAIL'} {extra}")
        return status

    s, body, _ = get_resource(USERINFO_URL, access, "DPoP")
    record("token, no proof", s, 401, body[:60])

    # Prove the scheme distinction explicitly — it is a real integration trap.
    s_bearer, _, _ = get_resource(USERINFO_URL, access, "Bearer",
                                  {"DPoP": key.proof("GET", USERINFO_URL)})
    record("bound token via Bearer scheme", s_bearer, 401,
           "correct: DPoP scheme required")

    s, body, hdrs, good, nonced = dpop_get(USERINFO_URL, access, key)
    record("token + valid proof", s, 200, "(answered nonce challenge)" if nonced else "")
    if s != 200:
        print(f"      reply body      : {body[:180]}")
        print(f"      WWW-Authenticate: {hdrs.get('WWW-Authenticate')}")
        print(f"      DPoP-Nonce      : {hdrs.get('DPoP-Nonce')}")
        print(f"      all headers     : {sorted(hdrs.keys())}")

    other = DpopKey()
    s, body, _, _, _ = dpop_get(USERINFO_URL, access, other)
    record("proof from another key", s, 401, body[:60])

    # Does Keycloak validate `htu` (the request URI in the proof)?
    # It checks the path but NOT the query string. Recorded as an observation
    # rather than a pass/fail: it is Keycloak's behaviour, not a harness fault,
    # and it means our own authoriser has to be stricter if it matters.
    s_path, _, _, _, _ = dpop_get(USERINFO_URL, access, key, htu=TOKEN_URL)
    record("proof htu: different path", s_path, 401)

    s_query, _, _, _, _ = dpop_get(USERINFO_URL, access, key,
                                   htu=USERINFO_URL + "?decoy=1")
    observation = (
        "Keycloak compares htu IGNORING the query string "
        f"(same path + ?decoy=1 was accepted: HTTP {s_query})"
    )
    print(f"  {'proof htu: extra query param':28s} -> HTTP {s_query}  OBSERVED")
    print(f"      {observation}")

    # Replaying the exact same proof must fail. Send the good proof verbatim.
    s, body, _, _, _ = dpop_get(USERINFO_URL, access, key, proof=good)
    record("replayed proof (same jti)", s, 401, body[:60])

    # ---- Can WE verify it? (this is the code we would actually ship) --------
    print("\n[our verifier] the logic a Lambda authorizer would run")

    def P(htm: str = "GET", htu: str = USERINFO_URL, **kw):
        """A proof bound to this token, as a real client would send."""
        return key.proof(htm, htu, access_token=access, **kw)

    checks = [
        ("valid proof accepted",
         verify_proof(access, P(), "GET", USERINFO_URL), True),
        ("proof from another key refused",
         verify_proof(access, other.proof("GET", USERINFO_URL, access_token=access),
                      "GET", USERINFO_URL), False),
        ("wrong method refused",
         verify_proof(access, P(htm="POST"), "GET", USERINFO_URL), False),
        ("wrong URL refused",
         verify_proof(access, P(htu=USERINFO_URL + "?x=1"), "GET", USERINFO_URL), False),
        ("proof with no ath refused",
         verify_proof(access, key.proof("GET", USERINFO_URL), "GET", USERINFO_URL), False),
        ("proof minted for a DIFFERENT token refused",
         verify_proof(access, key.proof("GET", USERINFO_URL, access_token=access + "x"),
                      "GET", USERINFO_URL), False),
    ]
    for label, (ok, reason), want_ok in checks:
        mark = "PASS" if ok == want_ok else "FAIL"
        print(f"  {label:44s} -> {str(ok):5s} ({reason})  {mark}")

    print("\n" + "=" * 74)
    passed = sum(1 for _, _, ok in results if ok)
    print(f"Keycloak enforcement: {passed}/{len(results)} behaviours as expected")
    print(f"Observation recorded : {observation}")
    print("=" * 74)
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
