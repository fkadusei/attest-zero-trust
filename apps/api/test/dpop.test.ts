/**
 * DPoP proof verification, tested against real Keycloak-bound tokens.
 *
 * The positive control matters more here than anywhere else in this project. A
 * DPoP proof is a self-contained JWS that carries its own public key, so a verifier
 * can be made to "pass" by a proof it generated itself. Proving that we accept a
 * proof Keycloak actually bound a token to is the only thing that shows we agree
 * with the standard rather than with ourselves.
 *
 * Every negative case asserts the REASON. "It threw" is satisfied by a verifier
 * that throws at everything — including the valid proof in the control.
 */
import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

import { verifyDpopProof, normalizeHtu } from "../src/dpop.ts";
import { TokenVerificationError, type FailureReason } from "../src/errors.ts";
import { InMemoryReplayCache } from "../src/ports/replay-cache.ts";
import { systemClock } from "../src/ports/clock.ts";
import { createDpopKey, setupBoundToken, type DpopKey } from "./dpop-harness.ts";
import { isLabUp } from "./lab.ts";

const labUp = await isLabUp();

/** The URI the API believes the request was made to. Trusted config, not headers. */
const API_URI = "https://api.attestmfa.example.com/v1/evidence";
const METHOD = "GET";

describe("DPoP proof verification, against the live lab", { skip: labUp ? false : "Keycloak is not running" }, () => {
  let key: DpopKey;
  let token: string;
  let thumbprint: string;

  before(async () => {
    const setup = await setupBoundToken();
    key = setup.key;
    token = setup.token;
    thumbprint = setup.thumbprint;
  });

  /** Fresh cache per call, so only the case under test can fail. */
  const verify = (proof: string, overrides: Partial<Parameters<typeof verifyDpopProof>[0]> = {}) =>
    verifyDpopProof({
      proof,
      method: METHOD,
      uri: API_URI,
      accessToken: token,
      expectedThumbprint: thumbprint,
      clock: systemClock,
      replayCache: new InMemoryReplayCache(),
      ...overrides,
    });

  async function expectReason(
    proof: string,
    expected: FailureReason,
    overrides: Partial<Parameters<typeof verifyDpopProof>[0]> = {},
  ): Promise<void> {
    try {
      const result = await verify(proof, overrides);
      assert.fail(`expected rejection (${expected}) but the proof VERIFIED with jti=${result.jti}`);
    } catch (error) {
      assert.ok(error instanceof TokenVerificationError, `expected TokenVerificationError, got ${String(error)}`);
      assert.equal(error.reason, expected, `wrong reason: got '${error.reason}', expected '${expected}'`);
    }
  }

  // ---------------------------------------------------------------- positive
  it("CONTROL: the provider really issued a DPoP-BOUND token", () => {
    // Establishes the premise. Without `cnf.jkt` every test below would be
    // comparing a proof against a token that was never bound to anything.
    assert.equal(typeof thumbprint, "string");
    assert.ok(thumbprint.length > 20, "cnf.jkt should be a base64url SHA-256 thumbprint");
    assert.equal(token.split(".").length, 3);
  });

  it("CONTROL: a valid proof for a real bound token verifies", async () => {
    const proof = await key.proof({ method: METHOD, uri: API_URI, accessToken: token });
    const result = await verify(proof);
    assert.equal(result.thumbprint, thumbprint);
    assert.equal(typeof result.jti, "string");
  });

  it("the verified thumbprint equals the token's cnf.jkt", async () => {
    const proof = await key.proof({ method: METHOD, uri: API_URI, accessToken: token });
    const result = await verify(proof);
    // Guards against a verifier that returns a plausible constant rather than a
    // value derived from the proof in front of it.
    assert.equal(result.thumbprint, thumbprint);
  });

  // ---------------------------------------------------------------- htm / htu
  it("a proof for a DIFFERENT method is refused", async () => {
    const proof = await key.proof({ method: "POST", uri: API_URI, accessToken: token });
    await expectReason(proof, "malformed");
  });

  it("a proof for a DIFFERENT URI is refused", async () => {
    const proof = await key.proof({
      method: METHOD,
      uri: "https://api.attestmfa.example.com/v1/other",
      accessToken: token,
    });
    await expectReason(proof, "malformed");
  });

  it("a proof whose htu carries a QUERY is refused as malformed", async () => {
    // RFC 9449: htu must not include a query. Refusing rather than stripping keeps
    // a non-conforming client from silently getting a weaker check.
    const proof = await key.proof({
      method: METHOD,
      uri: `${API_URI}?tenant=evil`,
      accessToken: token,
    });
    await expectReason(proof, "malformed");
  });

  it("a request URI with a query still matches a clean htu (RFC 9449)", async () => {
    // The request itself may carry a query; htu must not. This is the behaviour
    // S1 observed in Keycloak, and it is what the RFC specifies. Proving it here
    // means we match the provider rather than a private interpretation.
    const proof = await key.proof({ method: METHOD, uri: API_URI, accessToken: token });
    const result = await verify(proof, { uri: `${API_URI}?page=2&limit=10` });
    assert.equal(result.thumbprint, thumbprint);
  });

  it("htu comparison normalises host case and the DEFAULT port", async () => {
    assert.equal(normalizeHtu("HTTPS://API.Example.com/v1/x"), "https://api.example.com/v1/x");

    // The URL parser drops the default port for the scheme, so an explicit :443 and
    // an implicit one normalise identically — correct, because they ARE the same
    // origin, and a difference there would be an easy way to make a stolen proof
    // look like a mismatch.
    assert.equal(
      normalizeHtu("https://api.example.com:443/v1/x?q=1"),
      "https://api.example.com/v1/x",
    );
    assert.equal(
      normalizeHtu("https://api.example.com:443/v1/x"),
      normalizeHtu("https://api.example.com/v1/x"),
    );

    // A NON-default port is preserved. Dropping it would let a proof for one
    // service satisfy a request to another on the same host.
    assert.equal(normalizeHtu("https://api.example.com:8443/v1/x"), "https://api.example.com:8443/v1/x");
    assert.notEqual(
      normalizeHtu("https://api.example.com:8443/v1/x"),
      normalizeHtu("https://api.example.com/v1/x"),
    );

    // An absent path is canonicalised to "/", so the two spellings agree.
    assert.equal(normalizeHtu("https://api.example.com"), "https://api.example.com/");
  });

  // ---------------------------------------------------------------- iat
  it("a STALE proof is refused, as expired", async () => {
    const proof = await key.proof({
      method: METHOD,
      uri: API_URI,
      accessToken: token,
      issuedAt: Math.floor(Date.now() / 1000) - 600,
    });
    await expectReason(proof, "expired");
  });

  it("a proof from the FUTURE is refused, as not_yet_valid", async () => {
    const proof = await key.proof({
      method: METHOD,
      uri: API_URI,
      accessToken: token,
      issuedAt: Math.floor(Date.now() / 1000) + 600,
    });
    await expectReason(proof, "not_yet_valid");
  });

  // ---------------------------------------------------------------- ath
  it("a proof with NO ath is refused — it is mandatory for a resource request", async () => {
    const proof = await key.proof({ method: METHOD, uri: API_URI, omitAth: true });
    await expectReason(proof, "malformed");
  });

  it("a proof whose ath is for a DIFFERENT token is refused", async () => {
    const proof = await key.proof({
      method: METHOD,
      uri: API_URI,
      accessToken: "some.other.token",
    });
    await expectReason(proof, "bad_signature");
  });

  // ---------------------------------------------------------------- binding
  it("a proof signed by a DIFFERENT key is refused, even though it is valid", async () => {
    // The core DPoP property: a perfectly-formed, correctly-signed proof from a
    // key the token is not bound to must be worthless.
    const otherKey = await createDpopKey();
    const proof = await otherKey.proof({ method: METHOD, uri: API_URI, accessToken: token });
    await expectReason(proof, "bad_signature");
  });

  it("a proof signed by another key but EMBEDDING the right one is refused", async () => {
    // The signature is checked against the embedded key, so this fails on
    // signature — and if it somehow did not, the thumbprint check would catch it.
    const otherKey = await createDpopKey();
    const proof = await otherKey.proof({
      method: METHOD,
      uri: API_URI,
      accessToken: token,
      embedJwk: key.jwk,
    });
    await expectReason(proof, "bad_signature");
  });

  // ---------------------------------------------------------------- typ / alg
  it("a proof whose typ is not dpop+jwt is refused", async () => {
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    const proof = await new SignJWT({ jti: "x", htm: METHOD, htu: API_URI, iat: Math.floor(Date.now() / 1000) })
      .setProtectedHeader({ typ: "JWT", alg: "ES256", jwk: key.jwk })
      .sign(privateKey);
    await expectReason(proof, "wrong_token_type");
  });

  it("`alg: none` is refused", async () => {
    const header = Buffer.from(JSON.stringify({ typ: "dpop+jwt", alg: "none", jwk: key.jwk })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ jti: "x", htm: METHOD, htu: API_URI, iat: 1 })).toString("base64url");
    await expectReason(`${header}.${body}.`, "unsupported_algorithm");
  });

  it("`alg: HS256` is refused — signing with the embedded public key as a secret", async () => {
    // The attack DPoP's design makes possible if a verifier accepts symmetric
    // algorithms: the "key" is in the proof, so anyone can sign with it.
    const header = Buffer.from(JSON.stringify({ typ: "dpop+jwt", alg: "HS256", jwk: key.jwk })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ jti: "x", htm: METHOD, htu: API_URI, iat: 1 })).toString("base64url");
    await expectReason(`${header}.${body}.AAAA`, "unsupported_algorithm");
  });

  // ---------------------------------------------------------------- jwk hygiene
  it("a proof embedding PRIVATE key members is refused", async () => {
    const proof = await key.proof({
      method: METHOD,
      uri: API_URI,
      accessToken: token,
      includePrivateMembers: true,
    });
    await expectReason(proof, "malformed");
  });

  it("a proof with NO jwk header is refused", async () => {
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    const proof = await new SignJWT({
      jti: "x",
      htm: METHOD,
      htu: API_URI,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256" })
      .sign(privateKey);
    await expectReason(proof, "malformed");
  });

  it("a tampered proof signature is refused", async () => {
    const proof = await key.proof({ method: METHOD, uri: API_URI, accessToken: token });
    const [h, p] = proof.split(".");
    await expectReason(`${h}.${p}.AAAAdeadbeef`, "bad_signature");
  });

  // ---------------------------------------------------------------- replay
  it("REPLAY: the same proof used twice is refused the second time", async () => {
    // The whole reason a replay cache exists. Without it, a captured proof stays
    // usable for its entire freshness window.
    const shared = new InMemoryReplayCache();
    const proof = await key.proof({ method: METHOD, uri: API_URI, accessToken: token });

    const first = await verify(proof, { replayCache: shared });
    assert.equal(first.thumbprint, thumbprint, "first use must succeed");

    await expectReason(proof, "bad_signature", { replayCache: shared });
  });

  it("two proofs with different jti are both accepted", async () => {
    // Control for the replay test: proves the refusal above is about `jti`, not
    // about the cache refusing everything.
    const shared = new InMemoryReplayCache();
    const a = await key.proof({ method: METHOD, uri: API_URI, accessToken: token });
    const b = await key.proof({ method: METHOD, uri: API_URI, accessToken: token });
    await verify(a, { replayCache: shared });
    await verify(b, { replayCache: shared });
  });

  it("an EMPTY or ABSENT proof is refused by an explicit check", async () => {
    // Asserted directly, so the guard is mutation-visible. Previously this case was
    // satisfied only because decoding an undefined header throws, which meant the
    // caller's own check could be deleted without any test noticing.
    await expectReason("", "malformed");
    await expectReason(undefined as unknown as string, "malformed");
  });

  it("a proof with NO jti is refused", async () => {
    const proof = await key.proof({ method: METHOD, uri: API_URI, accessToken: token, omitJti: true });
    await expectReason(proof, "malformed");
  });
});

describe("replay cache", () => {
  it("consumes a value exactly once", async () => {
    const cache = new InMemoryReplayCache();
    assert.equal(await cache.consume("a", 60_000), true);
    assert.equal(await cache.consume("a", 60_000), false);
  });

  it("forgets a value once its window passes", async () => {
    const cache = new InMemoryReplayCache();
    assert.equal(await cache.consume("b", 1), true);
    await new Promise((r) => setTimeout(r, 5));
    // Still present until a sweep runs; the sweep happens on the next consume.
    assert.equal(await cache.consume("c", 60_000), true);
    assert.equal(cache.size, 1, "expired entry should have been swept");
  });

  it("does not grow without bound", async () => {
    const cache = new InMemoryReplayCache();
    for (let i = 0; i < 100; i++) await cache.consume(`j${i}`, 1);
    await new Promise((r) => setTimeout(r, 5));
    await cache.consume("trigger", 60_000);
    assert.equal(cache.size, 1);
  });
});
