/**
 * Tests for the key source — specifically the two properties the file exists to protect.
 *
 * WHY THIS FILE EXISTS
 *
 * `jwks.ts` is 60 lines wrapping `jose`'s remote key set, and it had no tests. Most of what
 * it does is the library's job, and re-testing `jose` would be noise. But **two settings in
 * it are ours, and both are security-relevant**:
 *
 *   `cooldownDuration` (default 30s) bounds how often an unknown `kid` can force a refetch.
 *   `cacheMaxAge` (default 600s) bounds how stale the key set may be before rotation.
 *
 * If the cooldown were 0, then **every unauthenticated request carrying a made-up `kid`
 * would trigger an outbound fetch** to the identity provider — the one service that must
 * stay up for anyone to log in. That is a denial-of-service amplifier, and nothing tested
 * that it was bounded.
 *
 * WHAT IS ASSERTED
 *
 *   A burst of verifications with an UNKNOWN kid does not fetch once per request.
 *   A CONTROL with the cooldown disabled DOES fetch repeatedly — proving the first test
 *   can fail, rather than passing because the fetch never happens at all.
 *
 * A test that passes because no fetch ever occurred would be worthless here, which is why
 * the control asserts a fetch count that goes UP.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";

import { JwksSource } from "../src/jwks.ts";

/** The private half, typed from what `generateKeyPair` actually returns. */
type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];

/** A local JWKS endpoint that counts how many times it is fetched. */
interface KeyServer {
  server: Server;
  url: string;
  fetches: () => number;
  reset: () => void;
  publicJwk: Record<string, unknown>;
  privateKey: PrivateKey;
}

async function startKeyServer(): Promise<KeyServer> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = await exportJWK(publicKey);
  const publicJwk = { ...jwk, kid: "the-real-key", alg: "RS256", use: "sig" };

  let count = 0;
  const server = createServer((request, response) => {
    // Only the JWKS path is served; anything else would be a bug in the caller.
    if (request.url?.endsWith("/certs") !== true) {
      response.writeHead(404).end();
      return;
    }
    count += 1;
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ keys: [publicJwk] }));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  return {
    server,
    url: `http://127.0.0.1:${address.port}/certs`,
    fetches: () => count,
    reset: () => { count = 0; },
    publicJwk,
    privateKey,
  };
}

/** A token signed by the server's key, but claiming a kid the key set does not contain. */
async function tokenWithUnknownKid(privateKey: PrivateKey): Promise<string> {
  return new SignJWT({ sub: "u1" })
    .setProtectedHeader({ alg: "RS256", kid: "a-kid-that-does-not-exist" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

/** A token signed by the server's key, with the kid it actually publishes. */
async function tokenWithRealKid(privateKey: PrivateKey): Promise<string> {
  return new SignJWT({ sub: "u1" })
    .setProtectedHeader({ alg: "RS256", kid: "the-real-key" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
}

describe("the key source", () => {
  let keys: KeyServer;

  before(async () => { keys = await startKeyServer(); });
  after(async () => { await new Promise<void>((r) => keys.server.close(() => r())); });

  it("resolves a token signed by the published key", async () => {
    // The positive control for everything below: the source actually works.
    keys.reset();
    const source = new JwksSource(keys.url);
    const token = await tokenWithRealKid(keys.privateKey);
    const { payload } = await jwtVerify(token, source.resolver);
    assert.equal(payload["sub"], "u1");
    assert.ok(keys.fetches() >= 1, "it must have fetched the key set at least once");
  });

  it("exposes the URL it was constructed with, and only that", async () => {
    // The URL is pinned at construction. A verifier that derived the key source from the
    // token would let a token nominate its own keys.
    const source = new JwksSource(keys.url);
    assert.equal(source.url, keys.url);
  });

  /**
   * THE PROPERTY THIS FILE EXISTS FOR.
   *
   * An attacker does not need a valid token to reach this code: any request with a
   * structurally valid JWT carrying an invented `kid` gets as far as key lookup. If each
   * one forced a fetch, the cost of one cheap request would be one outbound call to the
   * identity provider. The cooldown is what stops that.
   */
  it("does NOT fetch once per request when the kid is unknown", async () => {
    keys.reset();
    const source = new JwksSource(keys.url); // defaults: 30s cooldown
    const token = await tokenWithUnknownKid(keys.privateKey);

    const BURST = 10;
    for (let i = 0; i < BURST; i++) {
      await assert.rejects(
        () => jwtVerify(token, source.resolver),
        "an unknown kid must be refused",
      );
    }

    // The initial fetch is unavoidable. What must not happen is one per attempt.
    assert.ok(
      keys.fetches() < BURST,
      `${BURST} unknown-kid verifications caused ${keys.fetches()} fetches — the cooldown is not bounding them`,
    );
  });

  /**
   * THE CONTROL.
   *
   * The test above passes trivially if nothing is ever fetched. This one proves the fetch
   * counter moves: with the cooldown disabled, the same burst DOES produce repeated
   * fetches. If this ever stops being true, the test above has stopped measuring anything.
   */
  it("CONTROL: with the cooldown disabled, the same burst DOES fetch repeatedly", async () => {
    keys.reset();
    const source = new JwksSource(keys.url, { cooldownDurationSec: 0 });
    const token = await tokenWithUnknownKid(keys.privateKey);

    const BURST = 5;
    for (let i = 0; i < BURST; i++) {
      await assert.rejects(() => jwtVerify(token, source.resolver));
    }

    assert.ok(
      keys.fetches() > 1,
      `with the cooldown disabled, ${BURST} attempts produced only ${keys.fetches()} fetch(es) — the counter is not measuring, so the bounded test above proves nothing`,
    );
  });

  it("refuses to verify when the key server is unreachable", async () => {
    // A verifier that treated an unreachable issuer as "no keys, therefore fine" would be
    // a fail-open path. It must refuse.
    const source = new JwksSource("http://127.0.0.1:1/certs", { timeoutMs: 500 });
    const token = await tokenWithRealKid(keys.privateKey);
    await assert.rejects(() => jwtVerify(token, source.resolver));
  });
});
