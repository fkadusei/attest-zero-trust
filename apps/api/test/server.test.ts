/**
 * End-to-end HTTP tests — the request path that did not exist until now.
 *
 * Everything before this tested FUNCTIONS. These test REQUEST BEHAVIOUR: the
 * scheme the caller used, the header they omitted, the order the checks run in,
 * and what the response body actually says. Several of the controls below could
 * not be exercised at all before there was a server, `assertNotDowngraded` among
 * them — it was written, unit-tested, and referenced by no production code.
 *
 * `app.inject()` runs the full Fastify pipeline (routing, hooks, serialisation)
 * without opening a socket, so these are genuine HTTP-level tests and still fast.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";

import { loadConfig } from "../src/config.ts";
import { JwksSource } from "../src/jwks.ts";
import { InMemoryReplayCache } from "../src/ports/replay-cache.ts";
import { systemClock } from "../src/ports/clock.ts";
import { buildServer } from "../src/server.ts";
import { createDpopKey, getBoundToken, setupBoundToken, DPOP_CLIENT, type DpopKey } from "./dpop-harness.ts";
import { API_CLIENT, ISSUER, JWKS_URI, ensureLabFixtures, getRealToken, isLabUp } from "./lab.ts";

const labUp = await isLabUp();

/** Loopback, so plain HTTP is permitted by config's HTTPS rule. */
const BASE = "http://127.0.0.1:3000";
const SESSION_PATH = "/v1/session";
const SESSION_URI = `${BASE}${SESSION_PATH}`;

describe("the API over HTTP", { skip: labUp ? false : "Keycloak is not running" }, () => {
  let app: Awaited<ReturnType<typeof buildServer>>;
  let unboundToken: string;
  let boundToken: string;
  let boundKey: DpopKey;
  let boundThumbprint: string;

  before(async () => {
    await ensureLabFixtures();
    const config = loadConfig({
      KEYCLOAK_ISSUER: ISSUER,
      API_AUDIENCE: API_CLIENT,
      PUBLIC_BASE_URL: BASE,
      TENANT_CLAIM: "tenant_id",
    });

    app = buildServer({
      config,
      jwks: new JwksSource(JWKS_URI, { cooldownDurationSec: 1 }),
      clock: systemClock,
      replayCache: new InMemoryReplayCache(),
    });
    await app.ready();

    const real = await getRealToken();
    unboundToken = real.token;

    const bound = await setupBoundToken();
    boundToken = bound.token;
    boundKey = bound.key;
    boundThumbprint = bound.thumbprint;
  });

  after(async () => {
    await app?.close();
  });

  const get = (headers: Record<string, string> = {}) =>
    app.inject({ method: "GET", url: SESSION_PATH, headers });

  // ---------------------------------------------------------------- public
  it("/health is reachable without credentials", async () => {
    const res = await app.inject({ method: "GET", url: "/health" });
    assert.equal(res.statusCode, 200);
    assert.deepEqual(res.json(), { status: "ok" });
  });

  // ---------------------------------------------------------------- rejections
  it("no Authorization header is rejected", async () => {
    const res = await get();
    assert.equal(res.statusCode, 401);
  });

  it("a malformed Authorization header is rejected", async () => {
    const res = await get({ authorization: "nonsense" });
    assert.equal(res.statusCode, 401);
  });

  it("a tampered token is rejected", async () => {
    const [h, p] = unboundToken.split(".");
    const res = await get({ authorization: `Bearer ${h}.${p}.AAAAdeadbeef` });
    assert.equal(res.statusCode, 401);
  });

  it("the rejection body is OPAQUE — it names no reason", async () => {
    // A body that says "expired" or "bad signature" is an oracle telling an
    // attacker which part of a forgery to fix next.
    const [h, p] = unboundToken.split(".");
    const res = await get({ authorization: `Bearer ${h}.${p}.AAAAdeadbeef` });
    const body = res.body.toLowerCase();
    for (const leak of ["signature", "expired", "issuer", "audience", "jwt", "token", "key"]) {
      assert.ok(!body.includes(leak), `response leaked the word '${leak}': ${res.body}`);
    }
    assert.deepEqual(res.json(), { error: "unauthorized" });
  });

  // ---------------------------------------------------------------- unbound
  it("a valid UNBOUND token authenticates under the Bearer scheme", async () => {
    const res = await get({ authorization: `Bearer ${unboundToken}` });
    assert.equal(res.statusCode, 200, res.body);
    const body = res.json();
    assert.equal(body.senderConstrained, false);
    assert.equal(typeof body.subject, "string");
  });

  // ---------------------------------------------------------------- bound
  it("a DPoP-bound token WITH a valid proof authenticates", async () => {
    const proof = await boundKey.proof({
      method: "GET",
      uri: SESSION_URI,
      accessToken: boundToken,
    });
    const res = await get({ authorization: `DPoP ${boundToken}`, dpop: proof });
    assert.equal(res.statusCode, 200, res.body);
    const body = res.json();
    assert.equal(body.senderConstrained, true, "the API must report the token as sender-constrained");
    assert.equal(body.keyThumbprint, boundThumbprint);
  });

  it("THE S1 FINDING, now enforced: a bound token under the BEARER scheme is rejected", async () => {
    // RFC 9449 requires the DPoP scheme. Keycloak refuses the `Bearer` spelling of
    // a bound token; so must we, or the binding can be dropped by the caller.
    const proof = await boundKey.proof({ method: "GET", uri: SESSION_URI, accessToken: boundToken });
    const res = await get({ authorization: `Bearer ${boundToken}`, dpop: proof });
    assert.equal(res.statusCode, 401, `expected rejection, got ${res.statusCode}: ${res.body}`);
  });

  it("THE CONTROL THAT DID NOT EXIST BEFORE: a bound token with NO proof is rejected", async () => {
    // This is `assertNotDowngraded`, reached through a real request for the first
    // time. Before the server existed it was written, tested in isolation, and
    // called by nothing — a control protecting nothing.
    const res = await get({ authorization: `DPoP ${boundToken}` });
    assert.equal(res.statusCode, 401, `expected rejection, got ${res.statusCode}: ${res.body}`);
  });

  it("a bound token with a proof for a DIFFERENT URI is rejected", async () => {
    const proof = await boundKey.proof({
      method: "GET",
      uri: `${BASE}/v1/something-else`,
      accessToken: boundToken,
    });
    const res = await get({ authorization: `DPoP ${boundToken}`, dpop: proof });
    assert.equal(res.statusCode, 401);
  });

  it("a bound token with a proof for a DIFFERENT method is rejected", async () => {
    const proof = await boundKey.proof({ method: "POST", uri: SESSION_URI, accessToken: boundToken });
    const res = await get({ authorization: `DPoP ${boundToken}`, dpop: proof });
    assert.equal(res.statusCode, 401);
  });

  it("REPLAY over HTTP: the same proof twice fails the second time", async () => {
    // One shared server, therefore one shared replay cache — which is exactly the
    // production arrangement this check depends on.
    const proof = await boundKey.proof({ method: "GET", uri: SESSION_URI, accessToken: boundToken });
    const first = await get({ authorization: `DPoP ${boundToken}`, dpop: proof });
    assert.equal(first.statusCode, 200, first.body);
    const second = await get({ authorization: `DPoP ${boundToken}`, dpop: proof });
    assert.equal(second.statusCode, 401, "a replayed proof must be refused");
  });

  it("a proof whose ath is for a different token is rejected", async () => {
    const proof = await boundKey.proof({
      method: "GET",
      uri: SESSION_URI,
      accessToken: unboundToken,
    });
    const res = await get({ authorization: `DPoP ${boundToken}`, dpop: proof });
    assert.equal(res.statusCode, 401);
  });

  it("the DPoP scheme with an UNBOUND token is rejected", async () => {
    // The caller believes the token is bound. Accepting it would treat an
    // unprotected token as protected.
    const res = await get({ authorization: `DPoP ${unboundToken}` });
    assert.equal(res.statusCode, 401);
  });

  it("a proof signed by a different key is rejected", async () => {
    const other = await createDpopKey();
    const proof = await other.proof({ method: "GET", uri: SESSION_URI, accessToken: boundToken });
    const res = await get({ authorization: `DPoP ${boundToken}`, dpop: proof });
    assert.equal(res.statusCode, 401);
  });

  // ---------------------------------------------------------------- ADR-006
  it("ADR-006: the TOKEN's tenant wins over a header claiming another", async () => {
    // Stronger than asserting a missing claim is refused: the token genuinely
    // carries `tenant_id: "acme"`, the caller claims to be someone else by header,
    // and the API must report the token's value. This is the cross-tenant read the
    // rule exists to prevent.
    const res = await get({
      authorization: `Bearer ${unboundToken}`,
      "x-tenant-id": "attacker-tenant",
      "x-tenant": "attacker-tenant",
      tenant_id: "attacker-tenant",
    });
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(res.json().tenantId, "acme", "the tenant must come from the verified token");
    assert.ok(!res.body.includes("attacker-tenant"), "a header-supplied tenant must never be echoed");
  });

  it("ADR-006: the TOKEN's tenant wins over the query string", async () => {
    const res = await app.inject({
      method: "GET",
      url: `${SESSION_PATH}?tenant_id=attacker-tenant&tenant=attacker-tenant`,
      headers: { authorization: `Bearer ${unboundToken}` },
    });
    assert.equal(res.statusCode, 200, res.body);
    assert.equal(res.json().tenantId, "acme");
    assert.ok(!res.body.includes("attacker-tenant"));
  });
});
