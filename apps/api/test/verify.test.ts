/**
 * Token verification, tested against the real identity provider.
 *
 * Two rules govern this file.
 *
 * **Every negative case asserts the CAUSE, not just the failure.** "It threw" is
 * satisfied by a verifier that throws at everything, including valid tokens. S5e
 * in this project shipped a wrong conclusion because a probe could not tell
 * "denied" from "broken"; these assertions distinguish them by reason.
 *
 * **The positive control runs first and must pass.** Without it, every negative
 * assertion below is also satisfied by a verifier that refuses everything.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";

import { JwksSource } from "../src/jwks.ts";
import {
  assertNotDowngraded,
  requireTenant,
  verifyAccessToken,
  type VerifiedToken,
  type VerifyOptions,
} from "../src/verify.ts";
import { TokenVerificationError, type FailureReason } from "../src/errors.ts";
import {
  API_CLIENT,
  ISSUER,
  JWKS_URI,
  MASTER_JWKS_URI,
  ensureLabFixtures,
  getExpiredToken,
  getIdToken,
  getRealToken,
  isLabUp,
  tamperPayload,
  tamperSignature,
} from "./lab.ts";
import { startSyntheticIssuer, type SyntheticIssuer } from "./synthetic-issuer.ts";

const jwks = new JwksSource(JWKS_URI, { cooldownDurationSec: 1 });
const masterJwks = new JwksSource(MASTER_JWKS_URI, { cooldownDurationSec: 1 });
// Annotated, not `as const`: the tests below deliberately override issuer and
// audience with WRONG values, which a narrowed literal type would reject at
// compile time — the compiler would stop us testing the failure.
const base: VerifyOptions = { jwks, issuer: ISSUER, audience: API_CLIENT };

const labUp = await isLabUp();

/** Assert rejection AND the reason. The reason is the whole point. */
async function expectReason(
  token: string,
  expected: FailureReason,
  overrides: Partial<VerifyOptions> = {},
): Promise<void> {
  try {
    const result = await verifyAccessToken(token, { ...base, ...overrides });
    assert.fail(
      `expected rejection (${expected}) but the token VERIFIED as sub=${result.subject}`,
    );
  } catch (error) {
    assert.ok(
      error instanceof TokenVerificationError,
      `expected TokenVerificationError, got ${String(error)}`,
    );
    assert.equal(
      error.reason,
      expected,
      `wrong failure reason: got '${error.reason}', expected '${expected}'`,
    );
  }
}

describe("token verification against the live lab", { skip: labUp ? false : "Keycloak is not running" }, () => {
  let real: Awaited<ReturnType<typeof getRealToken>>;
  let verified: VerifiedToken;

  before(async () => {
    await ensureLabFixtures();
    real = await getRealToken();
    verified = await verifyAccessToken(real.token, base);
  });

  // ---------------------------------------------------------------- positive
  it("CONTROL: a real token from Keycloak verifies", async () => {
    assert.equal(typeof verified.subject, "string");
    assert.ok(verified.subject.length > 0, "subject should be present");
    assert.equal(verified.issuer, ISSUER);
    assert.ok(verified.audience.includes(API_CLIENT), `aud should include ${API_CLIENT}`);
    assert.ok(verified.expiresAt > Math.floor(Date.now() / 1000), "exp should be in the future");
  });

  it("the verified claims match what Keycloak actually issued", async () => {
    // Guards against a verifier that returns a plausible object not derived from
    // the token in front of it — the S5d `setFlow()` defect.
    assert.equal(verified.claims["sub"], real.payload["sub"]);
    assert.equal(verified.claims["iss"], real.payload["iss"]);
    assert.equal(verified.expiresAt, real.payload["exp"]);
  });

  // ---------------------------------------------------------------- integrity
  it("a tampered SIGNATURE is refused, as bad_signature", async () => {
    await expectReason(tamperSignature(real.token), "bad_signature");
  });

  it("a tampered PAYLOAD is refused, as bad_signature", async () => {
    const forged = tamperPayload(real.token, (p) => {
      p["sub"] = "attacker-controlled-subject";
    });
    await expectReason(forged, "bad_signature");
  });

  it("a structurally invalid token is refused, as malformed", async () => {
    await expectReason("not.a.token", "malformed");
  });

  // ---------------------------------------------------------------- claims
  it("a token for a DIFFERENT issuer is refused, as wrong_issuer", async () => {
    await expectReason(real.token, "wrong_issuer", { issuer: "http://evil.localhost/realms/etc" });
  });

  it("a token for a DIFFERENT audience is refused, as wrong_audience", async () => {
    await expectReason(real.token, "wrong_audience", { audience: "some-other-api" });
  });

  it("the issuer comparison is EXACT, not a prefix match", async () => {
    // A `startsWith` check would accept this. It must not.
    await expectReason(real.token, "wrong_issuer", { issuer: ISSUER.slice(0, -1) });
  });

  // ---------------------------------------------------------------- expiry
  it("an EXPIRED token is refused, as expired — with a real signature", async () => {
    // `clockToleranceSec: 0` deliberately. With the default 5s skew allowance a
    // 1-second token remains valid for 6 seconds, so a test that waits 2.5s would
    // find it still valid — and would report a verifier defect that does not exist.
    const expired = await getExpiredToken();
    await expectReason(expired, "expired", { clockToleranceSec: 0 });
  });

  it("clock tolerance is bounded, not unlimited", async () => {
    // Same token, generous tolerance: still accepted. Proves the test above fails
    // because of EXPIRY, not because the token was rejected for some other reason.
    const expired = await getExpiredToken();
    const tolerated = await verifyAccessToken(expired, { ...base, clockToleranceSec: 60 });
    assert.equal(typeof tolerated.subject, "string");
  });

  // ---------------------------------------------------------------- algorithms
  it("`alg: none` is refused, not honoured", async () => {
    const [header, payload] = real.token.split(".");
    void header;
    const noneHeader = Buffer.from(
      JSON.stringify({ alg: "none", typ: "Bearer" }),
    ).toString("base64url");
    await expectReason(`${noneHeader}.${payload}.`, "unsupported_algorithm");
  });

  it("an algorithm outside the allowed set is refused", async () => {
    // HS256 would let an attacker sign with the PUBLIC key treated as a shared
    // secret — the classic JWT confusion attack.
    const [header, payload, signature] = real.token.split(".");
    void header;
    const hs = Buffer.from(JSON.stringify({ alg: "HS256", typ: "Bearer" })).toString("base64url");
    await expectReason(`${hs}.${payload}.${signature}`, "unsupported_algorithm");
  });

  // ---------------------------------------------------------------- token type
  it("a header `typ` that is not the JOSE media type is refused", async () => {
    // The header is a cheap malformed-input guard ONLY. It is "JWT" for every
    // Keycloak token, so it cannot distinguish an access token from an ID token.
    const [, payload, signature] = real.token.split(".");
    const oddHeader = Buffer.from(JSON.stringify({ alg: "RS256", typ: "ID" })).toString("base64url");
    await expectReason(`${oddHeader}.${payload}.${signature}`, "wrong_token_type");
  });

  it("a real ID TOKEN is refused as an access token — the payload `typ` check", async () => {
    // THE meaningful case. A genuinely signed ID token has payload `typ: "ID"`.
    // This cannot be faked by editing a payload, because that breaks the signature
    // and the test would then pass for the wrong reason.
    const { idToken, issuer, audience } = await getIdToken();
    // Verified with the MASTER realm's keys, because that is who signed it.
    await expectReason(idToken, "wrong_token_type", { issuer, audience, jwks: masterJwks });
  });

  it("the ID token WOULD verify on its own issuer and audience", async () => {
    // Control for the test above: proves the ID token was rejected for its TYPE,
    // and not merely because its issuer or audience did not match the API's.
    const { idToken, issuer, audience } = await getIdToken();
    await assert.rejects(
      () => verifyAccessToken(idToken, { ...base, issuer, audience, jwks: masterJwks }),
      (error: unknown) =>
        error instanceof TokenVerificationError && error.reason === "wrong_token_type",
      "an ID token must fail on type even when issuer and audience are correct",
    );
  });

  // ---------------------------------------------------------------- tenant (ADR-006)
  it("a tenant claim is read from the VERIFIED token", async () => {
    const withTenant = { ...verified, claims: { ...verified.claims, tenant_id: "acme" } };
    assert.equal(requireTenant(withTenant, "tenant_id"), "acme");
  });

  it("a MISSING tenant claim is a hard failure, never a default", () => {
    // Built by hand rather than taken from the provider: real tokens now carry a
    // `tenant_id` mapper, so no real token can exercise the absence. A defaulted
    // tenant is how one customer's request reads another customer's data, so the
    // absence has to be a hard failure and has to be tested.
    const withoutTenant: VerifiedToken = {
      ...verified,
      claims: { ...verified.claims },
    };
    delete (withoutTenant.claims as Record<string, unknown>)["tenant_id"];

    assert.throws(
      () => requireTenant(withoutTenant, "tenant_id"),
      (error: unknown) =>
        error instanceof TokenVerificationError && error.reason === "missing_tenant",
    );
  });

  it("ADR-006: a tenant outside the token has NO effect on the result", () => {
    // The token says `acme`. Extra context claiming otherwise — however it arrived
    // — must not change what `requireTenant` returns, because it reads the verified
    // claims and nothing else.
    const withExtras = {
      ...verified,
      headers: { "x-tenant-id": "attacker-tenant" },
      query: { tenant_id: "attacker-tenant" },
      body: { tenant_id: "attacker-tenant" },
    } as unknown as VerifiedToken;

    assert.equal(requireTenant(withExtras, "tenant_id"), "acme");
  });

  // ---------------------------------------------------------------- DPoP downgrade
  it("a DPoP-bound token without a proof is refused (no silent downgrade)", () => {
    const bound: VerifiedToken = { ...verified, dpopThumbprint: "fake-thumbprint" };
    assert.throws(
      () => assertNotDowngraded(bound, false),
      (error: unknown) => error instanceof TokenVerificationError,
    );
  });

  it("a DPoP-bound token WITH a proof passes this guard", () => {
    const bound: VerifiedToken = { ...verified, dpopThumbprint: "fake-thumbprint" };
    assert.doesNotThrow(() => assertNotDowngraded(bound, true));
  });

  it("an unbound token is unaffected by the DPoP guard", () => {
    assert.doesNotThrow(() => assertNotDowngraded(verified, false));
  });
});

/**
 * Claims the real provider will not mint.
 *
 * This block exists because mutation testing showed a gap: deleting the `sub`
 * check from `verify.ts` left every test GREEN. Keycloak always issues a `sub`, so
 * no real-token test can prove the absence is handled. A check with no test is a
 * check that can be deleted silently.
 */
describe("synthetic issuer: shapes Keycloak cannot be asked to produce", () => {
  let synthetic: SyntheticIssuer;
  let synthJwks: JwksSource;

  before(async () => {
    synthetic = await startSyntheticIssuer();
    synthJwks = new JwksSource(synthetic.jwksUri, { cooldownDurationSec: 1 });
  });

  after(async () => {
    await synthetic?.close();
  });

  const opts = (): VerifyOptions => ({
    jwks: synthJwks,
    issuer: synthetic.issuer,
    audience: synthetic.audience,
  });

  it("CONTROL: a synthetic token with all required claims verifies", async () => {
    // Without this, every rejection below is also satisfied by a verifier that
    // rejects synthetic tokens unconditionally.
    const token = await synthetic.sign({});
    const verifiedSynth = await verifyAccessToken(token, opts());
    assert.equal(verifiedSynth.subject, "synthetic-subject");
    assert.equal(verifiedSynth.issuer, synthetic.issuer);
  });

  it("a token with NO `sub` is refused, as malformed", async () => {
    const token = await synthetic.sign({}, { dropClaims: ["sub"] });
    await expectReason(token, "malformed", opts());
  });

  it("a token with NO `exp` is refused, as malformed", async () => {
    const token = await synthetic.sign({}, { dropClaims: ["exp"] });
    await expectReason(token, "malformed", opts());
  });

  it("an empty-string `sub` is refused, not treated as present", async () => {
    const token = await synthetic.sign({ sub: "" });
    await expectReason(token, "malformed", opts());
  });

  it("a `cnf.jkt` is surfaced so the request layer can demand a proof", async () => {
    const token = await synthetic.sign({ cnf: { jkt: "thumbprint-abc" } });
    const verifiedSynth = await verifyAccessToken(token, opts());
    assert.equal(verifiedSynth.dpopThumbprint, "thumbprint-abc");
  });

  it("a NON-STRING `cnf.jkt` is ignored rather than trusted", async () => {
    const token = await synthetic.sign({ cnf: { jkt: { evil: true } } });
    const verifiedSynth = await verifyAccessToken(token, opts());
    assert.equal(verifiedSynth.dpopThumbprint, undefined);
  });

  it("a tenant claim from a verified token is returned", async () => {
    const token = await synthetic.sign({ tenant_id: "acme" });
    const verifiedSynth = await verifyAccessToken(token, opts());
    assert.equal(requireTenant(verifiedSynth, "tenant_id"), "acme");
  });
});
