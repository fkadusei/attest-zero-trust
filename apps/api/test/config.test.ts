/**
 * Configuration is a trust boundary.
 *
 * Environment variables are input from outside the program, and TypeScript says
 * nothing about them at runtime. These tests exist because two of the checks here
 * are security controls rather than conveniences:
 *
 * - the issuer must use HTTPS off loopback, or tokens are interceptable and every
 *   other control in the system becomes decorative
 * - the JWKS URI is pinned at startup and cannot be influenced by a request, or a
 *   token could nominate its own signing keys
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { ConfigError, loadConfig } from "../src/config.ts";

const VALID = {
  KEYCLOAK_ISSUER: "https://id.example.com/realms/attest",
  API_AUDIENCE: "attest-api",
  PUBLIC_BASE_URL: "https://api.example.com",
};

function expectConfigError(env: Record<string, string | undefined>, match: RegExp): void {
  assert.throws(
    () => loadConfig(env),
    (error: unknown) => {
      assert.ok(error instanceof ConfigError, `expected ConfigError, got ${String(error)}`);
      assert.match(error.message, match);
      return true;
    },
  );
}

describe("configuration", () => {
  it("a complete environment loads", () => {
    const config = loadConfig({ ...VALID });
    assert.equal(config.identity.issuer, "https://id.example.com/realms/attest");
    assert.equal(config.identity.audience, "attest-api");
  });

  it("derives the JWKS URI from the issuer when not given", () => {
    const config = loadConfig({ ...VALID });
    assert.equal(
      config.identity.jwksUri,
      "https://id.example.com/realms/attest/protocol/openid-connect/certs",
    );
  });

  it("allows the JWKS URI to be overridden for split-horizon DNS", () => {
    const config = loadConfig({ ...VALID, KEYCLOAK_JWKS_URI: "http://keycloak.internal:8080/certs" });
    assert.equal(config.identity.jwksUri, "http://keycloak.internal:8080/certs");
  });

  it("strips a trailing slash from the issuer so comparison stays exact", () => {
    // A trailing slash would make an exact `iss` comparison fail against tokens
    // Keycloak issues without one, and the obvious "fix" is a substring match —
    // which is a bypass.
    const config = loadConfig({ ...VALID, KEYCLOAK_ISSUER: "https://id.example.com/realms/attest/" });
    assert.equal(config.identity.issuer, "https://id.example.com/realms/attest");
    assert.equal(
      config.identity.jwksUri,
      "https://id.example.com/realms/attest/protocol/openid-connect/certs",
    );
  });

  // ------------------------------------------------------------ required values
  it("refuses to start without an issuer", () => {
    expectConfigError(
      { API_AUDIENCE: "attest-api", PUBLIC_BASE_URL: VALID.PUBLIC_BASE_URL },
      /KEYCLOAK_ISSUER/,
    );
  });

  it("refuses to start without an audience", () => {
    expectConfigError(
      { KEYCLOAK_ISSUER: VALID.KEYCLOAK_ISSUER, PUBLIC_BASE_URL: VALID.PUBLIC_BASE_URL },
      /API_AUDIENCE/,
    );
  });

  it("refuses to start without a public base URL", () => {
    // Required because DPoP's htu check needs a TRUSTED expected URI. Defaulting it
    // to something derived from the request would silently remove that check.
    expectConfigError(
      { KEYCLOAK_ISSUER: VALID.KEYCLOAK_ISSUER, API_AUDIENCE: VALID.API_AUDIENCE },
      /PUBLIC_BASE_URL/,
    );
  });

  it("REFUSES a plain-HTTP public base URL that is not loopback", () => {
    expectConfigError(
      { ...VALID, PUBLIC_BASE_URL: "http://api.example.com" },
      /must use https/,
    );
  });

  it("strips a trailing slash from the public base URL", () => {
    assert.equal(
      loadConfig({ ...VALID, PUBLIC_BASE_URL: "https://api.example.com/" }).publicBaseUrl,
      "https://api.example.com",
    );
  });

  it("treats an empty string as missing, not as a value", () => {
    expectConfigError({ ...VALID, API_AUDIENCE: "   " }, /API_AUDIENCE/);
  });

  // ------------------------------------------------------------ the HTTPS rule
  it("REFUSES a plain-HTTP issuer that is not loopback", () => {
    // Not a style preference: over plain HTTP off loopback, tokens are
    // interceptable in transit.
    expectConfigError(
      { ...VALID, KEYCLOAK_ISSUER: "http://id.example.com/realms/attest" },
      /must use https/,
    );
  });

  it("permits plain HTTP on loopback, for the local lab", () => {
    for (const host of ["localhost", "127.0.0.1", "app.localhost"]) {
      const config = loadConfig({ ...VALID, KEYCLOAK_ISSUER: `http://${host}:8080/realms/attest` });
      assert.equal(config.identity.issuer, `http://${host}:8080/realms/attest`);
    }
  });

  it("does NOT accept a hostname merely containing 'localhost'", () => {
    // `evil-localhost.example.com` ends with neither `.localhost` nor the exact
    // names, so it must be refused. A `includes()` check here would be a bypass.
    expectConfigError(
      { ...VALID, KEYCLOAK_ISSUER: "http://evil-localhost.example.com/realms/attest" },
      /must use https/,
    );
  });

  it("refuses a syntactically invalid issuer", () => {
    expectConfigError({ ...VALID, KEYCLOAK_ISSUER: "not a url" }, /not a valid absolute URL/);
  });

  // ------------------------------------------------------------ numeric bounds
  it("bounds the clock tolerance rather than accepting anything", () => {
    assert.equal(loadConfig({ ...VALID, CLOCK_TOLERANCE_SEC: "30" }).clockToleranceSec, 30);
    expectConfigError({ ...VALID, CLOCK_TOLERANCE_SEC: "99999" }, /between 0 and 120/);
    expectConfigError({ ...VALID, CLOCK_TOLERANCE_SEC: "-1" }, /between 0 and 120/);
    expectConfigError({ ...VALID, CLOCK_TOLERANCE_SEC: "abc" }, /must be an integer/);
  });

  it("bounds the port", () => {
    assert.equal(loadConfig({ ...VALID, HTTP_PORT: "8080" }).http.port, 8080);
    expectConfigError({ ...VALID, HTTP_PORT: "70000" }, /between 1 and 65535/);
  });

  it("defaults the tenant claim but lets the realm override it", () => {
    assert.equal(loadConfig({ ...VALID }).tenantClaim, "tenant_id");
    assert.equal(loadConfig({ ...VALID, TENANT_CLAIM: "org" }).tenantClaim, "org");
  });

  // ------------------------------------------------------------ the architecture rule
  it("ARCHITECTURE: the core config needs no cloud-specific variable", () => {
    // ADR-015 rule 1. If this ever starts failing, a cloud concept has leaked into
    // the core and the portability claim is no longer true.
    const cloudFree = loadConfig({ ...VALID });
    assert.equal(cloudFree.identity.issuer, VALID.KEYCLOAK_ISSUER);
    assert.ok(!JSON.stringify(cloudFree).toUpperCase().includes("AWS"));
    assert.ok(!JSON.stringify(cloudFree).toUpperCase().includes("AZURE"));
    assert.ok(!JSON.stringify(cloudFree).toUpperCase().includes("GCP"));
  });

  it("ignores cloud variables rather than depending on them", () => {
    // Supplying AWS settings must change nothing. They are for adapters, not here.
    const withCloud = loadConfig({
      ...VALID,
      AWS_REGION: "eu-west-1",
      AWS_ACCESS_KEY_ID: "AKIAEXAMPLE",
      DYNAMODB_TABLE: "attest",
      S3_BUCKET: "attest-evidence",
    });
    assert.deepEqual(withCloud, loadConfig({ ...VALID }));
  });
});
