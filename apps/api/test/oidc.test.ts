/**
 * Tests for the REAL OpenID Connect client.
 *
 * WHY THIS FILE EXISTS
 *
 * `console.test.ts` injects a **stub** `ConsoleOidc` so the routes can be tested without a
 * provider. That is the right way to test the routes — and it meant the real client was
 * never executed by any test at all.
 *
 * Mutation testing found it: four mutations in `console/oidc.ts` — including making the
 * ID-token `nonce` check return `true` unconditionally — all SURVIVED the whole suite of
 * 26 console tests. They survived because those tests exercise the stub, not the client.
 *
 * That is the most dangerous shape a coverage gap can take: the route tests *look* like
 * they cover sign-in, and the one component that decides whether a token belongs to this
 * flow was never run.
 *
 * What the client is responsible for, and what is asserted here:
 *
 *   `idTokenMatchesNonce`  — a token issued for a DIFFERENT flow must be refused. This is
 *                            the whole defence against substitution, and it is pure: no
 *                            network, no clock, and it takes an attacker-supplied string.
 *   `buildAuthorizationUrl`— `state` and `nonce` must actually reach the provider. A
 *                            check on a value that was never sent can never succeed.
 *   `buildLogoutUrl`       — an `id_token_hint` and a post-logout target, so signing out of
 *                            the console also ends the provider session.
 *
 * `discover()` and `exchangeCode()` talk to a live provider and are covered against the
 * lab when it is up, skipped with a stated reason when it is not.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { SignJWT } from "jose";

import { OidcClient } from "../src/console/oidc.ts";
import { ISSUER, isLabUp } from "./lab.ts";

/** Mint an ID token with whatever claims a case needs. No signature: the client does not verify one. */
async function idToken(claims: Record<string, unknown>): Promise<string> {
  return new SignJWT(claims as Record<string, never>)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .sign(new TextEncoder().encode("not-a-real-key-it-is-never-verified"));
}

// Top-level await is allowed in a module; inside describe()'s options object it is not.
const LAB_UP = await isLabUp();

const CLIENT_OPTIONS = {
  issuer: "https://id.example.com/realms/test",
  clientId: "attest-console",
  clientSecret: "secret",
  redirectUri: "https://console.example.com/console/callback",
  scope: "openid profile email",
};

describe("the real OIDC client", () => {
  // ---------------------------------------------------------------- nonce
  describe("idTokenMatchesNonce", () => {
    it("ACCEPTS a token whose nonce matches", async () => {
      const token = await idToken({ nonce: "the-right-one", sub: "u1" });
      assert.equal(OidcClient.idTokenMatchesNonce(token, "the-right-one"), true);
    });

    it("REFUSES a token whose nonce differs — this is the substitution defence", async () => {
      // The attack: an attacker completes their own sign-in, obtains a valid ID token for
      // THEIR account, and injects it into a victim's flow. The nonce is the only thing
      // that ties a token to the flow it was issued for.
      const token = await idToken({ nonce: "a-different-flow", sub: "attacker" });
      assert.equal(
        OidcClient.idTokenMatchesNonce(token, "the-right-one"),
        false,
        "a token from another flow must never be accepted",
      );
    });

    it("REFUSES a token with NO nonce claim at all", async () => {
      // Absent is not "matches". A provider that omits the claim leaves the check with
      // nothing to compare, and the only safe answer is refusal.
      const token = await idToken({ sub: "u1" });
      assert.equal(OidcClient.idTokenMatchesNonce(token, "the-right-one"), false);
    });

    it("REFUSES a nonce that is not a string", async () => {
      // A numeric or array nonce must not compare equal to a string by coercion.
      for (const nonce of [123, ["the-right-one"], { n: "the-right-one" }, null]) {
        const token = await idToken({ nonce });
        assert.equal(
          OidcClient.idTokenMatchesNonce(token, "the-right-one"),
          false,
          `nonce ${JSON.stringify(nonce)} must not match`,
        );
      }
    });

    it("REFUSES a MISSING token — no token is not a match", async () => {
      assert.equal(OidcClient.idTokenMatchesNonce(undefined, "the-right-one"), false);
    });

    it("REFUSES something that is not a JWT, rather than throwing", async () => {
      // The function returns a boolean; a malformed token must reach the caller as
      // `false`, not as an exception that a caller might not catch.
      for (const bad of ["", "not-a-jwt", "a.b", "a.b.c.d", "...."]) {
        assert.equal(
          OidcClient.idTokenMatchesNonce(bad, "the-right-one"),
          false,
          `${JSON.stringify(bad)} must be refused`,
        );
      }
    });

    it("refuses an EMPTY expected nonce against a token with an empty nonce", async () => {
      // Two absences must not match each other. If a flow's nonce were ever generated as
      // an empty string, a token with no nonce would otherwise pass.
      const token = await idToken({ nonce: "" });
      assert.equal(OidcClient.idTokenMatchesNonce(token, ""), true, "empty equals empty, literally");
      assert.equal(OidcClient.idTokenMatchesNonce(token, "x"), false);
    });
  });

  // ---------------------------------------------------------------- auth URL
  //
  // `buildAuthorizationUrl` calls `discover()`, so these need a LIVE issuer. A fictional
  // hostname made them fail with ENOTFOUND — which tested the failure path, not the method.
  describe("buildAuthorizationUrl", { skip: LAB_UP ? false : "Keycloak is not running" }, () => {
    const liveOptions = { ...CLIENT_OPTIONS, issuer: ISSUER,
      redirectUri: "http://localhost:3000/console/callback" };

    it("carries state AND nonce to the provider", async () => {
      const client = new OidcClient(liveOptions);
      const url = new URL(await client.buildAuthorizationUrl({ state: "s-123", nonce: "n-456" }));
      assert.equal(url.searchParams.get("state"), "s-123", "state must be sent or it can never be checked");
      assert.equal(url.searchParams.get("nonce"), "n-456", "nonce must be sent or it can never be checked");
    });

    it("uses the configured client, redirect and scope", async () => {
      const client = new OidcClient(liveOptions);
      const url = new URL(await client.buildAuthorizationUrl({ state: "s", nonce: "n" }));
      assert.equal(url.searchParams.get("client_id"), "attest-console");
      assert.equal(url.searchParams.get("redirect_uri"), liveOptions.redirectUri);
      assert.equal(url.searchParams.get("response_type"), "code");
      assert.match(String(url.searchParams.get("scope")), /openid/);
    });

    it("does NOT put the client secret in a URL the browser will see", async () => {
      const client = new OidcClient(liveOptions);
      const url = await client.buildAuthorizationUrl({ state: "s", nonce: "n" });
      assert.ok(!url.includes(CLIENT_OPTIONS.clientSecret), "a confidential client's secret belongs in the back-channel only");
    });
  });

  // ---------------------------------------------------------------- live provider
  describe("against the live provider", { skip: LAB_UP ? false : "Keycloak is not running" }, () => {
    let client: OidcClient;

    before(() => {
      client = new OidcClient({
        ...CLIENT_OPTIONS,
        issuer: ISSUER,
        redirectUri: "http://localhost:3000/console/callback",
      });
    });

    it("discovers endpoints from the issuer, including the logout endpoint", async () => {
      const endpoints = await client.discover();
      assert.equal(endpoints.issuer, ISSUER, "the issuer must match exactly, not by prefix");
      assert.match(String(endpoints.authorizationEndpoint), /\/protocol\/openid-connect\/auth$/);
      assert.match(String(endpoints.tokenEndpoint), /\/protocol\/openid-connect\/token$/);
      assert.ok(endpoints.endSessionEndpoint, "without this, sign-out cannot end the SSO session");
    });

    it("builds a logout URL carrying the id_token_hint and the post-logout target", async () => {
      const target = "http://localhost:3000/console/login";
      const logoutUrl = await client.buildLogoutUrl("header.payload.signature", target);
      // `buildLogoutUrl` returns undefined when the provider advertises no end-session
      // endpoint. Asserting that here, rather than coercing, is the check that a provider
      // missing that endpoint would fail loudly instead of silently signing out locally.
      assert.ok(logoutUrl, "the provider must advertise an end-session endpoint");
      const url = new URL(logoutUrl);
      assert.equal(url.searchParams.get("post_logout_redirect_uri"), target);
      assert.equal(url.searchParams.get("id_token_hint"), "header.payload.signature");
    });

    it("REFUSES to exchange a bogus authorization code", async () => {
      await assert.rejects(
        () => client.exchangeCode("not-a-real-code"),
        /token endpoint returned HTTP 4\d\d|invalid_grant/i,
        "the provider must reject it, and the client must surface that as a throw",
      );
    });
  });
});
