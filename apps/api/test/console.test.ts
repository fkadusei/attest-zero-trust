/**
 * The admin console.
 *
 * The provider is stubbed — driving a real browser through a Keycloak redirect is
 * not something a unit test can do — but **every token is real**. The stub replaces
 * the redirect dance, not the verification: the console still calls the API over
 * HTTP with a genuinely signed token, so the policy under test is the real policy.
 *
 * That distinction matters. A test that stubbed the API too would prove the console
 * can render HTML and nothing about whether it respects authorization.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

import { buildServer } from "../src/server.ts";
import { loadConfig } from "../src/config.ts";
import { JwksSource } from "../src/jwks.ts";
import { systemClock } from "../src/ports/clock.ts";
import { InMemoryReplayCache } from "../src/ports/replay-cache.ts";
import { InMemoryEvidenceRepository } from "../src/ports/memory-repository.ts";
import { InMemoryObjectStorage } from "../src/ports/memory-object-storage.ts";
import { CedarPolicyDecisionPoint } from "../src/pdp-cedar.ts";
import { InMemorySessionStore } from "../src/console/session.ts";
import type { ConsoleOidc } from "../src/console/routes.ts";
import { API_CLIENT, ISSUER, JWKS_URI, ensureLabFixtures, getRealToken, isLabUp } from "./lab.ts";
import { readFileSync } from "node:fs";

const labUp = await isLabUp();
const BASE = "http://127.0.0.1:3100";

describe("the admin console", { skip: labUp ? false : "Keycloak is not running" }, () => {
  let app: Awaited<ReturnType<typeof buildServer>>;
  let sessions: InMemorySessionStore;
  let realToken: string;
  /** Set by the stub so a test can control what the provider returns. */
  let nextIdTokenNonce: string | undefined;
  let exchangeShouldFail = false;

  const oidc: ConsoleOidc = {
    async buildAuthorizationUrl(flow) {
      return `https://id.example.com/auth?state=${flow.state}&nonce=${flow.nonce}`;
    },
    async exchangeCode() {
      if (exchangeShouldFail) throw new Error("exchange failed");
      return {
        accessToken: realToken,
        idToken: makeIdToken(nextIdTokenNonce),
        expiresInSec: 300,
      };
    },
    async refresh() {
      return { accessToken: realToken, expiresInSec: 300 };
    },
    async buildLogoutUrl() {
      return "https://id.example.com/logout";
    },
    idTokenMatchesNonce(idToken, expectedNonce) {
      if (idToken === undefined) return false;
      // Decode, rather than searching the encoded string: a base64url payload never
      // contains the plaintext of its own contents, so a substring check silently
      // fails for every input and looks like a working refusal.
      try {
        const payload = JSON.parse(
          Buffer.from(idToken.split(".")[1] ?? "", "base64url").toString("utf8"),
        ) as { nonce?: unknown };
        return payload.nonce === expectedNonce;
      } catch {
        return false;
      }
    },
  };

  function makeIdToken(nonce: string | undefined): string {
    const payload = Buffer.from(JSON.stringify({ nonce, sub: "test" })).toString("base64url");
    return `header.${payload}.signature`;
  }

  before(async () => {
    await ensureLabFixtures();
    realToken = (await getRealToken()).token;

    const config = loadConfig({
      KEYCLOAK_ISSUER: ISSUER,
      API_AUDIENCE: API_CLIENT,
      PUBLIC_BASE_URL: BASE,
      TENANT_CLAIM: "tenant_id",
    });
    const policies = readFileSync(new URL("../policies/attest.cedar", import.meta.url), "utf8");
    sessions = new InMemorySessionStore();

    app = buildServer({
      config,
      jwks: new JwksSource(JWKS_URI, { cooldownDurationSec: 1 }),
      clock: systemClock,
      replayCache: new InMemoryReplayCache(),
      pdp: new CedarPolicyDecisionPoint({ policies }),
      evidence: new InMemoryEvidenceRepository(),
      artifacts: new InMemoryObjectStorage(),
      console: {
        sessions,
        oidc,
        apiBaseUrl: BASE,
        consoleBaseUrl: BASE,
      },
    });
    await app.ready();
    // The console reaches the API over HTTP — deliberately, so it cannot bypass the
    // policy — which means a stub cannot satisfy it. `inject` does not open a
    // socket, so the server is genuinely listening for these tests. That is the
    // point: the console is tested as a real client of a real API.
    await app.listen({ host: "127.0.0.1", port: 3100 });
  });

  after(async () => {
    await app?.close();
  });

  /** Drive login and return the session cookie. */
  async function signIn(): Promise<{ cookie: string; sessionId: string }> {
    const started = await app.inject({ method: "GET", url: "/console/login" });
    const flowCookie = started.cookies.find((c) => c.name === "attest_flow");
    assert.ok(flowCookie, "login must set a flow cookie");
    const flow = JSON.parse(flowCookie.value) as { state: string; nonce: string };

    nextIdTokenNonce = flow.nonce;
    const callback = await app.inject({
      method: "GET",
      url: `/console/callback?code=test-code&state=${encodeURIComponent(flow.state)}`,
      cookies: { attest_flow: flowCookie.value },
    });
    assert.equal(callback.statusCode, 302, callback.body);
    const sessionCookie = callback.cookies.find((c) => c.name === "attest_session");
    assert.ok(sessionCookie, "callback must set a session cookie");
    return { cookie: sessionCookie.value, sessionId: sessionCookie.value };
  }

  // ---------------------------------------------------------------- auth gate
  it("an unauthenticated visit redirects to sign-in", async () => {
    const res = await app.inject({ method: "GET", url: "/console" });
    assert.equal(res.statusCode, 302);
    assert.equal(res.headers["location"], "/console/login");
  });

  it("sign-in redirects to the provider WITH state and nonce", async () => {
    const res = await app.inject({ method: "GET", url: "/console/login" });
    assert.equal(res.statusCode, 302);
    const location = String(res.headers["location"]);
    assert.match(location, /state=/, "state is what protects the redirect");
    assert.match(location, /nonce=/, "nonce is what protects the id_token");
    // The flow cookie must be HttpOnly: a state readable by script is a state an
    // injected script can complete a flow with.
    const flowCookie = res.cookies.find((c) => c.name === "attest_flow");
    assert.equal(flowCookie?.httpOnly, true);
    assert.equal(flowCookie?.sameSite, "Lax");
  });

  // ---------------------------------------------------------------- flow integrity
  it("a callback with a WRONG state is refused", async () => {
    const started = await app.inject({ method: "GET", url: "/console/login" });
    const flowCookie = started.cookies.find((c) => c.name === "attest_flow")!;
    const res = await app.inject({
      method: "GET",
      url: "/console/callback?code=test-code&state=not-the-state",
      cookies: { attest_flow: flowCookie.value },
    });
    assert.equal(res.statusCode, 400, "login CSRF must be refused");
  });

  it("a callback with NO flow cookie is refused", async () => {
    const res = await app.inject({ method: "GET", url: "/console/callback?code=x&state=y" });
    assert.equal(res.statusCode, 400);
  });

  it("a callback with an ID TOKEN for a DIFFERENT nonce is refused", async () => {
    // The case `nonce` exists for: a valid ID token issued for another flow being
    // substituted into this one.
    const started = await app.inject({ method: "GET", url: "/console/login" });
    const flowCookie = started.cookies.find((c) => c.name === "attest_flow")!;
    const flow = JSON.parse(flowCookie.value) as { state: string };
    nextIdTokenNonce = "a-completely-different-nonce";

    const res = await app.inject({
      method: "GET",
      url: `/console/callback?code=test-code&state=${encodeURIComponent(flow.state)}`,
      cookies: { attest_flow: flowCookie.value },
    });
    assert.equal(res.statusCode, 400, "a substituted id_token must be refused");
  });

  it("a provider error is reported without echoing its description", async () => {
    const started = await app.inject({ method: "GET", url: "/console/login" });
    const flowCookie = started.cookies.find((c) => c.name === "attest_flow")!;
    const flow = JSON.parse(flowCookie.value) as { state: string };
    const res = await app.inject({
      method: "GET",
      url: `/console/callback?error=access_denied&error_description=SECRET-DETAIL&state=${encodeURIComponent(flow.state)}`,
      cookies: { attest_flow: flowCookie.value },
    });
    assert.equal(res.statusCode, 400);
    assert.ok(res.body.includes("access_denied"), "the error code is safe to show");
    assert.ok(!res.body.includes("SECRET-DETAIL"), "the description can echo parameters and must not be shown");
  });

  it("a failed token exchange does not create a session", async () => {
    const started = await app.inject({ method: "GET", url: "/console/login" });
    const flowCookie = started.cookies.find((c) => c.name === "attest_flow")!;
    const flow = JSON.parse(flowCookie.value) as { state: string; nonce: string };
    nextIdTokenNonce = flow.nonce;
    exchangeShouldFail = true;
    try {
      const res = await app.inject({
        method: "GET",
        url: `/console/callback?code=test-code&state=${encodeURIComponent(flow.state)}`,
        cookies: { attest_flow: flowCookie.value },
      });
      assert.equal(res.statusCode, 502);
      assert.ok(!res.cookies.some((c) => c.name === "attest_session"), "no session on a failed exchange");
    } finally {
      exchangeShouldFail = false;
    }
  });

  // ---------------------------------------------------------------- session
  it("a signed-in user sees their own evidence", async () => {
    const { cookie } = await signIn();
    const res = await app.inject({ method: "GET", url: "/console", cookies: { attest_session: cookie } });
    assert.equal(res.statusCode, 200, res.body);
    assert.ok(res.body.includes("Attest"), "the page should render");
  });

  it("the session cookie is HttpOnly, SameSite=Lax and scoped to /console", async () => {
    const started = await app.inject({ method: "GET", url: "/console/login" });
    const flowCookie = started.cookies.find((c) => c.name === "attest_flow")!;
    const flow = JSON.parse(flowCookie.value) as { state: string; nonce: string };
    nextIdTokenNonce = flow.nonce;
    const callback = await app.inject({
      method: "GET",
      url: `/console/callback?code=c&state=${encodeURIComponent(flow.state)}`,
      cookies: { attest_flow: flowCookie.value },
    });
    const session = callback.cookies.find((c) => c.name === "attest_session")!;
    assert.equal(session.httpOnly, true, "a script-readable session id is a session a script can use");
    assert.equal(session.sameSite, "Lax");
    assert.equal(session.path, "/console", "the session must not travel to the API");
  });

  it("the session id is not a token — it is opaque and random", async () => {
    const { cookie } = await signIn();
    assert.ok(!cookie.includes("."), "a session id must not be a JWT");
    assert.ok(cookie.length >= 40, `a session id must have real entropy, got ${cookie.length} chars`);
  });

  it("an unknown session id is treated as signed out", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/console",
      cookies: { attest_session: randomBytes(32).toString("base64url") },
    });
    assert.equal(res.statusCode, 302);
    assert.equal(res.headers["location"], "/console/login");
  });

  // ---------------------------------------------------------------- CSRF
  it("sign-out without a CSRF token does NOT end the session", async () => {
    const { cookie } = await signIn();
    const res = await app.inject({
      method: "POST",
      url: "/console/logout",
      cookies: { attest_session: cookie },
      payload: "csrf=wrong",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 302);
    // The session must still work. If it did not, an attacker could sign a user out
    // by luring them to a form — a nuisance, but the assertion is really that the
    // CSRF check is load-bearing.
    const after_ = await app.inject({ method: "GET", url: "/console", cookies: { attest_session: cookie } });
    assert.equal(after_.statusCode, 200, "a bad CSRF token must not end the session");
  });

  it("sign-out WITH the right CSRF token ends the session", async () => {
    const { cookie, sessionId } = await signIn();
    const session = await sessions.get(sessionId);
    assert.ok(session, "the session should exist before sign-out");

    const res = await app.inject({
      method: "POST",
      url: "/console/logout",
      cookies: { attest_session: cookie },
      payload: `csrf=${encodeURIComponent(session.csrfToken)}`,
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    assert.equal(res.statusCode, 302);
    assert.equal(await sessions.get(sessionId), undefined, "the session must be destroyed server-side");
  });

  it("the CSRF token is rendered into the page for the form to use", async () => {
    const { cookie, sessionId } = await signIn();
    const session = await sessions.get(sessionId);
    assert.ok(session, "the session should exist");
    const res = await app.inject({ method: "GET", url: "/console", cookies: { attest_session: cookie } });
    assert.ok(res.body.includes(session.csrfToken), "the sign-out form needs the token");
  });

  // ---------------------------------------------------------------- create (L8)
  /** Build a multipart body by hand, so no extra dependency is needed. */
  function multipartBody(fields: Record<string, string>, file?: { name: string; bytes: string }): {
    payload: Buffer;
    contentType: string;
  } {
    const boundary = `----attest${randomBytes(8).toString("hex")}`;
    const parts: Buffer[] = [];
    for (const [name, value] of Object.entries(fields)) {
      parts.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
    }
    if (file) {
      parts.push(
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${file.name}"\r\nContent-Type: text/plain\r\n\r\n`,
        ),
      );
      parts.push(Buffer.from(file.bytes));
      parts.push(Buffer.from("\r\n"));
    }
    parts.push(Buffer.from(`--${boundary}--\r\n`));
    return { payload: Buffer.concat(parts), contentType: `multipart/form-data; boundary=${boundary}` };
  }

  async function sessionFor(): Promise<{ cookie: string; csrf: string }> {
    const { cookie, sessionId } = await signIn();
    const session = await sessions.get(sessionId);
    assert.ok(session, "the session should exist");
    return { cookie, csrf: session.csrfToken };
  }

  it("the create form renders with a CSRF token and multipart encoding", async () => {
    const { cookie, csrf } = await sessionFor();
    const res = await app.inject({ method: "GET", url: "/console/evidence/new", cookies: { attest_session: cookie } });
    assert.equal(res.statusCode, 200);
    assert.ok(res.body.includes(csrf), "the form needs the CSRF token");
    assert.ok(
      res.body.includes("multipart/form-data"),
      "without enctype the browser drops the file silently and the form looks like it worked",
    );
  });

  it("creating evidence WITH a file stores both, and the digest comes from the bytes", async () => {
    const { cookie, csrf } = await sessionFor();
    const content = "quarterly access review export";
    const { payload, contentType } = multipartBody({ csrf, control: "SOC2-CC6.1" }, { name: "e.txt", bytes: content });

    const res = await app.inject({
      method: "POST",
      url: "/console/evidence",
      cookies: { attest_session: cookie },
      payload,
      headers: { "content-type": contentType },
    });
    assert.equal(res.statusCode, 302, res.body);
    const location = String(res.headers["location"]);
    assert.match(location, /^\/console\/evidence\/ev-/, `expected a redirect to the new record, got ${location}`);

    // Read it back through the API with the same token: the record must carry the
    // digest of the bytes that were actually stored.
    const id = decodeURIComponent(location.split("/").pop() ?? "");
    const detail = await app.inject({
      method: "GET",
      url: `/v1/evidence/${encodeURIComponent(id)}`,
      headers: { authorization: `Bearer ${realToken}` },
    });
    assert.equal(detail.statusCode, 200, detail.body);
    const expected = createHash("sha256").update(content).digest("hex");
    assert.equal(detail.json().sha256, expected, "the digest must be of the STORED bytes");
  });

  it("the stored artifact round-trips through the API", async () => {
    const { cookie, csrf } = await sessionFor();
    const content = "content that must survive the round trip";
    const { payload, contentType } = multipartBody({ csrf, control: "ISO-A.5.15" }, { name: "a.txt", bytes: content });
    const res = await app.inject({
      method: "POST",
      url: "/console/evidence",
      cookies: { attest_session: cookie },
      payload,
      headers: { "content-type": contentType },
    });
    const id = decodeURIComponent(String(res.headers["location"]).split("/").pop() ?? "");

    const download = await app.inject({
      method: "GET",
      url: `/v1/evidence/${encodeURIComponent(id)}/content`,
      headers: { authorization: `Bearer ${realToken}` },
    });
    assert.equal(download.statusCode, 200, download.body);
    assert.equal(download.body, content);
  });

  it("creating WITHOUT a file still creates the record", async () => {
    // A record with no artifact yet is a legitimate state. Requiring a file would
    // force operators to attach something meaningless to proceed.
    const { cookie, csrf } = await sessionFor();
    const { payload, contentType } = multipartBody({ csrf, control: "SOC2-CC7.2" });
    const res = await app.inject({
      method: "POST",
      url: "/console/evidence",
      cookies: { attest_session: cookie },
      payload,
      headers: { "content-type": contentType },
    });
    assert.equal(res.statusCode, 302, res.body);
  });

  it("creating WITHOUT a valid CSRF token is refused", async () => {
    const { cookie } = await sessionFor();
    const { payload, contentType } = multipartBody({ csrf: "wrong", control: "SOC2-CC6.1" });
    const res = await app.inject({
      method: "POST",
      url: "/console/evidence",
      cookies: { attest_session: cookie },
      payload,
      headers: { "content-type": contentType },
    });
    assert.equal(res.statusCode, 403, "a form post without a valid CSRF token must be refused");
  });

  it("creating with an EMPTY control is refused", async () => {
    const { cookie, csrf } = await sessionFor();
    const { payload, contentType } = multipartBody({ csrf, control: "   " });
    const res = await app.inject({
      method: "POST",
      url: "/console/evidence",
      cookies: { attest_session: cookie },
      payload,
      headers: { "content-type": contentType },
    });
    assert.equal(res.statusCode, 400);
  });

  it("an empty file part does NOT create an empty artifact", async () => {
    // A browser sends an empty file part when nothing was chosen. Storing zero bytes
    // would produce evidence attesting to nothing.
    const { cookie, csrf } = await sessionFor();
    const { payload, contentType } = multipartBody({ csrf, control: "SOC2-CC6.1" }, { name: "empty.txt", bytes: "" });
    const res = await app.inject({
      method: "POST",
      url: "/console/evidence",
      cookies: { attest_session: cookie },
      payload,
      headers: { "content-type": contentType },
    });
    assert.equal(res.statusCode, 302, res.body);
    const id = decodeURIComponent(String(res.headers["location"]).split("/").pop() ?? "");
    const content = await app.inject({
      method: "GET",
      url: `/v1/evidence/${encodeURIComponent(id)}/content`,
      headers: { authorization: `Bearer ${realToken}` },
    });
    // No artifact was stored, so the zero-byte read must NOT succeed as evidence.
    assert.notEqual(content.statusCode, 200, "an empty upload must not become an artifact");
  });

  // ---------------------------------------------------------------- escaping
  it("HTML in API data is ESCAPED, not rendered", async () => {
    // The console renders strings that came from the database. An evidence control
    // containing markup must not become markup in an operator's browser.
    const { cookie } = await signIn();
    const res = await app.inject({
      method: "GET",
      url: "/console/evidence/%3Cscript%3Ealert(1)%3C%2Fscript%3E",
      cookies: { attest_session: cookie },
    });
    assert.ok(!res.body.includes("<script>alert"), "server data must be escaped before rendering");
  });
});
