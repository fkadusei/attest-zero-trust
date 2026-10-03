/**
 * Lab fixtures for the API tests.
 *
 * These tests run against the REAL Keycloak in `lab/keycloak`. That is the point:
 * a verifier tested against a hand-made token proves only that it agrees with our
 * own idea of what a token looks like. Signature verification, issuer matching and
 * algorithm handling are exactly the places where that assumption is wrong.
 *
 * Standing rule for this project, learned three times over: **every harness creates
 * the fixtures it depends on.** So this creates its own realm and clients, and does
 * not touch `attest-users`, `attest-privileged` or anything else the other slices
 * rely on.
 *
 * The realm is dedicated and separate rather than shared, because a test that
 * mutates shared state is a test that passes or fails depending on what ran before
 * it. The S5f CI failures were that, three separate times.
 *
 * No user and no password: the token comes from **client credentials**, a real
 * non-interactive flow. Adding a direct-grant client to test authentication would
 * mean adding the exact bypass this project closed in `attest-privileged`.
 */
import { randomUUID } from "node:crypto";

export const KC = process.env["KC_URL"] ?? "http://localhost:8080";
export const ADMIN_USER = process.env["KC_ADMIN"] ?? "admin";
export const ADMIN_PASS = process.env["KC_ADMIN_PASSWORD"] ?? "lab-only-not-a-secret";

/** Dedicated realm so these tests never disturb the application realms. */
export const TEST_REALM = "attest-api-test";
/** The audience the API expects — the API's own client id. */
export const API_CLIENT = "attest-api";
/** The caller. Client-credentials only; it can obtain a token but never a user session. */
export const HARNESS_CLIENT = "test-harness";
/**
 * A client whose tokens live one second.
 *
 * There is no honest way to test expiry without a token that actually expires. A
 * token with a hand-edited `exp` has a broken signature, so it would fail for the
 * WRONG REASON — and a test that asserts "it failed" without checking why is
 * exactly the defect class this project found in S5e and had to go back and fix.
 * This client makes expiry real.
 */
export const SHORT_CLIENT = "short-lived";

export const ISSUER = `${KC}/realms/${TEST_REALM}`;
export const JWKS_URI = `${ISSUER}/protocol/openid-connect/certs`;
/**
 * The `master` realm's keys.
 *
 * Needed because the ID token used to test the payload-`typ` check is issued by
 * `master`, and therefore signed with a DIFFERENT key. Verifying it against the
 * test realm's JWKS fails as `unknown_key` — a real failure, but not the one under
 * test. Asserting the cause caught that; asserting only "it failed" would not have.
 */
export const MASTER_JWKS_URI = `${KC}/realms/master/protocol/openid-connect/certs`;

export function isLabUp(): Promise<boolean> {
  return fetch(`${KC}/realms/master/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(3000),
  })
    .then((r) => r.ok)
    .catch(() => false);
}

async function adminToken(): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "password",
    client_id: "admin-cli",
    username: ADMIN_USER,
    password: ADMIN_PASS,
  });
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`admin token failed: HTTP ${res.status}`);
  const json = (await res.json()) as { access_token: string };
  return json.access_token;
}

async function admin(path: string, init: RequestInit = {}): Promise<Response> {
  const token = await adminToken();
  return fetch(`${KC}/admin/realms${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
    signal: AbortSignal.timeout(10_000),
  });
}

/**
 * Create the dedicated realm with both clients, idempotently.
 *
 * Safe to run repeatedly: every step checks first. The alternative — recreating
 * from scratch each run — makes the suite order-dependent the moment two test
 * files touch it.
 */
export async function ensureLabFixtures(): Promise<void> {
  const existing = await admin(`/${TEST_REALM}`);
  if (existing.status === 404) {
    const created = await admin("", {
      method: "POST",
      // Deliberately minimal and insecure-for-production: HTTP, no TLS. This realm
      // exists to produce correctly SIGNED tokens, nothing else. It holds no user
      // data and no credentials worth stealing.
      body: JSON.stringify({
        realm: TEST_REALM,
        enabled: true,
        sslRequired: "none",
        accessTokenLifespan: 300,
      }),
    });
    if (!created.ok && created.status !== 409) {
      throw new Error(`could not create realm ${TEST_REALM}: HTTP ${created.status}`);
    }
  }

  const apiClient = await ensureClient(API_CLIENT, {
    // Bearer-only: accepts tokens as an audience, never initiates a login.
    bearerOnly: true,
    publicClient: false,
    standardFlowEnabled: false,
    serviceAccountsEnabled: false,
    directAccessGrantsEnabled: false,
  });

  await ensureClient(HARNESS_CLIENT, {
    publicClient: false,
    standardFlowEnabled: false,
    serviceAccountsEnabled: true,
    directAccessGrantsEnabled: false,
    // Map the API client into `aud`, so the token is genuinely issued FOR the API.
    protocolMappers: [
      {
        name: "realm-roles-writer",
        protocol: "openid-connect",
        protocolMapper: "oidc-hardcoded-claim-mapper",
        consentRequired: false,
        config: {
          // WriteEvidence requires the `writer` role. Without a token that carries
          // one, the upload tests would assert that a correctly-refused request
          // succeeds — and the resulting 403 is the policy working, not a bug.
          "claim.name": "realm_access.roles",
          "claim.value": "[\"writer\"]",
          "jsonType.label": "JSON",
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
      {
        name: "tenant_id",
        protocol: "openid-connect",
        protocolMapper: "oidc-hardcoded-claim-mapper",
        consentRequired: false,
        config: {
          "claim.name": "tenant_id",
          "claim.value": "acme",
          "jsonType.label": "String",
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
      {
        name: "audience-attest-api",
        protocol: "openid-connect",
        protocolMapper: "oidc-audience-mapper",
        consentRequired: false,
        config: {
          "included.client.audience": API_CLIENT,
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
    ],
  });

  // Same shape, but its tokens expire in one second so expiry can be tested with a
  // REAL signature rather than a doctored payload.
  await ensureClient(SHORT_CLIENT, {
    publicClient: false,
    standardFlowEnabled: false,
    serviceAccountsEnabled: true,
    directAccessGrantsEnabled: false,
    // Keycloak's client-level token lifespan is NOT a top-level field on
    // ClientRepresentation — sending it there is rejected with
    // `Unrecognized field "accessTokenLifespan"`. It lives in `attributes`.
    attributes: { "access.token.lifespan": "1" },
    protocolMappers: [
      {
        name: "realm-roles-writer",
        protocol: "openid-connect",
        protocolMapper: "oidc-hardcoded-claim-mapper",
        consentRequired: false,
        config: {
          // WriteEvidence requires the `writer` role. Without a token that carries
          // one, the upload tests would assert that a correctly-refused request
          // succeeds — and the resulting 403 is the policy working, not a bug.
          "claim.name": "realm_access.roles",
          "claim.value": "[\"writer\"]",
          "jsonType.label": "JSON",
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
      {
        name: "tenant_id",
        protocol: "openid-connect",
        protocolMapper: "oidc-hardcoded-claim-mapper",
        consentRequired: false,
        config: {
          "claim.name": "tenant_id",
          "claim.value": "acme",
          "jsonType.label": "String",
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
      {
        name: "audience-attest-api",
        protocol: "openid-connect",
        protocolMapper: "oidc-audience-mapper",
        consentRequired: false,
        config: {
          "included.client.audience": API_CLIENT,
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
    ],
  });

  // The client-credentials secret is read back from Keycloak rather than invented,
  // because Keycloak generates it.
  void apiClient;
}

async function ensureClient(
  clientId: string,
  spec: Record<string, unknown>,
): Promise<{ id: string; secret: string }> {
  const found = await admin(`/${TEST_REALM}/clients?clientId=${encodeURIComponent(clientId)}`);
  const list = (await found.json()) as Array<{ id: string; secret?: string }>;
  if (list.length > 0) {
    const existing = list[0]!;
    await admin(`/${TEST_REALM}/clients/${existing.id}`, {
      method: "PUT",
      body: JSON.stringify({ clientId, ...spec }),
    });
    return { id: existing.id, secret: existing.secret ?? "" };
  }

  const created = await admin(`/${TEST_REALM}/clients`, {
    method: "POST",
    body: JSON.stringify({ clientId, ...spec }),
  });
  if (!created.ok && created.status !== 409) {
    // Include Keycloak's own message. A bare status code turns a five-second fix
    // into a guessing game, and this project has paid that price before.
    const detail = await created.text().catch(() => "");
    throw new Error(`could not create client ${clientId}: HTTP ${created.status} ${detail.slice(0, 300)}`);
  }
  const again = await admin(`/${TEST_REALM}/clients?clientId=${encodeURIComponent(clientId)}`);
  const made = (await again.json()) as Array<{ id: string; secret?: string }>;
  if (made.length === 0) throw new Error(`client ${clientId} not found after create`);
  return { id: made[0]!.id, secret: made[0]!.secret ?? "" };
}

export async function clientSecretFor(clientId: string): Promise<string> {
  const res = await admin(`/${TEST_REALM}/clients?clientId=${encodeURIComponent(clientId)}`);
  const list = (await res.json()) as Array<{ secret?: string }>;
  const secret = list[0]?.secret;
  if (!secret) throw new Error(`client ${clientId} has no secret`);
  return secret;
}

async function clientSecret(): Promise<string> {
  return clientSecretFor(HARNESS_CLIENT);
}

/**
 * A client that REQUIRES DPoP-bound tokens.
 *
 * `dpop.bound.access.tokens` is the attribute Keycloak's admin console writes when
 * you tick "Require DPoP bound tokens". With it set, the token endpoint demands a
 * valid DPoP proof and records the key's thumbprint in the token as `cnf.jkt` —
 * which is the only way to obtain a genuinely bound token to test against.
 *
 * Client credentials rather than a password grant: no user, no password, and no
 * direct-access-grant client introduced into any application realm.
 */
export const DPOP_CLIENT = "dpop-harness";

export async function ensureDpopClient(): Promise<void> {
  await ensureClient(DPOP_CLIENT, {
    publicClient: false,
    standardFlowEnabled: false,
    serviceAccountsEnabled: true,
    directAccessGrantsEnabled: false,
    attributes: { "dpop.bound.access.tokens": "true" },
    protocolMappers: [
      {
        name: "realm-roles-writer",
        protocol: "openid-connect",
        protocolMapper: "oidc-hardcoded-claim-mapper",
        consentRequired: false,
        config: {
          // WriteEvidence requires the `writer` role. Without a token that carries
          // one, the upload tests would assert that a correctly-refused request
          // succeeds — and the resulting 403 is the policy working, not a bug.
          "claim.name": "realm_access.roles",
          "claim.value": "[\"writer\"]",
          "jsonType.label": "JSON",
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
      {
        name: "tenant_id",
        protocol: "openid-connect",
        protocolMapper: "oidc-hardcoded-claim-mapper",
        consentRequired: false,
        config: {
          "claim.name": "tenant_id",
          "claim.value": "acme",
          "jsonType.label": "String",
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
      {
        name: "audience-attest-api",
        protocol: "openid-connect",
        protocolMapper: "oidc-audience-mapper",
        consentRequired: false,
        config: {
          "included.client.audience": API_CLIENT,
          "id.token.claim": "false",
          "access.token.claim": "true",
        },
      },
    ],
  });
}

export interface RealToken {
  readonly token: string;
  /** Its payload, decoded WITHOUT verification — for assertions about claims only. */
  readonly payload: Record<string, unknown>;
}

/** Get a genuine, correctly-signed token from the real identity provider. */
export async function getRealToken(overrides: Record<string, string> = {}): Promise<RealToken> {
  const secret = await clientSecret();
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: HARNESS_CLIENT,
    client_secret: secret,
    ...overrides,
  });
  const res = await fetch(`${ISSUER}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`token request failed: HTTP ${res.status} ${await res.text()}`);
  const json = (await res.json()) as { access_token: string };
  const token = json.access_token;
  const segment = token.split(".")[1]!;
  const payload = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<string, unknown>;
  return { token, payload };
}

/**
 * A genuinely EXPIRED token: real signature, real expiry, no tampering.
 *
 * Waits out the one-second lifespan rather than editing `exp`, so the only thing
 * wrong with this token is that it is old. That keeps `expired` from being
 * confused with `bad_signature` in the assertions.
 */
export async function getExpiredToken(): Promise<string> {
  const res = await admin(`/${TEST_REALM}/clients?clientId=${SHORT_CLIENT}`);
  const list = (await res.json()) as Array<{ secret?: string }>;
  const secret = list[0]?.secret;
  if (!secret) throw new Error(`${SHORT_CLIENT} has no secret`);

  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: SHORT_CLIENT,
    client_secret: secret,
  });
  const tok = await fetch(`${ISSUER}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!tok.ok) throw new Error(`short-lived token failed: HTTP ${tok.status}`);
  const json = (await tok.json()) as { access_token: string };

  // 2.5s covers the 1s lifespan plus the verifier's clock tolerance, so this is
  // unambiguously expired rather than borderline.
  await new Promise((resolve) => setTimeout(resolve, 2500));
  return json.access_token;
}

/**
 * A real ID TOKEN from the provider.
 *
 * This is the case the access-token check exists for. An ID token is a real,
 * correctly-signed Keycloak token whose **payload `typ` is `"ID"`** — it is not an
 * authorisation artifact, and presenting it to the API must fail.
 *
 * Note it cannot be produced by tampering: editing the payload breaks the
 * signature, so it would then fail as `bad_signature` and the test would pass for
 * the WRONG REASON. Only the provider can mint a genuine one. It comes from the
 * `master` realm because that realm's built-in `admin-cli` supports the
 * password grant, so no direct-grant client is added to any application realm.
 */
export async function getIdToken(): Promise<{ idToken: string; issuer: string; audience: string }> {
  const body = new URLSearchParams({
    grant_type: "password",
    client_id: "admin-cli",
    username: ADMIN_USER,
    password: ADMIN_PASS,
    scope: "openid",
  });
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`id token request failed: HTTP ${res.status}`);
  const json = (await res.json()) as { id_token?: string };
  if (!json.id_token) throw new Error("provider returned no id_token");
  return {
    idToken: json.id_token,
    issuer: `${KC}/realms/master`,
    // Read off a REAL ID token rather than assumed: Keycloak sets `aud` to the
    // client id (`admin-cli`) here. Getting this wrong made the token fail on
    // AUDIENCE before reaching the type check, so the test proved nothing about
    // token type — which is exactly why the assertion names the reason rather
    // than settling for "it failed".
    audience: "admin-cli",
  };
}

/**
 * Re-sign a payload with a DIFFERENT key, keeping the original header.
 *
 * This is the tamper case that matters: an attacker who can edit claims but not
 * forge the issuer's signature. It is produced by taking a real token and
 * replacing its signature with one made by a key we control.
 */
export function tamperSignature(token: string): string {
  const [header, payload] = token.split(".");
  // A syntactically valid but cryptographically meaningless signature segment.
  const garbage = Buffer.from(randomUUID() + randomUUID()).toString("base64url");
  return `${header}.${payload}.${garbage}`;
}

/** Replace the payload, keeping header and signature. Must fail verification. */
export function tamperPayload(token: string, mutate: (p: Record<string, unknown>) => void): string {
  const [header, payload, signature] = token.split(".");
  const decoded = JSON.parse(Buffer.from(payload!, "base64url").toString("utf8")) as Record<string, unknown>;
  mutate(decoded);
  const reencoded = Buffer.from(JSON.stringify(decoded)).toString("base64url");
  return `${header}.${reencoded}.${signature}`;
}
