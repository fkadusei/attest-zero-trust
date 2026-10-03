import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { randomUUID } from "node:crypto";

import { API_CLIENT, ISSUER, TEST_REALM, ensureDpopClient, clientSecretFor } from "./lab.ts";

/**
 * A DPoP key pair and the proofs it produces — the client half of RFC 9449.
 *
 * This mirrors what a browser does: generate a non-extractable key, publish only
 * the public half inside each proof, and never transmit the private half anywhere.
 * In the browser it lives in IndexedDB and the platform refuses to export it; here
 * it is a `CryptoKey` we simply never serialise.
 *
 * The tests need to *mint* proofs as well as verify them, and they need to mint
 * BROKEN ones deliberately. That is the whole point: a verifier tested only against
 * correct proofs proves nothing about what it rejects.
 */
export interface DpopKey {
  /** The public JWK, exactly as it appears in the `jwk` proof header. */
  readonly jwk: JWK;
  /** RFC 7638 thumbprint — the value Keycloak records as `cnf.jkt`. */
  readonly thumbprint: string;
  /** Build a proof. Every field is overridable so tests can break one at a time. */
  proof(options: {
    method: string;
    uri: string;
    accessToken?: string;
    nonce?: string;
    jti?: string;
    issuedAt?: number;
    /** Replace the embedded key with a different one — for the wrong-key case. */
    embedJwk?: JWK;
    /** Omit `ath` entirely. */
    omitAth?: boolean;
    /** Omit `jti` entirely. */
    omitJti?: boolean;
    /** Include private members in the embedded JWK. */
    includePrivateMembers?: boolean;
  }): Promise<string>;
}

export async function createDpopKey(): Promise<DpopKey> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(publicKey);
  const thumbprint = await calculateJwkThumbprint(jwk, "sha256");

  return {
    jwk,
    thumbprint,
    async proof(options) {
      const now = Math.floor(Date.now() / 1000);
      const payload: Record<string, unknown> = {
        jti: options.omitJti ? undefined : (options.jti ?? randomUUID()),
        htm: options.method,
        htu: options.uri,
        iat: options.issuedAt ?? now,
      };
      if (options.nonce !== undefined) payload["nonce"] = options.nonce;
      if (!options.omitAth && options.accessToken !== undefined) {
        const { createHash } = await import("node:crypto");
        payload["ath"] = createHash("sha256")
          .update(options.accessToken)
          .digest("base64url");
      }
      // Undefined values must not appear as explicit nulls in the payload.
      for (const key of Object.keys(payload)) {
        if (payload[key] === undefined) delete payload[key];
      }

      let embedded: Record<string, unknown> = { ...(options.embedJwk ?? jwk) };
      if (options.includePrivateMembers) {
        // A private member that is syntactically plausible. Its value is
        // irrelevant — the verifier must refuse on the member's PRESENCE.
        embedded = { ...embedded, d: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
      }

      return new SignJWT(payload)
        .setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: embedded })
        .sign(privateKey);
    },
  };
}

/**
 * Obtain a genuinely DPoP-BOUND access token from the real provider.
 *
 * Client credentials, not a password grant: no user, no password, and no
 * direct-access-grant client added to any application realm. Keycloak verifies the
 * proof at the token endpoint and writes the key's thumbprint into the token as
 * `cnf.jkt`.
 *
 * A nonce challenge is answered if the provider issues one. S1 observed that
 * Keycloak requires a nonce on resource requests; whether it does here is measured
 * rather than assumed, so both paths are handled.
 */
export async function getBoundToken(
  key: DpopKey,
  clientId: string,
  audienceClientId: string = API_CLIENT,
): Promise<{ token: string; payload: Record<string, unknown> }> {
  const secret = await clientSecretFor(clientId);
  const tokenUrl = `${ISSUER}/protocol/openid-connect/token`;
  void audienceClientId;

  const request = async (dpop: string) => {
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: secret,
    });
    return fetch(tokenUrl, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        DPoP: dpop,
      },
      body,
      signal: AbortSignal.timeout(10_000),
    });
  };

  let res = await request(await key.proof({ method: "POST", uri: tokenUrl }));
  if (!res.ok && res.status === 400) {
    const nonce = res.headers.get("DPoP-Nonce") ?? res.headers.get("dpop-nonce");
    if (nonce) {
      res = await request(await key.proof({ method: "POST", uri: tokenUrl, nonce }));
    }
  }
  if (!res.ok) {
    throw new Error(
      `DPoP-bound token request failed: HTTP ${res.status} ${(await res.text()).slice(0, 200)}`,
    );
  }

  const json = (await res.json()) as { access_token: string };
  const segment = json.access_token.split(".")[1]!;
  const payload = JSON.parse(
    Buffer.from(segment, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
  return { token: json.access_token, payload };
}

/** Convenience: set up the DPoP client and return a bound token with its key. */
export async function setupBoundToken(): Promise<{
  key: DpopKey;
  token: string;
  payload: Record<string, unknown>;
  thumbprint: string;
}> {
  await ensureDpopClient();
  const key = await createDpopKey();
  const { token, payload } = await getBoundToken(key, DPOP_CLIENT);
  const cnf = payload["cnf"] as { jkt?: string } | undefined;
  if (!cnf?.jkt) throw new Error("provider issued a token with no cnf.jkt — not DPoP-bound");
  return { key, token, payload, thumbprint: cnf.jkt };
}

export const DPOP_CLIENT = "dpop-harness";
export const TEST_REALM_NAME = TEST_REALM;
