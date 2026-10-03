/**
 * A synthetic OpenID issuer for claims the real provider will not produce.
 *
 * The suite found this gap by mutation testing: deleting the `sub` check from
 * `verify.ts` left the tests GREEN. Keycloak always issues a `sub`, so no
 * real-token test can exercise its absence — and a check with no test is a check
 * that can be deleted without anyone noticing.
 *
 * This runs a tiny HTTP server that publishes a JWKS for a key we generate here,
 * and signs tokens with whatever claims a test needs. It is deliberately NOT a
 * replacement for testing against real Keycloak: the real-provider tests remain
 * the ones that prove we agree with Keycloak. This covers only the shapes Keycloak
 * cannot be asked to produce.
 */
import { createServer, type Server } from "node:http";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";

export interface SyntheticIssuer {
  readonly issuer: string;
  readonly audience: string;
  readonly jwksUri: string;
  /** Sign a token with entirely arbitrary claims. `type` is the JOSE header typ. */
  sign(
    claims: Record<string, unknown>,
    options?: { type?: string; algorithm?: string; dropClaims?: string[] },
  ): Promise<string>;
  close(): Promise<void>;
}

export async function startSyntheticIssuer(): Promise<SyntheticIssuer> {
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const kid = "synthetic-key-1";
  const jwk = await exportJWK(publicKey);
  const jwks = { keys: [{ ...jwk, kid, alg: "RS256", use: "sig" }] };

  const server: Server = createServer((req, res) => {
    if (req.url?.endsWith("/certs")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(jwks));
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  const base = `http://127.0.0.1:${address.port}`;
  const issuer = `${base}/realms/synthetic`;
  const audience = "attest-api";

  return {
    issuer,
    audience,
    jwksUri: `${issuer}/protocol/openid-connect/certs`,
    async sign(claims, options = {}) {
      const now = Math.floor(Date.now() / 1000);
      const payload: Record<string, unknown> = {
        iss: issuer,
        aud: audience,
        iat: now,
        exp: now + 300,
        sub: "synthetic-subject",
        typ: "Bearer",
        ...claims,
      };
      for (const claim of options.dropClaims ?? []) delete payload[claim];
      return new SignJWT(payload)
        .setProtectedHeader({ alg: options.algorithm ?? "RS256", typ: options.type ?? "JWT", kid })
        .sign(privateKey as CryptoKey);
    },
    async close() {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}
