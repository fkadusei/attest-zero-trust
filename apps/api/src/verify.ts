import { decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";
import type { JwksSource } from "./jwks.ts";
import { TokenVerificationError } from "./errors.ts";

/**
 * Verifying an access token, and being strict about it.
 *
 * Every choice below exists because the loose version is exploitable:
 *
 * - **Algorithms are named explicitly.** `jwtVerify` is given the allowed set and
 *   never consults the token's own `alg` to decide what to accept. A verifier that
 *   honours the header's `alg` will accept `none`, or accept an HMAC signature
 *   computed with the public key as the secret. Both are real, both are old, both
 *   still ship.
 *
 * - **`typ` is checked — in the PAYLOAD, not the header.** Keycloak puts a type in
 *   both places, and they disagree:
 *
 *     | | header `typ` | payload `typ` |
 *     |---|---|---|
 *     | access token | `"JWT"` | `"Bearer"` |
 *     | ID token     | `"JWT"` | `"ID"` |
 *
 *   The header is `"JWT"` for every token, so **checking the header cannot tell an
 *   access token from an ID token.** Only the payload claim distinguishes them, and
 *   it can be trusted only AFTER the signature verifies. Checking the header would
 *   have looked like protection while providing none — this was measured against
 *   the live lab, after an early version of this file assumed `"Bearer"` in the
 *   header and was wrong.
 *
 * - **Issuer and audience are compared exactly**, not by prefix or substring. A
 *   `startsWith` check on an issuer is a bypass waiting for a clever hostname.
 *
 * - **The tenant is read only from verified claims**, in `requireTenant` below. It
 *   is never accepted from a header, a path segment, a query parameter or a body
 *   field. That is ADR-006, and this module is where it is enforced rather than
 *   merely intended.
 */

export interface VerifyOptions {
  readonly jwks: JwksSource;
  /** Exact issuer. Must equal the `iss` claim character for character. */
  readonly issuer: string;
  /** The API's own client id — the `azp`/`aud` the token must be issued for. */
  readonly audience: string;
  /** Leeway for clock skew between this service and the identity provider. */
  readonly clockToleranceSec?: number;
  /** Token type to require. Defaults to Keycloak's access-token type. */
  readonly expectedTyp?: string;
  /** Allowed signature algorithms. Defaults to the asymmetric set Keycloak uses. */
  readonly algorithms?: readonly string[];
}

export interface VerifiedToken {
  readonly subject: string;
  readonly issuer: string;
  readonly audience: readonly string[];
  readonly expiresAt: number;
  /**
   * RFC 9449 `cnf.jkt` — the SHA-256 thumbprint of the DPoP key the token is
   * bound to. Its PRESENCE is a promise the token makes: "I am only valid with a
   * proof from this key."
   *
   * Its presence is deliberately surfaced rather than enforced here, because
   * enforcement requires the request. A token carrying `cnf` that is accepted
   * without a proof is a sender-constrained token being treated as a bearer
   * token — a silent downgrade, and exactly the failure ADR-004 exists to
   * prevent. The request layer MUST refuse a `cnf`-bearing token without a
   * matching proof; `assertNotDowngraded` below is that guard.
   */
  readonly dpopThumbprint?: string;
  readonly claims: JWTPayload;
}

const DEFAULT_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"];

/** Maps a `jose` failure onto our internal reason. Never leaks to a client. */
function classify(error: unknown): TokenVerificationError {
  const code = (error as { code?: string } | undefined)?.code;
  switch (code) {
    case "ERR_JWT_EXPIRED":
      return new TokenVerificationError("expired");
    case "ERR_JWT_CLAIM_VALIDATION_FAILED": {
      const claim = (error as { claim?: string }).claim;
      if (claim === "iss") return new TokenVerificationError("wrong_issuer");
      if (claim === "aud") return new TokenVerificationError("wrong_audience");
      if (claim === "nbf") return new TokenVerificationError("not_yet_valid");
      return new TokenVerificationError("malformed", `claim ${claim ?? "unknown"}`);
    }
    case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED":
      return new TokenVerificationError("bad_signature");
    case "ERR_JWKS_NO_MATCHING_KEY":
    case "ERR_JWKS_MULTIPLE_MATCHING_KEYS":
      return new TokenVerificationError("unknown_key");
    case "ERR_JWKS_TIMEOUT":
    case "ERR_JWKS_INVALID":
      return new TokenVerificationError("jwks_unavailable");
    case "ERR_JOSE_ALG_NOT_ALLOWED":
      return new TokenVerificationError("unsupported_algorithm");
    default:
      return new TokenVerificationError("malformed", code ?? "unclassified");
  }
}

/**
 * Verify an access token. Throws `TokenVerificationError` on ANY doubt.
 *
 * There is no boolean return and no "warn" branch: a token is either fully
 * verified or the call throws. Ambiguous outcomes cannot be treated as success by
 * accident if they cannot be represented.
 */
export async function verifyAccessToken(token: string, options: VerifyOptions): Promise<VerifiedToken> {
  const algorithms = [...(options.algorithms ?? DEFAULT_ALGORITHMS)];
  // The ACCESS-TOKEN marker. This is the payload `typ` claim, not the header's —
  // see the note at the top of this file. Default is Keycloak's access-token value.
  const expectedTyp = options.expectedTyp ?? "Bearer";

  // Inspect the header BEFORE verifying, but only to reject cheaply. Nothing here
  // is trusted: `algorithms` is what constrains verification.
  let headerAlg: string;
  let headerTyp: string | undefined;
  try {
    const header = decodeProtectedHeader(token);
    if (typeof header.alg !== "string") throw new TokenVerificationError("malformed", "no alg");
    headerAlg = header.alg;
    headerTyp = typeof header.typ === "string" ? header.typ : undefined;
  } catch (error) {
    throw error instanceof TokenVerificationError
      ? error
      : new TokenVerificationError("malformed", "undecodable header");
  }

  if (!algorithms.includes(headerAlg)) {
    throw new TokenVerificationError("unsupported_algorithm", headerAlg);
  }
  // The JOSE media type. This is a malformed-input guard and NOTHING MORE: it is
  // "JWT" for access tokens and ID tokens alike, so it must never be the check that
  // decides whether a token authorises a request.
  if (headerTyp !== undefined && headerTyp !== "JWT") {
    throw new TokenVerificationError("wrong_token_type", `header typ ${headerTyp}`);
  }

  let payload: JWTPayload;
  try {
    const result = await jwtVerify(token, options.jwks.resolver, {
      issuer: options.issuer,
      audience: options.audience,
      algorithms,
      clockTolerance: options.clockToleranceSec ?? 5,
    });
    payload = result.payload;
  } catch (error) {
    throw classify(error);
  }

  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new TokenVerificationError("malformed", "no sub");
  }

  // NOW the payload can be trusted — the signature has verified. This is the check
  // that actually separates an access token from an ID token, and it cannot be done
  // any earlier: an unverified claim proves nothing.
  const payloadTyp = payload["typ"];
  if (typeof payloadTyp !== "string" || payloadTyp !== expectedTyp) {
    throw new TokenVerificationError("wrong_token_type", `payload typ ${String(payloadTyp)}`);
  }
  if (typeof payload.exp !== "number") {
    throw new TokenVerificationError("malformed", "no exp");
  }

  const audience = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];

  // `cnf.jkt` — see VerifiedToken.dpopThumbprint. Read from VERIFIED claims only.
  const cnf = payload["cnf"];
  const jkt =
    cnf && typeof cnf === "object" && !Array.isArray(cnf) && typeof (cnf as Record<string, unknown>)["jkt"] === "string"
      ? ((cnf as Record<string, unknown>)["jkt"] as string)
      : undefined;

  const verified: VerifiedToken = {
    subject: payload.sub,
    issuer: typeof payload.iss === "string" ? payload.iss : options.issuer,
    audience,
    expiresAt: payload.exp,
    claims: payload,
    ...(jkt !== undefined ? { dpopThumbprint: jkt } : {}),
  };
  return verified;
}

/**
 * ADR-006, in code: the tenant comes from the verified token and nowhere else.
 *
 * Callers pass the claim name their realm is configured to issue. There is no
 * fallback to a header, no default tenant, and no "trusted" bypass — a missing
 * claim is a hard failure, because a defaulted tenant is how one customer's
 * request ends up reading another customer's data.
 */
export function requireTenant(token: VerifiedToken, claimName: string): string {
  const value = token.claims[claimName];
  if (typeof value !== "string" || value.length === 0) {
    throw new TokenVerificationError("missing_tenant", claimName);
  }
  return value;
}

/**
 * Refuse a sender-constrained token that arrived without its proof.
 *
 * The dangerous case is not a token with a bad proof — that fails signature
 * verification anyway. It is a GOOD token whose binding is ignored, silently
 * degrading DPoP to bearer. This makes that downgrade impossible to perform by
 * forgetting to call something.
 */
export function assertNotDowngraded(token: VerifiedToken, proofPresented: boolean): void {
  if (token.dpopThumbprint !== undefined && !proofPresented) {
    throw new TokenVerificationError(
      "malformed",
      "token is DPoP-bound (cnf.jkt present) but no proof was presented",
    );
  }
}
