import { createHash } from "node:crypto";
import {
  base64url,
  calculateJwkThumbprint,
  compactVerify,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from "jose";

import { TokenVerificationError, type FailureReason } from "./errors.ts";
import type { Clock } from "./ports/clock.ts";
import type { ReplayCache } from "./ports/replay-cache.ts";

/**
 * DPoP proof verification — RFC 9449.
 *
 * L1 answers "was this token issued to us, for this API, and is it intact". That
 * is not enough. An access token is a bearer credential: whoever holds the bytes
 * can use them. DPoP changes that by binding the token to a key pair the client
 * generates and never transmits, so possession of the token alone is worthless.
 *
 * The binding is recorded in the token as `cnf.jkt` — the RFC 7638 thumbprint of
 * the client's public key. Every request must then carry a proof JWT signed by the
 * matching private key. This module verifies that proof.
 *
 * THE CHECKS, AND WHY EACH EXISTS
 *
 *   typ            must be `dpop+jwt`. Accepting any JWS lets a token-endpoint
 *                  artifact be replayed as a proof.
 *   alg            ASYMMETRIC ONLY. The proof embeds its own public key, so an
 *                  HMAC algorithm would let an attacker sign with that public key
 *                  as the shared secret and forge arbitrarily. `none` likewise.
 *   jwk            must be present, and must contain NO PRIVATE MEMBERS. A proof
 *                  carrying `d` is not something an honest client produces.
 *   signature      verified against the embedded key — and only THEN is any claim
 *                  inside trusted.
 *   htm            must equal the HTTP method.
 *   htu            must equal the request URI WITHOUT query and fragment, which is
 *                  what RFC 9449 specifies. Keycloak's observed behaviour matches.
 *   iat            within a narrow window. A proof is a one-shot artifact; a long
 *                  window is a long replay opportunity.
 *   ath            base64url(SHA-256(access token)). MANDATORY for a resource
 *                  request. Without it, a proof captured for one endpoint can be
 *                  re-pointed at another while the token stays the same.
 *   jti            consumed exactly once. The only stateful check, and the only
 *                  thing standing between a captured proof and a replay.
 *   thumbprint     the embedded key must BE the key the token is bound to. This
 *                  is the check that turns an arbitrary valid proof into a
 *                  specific credential.
 *
 * WHAT THIS MODULE DELIBERATELY DOES NOT DO
 *
 * It does not decide what the request URI is. The caller supplies it from trusted
 * configuration. Deriving it from `X-Forwarded-Proto` or `Host` would let the
 * attacker choose the value the proof is compared against, which makes every `htu`
 * check vacuous — a subtle way to have the check present and still fail open.
 */

/** Asymmetric algorithms only. `none` and `HS*` are absent by construction. */
const DEFAULT_ALGORITHMS = [
  "ES256",
  "ES384",
  "ES512",
  "PS256",
  "PS384",
  "PS512",
  "RS256",
  "RS384",
  "RS512",
  "EdDSA",
] as const;

/** JWK members that denote PRIVATE key material. Their presence is a red flag. */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"] as const;

export interface DpopVerifyOptions {
  /** The compact `DPoP` header value. */
  readonly proof: string;
  /** Expected HTTP method (`htm`). */
  readonly method: string;
  /**
   * The request URI as this service believes it to be, from TRUSTED configuration
   * — not from forwarded headers. Query and fragment are stripped before
   * comparison, per RFC 9449.
   */
  readonly uri: string;
  /** The access token this proof accompanies, for the `ath` binding. */
  readonly accessToken: string;
  /** `cnf.jkt` from the already-verified access token. */
  readonly expectedThumbprint: string;
  readonly clock: Clock;
  readonly replayCache: ReplayCache;
  /** Freshness window for `iat`, in seconds. Default 60. */
  readonly maxAgeSec?: number;
  /** Permitted forward clock skew, in seconds. Default 5. */
  readonly futureSkewSec?: number;
}

export interface VerifiedProof {
  readonly jti: string;
  /** Thumbprint of the key that signed the proof. Equals `cnf.jkt`. */
  readonly thumbprint: string;
  readonly issuedAt: number;
}

function sha256Base64Url(input: string): string {
  return base64url.encode(createHash("sha256").update(input).digest());
}

/**
 * Normalise a URI for `htu` comparison, discarding query and fragment.
 *
 * Returns undefined when the input does not parse. Comparison happens on the
 * normalised form so that a difference in default-port or host case cannot be used
 * to make two URIs that a server treats as identical look distinct.
 */
export function normalizeHtu(raw: string): string | undefined {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  const scheme = url.protocol.toLowerCase();
  const host = url.hostname.toLowerCase();
  const port = url.port === "" ? "" : `:${url.port}`;
  const path = url.pathname === "" ? "/" : url.pathname;
  return `${scheme}//${host}${port}${path}`;
}

function fail(reason: FailureReason, detail?: string): never {
  throw new TokenVerificationError(reason, detail);
}

/**
 * Verify a DPoP proof. Throws `TokenVerificationError` on ANY doubt.
 *
 * Like `verifyAccessToken`, there is no boolean return and no warning path: the
 * proof is either fully verified or the call throws.
 */
export async function verifyDpopProof(options: DpopVerifyOptions): Promise<VerifiedProof> {
  const maxAgeSec = options.maxAgeSec ?? 60;
  const futureSkewSec = options.futureSkewSec ?? 5;

  // ---------------------------------------------------------------- header
  let header: Record<string, unknown>;
  try {
    header = decodeProtectedHeader(options.proof) as Record<string, unknown>;
  } catch {
    fail("malformed", "undecodable DPoP proof header");
  }

  const typ = header["typ"];
  if (typ !== "dpop+jwt") {
    fail("wrong_token_type", `DPoP proof typ must be dpop+jwt, got ${String(typ)}`);
  }

  const alg = header["alg"];
  if (typeof alg !== "string" || !(DEFAULT_ALGORITHMS as readonly string[]).includes(alg)) {
    fail("unsupported_algorithm", `DPoP proof alg ${String(alg)}`);
  }

  const jwk = header["jwk"];
  if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk)) {
    fail("malformed", "DPoP proof has no jwk header");
  }
  const publicJwk = jwk as JWK & Record<string, unknown>;

  // A proof carrying private key material is not something an honest client
  // produces. Refusing it also denies an attacker any chance of persuading this
  // service to treat a private key as a public one.
  for (const member of PRIVATE_JWK_MEMBERS) {
    if (publicJwk[member] !== undefined) {
      fail("malformed", `DPoP proof jwk contains private member '${member}'`);
    }
  }

  // ---------------------------------------------------------------- signature
  // Verified with the EMBEDDED key, which is untrusted until the thumbprint check
  // below ties it to the token. Nothing inside the payload is read before this.
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(publicJwk, alg);
    const { payload: raw } = await compactVerify(options.proof, key, {
      algorithms: [...DEFAULT_ALGORITHMS],
    });
    payload = JSON.parse(new TextDecoder().decode(raw)) as Record<string, unknown>;
  } catch (error) {
    if (error instanceof TokenVerificationError) throw error;
    fail("bad_signature", "DPoP proof signature did not verify");
  }

  // ---------------------------------------------------------------- htm
  const htm = payload["htm"];
  if (typeof htm !== "string" || htm !== options.method) {
    fail("malformed", `DPoP htm mismatch: proof says ${String(htm)}, request is ${options.method}`);
  }

  // ---------------------------------------------------------------- htu
  const htu = payload["htu"];
  if (typeof htu !== "string") fail("malformed", "DPoP proof has no htu");

  // RFC 9449: htu MUST NOT carry a query or fragment. A proof that includes one is
  // malformed — silently stripping it would paper over a non-conforming client and
  // hide an attempt to make the comparison do something it does not.
  let htuUrl: URL;
  try {
    htuUrl = new URL(htu);
  } catch {
    fail("malformed", "DPoP htu is not a valid URI");
  }
  if (htuUrl.search !== "" || htuUrl.hash !== "") {
    fail("malformed", "DPoP htu must not contain a query or fragment");
  }

  const normalisedHtu = normalizeHtu(htu);
  const normalisedRequest = normalizeHtu(options.uri);
  if (normalisedRequest === undefined) {
    fail("malformed", `expected request URI is not a valid URI: ${options.uri}`);
  }
  if (normalisedHtu !== normalisedRequest) {
    fail("malformed", `DPoP htu mismatch: proof says ${normalisedHtu}, request is ${normalisedRequest}`);
  }

  // ---------------------------------------------------------------- iat
  const iat = payload["iat"];
  if (typeof iat !== "number" || !Number.isFinite(iat)) {
    fail("malformed", "DPoP proof has no iat");
  }
  const now = options.clock.nowSeconds();
  if (iat > now + futureSkewSec) {
    fail("not_yet_valid", `DPoP iat is ${iat - now}s in the future`);
  }
  if (now - iat > maxAgeSec) {
    fail("expired", `DPoP iat is ${now - iat}s old, limit is ${maxAgeSec}s`);
  }

  // ---------------------------------------------------------------- ath
  // MANDATORY on a resource request (RFC 9449 section 7.1). Without it a proof
  // captured for one endpoint can be re-aimed at another with the same token.
  const ath = payload["ath"];
  if (typeof ath !== "string") {
    fail("malformed", "DPoP proof is missing the ath claim required for a resource request");
  }
  const expectedAth = sha256Base64Url(options.accessToken);
  // Not a constant-time comparison, deliberately: both values are derived from
  // public material (the token travels in the Authorization header, in the clear
  // over TLS) so there is no secret for timing to leak.
  if (ath !== expectedAth) {
    fail("bad_signature", "DPoP ath does not match the presented access token");
  }

  // ---------------------------------------------------------------- binding
  // The check that makes this proof a credential rather than merely a valid JWS.
  let thumbprint: string;
  try {
    thumbprint = await calculateJwkThumbprint(publicJwk, "sha256");
  } catch {
    fail("malformed", "could not compute a thumbprint for the DPoP jwk");
  }
  if (thumbprint !== options.expectedThumbprint) {
    fail("bad_signature", "DPoP proof key is not the key the access token is bound to");
  }

  // ---------------------------------------------------------------- replay
  // LAST, and only after everything else has passed. Consuming earlier would let
  // a malformed proof burn a `jti` that a legitimate request might need.
  const jti = payload["jti"];
  if (typeof jti !== "string" || jti.length === 0) {
    fail("malformed", "DPoP proof has no jti");
  }
  // Remember for the full freshness window plus skew: past that the proof is
  // refused on `iat` anyway, so nothing further would be gained.
  const consumed = await options.replayCache.consume(jti, (maxAgeSec + futureSkewSec) * 1000);
  if (!consumed) {
    fail("bad_signature", `DPoP proof jti has already been used: ${jti}`);
  }

  return { jti, thumbprint, issuedAt: iat };
}
