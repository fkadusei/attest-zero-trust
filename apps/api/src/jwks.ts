import { createRemoteJWKSet, type JWTVerifyGetKey } from "jose";

/**
 * A cached view of the identity provider's signing keys.
 *
 * Two properties matter here, and neither is about correctness of the signature.
 *
 * 1. **Keys rotate.** Keycloak replaces signing keys, and a verifier that caches
 *    forever will start refusing valid tokens the moment it does. `jose`'s
 *    `createRemoteJWKSet` handles this: on an unknown `kid` it re-fetches, with a
 *    built-in cooldown so that an attacker cannot force a fetch per request.
 *
 * 2. **The fetch must never become a lever.** The JWKS URL is the one outbound
 *    call the verifier makes, and every unauthenticated request can trigger it.
 *    `jose` rate-limits refetches (default 30s cooldown) and coalesces them, which
 *    is why this uses the library rather than a hand-rolled cache. A hand-rolled
 *    "if unknown kid, refetch" is a denial-of-service amplifier pointed at the
 *    identity provider — the one service that must stay up for anyone to log in.
 *
 * The URL is pinned at construction. It must be the issuer's own JWKS endpoint,
 * never anything derived from the token being verified: a token that can nominate
 * its own key source is a token that can nominate its own keys.
 */
export interface JwksOptions {
  /** Seconds `jose` waits before re-fetching for an unrecognised `kid`. */
  readonly cooldownDurationSec?: number;
  /** Seconds a fetched key set is considered fresh without revalidation. */
  readonly cacheMaxAgeSec?: number;
  /** Milliseconds before an in-flight fetch is abandoned. */
  readonly timeoutMs?: number;
}

export class JwksSource {
  readonly #getKey: JWTVerifyGetKey;
  readonly #url: string;

  constructor(url: string, options: JwksOptions = {}) {
    this.#url = url;
    this.#getKey = createRemoteJWKSet(new URL(url), {
      cooldownDuration: (options.cooldownDurationSec ?? 30) * 1000,
      cacheMaxAge: (options.cacheMaxAgeSec ?? 600) * 1000,
      timeoutDuration: options.timeoutMs ?? 5000,
    });
  }

  get url(): string {
    return this.#url;
  }

  /**
   * The resolver `jose` calls during verification.
   *
   * Failures here propagate to the verifier, which converts them into an opaque
   * rejection. They must never be swallowed into a "no key, therefore no problem"
   * path.
   */
  get resolver(): JWTVerifyGetKey {
    return this.#getKey;
  }
}
