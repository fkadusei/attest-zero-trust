/**
 * Single-use claim tracking, as a port.
 *
 * DPoP proofs carry a `jti` — a unique identifier for that one proof. RFC 9449
 * requires a server to remember `jti` values it has accepted, for as long as the
 * proof's freshness window allows, and to refuse a repeat. Without that, a proof
 * that is still within its `iat` window can be replayed verbatim: the signature is
 * valid, the `htm`/`htu` match, the `ath` matches, and the attacker wins simply by
 * copying a header they observed.
 *
 * That makes this small interface load-bearing for the whole DPoP story, and it is
 * the one part of proof verification that CANNOT be done statelessly.
 *
 * It is a port because the choice of store is exactly the kind of decision ADR-015
 * keeps out of the domain: an in-memory map is correct for one process and wrong
 * for three, Redis is right for a fleet and wrong for a laptop, and DynamoDB
 * exists only on AWS. The contract is identical in all three cases, so the domain
 * never learns which one it has.
 */

export interface ReplayCache {
  /**
   * Record `jti` as used, and report whether this was the FIRST use.
   *
   * Returns `true` when the value had not been seen — the request may proceed.
   * Returns `false` when it has — the request is a replay and must be refused.
   *
   * The operation MUST be atomic. A check-then-set across two calls is a race in
   * which two concurrent replays both observe "not seen" and both proceed, which
   * is the exact scenario an attacker with a captured proof would attempt.
   *
   * @param jti      the proof's `jti`
   * @param ttlMs    how long to remember it — at least the freshness window
   */
  consume(jti: string, ttlMs: number): Promise<boolean>;
}

/**
 * In-memory replay cache for a single process.
 *
 * Correct for the local lab and for CI, and **explicitly not correct for a
 * multi-instance deployment**: each replica keeps its own map, so a proof replayed
 * to a different replica is seen as fresh. Swapping this for a shared store is a
 * deployment decision, not a code change, which is the point of the port.
 */
export class InMemoryReplayCache implements ReplayCache {
  readonly #seen = new Map<string, number>();

  async consume(jti: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    // Opportunistic sweep. A cache that only grows is a memory leak with a
    // security-shaped excuse; a sweep on each call is O(n) but n is bounded by
    // the freshness window, and this implementation is for single-process use.
    for (const [key, expiry] of this.#seen) {
      if (expiry <= now) this.#seen.delete(key);
    }
    if (this.#seen.has(jti)) return false;
    this.#seen.set(jti, now + ttlMs);
    return true;
  }

  /** Test helper: how many entries are currently remembered. */
  get size(): number {
    return this.#seen.size;
  }
}
