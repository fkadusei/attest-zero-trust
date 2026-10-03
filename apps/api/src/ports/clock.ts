/**
 * Time, as a dependency.
 *
 * Not ceremony. The API makes time-dependent decisions — token expiry now, session
 * freshness next (S5c), and eventually credential age — and a suite that cannot
 * control the clock can only test those at the two extremes of "obviously valid"
 * and "long expired". The interesting cases sit in between, and they are where the
 * freshness work already found a real vulnerability.
 *
 * It is also the smallest possible demonstration of the rule in ADR-015: the domain
 * declares what it needs, and something else provides it.
 */
export interface Clock {
  /** Current time. Milliseconds since the epoch, to match `Date.now()`. */
  nowMs(): number;
  /** Current time in whole seconds, which is the unit JWT claims use. */
  nowSeconds(): number;
}

export const systemClock: Clock = {
  nowMs: () => Date.now(),
  nowSeconds: () => Math.floor(Date.now() / 1000),
};

/** A clock frozen at a chosen instant. For tests that need the middle of a window. */
export function frozenClock(atMs: number): Clock {
  return {
    nowMs: () => atMs,
    nowSeconds: () => Math.floor(atMs / 1000),
  };
}
