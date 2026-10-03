/**
 * The policy decision point — PDP in the NIST SP 800-207 sense.
 *
 * This is the interface that keeps ADR-005 alive while making it portable. The
 * policies are written in **Cedar**, which is an open language; the *engine* is
 * swappable. In-process `cedar-wasm` is the default and runs anywhere, including a
 * laptop and CI. Amazon Verified Permissions is an optional adapter that evaluates
 * **the same policy text** — no rewrite, because the language is the portable part
 * and the service is not.
 *
 * Two properties are load-bearing and must survive every adapter:
 *
 * 1. **Fail closed.** A decision is `Allow` or `Deny`. There is no third answer and
 *    no undefined. An engine that cannot reach a decision, times out, or errors
 *    must produce `Deny` — a PDP that fails open converts an outage into a breach.
 *    Adapters enforce this by throwing, and the caller treats a throw as a denial.
 *
 * 2. **The tenant comes from the verified token, never from the request.** Every
 *    field here is derived from a token that has already passed `verifyAccessToken`.
 *    A `PolicyRequest` built from a header, a path segment or a body field is a
 *    cross-tenant read waiting to happen, and ADR-006 exists because of it.
 */

/** A tenant identity that can only have come from a verified token. */
export interface TenantScope {
  readonly tenantId: string;
}

export interface PolicyPrincipal {
  /** Stable subject from the token's `sub`. */
  readonly id: string;
  /** Principal kind, e.g. `User` or `ServiceAccount`. */
  readonly type: string;
  /** Roles carried by the verified token. Empty when the token carries none. */
  readonly roles: readonly string[];
  /** The tenant this principal belongs to, from the verified token. */
  readonly tenant: TenantScope;
}

export interface PolicyResource {
  readonly type: string;
  readonly id: string;
  /** The tenant that OWNS the resource. Compared against the principal's. */
  readonly tenant: TenantScope;
}

/**
 * A context value, in engine-neutral terms.
 *
 * Deliberately NOT the policy engine's own type. The port must stay usable by any
 * engine — in-process Cedar, Amazon Verified Permissions, or something else — and
 * importing one vendor's value type into it would make the boundary decorative.
 * This is the JSON-shaped subset every engine accepts.
 */
export type AttributeValue =
  | string
  | number
  | boolean
  | null
  | readonly AttributeValue[]
  | { readonly [key: string]: AttributeValue };

export interface PolicyRequest {
  readonly principal: PolicyPrincipal;
  readonly action: string;
  readonly resource: PolicyResource;
  /**
   * Extra attributes the policy may consult — device posture, request freshness,
   * authentication method. Values must still originate from verified sources.
   */
  readonly context?: Readonly<Record<string, AttributeValue>>;
}

export type PolicyEffect = "Allow" | "Deny";

export interface PolicyDecision {
  readonly effect: PolicyEffect;
  /**
   * Which policies produced the decision. Retained for audit: "denied" without
   * "by what" is not an explanation anyone can act on, and this system produces
   * compliance evidence for a living.
   */
  readonly determiningPolicies: readonly string[];
}

export interface PolicyDecisionPoint {
  /**
   * Decide a request. Implementations MUST NOT fail open: any inability to decide
   * is a `Deny`, expressed either as a returned Deny or by throwing.
   */
  decide(request: PolicyRequest): Promise<PolicyDecision>;
}

/** The only denial shape the rest of the system should construct for a hard stop. */
export const DENY: PolicyDecision = Object.freeze({ effect: "Deny", determiningPolicies: [] });
