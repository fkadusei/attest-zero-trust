import {
  isAuthorized,
  checkParsePolicySet,
  type CedarValueJson,
  type Context,
  type Entities,
  type EntityJson,
  type EntityUidJson,
} from "@cedar-policy/cedar-wasm/nodejs";

import type {
  AttributeValue,
  PolicyDecision,
  PolicyDecisionPoint,
  PolicyRequest,
} from "./ports/policy.ts";

/**
 * The Cedar policy decision point.
 *
 * Implements the `PolicyDecisionPoint` port with Cedar evaluated in-process by
 * WebAssembly. This is the PORTABLE default under ADR-015: it needs no cloud, runs
 * in CI and on a laptop, and evaluates the **same policy text** that would be sent
 * to Amazon Verified Permissions. The service is swappable; the language is not
 * rewritten.
 *
 * THREE WAYS A DECISION CAN FAIL, AND WHY ALL THREE DENY
 *
 * 1. **Cedar errors.** `isAuthorized` returns a non-success result — a malformed
 *    request, an entity that cannot be constructed. Deny.
 *
 * 2. **Evaluation errors inside the diagnostics.** This is the subtle one and the
 *    reason this adapter does not simply read `decision`. Cedar can return
 *    `allow` **with a non-empty `errors` array** when a DIFFERENT policy failed to
 *    evaluate. That policy might have been a `forbid`. Treating the allow as
 *    authoritative would mean an unevaluatable rule silently stops applying —
 *    exactly the failure a rule exists to prevent. **Any error denies.**
 *
 * 3. **No permit matched.** Cedar's own default is deny, and it is the reason the
 *    policies are written as narrow permits.
 *
 * The adapter never throws for a policy outcome: a decision is always returned, so
 * the caller has one thing to handle rather than two. A programming error — an
 * unreadable policy file at startup — is different, and fails loudly there.
 */
export interface CedarPdpOptions {
  /** The Cedar policy text. Loaded once at startup, never per request. */
  readonly policies: string;
}

export class CedarPolicyDecisionPoint implements PolicyDecisionPoint {
  readonly #policies: string;

  constructor(options: CedarPdpOptions) {
    // Validate ONCE, at construction. A policy syntax error must surface as a
    // startup failure, not as a stream of denials that look like an authorization
    // problem. Failing closed is correct; failing closed SILENTLY for every request
    // because of a typo is an outage.
    const parsed = checkParsePolicySet({ staticPolicies: options.policies });
    if (parsed.type !== "success") {
      throw new Error(
        `the Cedar policy set does not parse: ${JSON.stringify(parsed.errors).slice(0, 400)}`,
      );
    }
    this.#policies = options.policies;
  }

  async decide(request: PolicyRequest): Promise<PolicyDecision> {
    // Building the entities can fail — an unrepresentable context value, for
    // instance. That is a Deny, not an exception: the caller must have exactly one
    // thing to handle, and "the PDP threw" must never be mistaken for "proceed".
    let entities: Entities;
    let context: Context;
    try {
      entities = entitiesFor(request);
      context = toCedarContext(request.context);
    } catch {
      return { effect: "Deny", determiningPolicies: ["cedar:unrepresentable-request"] };
    }

    const result = isAuthorized({
      principal: { type: request.principal.type, id: request.principal.id },
      action: { type: "Action", id: request.action },
      resource: { type: request.resource.type, id: request.resource.id },
      context,
      policies: { staticPolicies: this.#policies },
      entities,
    });

    if (result.type !== "success") {
      // Cedar could not answer. It might have been a forbid that failed to
      // evaluate, so this is a Deny — never an Allow, and never an exception the
      // caller might handle as "proceed".
      return { effect: "Deny", determiningPolicies: ["cedar:evaluation-failure"] };
    }

    const { decision, diagnostics } = result.response;

    if (diagnostics.errors.length > 0) {
      // See (2) above. An `allow` alongside errors is not trustworthy: the errors
      // are policies that did not run, and one of them may have been a forbid.
      return {
        effect: "Deny",
        determiningPolicies: ["cedar:evaluation-error"],
      };
    }

    return {
      effect: decision === "allow" ? "Allow" : "Deny",
      // Retained for audit. "Denied" without "by what" is not an explanation anyone
      // can act on, and this product exists to produce evidence.
      determiningPolicies: diagnostics.reason,
    };
  }
}

/**
 * Build the entity set from the request.
 *
 * Every attribute here is derived from a VERIFIED source — the token and the
 * resource record. Nothing comes from a request header, a query parameter or a
 * body field, because an entity built from caller-supplied values would let the
 * caller choose the very attributes the tenant boundary compares.
 */
/**
 * Convert portable context values into Cedar values.
 *
 * A value that cannot be represented is REFUSED rather than dropped. Silently
 * omitting an attribute would let a policy that consults it fall through to a
 * different decision — and a dropped attribute on a `forbid` is a hole. The throw
 * becomes a Deny in `decide`, which is the correct direction to fail.
 */
function toCedarContext(context: Readonly<Record<string, AttributeValue>> | undefined): Context {
  if (context === undefined) return {};
  const out: Record<string, CedarValueJson> = {};
  for (const [key, value] of Object.entries(context)) {
    out[key] = toCedarValue(value);
  }
  return out;
}

function toCedarValue(value: AttributeValue): CedarValueJson {
  if (value === null) return null;
  switch (typeof value) {
    case "string":
    case "number":
    case "boolean":
      return value;
    case "object":
      if (Array.isArray(value)) return value.map(toCedarValue);
      {
        const nested: Record<string, CedarValueJson> = {};
        for (const [k, v] of Object.entries(value)) nested[k] = toCedarValue(v);
        return nested;
      }
    default:
      throw new Error(`context value for is not representable: ${typeof value}`);
  }
}

function entitiesFor(request: PolicyRequest): Entities {
  // The resource entity is built ONCE. A Tenant resource briefly produced two
  // entities with the same uid — the generic one and a Tenant-specific one — and
  // Cedar silently resolved the ambiguity in whichever direction it preferred, so
  // `ListEvidence` denied its own tenant. Building a single entity per uid removes
  // the question rather than answering it.
  const isTenant = request.resource.type === "Tenant";

  const resourceAttrs: Record<string, CedarValueJson> = {
    // For a Tenant entity its own id IS the tenant it represents, so the same
    // attribute name works for every resource type and the policies do not need a
    // second comparison.
    tenant: request.resource.tenant.tenantId,
  };
  if (isTenant) {
    resourceAttrs["id"] = request.resource.id;
  }

  return [
    {
      uid: { type: request.principal.type, id: request.principal.id },
      attrs: {
        tenant: request.principal.tenant.tenantId,
        // Spread, not the readonly array itself: Cedar's value type is a mutable
        // array, and handing it a readonly view would be a type error rather than a
        // real constraint. The copy also stops a caller mutating the roles after
        // the decision.
        roles: [...request.principal.roles],
      },
      parents: [],
    },
    {
      uid: { type: request.resource.type, id: request.resource.id },
      attrs: resourceAttrs,
      parents: [],
    },
  ];
}

/**
 * Load the policy text. Called once at startup.
 *
 * Kept separate so that tests can supply policy text directly and so that the
 * deployed policies are always a file in the repository rather than a string
 * assembled at runtime — the artifact that gets reviewed is the artifact that runs.
 */
export const DEFAULT_POLICY_PATH = new URL("../policies/attest.cedar", import.meta.url);
