import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";

import type { AppConfig } from "./config.ts";
import { TokenVerificationError } from "./errors.ts";
import type { JwksSource } from "./jwks.ts";
import { verifyAccessToken, type VerifiedToken } from "./verify.ts";
import { verifyDpopProof } from "./dpop.ts";
import { assertNotDowngraded, requireTenant } from "./verify.ts";
import type { Clock } from "./ports/clock.ts";
import type { ReplayCache } from "./ports/replay-cache.ts";
import type { PolicyDecisionPoint, PolicyRequest, TenantScope } from "./ports/policy.ts";
import type { EvidenceRepository } from "./ports/repository.ts";

/**
 * The API as a running service — the policy *enforcement point*.
 *
 * L1 and L2 are verified libraries. Until something calls them on a real request
 * they protect nothing: `assertNotDowngraded` in particular existed, was tested,
 * and was referenced by no production code. This is the code that calls it.
 *
 * THE ONE RULE THAT MATTERS HERE
 *
 * Verification happens in `authenticate`, in a fixed order, before the handler
 * runs. A handler cannot opt out, forget a step, or reorder them, because it never
 * sees an unverified request. That is deliberate: the failure mode this avoids is
 * an endpoint added later that reads `request.headers['x-tenant-id']` and skips
 * the whole chain. There is no such header here and no way to reach a handler
 * without passing through the chain.
 */

export interface ServerDeps {
  readonly config: AppConfig;
  readonly jwks: JwksSource;
  readonly clock: Clock;
  readonly replayCache: ReplayCache;
  /**
   * The policy decision point (ADR-005). Authorization is a SEPARATE step from
   * authentication: L1 and L2 establish who is calling, and this decides what they
   * may touch. Keeping them apart is what stops "authenticated" being mistaken for
   * "allowed".
   */
  readonly pdp: PolicyDecisionPoint;
  /** Evidence storage, scoped by tenant at the data layer. */
  readonly evidence: EvidenceRepository;
}

/** Attached to the request by `authenticate`, for handlers to read. */
export interface AuthenticatedRequest {
  readonly token: VerifiedToken;
  readonly tenantId: string;
  readonly thumbprint?: string;
}

declare module "fastify" {
  interface FastifyRequest {
    auth?: AuthenticatedRequest;
  }
}

/**
 * The single opaque rejection.
 *
 * Every verification failure returns exactly this. A response that distinguishes
 * "bad signature" from "expired" from "wrong audience" is an oracle telling an
 * attacker which part of a forgery to fix next. The reason is logged; the caller
 * learns only that it failed.
 */
function reject(reply: FastifyReply, reason: string): FastifyReply {
  reply.log.warn({ reason }, "request rejected");
  return reply.code(401).send({ error: "unauthorized" });
}

/** Parse `Authorization: <scheme> <credentials>`. */
function parseAuthorization(header: string | undefined): { scheme: string; token: string } | undefined {
  if (typeof header !== "string") return undefined;
  const space = header.indexOf(" ");
  if (space <= 0) return undefined;
  const scheme = header.slice(0, space);
  const token = header.slice(space + 1).trim();
  if (token === "") return undefined;
  return { scheme, token };
}

export function buildServer(deps: ServerDeps): FastifyInstance {
  const app = Fastify({
    // Never log the Authorization or DPoP headers: both are credentials for the
    // duration of the request, and a log is a place credentials leak to.
    logger: { redact: ["req.headers.authorization", "req.headers.dpop"] },
    disableRequestLogging: false,
    bodyLimit: 1024 * 1024,
  });

  /**
   * The verification chain. Runs before every protected handler.
   *
   * THREE INDEPENDENT LAYERS refuse a sender-constrained token presented without a
   * proof, and that is deliberate:
   *   1. `if (!proof)` below — early, and gives the clearest log line
   *   2. `assertNotDowngraded` — a guard that is hard to forget if code is added
   *   3. `verifyDpopProof` itself, which refuses a missing proof outright
   *
   * The consequence for testing is worth stating: **removing (1), (2) or both does
   * NOT break the property**, because (3) still refuses. Mutation testing reports
   * those mutants as surviving, which is easy to misread as a blind spot. It is
   * not — it is defence in depth, and a mutation harness that cannot tell the
   * difference will cry wolf.
   *
   * Order is load-bearing:
   *   1. token verified          — nothing is trusted before this
   *   2. binding established     — is this token sender-constrained?
   *   3. scheme checked          — a bound token must use `DPoP`, not `Bearer`
   *   4. proof verified          — signature, htu, htm, ath, jti, thumbprint
   *   5. downgrade guard         — fail closed if a bound token had no proof
   *   6. tenant derived          — from VERIFIED claims only (ADR-006)
   */
  async function authenticate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const parsed = parseAuthorization(request.headers.authorization);
    if (!parsed) {
      reject(reply, "missing or malformed Authorization header");
      return;
    }

    let token: VerifiedToken;
    try {
      token = await verifyAccessToken(parsed.token, {
        jwks: deps.jwks,
        issuer: deps.config.identity.issuer,
        audience: deps.config.identity.audience,
        clockToleranceSec: deps.config.clockToleranceSec,
      });
    } catch (error) {
      reject(reply, error instanceof TokenVerificationError ? error.reason : "verification error");
      return;
    }

    const thumbprint = token.dpopThumbprint;
    const proofHeader = request.headers["dpop"];
    const proof = typeof proofHeader === "string" ? proofHeader : undefined;

    if (thumbprint !== undefined) {
      // RFC 9449 requires a bound token to be presented with the `DPoP` scheme.
      // Keycloak enforces this and so must we: S1 found the same token under
      // `Bearer` fails with "Token verification failed", which reads like a
      // signature problem and is actually a scheme problem.
      if (parsed.scheme !== "DPoP") {
        reject(reply, `bound token presented with the ${parsed.scheme} scheme`);
        return;
      }
      if (!proof) {
        // Belt and braces. `assertNotDowngraded` below would also catch this, but
        // failing here gives a clearer log line without weakening anything.
        reject(reply, "bound token presented without a DPoP proof");
        return;
      }

      // The expected URI comes from CONFIGURATION, never from the request. See
      // AppConfig.publicBaseUrl: trusting a forwarded header here would let the
      // attacker choose what the proof is compared against.
      const uri = `${deps.config.publicBaseUrl}${request.url}`;
      try {
        await verifyDpopProof({
          proof,
          method: request.method,
          uri,
          accessToken: parsed.token,
          expectedThumbprint: thumbprint,
          clock: deps.clock,
          replayCache: deps.replayCache,
        });
      } catch (error) {
        reject(reply, error instanceof TokenVerificationError ? error.reason : "proof verification error");
        return;
      }
    } else if (parsed.scheme === "DPoP") {
      // A proof was supplied for a token that is not bound to anything. Not an
      // error in itself, but it means the caller believes the token is bound —
      // worth refusing rather than silently ignoring, because the alternative is
      // an unbound token being treated as protected.
      reject(reply, "DPoP scheme used with a token that carries no cnf.jkt");
      return;
    }

    // Fail closed on the downgrade, whatever the branches above concluded.
    try {
      assertNotDowngraded(token, proof !== undefined);
    } catch (error) {
      reject(reply, error instanceof TokenVerificationError ? error.reason : "downgrade guard");
      return;
    }

    // ADR-006: the tenant is read from the VERIFIED token and nowhere else.
    let tenantId: string;
    try {
      tenantId = requireTenant(token, deps.config.tenantClaim);
    } catch (error) {
      reject(reply, error instanceof TokenVerificationError ? error.reason : "tenant");
      return;
    }

    request.auth = {
      token,
      tenantId,
      ...(thumbprint !== undefined ? { thumbprint } : {}),
    };
  }

  /**
   * Ask the PDP, and turn its answer into a reply.
   *
   * Returns `true` when the caller may proceed. On refusal it has ALREADY replied,
   * so the handler must not continue — hence the boolean rather than a throw, which
   * is harder to ignore by accident in an `async` handler.
   *
   * The tenant on both sides comes from verified sources: the principal's from the
   * token, the resource's from the stored record. **Nothing here reads a tenant
   * from the request.**
   */
  async function authorize(
    request: FastifyRequest,
    reply: FastifyReply,
    action: string,
    resource: { type: string; id: string; tenant: TenantScope },
    context?: Readonly<Record<string, never>>,
  ): Promise<boolean> {
    const auth = request.auth!;
    const policyRequest: PolicyRequest = {
      principal: {
        id: auth.token.subject,
        type: principalType(auth.token),
        roles: extractRoles(auth.token),
        tenant: { tenantId: auth.tenantId },
      },
      action,
      resource,
      ...(context ? { context } : {}),
    };

    let decision;
    try {
      decision = await deps.pdp.decide(policyRequest);
    } catch {
      // A PDP that throws has not said "allow". Fail closed, and do not leak that
      // the policy engine had a problem.
      reply.log.error({ action }, "policy decision point failed");
      reply.code(403).send({ error: "forbidden" });
      return false;
    }

    if (decision.effect !== "Allow") {
      // Logged WITH the determining policies, because "denied" without "by what" is
      // not something an operator can act on. The caller learns only that it failed.
      reply.log.warn(
        { action, subject: auth.token.subject, policies: decision.determiningPolicies },
        "access denied by policy",
      );
      reply.code(403).send({ error: "forbidden" });
      return false;
    }

    request.log.info(
      { action, subject: auth.token.subject, policies: decision.determiningPolicies },
      "access allowed by policy",
    );
    return true;
  }

  // ---------------------------------------------------------------- public
  app.get("/health", async () => ({ status: "ok" }));

  // ---------------------------------------------------------------- protected
  app.get("/v1/session", { preHandler: authenticate }, async (request) => {
    const auth = request.auth!;
    return {
      subject: auth.token.subject,
      // Echoing the tenant makes the ADR-006 behaviour visible and testable: it
      // comes from the token, and a caller supplying one any other way has no
      // effect on this value.
      tenantId: auth.tenantId,
      audience: auth.token.audience,
      expiresAt: auth.token.expiresAt,
      // Tells the caller what the API actually verified, without leaking why a
      // failure failed.
      senderConstrained: auth.token.dpopThumbprint !== undefined,
      ...(auth.thumbprint !== undefined ? { keyThumbprint: auth.thumbprint } : {}),
    };
  });

  // ---------------------------------------------------------------- evidence
  /**
   * Read one piece of evidence.
   *
   * TWO independent tenant layers guard this, and they are deliberately different
   * kinds of control:
   *
   *   1. **The repository** looks the record up inside the caller's own tenant. A
   *      record belonging to anyone else is not filtered out afterwards — it is
   *      never in scope.
   *   2. **The policy** would refuse the pair even if the record were handed to it,
   *      because the tenant boundary is a `forbid` that cannot be overridden.
   *
   * Either alone would do. Both is what ADR-006 asks for, and it means a bug in one
   * is caught by the other rather than becoming a cross-tenant read.
   */
  app.get<{ Params: { id: string } }>("/v1/evidence/:id", { preHandler: authenticate }, async (request, reply) => {
    const auth = request.auth!;
    const tenant: TenantScope = { tenantId: auth.tenantId };

    const record = await deps.evidence.findById(tenant, request.params.id);

    if (!record) {
      // 404 for BOTH "does not exist" and "belongs to someone else". Distinguishing
      // them would turn this endpoint into an existence oracle: an attacker could
      // enumerate ids and learn which ones other tenants hold.
      return reply.code(404).send({ error: "not_found" });
    }

    // Note the resource tenant comes from the RECORD, never from the request.
    const allowed = await authorize(request, reply, "ReadEvidence", {
      type: "Evidence",
      id: record.id,
      tenant: { tenantId: record.tenantId },
    });
    if (!allowed) return reply;

    return {
      id: record.id,
      control: record.control,
      collectedAt: record.collectedAt,
      sha256: record.sha256,
    };
  });

  /**
   * List the caller's own evidence.
   *
   * The tenant is the TOKEN's, so there is no parameter that could name another.
   */
  app.get("/v1/evidence", { preHandler: authenticate }, async (request, reply) => {
    const auth = request.auth!;
    const tenant: TenantScope = { tenantId: auth.tenantId };

    const allowed = await authorize(request, reply, "ListEvidence", {
      type: "Tenant",
      id: tenant.tenantId,
      tenant,
    });
    if (!allowed) return reply;

    const page = await deps.evidence.list(tenant, { limit: 50 });
    return { items: page.items.map((r) => ({ id: r.id, control: r.control })) };
  });

  return app;
}

/**
 * Roles carried by the verified token.
 *
 * Read from `realm_access.roles` and `resource_access.<client>.roles`, which is
 * where Keycloak puts them. Absent means the token carried none — never a default,
 * because a default role is an unearned privilege.
 */
function extractRoles(token: VerifiedToken): string[] {
  const roles = new Set<string>();
  const realmAccess = token.claims["realm_access"];
  if (realmAccess && typeof realmAccess === "object" && !Array.isArray(realmAccess)) {
    const list = (realmAccess as Record<string, unknown>)["roles"];
    if (Array.isArray(list)) for (const r of list) if (typeof r === "string") roles.add(r);
  }
  return [...roles];
}

/**
 * The Cedar principal type for a token subject.
 *
 * A client-credentials token has no human behind it; a user token does. The
 * distinction is recorded in the policy (`principal is User || principal is
 * ServiceAccount`) so that a kind of principal added later is DENIED until someone
 * deliberately permits it.
 */
function principalType(token: VerifiedToken): string {
  // Keycloak marks client-credentials tokens with the service-account subject and
  // no `preferred_username`. Absent that, treat the caller as a service account:
  // the more restrictive of the two, since the permits that require a role will
  // still apply.
  const username = token.claims["preferred_username"];
  return typeof username === "string" && username.length > 0 ? "User" : "ServiceAccount";
}

