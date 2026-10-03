/**
 * The Cedar policy decision point.
 *
 * These tests run the REAL policy file at `policies/attest.cedar`. A PDP tested
 * against a simplified policy proves the adapter works and says nothing about the
 * policies that would actually run — and the policies are where the tenant boundary
 * lives.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { CedarPolicyDecisionPoint } from "../src/pdp-cedar.ts";
import type { PolicyRequest, PolicyPrincipal, PolicyResource } from "../src/ports/policy.ts";

const POLICY_TEXT = readFileSync(new URL("../policies/attest.cedar", import.meta.url), "utf8");

const pdp = new CedarPolicyDecisionPoint({ policies: POLICY_TEXT });

const principal = (tenant: string, roles: string[] = [], type = "User"): PolicyPrincipal => ({
  id: "user-1",
  type,
  roles,
  tenant: { tenantId: tenant },
});

const resource = (tenant: string, type = "Evidence"): PolicyResource => ({
  id: "evidence-1",
  type,
  tenant: { tenantId: tenant },
});

const request = (
  p: PolicyPrincipal,
  action: string,
  r: PolicyResource,
  context?: Record<string, never>,
): PolicyRequest => ({ principal: p, action, resource: r, ...(context ? { context } : {}) });

describe("the Cedar policy decision point", () => {
  // ---------------------------------------------------------------- permits
  it("CONTROL: a member of the owning tenant may READ their own evidence", async () => {
    const decision = await pdp.decide(request(principal("acme"), "ReadEvidence", resource("acme")));
    assert.equal(decision.effect, "Allow", JSON.stringify(decision));
  });

  it("a writer may WRITE to their own tenant", async () => {
    const decision = await pdp.decide(
      request(principal("acme", ["writer"]), "WriteEvidence", resource("acme")),
    );
    assert.equal(decision.effect, "Allow", JSON.stringify(decision));
  });

  // ---------------------------------------------------------------- the boundary
  it("THE TENANT BOUNDARY: reading ANOTHER tenant's evidence is denied", async () => {
    const decision = await pdp.decide(request(principal("acme"), "ReadEvidence", resource("globex")));
    assert.equal(decision.effect, "Deny", "cross-tenant read must be denied");
  });

  it("THE TENANT BOUNDARY: writing to ANOTHER tenant is denied, even as a writer", async () => {
    // Holding the role must not widen the boundary. If it did, a single over-privileged
    // account would be a cross-tenant write.
    const decision = await pdp.decide(
      request(principal("acme", ["writer"]), "WriteEvidence", resource("globex")),
    );
    assert.equal(decision.effect, "Deny");
  });

  it("the denial is attributable to a policy, for audit", async () => {
    const decision = await pdp.decide(request(principal("acme"), "ReadEvidence", resource("globex")));
    assert.equal(decision.effect, "Deny");
    assert.ok(
      decision.determiningPolicies.length > 0,
      "a denial must name the policy that produced it; 'denied' alone is not an explanation",
    );
  });

  // ---------------------------------------------------------------- roles
  it("a non-writer may NOT write, even within their own tenant", async () => {
    const decision = await pdp.decide(request(principal("acme"), "WriteEvidence", resource("acme")));
    assert.equal(decision.effect, "Deny");
  });

  it("a writer role in a DIFFERENT tenant does not help", async () => {
    const decision = await pdp.decide(
      request(principal("globex", ["writer"]), "WriteEvidence", resource("acme")),
    );
    assert.equal(decision.effect, "Deny");
  });

  // ---------------------------------------------------------------- missing attributes
  it("a resource with NO tenant is denied to everyone", async () => {
    // With no `tenant`, a bare comparison would be an evaluation error and the deny
    // would be a side effect of Cedar's default. The policy forbids it explicitly,
    // so the denial is a decision.
    const orphan: PolicyResource = { id: "orphan", type: "Evidence", tenant: { tenantId: "" } };
    const decision = await pdp.decide(request(principal("acme"), "ReadEvidence", orphan));
    assert.equal(decision.effect, "Deny");
  });

  // ---------------------------------------------------------------- default deny
  it("an action with no permit is denied", async () => {
    const decision = await pdp.decide(request(principal("acme"), "DeleteEverything", resource("acme")));
    assert.equal(decision.effect, "Deny");
  });

  it("an unknown principal type is denied rather than allowed", async () => {
    const decision = await pdp.decide(
      request(principal("acme", [], "MysteryActor"), "ReadEvidence", resource("acme")),
    );
    assert.equal(decision.effect, "Deny");
  });

  // ---------------------------------------------------------------- ListEvidence
  it("a member may LIST their own tenant", async () => {
    const decision = await pdp.decide(
      request(principal("acme"), "ListEvidence", resource("acme", "Tenant")),
    );
    assert.equal(decision.effect, "Allow", JSON.stringify(decision));
  });

  it("a member may NOT list another tenant", async () => {
    const decision = await pdp.decide(
      request(principal("acme"), "ListEvidence", resource("globex", "Tenant")),
    );
    assert.equal(decision.effect, "Deny");
  });
});

describe("the PDP fails closed", () => {
  it("a policy set that does not PARSE is refused at construction, not per request", async () => {
    // Failing closed is right; failing closed silently for every request because of
    // a typo is an outage. A syntax error must stop the process starting.
    assert.throws(
      () => new CedarPolicyDecisionPoint({ policies: "permit ( this is not cedar" }),
      /does not parse/,
    );
  });

  it("ALLOW WITH ERRORS is treated as DENY", async () => {
    // The subtle case this adapter exists to handle. Cedar can return `allow`
    // alongside a non-empty `errors` array when a DIFFERENT policy failed to
    // evaluate — and that policy may have been a `forbid`. Trusting the allow would
    // mean an unevaluatable rule silently stops applying.
    const broken = `
      permit (principal, action, resource);
      forbid (principal, action, resource) when { resource.no_such_attribute == 1 };
    `;
    const p = new CedarPolicyDecisionPoint({ policies: broken });
    const decision = await p.decide(request(principal("acme"), "ReadEvidence", resource("acme")));
    assert.equal(
      decision.effect,
      "Deny",
      "an allow accompanied by evaluation errors must not be trusted",
    );
    assert.ok(decision.determiningPolicies.some((x) => x.includes("error")), JSON.stringify(decision));
  });

  it("the control for the case above: the same policy WITHOUT the error does allow", async () => {
    // Proves the deny above is caused by the evaluation error, not by the permit
    // failing to match. Without this, the test would pass on a PDP that denies
    // everything.
    const clean = `permit (principal, action, resource);`;
    const p = new CedarPolicyDecisionPoint({ policies: clean });
    const decision = await p.decide(request(principal("acme"), "ReadEvidence", resource("acme")));
    assert.equal(decision.effect, "Allow");
  });

  it("a context value that cannot be represented is refused, never dropped", async () => {
    // Dropping an attribute would let a policy that consults it fall through to a
    // different decision — and a dropped attribute on a forbid is a hole.
    const decision = await pdp.decide({
      principal: principal("acme"),
      action: "ReadEvidence",
      resource: resource("acme"),
      context: { weird: (() => 1) as never },
    });
    assert.equal(decision.effect, "Deny");
  });
});
