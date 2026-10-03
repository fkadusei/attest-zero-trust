/**
 * The policy file, evaluated directly.
 *
 * These tests exist because mutation testing found a genuine gap: removing the
 * `forbid` that guards a resource with NO `tenant` attribute was undetected. The
 * reason was that the only test for it passed a resource whose tenant was the empty
 * STRING — the attribute was present, so the tenant-MISMATCH forbid fired instead.
 * The missing-attribute rule was never exercised.
 *
 * It cannot be exercised through the server, because the entity builder always sets
 * the attribute. So it is tested here, against the policy text and a hand-built
 * entity set. That is the right level anyway: **the policy file is the portable
 * artifact** (ADR-015), destined for any Cedar engine, and its rules deserve tests
 * that do not depend on how one adapter happens to build entities today.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { isAuthorized, type CedarValueJson } from "@cedar-policy/cedar-wasm/nodejs";

const POLICIES = readFileSync(new URL("../policies/attest.cedar", import.meta.url), "utf8");

interface Entity {
  uid: { type: string; id: string };
  attrs: Record<string, CedarValueJson>;
  parents: never[];
}

function askWith(policies: string, principal: Entity, action: string, resource: Entity) {
  const result = isAuthorized({
    principal: principal.uid,
    action: { type: "Action", id: action },
    resource: resource.uid,
    context: {},
    policies: { staticPolicies: policies },
    entities: [principal, resource],
  });
  if (result.type !== "success") return { decision: "error" as const, errors: [] as string[] };
  return {
    decision: result.response.decision,
    errors: result.response.diagnostics.errors.map((e) => e.error.message),
  };
}

function ask(principal: Entity, action: string, resource: Entity) {
  const result = isAuthorized({
    principal: principal.uid,
    action: { type: "Action", id: action },
    resource: resource.uid,
    context: {},
    policies: { staticPolicies: POLICIES },
    entities: [principal, resource],
  });
  if (result.type !== "success") return { decision: "error" as const, errors: [] as string[] };
  return {
    decision: result.response.decision,
    errors: result.response.diagnostics.errors.map((e) => e.error.message),
  };
}

const user = (id: string, attrs: Record<string, CedarValueJson>): Entity => ({
  uid: { type: "User", id },
  attrs,
  parents: [],
});
const evidence = (id: string, attrs: Record<string, CedarValueJson>): Entity => ({
  uid: { type: "Evidence", id },
  attrs,
  parents: [],
});

describe("the policy file, evaluated directly", () => {
  it("CONTROL: a same-tenant read is allowed", () => {
    const r = ask(user("u1", { tenant: "acme", roles: [] }), "ReadEvidence", evidence("e1", { tenant: "acme" }));
    assert.equal(r.decision, "allow", JSON.stringify(r));
  });

  it("a cross-tenant read is denied", () => {
    const r = ask(user("u1", { tenant: "acme", roles: [] }), "ReadEvidence", evidence("e1", { tenant: "globex" }));
    assert.equal(r.decision, "deny");
  });

  // ------------------------------------------------------------ the gap this file closes
  it("a resource with NO tenant attribute at all is denied", () => {
    // The case the entity builder cannot produce, and therefore the case no
    // end-to-end test could reach. `attrs: {}` means the attribute is ABSENT, which
    // is different from present-and-empty.
    const r = ask(user("u1", { tenant: "acme", roles: [] }), "ReadEvidence", evidence("e1", {}));
    assert.equal(r.decision, "deny", JSON.stringify(r));
  });

  it("that denial is a DECISION, not an evaluation error", () => {
    // The distinction matters. If this denied only because a comparison could not
    // be evaluated, the rule would be resting on Cedar's default rather than on
    // anything written down — and a future policy that happened to permit first
    // would open the hole.
    const r = ask(user("u1", { tenant: "acme", roles: [] }), "ReadEvidence", evidence("e1", {}));
    assert.equal(r.decision, "deny");
    assert.deepEqual(r.errors, [], `denial should be clean, got errors: ${JSON.stringify(r.errors)}`);
  });

  it("the missing-tenant forbid is a SAFETY NET that catches a careless permit", () => {
    // This rule is currently UNREACHABLE through the ordinary permits, because every
    // one of them already requires `resource has tenant`. So removing it changes no
    // outcome, and a mutation of it survives — correctly, because it is not doing
    // any work today.
    //
    // Its value is as a guard against a FUTURE permit that forgets the check. That
    // is exactly what this test simulates: a deliberately careless permit is added,
    // and the forbid must catch what it lets through.
    const careless =
      POLICIES +
      '\npermit (principal, action == Action::"ReadEvidence", resource)\n' +
      'when { resource is Evidence };\n';

    const withNet = askWith(careless, user("u1", { tenant: "acme", roles: [] }), "ReadEvidence", evidence("e1", {}));
    assert.equal(withNet.decision, "deny", "the forbid must catch a permit that omits the tenant check");

    // CONTROL: remove the safety net and the careless permit DOES allow. Without
    // this, the assertion above would also pass on a policy set that denies
    // everything for unrelated reasons.
    const netless = careless.replace(
      'forbid (principal, action, resource)\nwhen { resource is Evidence && !(resource has tenant) };',
      '// safety net removed',
    );
    assert.notEqual(netless, careless, "the safety net was not actually removed");
    const withoutNet = askWith(netless, user("u1", { tenant: "acme", roles: [] }), "ReadEvidence", evidence("e1", {}));
    assert.equal(
      withoutNet.decision,
      "allow",
      "control failed: the careless permit should allow once the net is gone, proving the net was doing the work",
    );
  });

  it("a PRINCIPAL with no tenant attribute is denied", () => {
    const r = ask(user("u1", { roles: [] }), "ReadEvidence", evidence("e1", { tenant: "acme" }));
    assert.equal(r.decision, "deny", JSON.stringify(r));
  });

  it("a principal with no tenant cannot even match its own resource", () => {
    const r = ask(user("u1", { roles: [] }), "ReadEvidence", evidence("e1", {}));
    assert.equal(r.decision, "deny");
  });

  // ------------------------------------------------------------ other rules
  it("an unknown principal TYPE is denied", () => {
    const mystery: Entity = { uid: { type: "MysteryActor", id: "m1" }, attrs: { tenant: "acme", roles: ["writer"] }, parents: [] };
    const r = ask(mystery, "ReadEvidence", evidence("e1", { tenant: "acme" }));
    assert.equal(r.decision, "deny", "a permit must not apply to an entity type nobody vetted");
  });

  it("writing requires the writer role", () => {
    assert.equal(
      ask(user("u1", { tenant: "acme", roles: [] }), "WriteEvidence", evidence("e1", { tenant: "acme" })).decision,
      "deny",
    );
    assert.equal(
      ask(user("u1", { tenant: "acme", roles: ["writer"] }), "WriteEvidence", evidence("e1", { tenant: "acme" })).decision,
      "allow",
    );
  });

  it("the writer role does not cross the tenant boundary", () => {
    const r = ask(user("u1", { tenant: "acme", roles: ["writer"] }), "WriteEvidence", evidence("e1", { tenant: "globex" }));
    assert.equal(r.decision, "deny");
  });

  it("an action with no permit is denied", () => {
    const r = ask(user("u1", { tenant: "acme", roles: [] }), "DeleteEverything", evidence("e1", { tenant: "acme" }));
    assert.equal(r.decision, "deny");
  });

  it("listing your own tenant is allowed; another is not", () => {
    const tenantEntity = (id: string): Entity => ({
      uid: { type: "Tenant", id },
      attrs: { tenant: id, id },
      parents: [],
    });
    assert.equal(
      ask(user("u1", { tenant: "acme", roles: [] }), "ListEvidence", tenantEntity("acme")).decision,
      "allow",
    );
    assert.equal(
      ask(user("u1", { tenant: "acme", roles: [] }), "ListEvidence", tenantEntity("globex")).decision,
      "deny",
    );
  });
});
