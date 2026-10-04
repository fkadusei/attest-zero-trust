/**
 * The PostgreSQL adapter, and the tenant boundary the DATABASE enforces.
 *
 * The tests that matter here are not "does findById work". They are the ones that
 * make a security claim falsifiable:
 *
 *   * an UNSCOPED query still cannot see another tenant's rows
 *   * the SAME query as a superuser CAN, which is what proves the policy is the
 *     thing doing the work rather than good manners in the SQL
 *   * a tenant setting does not survive on a pooled connection into the next request
 *
 * Without the superuser control, the first test would also pass on a database where
 * Row-Level Security does nothing at all and the queries simply happen to filter
 * correctly.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";

import { APP_DB_APP_PASSWORD, POSTGRES_PASSWORD } from "../../../lab/lab-env.mjs";

import { PostgresEvidenceRepository } from "../src/ports/postgres-repository.ts";
import type { EvidenceRecord } from "../src/ports/repository.ts";

const HOST = process.env["APPDB_HOST"] ?? "127.0.0.1";
const PORT = Number(process.env["APPDB_PORT"] ?? 55432);

/** The application role: NOT a superuser, NOT the table owner. */
const APP_URL = `postgresql://attest_app:${APP_DB_APP_PASSWORD}@${HOST}:${PORT}/attest`;
/** The owner/superuser, kept deliberately as the negative control. */
const OWNER_URL = `postgresql://attest_owner:${POSTGRES_PASSWORD}@${HOST}:${PORT}/attest`;

const ACME = { tenantId: "acme" } as const;
const GLOBEX = { tenantId: "globex" } as const;

let repo: PostgresEvidenceRepository;
let owner: pg.Client;
let available = true;

const record = (id: string, tenantId: string): EvidenceRecord => ({
  id,
  tenantId,
  control: "SOC2-CC6.1",
  artifactRef: `ref-${id}`,
  sha256: "a".repeat(64),
  collectedAt: "2026-01-01T00:00:00.000Z",
});

describe("the PostgreSQL evidence store", { skip: false }, () => {
  before(async () => {
    owner = new pg.Client({ connectionString: OWNER_URL });
    try {
      await owner.connect();
    } catch (error) {
      available = false;
      console.warn(`  appdb not reachable, skipping: ${String(error).slice(0, 90)}`);
      return;
    }
    // The owner connection bypasses RLS, which is exactly what makes it a control
    // and exactly why the application must not use it.
    await owner.query("DELETE FROM evidence");
    await owner.query(
      `INSERT INTO evidence (id, tenant_id, control, artifact_ref, sha256, collected_at) VALUES
         ('e-acme-1','acme','SOC2-CC6.1','ref-a1','${"a".repeat(64)}',now()),
         ('e-acme-2','acme','ISO-A.5.15','ref-a2','${"b".repeat(64)}',now()),
         ('e-globex-1','globex','SOC2-CC6.1','ref-g1','${"c".repeat(64)}',now())`,
    );
    repo = new PostgresEvidenceRepository({ connectionString: APP_URL, max: 2 });
  });

  after(async () => {
    await repo?.close().catch(() => {});
    await owner?.end().catch(() => {});
  });

  // ---------------------------------------------------------------- ordinary
  it("reads a record belonging to the caller's own tenant", async (t) => {
    if (!available) return t.skip("appdb not running");
    const found = await repo.findById(ACME, "e-acme-1");
    assert.equal(found?.id, "e-acme-1");
    assert.equal(found?.tenantId, "acme");
  });

  it("does NOT return another tenant's record, even by exact id", async (t) => {
    if (!available) return t.skip("appdb not running");
    const found = await repo.findById(ACME, "e-globex-1");
    assert.equal(found, undefined, "a cross-tenant read by id must return nothing");
  });

  it("lists only the caller's own records", async (t) => {
    if (!available) return t.skip("appdb not running");
    const page = await repo.list(ACME);
    assert.deepEqual(
      page.items.map((r) => r.id),
      ["e-acme-1", "e-acme-2"],
    );
  });

  it("refuses a write whose record tenant disagrees with the scope", async (t) => {
    if (!available) return t.skip("appdb not running");
    await assert.rejects(() => repo.put(ACME, record("e-x", "globex")));
  });

  // ---------------------------------------------------------------- THE RLS PROOF
  it("THE POINT OF THIS ADAPTER: an UNSCOPED query still cannot leak", async (t) => {
    if (!available) return t.skip("appdb not running");
    // No WHERE clause at all. If the tenant boundary were only a convention in the
    // SQL above, this would return every tenant's rows.
    const rows = await repo.unsafeUnscopedSelect(ACME);
    assert.ok(rows.length > 0, "the control needs at least one row to be meaningful");
    assert.ok(
      rows.every((r) => r.tenantId === "acme"),
      `RLS did not hide another tenant: ${JSON.stringify(rows.map((r) => r.tenantId))}`,
    );
  });

  it("NEGATIVE CONTROL: the SAME unscoped query as the SUPERUSER returns everything", async (t) => {
    if (!available) return t.skip("appdb not running");
    // This is what makes the test above meaningful. It proves the rows ARE there and
    // that the application role is what cannot see them — rather than the data
    // simply being absent, which would satisfy the previous assertion for the wrong
    // reason.
    const { rows } = await owner.query<{ tenant_id: string }>("SELECT tenant_id FROM evidence");
    const tenants = new Set(rows.map((r) => r.tenant_id));
    assert.ok(tenants.has("acme"), "acme rows must exist");
    assert.ok(
      tenants.has("globex"),
      "the superuser must SEE globex, proving RLS (not absence) hides it from the app",
    );
  });

  it("the application role is genuinely NOT privileged", async (t) => {
    if (!available) return t.skip("appdb not running");
    // If this ever changes — someone runs migrations as attest_app, or grants it
    // more — the boundary weakens silently. Asserted so it cannot.
    const { rows } = await owner.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
      "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'attest_app'",
    );
    assert.equal(rows[0]?.rolsuper, false, "attest_app must not be a superuser");
    assert.equal(rows[0]?.rolbypassrls, false, "attest_app must not bypass RLS");
  });

  it("the table is FORCE row-level secured, so even its owner is subject to the policy", async (t) => {
    if (!available) return t.skip("appdb not running");
    const { rows } = await owner.query<{ relrowsecurity: boolean; relforcerowsecurity: boolean }>(
      "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'evidence'",
    );
    assert.equal(rows[0]?.relrowsecurity, true, "RLS must be enabled");
    assert.equal(rows[0]?.relforcerowsecurity, true, "RLS must be FORCED, or the owner bypasses it");
  });

  // ---------------------------------------------------------------- connection reuse
  it("a tenant setting does NOT survive into the next request on a reused connection", async (t) => {
    if (!available) return t.skip("appdb not running");
    // The pool is capped at 2 connections, so these calls necessarily reuse them.
    // `SET LOCAL` is transaction-scoped; a plain `SET` would persist and leak the
    // tenant to whichever request picked the connection up next. This interleaves
    // two tenants repeatedly and checks the results never bleed.
    for (let i = 0; i < 6; i++) {
      const acme = await repo.list(ACME);
      const globex = await repo.list(GLOBEX);
      assert.ok(acme.items.every((r) => r.tenantId === "acme"), `round ${i}: acme list leaked`);
      assert.ok(globex.items.every((r) => r.tenantId === "globex"), `round ${i}: globex list leaked`);
      assert.equal(acme.items.length, 2);
      assert.equal(globex.items.length, 1);
    }
  });

  it("an UNSET tenant matches nothing — fail closed, not open", async (t) => {
    if (!available) return t.skip("appdb not running");
    // `current_setting(..., true)` returns NULL when unset, and `tenant_id = NULL` is
    // NULL, never true. A connection with no tenant therefore sees no rows at all.
    const client = new pg.Client({ connectionString: APP_URL });
    await client.connect();
    try {
      const { rows } = await client.query("SELECT id FROM evidence");
      assert.deepEqual(rows, [], "with no tenant set, no rows may be visible");
    } finally {
      await client.end();
    }
  });
});
