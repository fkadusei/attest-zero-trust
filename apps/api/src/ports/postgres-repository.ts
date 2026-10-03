import pg from "pg";

import type { EvidenceRecord, EvidenceRepository, ListOptions, Page } from "./repository.ts";
import type { TenantScope } from "./policy.ts";

/**
 * PostgreSQL-backed evidence storage, with the tenant boundary enforced by the
 * DATABASE.
 *
 * WHY THIS IS A DIFFERENT KIND OF CONTROL
 *
 * The in-memory repository enforces tenancy in application code: a bug in this
 * file could return another tenant's rows. Here the rule lives in the engine.
 * `evidence` has Row-Level Security enabled and FORCED, and a policy comparing
 * `tenant_id` against `app.current_tenant`. A query that forgets its tenant filter
 * — or one written next year by someone who has not read this file — returns
 * nothing it should not, because PostgreSQL removes those rows before the query
 * sees them.
 *
 * That has been verified rather than assumed: with `app.current_tenant = 'acme'`,
 * a bare `SELECT * FROM evidence` with no WHERE clause returns only acme's rows,
 * while the same statement as a superuser returns every tenant's. The difference
 * is the role, which is why the application connects as `attest_app` and NOT as the
 * owner.
 *
 * THE TRAP THIS AVOIDS
 *
 * Row-Level Security is bypassed by superusers, always, and by the table owner
 * unless FORCE is set. An application connecting as either gets **no row-level
 * security at all, silently** — every query succeeds, every test passes, and the
 * boundary is simply absent. The schema therefore creates a dedicated
 * non-superuser role, marks the table FORCE, and the tests keep a superuser
 * connection on purpose as the control that proves the policy is doing the work.
 *
 * TWO LAYERS, AGAIN
 *
 * The queries below ALSO filter by tenant. That is redundant given the policy, and
 * deliberately so: belt and braces. If the policy is ever dropped, the queries
 * still scope correctly; if a query is ever written without the filter, the policy
 * still holds. The test suite proves the second case directly.
 */

/** The session variable the RLS policy reads. */
const TENANT_SETTING = "app.current_tenant";

export interface PostgresRepositoryOptions {
  /** Connection string for the APPLICATION role — never a superuser. */
  readonly connectionString: string;
  /** Maximum pooled connections. */
  readonly max?: number;
}

export class PostgresEvidenceRepository implements EvidenceRepository {
  readonly #pool: pg.Pool;

  constructor(options: PostgresRepositoryOptions) {
    this.#pool = new pg.Pool({
      connectionString: options.connectionString,
      max: options.max ?? 10,
    });
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }

  /**
   * Run `body` inside a transaction whose `app.current_tenant` is set.
   *
   * Three details are load-bearing:
   *
   * 1. **A dedicated client.** `pool.query()` checks out and returns a connection
   *    per call, so a `SET` issued on the pool could land on a different connection
   *    from the query it was meant to scope. The client is held across both.
   *
   * 2. **`SET LOCAL`, not `SET`.** `SET LOCAL` is scoped to the transaction and
   *    reverts on commit or rollback. A plain `SET` would persist on a pooled
   *    connection and leak the tenant to whichever request picks that connection up
   *    next — a cross-tenant read caused by connection reuse, which is a real and
   *    subtle failure mode.
   *
   * 3. **Rollback on error, always.** A failed transaction must not leave a client
   *    with a half-applied tenant setting.
   */
  async #withTenant<T>(tenant: TenantScope, body: (client: pg.PoolClient) => Promise<T>): Promise<T> {
    const client = await this.#pool.connect();
    try {
      await client.query("BEGIN");
      // Parameterised: `SET LOCAL` does not accept bind parameters, so the value is
      // passed through `set_config`, which does. Interpolating a tenant id into SQL
      // would be an injection point in the one place that must never have one.
      await client.query("SELECT set_config($1, $2, true)", [TENANT_SETTING, tenant.tenantId]);
      const result = await body(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async findById(tenant: TenantScope, id: string): Promise<EvidenceRecord | undefined> {
    return this.#withTenant(tenant, async (client) => {
      // The tenant predicate below is defence in depth, not the enforcement. RLS is
      // the enforcement — see the class comment, and the test that removes the
      // predicate and shows the result is unchanged.
      const { rows } = await client.query<EvidenceRow>(
        `SELECT id, tenant_id, control, artifact_ref, sha256, collected_at
           FROM evidence
          WHERE tenant_id = $1 AND id = $2`,
        [tenant.tenantId, id],
      );
      const row = rows[0];
      return row ? toRecord(row) : undefined;
    });
  }

  async put(tenant: TenantScope, record: EvidenceRecord): Promise<void> {
    if (record.tenantId !== tenant.tenantId) {
      // Refused before the database sees it. The RLS `WITH CHECK` would also refuse
      // this, but failing here gives a clear error rather than a policy violation.
      throw new Error("record tenant does not match the scope it is being written under");
    }
    await this.#withTenant(tenant, async (client) => {
      await client.query(
        `INSERT INTO evidence (id, tenant_id, control, artifact_ref, sha256, collected_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (tenant_id, id) DO UPDATE
           SET control = EXCLUDED.control,
               artifact_ref = EXCLUDED.artifact_ref,
               sha256 = EXCLUDED.sha256,
               collected_at = EXCLUDED.collected_at`,
        [record.id, record.tenantId, record.control, record.artifactRef, record.sha256, record.collectedAt],
      );
    });
  }

  async list(tenant: TenantScope, options: ListOptions = {}): Promise<Page<EvidenceRecord>> {
    const limit = Math.min(options.limit ?? 50, 200);
    return this.#withTenant(tenant, async (client) => {
      const { rows } = await client.query<EvidenceRow>(
        `SELECT id, tenant_id, control, artifact_ref, sha256, collected_at
           FROM evidence
          WHERE tenant_id = $1 AND ($2::text IS NULL OR id > $2)
          ORDER BY id
          LIMIT $3`,
        [tenant.tenantId, options.cursor ?? null, limit + 1],
      );
      const hasMore = rows.length > limit;
      const items = rows.slice(0, limit).map(toRecord);
      const last = items.at(-1);
      return {
        items,
        ...(hasMore && last ? { nextCursor: last.id } : {}),
      };
    });
  }

  /**
   * Run a query with NO tenant predicate, for tests.
   *
   * Exists to make a claim falsifiable: that the database, not this file, is what
   * stops a cross-tenant read. The suite calls this and asserts it still returns
   * only the scoped tenant's rows.
   */
  async unsafeUnscopedSelect(tenant: TenantScope): Promise<EvidenceRecord[]> {
    return this.#withTenant(tenant, async (client) => {
      const { rows } = await client.query<EvidenceRow>(
        "SELECT id, tenant_id, control, artifact_ref, sha256, collected_at FROM evidence",
      );
      return rows.map(toRecord);
    });
  }
}

interface EvidenceRow {
  id: string;
  tenant_id: string;
  control: string;
  artifact_ref: string;
  sha256: string;
  collected_at: Date | string;
}

function toRecord(row: EvidenceRow): EvidenceRecord {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    control: row.control,
    artifactRef: row.artifact_ref,
    sha256: row.sha256,
    collectedAt:
      row.collected_at instanceof Date ? row.collected_at.toISOString() : String(row.collected_at),
  };
}
