import type { EvidenceRecord, EvidenceRepository, ListOptions, Page } from "./repository.ts";
import type { TenantScope } from "./policy.ts";

/**
 * An in-memory evidence repository — the PORTABLE DEFAULT for the repository port.
 *
 * This exists so the authorization path can be exercised end to end without a
 * database, and so that CI and a laptop behave identically. It is deliberately not
 * a stub that returns fixed data: it enforces the port's contract, including the
 * part that matters most.
 *
 * **The tenant scoping is enforced here, in the data layer, not left to callers.**
 * `findById` takes a `TenantScope` and returns `undefined` for a record belonging
 * to anyone else. That means a caller who forgets to check the tenant gets nothing
 * rather than someone else's data — the failure is a missing record, not a breach.
 *
 * Two layers now guard the boundary:
 *   1. this repository, which cannot return across tenants
 *   2. the Cedar policy, which refuses to authorise across tenants
 *
 * The portable replacement is PostgreSQL with Row-Level Security, which enforces
 * the same rule *inside the database* (ADR-015). This class is the local stand-in
 * for that engine-level guarantee, and it is honest about being weaker: it is
 * process-local and disappears on restart.
 */
export class InMemoryEvidenceRepository implements EvidenceRepository {
  readonly #byTenant = new Map<string, Map<string, EvidenceRecord>>();

  /** Seed a record. Used by tests and by local development. */
  seed(record: EvidenceRecord): void {
    let bucket = this.#byTenant.get(record.tenantId);
    if (!bucket) {
      bucket = new Map();
      this.#byTenant.set(record.tenantId, bucket);
    }
    bucket.set(record.id, record);
  }

  async findById(tenant: TenantScope, id: string): Promise<EvidenceRecord | undefined> {
    // Look ONLY in the caller's own bucket. A record with this id belonging to
    // another tenant is not merely filtered out afterwards — it is never in scope,
    // so it cannot leak through a bug in a filter.
    return this.#byTenant.get(tenant.tenantId)?.get(id);
  }

  async put(tenant: TenantScope, record: EvidenceRecord): Promise<void> {
    if (record.tenantId !== tenant.tenantId) {
      // Refuse rather than silently retarget. Writing a record into someone else's
      // tenant because the caller passed mismatched arguments would be a
      // cross-tenant write performed by the storage layer itself.
      throw new Error("record tenant does not match the scope it is being written under");
    }
    this.seed(record);
  }

  async list(tenant: TenantScope, options: ListOptions = {}): Promise<Page<EvidenceRecord>> {
    const all = [...(this.#byTenant.get(tenant.tenantId)?.values() ?? [])].sort((a, b) =>
      a.id.localeCompare(b.id),
    );
    const limit = options.limit ?? 50;
    const start = options.cursor ? all.findIndex((r) => r.id === options.cursor) + 1 : 0;
    const items = all.slice(start, start + limit);
    const last = items.at(-1);
    const hasMore = start + limit < all.length;
    return {
      items,
      ...(hasMore && last ? { nextCursor: last.id } : {}),
    };
  }
}
