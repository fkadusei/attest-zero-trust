import type { TenantScope } from "./policy.ts";

/**
 * Persistence, as a port.
 *
 * The shape of this interface is a security control, not just an abstraction.
 *
 * **Every method takes a `TenantScope` first, and there is no method that returns
 * records without one.** In ADR-008's DynamoDB design the tenant key was a
 * convention: nothing stopped a query that omitted it. Here it cannot be omitted,
 * because there is no overload that lets you. The portable default — PostgreSQL
 * with Row-Level Security — then enforces the same boundary *again* inside the
 * database, so a bug in the query builder is stopped by the engine rather than by
 * review.
 *
 * That is two independent layers under one requirement (ADR-006), which is what
 * "defence in depth" is supposed to mean and rarely does.
 *
 * The record shape below is deliberately minimal and **provisional**. It is the
 * smallest thing the port needs; the domain model is not designed yet, and
 * inventing it here would bury domain decisions inside a storage interface.
 */

export interface EvidenceRecord {
  readonly id: string;
  readonly tenantId: string;
  /** Control identifier the evidence addresses, e.g. `SOC2-CC6.1`. */
  readonly control: string;
  /** Artifact location in object storage. Never a signed URL — those expire. */
  readonly artifactRef: string;
  /** Hex SHA-256 of the artifact bytes, recorded at collection time. */
  readonly sha256: string;
  /** ISO-8601 instant the evidence was collected. */
  readonly collectedAt: string;
}

export interface ListOptions {
  readonly limit?: number;
  /** Opaque cursor from a previous page. Absent means "from the start". */
  readonly cursor?: string;
}

export interface Page<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
}

/**
 * Evidence storage, always scoped to one tenant.
 *
 * Implementations MUST NOT provide a way to read across tenants. A method like
 * `listAll()` would be convenient, would be used during debugging, and would be the
 * single point of failure for every customer at once.
 */
export interface EvidenceRepository {
  /** Returns undefined when absent — and also when it belongs to another tenant. */
  findById(tenant: TenantScope, id: string): Promise<EvidenceRecord | undefined>;

  put(tenant: TenantScope, record: EvidenceRecord): Promise<void>;

  list(tenant: TenantScope, options?: ListOptions): Promise<Page<EvidenceRecord>>;
}

