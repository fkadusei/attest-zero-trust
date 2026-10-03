import { createHash, randomUUID } from "node:crypto";

import type { ObjectStorage, StoredObject } from "./object-storage.ts";
import type { TenantScope } from "./policy.ts";

/**
 * In-memory artifact storage — the PORTABLE DEFAULT for the object-storage port.
 *
 * Correct for one process and for tests, and **explicitly wrong for anything that
 * must survive a restart**. The startup log says so when it is in use.
 *
 * It exists so that the authorization path can be exercised end to end with
 * nothing running, which is what keeps CI and a laptop identical (ADR-015). It is
 * not a stub: it enforces the port's contract, including the two rules that make
 * the contract worth having — tenant scoping, and content integrity.
 */
export class InMemoryObjectStorage implements ObjectStorage {
  /** Keyed by tenant, so a lookup for the wrong tenant cannot find the bytes. */
  readonly #byTenant = new Map<string, Map<string, StoredObject>>();

  async put(
    tenant: TenantScope,
    artifactId: string,
    bytes: Uint8Array,
    contentType: string,
  ): Promise<{ ref: string; sha256: string }> {
    const sha256 = digest(bytes);
    // The ref is generated HERE, not accepted from the caller. A caller that names
    // its own storage key will eventually name one that escapes its prefix.
    const ref = `${safe(tenant.tenantId)}/${safe(artifactId)}-${randomUUID()}`;

    let bucket = this.#byTenant.get(tenant.tenantId);
    if (!bucket) {
      bucket = new Map();
      this.#byTenant.set(tenant.tenantId, bucket);
    }
    bucket.set(ref, { bytes, contentType, sha256 });
    return { ref, sha256 };
  }

  async get(tenant: TenantScope, ref: string): Promise<StoredObject | undefined> {
    // Look only in the caller's own bucket. A ref belonging to another tenant is
    // not filtered out afterwards — it is never in scope.
    const stored = this.#byTenant.get(tenant.tenantId)?.get(ref);
    if (!stored) return undefined;

    // Verify on read. Storage is not trusted to have kept the bytes intact, and a
    // silent corruption in an evidence product is a false attestation.
    if (digest(stored.bytes) !== stored.sha256) {
      throw new Error("stored artifact failed its integrity check");
    }
    return stored;
  }

  async delete(tenant: TenantScope, ref: string): Promise<void> {
    this.#byTenant.get(tenant.tenantId)?.delete(ref);
  }
}

/** Hex SHA-256, matching the `sha256` field on an evidence record. */
export function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Make a string safe to appear in a storage key.
 *
 * Percent-encoding is reversible, so an operator can still read a key and tell
 * which tenant and artifact it belongs to, while `/`, `..` and everything else
 * path-significant is neutralised. Used for the in-memory ref and, in the
 * filesystem adapter, for the tenant DIRECTORY — where an unescaped `../..` would
 * be a directory traversal.
 */
export function safe(value: string): string {
  return encodeURIComponent(value).replace(/\*/g, "%2A");
}
