import type { TenantScope } from "./policy.ts";

/**
 * Artifact storage, as a port.
 *
 * This is where compliance evidence actually lives — the screenshots, exports and
 * configuration dumps that prove a control operates. It is a separate port from
 * the repository because it is a genuinely different capability with genuinely
 * different failure modes, and because every cloud has an object store with a
 * different API. S3, GCS, Azure Blob and MinIO all satisfy this interface.
 *
 * Two rules, both learned from how object storage is normally misused:
 *
 * 1. **Keys are tenant-prefixed by the implementation, never by the caller.** A
 *    caller that builds its own key will eventually build one that escapes its
 *    prefix — `../` and unencoded tenant ids are the usual route. The port takes a
 *    tenant and an opaque artifact id and derives the key itself.
 *
 * 2. **Signed URLs are deliberately absent.** They are convenient and they leak:
 *    a URL that outlives the authorisation decision that produced it is an
 *    unauthenticated bearer capability. Reads go through the API, where the
 *    policy decision is re-evaluated on every request, which is the entire point
 *    of a Zero Trust design.
 */

export interface StoredObject {
  readonly bytes: Uint8Array;
  readonly contentType: string;
  /** Hex SHA-256 of the returned bytes. Callers verify it against the record. */
  readonly sha256: string;
}

export interface ObjectStorage {
  /** Store bytes and return the opaque reference to record in the repository. */
  put(
    tenant: TenantScope,
    artifactId: string,
    bytes: Uint8Array,
    contentType: string,
  ): Promise<{ readonly ref: string; readonly sha256: string }>;

  /** Read bytes. Returns undefined when absent OR owned by another tenant. */
  get(tenant: TenantScope, ref: string): Promise<StoredObject | undefined>;

  /** Remove an artifact. Idempotent: removing something absent is not an error. */
  delete(tenant: TenantScope, ref: string): Promise<void>;
}
