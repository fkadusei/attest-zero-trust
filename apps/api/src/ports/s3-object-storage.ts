import { createHash, randomUUID } from "node:crypto";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  CreateBucketCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";

import type { ObjectStorage, StoredObject } from "./object-storage.ts";
import type { TenantScope } from "./policy.ts";

/**
 * S3-compatible artifact storage.
 *
 * This is the adapter that proves the port was worth having. It is the third
 * implementation of `ObjectStorage` — after in-memory and filesystem — and it
 * satisfies the same contract, which is checked by running all three against one
 * suite in `test/object-storage.test.ts`. Nothing in the domain changed.
 *
 * It speaks to **any S3-compatible endpoint**: AWS S3, MinIO, Cloudflare R2, Google
 * Cloud Storage's S3 interoperability mode, Backblaze B2, Ceph. That is why the
 * endpoint is configured rather than assumed. Tests run it against `adobe/s3mock`,
 * so the code path exercised is the real one — a signed request to an S3 API.
 *
 * ADR-015 says cloud SDKs live in ADAPTERS and nowhere else. This is that adapter:
 * the `@aws-sdk/client-s3` import is confined to this file, and the domain still
 * does not know which cloud it runs on — or whether it runs on one.
 *
 * WHY `forcePathStyle`
 * Virtual-host addressing (`bucket.s3.amazonaws.com`) does not work against a
 * local endpoint where the bucket name is not a DNS name. Path style
 * (`endpoint/bucket/key`) works everywhere, at the cost of nothing that matters
 * here.
 *
 * WHAT IS DELIBERATELY ABSENT, AGAIN
 * **No pre-signed URLs.** They are the obvious convenience and they leak: a URL
 * remains a bearer capability until it expires, regardless of any decision made
 * afterwards. Reads go through the API so the policy is re-evaluated every time.
 * The `GetObjectCommand` above is used only with credentials this service holds.
 */
export interface S3ObjectStorageOptions {
  readonly bucket: string;
  readonly region: string;
  /** Custom endpoint for S3-compatible services. Omit for AWS S3. */
  readonly endpoint?: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  /** Create the bucket if it is absent. Convenient for tests and first boot. */
  readonly createBucketIfMissing?: boolean;
}

export class S3ObjectStorage implements ObjectStorage {
  readonly #client: S3Client;
  readonly #bucket: string;

  constructor(options: S3ObjectStorageOptions) {
    this.#bucket = options.bucket;
    this.#client = new S3Client({
      region: options.region,
      // Path style so a custom endpoint resolves. Harmless against real S3.
      forcePathStyle: options.endpoint !== undefined,
      ...(options.endpoint !== undefined ? { endpoint: options.endpoint } : {}),
      credentials: {
        accessKeyId: options.accessKeyId,
        secretAccessKey: options.secretAccessKey,
      },
    });
  }

  /** Ensure the bucket exists. Safe to call repeatedly. */
  async ensureBucket(): Promise<void> {
    try {
      await this.#client.send(new HeadBucketCommand({ Bucket: this.#bucket }));
      return;
    } catch {
      // Fall through to creation. A HeadBucket failure can mean "absent" or
      // "forbidden", and creation disambiguates: if it also fails, the error from
      // CreateBucket is the informative one.
    }
    try {
      await this.#client.send(new CreateBucketCommand({ Bucket: this.#bucket }));
    } catch (error) {
      const name = (error as { name?: string }).name;
      // Already exists, or owned by someone else. Either way, verify by using it.
      if (name !== "BucketAlreadyOwnedByYou" && name !== "BucketAlreadyExists") throw error;
    }
  }

  /**
   * The S3 key for an artifact.
   *
   * The tenant is a PREFIX, and it is percent-encoded so that a tenant id
   * containing `/` or `..` cannot alter the key's structure. A caller cannot
   * influence the prefix: the port passes a `TenantScope`, and the ref is generated
   * by this class.
   *
   * Note what is NOT relied upon here: S3 has no filesystem, so `..` is not a
   * traversal — it is just a character in a key. The encoding matters anyway,
   * because a tenant id containing `/` would place one tenant's objects under
   * another's prefix, and every listing and lifecycle rule would then be wrong.
   */
  #keyFor(tenant: TenantScope, ref: string): string {
    return `tenants/${encodeURIComponent(tenant.tenantId)}/${ref}`;
  }

  async put(
    tenant: TenantScope,
    artifactId: string,
    bytes: Uint8Array,
    contentType: string,
  ): Promise<{ ref: string; sha256: string }> {
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    // Generated here, never accepted from the caller. A caller that names its own
    // storage key will eventually name one that escapes its prefix.
    const safeId = artifactId.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120);
    const ref = `${safeId}-${randomUUID()}`;

    await this.#client.send(
      new PutObjectCommand({
        Bucket: this.#bucket,
        Key: this.#keyFor(tenant, ref),
        Body: bytes,
        ContentType: contentType,
        // The digest travels WITH the object as metadata. It is also recorded in the
        // evidence table, and the two are compared on read, so a disagreement
        // between storage and the database is detected rather than trusted.
        Metadata: { sha256 },
      }),
    );

    return { ref, sha256 };
  }

  async get(tenant: TenantScope, ref: string): Promise<StoredObject | undefined> {
    let response;
    try {
      response = await this.#client.send(
        new GetObjectCommand({ Bucket: this.#bucket, Key: this.#keyFor(tenant, ref) }),
      );
    } catch (error) {
      const name = (error as { name?: string }).name;
      // Absent, or another tenant's — indistinguishable by construction, since the
      // key is derived from the caller's own tenant prefix. Reported as "absent"
      // rather than as an error, so the two cannot be told apart from outside.
      if (name === "NoSuchKey" || name === "NotFound" || name === "AccessDenied") return undefined;
      throw error;
    }

    if (!response.Body) return undefined;
    const bytes = new Uint8Array(await response.Body.transformToByteArray());

    // Verify on read. Storage is not trusted to have kept the bytes intact, and a
    // silent corruption in an evidence product is a false attestation.
    const expected = response.Metadata?.["sha256"] ?? "";
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (expected === "" || actual !== expected) {
      throw new Error(`stored artifact ${ref} failed its integrity check`);
    }

    return {
      bytes,
      contentType: response.ContentType ?? "application/octet-stream",
      sha256: actual,
    };
  }

  async delete(tenant: TenantScope, ref: string): Promise<void> {
    // S3 delete is idempotent: removing an absent key succeeds. That matches the
    // port's contract without any special handling.
    await this.#client.send(
      new DeleteObjectCommand({ Bucket: this.#bucket, Key: this.#keyFor(tenant, ref) }),
    );
  }

  async close(): Promise<void> {
    this.#client.destroy();
  }
}
