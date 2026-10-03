import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import type { ObjectStorage, StoredObject } from "./object-storage.ts";
import type { TenantScope } from "./policy.ts";

/**
 * Filesystem-backed artifact storage.
 *
 * Persistent, needs no cloud, and runs anywhere a container does — so it is a
 * genuinely useful adapter, not a placeholder. An S3 or GCS adapter implements the
 * same port; which one is used is a deployment decision (ADR-015).
 *
 * ---------------------------------------------------------------------------
 * THE VULNERABILITY THIS FILE EXISTS TO AVOID
 *
 * Storing files under a caller-influenced name is directory traversal, and the
 * usual version is subtle: the code looks safe because it joins a tenant directory
 * and an id, and one of those contains `../`. Three defences, layered:
 *
 *   1. **The tenant directory name is derived, not used raw.** A tenant id comes
 *      from an identity provider and may contain anything. It is percent-encoded
 *      into a single path segment, so `../../etc` becomes `..%2F..%2Fetc` — one
 *      directory name, not three traversals.
 *
 *   2. **The ref is validated against a strict allowlist** before it is used as a
 *      path at all. Anything outside `[A-Za-z0-9._-]` is refused.
 *
 *   3. **The RESOLVED path is checked for containment** in the tenant's directory
 *      after joining. This is the backstop: it does not matter how a traversal was
 *      spelled, if the result is outside the directory it is refused.
 *
 * Defence 3 alone would be sufficient if it were correct, and defences 1 and 2
 * alone would be sufficient if they were complete. All three is what makes this
 * robust to one of them being wrong.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS DELIBERATELY ABSENT
 *
 * **No signed URLs.** They are convenient and they leak: a URL that outlives the
 * authorization decision that produced it is an unauthenticated bearer capability.
 * Reads go through the API, where the policy is re-evaluated on every request,
 * which is the entire premise of the design.
 */
export interface FilesystemObjectStorageOptions {
  /** Root directory. Created if absent. */
  readonly root: string;
}

export class FilesystemObjectStorage implements ObjectStorage {
  readonly #root: string;

  constructor(options: FilesystemObjectStorageOptions) {
    this.#root = path.resolve(options.root);
  }

  /** The directory holding one tenant's artifacts. */
  #tenantDirectory(tenant: TenantScope): string {
    // Percent-encoded, so the tenant id becomes exactly ONE path segment whatever
    // it contains. See defence 1 above.
    return path.join(this.#root, "tenants", encodeURIComponent(tenant.tenantId));
  }

  /**
   * Resolve a stored ref to an absolute path, or throw.
   *
   * Refuses anything that does not resolve to a file inside the tenant's own
   * directory — the backstop that holds even if the earlier defences are wrong.
   */
  #resolveWithinTenant(tenant: TenantScope, ref: string): string {
    // Defence 2: a strict allowlist. The refs this class produces always satisfy
    // it, so a ref that does not is either corrupted or hostile.
    if (!/^[A-Za-z0-9._-]+$/.test(ref) || ref === "." || ref === "..") {
      throw new Error(`refusing a malformed artifact ref: ${JSON.stringify(ref.slice(0, 40))}`);
    }

    const directory = this.#tenantDirectory(tenant);
    const resolved = path.resolve(directory, ref);

    // Defence 3: containment. `path.resolve` has already collapsed any `..`, so
    // this compares final, real paths rather than the strings that produced them.
    if (resolved !== path.join(directory, path.basename(ref)) || !resolved.startsWith(directory + path.sep)) {
      throw new Error("refusing an artifact ref that escapes its tenant directory");
    }
    return resolved;
  }

  async put(
    tenant: TenantScope,
    artifactId: string,
    bytes: Uint8Array,
    contentType: string,
  ): Promise<{ ref: string; sha256: string }> {
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    // The ref is generated HERE. A caller that names its own storage key will
    // eventually name one that escapes its prefix.
    const ref = `${encodeURIComponent(artifactId).replace(/[^A-Za-z0-9._-]/g, "_")}-${randomUUID()}`;
    const directory = this.#tenantDirectory(tenant);
    const target = this.#resolveWithinTenant(tenant, ref);

    await mkdir(directory, { recursive: true });

    // Write to a temporary name and rename. A partially written artifact that then
    // failed its integrity check on read would look like tampering; rename is
    // atomic within a filesystem, so a reader sees either nothing or the whole file.
    const temporary = `${target}.tmp-${randomUUID()}`;
    await writeFile(temporary, bytes);
    await rename(temporary, target);

    // Content type is recorded alongside rather than inferred, because an evidence
    // artifact's type is part of the evidence.
    await writeFile(`${target}.meta`, JSON.stringify({ contentType, sha256 }), "utf8");

    return { ref, sha256 };
  }

  async get(tenant: TenantScope, ref: string): Promise<StoredObject | undefined> {
    let target: string;
    try {
      target = this.#resolveWithinTenant(tenant, ref);
    } catch {
      // A hostile or corrupted ref is "absent", not an error the caller can
      // distinguish. Reporting the difference would tell an attacker whether their
      // traversal attempt was understood.
      return undefined;
    }

    let bytes: Buffer;
    let meta: { contentType: string; sha256: string };
    try {
      bytes = await readFile(target);
      meta = JSON.parse(await readFile(`${target}.meta`, "utf8")) as {
        contentType: string;
        sha256: string;
      };
    } catch {
      return undefined;
    }

    // Verify on read. Storage is not trusted to have kept the bytes intact, and a
    // silent corruption in an evidence product is a false attestation.
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== meta.sha256) {
      throw new Error(`stored artifact ${ref} failed its integrity check`);
    }

    return { bytes: new Uint8Array(bytes), contentType: meta.contentType, sha256: actual };
  }

  async delete(tenant: TenantScope, ref: string): Promise<void> {
    let target: string;
    try {
      target = this.#resolveWithinTenant(tenant, ref);
    } catch {
      return;
    }
    await rm(target, { force: true });
    await rm(`${target}.meta`, { force: true });
  }
}
