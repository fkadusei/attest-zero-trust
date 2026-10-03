/**
 * Artifact storage — the two rules that make the port worth having.
 *
 * Most of these tests are about failure, not success. A storage adapter that
 * round-trips bytes correctly is unremarkable; one that refuses to serve another
 * tenant's artifact, and that refuses to be talked into reading a file outside its
 * root, is the point.
 *
 * Both adapters run the SAME suite, because the contract is what matters. An
 * adapter that satisfies it differently is fine; one that satisfies it less is a
 * vulnerability, and the tests are the only thing that would say so.
 */
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";

import { InMemoryObjectStorage } from "../src/ports/memory-object-storage.ts";
import { FilesystemObjectStorage } from "../src/ports/filesystem-object-storage.ts";
import { S3ObjectStorage } from "../src/ports/s3-object-storage.ts";
import type { ObjectStorage } from "../src/ports/object-storage.ts";

const ACME = { tenantId: "acme" } as const;
const GLOBEX = { tenantId: "globex" } as const;

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
const text = (b: Uint8Array): string => new TextDecoder().decode(b);

/** The shared contract. Every adapter must satisfy it identically. */
interface Victim {
  cleanup(): Promise<void>;
  stillExists(): Promise<boolean>;
}

function contract(
  name: string,
  make: () => Promise<ObjectStorage>,
  cleanup?: () => Promise<void>,
  plantVictim?: () => Promise<Victim>,
) {
  describe(`object storage contract: ${name}`, () => {
    let storage: ObjectStorage;
    before(async () => {
      storage = await make();
    });
    after(async () => {
      await cleanup?.();
    });

    it("round-trips bytes and reports their SHA-256", async () => {
      const { ref, sha256 } = await storage.put(ACME, "artifact-1", bytes("hello evidence"), "text/plain");
      assert.match(sha256, /^[0-9a-f]{64}$/);
      const got = await storage.get(ACME, ref);
      assert.ok(got, "the artifact should be retrievable by its own tenant");
      assert.equal(text(got.bytes), "hello evidence");
      assert.equal(got.contentType, "text/plain");
      assert.equal(got.sha256, sha256);
    });

    it("returns undefined for a ref that does not exist", async () => {
      assert.equal(await storage.get(ACME, "no-such-artifact-99"), undefined);
    });

    it("REFUSES to serve one tenant's artifact to another", async () => {
      const { ref } = await storage.put(ACME, "private", bytes("acme only"), "text/plain");
      assert.equal(
        await storage.get(GLOBEX, ref),
        undefined,
        "a ref leaked from another tenant must be worthless",
      );
    });

    it("two tenants may use the SAME artifact id without colliding", async () => {
      const a = await storage.put(ACME, "shared-name", bytes("from acme"), "text/plain");
      const b = await storage.put(GLOBEX, "shared-name", bytes("from globex"), "text/plain");
      assert.notEqual(a.ref, b.ref, "refs must not collide across tenants");
      assert.equal(text((await storage.get(ACME, a.ref))!.bytes), "from acme");
      assert.equal(text((await storage.get(GLOBEX, b.ref))!.bytes), "from globex");
    });

    it("delete removes an artifact, and deleting twice is not an error", async () => {
      const { ref } = await storage.put(ACME, "to-delete", bytes("gone"), "text/plain");
      await storage.delete(ACME, ref);
      assert.equal(await storage.get(ACME, ref), undefined);
      await assert.doesNotReject(() => storage.delete(ACME, ref));
    });

    it("deleting via ANOTHER tenant does not remove the artifact", async () => {
      const { ref } = await storage.put(ACME, "keep-me", bytes("still here"), "text/plain");
      await storage.delete(GLOBEX, ref);
      assert.ok(await storage.get(ACME, ref), "another tenant must not be able to delete");
    });

    // ------------------------------------------------------------ traversal
    it("REFUSES a ref that escapes its tenant directory", async (t) => {
      // The first version of this test was WORTHLESS, and mutation testing is what
      // exposed it. It asked for `/etc/passwd` and got `undefined`, which looked
      // like a refusal — but the adapter also reads a `.meta` sidecar, which does
      // not exist for `/etc/passwd`. The read failed for an unrelated reason and the
      // test would have passed on an adapter with no traversal defence at all.
      //
      // A traversal test is only meaningful if the target EXISTS and WOULD BE
      // SERVED. So the victim is planted inside the storage root but outside the
      // tenant directory, with a valid sidecar, and the ref is the relative path to
      // it. If traversal works, this read returns the secret and the test fails.
      if (!plantVictim) return t.skip("this adapter cannot expose a traversal target");
      const secret = await plantVictim();

      for (const evil of [
        "../../secret.txt",
        "..%2F..%2Fsecret.txt",
        "....//....//secret.txt",
        "subdir/../../../secret.txt",
        "%2E%2E%2F%2E%2E%2Fsecret.txt",
      ]) {
        const got = await storage.get(ACME, evil);
        if (got) {
          assert.fail(
            `TRAVERSAL SUCCEEDED with ref ${JSON.stringify(evil)}: ${text(got.bytes).slice(0, 60)}`,
          );
        }
      }
      await secret.cleanup();
    });

    it("REFUSES a traversal ref on DELETE too", async (t) => {
      // A delete that escapes is a destructive primitive, and it is easy to forget
      // that the same validation must apply to every method that takes a ref.
      if (!plantVictim) return t.skip("this adapter cannot expose a traversal target");
      const victim = await plantVictim();
      await storage.delete(ACME, "../../secret.txt");
      assert.equal(
        await victim.stillExists(),
        true,
        "a traversal delete removed a file outside the tenant directory",
      );
      await victim.cleanup();
    });

    it("handles a TENANT ID containing traversal characters", async () => {
      // Tenant ids come from an identity provider and may contain anything. The
      // directory name is derived, so this must stay inside the root.
      const hostile = { tenantId: "../../../etc" };
      const { ref } = await storage.put(hostile, "a", bytes("contained"), "text/plain");
      assert.equal(text((await storage.get(hostile, ref))!.bytes), "contained");
      // And it must not be visible to a legitimate tenant.
      assert.equal(await storage.get(ACME, ref), undefined);
    });

    it("does not confuse tenants whose ids differ only by encoding", async () => {
      const a = await storage.put({ tenantId: "a/b" }, "x", bytes("slash"), "text/plain");
      const b = await storage.put({ tenantId: "a%2Fb" }, "x", bytes("encoded"), "text/plain");
      assert.equal(text((await storage.get({ tenantId: "a/b" }, a.ref))!.bytes), "slash");
      assert.equal(text((await storage.get({ tenantId: "a%2Fb" }, b.ref))!.bytes), "encoded");
    });
  });
}

contract("in-memory", async () => new InMemoryObjectStorage());

let root: string;
contract(
  "filesystem",
  async () => {
    root = await mkdtemp(path.join(tmpdir(), "attest-objstore-"));
    return new FilesystemObjectStorage({ root });
  },
  async () => {
    await rm(root, { recursive: true, force: true });
  },
  async () => {
    const secretText = "TOP SECRET FROM OUTSIDE THE TENANT";
    const victim = path.join(root, "secret.txt");
    // A real content file AND a valid sidecar, so nothing but the traversal defence
    // stands between the caller and the bytes.
    await writeFile(victim, secretText);
    await writeFile(
      `${victim}.meta`,
      JSON.stringify({
        contentType: "text/plain",
        // Must be the true digest, or the integrity check refuses it and the test
        // passes for the wrong reason all over again.
        sha256: createHash("sha256").update(secretText).digest("hex"),
      }),
    );
    return {
      async cleanup() {
        await rm(victim, { force: true });
        await rm(`${victim}.meta`, { force: true });
      },
      async stillExists() {
        return readFile(victim, "utf8").then(
          () => true,
          () => false,
        );
      },
    };
  },
);

// ---------------------------------------------------------------------------
// The THIRD implementation of the same port. Running it through the identical
// contract is the evidence that ADR-015's promise is real: the domain did not
// change when the storage backend did.
//
// It runs against `adobe/s3mock`, so the code path exercised is a real signed
// request to an S3 API rather than a stand-in for one. MinIO was the first choice
// and is NOT used: MinIO removed its Docker Hub images in 2025 and the registry
// proxy here refuses quay.io — verified, not assumed.
// ---------------------------------------------------------------------------
const S3_ENDPOINT = process.env["S3_ENDPOINT"] ?? "http://127.0.0.1:59090";
const S3_BUCKET = process.env["S3_BUCKET"] ?? "attest-evidence";

let s3: S3ObjectStorage | undefined;
contract(
  "s3",
  async () => {
    s3 = new S3ObjectStorage({
      bucket: S3_BUCKET,
      region: "us-east-1",
      endpoint: S3_ENDPOINT,
      accessKeyId: "test",
      secretAccessKey: "test",
    });
    // The harness creates what it depends on. `initialBuckets` on s3mock did not
    // take effect, and relying on it would have made this suite environment-
    // dependent — the failure mode that broke every other CI job in this project.
    await s3.ensureBucket();
    return s3;
  },
  async () => {
    await s3?.close();
  },
  // No victim to plant: S3 has no filesystem, so `..` is a character in a key
  // rather than a traversal. The traversal tests skip for this adapter, with that
  // reason stated rather than silently.
);

describe("filesystem storage, specifics", () => {
  let store: FilesystemObjectStorage;
  let dir: string;

  before(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "attest-fs-specifics-"));
    store = new FilesystemObjectStorage({ root: dir });
  });
  after(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("detects TAMPERING with a stored artifact", async () => {
    // Evidence that silently changes is a false attestation, so corruption is
    // detected rather than served. Simulated by rewriting the file behind the
    // adapter's back, which is what a storage compromise looks like.
    const { ref } = await store.put(ACME, "tamper-me", bytes("original"), "text/plain");
    const files = await readFile(path.join(dir, "tenants", "acme", ref)).catch(() => null);
    assert.ok(files, "the artifact file should exist at the derived path");
    await writeFile(path.join(dir, "tenants", "acme", ref), "replaced");

    await assert.rejects(
      () => store.get(ACME, ref),
      /integrity check/,
      "a modified artifact must be refused, not returned",
    );
  });

  it("keeps every tenant's artifacts in a directory of its own", async () => {
    await store.put(ACME, "iso", bytes("acme"), "text/plain");
    await store.put(GLOBEX, "iso", bytes("globex"), "text/plain");
    const acmeDir = await readFile(path.join(dir, "tenants", "acme", "iso".replace(/.*/, ""))).catch(() => null);
    void acmeDir;
    // The tenant directories are distinct and named from the tenant id.
    const { readdir } = await import("node:fs/promises");
    const tenants = await readdir(path.join(dir, "tenants"));
    assert.ok(tenants.includes("acme"));
    assert.ok(tenants.includes("globex"));
  });
});
