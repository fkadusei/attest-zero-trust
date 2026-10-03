/**
 * The process entry point.
 *
 * Deliberately thin. All of it is configuration, dependency construction and
 * shutdown — the decisions live in `server.ts` and the verifiers, where they can be
 * tested without starting a process.
 *
 * It reads configuration, fails fast if something is missing, and listens. It does
 * not reach for credentials, contact a metadata service, or discover anything at
 * runtime: the same image must boot in a container anywhere, and a startup that
 * depends on an environment it cannot see is a startup that hangs instead of
 * telling you what is wrong.
 */
import { loadConfig, ConfigError } from "./config.ts";
import { JwksSource } from "./jwks.ts";
import { readFileSync } from "node:fs";

import { InMemoryReplayCache } from "./ports/replay-cache.ts";
import { InMemoryEvidenceRepository } from "./ports/memory-repository.ts";
import { PostgresEvidenceRepository } from "./ports/postgres-repository.ts";
import type { EvidenceRepository } from "./ports/repository.ts";
import { systemClock } from "./ports/clock.ts";
import { CedarPolicyDecisionPoint, DEFAULT_POLICY_PATH } from "./pdp-cedar.ts";
import { buildServer } from "./server.ts";

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (error) {
    if (error instanceof ConfigError) {
      // Printed rather than thrown so that the reason is the FIRST thing in the
      // logs, not buried under a stack trace about a failed listen.
      console.error(`configuration error: ${error.message}`);
      process.exit(78); // EX_CONFIG
    }
    throw error;
  }

  // The policies are read ONCE, at startup. A policy syntax error stops the
  // process here rather than turning every request into a denial that looks like an
  // authorization problem. The CedarPdp constructor validates and throws.
  let pdp;
  try {
    pdp = new CedarPolicyDecisionPoint({ policies: readFileSync(DEFAULT_POLICY_PATH, "utf8") });
  } catch (error) {
    console.error(`policy error: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(78); // EX_CONFIG
  }

  // Adapter selection. The portable in-memory default needs nothing running; a
  // DATABASE_URL selects PostgreSQL, where RLS enforces the tenant boundary in the
  // engine rather than in our code.
  let evidence: EvidenceRepository;
  if (config.databaseUrl) {
    evidence = new PostgresEvidenceRepository({ connectionString: config.databaseUrl });
  } else {
    evidence = new InMemoryEvidenceRepository();
  }

  const app = buildServer({
    config,
    jwks: new JwksSource(config.identity.jwksUri),
    clock: systemClock,
    replayCache: new InMemoryReplayCache(),
    pdp,
    evidence,
  });

  // Say one thing about the replay cache out loud, because it is the one component
  // whose correctness depends on how many processes are running. An operator who
  // sees this line in a multi-replica deployment has been warned.
  app.log.warn(
    "replay cache is in-process: correct for a single instance, INCORRECT for a fleet. " +
      "A proof replayed to another replica would be treated as fresh.",
  );
  if (config.databaseUrl) {
    app.log.info("evidence repository: PostgreSQL (tenant boundary enforced by Row-Level Security)");
    app.log.warn(
      "verify the database role is NOT a superuser and NOT the table owner — Row-Level Security " +
        "is bypassed by both, silently, leaving the tenant boundary absent.",
    );
  } else {
    app.log.warn(
      "evidence repository is IN-MEMORY: empty on every restart, and each replica has its own. " +
        "Set DATABASE_URL for the PostgreSQL adapter before this serves anyone.",
    );
  }

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, () => {
      app.log.info({ signal }, "shutting down");
      void app.close().then(() => process.exit(0));
    });
  }

  await app.listen({ host: config.http.host, port: config.http.port });
}

await main();
