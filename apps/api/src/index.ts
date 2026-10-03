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
import { InMemoryReplayCache } from "./ports/replay-cache.ts";
import { systemClock } from "./ports/clock.ts";
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

  const app = buildServer({
    config,
    jwks: new JwksSource(config.identity.jwksUri),
    clock: systemClock,
    replayCache: new InMemoryReplayCache(),
  });

  // Say one thing about the replay cache out loud, because it is the one component
  // whose correctness depends on how many processes are running. An operator who
  // sees this line in a multi-replica deployment has been warned.
  app.log.warn(
    "replay cache is in-process: correct for a single instance, INCORRECT for a fleet. " +
      "A proof replayed to another replica would be treated as fresh.",
  );

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, () => {
      app.log.info({ signal }, "shutting down");
      void app.close().then(() => process.exit(0));
    });
  }

  await app.listen({ host: config.http.host, port: config.http.port });
}

await main();
