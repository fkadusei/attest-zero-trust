/**
 * Configuration, read from the environment and validated at startup.
 *
 * Two rules make this cloud-agnostic, and both are easy to break later:
 *
 * 1. **The core knows nothing about any cloud.** There is no `AWS_REGION`, no
 *    bucket name, no table name here. Those belong to the *adapters* that need
 *    them, and an adapter reads its own settings. If a cloud concept appears in
 *    this file, the boundary has already leaked.
 *
 * 2. **Configuration is inert.** Reading it makes no network calls, resolves no
 *    credentials and contacts no metadata service. Startup must succeed — or fail
 *    for a stated reason — with nothing running. This is what lets the same image
 *    boot in a container anywhere, and it is why the failure mode is a clear
 *    message rather than a hang against an instance metadata endpoint.
 *
 * Validation is explicit rather than decorative: TypeScript types vanish at
 * runtime, and this project's premise is not trusting inputs. Environment
 * variables are an input.
 */

export interface IdentityConfig {
  /** Exact expected `iss`. Compared character for character. */
  readonly issuer: string;
  /** Where the issuer publishes its signing keys. Must be the ISSUER's own URL. */
  readonly jwksUri: string;
  /** This API's client id — the audience a token must have been issued for. */
  readonly audience: string;
}

export interface HttpConfig {
  readonly host: string;
  readonly port: number;
}

export interface AppConfig {
  readonly identity: IdentityConfig;
  /**
   * The public base URL this API is reached at, e.g. `https://api.example.com`.
   *
   * REQUIRED, and deliberately trusted configuration rather than derived from the
   * request. DPoP's `htu` check compares the proof against the URI the request was
   * made to; deriving that from `X-Forwarded-Proto` or `Host` would let the
   * ATTACKER choose the value the proof is compared against, making every `htu`
   * check vacuous while still appearing present. A proxy may rewrite those
   * headers; this value is ours.
   */
  readonly publicBaseUrl: string;
  /** Claim the tenant id is read from. Read only from a VERIFIED token (ADR-006). */
  readonly tenantClaim: string;
  /** Permitted clock skew against the identity provider, in seconds. */
  readonly clockToleranceSec: number;
  readonly http: HttpConfig;
  /**
   * Where evidence is stored.
   *
   * Absent means the in-memory adapter — the PORTABLE DEFAULT under ADR-015, which
   * needs nothing running and is what a laptop and CI use. Present selects the
   * PostgreSQL adapter, whose Row-Level Security enforces the tenant boundary in
   * the database rather than in our code.
   *
   * The connection string must be for the APPLICATION role, never a superuser.
   * Row-Level Security is bypassed by superusers and by table owners, silently —
   * see lab/app/init/01-schema.sql. The startup log warns if the role looks wrong.
   */
  readonly databaseUrl?: string;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

type Env = Record<string, string | undefined>;

function required(env: Env, name: string): string {
  const value = env[name];
  if (value === undefined || value.trim() === "") {
    throw new ConfigError(`missing required environment variable ${name}`);
  }
  return value;
}

function integer(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value)) {
    throw new ConfigError(`${name} must be an integer, got ${JSON.stringify(raw)}`);
  }
  if (value < min || value > max) {
    throw new ConfigError(`${name} must be between ${min} and ${max}, got ${value}`);
  }
  return value;
}

/**
 * Build the configuration, or throw with a message that names the problem.
 *
 * `KEYCLOAK_JWKS_URI` is optional and derived from the issuer when absent. It is
 * overridable **only** so that a deployment behind a split-horizon DNS setup can
 * point at an internal address — never so that it can point somewhere unrelated to
 * the issuer. A verifier that trusts a JWKS URI taken from the token it is
 * checking trusts keys of the attacker's choosing, so the value is pinned here, at
 * startup, from configuration a caller cannot influence.
 */
export function loadConfig(env: Env = process.env): AppConfig {
  const issuer = required(env, "KEYCLOAK_ISSUER").replace(/\/+$/, "");
  const jwksUri = env["KEYCLOAK_JWKS_URI"]?.trim() || `${issuer}/protocol/openid-connect/certs`;

  let parsedIssuer: URL;
  try {
    parsedIssuer = new URL(issuer);
  } catch {
    throw new ConfigError(`KEYCLOAK_ISSUER is not a valid absolute URL: ${issuer}`);
  }
  // An issuer reached over plain HTTP is only acceptable for loopback. Anywhere
  // else it means tokens can be intercepted and replayed, which would make every
  // other control in this system decorative.
  if (parsedIssuer.protocol !== "https:" && !isLoopback(parsedIssuer.hostname)) {
    throw new ConfigError(
      `KEYCLOAK_ISSUER must use https:// unless it is loopback, got ${issuer}`,
    );
  }

  const publicBaseUrl = required(env, "PUBLIC_BASE_URL").replace(/\/+$/, "");
  let parsedBase: URL;
  try {
    parsedBase = new URL(publicBaseUrl);
  } catch {
    throw new ConfigError(`PUBLIC_BASE_URL is not a valid absolute URL: ${publicBaseUrl}`);
  }
  if (parsedBase.protocol !== "https:" && !isLoopback(parsedBase.hostname)) {
    throw new ConfigError(
      `PUBLIC_BASE_URL must use https:// unless it is loopback, got ${publicBaseUrl}`,
    );
  }

  const databaseUrl = env["DATABASE_URL"]?.trim();

  return {
    identity: { issuer, jwksUri, audience: required(env, "API_AUDIENCE") },
    publicBaseUrl,
    ...(databaseUrl ? { databaseUrl } : {}),
    tenantClaim: env["TENANT_CLAIM"]?.trim() || "tenant_id",
    clockToleranceSec: integer(env, "CLOCK_TOLERANCE_SEC", 5, 0, 120),
    http: {
      host: env["HTTP_HOST"]?.trim() || "0.0.0.0",
      port: integer(env, "HTTP_PORT", 3000, 1, 65535),
    },
  };
}

function isLoopback(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1" ||
    hostname.endsWith(".localhost")
  );
}
