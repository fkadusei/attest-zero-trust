/**
 * Lab credentials for the JavaScript harnesses.
 *
 * The counterpart to `lab/keycloak/scripts/lab_env.py`, reading the same `lab/.env`.
 * Both languages have harnesses, so both need to read the file — but the FORMAT is
 * shared and only the file is authoritative, so there is no second source of truth.
 *
 * See the Python module for why this exists at all. The short version: a hardcoded
 * password in a public repository is a hardcoded password in a public repository,
 * and GitHub's scanner is right to flag it. The value is generated instead.
 *
 * This generates the file if it is absent, so a JavaScript-first run works without
 * someone having to run a Python script first — a setup step that would be
 * discovered only by failing.
 */
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, appendFileSync, chmodSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// This file IS in lab/, so the lab directory is its own directory. Resolving to the
// parent silently created a SECOND .env at the repository root, with different
// values — and the resulting "invalid credentials" looked like a Keycloak problem
// rather than a path bug.
const LAB_DIR = path.dirname(fileURLToPath(import.meta.url));
const ENV_FILE = path.join(LAB_DIR, ".env");

const VARIABLES = {
  LAB_KEYCLOAK_ADMIN_PASSWORD: 24,
  LAB_POSTGRES_PASSWORD: 24,
  LAB_APP_DB_APP_PASSWORD: 24,
};

/** `token_urlsafe`-equivalent: 24 bytes of entropy, base64url, no padding. */
const generate = (bytes) => randomBytes(bytes).toString("base64url");

function readEnvFile() {
  const values = {};
  if (!existsSync(ENV_FILE)) return values;
  for (const line of readFileSync(ENV_FILE, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const index = trimmed.indexOf("=");
    values[trimmed.slice(0, index).trim()] = trimmed.slice(index + 1).trim();
  }
  return values;
}

let cache;

/** The lab credentials, creating `lab/.env` if it does not exist. */
export function labCredentials() {
  if (cache) return cache;
  const values = readEnvFile();

  const missing = {};
  for (const [name, bytes] of Object.entries(VARIABLES)) {
    if (!values[name]) missing[name] = generate(bytes);
  }
  if (Object.keys(missing).length > 0) {
    Object.assign(values, missing);
    // Appended rather than rewritten: a hand-edited file keeps what it had, and a
    // partial file gains only what it lacked.
    appendFileSync(ENV_FILE, Object.entries(missing).map(([k, v]) => `${k}=${v}\n`).join(""));
    try {
      chmodSync(ENV_FILE, 0o600);
    } catch {
      // Best effort. A world-readable lab credential on a throwaway container is not
      // worth failing a test run over.
    }
  }

  cache = values;
  return values;
}

/**
 * One credential. The environment wins over the file, so CI can supply its own and
 * an operator can override without editing anything.
 */
export function labCredential(name) {
  const fromEnvironment = process.env[name];
  if (fromEnvironment) return fromEnvironment;
  return labCredentials()[name];
}

export const KEYCLOAK_ADMIN_PASSWORD = labCredential("LAB_KEYCLOAK_ADMIN_PASSWORD");
export const POSTGRES_PASSWORD = labCredential("LAB_POSTGRES_PASSWORD");
export const APP_DB_OWNER_PASSWORD = labCredential("LAB_APP_DB_OWNER_PASSWORD");
export const APP_DB_APP_PASSWORD = labCredential("LAB_APP_DB_APP_PASSWORD");
