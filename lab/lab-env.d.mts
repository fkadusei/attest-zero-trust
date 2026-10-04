/**
 * Types for `lab-env.mjs`.
 *
 * The test harnesses are TypeScript and the credential loader is JavaScript, because
 * the browser harnesses are JavaScript too — one loader read by both, rather than two
 * copies that drift. TypeScript needs to be told the shape.
 *
 * This exists because the alternative was `TS7016: implicitly has an 'any' type`, which
 * the typecheck correctly treats as an error: an untyped credential loader is exactly
 * the kind of thing that returns `undefined` and gets interpolated into a connection
 * string.
 */

/** One credential. The environment wins over `lab/.env`. */
export declare function labCredential(name: string): string;

/** Every lab credential, creating `lab/.env` if it does not exist. */
export declare function labCredentials(): Record<string, string>;

/** The Keycloak administration password for the lab realm. */
export declare const KEYCLOAK_ADMIN_PASSWORD: string;

/** The password of the container's own PostgreSQL superuser role, `attest_owner`. */
export declare const POSTGRES_PASSWORD: string;

/**
 * The password of `attest_app`, created by `lab/app/init/01-schema.sh`.
 *
 * This role is deliberately NOT a superuser and NOT the table owner, because
 * PostgreSQL Row-Level Security is bypassed by superusers always and by the owner
 * unless FORCE is set. It is the role the application actually connects as.
 */
export declare const APP_DB_APP_PASSWORD: string;
