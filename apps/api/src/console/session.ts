import { randomBytes, createHash } from "node:crypto";

/**
 * Server-side sessions for the admin console.
 *
 * ---------------------------------------------------------------------------
 * WHY TOKENS DO NOT GO IN THE BROWSER
 *
 * The console is a confidential OIDC client. It completes the authorization code
 * flow on the SERVER and keeps the resulting tokens here, in this store. The
 * browser receives only an **opaque session id** in an HttpOnly cookie.
 *
 * That is the whole point. An access token in `localStorage` is readable by any
 * injected script, and an access token in a non-HttpOnly cookie is readable by
 * exactly the same scripts. S4 in this project measured how a browser-side key can
 * be made non-extractable and still survive a restart; the same principle applies
 * to the console, and the strongest version is that **the browser never holds a
 * token at all**.
 *
 * A session id is not a credential being protected: it is worthless without the
 * server-side record, it is not a bearer token for any other service, and it can be
 * revoked by deleting one entry.
 *
 * ---------------------------------------------------------------------------
 * WHAT A SESSION HOLDS, AND WHAT IT DELIBERATELY DOES NOT
 *
 * It holds the tokens and the expiry. It does NOT hold the user's identity fields
 * as authoritative data — the console re-derives those from a **verified token** on
 * every request, through the same `verifyAccessToken` the API uses.
 *
 * A session that carried "this user is an admin" as a stored fact would be a second
 * source of truth that drifts from the token, and the drift would be silent. The
 * session says *which tokens*; the tokens say *who and what*.
 */

export interface ConsoleSession {
  /** Opaque. The only thing the browser ever sees. */
  readonly id: string;
  readonly tokens: {
    readonly accessToken: string;
    readonly refreshToken?: string;
    readonly idToken?: string;
  };
  /** Absolute expiry of the session, in ms since the epoch. */
  readonly expiresAtMs: number;
  /** CSRF token for state-changing form posts. */
  readonly csrfToken: string;
  readonly createdAtMs: number;
}

export interface SessionStore {
  create(tokens: ConsoleSession["tokens"], ttlMs: number): Promise<ConsoleSession>;
  /** Returns undefined for absent OR expired — the caller cannot tell them apart. */
  get(id: string): Promise<ConsoleSession | undefined>;
  /** Replace the tokens after a refresh, keeping the same session id. */
  update(id: string, tokens: ConsoleSession["tokens"], expiresAtMs: number): Promise<void>;
  destroy(id: string): Promise<void>;
}

/**
 * In-memory sessions.
 *
 * Correct for one process and **explicitly wrong for a fleet**: a session created on
 * one replica is unknown to the next, so a user is logged out at random. The
 * portable replacement is a session table, and the port means that is a deployment
 * change rather than a rewrite.
 *
 * Note what else it being in-memory means: **a restart logs everyone out**. For a
 * console that is an annoyance. It is stated because the alternative — assuming
 * persistence that is not there — is how "sessions randomly expire" becomes a
 * mystery.
 */
export class InMemorySessionStore implements SessionStore {
  readonly #sessions = new Map<string, ConsoleSession>();

  async create(tokens: ConsoleSession["tokens"], ttlMs: number): Promise<ConsoleSession> {
    const now = Date.now();
    const session: ConsoleSession = {
      // 32 bytes from the CSPRNG. Not a counter, not a UUID: a session id that can be
      // guessed is an authentication bypass, and UUIDv4's 122 bits are fine but
      // there is no reason to take the smaller number or the weaker promise.
      id: randomBytes(32).toString("base64url"),
      tokens,
      expiresAtMs: now + ttlMs,
      csrfToken: randomBytes(32).toString("base64url"),
      createdAtMs: now,
    };
    this.#sessions.set(session.id, session);
    return session;
  }

  async get(id: string): Promise<ConsoleSession | undefined> {
    const session = this.#sessions.get(id);
    if (!session) return undefined;
    if (session.expiresAtMs <= Date.now()) {
      // Expired sessions are removed on sight rather than left to a sweeper. The
      // lookup is the only moment it matters.
      this.#sessions.delete(id);
      return undefined;
    }
    return session;
  }

  async update(id: string, tokens: ConsoleSession["tokens"], expiresAtMs: number): Promise<void> {
    const session = this.#sessions.get(id);
    if (!session) return;
    this.#sessions.set(id, { ...session, tokens, expiresAtMs });
  }

  async destroy(id: string): Promise<void> {
    this.#sessions.delete(id);
  }

  /** Test helper. */
  get size(): number {
    return this.#sessions.size;
  }
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

/**
 * A cookie-authenticated console needs CSRF protection, and `SameSite=Lax` is not
 * sufficient on its own: it permits top-level GET navigations, and it is a browser
 * behaviour rather than a server-side check. An old browser that ignores it would
 * silently lose the protection with nothing in the logs to say so.
 *
 * So the check is explicit. Every state-changing request must carry the session's
 * CSRF token, compared in constant time.
 */
export function csrfTokenMatches(expected: string, presented: string | undefined): boolean {
  if (typeof presented !== "string" || presented.length !== expected.length) return false;
  // Constant-time. A byte-by-byte comparison leaks the token one character at a
  // time to an attacker who can measure; the token is short enough for that to be
  // practical.
  return timingSafeEqualStrings(expected, presented);
}

function timingSafeEqualStrings(a: string, b: string): boolean {
  // Hashing first sidesteps length-dependent timing in the XOR loop while keeping
  // the comparison constant-time for equal-length inputs.
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= (ha[i] ?? 0) ^ (hb[i] ?? 0);
  return diff === 0;
}
