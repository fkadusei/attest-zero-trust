import { randomBytes } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
// Imported for its type augmentation: it adds `request.cookies`, `reply.setCookie`
// and `reply.clearCookie` to Fastify's types. Without it those are type errors even
// though the plugin registers them at runtime.
import "@fastify/cookie";
import "@fastify/multipart";

import type { ConsoleSession, SessionStore } from "./session.ts";
import { csrfTokenMatches } from "./session.ts";
import type { OidcClient } from "./oidc.ts";

/**
 * What the console needs from an OIDC client.
 *
 * Narrowed deliberately. The console does not care how tokens are obtained, only
 * that they are — so a test can supply a stub for the PROVIDER while every call to
 * the API still carries a genuinely signed token. That keeps the interesting
 * assertions about the policy honest: the stub replaces Keycloak's redirect dance,
 * not the verification.
 */
export interface ConsoleOidc {
  buildAuthorizationUrl(
    flow: { state: string; nonce: string },
    options?: { acrValues?: string; prompt?: string },
  ): Promise<string>;
  exchangeCode(code: string): Promise<{ accessToken: string; refreshToken?: string; idToken?: string; expiresInSec: number }>;
  refresh(refreshToken: string): Promise<{ accessToken: string; refreshToken?: string; idToken?: string; expiresInSec: number }>;
  buildLogoutUrl(idToken: string | undefined, postLogoutRedirect: string): Promise<string | undefined>;
  /** Instance form so a stub can implement it; delegates to the static below. */
  idTokenMatchesNonce(idToken: string | undefined, expectedNonce: string): boolean;
}

/** The subset of `OidcClient` the console uses. Satisfied structurally. */
export type { OidcClient };

/**
 * The admin console: server-rendered, and a client of the API rather than a
 * privileged path into it.
 *
 * ---------------------------------------------------------------------------
 * THE RULE THAT SHAPES THIS FILE
 *
 * **The console does not get to skip the policy.** Every piece of data it shows
 * comes from the API, fetched with the user's own access token over HTTP, so the
 * same `authenticate` → `authorize` chain runs as for any other caller. It would
 * have been far easier to read the repository directly — the code is right there —
 * and that is exactly how an admin console becomes a bypass: a second path to the
 * data that does not pass through the checks, which nobody notices until it is the
 * incident.
 *
 * The cost is a loopback HTTP call per page. That is a real cost and it is worth
 * paying: the alternative is a second authorisation implementation, and a second
 * implementation is a second place to be wrong.
 *
 * ---------------------------------------------------------------------------
 * THE COOKIES
 *
 * | Cookie | Holds | Flags |
 * |---|---|---|
 * | `attest_session` | an opaque session id | HttpOnly, SameSite=Lax, Secure, Path=/console |
 * | `attest_flow` | `state` and `nonce` for one login | HttpOnly, SameSite=Lax, Secure, Path=/console, short-lived |
 *
 * **HttpOnly** because a session id readable by an injected script is a session an
 * injected script can use. **SameSite=Lax** so a cross-site request does not carry
 * it. **Path=/console** so it is not sent to the API. **Secure** unless the origin
 * is loopback, because over plain HTTP off loopback the cookie is interceptable.
 *
 * The token itself is in NEITHER. It is server-side, and the browser never sees it.
 */

export interface ConsoleDeps {
  readonly sessions: SessionStore;
  readonly oidc: ConsoleOidc;
  /** Where the API is reachable. The console calls it like any other client. */
  readonly apiBaseUrl: string;
  /** Public base URL of the console itself, for building redirect URIs. */
  readonly consoleBaseUrl: string;
  /** Session lifetime. */
  readonly sessionTtlMs?: number;
}

const SESSION_COOKIE = "attest_session";
const FLOW_COOKIE = "attest_flow";
const COOKIE_PATH = "/console";

function isLoopback(url: string): boolean {
  try {
    const host = new URL(url).hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".localhost");
  } catch {
    return false;
  }
}

function cookieOptions(baseUrl: string, maxAgeSec: number) {
  return {
    path: COOKIE_PATH,
    httpOnly: true,
    sameSite: "lax" as const,
    // Left off for loopback so the local lab works over plain HTTP, exactly as the
    // config's HTTPS rule does. A `Secure` cookie on `http://localhost` is silently
    // dropped by the browser, which would look like "login does nothing".
    secure: !isLoopback(baseUrl),
    maxAge: maxAgeSec,
  };
}

/** Minimal HTML escaping. Every interpolated value goes through this. */
function esc(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function page(title: string, body: string, csrf?: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} — Attest</title>
<meta name="referrer" content="same-origin">
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; margin: 0; }
  header { padding: 12px 20px; border-bottom: 1px solid #8883; display: flex; gap: 16px; align-items: center; }
  header strong { margin-right: auto; }
  main { padding: 20px; max-width: 60rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #8882; }
  code { font-family: ui-monospace, monospace; font-size: 13px; }
  form { display: inline; }
  button { font: inherit; padding: 6px 12px; cursor: pointer; }
  .muted { opacity: 0.7; }
</style>
</head>
<body>
<header>
  <strong>Attest</strong>
  ${csrf ? `<form method="post" action="/console/logout"><input type="hidden" name="csrf" value="${esc(csrf)}"><button type="submit">Sign out</button></form>` : ""}
</header>
<main>${body}</main>
</body>
</html>`;
}

/**
 * Fetch from the API using the SESSION's token.
 *
 * The token is the user's own, so the API applies the user's own policy. The
 * console cannot ask for anything the user could not.
 */
async function api(
  deps: ConsoleDeps,
  session: ConsoleSession,
  path: string,
  init: RequestInit = {},
): Promise<{ status: number; body: unknown; text: string }> {
  const response = await fetch(`${deps.apiBaseUrl}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${session.tokens.accessToken}`,
      ...(init.headers ?? {}),
    },
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  let body: unknown = undefined;
  try {
    body = JSON.parse(text);
  } catch {
    // Not JSON. Kept as text so a proxy's HTML error page is not mistaken for a
    // structured response — an HTML body would otherwise look like a successful
    // empty result.
  }
  return { status: response.status, body, text };
}

export function registerConsole(app: FastifyInstance, deps: ConsoleDeps): void {
  const ttlSec = Math.floor((deps.sessionTtlMs ?? 8 * 60 * 60 * 1000) / 1000);

  /** Load the session, refreshing the token when it is close to expiry. */
  async function currentSession(request: FastifyRequest): Promise<ConsoleSession | undefined> {
    const id = request.cookies[SESSION_COOKIE];
    if (typeof id !== "string" || id === "") return undefined;
    const session = await deps.sessions.get(id);
    if (!session) return undefined;

    // Refresh only when the access token is nearly expired, decided from the token
    // itself rather than from a stored timestamp that could drift from it.
    const exp = tokenExpiry(session.tokens.accessToken);
    if (exp !== undefined && exp - Date.now() < 60_000 && session.tokens.refreshToken) {
      try {
        const refreshed = await deps.oidc.refresh(session.tokens.refreshToken);
        const tokens = {
          accessToken: refreshed.accessToken,
          ...(refreshed.refreshToken ? { refreshToken: refreshed.refreshToken } : {}),
          ...(refreshed.idToken ? { idToken: refreshed.idToken } : {}),
        };
        const expiresAtMs = Date.now() + Math.min(ttlSec * 1000, refreshed.expiresInSec * 1000);
        await deps.sessions.update(session.id, tokens, expiresAtMs);
        return { ...session, tokens, expiresAtMs };
      } catch {
        // A failed refresh ends the session rather than continuing with a token
        // that is about to expire. Continuing would produce a confusing sequence of
        // 401s from the API.
        await deps.sessions.destroy(session.id);
        return undefined;
      }
    }
    return session;
  }

  function requireSession(session: ConsoleSession | undefined, reply: FastifyReply): session is ConsoleSession {
    if (!session) {
      reply.redirect("/console/login", 302);
      return false;
    }
    return true;
  }

  // ---------------------------------------------------------------- login
  app.get("/console/login", async (request, reply) => {
    // `state` and `nonce` are generated together, stored in a short-lived cookie,
    // and both are single-use: the callback clears the cookie whatever happens.
    const flow = { state: randomBytes(32).toString("base64url"), nonce: randomBytes(32).toString("base64url") };
    reply.setCookie(FLOW_COOKIE, JSON.stringify(flow), cookieOptions(deps.consoleBaseUrl, 600));
    const url = await deps.oidc.buildAuthorizationUrl(flow);
    return reply.redirect(url, 302);
  });

  app.get("/console/callback", async (request, reply) => {
    const query = request.query as Record<string, string | undefined>;
    const raw = request.cookies[FLOW_COOKIE];
    // Clear it immediately: a `state` that can be replayed is not a state check.
    reply.clearCookie(FLOW_COOKIE, { path: COOKIE_PATH });

    if (typeof raw !== "string") {
      return reply.code(400).send(page("Sign-in failed", "<p>The sign-in attempt expired. Please try again.</p>"));
    }
    let flow: { state?: string; nonce?: string };
    try {
      flow = JSON.parse(raw) as { state?: string; nonce?: string };
    } catch {
      return reply.code(400).send(page("Sign-in failed", "<p>Malformed sign-in state.</p>"));
    }

    // `state` protects the REDIRECT. Without it, an attacker can make a victim's
    // browser finish a flow the victim never started — and end up signed in as the
    // attacker, doing work inside the attacker's account.
    if (typeof flow.state !== "string" || query["state"] !== flow.state) {
      request.log.warn("console callback rejected: state mismatch");
      return reply.code(400).send(page("Sign-in failed", "<p>This sign-in could not be verified.</p>"));
    }

    const error = query["error"];
    if (typeof error === "string") {
      // The provider's error code is safe to show; its description is not, because
      // it can echo request parameters.
      return reply
        .code(400)
        .send(page("Sign-in failed", `<p>The identity provider refused the sign-in (<code>${esc(error)}</code>).</p>`));
    }

    const code = query["code"];
    if (typeof code !== "string" || code === "") {
      return reply.code(400).send(page("Sign-in failed", "<p>No authorization code was returned.</p>"));
    }

    let tokens;
    try {
      tokens = await deps.oidc.exchangeCode(code);
    } catch (exchangeError) {
      request.log.error({ err: String(exchangeError) }, "console token exchange failed");
      return reply.code(502).send(page("Sign-in failed", "<p>Could not complete sign-in.</p>"));
    }

    // `nonce` protects the ID TOKEN: a token issued for a different flow must not be
    // substitutable into this one. A missing nonce in the stored flow is a failure,
    // not a skipped check.
    if (typeof flow.nonce !== "string" || !deps.oidc.idTokenMatchesNonce(tokens.idToken, flow.nonce)) {
      request.log.warn("console callback rejected: id_token nonce mismatch");
      return reply.code(400).send(page("Sign-in failed", "<p>This sign-in could not be verified.</p>"));
    }

    const session = await deps.sessions.create(
      {
        accessToken: tokens.accessToken,
        ...(tokens.refreshToken ? { refreshToken: tokens.refreshToken } : {}),
        ...(tokens.idToken ? { idToken: tokens.idToken } : {}),
      },
      deps.sessionTtlMs ?? 8 * 60 * 60 * 1000,
    );
    reply.setCookie(SESSION_COOKIE, session.id, cookieOptions(deps.consoleBaseUrl, ttlSec));
    return reply.redirect("/console", 302);
  });

  // ---------------------------------------------------------------- logout
  app.post("/console/logout", async (request, reply) => {
    const session = await currentSession(request);
    const body = (request.body ?? {}) as Record<string, unknown>;

    // CSRF on a state-changing POST. The session cookie is SameSite=Lax, which is
    // not sufficient alone: it is a browser behaviour, and an old browser that
    // ignores it would silently lose the protection.
    if (!session || !csrfTokenMatches(session.csrfToken, typeof body["csrf"] === "string" ? (body["csrf"] as string) : undefined)) {
      reply.clearCookie(SESSION_COOKIE, { path: COOKIE_PATH });
      return reply.redirect("/console/login", 302);
    }

    const idToken = session.tokens.idToken;
    await deps.sessions.destroy(session.id);
    reply.clearCookie(SESSION_COOKIE, { path: COOKIE_PATH });

    // End the SSO session too. Clearing only our cookie would leave the user signed
    // in at the provider, so the next visit would silently sign them back in —
    // which is not what "sign out" means to anyone who clicks it.
    const logoutUrl = await deps.oidc.buildLogoutUrl(idToken, `${deps.consoleBaseUrl}/console/login`);
    return reply.redirect(logoutUrl ?? "/console/login", 302);
  });

  // ---------------------------------------------------------------- create
  app.get("/console/evidence/new", async (request, reply) => {
    const session = await currentSession(request);
    if (!requireSession(session, reply)) return reply;
    return reply.send(page("New evidence", newEvidenceForm(session.csrfToken), session.csrfToken));
  });

  /**
   * Create an evidence record and upload its artifact.
   *
   * Two API calls, not one, because they are two different authorisations: creating
   * a record is `CreateEvidence` against the tenant, and attaching bytes to it is
   * `WriteEvidence` against the record. Doing them as one API operation would hide
   * that distinction, and the distinction is the point.
   *
   * The console forwards the bytes UNCHANGED. It does not hash them, and it does not
   * tell the API what the digest is — the API computes it from what it receives. A
   * console that computed the hash would be attesting to content on the user's
   * behalf, which is not the same as storing it.
   */
  app.post("/console/evidence", async (request, reply) => {
    const session = await currentSession(request);
    if (!requireSession(session, reply)) return reply;

    let parts;
    try {
      parts = request.parts();
    } catch {
      return reply.code(400).send(page("New evidence", "<p>Malformed upload.</p>", session.csrfToken));
    }

    let csrf: string | undefined;
    let control = "";
    let file: { bytes: Buffer; contentType: string } | undefined;

    for await (const part of parts) {
      if (part.type === "field") {
        if (part.fieldname === "csrf") csrf = String(part.value);
        if (part.fieldname === "control") control = String(part.value).trim();
      } else if (part.type === "file") {
        // Bounded. An unbounded read of a request body is a memory exhaustion
        // primitive, and this one is reachable by any signed-in writer.
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of part.file) {
          size += chunk.length;
          if (size > 20 * 1024 * 1024) {
            return reply.code(413).send(page("New evidence", "<p>That file is too large.</p>", session.csrfToken));
          }
          chunks.push(chunk as Buffer);
        }
        // An empty file part is what a browser sends when no file was chosen. It is
        // not an artifact, and storing zero bytes would produce evidence that
        // attests to nothing.
        if (size > 0) {
          file = { bytes: Buffer.concat(chunks), contentType: part.mimetype || "application/octet-stream" };
        }
      }
    }

    // CSRF AFTER parsing, because the token arrives as a field. Same check, later
    // point — the request has already been fully received either way.
    if (!csrfTokenMatches(session.csrfToken, csrf)) {
      request.log.warn("console create rejected: csrf");
      return reply.code(403).send(page("New evidence", "<p>That form could not be verified.</p>", session.csrfToken));
    }
    if (control === "") {
      return reply.code(400).send(page("New evidence", `<p>${esc("A control name is required.")}</p>`, session.csrfToken));
    }

    const created = await api(deps, session, "/v1/evidence", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ control }),
    });
    if (created.status !== 201) {
      return reply
        .code(created.status === 403 ? 403 : 502)
        .send(page("New evidence", `<p>Could not create the record (${esc(created.status)}).</p>`, session.csrfToken));
    }
    const id = String((created.body as { id?: unknown })?.id ?? "");

    if (file) {
      const uploaded = await api(deps, session, `/v1/evidence/${encodeURIComponent(id)}/content`, {
        method: "PUT",
        headers: { "content-type": file.contentType },
        body: file.bytes,
      });
      if (uploaded.status !== 201) {
        // The record exists; the artifact does not. Reported rather than hidden: a
        // record with no artifact is a real state an operator needs to see.
        return reply
          .code(502)
          .send(page("New evidence", `<p>The record was created but the file was not stored (${esc(uploaded.status)}).</p>`, session.csrfToken));
      }
    }

    return reply.redirect(`/console/evidence/${encodeURIComponent(id)}`, 302);
  });

  // ---------------------------------------------------------------- pages
  app.get<{ Querystring: { cursor?: string } }>("/console", async (request, reply) => {
    const session = await currentSession(request);
    if (!requireSession(session, reply)) return reply;

    // Pagination is a cursor, not an offset. An offset over a changing set skips or
    // repeats rows, which in an evidence product means a record that appears to be
    // missing.
    const cursor = typeof (request.query as Record<string, unknown>)["cursor"] === "string"
      ? String((request.query as Record<string, unknown>)["cursor"])
      : undefined;
    const listPath = cursor ? `/v1/evidence?cursor=${encodeURIComponent(cursor)}` : "/v1/evidence";
    const result = await api(deps, session, listPath);
    if (result.status === 401) {
      await deps.sessions.destroy(session.id);
      reply.clearCookie(SESSION_COOKIE, { path: COOKIE_PATH });
      return reply.redirect("/console/login", 302);
    }
    if (result.status !== 200) {
      return reply
        .code(502)
        .send(page("Evidence", `<p class="muted">The API returned ${esc(result.status)}.</p>`, session.csrfToken));
    }

    const items = ((result.body as { items?: Array<{ id: string; control: string }> })?.items ?? []);
    const rows = items
      .map(
        (item) =>
          `<tr><td><a href="/console/evidence/${encodeURIComponent(item.id)}"><code>${esc(item.id)}</code></a></td><td>${esc(item.control)}</td></tr>`,
      )
      .join("");
    const nextCursor = (result.body as { nextCursor?: string })?.nextCursor;
    const pagination = nextCursor
      ? `<p><a href="/console?cursor=${encodeURIComponent(nextCursor)}">Next page &rarr;</a></p>`
      : "";
    const body =
      (items.length === 0
        ? "<p class=\"muted\">No evidence yet.</p>"
        : `<table><thead><tr><th>ID</th><th>Control</th></tr></thead><tbody>${rows}</tbody></table>`) +
      pagination +
      '<p><a href="/console/evidence/new">Add evidence</a></p>';
    return reply.send(page("Evidence", body, session.csrfToken));
  });

  app.get<{ Params: { id: string } }>("/console/evidence/:id", async (request, reply) => {
    const session = await currentSession(request);
    if (!requireSession(session, reply)) return reply;

    const id = request.params.id;
    const result = await api(deps, session, `/v1/evidence/${encodeURIComponent(id)}`);
    if (result.status === 404) {
      return reply.code(404).send(page("Not found", "<p>No such evidence.</p>", session.csrfToken));
    }
    if (result.status !== 200) {
      return reply
        .code(502)
        .send(page("Evidence", `<p class="muted">The API returned ${esc(result.status)}.</p>`, session.csrfToken));
    }

    const record = result.body as Record<string, unknown>;
    const body = `<h1><code>${esc(record["id"])}</code></h1>
<dl>
  <dt>Control</dt><dd>${esc(record["control"])}</dd>
  <dt>Collected</dt><dd>${esc(record["collectedAt"])}</dd>
  <dt>SHA-256</dt><dd><code>${esc(record["sha256"])}</code></dd>
</dl>
<p><a href="/console">Back</a></p>`;
    return reply.send(page(String(record["id"]), body, session.csrfToken));
  });
}

/**
 * The create form.
 *
 * `multipart/form-data` so a file can be attached, and `enctype` is stated
 * explicitly because a browser defaults to urlencoded and the file would be
 * silently dropped — the form would appear to work and store no artifact.
 */
function newEvidenceForm(csrf: string): string {
  return `<h1>Add evidence</h1>
<form method="post" action="/console/evidence" enctype="multipart/form-data">
  <input type="hidden" name="csrf" value="${esc(csrf)}">
  <p>
    <label for="control">Control</label><br>
    <input id="control" name="control" required maxlength="200" placeholder="SOC2-CC6.1" style="width: 20rem">
  </p>
  <p>
    <label for="file">Artifact</label><br>
    <input id="file" name="file" type="file">
  </p>
  <p><button type="submit">Create</button> <a href="/console">Cancel</a></p>
</form>`;
}

/** `exp` from a JWT payload, in ms. Undefined when absent or unreadable. */
function tokenExpiry(token: string): number | undefined {
  const segment = token.split(".")[1];
  if (!segment) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as { exp?: number };
    return typeof payload.exp === "number" ? payload.exp * 1000 : undefined;
  } catch {
    return undefined;
  }
}
