import { decodeJwt } from "jose";

/**
 * The OIDC authorization code flow, as a CONFIDENTIAL client.
 *
 * ---------------------------------------------------------------------------
 * WHY THE CONSOLE IS A CONFIDENTIAL CLIENT, AND WHAT THAT COSTS
 *
 * This is a server-rendered console, so the tokens live on the server (see
 * `session.ts`). That rules out DPoP for these tokens, and it is worth being
 * explicit about why, because DPoP is the centrepiece of the rest of this system.
 *
 * DPoP binds a token to a private key the CLIENT holds. For the console to present
 * a proof on every request, it would need that private key — and the only place it
 * could live is the browser, which reintroduces exactly the problem the session
 * store exists to remove. A server-rendered console cannot be a DPoP client without
 * becoming a browser-side application.
 *
 * So the console authenticates with a **client secret**, over TLS, on the back
 * channel. That is a different, standard, and appropriate control for a
 * confidential server-side client:
 *
 *   - The **user's login is still a passkey** — WebAuthn, phishing-resistant,
 *     origin-bound. That is unchanged and it is what S9 proved.
 *   - The resulting tokens are not sender-constrained, so **token theft from the
 *     server is not detectable** the way it is at the API. The mitigation is that
 *     the tokens never reach the browser and the session is server-side.
 *   - The API's DPoP enforcement is untouched. A token the console holds is
 *     unbound, so the API accepts it under the `Bearer` scheme — which is precisely
 *     the case L2's `assertNotDowngraded` distinguishes.
 *
 * This is a real trade-off, not a free choice, and it is recorded rather than
 * glossed. **A future browser-side console would use DPoP and hold its own key.**
 *
 * ---------------------------------------------------------------------------
 * THE TWO PARAMETERS THAT ARE NOT DECORATION
 *
 * **`state`** protects the REDIRECT. It is generated before the user leaves, stored
 * server-side, and compared on return. Without it, an attacker can cause a victim's
 * browser to complete a flow the victim did not start — login CSRF, where the
 * victim ends up authenticated as the attacker and then does work inside the
 * attacker's account.
 *
 * **`nonce`** protects the ID TOKEN. It is sent in the request, and the returned ID
 * token must carry the same value. Without it, a valid ID token issued for a
 * different session can be replayed into this one.
 *
 * Both are compared with a constant-time equality and both are single-use.
 */

export interface OidcEndpoints {
  readonly issuer: string;
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly endSessionEndpoint?: string;
  readonly jwksUri: string;
}

export interface OidcClientOptions {
  /** Exact issuer base URL, e.g. `https://id.example.com/realms/attest`. */
  readonly issuer: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly scope?: string;
  /** Milliseconds before an outbound call is abandoned. */
  readonly timeoutMs?: number;
}

export interface TokenSet {
  readonly accessToken: string;
  readonly refreshToken?: string;
  readonly idToken?: string;
  readonly expiresInSec: number;
}

export class OidcClient {
  readonly #options: OidcClientOptions;
  #endpoints?: OidcEndpoints;

  constructor(options: OidcClientOptions) {
    this.#options = options;
  }

  /**
   * Discover the endpoints from the issuer.
   *
   * Discovery rather than hard-coding: an issuer that moves its endpoints (Keycloak
   * does not, but a different provider might) should not require a code change. The
   * issuer itself is configuration, so this is not a trust-on-first-use problem —
   * the document is fetched from the issuer we already trust.
   */
  async discover(): Promise<OidcEndpoints> {
    if (this.#endpoints) return this.#endpoints;

    const discoveryUrl = `${this.#options.issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
    const response = await fetch(discoveryUrl, {
      signal: AbortSignal.timeout(this.#options.timeoutMs ?? 5000),
    });
    if (!response.ok) {
      throw new Error(`OIDC discovery failed: HTTP ${response.status}`);
    }
    const doc = (await response.json()) as Record<string, unknown>;
    const str = (key: string): string => {
      const value = doc[key];
      if (typeof value !== "string") throw new Error(`OIDC discovery document has no ${key}`);
      return value;
    };
    this.#endpoints = {
      issuer: str("issuer"),
      authorizationEndpoint: str("authorization_endpoint"),
      tokenEndpoint: str("token_endpoint"),
      jwksUri: str("jwks_uri"),
      ...(typeof doc["end_session_endpoint"] === "string"
        ? { endSessionEndpoint: doc["end_session_endpoint"] as string }
        : {}),
    };
    return this.#endpoints;
  }

  /**
   * Build the URL to send the user to, and the secrets to remember for the return.
   *
   * `state` and `nonce` are returned rather than generated internally, because the
   * caller must persist them across the redirect — and a value generated here and
   * forgotten would be worse than useless: it would look like protection.
   */
  async buildAuthorizationUrl(
    toRemember: { state: string; nonce: string },
    options: { acrValues?: string; prompt?: string } = {},
  ): Promise<string> {
    const endpoints = await this.discover();
    const url = new URL(endpoints.authorizationEndpoint);
    url.searchParams.set("client_id", this.#options.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("redirect_uri", this.#options.redirectUri);
    url.searchParams.set("scope", this.#options.scope ?? "openid profile email");
    url.searchParams.set("state", toRemember.state);
    url.searchParams.set("nonce", toRemember.nonce);
    if (options.acrValues) url.searchParams.set("acr_values", options.acrValues);
    if (options.prompt) url.searchParams.set("prompt", options.prompt);
    return url.toString();
  }

  /** Exchange the authorization code. Authenticates with the client secret. */
  async exchangeCode(code: string): Promise<TokenSet> {
    const endpoints = await this.discover();
    return this.#tokenRequest(endpoints.tokenEndpoint, {
      grant_type: "authorization_code",
      code,
      redirect_uri: this.#options.redirectUri,
    });
  }

  async refresh(refreshToken: string): Promise<TokenSet> {
    const endpoints = await this.discover();
    return this.#tokenRequest(endpoints.tokenEndpoint, {
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
  }

  /** Instance form of the nonce check, so the class satisfies the console's port. */
  idTokenMatchesNonce(idToken: string | undefined, expectedNonce: string): boolean {
    return OidcClient.idTokenMatchesNonce(idToken, expectedNonce);
  }

  /**
   * Verify the ID token's `nonce`, and nothing else.
   *
   * The signature is deliberately NOT the concern here. The ID token arrived over a
   * back-channel TLS connection directly from the token endpoint in response to a
   * request this server made with its own client secret — there is no untrusted
   * hop for a signature to protect against. What a signature cannot protect against
   * is a token issued for a DIFFERENT flow being substituted into this one, and
   * that is exactly what `nonce` catches.
   *
   * The access token is verified properly, and elsewhere: it is the API's job, with
   * `verifyAccessToken`, against the issuer's JWKS.
   */
  static idTokenMatchesNonce(idToken: string | undefined, expectedNonce: string): boolean {
    if (typeof idToken !== "string") return false;
    try {
      const claims = decodeJwt(idToken);
      return typeof claims["nonce"] === "string" && claims["nonce"] === expectedNonce;
    } catch {
      return false;
    }
  }

  /** The provider's logout URL, so ending the console session ends the SSO session too. */
  async buildLogoutUrl(idToken: string | undefined, postLogoutRedirect: string): Promise<string | undefined> {
    const endpoints = await this.discover();
    if (!endpoints.endSessionEndpoint) return undefined;
    const url = new URL(endpoints.endSessionEndpoint);
    if (idToken) url.searchParams.set("id_token_hint", idToken);
    url.searchParams.set("post_logout_redirect_uri", postLogoutRedirect);
    return url.toString();
  }

  async #tokenRequest(
    tokenEndpoint: string,
    params: Record<string, string>,
  ): Promise<TokenSet> {
    const body = new URLSearchParams({
      ...params,
      client_id: this.#options.clientId,
      client_secret: this.#options.clientSecret,
    });
    const response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(this.#options.timeoutMs ?? 10_000),
    });
    if (!response.ok) {
      // The body is NOT included in the error: it can echo the authorization code or
      // a token, and an error message is a thing that ends up in logs.
      throw new Error(`token endpoint returned HTTP ${response.status}`);
    }
    const json = (await response.json()) as Record<string, unknown>;
    const accessToken = json["access_token"];
    if (typeof accessToken !== "string") throw new Error("token response had no access_token");
    const expiresIn = typeof json["expires_in"] === "number" ? json["expires_in"] : 300;
    return {
      accessToken,
      expiresInSec: expiresIn,
      ...(typeof json["refresh_token"] === "string" ? { refreshToken: json["refresh_token"] } : {}),
      ...(typeof json["id_token"] === "string" ? { idToken: json["id_token"] } : {}),
    };
  }
}
