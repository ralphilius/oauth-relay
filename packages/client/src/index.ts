/**
 * oauth-relay-client — app-side helpers for the Cloudflare Workers OAuth relay.
 *
 * No Node APIs: uses Web Crypto so it runs in Workers, edge runtimes, and
 * Node 18+ alike.
 *
 * Wire-up (one-time):
 *   1. wrangler vars:  OAUTH_RELAY_CALLBACK_URL (relay /callback URL),
 *      OAUTH_RELAY_APP_ID (informational slug), PREVIEW_HOSTNAME_SUFFIX
 *      (your worker's workers.dev hostname).
 *   2. wrangler secret put OAUTH_RELAY_SIGNING_KEY (shared with the relay).
 *   3. Add https://<relay-domain>/callback to your Google OAuth client.
 *
 * Minimal mount (fetch API):
 *   if (pathname === "/auth/google/start")    return startRelaySignIn(request, { googleClientId, env });
 *   if (pathname === "/auth/google/callback") return handleRelayCallback(request, { googleClientId, googleClientSecret, env });
 *   if (pathname === "/auth/google/consume")  return consumeRelayCredential();
 */

// ---------- env / types ----------

export type RelayEnv = {
  OAUTH_RELAY_CALLBACK_URL?: string;
  OAUTH_RELAY_APP_ID?: string;
  OAUTH_RELAY_SIGNING_KEY?: string;
  PREVIEW_HOSTNAME_SUFFIX?: string;
};

export type RelayConfig = {
  callbackUrl: string;
  appId: string;
  signingKey: string;
};

export type RelayContext = {
  relay: RelayConfig;
  /** Normalized request host, e.g. "abc123-myapp.acct.workers.dev". */
  normalizedHost: string;
};

// ---------- cookie names (shared contract with your app's client page) ----------

/** HttpOnly CSRF nonce set by startRelaySignIn, verified by handleRelayCallback. */
export const OAUTH_RELAY_NONCE_COOKIE = "oauth_relay_nonce";
/** HttpOnly one-time Google credential, readable only by the consume endpoint. */
export const OAUTH_RELAY_CREDENTIAL_COOKIE = "oauth_relay_credential";
/** Non-HttpOnly error flag the sign-in page can read & clear for display. */
export const OAUTH_RELAY_ERROR_COOKIE = "oauth_relay_error";

const NONCE_MAX_AGE_S = 10 * 60;
const CREDENTIAL_MAX_AGE_S = 3 * 60;
const CONSUME_PATH = "/api/auth/google/consume";

// ---------- hostname helpers ----------

export function normalizeHostname(hostname: string): string {
  return hostname.split(":")[0];
}

export function hostnameFromHeaders(headers: Headers): string | undefined {
  return headers.get("x-forwarded-host") ?? headers.get("host") ?? undefined;
}

/**
 * Preview hosts are <prefix>-<worker>.<subdomain>.workers.dev. The suffix is
 * the worker's own workers.dev hostname. A delimiter ("-" or ".") must precede
 * the suffix so glued names don't match, and the bare worker hostname is not
 * a preview.
 */
export function isPreviewHostname(
  hostname: string,
  env: Pick<RelayEnv, "PREVIEW_HOSTNAME_SUFFIX">
): boolean {
  const suffix = env.PREVIEW_HOSTNAME_SUFFIX;
  if (!suffix) return false;
  const host = normalizeHostname(hostname);
  if (!host.endsWith(suffix) || host.length <= suffix.length) return false;
  const precedingChar = host[host.length - suffix.length - 1];
  return precedingChar === "-" || precedingChar === ".";
}

export function getRelayConfig(env: RelayEnv): RelayConfig | null {
  if (!env.OAUTH_RELAY_CALLBACK_URL || !env.OAUTH_RELAY_APP_ID || !env.OAUTH_RELAY_SIGNING_KEY) {
    return null;
  }
  return {
    callbackUrl: env.OAUTH_RELAY_CALLBACK_URL,
    appId: env.OAUTH_RELAY_APP_ID,
    signingKey: env.OAUTH_RELAY_SIGNING_KEY,
  };
}

/**
 * Relay context for the current request. Null on non-preview hosts or when
 * relay env vars are missing — callers should 404/fall through then so
 * production auth is untouched.
 */
export function getRelayContextForRequest(headers: Headers, env: RelayEnv): RelayContext | null {
  const hostname = hostnameFromHeaders(headers);
  if (!hostname) return null;
  const normalizedHost = normalizeHostname(hostname);
  if (!isPreviewHostname(normalizedHost, env)) return null;
  const relay = getRelayConfig(env);
  if (!relay) return null;
  return { relay, normalizedHost };
}

// ---------- Web Crypto primitives ----------

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (const b of arr) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacSign(payload: string, key: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return b64url(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(payload)));
}

export function generateNonce(): string {
  return b64url(crypto.getRandomValues(new Uint8Array(16)));
}

// ---------- relay state token ----------

export type RelayStateInput = {
  appId: string;
  targetOrigin: string;
  callbackPath: string;
  /** Verbatim payload the relay returns as ?state= — use a CSRF nonce. */
  appState: string;
  signingKey: string;
};

/** `base64url(payloadJson).base64url(hmac)` — the token the relay verifies. */
export async function createRelayState(input: RelayStateInput): Promise<string> {
  const payload = {
    appId: input.appId,
    targetOrigin: input.targetOrigin,
    callbackPath: input.callbackPath,
    appState: input.appState,
    nonce: generateNonce(),
    issuedAt: Date.now(),
  };
  const encodedPayload = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await hmacSign(encodedPayload, input.signingKey);
  return `${encodedPayload}.${signature}`;
}

// ---------- cookie serialization ----------

function cookie(name: string, value: string, opts: { maxAge: number; path: string; httpOnly?: boolean }): string {
  const parts = [
    `${name}=${value}`,
    `Path=${opts.path}`,
    `Max-Age=${opts.maxAge}`,
    "Secure",
    "SameSite=Lax",
  ];
  if (opts.httpOnly) parts.push("HttpOnly");
  return parts.join("; ");
}

function readCookie(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie");
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return undefined;
}

// ---------- handlers ----------

export type StartOptions = {
  googleClientId: string;
  env: RelayEnv;
  /** Extra Google auth params (e.g. access_type: "offline"). */
  authParams?: Record<string, string>;
};

/**
 * GET /start — preview-only sign-in entry. 302 → Google with
 * redirect_uri = relay callback and a signed state embedding this host's
 * callback path. Sets the CSRF nonce cookie. 404 on non-preview hosts.
 */
export async function startRelaySignIn(request: Request, options: StartOptions): Promise<Response> {
  const ctx = getRelayContextForRequest(request.headers, options.env);
  if (!ctx) return new Response("Not Found", { status: 404 });

  const nonce = generateNonce();
  const state = await createRelayState({
    appId: ctx.relay.appId,
    targetOrigin: `https://${ctx.normalizedHost}`,
    callbackPath: new URL(request.url).pathname.replace(/\/start\/?$/, "/callback"),
    appState: nonce,
    signingKey: ctx.relay.signingKey,
  });

  const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  authUrl.searchParams.set("client_id", options.googleClientId);
  authUrl.searchParams.set("redirect_uri", ctx.relay.callbackUrl);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid email profile");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("prompt", "select_account");
  for (const [k, v] of Object.entries(options.authParams ?? {})) {
    authUrl.searchParams.set(k, v);
  }

  const headers = new Headers({ Location: authUrl.toString() });
  headers.append("Set-Cookie", cookie(OAUTH_RELAY_NONCE_COOKIE, nonce, { maxAge: NONCE_MAX_AGE_S, path: "/", httpOnly: true }));
  return new Response(null, { status: 302, headers });
}

export type CallbackOptions = {
  googleClientId: string;
  googleClientSecret: string;
  env: RelayEnv;
  /** Where to send the user after success. Default "/auth/callback". */
  successPath?: string;
  /** Sign-in page for error redirects. Default "/auth". */
  authPath?: string;
};

function authErrorRedirect(request: Request, authPath: string, code: string): Response {
  const headers = new Headers({ Location: new URL(authPath, request.url).toString() });
  headers.append("Set-Cookie", cookie(OAUTH_RELAY_NONCE_COOKIE, "", { maxAge: 0, path: "/" }));
  headers.append("Set-Cookie", cookie(OAUTH_RELAY_ERROR_COOKIE, code, { maxAge: 60, path: "/" }));
  return new Response(null, { status: 302, headers });
}

/**
 * GET /callback — relay lands here with ?code&state=<nonce>. Verifies the
 * nonce cookie, exchanges the code at Google (redirect_uri = the relay URL,
 * matching the auth request), stashes the ID token in a one-time HttpOnly
 * cookie, and 302s to successPath (default /auth/callback).
 */
export async function handleRelayCallback(request: Request, options: CallbackOptions): Promise<Response> {
  const ctx = getRelayContextForRequest(request.headers, options.env);
  if (!ctx) return new Response("Not Found", { status: 404 });

  const authPath = options.authPath ?? "/auth";
  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  if (error) return authErrorRedirect(request, authPath, error);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const nonceCookie = readCookie(request, OAUTH_RELAY_NONCE_COOKIE);
  if (!code || !state || !nonceCookie || nonceCookie !== state) {
    return authErrorRedirect(request, authPath, "invalid_state");
  }

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: options.googleClientId,
      client_secret: options.googleClientSecret,
      code,
      grant_type: "authorization_code",
      redirect_uri: ctx.relay.callbackUrl,
    }),
  });

  if (!tokenResponse.ok) {
    const detail = await tokenResponse.text().catch(() => "");
    console.error("OAuth code exchange failed:", tokenResponse.status, detail.slice(0, 300));
    return authErrorRedirect(request, authPath, "token_exchange_failed");
  }

  const tokens = (await tokenResponse.json()) as { id_token?: string };
  if (!tokens.id_token) {
    console.error("OAuth exchange returned no id_token");
    return authErrorRedirect(request, authPath, "missing_id_token");
  }

  const headers = new Headers({
    Location: new URL(options.successPath ?? "/auth/callback", request.url).toString(),
  });
  headers.append(
    "Set-Cookie",
    cookie(OAUTH_RELAY_CREDENTIAL_COOKIE, tokens.id_token, {
      maxAge: CREDENTIAL_MAX_AGE_S,
      path: CONSUME_PATH,
      httpOnly: true,
    })
  );
  headers.append("Set-Cookie", cookie(OAUTH_RELAY_NONCE_COOKIE, "", { maxAge: 0, path: "/" }));
  return new Response(null, { status: 302, headers });
}

/**
 * GET /consume — returns { idToken } once, then burns the credential cookie.
 * Your client-side success page calls this, then finishes sign-in
 * (e.g. Firebase signInWithCredential).
 */
export function consumeRelayCredential(request: Request): Response {
  const idToken = readCookie(request, OAUTH_RELAY_CREDENTIAL_COOKIE);
  const headers = new Headers({ "Cache-Control": "no-store" });
  headers.append(
    "Set-Cookie",
    cookie(OAUTH_RELAY_CREDENTIAL_COOKIE, "", { maxAge: 0, path: CONSUME_PATH })
  );
  if (!idToken) {
    return new Response(JSON.stringify({ error: "no_credential" }), { status: 404, headers });
  }
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify({ idToken }), { status: 200, headers });
}
