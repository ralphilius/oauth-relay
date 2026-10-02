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
export interface RelayEnv {
    OAUTH_RELAY_CALLBACK_URL?: string;
    OAUTH_RELAY_APP_ID?: string;
    OAUTH_RELAY_SIGNING_KEY?: string;
    PREVIEW_HOSTNAME_SUFFIX?: string;
    [key: string]: string | undefined;
}
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
/** HttpOnly CSRF nonce set by startRelaySignIn, verified by handleRelayCallback. */
export declare const OAUTH_RELAY_NONCE_COOKIE = "oauth_relay_nonce";
/** HttpOnly one-time Google credential, readable only by the consume endpoint. */
export declare const OAUTH_RELAY_CREDENTIAL_COOKIE = "oauth_relay_credential";
/** Non-HttpOnly error flag the sign-in page can read & clear for display. */
export declare const OAUTH_RELAY_ERROR_COOKIE = "oauth_relay_error";
export declare function normalizeHostname(hostname: string): string;
export declare function hostnameFromHeaders(headers: Headers): string | undefined;
/**
 * Preview hosts are <prefix>-<worker>.<subdomain>.workers.dev. The suffix is
 * the worker's own workers.dev hostname. A delimiter ("-" or ".") must precede
 * the suffix so glued names don't match, and the bare worker hostname is not
 * a preview.
 */
export declare function isPreviewHostname(hostname: string, env: Pick<RelayEnv, "PREVIEW_HOSTNAME_SUFFIX">): boolean;
export declare function getRelayConfig(env: RelayEnv): RelayConfig | null;
/**
 * Relay context for the current request. Null on non-preview hosts or when
 * relay env vars are missing — callers should 404/fall through then so
 * production auth is untouched.
 */
export declare function getRelayContextForRequest(headers: Headers, env: RelayEnv): RelayContext | null;
export declare function generateNonce(): string;
export type RelayStateInput = {
    appId: string;
    targetOrigin: string;
    callbackPath: string;
    /** Verbatim payload the relay returns as ?state= — use a CSRF nonce. */
    appState: string;
    signingKey: string;
};
/** `base64url(payloadJson).base64url(hmac)` — the token the relay verifies. */
export declare function createRelayState(input: RelayStateInput): Promise<string>;
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
export declare function startRelaySignIn(request: Request, options: StartOptions): Promise<Response>;
export type CallbackOptions = {
    googleClientId: string;
    googleClientSecret: string;
    env: RelayEnv;
    /** Where to send the user after success. Default "/auth/callback". */
    successPath?: string;
    /** Sign-in page for error redirects. Default "/auth". */
    authPath?: string;
};
/**
 * GET /callback — relay lands here with ?code&state=<nonce>. Verifies the
 * nonce cookie, exchanges the code at Google (redirect_uri = the relay URL,
 * matching the auth request), stashes the ID token in a one-time HttpOnly
 * cookie, and 302s to successPath (default /auth/callback).
 */
export declare function handleRelayCallback(request: Request, options: CallbackOptions): Promise<Response>;
/**
 * GET /consume — returns { idToken } once, then burns the credential cookie.
 * Your client-side success page calls this, then finishes sign-in
 * (e.g. Firebase signInWithCredential).
 */
export declare function consumeRelayCredential(request: Request): Response;
