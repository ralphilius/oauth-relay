import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Drop-in OAuth-relay client. Copy this file into your app (e.g.
 * `src/auth/oauth-relay-client.ts`) — no package install needed.
 *
 * Wire-up (one-time):
 *   1. wrangler vars on your worker: OAUTH_RELAY_CALLBACK_URL (the relay's
 *      /callback URL), OAUTH_RELAY_APP_ID (any slug — informational), and
 *      PREVIEW_HOSTNAME_SUFFIX (your worker's workers.dev hostname, e.g.
 *      "my-app.<subdomain>.workers.dev").
 *   2. wrangler secret put OAUTH_RELAY_SIGNING_KEY — same shared value as the
 *      relay and other apps.
 *   3. Add https://<relay-domain>/callback to your Google OAuth client's
 *      authorized redirect URIs.
 *
 * Flow: signInStart() → Google → relay → your callbackPath?code&state=<nonce>
 * → verify the nonce, then exchange the code with
 * redirect_uri = env.OAUTH_RELAY_CALLBACK_URL (must match the auth request).
 */

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

export function normalizeHostname(hostname: string): string {
  return hostname.split(":")[0];
}

export function hostnameFromHeaders(headers: Headers): string | undefined {
  return headers.get("x-forwarded-host") ?? headers.get("host") ?? undefined;
}

/**
 * Preview hosts are <prefix>-<worker>.<subdomain>.workers.dev. The suffix is
 * the worker's own workers.dev hostname. A delimiter ("-" or ".") must precede
 * the suffix so glued names ("foomyapp…") don't match, and the bare worker
 * hostname is not a preview.
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

export type RelayContext = {
  relay: RelayConfig;
  normalizedHost: string;
};

/** Null on non-preview hosts or when relay env vars are missing. */
export function getRelayContextForRequest(headers: Headers, env: RelayEnv): RelayContext | null {
  const hostname = hostnameFromHeaders(headers);
  if (!hostname) return null;
  const normalizedHost = normalizeHostname(hostname);
  if (!isPreviewHostname(normalizedHost, env)) return null;
  const relay = getRelayConfig(env);
  if (!relay) return null;
  return { relay, normalizedHost };
}

export type RelayStateInput = {
  appId: string;
  targetOrigin: string;
  callbackPath: string;
  /** Verbatim app payload the relay returns as ?state= — use a CSRF nonce. */
  appState: string;
  signingKey: string;
};

/** `base64url(payloadJson).base64url(hmac)` — the token the relay verifies. */
export function createRelayState(input: RelayStateInput): string {
  const payload = {
    appId: input.appId,
    targetOrigin: input.targetOrigin,
    callbackPath: input.callbackPath,
    appState: input.appState,
    nonce: randomBytes(12).toString("hex"),
    issuedAt: Date.now(),
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signature = createHmac("sha256", input.signingKey).update(encodedPayload).digest("base64url");
  return `${encodedPayload}.${signature}`;
}

export function generateNonce(): string {
  return randomBytes(16).toString("base64url");
}

/** Constant-time compare for the CSRF nonce returned as ?state=. */
export function nonceMatches(expected: string, actual: string): boolean {
  const a = Buffer.from(expected);
  const b = Buffer.from(actual);
  return a.length === b.length && timingSafeEqual(a, b);
}
