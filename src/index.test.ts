import { describe, expect, it } from "vitest";

import { createRelayHandler, type RelayEnv } from "./index";
import { createRelayState } from "./state";

const SIGNING_KEY = "test-signing-key";

function makeEnv(overrides: Partial<RelayEnv> = {}): RelayEnv {
  return {
    APPS: JSON.stringify({
      anys3: { allowedOriginSuffix: ".anys3-dashboard.example.workers.dev" }
    }),
    APP_SECRET_anys3: SIGNING_KEY,
    ...overrides
  };
}

function makeRequest(url: string): Request {
  return new Request(url);
}

describe("relay handler", () => {
  it("redirects to the target origin callback path with code and unwrapped appState", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();
    const state = createRelayState({
      appId: "anys3",
      targetOrigin: "https://preview.anys3-dashboard.example.workers.dev",
      callbackPath: "/api/auth/callback/google",
      appState: "app-state-payload",
      signingKey: SIGNING_KEY
    });

    const response = await handler(
      makeRequest(`https://oauth-relay.example.com/callback?code=test-code&state=${state}`),
      env
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    expect(location).toBe(
      "https://preview.anys3-dashboard.example.workers.dev/api/auth/callback/google?code=test-code&state=app-state-payload"
    );
  });

  it("returns 400 when code is missing", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();
    const state = createRelayState({
      appId: "anys3",
      targetOrigin: "https://preview.anys3-dashboard.example.workers.dev",
      callbackPath: "/api/auth/callback/google",
      appState: "app-state-payload",
      signingKey: SIGNING_KEY
    });

    const response = await handler(
      makeRequest(`https://oauth-relay.example.com/callback?state=${state}`),
      env
    );

    expect(response.status).toBe(400);
  });

  it("returns 400 when state is missing", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();

    const response = await handler(
      makeRequest("https://oauth-relay.example.com/callback?code=test-code"),
      env
    );

    expect(response.status).toBe(400);
  });

  it("returns 400 when the state signature is invalid", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();

    const response = await handler(
      makeRequest("https://oauth-relay.example.com/callback?code=test-code&state=bogus.state"),
      env
    );

    expect(response.status).toBe(400);
  });

  it("returns 400 when the app id is unknown to the registry", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();
    const state = createRelayState({
      appId: "unknown-app",
      targetOrigin: "https://preview.anys3-dashboard.example.workers.dev",
      callbackPath: "/api/auth/callback/google",
      appState: "app-state-payload",
      signingKey: SIGNING_KEY
    });

    const response = await handler(
      makeRequest(`https://oauth-relay.example.com/callback?code=test-code&state=${state}`),
      env
    );

    expect(response.status).toBe(400);
  });

  it("returns 400 when the target origin is not allowed for the app", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();
    const state = createRelayState({
      appId: "anys3",
      targetOrigin: "https://evil.example.com",
      callbackPath: "/api/auth/callback/google",
      appState: "app-state-payload",
      signingKey: SIGNING_KEY
    });

    const response = await handler(
      makeRequest(`https://oauth-relay.example.com/callback?code=test-code&state=${state}`),
      env
    );

    expect(response.status).toBe(400);
  });

  it("returns 400 when the signing key for the app is not configured", async () => {
    const env = makeEnv({ APP_SECRET_anys3: undefined as unknown as string });
    const handler = createRelayHandler();
    const state = createRelayState({
      appId: "anys3",
      targetOrigin: "https://preview.anys3-dashboard.example.workers.dev",
      callbackPath: "/api/auth/callback/google",
      appState: "app-state-payload",
      signingKey: SIGNING_KEY
    });

    const response = await handler(
      makeRequest(`https://oauth-relay.example.com/callback?code=test-code&state=${state}`),
      env
    );

    expect(response.status).toBe(400);
  });

  it("returns 404 for non-callback paths", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();

    const response = await handler(
      makeRequest("https://oauth-relay.example.com/other"),
      env
    );

    expect(response.status).toBe(404);
  });

  it("preserves additional query parameters from the original callback in the redirect", async () => {
    const env = makeEnv();
    const handler = createRelayHandler();
    const state = createRelayState({
      appId: "anys3",
      targetOrigin: "https://preview.anys3-dashboard.example.workers.dev",
      callbackPath: "/api/providers/google-drive/callback",
      appState: "drive-state-payload",
      signingKey: SIGNING_KEY
    });

    const response = await handler(
      makeRequest(`https://oauth-relay.example.com/callback?code=test-code&state=${state}&extra=keep`),
      env
    );

    expect(response.status).toBe(302);
    const location = response.headers.get("location");
    const parsed = new URL(location!);
    expect(parsed.origin + parsed.pathname).toBe(
      "https://preview.anys3-dashboard.example.workers.dev/api/providers/google-drive/callback"
    );
    expect(parsed.searchParams.get("code")).toBe("test-code");
    expect(parsed.searchParams.get("state")).toBe("drive-state-payload");
  });
});
