import { describe, expect, it } from "vitest";

import {
  createRelayState,
  decodeRelayState,
  validateRelayState,
  type RelayStateInput
} from "./state";

const SIGNING_KEY = "test-signing-key";

function makeInput(overrides: Partial<RelayStateInput> = {}): RelayStateInput {
  return {
    appId: "anys3",
    targetOrigin: "https://preview.anys3-dashboard.example.workers.dev",
    callbackPath: "/api/auth/callback/google",
    appState: "app-state-payload",
    signingKey: SIGNING_KEY,
    ...overrides
  };
}

describe("relay state", () => {
  it("encodes a state payload that round-trips through decode", () => {
    const token = createRelayState(makeInput());
    const decoded = decodeRelayState(token, { signingKey: SIGNING_KEY });

    expect(decoded.appId).toBe("anys3");
    expect(decoded.targetOrigin).toBe("https://preview.anys3-dashboard.example.workers.dev");
    expect(decoded.callbackPath).toBe("/api/auth/callback/google");
    expect(decoded.appState).toBe("app-state-payload");
    expect(typeof decoded.nonce).toBe("string");
    expect(decoded.nonce).toHaveLength(24);
    expect(typeof decoded.issuedAt).toBe("number");
  });

  it("rejects a token with a tampered payload", () => {
    const token = createRelayState(makeInput());
    const [encodedPayload, signature] = token.split(".");
    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8")
    ) as Record<string, unknown>;
    payload.appId = "evil-app";
    const tamperedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    const tamperedToken = `${tamperedPayload}.${signature}`;

    expect(() => decodeRelayState(tamperedToken, { signingKey: SIGNING_KEY })).toThrow();
  });

  it("rejects a token with a tampered signature", () => {
    const token = createRelayState(makeInput());
    const [encodedPayload] = token.split(".");
    const tamperedToken = `${encodedPayload}.invalid-signature`;

    expect(() => decodeRelayState(tamperedToken, { signingKey: SIGNING_KEY })).toThrow();
  });

  it("rejects a token signed with a different key", () => {
    const token = createRelayState(makeInput({ signingKey: "other-key" }));

    expect(() => decodeRelayState(token, { signingKey: SIGNING_KEY })).toThrow();
  });

  it("rejects a malformed token without a separator", () => {
    expect(() => decodeRelayState("not-a-token", { signingKey: SIGNING_KEY })).toThrow();
  });

  it("rejects an expired token beyond the max age", () => {
    const issuedAt = Date.now() - 11 * 60 * 1000;
    const token = createRelayState(makeInput({ issuedAt }));

    expect(() =>
      validateRelayState(token, {
        signingKey: SIGNING_KEY,
        now: Date.now(),
        maxAgeMs: 10 * 60 * 1000
      })
    ).toThrow(/expired/i);
  });

  it("accepts a token within the max age", () => {
    const issuedAt = Date.now() - 5 * 60 * 1000;
    const token = createRelayState(makeInput({ issuedAt }));

    const result = validateRelayState(token, {
      signingKey: SIGNING_KEY,
      now: issuedAt + 60_000,
      maxAgeMs: 10 * 60 * 1000
    });

    expect(result.appId).toBe("anys3");
  });

  it("rejects a payload missing required fields", () => {
    const token = createRelayState(makeInput());
    const [encodedPayload, signature] = token.split(".");
    const payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf8")
    ) as Record<string, unknown>;
    delete payload.targetOrigin;
    const tamperedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    // Re-sign because signature check happens before field validation.
    const crypto = require("node:crypto") as typeof import("node:crypto");
    const newSignature = crypto
      .createHmac("sha256", SIGNING_KEY)
      .update(tamperedPayload)
      .digest("base64url");
    const tamperedToken = `${tamperedPayload}.${newSignature}`;

    expect(() => decodeRelayState(tamperedToken, { signingKey: SIGNING_KEY })).toThrow();
  });
});
