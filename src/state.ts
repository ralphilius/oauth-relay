import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export type RelayStateInput = {
  appId: string;
  targetOrigin: string;
  callbackPath: string;
  appState: string;
  signingKey: string;
  issuedAt?: number;
  nonce?: string;
};

export type RelayStatePayload = {
  appId: string;
  targetOrigin: string;
  callbackPath: string;
  appState: string;
  nonce: string;
  issuedAt: number;
};

export class RelayStateError extends Error {
  constructor(message = "Invalid relay state") {
    super(message);
    this.name = "RelayStateError";
  }
}

function base64UrlEncode(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function base64UrlDecode(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}

function sign(payload: string, key: string): string {
  return createHmac("sha256", key).update(payload).digest("base64url");
}

export function createRelayState(input: RelayStateInput): string {
  const payload: RelayStatePayload = {
    appId: input.appId,
    targetOrigin: input.targetOrigin,
    callbackPath: input.callbackPath,
    appState: input.appState,
    nonce: input.nonce ?? randomBytes(12).toString("hex"),
    issuedAt: input.issuedAt ?? Date.now()
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = sign(encodedPayload, input.signingKey);

  return `${encodedPayload}.${signature}`;
}

function parseAndVerify(token: string, signingKey: string): RelayStatePayload {
  const [encodedPayload, providedSignature] = token.split(".");

  if (!encodedPayload || !providedSignature) {
    throw new RelayStateError("Malformed relay state");
  }

  const expectedSignature = sign(encodedPayload, signingKey);

  if (
    expectedSignature.length !== providedSignature.length ||
    !timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(providedSignature))
  ) {
    throw new RelayStateError("Invalid relay state signature");
  }

  const payload = JSON.parse(base64UrlDecode(encodedPayload)) as Partial<RelayStatePayload>;

  if (
    typeof payload.appId !== "string" ||
    typeof payload.targetOrigin !== "string" ||
    typeof payload.callbackPath !== "string" ||
    typeof payload.appState !== "string" ||
    typeof payload.nonce !== "string" ||
    typeof payload.issuedAt !== "number"
  ) {
    throw new RelayStateError("Relay state payload missing required fields");
  }

  return payload as RelayStatePayload;
}

export function decodeRelayState(token: string, options: { signingKey: string }): RelayStatePayload {
  return parseAndVerify(token, options.signingKey);
}

export function validateRelayState(
  token: string,
  options: { signingKey: string; now?: number; maxAgeMs?: number }
): RelayStatePayload {
  const payload = parseAndVerify(token, options.signingKey);
  const now = options.now ?? Date.now();
  const maxAgeMs = options.maxAgeMs ?? 10 * 60 * 1000;

  if (now - payload.issuedAt > maxAgeMs) {
    throw new RelayStateError("Expired relay state");
  }

  return payload;
}
