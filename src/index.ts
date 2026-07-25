import { createAppRegistry, type AppRegistryEntry } from "./app-registry";
import { validateRelayState, RelayStateError } from "./state";

export type RelayEnv = {
  APPS: string;
  [key: `APP_SECRET_${string}`]: string;
};

export type RelayRequestHandler = (request: Request, env: RelayEnv) => Promise<Response>;

export function createRelayHandler(): RelayRequestHandler {
  return async (request, env) => {
    const url = new URL(request.url);

    if (url.pathname !== "/callback") {
      return new Response("Not Found", { status: 404 });
    }

    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (!code || !state) {
      return new Response("Missing code or state", { status: 400 });
    }

    let entries: Record<string, AppRegistryEntry>;
    try {
      entries = JSON.parse(env.APPS) as Record<string, AppRegistryEntry>;
    } catch {
      return new Response("Misconfigured app registry", { status: 500 });
    }
    const registry = createAppRegistry(entries);

    const [encodedPayload] = state.split(".");
    if (!encodedPayload) {
      return new Response("Malformed state", { status: 400 });
    }

    let appId: string;
    try {
      const payload = JSON.parse(
        Buffer.from(encodedPayload, "base64url").toString("utf8")
      ) as { appId?: unknown };
      if (typeof payload.appId !== "string") {
        return new Response("Malformed state", { status: 400 });
      }
      appId = payload.appId;
    } catch {
      return new Response("Malformed state", { status: 400 });
    }

    const signingKey = env[`APP_SECRET_${appId}`];
    if (!signingKey) {
      return new Response("Unknown app", { status: 400 });
    }

    let payload;
    try {
      payload = validateRelayState(state, { signingKey });
    } catch (error) {
      if (error instanceof RelayStateError) {
        return new Response("Invalid state", { status: 400 });
      }
      throw error;
    }

    if (!registry.isOriginAllowed(payload.appId, payload.targetOrigin)) {
      return new Response("Origin not allowed", { status: 400 });
    }

    const redirectUrl = new URL(payload.callbackPath, payload.targetOrigin);
    redirectUrl.searchParams.set("code", code);
    redirectUrl.searchParams.set("state", payload.appState);

    return Response.redirect(redirectUrl.toString(), 302);
  };
}

const handler = createRelayHandler();

export default {
  async fetch(request: Request, env: RelayEnv): Promise<Response> {
    return handler(request, env);
  }
};
