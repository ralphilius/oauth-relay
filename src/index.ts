import { createAppRegistry, type AppRegistryEntry } from "./app-registry";
import { validateRelayState, RelayStateError } from "./state";

export type RelayEnv = {
  APPS: string;
  // Optional JSON array of origin suffixes allowed for ANY app — e.g.
  // '["ralphilius.workers.dev"]'. Only the account can deploy to its own
  // workers.dev subdomain, so this safely covers every app's preview host
  // without a per-app APPS entry.
  ALLOWED_ORIGIN_SUFFIXES?: string;
  OAUTH_RELAY_SIGNING_KEY: string;
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
    let globalSuffixes: string[] = [];
    try {
      entries = JSON.parse(env.APPS) as Record<string, AppRegistryEntry>;
      if (env.ALLOWED_ORIGIN_SUFFIXES) {
        const parsed = JSON.parse(env.ALLOWED_ORIGIN_SUFFIXES);
        if (Array.isArray(parsed) && parsed.every((s) => typeof s === "string")) {
          globalSuffixes = parsed;
        }
      }
    } catch {
      return new Response("Misconfigured app registry", { status: 500 });
    }
    const registry = createAppRegistry(entries, globalSuffixes);

    let payload;
    try {
      payload = validateRelayState(state, { signingKey: env.OAUTH_RELAY_SIGNING_KEY });
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
