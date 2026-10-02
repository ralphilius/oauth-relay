import { describe, expect, it } from "vitest";
import { createRelayState, getRelayContextForRequest, isPreviewHostname, startRelaySignIn, handleRelayCallback, consumeRelayCredential, OAUTH_RELAY_NONCE_COOKIE, OAUTH_RELAY_CREDENTIAL_COOKIE, OAUTH_RELAY_ERROR_COOKIE, } from "./index";
const SUFFIX = "myapp.example.workers.dev";
const PREVIEW_HOST = `abc123-${SUFFIX}`;
const ENV = {
    PREVIEW_HOSTNAME_SUFFIX: SUFFIX,
    OAUTH_RELAY_CALLBACK_URL: "https://oauth-relay.example.com/callback",
    OAUTH_RELAY_APP_ID: "myapp",
    OAUTH_RELAY_SIGNING_KEY: "key",
};
const previewReq = (path, init) => new Request(`https://${PREVIEW_HOST}${path}`, {
    ...init,
    headers: { host: PREVIEW_HOST, ...init?.headers },
});
describe("isPreviewHostname", () => {
    it("matches prefixed preview hosts, rejects apex/prod/unglued", () => {
        expect(isPreviewHostname(PREVIEW_HOST, ENV)).toBe(true);
        expect(isPreviewHostname(SUFFIX, ENV)).toBe(false);
        expect(isPreviewHostname(`foo${SUFFIX}`, ENV)).toBe(false);
        expect(isPreviewHostname("prod.example.com", ENV)).toBe(false);
    });
});
describe("getRelayContextForRequest", () => {
    it("returns context on preview host, null elsewhere", () => {
        const ctx = getRelayContextForRequest(new Headers({ host: PREVIEW_HOST }), ENV);
        expect(ctx?.normalizedHost).toBe(PREVIEW_HOST);
        expect(ctx?.relay.appId).toBe("myapp");
        expect(getRelayContextForRequest(new Headers({ host: "prod.example.com" }), ENV)).toBeNull();
    });
});
describe("startRelaySignIn", () => {
    it("302s to Google with relay redirect_uri and signed state", async () => {
        const res = await startRelaySignIn(previewReq("/api/auth/google/start"), {
            googleClientId: "cid",
            env: ENV,
        });
        expect(res.status).toBe(302);
        const loc = new URL(res.headers.get("location"));
        expect(loc.origin + loc.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
        expect(loc.searchParams.get("redirect_uri")).toBe(ENV.OAUTH_RELAY_CALLBACK_URL);
        expect(loc.searchParams.get("client_id")).toBe("cid");
        const state = decodeURIComponent(loc.searchParams.get("state"));
        const [enc] = state.split(".");
        const payload = JSON.parse(atob(enc.replace(/-/g, "+").replace(/_/g, "/")));
        expect(payload.appId).toBe("myapp");
        expect(payload.targetOrigin).toBe(`https://${PREVIEW_HOST}`);
        // start -> callback path derivation
        expect(payload.callbackPath).toBe("/api/auth/google/callback");
        expect(typeof payload.appState).toBe("string");
        const setCookie = res.headers.get("set-cookie");
        expect(setCookie).toContain(`${OAUTH_RELAY_NONCE_COOKIE}=${payload.appState}`);
        expect(setCookie).toContain("HttpOnly");
    });
    it("404s on a non-preview host", async () => {
        const res = await startRelaySignIn(new Request("https://prod.example.com/api/auth/google/start", {
            headers: { host: "prod.example.com" },
        }), { googleClientId: "cid", env: ENV });
        expect(res.status).toBe(404);
    });
});
describe("handleRelayCallback", () => {
    it("rejects a state that doesn't match the nonce cookie", async () => {
        const res = await handleRelayCallback(previewReq("/api/auth/google/callback?code=c&state=wrong", {
            headers: { cookie: `${OAUTH_RELAY_NONCE_COOKIE}=real` },
        }), { googleClientId: "cid", googleClientSecret: "sec", env: ENV });
        expect(res.status).toBe(302);
        expect(new URL(res.headers.get("location")).pathname).toBe("/auth");
        expect(res.headers.get("set-cookie")).toContain(`${OAUTH_RELAY_ERROR_COOKIE}=invalid_state`);
    });
    it("404s on a non-preview host", async () => {
        const res = await handleRelayCallback(new Request("https://prod.example.com/api/auth/google/callback?code=c&state=s", {
            headers: { host: "prod.example.com" },
        }), { googleClientId: "cid", googleClientSecret: "sec", env: ENV });
        expect(res.status).toBe(404);
    });
});
describe("consumeRelayCredential", () => {
    it("returns the credential once and burns the cookie", async () => {
        const res = consumeRelayCredential(new Request(`https://${PREVIEW_HOST}/api/auth/google/consume`, {
            headers: { cookie: `${OAUTH_RELAY_CREDENTIAL_COOKIE}=tok123` },
        }));
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ idToken: "tok123" });
        expect(res.headers.get("set-cookie")).toContain(`${OAUTH_RELAY_CREDENTIAL_COOKIE}=;`);
        expect(res.headers.get("set-cookie")).toContain("Max-Age=0");
    });
    it("404s with no credential and still clears the cookie", async () => {
        const res = consumeRelayCredential(new Request(`https://${PREVIEW_HOST}/api/auth/google/consume`));
        expect(res.status).toBe(404);
        expect(res.headers.get("set-cookie")).toContain(`${OAUTH_RELAY_CREDENTIAL_COOKIE}=;`);
    });
});
describe("createRelayState", () => {
    it("produces payload.signature format the relay verifies", async () => {
        const token = await createRelayState({
            appId: "myapp",
            targetOrigin: `https://${PREVIEW_HOST}`,
            callbackPath: "/cb",
            appState: "nonce",
            signingKey: "k",
        });
        expect(token.split(".")).toHaveLength(2);
    });
});
