# oauth-relay

A stateless Cloudflare Worker that relays Google OAuth callbacks to per-branch
preview deployments. Solves the problem of Google OAuth's fixed redirect URI
requirement conflicting with dynamic preview hostnames.

## How it works

```
Dashboard (preview)          Relay Worker              Google
     │                           │                       │
     │  1. createRelayState()    │                       │
     │     (HMAC-sign payload    │                       │
     │      with shared secret)  │                       │
     │                           │                       │
     │  2. redirect to Google ──────────────────────────▶│
     │     &state=<relay token>  │                       │
     │                           │                       │
     │                           │  3. Google redirects ◀│
     │                           │     /callback?code=.. │
     │                           │     &state=<token>    │
     │                           │                       │
     │                           │  4. verify signature  │
     │                           │     check expiry      │
     │                           │     check origin      │
     │                           │                       │
     │  5. 302 to preview host ◀─┘                       │
     │     ?code=..&state=<orig>                         │
     │                                                   │
     │  6. better-auth validates                         │
     │     original state, session ✓                     │
```

The app and relay share a single secret (`OAUTH_RELAY_SIGNING_KEY`). The
dashboard uses `createRelayState()` (~20 lines of HMAC signing) to compose the
relay token locally — no network call to the relay during sign-in start. The
relay verifies the token with the same secret and redirects to the preview host
with the original `appState` unwrapped.

## Configuration

### Global suffix allowlist (`ALLOWED_ORIGIN_SUFFIXES` var)

JSON array of hostname suffixes any app may relay to — the account's
`workers.dev` subdomain:

```json
["ralphilius.workers.dev"]
```

Only this Cloudflare account can deploy to `*.ralphilius.workers.dev`, so
listing it covers every app's preview hosts with zero per-app registration.

### Per-app registry (`APPS` var)

JSON mapping app IDs to an extra allowed origin suffix. Only needed when an
app's preview origins live outside the global suffixes (e.g. a custom domain):

```json
{"myapp": {"allowedOriginSuffix": "preview.myapp.example.com"}}
```

### Secrets

```bash
# Shared HMAC signing key — identical value on the relay and every app.
npx wrangler secret put OAUTH_RELAY_SIGNING_KEY
```

### Custom domain

Add a custom domain (e.g. `oauth-relay.ralphilius.com`) in the Cloudflare
dashboard, or remove the `routes` block from `wrangler.jsonc` to use the
default `*.workers.dev` URL.

## Deploy

```bash
pnpm install
npx wrangler deploy
```

## Development

```bash
pnpm test        # run unit tests
pnpm typecheck   # type-check
```

## Onboarding a new app

1. **Client package:** `pnpm add "github:ralphilius/oauth-relay#<sha>&path:packages/client"`
   (dist/ is committed — no build step), or `pnpm add oauth-relay-client` once
   it's on npm. Exposes `startRelaySignIn`, `handleRelayCallback`,
   `consumeRelayCredential`, `createRelayState`, `isPreviewHostname`,
   `getRelayContextForRequest` — fetch-level handlers you delegate to from
   your routes. Reference wiring: `sheetson/apps/site/app/api/auth/google/`.
2. **Worker vars** on the app: `OAUTH_RELAY_CALLBACK_URL=https://<relay-domain>/callback`,
   `OAUTH_RELAY_APP_ID=<slug>`, `PREVIEW_HOSTNAME_SUFFIX=<worker>.<subdomain>.workers.dev`.
3. **Secret:** `wrangler secret put OAUTH_RELAY_SIGNING_KEY` on the app — same
   shared value (grab from another app's `.dev.vars` or wherever you store it).
4. **Google Console:** add `https://<relay-domain>/callback` as an authorized
   redirect URI on that app's OAuth client (one URI total — shared by every
   preview host of that app).

For workers.dev previews no relay-side change is needed — the global suffix
already covers them. APPS entries are only for custom-domain suffixes.
