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

The dashboard and relay share a single secret (`APP_SECRET_<appId>`). The
dashboard uses `createRelayState()` (~20 lines of HMAC signing) to compose the
relay token locally — no network call to the relay during sign-in start. The
relay verifies the token with the same secret and redirects to the preview host
with the original `appState` unwrapped.

## Configuration

### App registry (`APPS` var)

JSON mapping app IDs to their allowed origin suffix:

```json
{"anys3": {"allowedOriginSuffix": ".anys3-dashboard.<account>.workers.dev"}}
```

### Secrets

```bash
# The shared HMAC signing key. The dashboard must have the same value
# set as OAUTH_RELAY_SIGNING_KEY.
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

## Adding a new app

1. Add the app to the `APPS` var in `wrangler.jsonc`.
2. Share the existing `OAUTH_RELAY_SIGNING_KEY` with the app.
3. Add `https://<relay-domain>/callback` to the app's Google OAuth redirect URIs.
