export type AppRegistryEntry = {
  allowedOriginSuffix: string;
};

export type AppRegistry = {
  get(appId: string): AppRegistryEntry | undefined;
  isOriginAllowed(appId: string, targetOrigin: string): boolean;
};

// A suffix matches when the host ends with it AND a delimiter ("-" or ".")
// precedes it — so "foosheetson…" doesn't match "sheetson…" — and the host is
// strictly longer than the suffix so the bare apex host is rejected.
function matchesSuffix(host: string, suffix: string): boolean {
  if (!host.endsWith(suffix) || host.length <= suffix.length) return false;
  const precedingChar = host[host.length - suffix.length - 1];
  return precedingChar === "-" || precedingChar === ".";
}

/**
 * Origin allowlist. An origin is allowed when its hostname matches EITHER:
 * - the app-specific `allowedOriginSuffix` from `APPS` (custom domains), or
 * - any entry in `globalSuffixes` (ALLOWED_ORIGIN_SUFFIXES) — typically the
 *   account's workers.dev subdomain, which only this account can deploy to.
 *   This is what lets a new app onboard without a registry entry.
 */
export function createAppRegistry(
  entries: Record<string, AppRegistryEntry>,
  globalSuffixes: string[] = []
): AppRegistry {
  return {
    get(appId) {
      return entries[appId];
    },
    isOriginAllowed(appId, targetOrigin) {
      let host: string;
      try {
        host = new URL(targetOrigin).hostname;
      } catch {
        return false;
      }

      const appSuffix = entries[appId]?.allowedOriginSuffix;
      const candidates = appSuffix ? [appSuffix, ...globalSuffixes] : globalSuffixes;
      return candidates.some((suffix) => matchesSuffix(host, suffix));
    }
  };
}
