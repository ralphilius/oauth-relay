export type AppRegistryEntry = {
  allowedOriginSuffix: string;
};

export type AppRegistry = {
  get(appId: string): AppRegistryEntry | undefined;
  isOriginAllowed(appId: string, targetOrigin: string): boolean;
};

export function createAppRegistry(entries: Record<string, AppRegistryEntry>): AppRegistry {
  return {
    get(appId) {
      return entries[appId];
    },
    isOriginAllowed(appId, targetOrigin) {
      const entry = entries[appId];
      if (!entry) return false;

      try {
        const host = new URL(targetOrigin).hostname;
        const suffix = entry.allowedOriginSuffix;
        // Require a delimiter (- or .) before the suffix so hostnames like
        // "fooanys3-dashboard..." don't match, and require the host to be
        // strictly longer than the suffix so the bare worker URL is rejected.
        if (!host.endsWith(suffix) || host.length <= suffix.length) return false;
        const precedingChar = host[host.length - suffix.length - 1];
        return precedingChar === "-" || precedingChar === ".";
      } catch {
        return false;
      }
    }
  };
}
