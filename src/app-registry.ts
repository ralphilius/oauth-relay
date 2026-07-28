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
        // Require the host to be strictly longer than the suffix so the bare
        // worker URL (no branch prefix) is not treated as a valid target.
        return host.endsWith(entry.allowedOriginSuffix)
          && host.length > entry.allowedOriginSuffix.length;
      } catch {
        return false;
      }
    }
  };
}
