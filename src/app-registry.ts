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
        return host.endsWith(entry.allowedOriginSuffix);
      } catch {
        return false;
      }
    }
  };
}
