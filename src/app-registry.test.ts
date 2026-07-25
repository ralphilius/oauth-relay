import { describe, expect, it } from "vitest";

import { createAppRegistry, type AppRegistryEntry } from "./app-registry";

const ENTRIES: Record<string, AppRegistryEntry> = {
  anys3: { allowedOriginSuffix: ".anys3-dashboard.example.workers.dev" },
  other: { allowedOriginSuffix: ".other-app.example.workers.dev" }
};

describe("app registry", () => {
  it("returns the entry for a known app id", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(registry.get("anys3")?.allowedOriginSuffix).toBe(".anys3-dashboard.example.workers.dev");
  });

  it("returns undefined for an unknown app id", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(registry.get("unknown")).toBeUndefined();
  });

  it("accepts a target origin that ends with the app's allowed suffix", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(
      registry.isOriginAllowed("anys3", "https://preview.anys3-dashboard.example.workers.dev")
    ).toBe(true);
  });

  it("rejects a target origin that does not end with the app's allowed suffix", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(
      registry.isOriginAllowed("anys3", "https://evil.example.com")
    ).toBe(false);
  });

  it("rejects a target origin whose suffix matches another app's entry", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(
      registry.isOriginAllowed("anys3", "https://preview.other-app.example.workers.dev")
    ).toBe(false);
  });

  it("rejects an origin check for an unknown app id", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(
      registry.isOriginAllowed("unknown", "https://preview.anys3-dashboard.example.workers.dev")
    ).toBe(false);
  });

  it("rejects a suffix that is a substring match but not a domain suffix", () => {
    const registry = createAppRegistry({
      anys3: { allowedOriginSuffix: ".anys3-dashboard.example.workers.dev" }
    });

    // Suffix appears as a substring but the host does not end with it as a
    // domain suffix (extra path-like component glued on).
    expect(
      registry.isOriginAllowed("anys3", "https://evil.anys3-dashboard.example.workers.dev.attacker.com")
    ).toBe(false);
  });
});
