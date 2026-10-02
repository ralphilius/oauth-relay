import { describe, expect, it } from "vitest";

import { createAppRegistry, type AppRegistryEntry } from "./app-registry";

const ENTRIES: Record<string, AppRegistryEntry> = {
  anys3: { allowedOriginSuffix: "anys3-dashboard.example.workers.dev" },
  other: { allowedOriginSuffix: "other-app.example.workers.dev" }
};

describe("app registry", () => {
  it("returns the entry for a known app id", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(registry.get("anys3")?.allowedOriginSuffix).toBe("anys3-dashboard.example.workers.dev");
  });

  it("returns undefined for an unknown app id", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(registry.get("unknown")).toBeUndefined();
  });

  it("accepts a target origin that ends with the app's allowed suffix", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(
      registry.isOriginAllowed("anys3", "https://some-branch-anys3-dashboard.example.workers.dev")
    ).toBe(true);
  });

  it("rejects the bare worker hostname (no branch prefix)", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(
      registry.isOriginAllowed("anys3", "https://anys3-dashboard.example.workers.dev")
    ).toBe(false);
  });

  it("rejects a hostname that ends with the suffix but has no delimiter before it", () => {
    const registry = createAppRegistry(ENTRIES);

    // "fooanys3-dashboard..." ends with the suffix but the char before it
    // is "o", not "-" or ".", so it must not match.
    expect(
      registry.isOriginAllowed("anys3", "https://fooanys3-dashboard.example.workers.dev")
    ).toBe(false);
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
      registry.isOriginAllowed("anys3", "https://some-branch-other-app.example.workers.dev")
    ).toBe(false);
  });

  it("rejects an origin check for an unknown app id", () => {
    const registry = createAppRegistry(ENTRIES);

    expect(
      registry.isOriginAllowed("unknown", "https://some-branch-anys3-dashboard.example.workers.dev")
    ).toBe(false);
  });

  it("rejects a suffix that is a substring match but not a domain suffix", () => {
    const registry = createAppRegistry({
      anys3: { allowedOriginSuffix: "anys3-dashboard.example.workers.dev" }
    });

    // Suffix appears as a substring but the host does not end with it as a
    // domain suffix (extra path-like component glued on).
    expect(
      registry.isOriginAllowed("anys3", "https://evil.anys3-dashboard.example.workers.dev.attacker.com")
    ).toBe(false);
  });
});

describe("global suffixes (ALLOWED_ORIGIN_SUFFIXES)", () => {
  const GLOBAL = ["example.workers.dev"];

  it("allows any appId whose origin matches a global suffix", () => {
    const registry = createAppRegistry({}, GLOBAL);
    expect(
      registry.isOriginAllowed("brand-new-app", "https://v123-new-app.example.workers.dev")
    ).toBe(true);
  });

  it("still rejects the apex hostname for a global suffix", () => {
    const registry = createAppRegistry({}, GLOBAL);
    expect(registry.isOriginAllowed("app", "https://example.workers.dev")).toBe(false);
    expect(registry.isOriginAllowed("app", "https://fooexample.workers.dev")).toBe(false);
  });

  it("rejects origins outside the global suffixes even for known apps", () => {
    const registry = createAppRegistry(ENTRIES, GLOBAL);
    expect(registry.isOriginAllowed("anys3", "https://evil.attacker.com")).toBe(false);
  });

  it("keeps honoring per-app entries alongside global suffixes", () => {
    const registry = createAppRegistry(
      { custom: { allowedOriginSuffix: "preview.custom-app.com" } },
      GLOBAL
    );
    expect(registry.isOriginAllowed("custom", "https://pr-7.preview.custom-app.com")).toBe(true);
    expect(registry.isOriginAllowed("custom", "https://any.example.workers.dev")).toBe(true);
    expect(registry.isOriginAllowed("custom", "https://evil.attacker.com")).toBe(false);
  });
});
