import { expect, test, type Page } from "@playwright/test";

function lookupFixture(query: string, overrides: Record<string, any> = {}) {
  const base = {
    query,
    normalizedQuery: query,
    type: "domain",
    status: "registered",
    source: { primary: "rdap", used: ["rdap"], errors: [] },
    domain: { name: query, suffix: query.split(".").slice(1).join("."), registeredDomain: query, reserved: false, registered: true },
    registry: {},
    registrar: { name: "Fixture Registrar" },
    dates: {},
    statuses: [],
    nameservers: [{ host: `ns1.${query}` }, { host: `ns2.${query}` }],
    dnssec: {},
    registrant: {},
    network: {},
    enrichment: { dnsviz: { url: `https://dnsviz.net/d/${query}/dnssec/` } },
    raw: { rdap: "{}" },
    meta: { elapsedMs: 7, providers: [] },
  };
  return {
    ...base,
    ...overrides,
    source: { ...base.source, ...(overrides.source || {}) },
    domain: { ...base.domain, ...(overrides.domain || {}) },
    registry: { ...base.registry, ...(overrides.registry || {}) },
    registrar: { ...base.registrar, ...(overrides.registrar || {}) },
    dates: { ...base.dates, ...(overrides.dates || {}) },
    dnssec: { ...base.dnssec, ...(overrides.dnssec || {}) },
    registrant: { ...base.registrant, ...(overrides.registrant || {}) },
    network: { ...base.network, ...(overrides.network || {}) },
    enrichment: { ...base.enrichment, ...(overrides.enrichment || {}) },
    raw: { ...base.raw, ...(overrides.raw || {}) },
    meta: { ...base.meta, ...(overrides.meta || {}) },
  };
}

async function routeLookupFixtures(page: Page, fixtures: Record<string, any>) {
  await page.route("**/api/lookup?**", async (route) => {
    const url = new URL(route.request().url());
    const query = url.searchParams.get("query") || "";
    const result = fixtures[query];
    if (!result) {
      await route.fallback();
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ ok: true, result }),
    });
  });
}

async function seedLookup(page: Page, query = "fixture.test", result = lookupFixture(query)) {
  await routeLookupFixtures(page, { [query]: result });
  await page.goto("/lookup");
  await page.getByLabel("Search query").fill(query);
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByRole("heading", { name: query })).toBeVisible();
}

test("home page hydrates without stale shell markup", async ({ page }) => {
  const hydrationErrors: string[] = [];
  const collectHydrationError = (text: string) => {
    if (/Hydration failed|Expected server HTML|error while hydrating/i.test(text)) {
      hydrationErrors.push(text);
    }
  };

  page.on("console", (message) => collectHydrationError(message.text()));
  page.on("pageerror", (error) => collectHydrationError(error.message));

  await page.goto("/");
  await expect(page.locator(".advanced-lookup")).toHaveCount(1);
  await expect(page.locator("form.lookup-form details")).toHaveCount(0);
  await page.waitForTimeout(500);

  expect(hydrationErrors).toEqual([]);
});

test("status page exposes runtime capabilities and plugin descriptors", async ({ page, request }) => {
  await page.goto("/status");

  await expect(page.getByRole("heading", { name: "System status" })).toBeVisible();
  await expect(page.getByText("healthy")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Capabilities" })).toBeVisible();
  const capabilities = page.getByLabel("Runtime capabilities");
  await expect(capabilities.getByText("RDAP", { exact: true })).toBeVisible();
  await expect(capabilities.getByText("WHOIS", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Plugins" })).toBeVisible();
  const plugins = page.getByLabel("Runtime plugins");
  await expect(plugins.getByText("provider", { exact: true })).toBeVisible();
  await expect(plugins.getByText("parser", { exact: true })).toBeVisible();

  const version = await request.get("/api/version");
  expect(version.ok()).toBeTruthy();
  const body = await version.json();
  expect(body.plugins.length).toBeGreaterThan(0);
});

test("result page searches in place without a full document navigation", async ({ page }) => {
  let documentNavigations = 0;
  page.on("request", (request) => {
    if (request.isNavigationRequest() && request.resourceType() === "document") {
      documentNavigations += 1;
    }
  });

  await page.goto("/lookup?query=example.com&rdap=1&whois_follow=0");
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();
  const initialNavigations = documentNavigations;
  let cloudflareLookups = 0;
  page.on("request", (request) => {
    const url = request.url();
    if (url.includes("/api/lookup?") && url.includes("query=cloudflare.com")) {
      cloudflareLookups += 1;
    }
  });

  await page.getByLabel("Search query").fill("cloudflare.com");
  await page.getByRole("button", { name: "Search" }).click();

  await expect(page).toHaveURL(/\/lookup\?query=cloudflare\.com/);
  await expect(page.getByRole("heading", { name: "cloudflare.com" })).toBeVisible();
  await expect(page.getByText("Provider Trace")).toBeVisible();
  expect(documentNavigations).toBe(initialNavigations);
  await page.waitForTimeout(750);
  expect(cloudflareLookups).toBe(1);
});

test("separator typos normalize from home and result searches without repeated requests", async ({ page }) => {
  let exampleLookups = 0;
  page.on("request", (request) => {
    const url = request.url();
    if (url.includes("/api/lookup?") && url.includes("query=example.com")) {
      exampleLookups += 1;
    }
  });

  await page.goto("/");
  await page.locator("#whoice-search").fill(" example，com ");
  await page.getByRole("button", { name: "Search" }).click();

  await expect(page).toHaveURL(/\/lookup\?query=example\.com/);
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();
  await page.waitForTimeout(750);
  expect(exampleLookups).toBeLessThanOrEqual(1);

  let cloudflareLookups = 0;
  page.on("request", (request) => {
    const url = request.url();
    if (url.includes("/api/lookup?") && url.includes("query=cloudflare.com")) {
      cloudflareLookups += 1;
    }
  });

  await page.getByLabel("Search query").fill(" cloudflare，com ");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page).toHaveURL(/\/lookup\?query=cloudflare\.com/);
  await expect(page.getByRole("heading", { name: "cloudflare.com" })).toBeVisible();
  await page.waitForTimeout(750);
  expect(cloudflareLookups).toBe(1);
});

test("result plugins tolerate null arrays from stale or nonconforming APIs", async ({ page }) => {
  await page.goto("/lookup?query=example.com&rdap=1&whois_follow=0");
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();

  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await page.route("**/api/lookup?**query=nullarray.test**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          query: "nullarray.test",
          normalizedQuery: "nullarray.test",
          type: "domain",
          status: "registered",
          source: { primary: "rdap", used: ["rdap"], errors: null },
          domain: { name: "nullarray.test", reserved: false, registered: true },
          registry: {},
          registrar: {},
          dates: {},
          statuses: null,
          nameservers: null,
          dnssec: {},
          registrant: {},
          network: {},
          enrichment: null,
          raw: {},
          meta: { elapsedMs: 3, providers: null, warnings: null },
        },
      }),
    });
  });

  await page.getByLabel("Search query").fill("nullarray.test");
  await page.getByRole("button", { name: "Search" }).click();

  await expect(page.getByRole("heading", { name: "nullarray.test" })).toBeVisible();
  await expect(page.getByText("No nameservers parsed.")).toBeVisible();
  await page.waitForTimeout(500);
  expect(pageErrors).toEqual([]);
});

test("source switch, controls, lookup proxy path, and DNSViz panel stay usable", async ({ page, request }) => {
  await routeLookupFixtures(page, {
    "dnsviz-fixture.test": lookupFixture("dnsviz-fixture.test"),
  });
  await page.goto("/lookup");
  await page.getByLabel("Search query").fill("dnsviz-fixture.test");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByRole("heading", { name: "dnsviz-fixture.test" })).toBeVisible();

  await page.getByRole("radio", { name: "WHOIS" }).click();
  await expect(page).toHaveURL(/whois=1/);
  await expect(page.getByRole("radio", { name: "WHOIS" })).toHaveAttribute("aria-checked", "true");

  await page.getByLabel("Theme").selectOption("dark");
  await page.getByLabel("Language").selectOption("zh-CN");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");

  await expect(page.getByRole("heading", { name: "DNSViz", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open DNSViz" })).toHaveAttribute("href", /dnsviz\.net\/d\/dnsviz-fixture\.test\/dnssec\//);

  const proxiedLookup = await request.get("/api/lookup?query=example.com&rdap=1&whois_follow=0");
  expect(proxiedLookup.ok()).toBeTruthy();
});

test("deferred enrichment updates stay inside stable result slots", async ({ page }) => {
  await page.goto("/lookup?query=example.com&rdap=1&whois_follow=0");
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();

  let releaseEnrichment!: () => void;
  const enrichmentReleased = new Promise<void>((resolve) => {
    releaseEnrichment = resolve;
  });

  await page.route("**/api/lookup?**", async (route) => {
    const url = new URL(route.request().url());
    if (url.searchParams.get("query") !== "stable-layout.test") {
      await route.fallback();
      return;
    }
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          query: "stable-layout.test",
          normalizedQuery: "stable-layout.test",
          type: "domain",
          status: "registered",
          source: { primary: "rdap", used: ["rdap"], errors: [] },
          domain: { name: "stable-layout.test", suffix: "test", registeredDomain: "stable-layout.test", reserved: false, registered: true },
          registry: {},
          registrar: { name: "Fixture Registrar" },
          dates: {},
          statuses: [],
          nameservers: [],
          dnssec: {},
          registrant: {},
          network: {},
          enrichment: { dnsviz: { url: "https://dnsviz.net/d/stable-layout.test/dnssec/" } },
          raw: { rdap: "{}" },
          meta: { elapsedMs: 12, pendingEnrichments: ["dns", "pricing"], providers: [] },
        },
      }),
    });
  });

  await page.route("**/api/lookup/enrich", async (route) => {
    const request = route.request();
    const payload = JSON.parse(request.postData() || "{}");
    const result = payload.result;
    await enrichmentReleased;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          ...result,
          enrichment: {
            ...(result.enrichment || {}),
            dns: {
              a: [{ ip: "93.184.216.34", version: "ipv4", source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve" }],
              ns: ["a.iana-servers.net", "b.iana-servers.net"],
              registryNs: ["a.iana-servers.net", "b.iana-servers.net"],
              resolvers: [{ source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve", status: "ok" }],
              elapsedMs: 42,
            },
            pricing: {
              currency: "USD",
              provider: "test",
              source: "fixture",
              registerOffer: { registrar: "Example Registrar", price: 9.99, currency: "USD", website: "https://example.com" },
              renewOffer: { registrar: "Renew Registrar", price: 12.5, currency: "USD", website: "https://example.net" },
            },
          },
          meta: {
            ...(result.meta || {}),
            pendingEnrichments: [],
          },
        },
      }),
    });
  });

  await page.getByLabel("Search query").fill("stable-layout.test");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.getByRole("heading", { name: "stable-layout.test" })).toBeVisible();
  await expect(page.getByText("DNS records are updating in the background.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Evidence" })).toBeVisible();

  const before = await page.locator(".tool-zone", { hasText: "Evidence" }).boundingBox();
  releaseEnrichment();
  await expect(page.getByRole("heading", { name: "Pricing" })).toBeVisible();
  await expect(page.getByText("Example Registrar")).toBeVisible();
  const after = await page.locator(".tool-zone", { hasText: "Evidence" }).boundingBox();

  expect(Math.abs((after?.y ?? 0) - (before?.y ?? 0))).toBeLessThanOrEqual(8);
});

test("AI metadata and parsed fields survive deferred enrichment", async ({ page }) => {
  let releaseEnrichment!: () => void;
  const enrichmentReleased = new Promise<void>((resolve) => {
    releaseEnrichment = resolve;
  });

  await page.route("**/api/lookup?**query=ai-stable.test**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          query: "ai-stable.test",
          normalizedQuery: "ai-stable.test",
          type: "domain",
          status: "registered",
          source: { primary: "whois", used: ["whois"], errors: [] },
          domain: { name: "ai-stable.test", suffix: "test", registeredDomain: "ai-stable.test", reserved: false, registered: true },
          registry: {},
          registrar: { name: "Fixture Registrar" },
          dates: {},
          statuses: [],
          nameservers: [],
          dnssec: {},
          registrant: {
            name: "AI Parsed Person",
            fieldSources: {
              name: [{ label: "Name", value: "AI Parsed Person", source: "ai:qwen", confidence: 1, evidence: "Registrant" }],
            },
          },
          network: {},
          enrichment: { dnsviz: { url: "https://dnsviz.net/d/ai-stable.test/dnssec/" } },
          raw: { whois: "Registrant: AI Parsed Person" },
          meta: {
            elapsedMs: 21,
            pendingEnrichments: ["dns", "pricing"],
            providers: [],
            ai: { status: "ok", provider: "fixture", model: "fixture-ai", applied: ["name"] },
          },
        },
      }),
    });
  });

  await page.route("**/api/lookup/enrich", async (route) => {
    const payload = JSON.parse(route.request().postData() || "{}");
    const result = payload.result;
    await enrichmentReleased;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          ...result,
          registrant: {},
          enrichment: {
            ...(result.enrichment || {}),
            dns: {
              a: [{ ip: "203.0.113.10", version: "ipv4", source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve" }],
              resolvers: [{ source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve", status: "ok" }],
              elapsedMs: 18,
            },
            pricing: {
              currency: "USD",
              provider: "fixture",
              source: "fixture",
              registerOffer: { registrar: "Price Registrar", price: 10, currency: "USD" },
              renewOffer: { registrar: "Renew Registrar", price: 12, currency: "USD" },
            },
          },
          meta: { elapsedMs: 44, pendingEnrichments: [], providers: [] },
        },
      }),
    });
  });

  await seedLookup(page);
  await page.getByLabel("Search query").fill("ai-stable.test");
  await page.getByRole("button", { name: "Search" }).click();

  const registration = page.locator(".registration-panel");
  await expect(registration.getByText("AI ok")).toBeVisible();
  await expect(registration.getByText("AI Parsed Person", { exact: true })).toBeVisible();
  releaseEnrichment();
  await expect(page.getByText("Price Registrar")).toBeVisible();
  await expect(registration.getByText("AI ok")).toBeVisible();
  await expect(registration.getByText("AI Parsed Person", { exact: true })).toBeVisible();
});

test("AI option waits for an explicit search", async ({ page }) => {
  let aiRequests = 0;
  await page.route("**/api/lookup/ai", async (route) => {
    aiRequests += 1;
    const payload = JSON.parse(route.request().postData() || "{}");
    const result = payload.result;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          ...result,
          registrant: { ...(result.registrant || {}), name: "Toggle AI Person" },
          meta: { ...(result.meta || {}), ai: { status: "ok", provider: "fixture", model: "fixture-ai", applied: ["name"] } },
        },
      }),
    });
  });

  await page.route("**/api/lookup?**query=ai-toggle.test**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          query: "ai-toggle.test",
          normalizedQuery: "ai-toggle.test",
          type: "domain",
          status: "registered",
          source: { primary: "whois", used: ["whois"], errors: [] },
          domain: { name: "ai-toggle.test", suffix: "test", registeredDomain: "ai-toggle.test", reserved: false, registered: true },
          registry: {},
          registrar: {},
          dates: {},
          statuses: [],
          nameservers: [],
          dnssec: {},
          registrant: {},
          network: {},
          enrichment: {},
          raw: { whois: "Registrant: Toggle Person" },
          meta: { elapsedMs: 9, providers: [] },
        },
      }),
    });
  });

  await seedLookup(page);
  await page.getByLabel("AI parser").check();
  await page.waitForTimeout(300);
  expect(aiRequests).toBe(0);

  await page.getByLabel("Search query").fill("ai-toggle.test");
  await page.getByRole("button", { name: "Search" }).click();
  await expect(page.locator(".registration-panel").getByText("AI ok")).toBeVisible();
  await expect(page.locator(".registration-panel").getByText("Toggle AI Person", { exact: true })).toBeVisible();
  expect(aiRequests).toBe(1);
});

test("AI ignored status survives deferred enrichment", async ({ page }) => {
  let releaseEnrichment!: () => void;
  const enrichmentReleased = new Promise<void>((resolve) => {
    releaseEnrichment = resolve;
  });

  await page.route("**/api/lookup?**query=ai-ignored.test**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          query: "ai-ignored.test",
          normalizedQuery: "ai-ignored.test",
          type: "domain",
          status: "registered",
          source: { primary: "whois", used: ["whois"], errors: [] },
          domain: { name: "ai-ignored.test", suffix: "test", registeredDomain: "ai-ignored.test", reserved: false, registered: true },
          registry: {},
          registrar: { name: "Fixture Registrar" },
          dates: {},
          statuses: [],
          nameservers: [],
          dnssec: {},
          registrant: { name: "Rule Parsed Person" },
          network: {},
          enrichment: { dnsviz: { url: "https://dnsviz.net/d/ai-ignored.test/dnssec/" } },
          raw: { whois: "Registrant: Rule Parsed Person" },
          meta: {
            elapsedMs: 11,
            pendingEnrichments: ["dns", "pricing"],
            providers: [],
            ai: { status: "ignored", provider: "fixture", model: "fixture-ai", reason: "suffix ignored", applied: [] },
          },
        },
      }),
    });
  });

  await page.route("**/api/lookup/enrich", async (route) => {
    const payload = JSON.parse(route.request().postData() || "{}");
    const result = payload.result;
    await enrichmentReleased;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          ...result,
          meta: { elapsedMs: 40, pendingEnrichments: [], providers: [] },
          enrichment: {
            ...(result.enrichment || {}),
            dns: {
              a: [{ ip: "203.0.113.20", version: "ipv4", source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve" }],
              resolvers: [{ source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve", status: "ok" }],
            },
            pricing: {
              currency: "USD",
              provider: "fixture",
              source: "fixture",
              registerOffer: { registrar: "Ignored Price Registrar", price: 8.8, currency: "USD" },
            },
          },
        },
      }),
    });
  });

  await seedLookup(page);
  await page.getByLabel("Search query").fill("ai-ignored.test");
  await page.getByRole("button", { name: "Search" }).click();

  const registration = page.locator(".registration-panel");
  await expect(registration.getByText("AI ignored")).toBeVisible();
  releaseEnrichment();
  await expect(page.getByText("Ignored Price Registrar")).toBeVisible();
  await expect(registration.getByText("AI ignored")).toBeVisible();
  await expect(registration.getByText("Rule Parsed Person", { exact: true })).toBeVisible();
});

test("lookup failure state is actionable without crashing the workbench", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await page.route("**/api/lookup?**query=broken.test**", async (route) => {
    await route.fulfill({
      status: 502,
      contentType: "application/json",
      body: JSON.stringify({
        ok: false,
        error: {
          code: "upstream_failed",
          message: "Lookup failed",
        },
      }),
    });
  });

  await seedLookup(page);

  await page.getByLabel("Search query").fill("broken.test");
  await page.getByRole("button", { name: "Search" }).click();

  await expect(page).toHaveURL(/\/lookup\?query=broken\.test/);
  await expect(page.getByRole("heading", { name: "Lookup API unavailable" })).toBeVisible();
  await expect(page.getByText("Whoice could not reach the lookup API or received a gateway error page instead of JSON.")).toBeVisible();
  await expect(page.locator(".tool-sidebar")).toBeVisible();
  await expect(page.locator(".error-panel")).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("HTML gateway failures render a dedicated API unavailable state", async ({ page }) => {
  await page.route("**/api/lookup?**query=html-gateway.test**", async (route) => {
    await route.fulfill({
      status: 502,
      contentType: "text/html",
      body: "<!DOCTYPE html><html><body>Bad gateway</body></html>",
    });
  });

  await seedLookup(page);
  await page.getByLabel("Search query").fill("html-gateway.test");
  await page.getByRole("button", { name: "Search" }).click();

  await expect(page.getByRole("heading", { name: "Lookup API unavailable" })).toBeVisible();
  await expect(page.getByText("Whoice could not reach the lookup API or received a gateway error page instead of JSON.")).toBeVisible();
  await expect(page.getByText("Unexpected token")).toHaveCount(0);
});

test("mobile-chrome touch-friendly layout has no horizontal overflow", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-chrome", "mobile layout is covered by the mobile-chrome project");

  await seedLookup(page);
  await expect(page.getByLabel("Lookup toolbox")).toBeVisible();
  await expect(page.getByLabel("Lookup result workspace")).toBeVisible();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(2);

  const touchTargets = page.locator(".tool-panel button, .source-option, .inline-check");
  const count = await touchTargets.count();
  expect(count).toBeGreaterThan(0);
  for (let index = 0; index < Math.min(count, 8); index += 1) {
    const box = await touchTargets.nth(index).boundingBox();
    expect(box?.height ?? 0).toBeGreaterThanOrEqual(34);
  }

  await page.getByRole("radio", { name: "RDAP" }).tap();
  await expect(page.getByRole("radio", { name: "RDAP" })).toHaveAttribute("aria-checked", "true");
  await page.getByRole("button", { name: "Copy raw" }).tap();
});

test("mobile deferred enrichment keeps toolbox slots stable", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-chrome", "mobile slot stability is covered by the mobile-chrome project");

  let releaseEnrichment!: () => void;
  const enrichmentReleased = new Promise<void>((resolve) => {
    releaseEnrichment = resolve;
  });

  await page.route("**/api/lookup?**query=mobile-stable.test**", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          query: "mobile-stable.test",
          normalizedQuery: "mobile-stable.test",
          type: "domain",
          status: "registered",
          source: { primary: "rdap", used: ["rdap"], errors: [] },
          domain: { name: "mobile-stable.test", suffix: "test", registeredDomain: "mobile-stable.test", reserved: false, registered: true },
          registry: {},
          registrar: { name: "Fixture Registrar" },
          dates: {},
          statuses: [],
          nameservers: [],
          dnssec: {},
          registrant: {},
          network: {},
          enrichment: { dnsviz: { url: "https://dnsviz.net/d/mobile-stable.test/dnssec/" } },
          raw: { rdap: "{}" },
          meta: { elapsedMs: 12, pendingEnrichments: ["dns", "pricing"], providers: [] },
        },
      }),
    });
  });

  await page.route("**/api/lookup/enrich", async (route) => {
    const payload = JSON.parse(route.request().postData() || "{}");
    const result = payload.result;
    await enrichmentReleased;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        result: {
          ...result,
          enrichment: {
            ...(result.enrichment || {}),
            dns: {
              a: [{ ip: "93.184.216.34", version: "ipv4", source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve" }],
              ns: ["a.iana-servers.net", "b.iana-servers.net"],
              registryNs: ["a.iana-servers.net", "b.iana-servers.net"],
              resolvers: [{ source: "doh", resolver: "dns.google", endpoint: "https://dns.google/resolve", status: "ok" }],
              elapsedMs: 42,
            },
            pricing: {
              currency: "USD",
              provider: "test",
              source: "fixture",
              registerOffer: { registrar: "Example Registrar", price: 9.99, currency: "USD" },
              renewOffer: { registrar: "Renew Registrar", price: 12.5, currency: "USD" },
            },
          },
          meta: { ...(result.meta || {}), pendingEnrichments: [] },
        },
      }),
    });
  });

  await seedLookup(page);
  await page.getByLabel("Search query").fill("mobile-stable.test");
  await page.getByRole("button", { name: "Search" }).tap();
  await expect(page.getByRole("heading", { name: "mobile-stable.test" })).toBeVisible();

  const overviewBefore = await page.locator(".zone-body-overview").boundingBox();
  const ownershipBefore = await page.locator(".zone-body-ownership").boundingBox();
  releaseEnrichment();
  await expect(page.getByText("Example Registrar")).toBeVisible();
  const overviewAfter = await page.locator(".zone-body-overview").boundingBox();
  const ownershipAfter = await page.locator(".zone-body-ownership").boundingBox();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);

  expect(Math.abs((overviewAfter?.height ?? 0) - (overviewBefore?.height ?? 0))).toBeLessThanOrEqual(2);
  expect(Math.abs((ownershipAfter?.height ?? 0) - (ownershipBefore?.height ?? 0))).toBeLessThanOrEqual(2);
  expect(overflow).toBeLessThanOrEqual(2);
  await expect(page.getByText("...", { exact: true })).toHaveCount(0);
});
