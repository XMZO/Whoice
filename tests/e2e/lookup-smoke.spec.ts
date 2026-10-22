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

// Result sections are tabs on short desktop and mobile viewports; on tall desktops every
// section is visible and there is no tab to click.
async function showSection(page: Page, name: RegExp) {
  // The page renders a pending view (with the query as heading) until the
  // streamed result arrives; tabs only exist once it has.
  await expect(page.locator(".lookup-pending")).toHaveCount(0);
  const tab = page.getByRole("tab", { name });
  if (await tab.count()) {
    await tab.first().click();
    await expect(tab.first()).toHaveAttribute("aria-selected", "true");
  }
}

async function chooseSource(page: Page, source: "rdap" | "whois") {
  const radio = page.getByRole("radio", { name: source === "rdap" ? "RDAP" : "WHOIS" });
  if (await radio.isVisible()) {
    await radio.click();
    await expect(radio).toHaveAttribute("aria-checked", "true");
  } else {
    await page.getByLabel("Source", { exact: true }).selectOption(source);
  }
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
  await showSection(page, /^Sources/);
  await expect(page.locator("#evidence")).toBeVisible();
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
  await showSection(page, /^DNS/);
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

  await chooseSource(page, "whois");
  await expect(page).toHaveURL(/whois=1/);

  await page.getByLabel("Theme").selectOption("dark");
  await page.getByLabel("Language").selectOption("zh-CN");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");

  await showSection(page, /^DNS/);
  await expect(page.getByRole("link", { name: /DNSViz/ })).toHaveAttribute("href", /dnsviz\.net\/d\/dnsviz-fixture\.test\/dnssec\//);

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
  await showSection(page, /^DNS/);
  await expect(page.getByText("DNS records are updating in the background.")).toBeVisible();

  const heroBefore = await page.locator(".result-hero").boundingBox();
  const lowerBefore = await page.locator(".result-lower").boundingBox();
  releaseEnrichment();
  await showSection(page, /^Pric/);
  await expect(page.getByText("Example Registrar")).toBeVisible();
  const heroAfter = await page.locator(".result-hero").boundingBox();
  const lowerAfter = await page.locator(".result-lower").boundingBox();

  expect(Math.abs((heroAfter?.height ?? 0) - (heroBefore?.height ?? 0))).toBeLessThanOrEqual(2);
  expect(Math.abs((lowerAfter?.y ?? 0) - (lowerBefore?.y ?? 0))).toBeLessThanOrEqual(8);
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
  await showSection(page, /^Registrant/);
  await expect(registration.getByText("AI ok")).toBeVisible();
  await expect(registration.getByText("AI Parsed Person", { exact: true })).toBeVisible();
  releaseEnrichment();
  await showSection(page, /^Pric/);
  await expect(page.getByText("Price Registrar")).toBeVisible();
  await showSection(page, /^Registrant/);
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
  await expect(page.getByRole("heading", { name: "ai-toggle.test" })).toBeVisible();
  await showSection(page, /^Registrant/);
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
  await showSection(page, /^Registrant/);
  await expect(registration.getByText("AI ignored")).toBeVisible();
  releaseEnrichment();
  await showSection(page, /^Pric/);
  await expect(page.getByText("Ignored Price Registrar")).toBeVisible();
  await showSection(page, /^Registrant/);
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
  const verticalOverflow = await page.evaluate(() => document.documentElement.scrollHeight - window.innerHeight);
  expect(verticalOverflow).toBeLessThanOrEqual(2);

  const touchTargets = page.locator(".mini-search button, .result-tab, .action-btn").filter({ visible: true });
  const count = await touchTargets.count();
  expect(count).toBeGreaterThan(0);
  for (let index = 0; index < Math.min(count, 8); index += 1) {
    const box = await touchTargets.nth(index).boundingBox();
    expect(box?.height ?? 0).toBeGreaterThanOrEqual(34);
  }

  await chooseSource(page, "rdap");
  await expect(page).toHaveURL(/rdap=1/);
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

  const stageBefore = await page.locator(".tool-stage").boundingBox();
  await showSection(page, /^Pric/);
  releaseEnrichment();
  await expect(page.getByText("Example Registrar")).toBeVisible();
  const stageAfter = await page.locator(".tool-stage").boundingBox();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  const verticalOverflow = await page.evaluate(() => document.documentElement.scrollHeight - window.innerHeight);

  expect(Math.abs((stageAfter?.height ?? 0) - (stageBefore?.height ?? 0))).toBeLessThanOrEqual(2);
  expect(Math.abs((stageAfter?.y ?? 0) - (stageBefore?.y ?? 0))).toBeLessThanOrEqual(2);
  expect(overflow).toBeLessThanOrEqual(2);
  expect(verticalOverflow).toBeLessThanOrEqual(2);
  await expect(page.getByText("...", { exact: true })).toHaveCount(0);
});

test("admin panel signs in, saves a setting, and fits one screen", async ({ page }, testInfo) => {
  await page.goto("/admin");
  await page.getByLabel("Password").fill("e2e-admin-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // playwright.config.ts sets WHOICE_PROVIDER_TIMEOUT, so that field is read-only in the panel.
  await page.getByRole("button", { name: "Lookup", exact: true }).click();
  await expect(page.getByLabel("Per-source timeout")).toBeDisabled();
  await expect(page.getByText("Set by WHOICE_PROVIDER_TIMEOUT")).toBeVisible();

  await page.getByRole("button", { name: "DNS", exact: true }).click();
  const dnsTimeout = page.getByLabel("Timeout", { exact: true });
  const original = await dnsTimeout.inputValue();
  const next = original === "4s" ? "5s" : "4s";
  await dnsTimeout.fill(next);
  await expect(page.getByText("1 unsaved")).toBeVisible();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Saved and applied")).toBeVisible();

  await page.reload();
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  await expect(page.getByLabel("Timeout", { exact: true })).toHaveValue(next);
  await page.getByLabel("Timeout", { exact: true }).fill(original);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Saved and applied")).toBeVisible();

  if (testInfo.project.name === "mobile-chrome") {
    const verticalOverflow = await page.evaluate(() => document.documentElement.scrollHeight - window.innerHeight);
    expect(verticalOverflow).toBeLessThanOrEqual(2);
  }
});

test("first visit follows the browser language until one is picked", async ({ browser }) => {
  for (const [locale, lang] of [["zh-CN", "zh-CN"], ["zh-TW", "zh-TW"], ["zh-HK", "zh-TW"], ["fr-FR", "en"]] as const) {
    const context = await browser.newContext({ locale });
    const page = await context.newPage();
    await page.goto("/");
    await expect(page.locator("html")).toHaveAttribute("lang", lang);
    await context.close();
  }

  // A language picked in the UI is remembered over the browser's.
  const context = await browser.newContext({ locale: "zh-CN" });
  const page = await context.newPage();
  await page.goto("/");
  await page.locator('select[aria-label="语言"]:visible').first().selectOption("en");
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await context.close();
});

test("a failed provider is greyed out without a warning while another one answered", async ({ page }) => {
  const query = "quiet-provider.test";
  await seedLookup(
    page,
    query,
    lookupFixture(query, {
      source: { primary: "rdap", used: ["rdap"], errors: [{ source: "whois", error: "connection refused" }] },
      meta: {
        elapsedMs: 9,
        warnings: ["empty WHOIS response"],
        providers: [
          { source: "rdap", status: "ok", elapsedMs: 5, server: "https://rdap.example/" },
          { source: "whois", status: "error", elapsedMs: 4, server: "whois.example", error: "connection refused" },
        ],
      },
    }),
  );
  await expect(page.locator(".warn-pill")).toHaveCount(0);
  await showSection(page, /Sources/);
  await expect(page.locator(".trace-row.trace-quiet")).toContainText("connection refused");
});

test("the result layout is in place before the first source answers and does not move", async ({ page }, testInfo) => {
  const query = "steady-layout.test";
  let release: () => void = () => {};
  const answered = new Promise<void>((resolve) => (release = resolve));
  await page.route("**/api/lookup?**", async (route) => {
    await answered;
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ ok: true, result: lookupFixture(query, { dates: { createdAt: "2001-02-03T00:00:00Z", expiresAt: "2031-02-03T00:00:00Z" } }) }),
    });
  });
  await page.goto(`/lookup?query=${query}`);
  await expect(page.locator(".lookup-pending")).toBeVisible();
  if (testInfo.project.name === "mobile-chrome") {
    await expect(page.locator(".mobile-tabs")).toBeVisible();
  } else {
    await expect(page.locator(".result-lower")).toBeVisible();
  }
  const before = await page.locator(".metric-grid").boundingBox();
  release();
  await expect(page.locator(".lookup-pending")).toHaveCount(0);
  await expect(page.locator(".metric-grid")).toContainText("Fixture Registrar");
  const after = await page.locator(".metric-grid").boundingBox();
  expect(after).toEqual(before);
});

test("the ICP block says whether the suffix can be filed", async ({ page }) => {
  for (const [query, eligible, label] of [
    ["fileable.cn", true, "Fileable suffix"],
    ["not-fileable.org", false, "Suffix not fileable"],
  ] as const) {
    await seedLookup(page, query, lookupFixture(query, { enrichment: { icpFiling: { eligible, suffix: query.split(".").pop() } } }));
    await showSection(page, /^Registrant/);
    await expect(page.locator(".icp-block")).toContainText(label);
    await page.unrouteAll({ behavior: "ignoreErrors" });
  }
});

test("marketplace listings and registry deletion stages get their own badges", async ({ page }) => {
  const hero = page.locator(".result-hero");
  await seedLookup(page, "listed.test", lookupFixture("listed.test", { enrichment: { forSale: { market: "Atom", website: "https://www.atom.com" } } }));
  await expect(hero).toContainText("For sale · Atom");
  await page.unrouteAll({ behavior: "ignoreErrors" });

  // RFC 3915: redemption carries redemptionPeriod alongside pendingDelete.
  await seedLookup(page, "redeem.test", lookupFixture("redeem.test", { statuses: [{ code: "pendingDelete" }, { code: "redemptionPeriod" }] }));
  await expect(hero).toContainText("Redemption period");
  await expect(hero).not.toContainText("Pending delete");
  await expect(hero).not.toContainText("For sale");
  await page.unrouteAll({ behavior: "ignoreErrors" });

  await seedLookup(page, "dropping.test", lookupFixture("dropping.test", { statuses: [{ code: "pending delete" }] }));
  await expect(hero).toContainText("Pending delete");
});

test("a resolver tooltip stays on screen and never widens the DNS card", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === "mobile-chrome", "hover tooltips are a pointer feature");
  const resolvers = ["Cloudflare", "Google", "Tencent", "Ali"].map((resolver) => ({
    source: "doh",
    resolver,
    status: "error",
    error: "A: SERVFAIL; AAAA: SERVFAIL",
  }));
  await seedLookup(page, "tooltip.test", lookupFixture("tooltip.test", { enrichment: { dns: { a: [], aaaa: [], mx: [], resolvers, elapsedMs: 12 } } }));
  await showSection(page, /^DNS/);
  const dots = page.locator(".dns-panel .resolver-dot").filter({ visible: true });
  await dots.last().hover();
  const tip = page.locator(".resolver-tooltip");
  await expect(tip).toContainText("SERVFAIL");
  const box = await tip.boundingBox();
  const viewport = page.viewportSize();
  expect(box && viewport && box.x >= 0 && box.x + box.width <= viewport.width).toBeTruthy();
  const overflowing = await page.evaluate(() =>
    [...document.querySelectorAll(".dns-panel, .dns-panel *")].filter((el) => el.scrollWidth > el.clientWidth + 1 && /(auto|scroll)/.test(getComputedStyle(el).overflowX)).length,
  );
  expect(overflowing).toBe(0);
});

test("an API restart does not re-run the open lookup; a settings change does", async ({ page }) => {
  let config = { status: "ok", fingerprint: "settings-a", loadedAt: "2026-01-01T00:00:00Z" };
  await page.route("**/api/capabilities", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ ok: true, version: `v${process.env.npm_package_version || ""}`, config }) }),
  );
  let lookups = 0;
  await page.route("**/api/lookup?**", async (route) => {
    lookups += 1;
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ ok: true, result: lookupFixture("restart.test") }) });
  });
  await page.goto("/lookup?query=restart.test");
  await expect(page.locator(".lookup-pending")).toHaveCount(0);
  await page.waitForTimeout(3000);
  const afterLoad = lookups;

  // Redeploy: new load time, same settings.
  config = { ...config, loadedAt: "2026-01-02T00:00:00Z" };
  await page.waitForTimeout(3500);
  expect(lookups).toBe(afterLoad);

  // Admin edit: the settings fingerprint changes.
  config = { ...config, fingerprint: "settings-b", loadedAt: "2026-01-02T00:05:00Z" };
  await expect.poll(() => lookups, { timeout: 10_000 }).toBeGreaterThan(afterLoad);
});

test("after a newer release is deployed, the next search loads the page afresh", async ({ page }) => {
  await page.route("**/api/capabilities", (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ ok: true, version: "v99.0.0", config: { status: "ok", fingerprint: "same" } }) }),
  );
  await routeLookupFixtures(page, { "first.test": lookupFixture("first.test"), "second.test": lookupFixture("second.test") });
  await page.goto("/lookup?query=first.test");
  await expect(page.locator(".lookup-pending")).toHaveCount(0);
  await page.waitForTimeout(3000);

  const documentLoad = page.waitForRequest((request) => request.resourceType() === "document" && request.url().includes("query=second.test"));
  await page.getByLabel("Search query").fill("second.test");
  await page.getByLabel("Search query").press("Enter");
  await documentLoad;
  await expect(page.getByRole("heading", { name: "second.test" })).toBeVisible();
});

test("an internationalized name is titled in Unicode with its punycode beside it", async ({ page }) => {
  const ascii = "xn--fiqs8s.xn--6qq986b3xl";
  await routeLookupFixtures(page, {
    "中国.我爱你": lookupFixture(ascii, { domain: { name: ascii, unicodeName: "中国.我爱你", suffix: "xn--6qq986b3xl", registeredDomain: ascii } }),
  });
  await page.goto(`/lookup?query=${encodeURIComponent("中国.我爱你")}`);
  await expect(page.getByRole("heading", { name: "中国.我爱你" })).toBeVisible();
  await expect(page.locator(".lookup-pending")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "中国.我爱你" })).toBeVisible();
  await expect(page.locator(".hero-ascii")).toHaveText(ascii);
  await expect(page).toHaveTitle(/中国\.我爱你/);
});

test("expiry badges and the calendar reminder", async ({ page }, testInfo) => {
  // The badge row only: the time-remaining card says "Expired ... ago" on its own.
  const hero = page.locator(".hero-badges");
  await seedLookup(page, "soon.test", lookupFixture("soon.test", { dates: { expiresAt: "2026-11-01T08:05:19Z", remainingDays: 10 }, registrar: { name: "Fixture Registrar" } }));
  await expect(hero).toContainText("Expiring soon");
  await expect(hero).not.toContainText("Expired");

  if (testInfo.project.name !== "mobile-chrome") {
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Expiry reminder" }).click();
    const file = await download;
    expect(file.suggestedFilename()).toBe("soon.test-expiry.ics");
    const body = (await import("node:fs")).readFileSync(await file.path(), "utf8");
    expect(body).toContain("BEGIN:VCALENDAR");
    expect(body).toContain("DTSTART;VALUE=DATE:20261101");
    expect(body).toContain("DTEND;VALUE=DATE:20261102");
    expect(body).toContain("TRIGGER:-P30D");
    expect(body).toContain("SUMMARY:soon.test expires");
    for (const line of body.split("\r\n")) expect(Buffer.byteLength(line, "utf8")).toBeLessThanOrEqual(75);
  }
  await page.unrouteAll({ behavior: "ignoreErrors" });

  await seedLookup(page, "lapsed.test", lookupFixture("lapsed.test", { dates: { expiresAt: "2026-10-01", remainingDays: -3 } }));
  await expect(hero).toContainText("Expired");
  await page.unrouteAll({ behavior: "ignoreErrors" });

  // The registry's deletion stage takes precedence over the date.
  await seedLookup(page, "redeem2.test", lookupFixture("redeem2.test", { dates: { expiresAt: "2026-09-01", remainingDays: -40 }, statuses: [{ code: "redemptionPeriod" }] }));
  await expect(hero).toContainText("Redemption period");
  await expect(hero).not.toContainText("Expired");
  await page.unrouteAll({ behavior: "ignoreErrors" });

  await seedLookup(page, "free.test", lookupFixture("free.test", { status: "unregistered" }));
  await expect(page.getByRole("button", { name: "Expiry reminder" })).toBeDisabled();
});

test("transfer and renewal badges come from registry dates and grace-period statuses", async ({ page }) => {
  const badges = page.locator(".hero-badges");
  const daysAgo = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
  const cases: { name: string; overrides: Record<string, any>; has: string[]; not: string[] }[] = [
    { name: "moved.test", overrides: { dates: { transferredAt: daysAgo(10) } }, has: ["Recently transferred"], not: ["Transfer pending"] },
    { name: "settled.test", overrides: { dates: { transferredAt: daysAgo(100) } }, has: [], not: ["Recently transferred"] },
    { name: "moving.test", overrides: { statuses: [{ code: "pendingTransfer" }, { code: "transferPeriod" }] }, has: ["Transfer pending"], not: ["Recently transferred"] },
    { name: "renewed.test", overrides: { statuses: [{ code: "renewPeriod" }] }, has: ["Recently renewed"], not: [] },
    { name: "lapsing.test", overrides: { statuses: [{ code: "autoRenewPeriod" }] }, has: ["Auto-renew grace"], not: ["Recently renewed"] },
    { name: "free2.test", overrides: { status: "unregistered", statuses: [{ code: "renewPeriod" }], dates: { transferredAt: daysAgo(3) } }, has: [], not: ["Recently renewed", "Recently transferred"] },
  ];
  for (const item of cases) {
    await seedLookup(page, item.name, lookupFixture(item.name, item.overrides));
    for (const text of item.has) await expect(badges).toContainText(text);
    for (const text of item.not) await expect(badges).not.toContainText(text);
    await page.unrouteAll({ behavior: "ignoreErrors" });
  }
});

test("a search typed while the page is still loading is not lost", async ({ page }) => {
  await routeLookupFixtures(page, { "early.test": lookupFixture("early.test") });
  await page.goto("/lookup", { waitUntil: "commit" });
  await page.getByLabel("Search query").fill("early.test");
  await page.getByLabel("Search query").press("Enter");
  await expect(page.getByRole("heading", { name: "early.test" })).toBeVisible();
});

test("a domain paid years ahead is badged with the year it runs to", async ({ page }) => {
  const badges = page.locator(".hero-badges");
  await seedLookup(page, "decade.test", lookupFixture("decade.test", { dates: { expiresAt: "2035-12-12T23:59:59Z", remainingDays: 3338 } }));
  await expect(badges).toContainText("Paid through 2035");
  await page.unrouteAll({ behavior: "ignoreErrors" });

  await seedLookup(page, "short.test", lookupFixture("short.test", { dates: { expiresAt: "2029-12-12T23:59:59Z", remainingDays: 1100 } }));
  await expect(badges).not.toContainText("Paid through");
});

test("overview cards show full timestamps and long registrar names", async ({ page }) => {
  await seedLookup(
    page,
    "longname.test",
    lookupFixture("longname.test", {
      registrar: { name: "Alibaba Cloud Computing (Beijing) Co., Ltd.", ianaId: "420", country: "CN" },
      dates: { createdAt: "2007-09-28T11:09:56Z", expiresAt: "2029-09-28T11:09:56Z", updatedAt: "2026-08-19T15:35:44Z", ageDays: 6965, remainingDays: 1072 },
    }),
  );
  await expect(page.locator(".metric-grid")).toContainText("2007-09-28 11:09:56Z");
  const clipped = await page.evaluate(() =>
    [...document.querySelectorAll(".metric-value, .metric-sub")]
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 2)
      .map((el) => el.textContent?.trim()),
  );
  expect(clipped).toEqual([]);
});
