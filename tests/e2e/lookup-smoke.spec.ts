import { expect, test } from "@playwright/test";

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
  await page.goto("/lookup?query=example.com&rdap=1&whois_follow=0");

  await page.getByRole("radio", { name: "WHOIS" }).click();
  await expect(page).toHaveURL(/whois=1/);
  await expect(page.getByRole("radio", { name: "WHOIS" })).toHaveAttribute("aria-checked", "true");

  await page.getByLabel("Theme").selectOption("dark");
  await page.getByLabel("Language").selectOption("zh-CN");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");

  await expect(page.getByRole("heading", { name: "DNSViz" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open DNSViz" })).toHaveAttribute("href", /dnsviz\.net\/d\/example\.com\/dnssec\//);

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

  await page.goto("/lookup?query=example.com&rdap=1&whois_follow=0");
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();

  await page.getByLabel("Search query").fill("broken.test");
  await page.getByRole("button", { name: "Search" }).click();

  await expect(page).toHaveURL(/\/lookup\?query=broken\.test/);
  await expect(page.getByRole("heading", { name: "Lookup failed" })).toBeVisible();
  await expect(page.getByText("Switch source mode or check whether the lookup API is running.")).toBeVisible();
  await expect(page.locator(".tool-sidebar")).toBeVisible();
  await expect(page.locator(".error-panel")).toBeVisible();
  expect(pageErrors).toEqual([]);
});

test("mobile-chrome touch-friendly layout has no horizontal overflow", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-chrome", "mobile layout is covered by the mobile-chrome project");

  await page.goto("/lookup?query=example.com&rdap=1&whois_follow=0");
  await expect(page.getByRole("heading", { name: "example.com" })).toBeVisible();
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

  await page.getByRole("radio", { name: "WHOIS" }).tap();
  await expect(page.getByRole("radio", { name: "WHOIS" })).toHaveAttribute("aria-checked", "true");
  await page.getByRole("button", { name: "Copy raw" }).tap();
});
