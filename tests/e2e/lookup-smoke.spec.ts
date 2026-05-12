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
