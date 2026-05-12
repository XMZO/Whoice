import { defineConfig, devices } from "@playwright/test";

const webPort = Number(process.env.WHOICE_E2E_WEB_PORT || 13100);
const apiPort = Number(process.env.WHOICE_E2E_API_PORT || 18080);
const baseURL = process.env.WHOICE_E2E_BASE_URL || `http://127.0.0.1:${webPort}`;

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 60_000,
  expect: {
    timeout: 15_000,
  },
  fullyParallel: true,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
  webServer: [
    {
      command: `go run ./services/lookup-api/cmd/whoice-api`,
      env: {
        WHOICE_API_ADDR: `:${apiPort}`,
        WHOICE_LOOKUP_TIMEOUT: "12s",
        WHOICE_PROVIDER_TIMEOUT: "8s",
        WHOICE_WHOIS_FOLLOW_LIMIT: "0",
        WHOICE_METRICS_ENABLED: "true",
      },
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      url: `http://127.0.0.1:${apiPort}/api/health`,
    },
    {
      command: `pnpm --dir apps/web dev -p ${webPort}`,
      env: {
        WHOICE_WEB_API_BASE: `http://127.0.0.1:${apiPort}`,
      },
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      url: baseURL,
    },
  ],
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "mobile-chrome",
      use: { ...devices["Pixel 5"] },
    },
  ],
});

