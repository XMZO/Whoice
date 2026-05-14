import { access, readFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const failures = [];

async function exists(file) {
  try {
    await access(path.join(root, file));
    return true;
  } catch {
    return false;
  }
}

async function text(file) {
  return readFile(path.join(root, file), "utf8");
}

async function requireFile(section, file) {
  if (!(await exists(file))) failures.push(`${section}: missing ${file}`);
}

async function requireText(section, file, needles) {
  const body = await text(file).catch((error) => {
    failures.push(`${section}: cannot read ${file}: ${error.message}`);
    return "";
  });
  for (const needle of needles) {
    if (!body.includes(needle)) {
      failures.push(`${section}: ${file} is missing ${JSON.stringify(needle)}`);
    }
  }
  return body;
}

async function requireNoText(section, file, needles) {
  const body = await text(file).catch((error) => {
    failures.push(`${section}: cannot read ${file}: ${error.message}`);
    return "";
  });
  for (const needle of needles) {
    if (body.includes(needle)) {
      failures.push(`${section}: ${file} must not contain ${JSON.stringify(needle)}`);
    }
  }
}

async function checkObservability() {
  const section = "Phase 5 observability";
  for (const file of [
    "services/lookup-api/internal/observability/stats.go",
    "services/lookup-api/internal/observability/reporter.go",
    "services/lookup-api/internal/httpapi/server.go",
    "apps/web/src/pages/status.tsx",
  ]) {
    await requireFile(section, file);
  }
  await requireText(section, "services/lookup-api/internal/httpapi/server.go", [
    "GET /api/health",
    "GET /api/version",
    "GET /api/capabilities",
    "GET /api/metrics",
    "GET /api/admin/status",
    "X-Trace-ID",
    "handleAdminStatus",
    "ConfigStatus",
    "go snap.reporter.ReportLookup",
  ]);
  await requireText(section, "services/lookup-api/internal/observability/stats.go", [
    "whoice_lookup_requests_total",
    "whoice_provider_requests_total",
    "whoice_lookup_latency_milliseconds",
    "whoice_provider_latency_milliseconds",
  ]);
  await requireText(section, "services/lookup-api/internal/observability/reporter.go", [
    "LogReporter",
    "WebhookReporter",
    "MultiReporter",
    "ReportLookup",
  ]);
  await requireText(section, "apps/web/src/pages/status.tsx", [
    "/api/health",
    "/api/version",
    "/api/capabilities",
    "/api/metrics",
    "rolled back",
  ]);
}

async function checkDataAndContracts() {
  const section = "Phase 5 data and contracts";
  for (const file of [
    ".github/workflows/data-update.yml",
    "scripts/validate-data.mjs",
    "scripts/validate-schema.mjs",
    "packages/fixtures/api-runtime/lookup-rdap-domain.response.json",
    "packages/fixtures/api-runtime/lookup-whois-domain.response.json",
    "packages/fixtures/api-runtime/lookup-whoisweb-domain.response.json",
    "packages/fixtures/api-runtime/lookup-rdap-ipv4.response.json",
    "packages/fixtures/api-runtime/lookup-rdap-ipv6.response.json",
    "packages/fixtures/api-runtime/lookup-rdap-asn.response.json",
    "packages/fixtures/api-runtime/lookup-rdap-cidr.response.json",
    "packages/fixtures/api-runtime/lookup-invalid-query.response.json",
  ]) {
    await requireFile(section, file);
  }
  await requireText(section, ".github/workflows/data-update.yml", [
    "Update RDAP bootstrap snapshots",
    "Update ICANN registrar snapshot",
    "Update Public Suffix List snapshot",
    "Validate data snapshots",
    "git commit -m \"chore(data): update data snapshots\"",
  ]);
  await requireText(section, "services/lookup-api/internal/httpapi/server_test.go", [
    "TestRuntimeLookupResponsesMatchSchemaFixtures",
    "WHOICE_UPDATE_RUNTIME_FIXTURES",
    "lookup-rdap-cidr.response.json",
    "lookup-whoisweb-domain.response.json",
  ]);
  await requireText(section, "scripts/validate-schema.mjs", [
    "packages/fixtures/api-runtime",
    "api-response.schema.json",
    "openapi.yaml",
  ]);
}

async function checkCIAndRelease() {
  const section = "Phase 5 CI and release";
  await requireFile(section, ".github/workflows/ci.yml");
  await requireFile(section, ".github/workflows/container-images.yml");
  await requireText(section, ".github/workflows/ci.yml", [
    "pnpm test:web",
    "pnpm test:schema",
    "pnpm test:data",
    "pnpm test:pre5",
    "pnpm test:phase5",
    "--project=chromium",
    "--project=mobile-chrome",
  ]);
  await requireText(section, ".github/workflows/container-images.yml", [
    "ubuntu-latest",
    "ubuntu-24.04-arm",
    "linux/amd64",
    "linux/arm64",
    "Create and push multi-arch manifest",
    "sbom: true",
    "provenance: true",
  ]);
  await requireNoText(section, ".github/workflows/container-images.yml", [
    "docker/setup-qemu-action",
    "setup-qemu",
  ]);
  await requireText(section, "deploy/compose/docker-compose.yml", [
    "ghcr.io/xmzo/whoice-lookup-api:latest",
    "ghcr.io/xmzo/whoice-web:latest",
    "0.0.0.0:18080:8080",
    "0.0.0.0:18081:8081",
    "condition: service_healthy",
    "healthcheck:",
    "restart: unless-stopped",
  ]);
}

async function checkPlaywrightAndUX() {
  const section = "Phase 5 browser coverage";
  await requireFile(section, "playwright.config.ts");
  await requireFile(section, "tests/e2e/lookup-smoke.spec.ts");
  await requireText(section, "playwright.config.ts", [
    "Desktop Chrome",
    "Pixel 5",
    "mobile-chrome",
  ]);
  await requireText(section, "tests/e2e/lookup-smoke.spec.ts", [
    "Lookup failed",
    "broken.test",
    "scrollWidth",
    "touch-friendly",
    "mobile-chrome",
  ]);
  await requireText(section, "apps/web/src/styles/globals.css", [
    "@media (max-width: 760px)",
    "@media (hover: none) and (pointer: coarse)",
    "env(safe-area-inset-bottom)",
    "min-height: 40px",
  ]);
}

async function checkSecurityAndDocs() {
  const section = "Phase 5 docs and security";
  for (const file of [
    "README.md",
    "docs/SECURITY.md",
    "docs/OPERATIONS.md",
    "docs/IMPLEMENTATION_STATUS.md",
  ]) {
    await requireFile(section, file);
  }
  await requireText(section, "README.md", [
    "pnpm test:phase5",
    "native GitHub-hosted runners",
    "does not use QEMU",
    "/api/metrics",
    "/status",
  ]);
  await requireText(section, "docs/SECURITY.md", [
    "Custom Servers",
    "Authentication",
    "Rate Limit",
    "Webhook",
    "Admin Config",
  ]);
  await requireText(section, "docs/OPERATIONS.md", [
    "Health",
    "Metrics",
    "Release",
    "Rollback",
    "Data Updates",
    "Native Multi-Arch",
  ]);
  await requireText(section, "docs/IMPLEMENTATION_STATUS.md", [
    "Phase 5: productionization | Done for planned stage",
    "pnpm test:phase5",
  ]);
}

await checkObservability();
await checkDataAndContracts();
await checkCIAndRelease();
await checkPlaywrightAndUX();
await checkSecurityAndDocs();

if (failures.length > 0) {
  console.error("Plan Phase 5 audit failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Validated Phase 5 productionization guardrails.");
