import { access, readdir, readFile } from "node:fs/promises";
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

async function requireFile(phase, file) {
  if (!(await exists(file))) failures.push(`${phase}: missing ${file}`);
}

async function requireDir(phase, dir) {
  if (!(await exists(dir))) failures.push(`${phase}: missing ${dir}`);
}

async function requireText(phase, file, needles) {
  const body = await text(file).catch((error) => {
    failures.push(`${phase}: cannot read ${file}: ${error.message}`);
    return "";
  });
  for (const needle of needles) {
    if (!body.includes(needle)) failures.push(`${phase}: ${file} is missing ${JSON.stringify(needle)}`);
  }
}

async function requireJSONPathValue(phase, file, pathParts, expected) {
  const body = await text(file).catch((error) => {
    failures.push(`${phase}: cannot read ${file}: ${error.message}`);
    return "";
  });
  if (!body) return;
  let data;
  try {
    data = JSON.parse(body);
  } catch (error) {
    failures.push(`${phase}: cannot parse ${file}: ${error.message}`);
    return;
  }
  let value = data;
  for (const part of pathParts) value = value?.[part];
  if (value !== expected) {
    failures.push(`${phase}: ${file} ${pathParts.join(".")} is ${JSON.stringify(value)}, want ${JSON.stringify(expected)}`);
  }
}

async function listFixtureTLDs() {
  const base = path.join(root, "packages/fixtures/whois");
  const entries = await readdir(base, { withFileTypes: true }).catch(() => []);
  return entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
}

async function checkPhase0() {
  const phase = "Phase 0";
  for (const file of [
    "package.json",
    "pnpm-workspace.yaml",
    "apps/web/package.json",
    "services/lookup-api/go.mod",
    "services/lookup-api/cmd/whoice-api/main.go",
    "services/lookup-api/internal/model/types.go",
    "services/lookup-api/internal/plugin/registry.go",
    "packages/schema/openapi.yaml",
    "packages/schema/json/api-response.schema.json",
    "deploy/compose/docker-compose.yml",
  ]) {
    await requireFile(phase, file);
  }
  await requireText(phase, "services/lookup-api/internal/plugin/registry.go", ["RegisterProvider", "RegisterParser", "Plugins()"]);
  await requireText(phase, "services/lookup-api/internal/model/types.go", ["type LookupResult struct", "type APIResponse struct"]);
}

async function checkPhase1() {
  const phase = "Phase 1";
  for (const file of [
    "services/lookup-api/internal/normalize/normalize.go",
    "services/lookup-api/internal/providers/rdap/rdap.go",
    "services/lookup-api/internal/providers/whois/whois.go",
    "services/lookup-api/internal/parsers/rdap.go",
    "services/lookup-api/internal/parsers/whois.go",
    "services/lookup-api/internal/merger/merger.go",
    "services/lookup-api/internal/httpapi/server.go",
    "apps/web/src/pages/index.tsx",
    "apps/web/src/pages/lookup.tsx",
  ]) {
    await requireFile(phase, file);
  }
  for (const fixture of [
    "lookup-rdap-domain.response.json",
    "lookup-whois-domain.response.json",
    "lookup-rdap-ipv4.response.json",
    "lookup-rdap-ipv6.response.json",
    "lookup-rdap-asn.response.json",
    "lookup-rdap-cidr.response.json",
    "lookup-invalid-query.response.json",
  ]) {
    await requireFile(phase, `packages/fixtures/api-runtime/${fixture}`);
  }
  await requireText(phase, "services/lookup-api/internal/httpapi/server.go", ["GET /api/lookup"]);
  await requireText(phase, "apps/web/src/lib/types.ts", ["providers?:"]);
  await requireText(phase, "apps/web/src/pages/lookup.tsx", ["rawWhois", "rawRdap", "request diagnostics"]);
}

async function checkPhase2() {
  const phase = "Phase 2";
  for (const file of [
    "apps/web/src/lib/history.ts",
    "apps/web/src/lib/i18n.tsx",
    "apps/web/src/components/AppControls.tsx",
    "apps/web/src/pages/docs.tsx",
    "apps/web/src/pages/api/og.tsx",
    "apps/web/public/manifest.webmanifest",
    "apps/web/public/sw.js",
    "apps/web/src/styles/theme.css",
  ]) {
    await requireFile(phase, file);
  }
  await requireText(phase, "apps/web/src/lib/i18n.tsx", ["zh-CN", "zh-TW", "themeLight", "themeDark"]);
  await requireText(phase, "apps/web/src/pages/lookup.tsx", ["downloadResult", "downloadOGImage", "copyRaw", "shareMenuOpen"]);
  await requireText(phase, "apps/web/src/pages/docs.tsx", ["/api/lookup", "Response envelope", "Runtime configuration"]);
}

async function checkPhase3() {
  const phase = "Phase 3";
  for (const file of [
    "services/lookup-api/internal/providers/whoisweb/whoisweb.go",
    "services/lookup-api/internal/providers/whoisweb/whoisweb_test.go",
    "services/lookup-api/internal/data/registrars/registry.go",
    "services/lookup-api/internal/data/whoisservers/resolver.go",
    "services/lookup-api/internal/data/rdapbootstrap/resolver.go",
    "services/lookup-api/internal/security/serverpolicy.go",
  ]) {
    await requireFile(phase, file);
  }
  const tlds = await listFixtureTLDs();
  if (tlds.length < 30) failures.push(`${phase}: expected at least 30 WHOIS fixture TLD directories, found ${tlds.length}`);
  for (const tld of ["cn", "de", "jp", "kz", "uk"]) {
    if (!tlds.includes(tld)) failures.push(`${phase}: missing fixture coverage for .${tld}`);
  }
  await requireJSONPathValue(phase, "packages/data/rdap-bootstrap/extra.json", ["li"], "https://rdap.nic.li/");
  await requireJSONPathValue(phase, "services/lookup-api/internal/data/rdapbootstrap/snapshots/extra.json", ["li"], "https://rdap.nic.li/");
  await requireText(phase, "services/lookup-api/internal/data/rdapbootstrap/resolver_test.go", ["example.li", "https://rdap.nic.li/"]);
  await requireText(phase, "services/lookup-api/internal/providers/whoisweb/whoisweb_test.go", [".dz", ".ni", ".vn"]);
  await requireText(phase, "services/lookup-api/internal/parsers/whois.go", ["reservedPatterns", "unregisteredPatterns"]);
  await requireText(phase, "apps/web/src/pages/lookup.tsx", ["rdapServer", "whoisServer", "whoisFollow"]);
}

async function checkPhase4() {
  const phase = "Phase 4";
  for (const file of [
    "services/lookup-api/internal/lookup/singleflight.go",
    "services/lookup-api/internal/auth/auth.go",
    "services/lookup-api/internal/ratelimit/limiter.go",
    "services/lookup-api/internal/enrich/epp/epp.go",
    "services/lookup-api/internal/enrich/brand/brand.go",
    "services/lookup-api/internal/enrich/pricing/pricing.go",
    "services/lookup-api/internal/enrich/moz/moz.go",
    "services/lookup-api/internal/enrich/dns/dns.go",
    "services/lookup-api/internal/enrich/dnsviz/dnsviz.go",
    "services/lookup-api/internal/enrich/pipeline/pipeline.go",
  ]) {
    await requireFile(phase, file);
  }
  await requireText(phase, "services/lookup-api/internal/config/config.go", [
    "RateLimitEnabled",
    "EnrichEPP",
    "EnrichBrands",
    "EnrichPricing",
    "EnrichMoz",
    "EnrichDNSViz",
  ]);
  await requireText(phase, "services/lookup-api/internal/plugin/defaults.go", [
    "epp",
    "brand-map",
    "pricing",
    "moz",
    "dns",
    "dnsviz",
  ]);
}

await checkPhase0();
await checkPhase1();
await checkPhase2();
await checkPhase3();
await checkPhase4();

if (failures.length > 0) {
  console.error("Plan pre-Phase-5 audit failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Validated Phase 0-4 implementation guardrails.");
