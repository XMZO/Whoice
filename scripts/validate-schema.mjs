import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const files = [
  "packages/schema/openapi.yaml",
  "packages/schema/json/api-response.schema.json",
];

for (const file of files) {
  const body = await readFile(file, "utf8");
  if (file.endsWith(".json")) {
    JSON.parse(body);
  } else {
    parseYaml(body);
  }
}

const apiResponseSchema = JSON.parse(await readFile("packages/schema/json/api-response.schema.json", "utf8"));
const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);
const validateAPIResponse = ajv.compile(apiResponseSchema);

const samples = [
  {
    ok: false,
    error: {
      code: "query_required",
      message: "Query is required.",
    },
    meta: {
      elapsedMs: 0,
      traceId: "schema-smoke",
    },
  },
  {
    ok: true,
    result: {
      query: "example.com",
      normalizedQuery: "example.com",
      type: "domain",
      status: "registered",
      source: {
        primary: "rdap",
        used: ["rdap"],
      },
      domain: {
        name: "example.com",
        unicodeName: "example.com",
        punycodeName: "example.com",
        suffix: "com",
        registeredDomain: "example.com",
        reserved: false,
        registered: true,
      },
      registry: {
        rdapServer: "https://rdap.example/domain/example.com",
      },
      registrar: {
        name: "Example Registrar, Inc.",
        ianaId: "376",
        brand: {
          name: "Example Registrar",
          slug: "example-registrar",
          color: "#336699",
          logo: "https://example.com/favicon.ico",
          website: "https://example.com",
          aliases: ["Example"],
        },
      },
      dates: {
        createdAt: "1995-08-14T04:00:00Z",
      },
      statuses: [
        {
          code: "active",
          label: "Active",
        },
      ],
      nameservers: [
        {
          host: "a.iana-servers.net",
        },
      ],
      dnssec: {
        signed: true,
        text: "signed",
      },
      registrant: {
        country: "US",
      },
      network: {},
      enrichment: {
        dns: {
          a: [{ ip: "93.184.216.34", version: "ipv4" }],
          elapsedMs: 12,
        },
        dnsviz: {
          url: "https://dnsviz.net/d/example.com/dnssec/",
        },
      },
      raw: {
        rdap: "{}",
      },
      meta: {
        elapsedMs: 123,
        providers: [
          {
            source: "rdap",
            status: "ok",
            elapsedMs: 100,
          },
        ],
      },
    },
    meta: {
      elapsedMs: 123,
    },
  },
];

const fixtureSamples = await apiSamplesFromParserFixtures();
samples.push(...fixtureSamples);
const runtimeSamples = await apiSamplesFromRuntimeFixtures();
samples.push(...runtimeSamples);

for (const sample of samples) {
  if (!validateAPIResponse(sample)) {
    throw new Error(`API response schema sample failed for ${sample?.result?.normalizedQuery || sample?.error?.code || "unknown"}: ${ajv.errorsText(validateAPIResponse.errors)}`);
  }
}

console.log(`Validated ${files.length} schema files, ${fixtureSamples.length} parser fixture API samples, ${runtimeSamples.length} runtime API samples, and ${samples.length} total API response samples.`);

async function apiSamplesFromParserFixtures() {
  const fixturesRoot = "packages/fixtures";
  const files = await expectedFixtureFiles(fixturesRoot);
  const samples = [];
  for (const file of files) {
    const expected = JSON.parse(await readFile(file, "utf8"));
    const rawPath = file.replace(/\.expected\.json$/, ".raw");
    const raw = await readFile(rawPath, "utf8").catch(() => "");
    const source = file.includes(`${path.sep}rdap${path.sep}`) ? "rdap" : "whois";
    const queryType = file.includes(`${path.sep}rdap${path.sep}`) ? path.basename(path.dirname(file)) : "domain";
    const normalizedQuery = expected.domainName || domainFromFixturePath(file);
    samples.push(stripUndefined({
      ok: true,
      result: {
        query: normalizedQuery,
        normalizedQuery,
        type: queryType === "domain" ? "domain" : "domain",
        status: expected.status || "unknown",
        source: {
          primary: source,
          used: [source],
        },
        domain: {
          name: expected.domainName || normalizedQuery,
          unicodeName: expected.domainName || normalizedQuery,
          punycodeName: expected.domainName || normalizedQuery,
          suffix: suffixFromDomain(expected.domainName || normalizedQuery),
          registeredDomain: expected.domainName || normalizedQuery,
          reserved: expected.status === "reserved",
          registered: expected.status === "registered",
        },
        registry: {},
        registrar: {
          name: expected.registrarName || undefined,
          ianaId: expected.registrarIanaId || undefined,
        },
        dates: {
          createdAt: expected.createdAt || undefined,
          expiresAt: expected.expiresAt || undefined,
          updatedAt: expected.updatedAt || undefined,
        },
        statuses: (expected.statuses || []).map((code) => ({ code })),
        nameservers: (expected.nameservers || []).map((host) => ({ host })),
        dnssec: {
          text: expected.dnssec || undefined,
        },
        registrant: {
          country: expected.registrantCountry || undefined,
        },
        network: {},
        enrichment: {},
        raw: raw ? { [source]: raw } : {},
        meta: {
          elapsedMs: 1,
          providers: [
            {
              source,
              status: "ok",
              elapsedMs: 1,
              bytes: raw.length,
            },
          ],
        },
      },
      meta: {
        elapsedMs: 1,
      },
    }));
  }
  return samples;
}

async function apiSamplesFromRuntimeFixtures() {
  const fixturesRoot = "packages/fixtures/api-runtime";
  const files = await responseFixtureFiles(fixturesRoot);
  const samples = [];
  for (const file of files) {
    samples.push(JSON.parse(await readFile(file, "utf8")));
  }
  return samples;
}

async function expectedFixtureFiles(root) {
  const out = [];
  async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const item = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(item);
      } else if (entry.isFile() && entry.name.endsWith(".expected.json")) {
        out.push(item);
      }
    }
  }
  await walk(root);
  return out.sort();
}

async function responseFixtureFiles(root) {
  const out = [];
  async function walk(dir) {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const item = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(item);
      } else if (entry.isFile() && entry.name.endsWith(".response.json")) {
        out.push(item);
      }
    }
  }
  await walk(root);
  return out.sort();
}

function domainFromFixturePath(file) {
  const parts = file.split(path.sep);
  const tld = parts.at(-2) || "example";
  return tld === "generic" ? "example.com" : `example.${tld}`;
}

function suffixFromDomain(domain) {
  const parts = String(domain).toLowerCase().split(".");
  return parts.length > 1 ? parts.at(-1) : undefined;
}

function stripUndefined(value) {
  if (Array.isArray(value)) {
    return value.map(stripUndefined);
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .map(([key, item]) => [key, stripUndefined(item)]),
  );
}
