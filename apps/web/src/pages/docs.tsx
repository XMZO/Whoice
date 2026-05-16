import Head from "next/head";
import Link from "next/link";
import { AppControls } from "@/components/AppControls";
import { useI18n } from "@/lib/i18n";

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="detail-row">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function CodeBlock({ children }: { children: string }) {
  return <pre>{children}</pre>;
}

export default function DocsPage() {
  const { t } = useI18n();

  return (
    <>
      <Head>
        <title>API Docs | Whoice</title>
      </Head>
      <main className="shell docs-shell">
        <nav className="top-nav">
          <Link href="/" className="brand">Whoice</Link>
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <AppControls />
          </div>
        </nav>
        <section className="panel">
          <p className="eyebrow">Overview</p>
          <h1>Whoice API and runtime guide</h1>
          <p>
            Whoice exposes one stable lookup envelope for RDAP, WHOIS, WHOIS Web fallback,
            IP, ASN, DNS enrichment, optional AI parsing, and optional ICP lookup. The Web
            app talks to the same API through same-origin proxy routes, so self-hosted
            deployments can keep the lookup API private behind the Web container.
          </p>
          <div className="docs-grid">
            <dl className="detail-list">
              <Row label="Base API" value="Local dev: http://localhost:8080; Docker host port: http://localhost:18080" />
              <Row label="Web UI" value="Local dev and Docker default: http://localhost:18081" />
              <Row label="Config" value="data/whoice.toml hot-reloads; invalid runtime edits roll back in memory" />
              <Row label="Schema" value="OpenAPI plus JSON Schema under packages/schema" />
            </dl>
            <dl className="detail-list">
              <Row label="Freshness" value="WHOIS/RDAP results are fresh-first and not cached" />
              <Row label="Concurrency" value="Identical live lookups are coalesced with singleflight" />
              <Row label="Plugins" value="/api/version returns provider, parser, enricher, auth, and reporter descriptors" />
              <Row label="Trace" value="Every lookup response includes X-Trace-ID and result.meta.traceId" />
            </dl>
          </div>
        </section>
        <section className="panel">
          <p className="eyebrow">GET</p>
          <h1>/api/lookup</h1>
          <p>Query domains, IPv4, IPv6, ASN, and CIDR values through the Go lookup API.</p>
          <CodeBlock>{`curl "http://localhost:8080/api/lookup?query=example.com"`}</CodeBlock>
          <div className="docs-grid">
            <div>
              <h2>Query params</h2>
              <dl className="detail-list">
                <Row label="query" value="Domain, IP, ASN, CIDR, or URL" />
                <Row label="rdap" value="1 to force RDAP only" />
                <Row label="whois" value="1 to force WHOIS only" />
                <Row label="rdap_server" value="Optional custom RDAP base URL" />
                <Row label="whois_server" value="Optional custom WHOIS host[:port]" />
                <Row label="whois_follow" value="0-5 referral follow depth" />
                <Row label="exact_domain" value="1 to query the full typed domain without PSL reduction" />
                <Row label="ai" value="1 to let the UI run background AI parsing after the main lookup returns" />
              </dl>
            </div>
            <div>
              <h2>Related endpoints</h2>
              <dl className="detail-list">
                <Row label="/api/health" value="Health check" />
                <Row label="/api/version" value="Version and plugin descriptors" />
                <Row label="/api/capabilities" value="Runtime feature flags" />
                <Row label="/api/lookup/ai" value="Optional background AI registration analysis" />
                <Row label="/api/icp" value="Optional async ICP filing lookup" />
                <Row label="/api/metrics" value="Prometheus-style metrics" />
                <Row label="/api/admin/status" value="Authenticated runtime stats and plugin status" />
                <Row label="/api/admin/config" value="Reserved Web config editor capability endpoint" />
                <Row label="/api/og" value="Dynamic result image" />
              </dl>
            </div>
          </div>
        </section>
        <section className="panel">
          <p className="eyebrow">Envelope</p>
          <h1>Response envelope</h1>
          <p>
            All JSON API responses use an `ok` envelope. Successful lookups return `result`
            plus `meta`; failures return `error`. Config reload errors appear in `config`
            and in result warnings while the previous valid runtime config is still active.
          </p>
          <CodeBlock>{`{
  "ok": true,
  "result": {
    "normalizedQuery": "example.com",
    "type": "domain",
    "status": "registered",
    "source": { "primary": "rdap", "used": ["rdap", "whois"] },
    "domain": { "registeredDomain": "example.com", "registered": true },
    "raw": { "rdap": "{ escaped RDAP payload }", "whois": "raw WHOIS payload" },
    "meta": {
      "elapsedMs": 123,
      "warnings": [],
      "traceId": "trace-id"
    }
  },
  "meta": { "traceId": "trace-id" }
}`}</CodeBlock>
          <dl className="detail-list">
            <Row label="result.source.errors" value="Per-provider errors; useful when RDAP succeeds but WHOIS fails, or the reverse" />
            <Row label="result.meta.providers" value="Provider trace with source, server, status, elapsed time, and errors" />
            <Row label="result.enrichment" value="Optional DNS, DNSViz, pricing, Moz, and other plugin output" />
            <Row label="result.raw" value="Escaped raw evidence for debugging and parser review" />
          </dl>
        </section>
        <section className="panel">
          <p className="eyebrow">Compatibility</p>
          <h1>Source and compatibility controls</h1>
          <p>
            Phase 3 compatibility features are exposed as explicit controls. Custom RDAP and
            WHOIS servers are disabled by default for SSRF safety; enable them only on trusted
            admin deployments.
          </p>
          <CodeBlock>{`[server]
allow_custom_servers = true
allow_private_servers = false

[lookup]
rdap_enabled = true
whois_enabled = true
whois_web_enabled = false
whois_follow_limit = 1`}</CodeBlock>
          <dl className="detail-list">
            <Row label="WHOIS Web" value="A separate provider for selected stable ccTLD fallbacks; disabled by default" />
            <Row label="Server data" value="Mounted data/whois-servers and data/rdap-bootstrap files override embedded snapshots" />
            <Row label="Exact domain" value="Useful for private or unofficial multi-level suffixes that are not in PSL" />
            <Row label="Fixture rule" value="New TLD parsers should include raw/expected fixtures and schema validation" />
          </dl>
        </section>
        <section className="panel">
          <p className="eyebrow">GET</p>
          <h1>/api/icp</h1>
          <p>Query ICP filing information for a domain. It is intentionally separate from the main lookup endpoint.</p>
          <CodeBlock>{`curl "http://localhost:8080/api/icp?domain=example.cn"`}</CodeBlock>
          <dl className="detail-list">
            <Row label="domain" value="Domain or URL; normalized to the registered domain" />
            <Row label="cache" value="Positive, empty, and error responses use separate TTLs" />
            <Row label="ui" value="Manual by default; [icp] auto_query can enable async auto lookup" />
          </dl>
        </section>
        <section className="panel">
          <p className="eyebrow">Optional</p>
          <h1>AI parser</h1>
          <p>AI-assisted parsing can fill missing registrar and public registrant fields from raw RDAP/WHOIS evidence. It runs through POST /api/lookup/ai so the main lookup result is not blocked by model latency.</p>
          <CodeBlock>{`[ai]
enabled = true
base_url = "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/v1"
api_key = "<token>"
model = "@cf/meta/llama-3.1-8b-instruct"
temperature = 0
max_output_tokens = 700
ignore_suffixes = ["com", "net", "org", "cn"]
ignore_regex = []`}</CodeBlock>
          <dl className="detail-list">
            <Row label="provider" value="OpenAI-compatible by default; set provider = ollama for local Ollama" />
            <Row label="cache" value="Caches AI analysis only, keyed by raw evidence, model, and prompt" />
            <Row label="ignore" value="Exact suffixes and regex rules can skip AI for predictable TLDs; ignored results show AI ignored" />
            <Row label="prompt" value="Built-in English strict JSON prompt; override with prompt" />
          </dl>
        </section>
        <section className="panel">
          <p className="eyebrow">Runtime configuration</p>
          <h1>Hot reload and optional plugins</h1>
          <p>
            Runtime settings live in `data/whoice.toml`. Most changes hot-reload within the
            API process. Invalid edits are reported in logs, `/status`, and lookup warnings
            while Whoice keeps using the last valid runtime snapshot.
          </p>
          <CodeBlock>{`[enrichment]
epp = true
registrar = true
brands = false
pricing = false
moz = false

[dns]
enabled = true
dnsviz_enabled = true

[rate_limit]
enabled = false
anon = "60/min"`}</CodeBlock>
          <dl className="detail-list">
            <Row label="Startup-only" value="server.addr requires a process/container restart" />
            <Row label="Base64" value="The config file may contain a base64-encoded TOML document" />
            <Row label="Pricing/Moz" value="Read local JSON snapshots only; no external API calls during lookup" />
            <Row label="Admin config" value="/api/admin/config is reserved for future Web editing and does not write files yet" />
          </dl>
        </section>
        <section className="panel">
          <p className="eyebrow">Workspace</p>
          <h2>Result shortcuts</h2>
          <div className="shortcut-grid">
            <span><kbd>/</kbd> Focus search</span>
            <span><kbd>S</kbd> Toggle share menu</span>
            <span><kbd>C</kbd> Copy result URL</span>
            <span><kbd>R</kbd> Copy raw evidence</span>
            <span><kbd>J</kbd> Download JSON</span>
            <span><kbd>O</kbd> Download OG image</span>
          </div>
        </section>
      </main>
    </>
  );
}
