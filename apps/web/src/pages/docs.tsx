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
          <p className="eyebrow">GET</p>
          <h1>/api/lookup</h1>
          <p>Query domains, IPv4, IPv6, ASN, and CIDR values through the Go lookup API.</p>
          <pre>{`curl "http://localhost:8080/api/lookup?query=example.com"`}</pre>
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
                <Row label="/api/og" value="Dynamic result image" />
              </dl>
            </div>
          </div>
        </section>
        <section className="panel">
          <p className="eyebrow">GET</p>
          <h1>/api/icp</h1>
          <p>Query ICP filing information for a domain. It is intentionally separate from the main lookup endpoint.</p>
          <pre>{`curl "http://localhost:8080/api/icp?domain=example.cn"`}</pre>
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
          <pre>{`[ai]
enabled = true
base_url = "https://api.cloudflare.com/client/v4/accounts/<ACCOUNT_ID>/ai/v1"
api_key = "<token>"
model = "@cf/meta/llama-3.1-8b-instruct"
temperature = 0
max_output_tokens = 700`}</pre>
          <dl className="detail-list">
            <Row label="provider" value="OpenAI-compatible by default; set provider = ollama for local Ollama" />
            <Row label="cache" value="Caches AI analysis only, keyed by raw evidence, model, and prompt" />
            <Row label="prompt" value="Built-in English strict JSON prompt; override with prompt" />
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
