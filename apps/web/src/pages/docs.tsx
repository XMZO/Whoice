import Head from "next/head";
import Link from "next/link";
import { AppControls } from "@/components/AppControls";
import { BrandMark } from "@/components/BrandMark";
import { useI18n } from "@/lib/i18n";
import { t3, useT3, type T3 } from "@/lib/t3";

type Row = { name: string; text: T3 };
type DocSection = { eyebrow: T3 | string; title: T3 | string; intro?: T3; code?: string; columns?: { title?: T3; rows: Row[] }[]; rows?: Row[] };

const SECTIONS: DocSection[] = [
  {
    eyebrow: t3("Overview", "概述", "概述"),
    title: t3("Whoice API and runtime guide", "Whoice API 与运行说明", "Whoice API 與執行說明"),
    intro: t3(
      "Whoice returns one stable lookup envelope for RDAP, WHOIS, WHOIS Web fallback, IP, ASN, DNS enrichment, optional AI parsing, and optional ICP lookup. The web app reaches the same API through same-origin proxy routes, so the lookup API can stay private behind the web container.",
      "Whoice 为 RDAP、WHOIS、WHOIS Web 备用、IP、ASN、DNS 补充、可选的 AI 解析和 ICP 备案查询提供统一的响应结构。Web 界面通过同源代理访问同一套 API，因此查询 API 可以只对 Web 容器开放。",
      "Whoice 為 RDAP、WHOIS、WHOIS Web 備用、IP、ASN、DNS 補充、可選的 AI 解析和 ICP 備案查詢提供統一的回應結構。Web 介面透過同源代理存取同一套 API，因此查詢 API 可以只對 Web 容器開放。",
    ),
    columns: [
      {
        rows: [
          { name: "API", text: t3("Local development: http://localhost:8080; Docker: http://127.0.0.1:18080", "本地开发：http://localhost:8080；Docker：http://127.0.0.1:18080", "本機開發：http://localhost:8080；Docker：http://127.0.0.1:18080") },
          { name: "Web", text: t3("Local development and Docker: http://localhost:18081", "本地开发与 Docker：http://localhost:18081", "本機開發與 Docker：http://localhost:18081") },
          { name: "Config", text: t3("data/whoice.toml or the admin panel; changes apply without a restart", "data/whoice.toml 或管理面板；修改后无需重启", "data/whoice.toml 或管理面板；修改後無需重啟") },
          { name: "Schema", text: t3("OpenAPI and JSON Schema in packages/schema", "OpenAPI 与 JSON Schema 位于 packages/schema", "OpenAPI 與 JSON Schema 位於 packages/schema") },
        ],
      },
      {
        rows: [
          { name: "Freshness", text: t3("WHOIS and RDAP results are never cached", "WHOIS 与 RDAP 结果从不缓存", "WHOIS 與 RDAP 結果從不快取") },
          { name: "Concurrency", text: t3("Identical concurrent lookups share one upstream request", "相同的并发查询共用一次上游请求", "相同的並行查詢共用一次上游請求") },
          { name: "Plugins", text: t3("/api/version lists providers, parsers, enrichers, auth, and reporters", "/api/version 列出数据源、解析器、补充模块、鉴权与上报插件", "/api/version 列出資料來源、解析器、補充模組、驗證與回報外掛") },
          { name: "Trace", text: t3("Every response carries X-Trace-ID and result.meta.traceId", "每个响应都带有 X-Trace-ID 和 result.meta.traceId", "每個回應都帶有 X-Trace-ID 和 result.meta.traceId") },
        ],
      },
    ],
  },
  {
    eyebrow: "GET",
    title: "/api/lookup",
    intro: t3("Looks up domains, IPv4 and IPv6 addresses, CIDR ranges, and ASNs.", "查询域名、IPv4 与 IPv6 地址、CIDR 网段和 ASN。", "查詢網域、IPv4 與 IPv6 位址、CIDR 網段和 ASN。"),
    code: `curl "http://localhost:8080/api/lookup?query=example.com"`,
    columns: [
      {
        title: t3("Query parameters", "查询参数", "查詢參數"),
        rows: [
          { name: "query", text: t3("Domain, IP, CIDR, ASN, or URL", "域名、IP、CIDR、ASN 或 URL", "網域、IP、CIDR、ASN 或 URL") },
          { name: "rdap", text: t3("1 to use RDAP only", "设为 1 只用 RDAP", "設為 1 只用 RDAP") },
          { name: "whois", text: t3("1 to use WHOIS only", "设为 1 只用 WHOIS", "設為 1 只用 WHOIS") },
          { name: "rdap_server", text: t3("Custom RDAP base URL, if allowed", "自定义 RDAP 地址（需允许）", "自訂 RDAP 位址（需允許）") },
          { name: "whois_server", text: t3("Custom WHOIS host[:port], if allowed", "自定义 WHOIS 主机[:端口]（需允许）", "自訂 WHOIS 主機[:連接埠]（需允許）") },
          { name: "whois_follow", text: t3("Referral depth, 0 to 5", "referral 跟随层数，0 到 5", "referral 跟隨層數，0 到 5") },
          { name: "exact_domain", text: t3("1 to query the typed name without registrable-domain reduction", "设为 1 时按输入的完整域名查询，不缩到可注册域", "設為 1 時按輸入的完整網域查詢，不縮到可註冊網域") },
        ],
      },
      {
        title: t3("Related endpoints", "相关接口", "相關介面"),
        rows: [
          { name: "/api/lookup/enrich", text: t3("Deferred DNS and pricing for a result", "为结果补充 DNS 与价格", "為結果補充 DNS 與價格") },
          { name: "/api/lookup/ai", text: t3("Background AI registration analysis", "后台 AI 注册信息分析", "背景 AI 註冊資訊分析") },
          { name: "/api/icp", text: t3("ICP filing lookup", "ICP 备案查询", "ICP 備案查詢") },
          { name: "/api/health", text: t3("Health check", "健康检查", "健康檢查") },
          { name: "/api/version", text: t3("Version and plugins", "版本与插件", "版本與外掛") },
          { name: "/api/capabilities", text: t3("Feature flags", "功能开关", "功能開關") },
          { name: "/api/metrics", text: t3("Prometheus metrics", "Prometheus 指标", "Prometheus 指標") },
          { name: "/api/admin/*", text: t3("Admin panel API; requires the admin password", "管理面板接口，需要管理密码", "管理面板介面，需要管理密碼") },
          { name: "/api/og", text: t3("Link preview image (og:image)", "链接预览图片（og:image）", "連結預覽圖片（og:image）") },
        ],
      },
    ],
  },
  {
    eyebrow: t3("Envelope", "响应结构", "回應結構"),
    title: t3("Response envelope", "响应结构", "回應結構"),
    intro: t3(
      "Every JSON response has an ok flag. Successful lookups return result and meta; failures return error with a code and message. Configuration reload errors appear in config and in result warnings while the previous valid configuration stays active.",
      "所有 JSON 响应都带有 ok 字段。查询成功时返回 result 和 meta，失败时返回带 code 与 message 的 error。配置重新加载失败时，错误会出现在 config 和结果警告中，同时继续使用上一份有效配置。",
      "所有 JSON 回應都帶有 ok 欄位。查詢成功時回傳 result 和 meta，失敗時回傳帶 code 與 message 的 error。設定重新載入失敗時，錯誤會出現在 config 和結果警告中，同時繼續使用上一份有效設定。",
    ),
    code: `{
  "ok": true,
  "result": {
    "normalizedQuery": "example.com",
    "type": "domain",
    "status": "registered",
    "source": { "primary": "rdap", "used": ["rdap", "whois"] },
    "raw": { "rdap": "{ ... }", "whois": "..." },
    "meta": { "elapsedMs": 123, "warnings": [], "traceId": "..." }
  }
}`,
    rows: [
      { name: "result.source.errors", text: t3("Per-source errors, for example when RDAP succeeds and WHOIS fails", "各数据来源的错误，例如 RDAP 成功而 WHOIS 失败", "各資料來源的錯誤，例如 RDAP 成功而 WHOIS 失敗") },
      { name: "result.meta.providers", text: t3("Per-source server, status, size, and timing", "各数据来源的服务器、状态、大小与耗时", "各資料來源的伺服器、狀態、大小與耗時") },
      { name: "result.enrichment", text: t3("DNS, DNSViz, pricing, and Moz data", "DNS、DNSViz、价格与 Moz 数据", "DNS、DNSViz、價格與 Moz 資料") },
      { name: "result.raw", text: t3("Raw RDAP and WHOIS responses", "RDAP 与 WHOIS 原始响应", "RDAP 與 WHOIS 原始回應") },
    ],
  },
  {
    eyebrow: "GET",
    title: "/api/icp",
    intro: t3("Looks up the ICP filing of a domain. It is separate from the main lookup so WHOIS and RDAP results are never delayed.", "查询域名的 ICP 备案。它与主查询分开，不会拖慢 WHOIS 和 RDAP 结果。", "查詢網域的 ICP 備案。它與主查詢分開，不會拖慢 WHOIS 和 RDAP 結果。"),
    code: `curl "http://localhost:8080/api/icp?domain=example.cn"`,
    rows: [
      { name: "domain", text: t3("Domain or URL; reduced to the registered domain", "域名或 URL，会缩到可注册域", "網域或 URL，會縮到可註冊網域") },
      { name: "cache", text: t3("Found, empty, and failed results have separate cache durations", "有备案、无备案、出错三种结果分别缓存", "有備案、無備案、出錯三種結果分別快取") },
    ],
  },
  {
    eyebrow: t3("Runtime configuration", "运行配置", "執行設定"),
    title: t3("Hot reload and the admin panel", "热加载与管理面板", "熱載入與管理面板"),
    intro: t3(
      "Runtime configuration lives in data/whoice.toml and can be edited there or in the admin panel at /admin. Changes apply without a restart; an invalid edit is rejected and the previous configuration stays active.",
      "运行配置保存在 data/whoice.toml，可以直接编辑，也可以在 /admin 管理面板中修改。修改无需重启即可生效；无效的修改会被拒绝，并继续使用上一份配置。",
      "執行設定保存在 data/whoice.toml，可以直接編輯，也可以在 /admin 管理面板中修改。修改無需重啟即可生效；無效的修改會被拒絕，並繼續使用上一份設定。",
    ),
    code: `[enrichment]
pricing = true

[rate_limit]
enabled = true
anon = "60/min"`,
    rows: [
      { name: "server.addr", text: t3("Startup-only; requires a restart", "启动期配置，需要重启", "啟動期設定，需要重啟") },
      { name: "WHOICE_*", text: t3("Environment variables override the file and appear read-only in the panel", "环境变量优先于配置文件，在面板中显示为只读", "環境變數優先於設定檔，在面板中顯示為唯讀") },
      { name: "[ai]", text: t3("OpenAI-compatible or Ollama model; caches analysis only, never lookup results", "OpenAI 兼容接口或 Ollama 模型；只缓存分析结果，不缓存查询结果", "OpenAI 相容介面或 Ollama 模型；只快取分析結果，不快取查詢結果") },
    ],
  },
];

const SHORTCUTS: [string, T3][] = [
  ["/", t3("Focus search", "聚焦搜索框", "聚焦搜尋框")],
  ["C", t3("Copy result link", "复制结果链接", "複製結果連結")],
  ["R", t3("Copy raw data", "复制原文", "複製原文")],
  ["J", t3("Download JSON", "下载 JSON", "下載 JSON")],
];

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
  const pick = useT3();
  const text = (value: T3 | string) => (typeof value === "string" ? value : pick(value));

  return (
    <>
      <Head>
        <title>{`${pick(t3("API documentation", "API 文档", "API 文件"))} | Whoice`}</title>
      </Head>
      <main className="shell docs-shell">
        <nav className="top-nav">
          <BrandMark />
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <Link href="/admin">{t("adminPanel")}</Link>
            <AppControls />
          </div>
        </nav>
        {SECTIONS.map((section, index) => (
          <section className="panel" key={index}>
            <p className="eyebrow">{text(section.eyebrow)}</p>
            <h1>{text(section.title)}</h1>
            {section.intro && <p>{pick(section.intro)}</p>}
            {section.code && <CodeBlock>{section.code}</CodeBlock>}
            {section.columns && (
              <div className="docs-grid">
                {section.columns.map((column, columnIndex) => (
                  <div key={columnIndex}>
                    {column.title && <h2>{pick(column.title)}</h2>}
                    <dl className="detail-list">
                      {column.rows.map((row) => <Row key={row.name} label={row.name} value={pick(row.text)} />)}
                    </dl>
                  </div>
                ))}
              </div>
            )}
            {section.rows && (
              <dl className="detail-list">
                {section.rows.map((row) => <Row key={row.name} label={row.name} value={pick(row.text)} />)}
              </dl>
            )}
          </section>
        ))}
        <section className="panel">
          <p className="eyebrow">{pick(t3("Keyboard", "键盘", "鍵盤"))}</p>
          <h2>{pick(t3("Result page shortcuts", "结果页快捷键", "結果頁快捷鍵"))}</h2>
          <div className="shortcut-grid">
            {SHORTCUTS.map(([key, label]) => (
              <span key={key}>
                <kbd>{key}</kbd> {pick(label)}
              </span>
            ))}
          </div>
        </section>
      </main>
    </>
  );
}
