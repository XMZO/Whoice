import Head from "next/head";
import Link from "next/link";
import { useRouter } from "next/router";
import { FormEvent, useEffect, useState } from "react";
import { AppControls } from "@/components/AppControls";
import { appendLookupOptions, normalizeLookupInput, type LookupOptions } from "@/lib/api";
import { detectLookupType, readHistory, writeHistory, type HistoryItem } from "@/lib/history";
import { useI18n } from "@/lib/i18n";

type SourceMode = "all" | "rdap" | "whois";

type AdvancedState = {
  rdapServer: string;
  whoisServer: string;
  whoisFollow: string;
  exactDomain: boolean;
  forceAI: boolean;
};

function sourceParams(mode: SourceMode) {
  const params = new URLSearchParams();
  if (mode === "rdap") params.set("rdap", "1");
  if (mode === "whois") params.set("whois", "1");
  return params;
}

function advancedOptions(value: AdvancedState): LookupOptions {
  return {
    rdapServer: value.rdapServer.trim(),
    whoisServer: value.whoisServer.trim(),
    whoisFollow: value.whoisFollow,
    exactDomain: value.exactDomain ? "1" : undefined,
    ai: value.forceAI ? "1" : undefined,
  };
}

function SourceToggle({ value, onChange }: { value: SourceMode; onChange: (value: SourceMode) => void }) {
  const options: { value: SourceMode; label: string }[] = [
    { value: "all", label: "All" },
    { value: "rdap", label: "RDAP" },
    { value: "whois", label: "WHOIS" },
  ];

  return (
    <div className="source-toggle" role="radiogroup" aria-label="Lookup source">
      {options.map((option) => (
        <button
          key={option.value}
          aria-checked={value === option.value}
          className={value === option.value ? "source-option active" : "source-option"}
          onClick={() => onChange(option.value)}
          role="radio"
          type="button"
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export default function HomePage() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [sourceMode, setSourceMode] = useState<SourceMode>("all");
  const [advanced, setAdvanced] = useState<AdvancedState>({
    rdapServer: "",
    whoisServer: "",
    whoisFollow: "",
    exactDomain: false,
    forceAI: false,
  });
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const { t } = useI18n();

  useEffect(() => {
    setHistory(readHistory());
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      if (event.key === "/" && document.activeElement?.tagName !== "INPUT") {
        event.preventDefault();
        document.getElementById("whoice-search")?.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  function submit(event: FormEvent) {
    event.preventDefault();
    const value = normalizeLookupInput(query);
    if (!value) return;
    setQuery(value);
    writeHistory(value);
    const params = sourceParams(sourceMode);
    params.set("query", value);
    appendLookupOptions(params, advancedOptions(advanced));
    router.push(`/lookup?${params.toString()}`);
  }

  return (
    <>
      <Head>
        <title>Whoice</title>
        <meta name="description" content="Modular WHOIS and RDAP lookup." />
        <meta property="og:title" content="Whoice" />
        <meta property="og:image" content="/api/og" />
        <meta name="twitter:card" content="summary_large_image" />
      </Head>
      <main className="shell home-shell">
        <nav className="top-nav">
          <Link href="/" className="brand">Whoice</Link>
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <a href="https://github.com/XMZO/Whoice" target="_blank" rel="noreferrer">GitHub</a>
            <AppControls />
          </div>
        </nav>

        <section className="search-hero">
          <p className="eyebrow">{t("heroEyebrow")}</p>
          <h1>{t("heroTitle")}</h1>
          <form className="lookup-form" onSubmit={submit}>
            <div className="search-box">
              <input
                id="whoice-search"
                autoFocus
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={t("placeholder")}
                spellCheck={false}
              />
              <button type="submit">{t("search")}</button>
            </div>
          </form>
          <div className="lookup-options">
            <SourceToggle value={sourceMode} onChange={setSourceMode} />
            <div className="advanced-lookup">
              <button
                type="button"
                className="advanced-toggle"
                aria-expanded={advancedOpen}
                aria-controls="advanced-lookup-panel"
                onClick={() => setAdvancedOpen((open) => !open)}
              >
                {t("advanced")}
              </button>
              {advancedOpen && (
                <div id="advanced-lookup-panel" className="advanced-grid">
                <label>
                  <span>{t("rdapServer")}</span>
                  <input
                    value={advanced.rdapServer}
                    onChange={(event) => setAdvanced((current) => ({ ...current, rdapServer: event.target.value }))}
                    placeholder="https://rdap.example"
                    spellCheck={false}
                  />
                </label>
                <label>
                  <span>{t("whoisServer")}</span>
                  <input
                    value={advanced.whoisServer}
                    onChange={(event) => setAdvanced((current) => ({ ...current, whoisServer: event.target.value }))}
                    placeholder="whois.example:43"
                    spellCheck={false}
                  />
                </label>
                <label>
                  <span>{t("whoisFollow")}</span>
                  <input
                    min="0"
                    max="5"
                    type="number"
                    value={advanced.whoisFollow}
                    onChange={(event) => setAdvanced((current) => ({ ...current, whoisFollow: event.target.value }))}
                  />
                </label>
                <label className="check-row wide-check" title={t("exactDomainHint")}>
                  <input
                    type="checkbox"
                    checked={advanced.exactDomain}
                    onChange={(event) => setAdvanced((current) => ({ ...current, exactDomain: event.target.checked }))}
                  />
                  <span>{t("exactDomain")}</span>
                </label>
                <label className="check-row wide-check" title={t("forceAIHint")}>
                  <input
                    type="checkbox"
                    checked={advanced.forceAI}
                    onChange={(event) => setAdvanced((current) => ({ ...current, forceAI: event.target.checked }))}
                  />
                  <span>{t("forceAI")}</span>
                </label>
                </div>
              )}
            </div>
          </div>
          <div className="search-meta">
            {query && <span className="type-pill">{detectLookupType(query)}</span>}
            <span className="type-pill">{sourceMode}</span>
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>{t("recent")}</h2>
          </div>
          {history.length === 0 ? (
            <p className="muted">{t("emptyHistory")}</p>
          ) : (
            <div className="history-list">
              {history.map((item) => (
                <Link key={`${item.query}-${item.timestamp}`} href={`/lookup?query=${encodeURIComponent(item.query)}`} className="history-item">
                  <span>{item.query}</span>
                  <span>{item.type}</span>
                </Link>
              ))}
            </div>
          )}
        </section>
      </main>
    </>
  );
}
