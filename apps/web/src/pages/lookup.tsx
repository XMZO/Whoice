import Head from "next/head";
import Link from "next/link";
import type { GetServerSideProps } from "next";
import { useRouter } from "next/router";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { AppControls } from "@/components/AppControls";
import { appendLookupOptions, lookup, normalizeLookupInput, type LookupOptions } from "@/lib/api";
import { useI18n } from "@/lib/i18n";
import { renderResultPlugins } from "@/lib/resultPlugins";
import type { APIResponse, LookupResult } from "@/lib/types";

type Props = {
  query: string;
  response: APIResponse;
  httpStatus: number;
  sourceMode: SourceMode;
  options: LookupOptions;
};

type SourceMode = "all" | "rdap" | "whois";

type LookupState = {
  query: string;
  response: APIResponse;
  httpStatus: number;
  sourceMode: SourceMode;
  options: LookupOptions;
};

function parseBool(value?: string) {
  if (!value) return false;
  return value === "1" || value.toLowerCase() === "true";
}

function sourceModeFromQuery(rdap?: string, whois?: string): SourceMode {
  if (!rdap && !whois) return "all";
  const useRDAP = parseBool(rdap);
  const useWHOIS = parseBool(whois);
  if (useRDAP && !useWHOIS) return "rdap";
  if (useWHOIS && !useRDAP) return "whois";
  return "all";
}

function lookupUrl(query: string, mode: SourceMode, options: LookupOptions) {
  const params = new URLSearchParams({ query: normalizeLookupInput(query) });
  if (mode === "rdap") params.set("rdap", "1");
  if (mode === "whois") params.set("whois", "1");
  appendLookupOptions(params, {
    rdapServer: options.rdapServer,
    whoisServer: options.whoisServer,
    whoisFollow: options.whoisFollow,
  });
  return `/lookup?${params.toString()}`;
}

function cleanOptions(options: LookupOptions): LookupOptions {
  return Object.fromEntries(Object.entries(options).filter(([, value]) => value !== undefined && value !== "")) as LookupOptions;
}

function lookupParamsFromPath(path: string) {
  const search = path.split("?")[1]?.split("#")[0] || "";
  const params = new URLSearchParams(search);
  return {
    query: params.get("query") || "",
    sourceMode: sourceModeFromQuery(params.get("rdap") || undefined, params.get("whois") || undefined),
    options: cleanOptions({
      rdapServer: params.get("rdap_server") || undefined,
      whoisServer: params.get("whois_server") || undefined,
      whoisFollow: params.get("whois_follow") || undefined,
    }),
  };
}

export const getServerSideProps: GetServerSideProps<Props> = async (context) => {
  const query = typeof context.query.query === "string" ? context.query.query : "";
  const rdap = typeof context.query.rdap === "string" ? context.query.rdap : undefined;
  const whois = typeof context.query.whois === "string" ? context.query.whois : undefined;
  const options: LookupOptions = {
    rdap,
    whois,
    rdapServer: typeof context.query.rdap_server === "string" ? context.query.rdap_server : undefined,
    whoisServer: typeof context.query.whois_server === "string" ? context.query.whois_server : undefined,
    whoisFollow: typeof context.query.whois_follow === "string" ? context.query.whois_follow : undefined,
  };
  const serializableOptions = cleanOptions(options);
  const sourceMode = sourceModeFromQuery(rdap, whois);

  if (!query) {
    return {
      props: {
        query,
        httpStatus: 400,
        sourceMode,
        options: serializableOptions,
        response: {
          ok: false,
          error: { code: "query_required", message: "Query is required." },
        },
      },
    };
  }

  try {
    const { status, body } = await lookup(query, options);
    return { props: { query, httpStatus: status, response: body, sourceMode, options: serializableOptions } };
  } catch (error) {
    return {
      props: {
        query,
        httpStatus: 502,
        sourceMode,
        options: serializableOptions,
        response: {
          ok: false,
          error: {
            code: "api_unreachable",
            message: error instanceof Error ? error.message : "Lookup API is unreachable.",
          },
        },
      },
    };
  }
};

function Row({ label, value }: { label: string; value?: string | number | null }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <div className="detail-row">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function brandLabel(brand?: { name: string; color?: string }) {
  if (!brand) return undefined;
  return brand.color ? `${brand.name} ${brand.color}` : brand.name;
}

function RawBlock({ title, value }: { title: string; value?: string }) {
  if (!value) return null;
  return (
    <section className="panel raw-panel">
      <div className="panel-head">
        <h2>{title}</h2>
      </div>
      <pre>{value}</pre>
    </section>
  );
}

function hasNetwork(result: LookupResult) {
  return Boolean(result.network.range || result.network.cidr || result.network.name || result.network.type || result.network.originAS || result.network.country);
}

function DNSPanel({ result }: { result: LookupResult }) {
  const { t } = useI18n();
  const dns = result.enrichment?.dns;
  const hasRecords = Boolean(dns?.cname || dns?.a?.length || dns?.aaaa?.length || dns?.mx?.length || dns?.ns?.length);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{t("dns")}</h2>
      </div>
      {!hasRecords ? (
        <p className="muted">{t("noDns")}</p>
      ) : (
        <dl className="detail-list">
          <Row label="CNAME" value={dns?.cname} />
          <Row label="A" value={dns?.a?.map((item) => item.ip).join(", ")} />
          <Row label="AAAA" value={dns?.aaaa?.map((item) => item.ip).join(", ")} />
          <Row label="MX" value={dns?.mx?.map((item) => `${item.pref} ${item.host}`).join(", ")} />
          <Row label="NS" value={dns?.ns?.join(", ")} />
          <Row label="DNS ms" value={dns?.elapsedMs} />
        </dl>
      )}
    </section>
  );
}

function NetworkPanel({ result }: { result: LookupResult }) {
  const { t } = useI18n();
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{t("network")}</h2>
      </div>
      {!hasNetwork(result) ? (
        <p className="muted">{t("noNetwork")}</p>
      ) : (
        <dl className="detail-list">
          <Row label="Range" value={result.network.range} />
          <Row label="CIDR" value={result.network.cidr} />
          <Row label="Name" value={result.network.name} />
          <Row label="Type" value={result.network.type} />
          <Row label="Origin AS" value={result.network.originAS} />
          <Row label="Country" value={result.network.country} />
        </dl>
      )}
    </section>
  );
}

function StatusStrip({ result }: { result: LookupResult }) {
  return (
    <section className={`status-strip status-${result.status}`}>
      <div>
        <p className="eyebrow">{result.type}</p>
        <h1>{result.normalizedQuery}</h1>
      </div>
      <div className="status-badges">
        <span>{result.status}</span>
        {result.source.primary && <span>{result.source.primary} primary</span>}
        <span>{result.meta.elapsedMs} ms</span>
      </div>
    </section>
  );
}

function SourceLinks({
  query,
  value,
  options,
  onChange,
}: {
  query: string;
  value: SourceMode;
  options: LookupOptions;
  onChange: (value: SourceMode) => void;
}) {
  const sourceOptions: { value: SourceMode; label: string }[] = [
    { value: "all", label: "All" },
    { value: "rdap", label: "RDAP" },
    { value: "whois", label: "WHOIS" },
  ];

  return (
    <div className="source-toggle source-tabs" role="radiogroup" aria-label="Lookup source">
      {sourceOptions.map((option) => (
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

export default function LookupPage({ query, response, httpStatus, sourceMode, options }: Props) {
  const router = useRouter();
  const [state, setState] = useState<LookupState>({ query, response, httpStatus, sourceMode, options });
  const [searchValue, setSearchValue] = useState(query);
  const [isLoading, setIsLoading] = useState(false);
  const handledURLRef = useRef(lookupUrl(query, sourceMode, options));
  const inflightURLRef = useRef("");
  const result = state.response.result;
  const title = result ? `${result.normalizedQuery} | Whoice` : `${state.query || "Lookup"} | Whoice`;
  const statuses = Array.isArray(result?.statuses) ? result.statuses : [];
  const nameservers = Array.isArray(result?.nameservers) ? result.nameservers : [];
  const sourceErrors = Array.isArray(result?.source.errors) ? result.source.errors : [];
  const [actionState, setActionState] = useState("");
  const { t } = useI18n();
  const pageURL = useMemo(() => lookupUrl(state.query, state.sourceMode, state.options), [state.options, state.query, state.sourceMode]);

  useEffect(() => {
    const propsURL = lookupUrl(query, sourceMode, options);
    if (router.isReady) {
      const current = lookupParamsFromPath(router.asPath);
      const currentURL = current.query ? lookupUrl(current.query, current.sourceMode, current.options) : "";
      if (currentURL && currentURL !== propsURL) {
        return;
      }
    }
    setState({ query, response, httpStatus, sourceMode, options });
    setSearchValue(query);
    handledURLRef.current = propsURL;
  }, [httpStatus, options, query, response, router.asPath, router.isReady, sourceMode]);

  useEffect(() => {
    if (!router.isReady) return;
    const next = lookupParamsFromPath(router.asPath);
    if (!next.query || isLoading) return;
    const nextURL = lookupUrl(next.query, next.sourceMode, next.options);
    if (nextURL !== handledURLRef.current && nextURL !== inflightURLRef.current) {
      void runLookup(next.query, next.sourceMode, next.options, false);
    }
  }, [router.asPath, router.isReady]);

  async function runLookup(nextQuery: string, nextSourceMode = state.sourceMode, nextOptions = state.options, updateURL = true) {
    const trimmed = normalizeLookupInput(nextQuery);
    if (!trimmed || isLoading) return;
    const requestOptions = {
      ...nextOptions,
      rdap: nextSourceMode === "rdap" ? "1" : undefined,
      whois: nextSourceMode === "whois" ? "1" : undefined,
    };
    const serializableOptions = cleanOptions(requestOptions);
    const nextURL = lookupUrl(trimmed, nextSourceMode, serializableOptions);
    if (inflightURLRef.current === nextURL) return;
    inflightURLRef.current = nextURL;
    setIsLoading(true);
    try {
      const { status, body } = await lookup(trimmed, requestOptions);
      setState({
        query: trimmed,
        response: body,
        httpStatus: status,
        sourceMode: nextSourceMode,
        options: serializableOptions,
      });
      handledURLRef.current = nextURL;
      setSearchValue(trimmed);
      if (updateURL && typeof window !== "undefined") {
        void router.push(nextURL, undefined, { shallow: true, scroll: false });
      }
    } catch (error) {
      setState({
        query: trimmed,
        httpStatus: 502,
        sourceMode: nextSourceMode,
        options: serializableOptions,
        response: {
          ok: false,
          error: {
            code: "api_unreachable",
            message: error instanceof Error ? error.message : "Lookup API is unreachable.",
          },
        },
      });
      handledURLRef.current = nextURL;
      setSearchValue(trimmed);
      if (updateURL && typeof window !== "undefined") {
        void router.push(nextURL, undefined, { shallow: true, scroll: false });
      }
    } finally {
      inflightURLRef.current = "";
      setIsLoading(false);
    }
  }

  function submitMiniSearch(event: FormEvent) {
    event.preventDefault();
    void runLookup(searchValue);
  }

  function switchSource(nextSourceMode: SourceMode) {
    if (nextSourceMode === state.sourceMode) return;
    void runLookup(state.query, nextSourceMode);
  }

  async function copy(value: string, label: string) {
    if (!value || typeof navigator === "undefined" || !navigator.clipboard) return;
    await navigator.clipboard.writeText(value);
    setActionState(label);
    window.setTimeout(() => setActionState(""), 1400);
  }

  async function shareResult() {
    const url = typeof window === "undefined" ? pageURL : window.location.href;
    await copy(url, t("copied"));
  }

  function downloadResult() {
    if (!result || typeof window === "undefined") return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${result.normalizedQuery}.whoice.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <Head>
        <title>{title}</title>
        <meta property="og:title" content={title} />
        <meta property="og:image" content={`/api/og?query=${encodeURIComponent(result?.normalizedQuery || state.query)}`} />
        <meta name="twitter:card" content="summary_large_image" />
      </Head>
      <main className="shell result-shell">
        <nav className="top-nav">
          <Link href="/" className="brand">Whoice</Link>
          <form className="mini-search" onSubmit={submitMiniSearch}>
            <input name="query" value={searchValue} onChange={(event) => setSearchValue(event.target.value)} aria-label="Search query" />
            <button disabled={isLoading} type="submit">{isLoading ? "..." : "Search"}</button>
          </form>
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <AppControls />
          </div>
        </nav>

        {state.query && <SourceLinks query={state.query} value={state.sourceMode} options={state.options} onChange={switchSource} />}

        {isLoading && (
          <section className="panel loading-panel">
            <p className="eyebrow">Live lookup</p>
            <h2>{searchValue}</h2>
          </section>
        )}

        {!state.response.ok || !result ? (
          <section className="panel error-panel">
            <p className="eyebrow">HTTP {state.httpStatus}</p>
            <h1>{state.response.error?.message || t("failed")}</h1>
            <p className="muted">{t("sourceHint")}</p>
          </section>
        ) : (
          <>
            <section className="action-bar" aria-label="Result actions">
              <button type="button" onClick={shareResult}>{t("share")}</button>
              <button type="button" onClick={() => copy([result.raw.whois, result.raw.whoisWeb, result.raw.rdap].filter(Boolean).join("\n\n"), t("copied"))}>{t("copyRaw")}</button>
              <button type="button" onClick={downloadResult}>{t("downloadJson")}</button>
              {actionState && <span>{actionState}</span>}
            </section>
            <StatusStrip result={result} />
            <div className="result-grid">
              <section className="panel">
                <div className="panel-head">
                  <h2>{t("summary")}</h2>
                </div>
                <dl className="detail-list">
                  <Row label="Domain" value={result.domain.name} />
                  <Row label="Unicode" value={result.domain.unicodeName} />
                  <Row label="Registrar" value={result.registrar.name} />
                  <Row label="Registrar Brand" value={brandLabel(result.registrar.brand)} />
                  <Row label="IANA ID" value={result.registrar.ianaId} />
                  <Row label="Registrar Country" value={result.registrar.country} />
                  <Row label="Registrar URL" value={result.registrar.url} />
                  <Row label="Created" value={result.dates.createdAt} />
                  <Row label="Expires" value={result.dates.expiresAt} />
                  <Row label="Updated" value={result.dates.updatedAt} />
                  <Row label="Age days" value={result.dates.ageDays} />
                  <Row label="Remaining days" value={result.dates.remainingDays} />
                  <Row label="DNSSEC" value={result.dnssec.text} />
                </dl>
              </section>

              {result.type === "domain" ? <DNSPanel result={result} /> : <NetworkPanel result={result} />}

              <section className="panel">
                <div className="panel-head">
                  <h2>{t("status")}</h2>
                </div>
                {statuses.length === 0 ? (
                  <p className="muted">{t("noStatus")}</p>
                ) : (
                  <div className="chip-list">
                    {statuses.map((status) => (
                      <span key={`${status.code}-${status.source}`} className="chip" title={status.description}>
                        {status.label || status.code}
                      </span>
                    ))}
                  </div>
                )}
              </section>

              <section className="panel">
                <div className="panel-head">
                  <h2>{t("nameservers")}</h2>
                </div>
                {nameservers.length === 0 ? (
                  <p className="muted">{t("noNameservers")}</p>
                ) : (
                  <div className="mono-list">
                    {nameservers.map((ns) => <span key={ns.host}>{ns.host}{ns.brand ? ` - ${brandLabel(ns.brand)}` : ""}</span>)}
                  </div>
                )}
              </section>
            </div>

            <div className="result-grid">
              {renderResultPlugins("details", result)}
            </div>

            {sourceErrors.length > 0 && (
              <section className="panel warning-panel">
                <div className="panel-head">
                  <h2>{t("warnings")}</h2>
                </div>
                <ul>
                  {sourceErrors.map((error) => (
                    <li key={`${error.source}-${error.error}`}>{error.source}: {error.error}</li>
                  ))}
                </ul>
              </section>
            )}

            {renderResultPlugins("debug", result)}

            <RawBlock title={t("rawWhois")} value={result.raw.whois} />
            <RawBlock title="WHOIS Web" value={result.raw.whoisWeb} />
            <RawBlock title={t("rawRdap")} value={result.raw.rdap} />
          </>
        )}
      </main>
    </>
  );
}
