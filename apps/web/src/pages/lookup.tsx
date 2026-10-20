import Head from "next/head";
import Link from "next/link";
import type { GetServerSideProps } from "next";
import { useRouter } from "next/router";
import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import packageInfo from "../../package.json";
import { AppControls } from "@/components/AppControls";
import { BrandMark } from "@/components/BrandMark";
import { CheckCircleIcon, CopyIcon, DownloadIcon, FileIcon, ImageIcon, LinkIcon, SearchIcon, WarnIcon } from "@/components/Icons";
import { RawDrawer, type RawTab } from "@/components/RawDrawer";
import {
  DNSSection,
  DNSVizLink,
  DomainMetrics,
  LockBar,
  NetworkMetrics,
  NetworkSection,
  PriceSection,
  RegistrantSection,
  SourceTags,
  SourcesSection,
  StatusList,
  pricingMeta,
  pricingSummary,
  registrantFieldCount,
  type ICPState,
} from "@/components/ResultSections";
import { analyzeRegistration, appendLookupOptions, enrichLookup, getCapabilities, lookup, lookupICP, normalizeLookupInput, type LookupOptions } from "@/lib/api";
import { writeHistory } from "@/lib/history";
import { useI18n, type I18nKey } from "@/lib/i18n";
import { kindLabel, sourceName, sourceTag } from "@/lib/resultModel";
import type { APIResponse, LookupResult } from "@/lib/types";

type SectionTab = "overview" | "dns" | "owner" | "price" | "source" | "network";


type Props = {
  query: string;
  response: APIResponse;
  httpStatus: number;
  sourceMode: SourceMode;
  options: LookupOptions;
  icpAutoQuery: boolean;
};

type SourceMode = "all" | "rdap" | "whois";

type LookupState = {
  query: string;
  response: APIResponse;
  httpStatus: number;
  sourceMode: SourceMode;
  options: LookupOptions;
  nonce: number;
};


type AIState = {
  key: string;
  identity?: string;
  loading: boolean;
  requested: boolean;
  error?: string;
};

type EnrichmentState = {
  key: string;
  identity?: string;
  loading: boolean;
  requested: boolean;
  names?: string[];
  error?: string;
};

type ErrorViewModel = {
  eyebrow: string;
  title: string;
  message: string;
  detail?: string;
};


async function loadICPAutoQuery() {
  try {
    const { body } = await getCapabilities();
    return Boolean(body.capabilities?.icpAutoQuery);
  } catch {
    return false;
  }
}

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
    exactDomain: options.exactDomain,
  });
  if (options.ai) params.set("ai", options.ai);
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
    exactDomain: params.get("exact_domain") || undefined,
    ai: params.get("ai") || undefined,
    fast: params.get("fast") || undefined,
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
    exactDomain: typeof context.query.exact_domain === "string" ? context.query.exact_domain : undefined,
    ai: typeof context.query.ai === "string" ? context.query.ai : undefined,
  };
  const serializableOptions = cleanOptions(options);
  const sourceMode = sourceModeFromQuery(rdap, whois);
  const icpAutoQuery = await loadICPAutoQuery();

  if (!query) {
    return {
      props: {
        query,
        httpStatus: 400,
        sourceMode,
        options: serializableOptions,
        icpAutoQuery,
        response: {
          ok: false,
          error: { code: "query_required", message: "Query is required." },
        },
      },
    };
  }

  try {
    const { status, body } = await lookup(query, options);
    return { props: { query, httpStatus: status, response: body, sourceMode, options: serializableOptions, icpAutoQuery } };
  } catch (error) {
    return {
      props: {
        query,
        httpStatus: 502,
        sourceMode,
        options: serializableOptions,
        icpAutoQuery,
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

function rawText(result: LookupResult) {
  return [result.raw.whois, result.raw.whoisWeb, result.raw.rdap].filter(Boolean).join("\n\n");
}

function aiResultKey(result?: LookupResult) {
  if (!result || result.type !== "domain") return "";
  const raw = rawText(result);
  if (!raw.trim()) return "";
  return `${result.normalizedQuery}\x00${raw.length}\x00${raw.slice(0, 160)}\x00${raw.slice(-160)}`;
}

function aiRequestKey(result: LookupResult | undefined, nonce: number) {
  const key = aiResultKey(result);
  return key ? `${nonce}\x1f${key}` : "";
}

function aiIdentity(result: LookupResult | undefined, nonce: number) {
  return result ? `${nonce}\x1f${result.normalizedQuery}` : "";
}

function enrichmentRequestKey(result: LookupResult | undefined, nonce: number) {
  if (!result?.meta?.pendingEnrichments?.length) return "";
  return `${nonce}\x1f${result.normalizedQuery}\x1f${result.meta.pendingEnrichments.join(",")}`;
}

function enrichmentIdentity(result: LookupResult | undefined, nonce: number) {
  return result ? `${nonce}\x1f${result.normalizedQuery}` : "";
}

function mergeAIResult(current: LookupResult, incoming: LookupResult): LookupResult {
  return {
    ...current,
    registrant: incoming.registrant || current.registrant,
    registrar: incoming.registrar || current.registrar,
    enrichment: current.enrichment,
    meta: {
      ...current.meta,
      ai: incoming.meta?.ai || current.meta?.ai,
    },
  };
}

function mergeEnrichmentResult(current: LookupResult, incoming: LookupResult): LookupResult {
  const incomingMeta = incoming.meta || current.meta;
  const currentAI = current.meta?.ai;
  return {
    ...current,
    nameservers: Array.isArray(incoming.nameservers) && incoming.nameservers.length ? incoming.nameservers : current.nameservers,
    enrichment: {
      ...(current.enrichment || {}),
      ...(incoming.enrichment || {}),
    },
    meta: {
      ...current.meta,
      warnings: incomingMeta.warnings ?? current.meta.warnings,
      providers: incomingMeta.providers ?? current.meta.providers,
      pendingEnrichments: incomingMeta.pendingEnrichments ?? [],
      ai: currentAI || incomingMeta.ai,
    },
  };
}

function errorView(response: APIResponse, status: number): ErrorViewModel {
  const code = response.error?.code || "";
  const message = response.error?.message || "";
  if (status === 502 || code === "api_unreachable" || code === "invalid_json_response" || code === "html_error_response") {
    return {
      eyebrow: `HTTP ${status || 502}`,
      title: "Lookup API unavailable",
      message: "Whoice could not reach the lookup API or received a gateway error page instead of JSON.",
      detail: message,
    };
  }
  return {
    eyebrow: status ? `HTTP ${status}` : "Lookup error",
    title: message || "Lookup failed",
    message: "Switch source mode or check whether the lookup API is running.",
    detail: code,
  };
}

function SourceToggle({ value, onChange }: { value: SourceMode; onChange: (value: SourceMode) => void }) {
  const { t } = useI18n();
  const options: { value: SourceMode; label: string }[] = [
    { value: "all", label: t("all") },
    { value: "rdap", label: "RDAP" },
    { value: "whois", label: "WHOIS" },
  ];
  return (
    <div className="source-toggle" role="radiogroup" aria-label={t("lookupSource")}>
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

const statusLabelKey: Record<string, I18nKey> = {
  registered: "statusRegistered",
  unregistered: "statusUnregistered",
  reserved: "statusReserved",
  unknown: "statusUnknown",
  error: "statusError",
};

function StatusBadge({ status }: { status: string }) {
  const { t } = useI18n();
  return (
    <span className={`status-badge status-badge-${status}`}>
      {status === "registered" ? <CheckCircleIcon size={14} /> : status === "error" || status === "reserved" ? <WarnIcon size={13} /> : <span className="status-badge-dot" aria-hidden="true" />}
      {t(statusLabelKey[status] || "statusUnknown")}
    </span>
  );
}

function TabButton({
  id,
  active,
  label,
  meta,
  dot,
  onSelect,
}: {
  id: SectionTab;
  active: boolean;
  label: string;
  meta?: ReactNode;
  dot?: boolean;
  onSelect: (id: SectionTab) => void;
}) {
  const { t } = useI18n();
  return (
    <button type="button" role="tab" aria-selected={active} aria-controls={`section-${id}`} className={active ? "result-tab active" : "result-tab"} onClick={() => onSelect(id)}>
      {label}
      {meta !== undefined && meta !== "" && <span className="tab-meta">{meta}</span>}
      {dot && <span className="tab-dot" role="img" aria-label={t("hasWarning")} />}
    </button>
  );
}

function LookupErrorPanel({ response, status, onRetry }: { response: APIResponse; status: number; onRetry?: () => void }) {
  const { t } = useI18n();
  const view = errorView(response, status);
  return (
    <section className="error-panel">
      <span className="status-badge status-badge-error">
        <WarnIcon size={13} />
        {view.eyebrow}
      </span>
      <h1>{view.title}</h1>
      <p className="muted">{view.message}</p>
      {view.detail && <pre className="error-detail">{view.detail}</pre>}
      {onRetry && (
        <button type="button" className="btn btn-primary" onClick={onRetry}>
          {t("retry")}
        </button>
      )}
    </section>
  );
}


export default function LookupPage({ query, response, httpStatus, sourceMode, options, icpAutoQuery }: Props) {
  const router = useRouter();
  const [state, setState] = useState<LookupState>({ query, response, httpStatus, sourceMode, options, nonce: 0 });
  const [searchValue, setSearchValue] = useState(query);
  const [isLoading, setIsLoading] = useState(false);
  const handledURLRef = useRef(lookupUrl(query, sourceMode, options));
  const inflightURLRef = useRef("");
  const icpInflightRef = useRef("");
  const aiInflightRef = useRef("");
  const enrichmentInflightRef = useRef("");
  const runtimeConfigRef = useRef(response.config?.loadedAt || "");
  const aiArmedRef = useRef(parseBool(options.ai));
  const result = state.response.result;
  const title = result ? `${result.normalizedQuery} | Whoice` : `${state.query || "Lookup"} | Whoice`;
  const statuses = Array.isArray(result?.statuses) ? result.statuses : [];
  const sourceErrors = Array.isArray(result?.source.errors) ? result.source.errors : [];
  const metaWarnings = Array.isArray(result?.meta.warnings) ? result.meta.warnings : [];
  const [actionState, setActionState] = useState("");
  const [shareMenuOpen, setShareMenuOpen] = useState(false);
  const [icpState, setICPState] = useState<ICPState>({ domain: "", loading: false, requested: false });
  const [aiState, setAIState] = useState<AIState>({ key: "", loading: false, requested: false });
  const [enrichmentState, setEnrichmentState] = useState<EnrichmentState>({ key: "", loading: false, requested: false });
  const { t, tf } = useI18n();
  const [tab, setTab] = useState<SectionTab>("overview");
  const [rawTab, setRawTab] = useState<RawTab | null>(null);
  const pageURL = useMemo(() => lookupUrl(state.query, state.sourceMode, state.options), [state.options, state.query, state.sourceMode]);
  const absolutePageURL = typeof window === "undefined" ? pageURL : window.location.href;
  const ogImageURL = `/api/og?query=${encodeURIComponent(result?.normalizedQuery || state.query)}`;
  const icpDomain = result?.type === "domain" ? result.domain.registeredDomain || result.domain.name || result.normalizedQuery : "";
  const currentAIIdentity = aiIdentity(result, state.nonce);
  const currentEnrichmentIdentity = enrichmentIdentity(result, state.nonce);
  const pendingEnrichments = result?.meta?.pendingEnrichments || [];
  const rememberedEnrichments = enrichmentState.identity === currentEnrichmentIdentity && enrichmentState.requested ? enrichmentState.names || [] : [];
  const visibleEnrichments = pendingEnrichments.length ? pendingEnrichments : rememberedEnrichments;
  const enrichmentLoading = enrichmentState.loading && enrichmentState.identity === currentEnrichmentIdentity;
  const enrichmentError = enrichmentState.identity === currentEnrichmentIdentity ? enrichmentState.error : undefined;
  const dnsPending = Boolean(result && pendingEnrichments.includes("dns"));
  const pricingPending = Boolean(result && !result.enrichment?.pricing && visibleEnrichments.includes("pricing") && (enrichmentLoading || pendingEnrichments.includes("pricing")));
  const warnings = [
    ...(enrichmentError ? [`enrichment: ${enrichmentError}`] : []),
    ...metaWarnings,
    ...sourceErrors.map((error) => `${error.source}: ${error.error}`),
  ];

  useEffect(() => {
    const propsURL = lookupUrl(query, sourceMode, options);
    if (router.isReady) {
      const current = lookupParamsFromPath(router.asPath);
      const currentURL = current.query ? lookupUrl(current.query, current.sourceMode, current.options) : "";
      if (currentURL && currentURL !== propsURL) {
        return;
      }
    }
    setState((current) => ({
      query,
      response,
      httpStatus,
      sourceMode,
      options,
      nonce: lookupUrl(query, sourceMode, options) === handledURLRef.current ? current.nonce : current.nonce + 1,
    }));
    setSearchValue(query);
    handledURLRef.current = propsURL;
    if (response.ok && query) {
      writeHistory(normalizeLookupInput(query));
    }
  }, [httpStatus, options, query, response, router.asPath, router.isReady, sourceMode]);

  useEffect(() => {
    setICPState({ domain: icpDomain, loading: false, requested: false });
  }, [icpDomain]);

  useEffect(() => {
    const key = aiRequestKey(result, state.nonce);
    const identity = aiIdentity(result, state.nonce);
    if (!key) {
      setAIState({ key: "", identity, loading: false, requested: false });
      return;
    }
    if (result?.meta?.ai) {
      setAIState({ key, identity, loading: false, requested: true, error: result.meta.ai.status === "error" ? result.meta.ai.error : undefined });
      return;
    }
    setAIState((current) => (current.key === key ? { ...current, identity } : { key, identity, loading: false, requested: false }));
  }, [result?.normalizedQuery, result?.raw?.whois, result?.raw?.whoisWeb, result?.raw?.rdap, state.nonce]);

  useEffect(() => {
    const key = enrichmentRequestKey(result, state.nonce);
    const identity = enrichmentIdentity(result, state.nonce);
    const names = result?.meta?.pendingEnrichments || [];
    if (!key) {
      setEnrichmentState((current) => {
        if (identity && current.identity === identity && current.requested) {
          return { ...current, loading: false };
        }
        return { key: "", identity, loading: false, requested: false, names: [] };
      });
      return;
    }
    setEnrichmentState((current) => (current.key === key ? { ...current, identity, names } : { key, identity, loading: false, requested: false, names }));
  }, [result?.normalizedQuery, result?.meta?.pendingEnrichments?.join(","), state.nonce]);

  useEffect(() => {
    if (!icpAutoQuery || !icpDomain || icpState.requested || icpState.loading) return;
    void runICPLookup(icpDomain);
  }, [icpAutoQuery, icpDomain, icpState.loading, icpState.requested]);

  useEffect(() => {
    if (!aiArmedRef.current) return;
    if (!parseBool(state.options.ai) || !result || result.type !== "domain") return;
    const key = aiRequestKey(result, state.nonce);
    if (!key || aiState.key !== key || aiState.requested || aiState.loading) return;
    aiArmedRef.current = false;
    void runAIAnalysis(result, key, state.nonce);
  }, [aiState.key, aiState.loading, aiState.requested, result, state.nonce, state.options.ai]);

  useEffect(() => {
    if (!result?.meta?.pendingEnrichments?.length) return;
    const key = enrichmentRequestKey(result, state.nonce);
    if (!key || enrichmentState.key !== key || enrichmentState.loading || enrichmentState.requested) return;
    void runDeferredEnrichment(result, key);
  }, [enrichmentState.key, enrichmentState.loading, enrichmentState.requested, result, state.nonce]);

  useEffect(() => {
    if (!router.isReady) return;
    const next = lookupParamsFromPath(router.asPath);
    if (!next.query || isLoading) return;
    const nextURL = lookupUrl(next.query, next.sourceMode, next.options);
    if (nextURL !== handledURLRef.current && nextURL !== inflightURLRef.current) {
      void runLookup(next.query, next.sourceMode, next.options, false);
    }
  }, [router.asPath, router.isReady]);

  useEffect(() => {
    if (!state.query || isLoading) return;
    let stopped = false;
    const checkRuntimeConfig = async () => {
      try {
        const { body } = await getCapabilities();
        const loadedAt = body.config?.loadedAt || "";
        const current = runtimeConfigRef.current;
        if (loadedAt) {
          runtimeConfigRef.current = loadedAt;
        }
        if (!stopped && loadedAt && current && loadedAt !== current) {
          await runLookup(state.query, state.sourceMode, state.options, false, false);
        }
      } catch {
        // Runtime config polling is best-effort; lookup itself still reports API errors.
      }
    };
    const interval = window.setInterval(() => {
      void checkRuntimeConfig();
    }, 2500);
    void checkRuntimeConfig();
    return () => {
      stopped = true;
      window.clearInterval(interval);
    };
  }, [isLoading, state.options, state.query, state.sourceMode]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      const tag = target?.tagName;
      const isTyping = tag === "INPUT" || tag === "TEXTAREA" || target?.isContentEditable;
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      if (isTyping) return;
      if (event.key === "Escape") {
        setShareMenuOpen(false);
        return;
      }
      if (rawTab) return;
      if (event.key === "/") {
        event.preventDefault();
        document.getElementById("lookup-mini-search")?.focus();
      }
      if (!result) return;
      if (event.key.toLowerCase() === "s") {
        event.preventDefault();
        setShareMenuOpen((open) => !open);
      }
      if (event.key.toLowerCase() === "c") {
        event.preventDefault();
        void copy(absolutePageURL, t("copied"));
      }
      if (event.key.toLowerCase() === "r") {
        event.preventDefault();
        void copy(rawText(result), t("copied"));
      }
      if (event.key.toLowerCase() === "j") {
        event.preventDefault();
        downloadResult();
      }
      if (event.key.toLowerCase() === "o") {
        event.preventDefault();
        downloadOGImage();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [absolutePageURL, rawTab, result, t]);

  async function runLookup(nextQuery: string, nextSourceMode = state.sourceMode, nextOptions = state.options, updateURL = true, armAI = true) {
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
    aiArmedRef.current = armAI && parseBool(serializableOptions.ai);
    setIsLoading(true);
    setAIState({ key: "", loading: false, requested: false });
    setEnrichmentState({ key: "", loading: false, requested: false });
    try {
      const { status, body } = await lookup(trimmed, requestOptions);
      const nextNonce = Date.now();
      setState({
        query: trimmed,
        response: body,
        httpStatus: status,
        sourceMode: nextSourceMode,
        options: serializableOptions,
        nonce: nextNonce,
      });
      handledURLRef.current = nextURL;
      setSearchValue(trimmed);
      if (body.ok) {
        writeHistory(trimmed);
      }
      if (updateURL && typeof window !== "undefined") {
        void router.push(nextURL, undefined, { shallow: true, scroll: false });
      }
    } catch (error) {
      aiArmedRef.current = false;
      setState({
        query: trimmed,
        httpStatus: 502,
        sourceMode: nextSourceMode,
        options: serializableOptions,
        nonce: Date.now(),
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
      setAIState({ key: "", loading: false, requested: false });
      setEnrichmentState({ key: "", loading: false, requested: false });
      if (updateURL && typeof window !== "undefined") {
        void router.push(nextURL, undefined, { shallow: true, scroll: false });
      }
    } finally {
      inflightURLRef.current = "";
      setIsLoading(false);
    }
  }

  async function runICPLookup(domain = icpDomain) {
    const normalized = normalizeLookupInput(domain);
    if (!normalized || icpState.loading) return;
    if (icpInflightRef.current === normalized) return;
    icpInflightRef.current = normalized;
    setICPState({ domain: normalized, loading: true, requested: true });
    try {
      const { status, body } = await lookupICP(normalized);
      setICPState({
        domain: normalized,
        loading: false,
        requested: true,
        httpStatus: status,
        result: body.result,
        errorCode: body.ok ? undefined : body.error?.code,
        error: body.ok ? undefined : body.error?.message || "ICP lookup failed",
      });
    } catch (error) {
      setICPState({
        domain: normalized,
        loading: false,
        requested: true,
        errorCode: "icp_request_failed",
        error: error instanceof Error ? error.message : "ICP lookup failed",
      });
    } finally {
      if (icpInflightRef.current === normalized) {
        icpInflightRef.current = "";
      }
    }
  }

  async function runAIAnalysis(target = result, key = aiRequestKey(target, state.nonce), nonce = state.nonce) {
    if (!target || target.type !== "domain" || !key) return;
    if (aiInflightRef.current === key) return;
    aiInflightRef.current = key;
    const identity = aiIdentity(target, nonce);
    setAIState({ key, identity, loading: true, requested: true });
    try {
      const { body } = await analyzeRegistration(target, true);
      if (!body.ok || !body.result) {
        setAIState({
          key,
          identity,
          loading: false,
          requested: true,
          error: body.error?.message || "AI registration analysis failed",
        });
        return;
      }
      const nextResult = body.result;
      setState((current) => {
        if (aiRequestKey(current.response.result, current.nonce) !== key) return current;
        if (!current.response.result) return current;
        return {
          ...current,
          response: {
            ...current.response,
            result: mergeAIResult(current.response.result, nextResult),
            meta: body.meta || nextResult.meta,
          },
        };
      });
      setAIState({ key, identity, loading: false, requested: true });
    } catch (error) {
      setAIState({
        key,
        identity,
        loading: false,
        requested: true,
        error: error instanceof Error ? error.message : "AI registration analysis failed",
      });
    } finally {
      if (aiInflightRef.current === key) {
        aiInflightRef.current = "";
      }
    }
  }

  async function runDeferredEnrichment(target = result, key = enrichmentRequestKey(target, state.nonce)) {
    if (!target || !key) return;
    if (enrichmentInflightRef.current === key) return;
    enrichmentInflightRef.current = key;
    const identity = enrichmentIdentity(target, state.nonce);
    const names = target.meta?.pendingEnrichments || [];
    setEnrichmentState({ key, identity, loading: true, requested: true, names });
    try {
      const { body } = await enrichLookup(target);
      if (!body.ok || !body.result) {
        setEnrichmentState({
          key,
          identity,
          loading: false,
          requested: true,
          names,
          error: body.error?.message || "Enrichment failed",
        });
        return;
      }
      const nextResult = body.result;
      setState((current) => {
        if (enrichmentRequestKey(current.response.result, current.nonce) !== key) return current;
        if (!current.response.result) return current;
        return {
          ...current,
          response: {
            ...current.response,
            result: mergeEnrichmentResult(current.response.result, nextResult),
            meta: body.meta || nextResult.meta,
          },
        };
      });
      setEnrichmentState({ key, identity, loading: false, requested: true, names });
    } catch (error) {
      setEnrichmentState({
        key,
        identity,
        loading: false,
        requested: true,
        names,
        error: error instanceof Error ? error.message : "Enrichment failed",
      });
    } finally {
      if (enrichmentInflightRef.current === key) {
        enrichmentInflightRef.current = "";
      }
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

  function switchExactDomain(enabled: boolean) {
    const nextOptions = cleanOptions({
      ...state.options,
      exactDomain: enabled ? "1" : undefined,
    });
    void runLookup(state.query, state.sourceMode, nextOptions);
  }

  function switchForceAI(enabled: boolean) {
    const nextOptions = cleanOptions({
      ...state.options,
      ai: enabled ? "1" : undefined,
    });
    const nextURL = lookupUrl(state.query, state.sourceMode, nextOptions);
    aiArmedRef.current = false;
    setState((current) => ({ ...current, options: nextOptions }));
    handledURLRef.current = nextURL;
    if (typeof window !== "undefined") {
      void router.push(nextURL, undefined, { shallow: true, scroll: false });
    }
  }

  async function copy(value: string, label: string) {
    if (!value || typeof navigator === "undefined" || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(value);
      setActionState(label);
    } catch {
      setActionState("Copy blocked");
    }
    window.setTimeout(() => setActionState(""), 1400);
  }

  async function shareResult() {
    void copy(absolutePageURL, t("copied"));
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

  async function downloadOGImage() {
    if (!result || typeof window === "undefined") return;
    const response = await fetch(ogImageURL);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${result.normalizedQuery}.whoice-og.png`;
    anchor.click();
    URL.revokeObjectURL(url);
    setActionState(t("imageDownloaded"));
    window.setTimeout(() => setActionState(""), 1400);
  }

  const isDomain = result?.type === "domain";
  const lowerTabs: SectionTab[] = isDomain ? ["dns", "owner", "price", "source"] : ["network", "owner", "source"];
  const activeLower: SectionTab = lowerTabs.includes(tab) ? tab : lowerTabs[0];
  const activeMobile: SectionTab = tab === "overview" || lowerTabs.includes(tab) ? tab : "overview";
  const copyValue = (value: string) => void copy(value, t("copied"));
  const usedSources = Array.isArray(result?.source?.used) ? result.source.used : [];
  const elapsed = result?.meta?.elapsedMs ?? 0;
  const warningText = warnings.length === 1 ? t("warningOne") : tf("warningMany", { n: warnings.length });
  const ownerFields = result ? registrantFieldCount(result) : 0;
  const ownerSources = result
    ? Array.from(new Set(Object.values(result.registrant?.fieldSources || {}).flat().map((item) => sourceTag(item.source)).filter(Boolean)))
    : [];

  function selectTab(next: SectionTab) {
    setTab(next);
  }

  function goSources() {
    setTab("source");
    window.requestAnimationFrame(() => document.getElementById("evidence")?.scrollIntoView({ block: "nearest", behavior: "smooth" }));
  }

  function section(id: SectionTab, node: ReactNode) {
    return (
      <div className="result-section tool-zone" id={`section-${id}`} data-section={id} data-active={activeLower === id} data-mobile-active={activeMobile === id}>
        {node}
      </div>
    );
  }

  const lowerTabLabel = (id: SectionTab): { label: string; meta?: ReactNode; dot?: boolean } => {
    if (!result) return { label: id };
    switch (id) {
      case "dns":
        return { label: t("dns"), meta: result.enrichment?.dns?.elapsedMs !== undefined ? `${result.enrichment.dns.elapsedMs} ms` : undefined };
      case "owner":
        return { label: t("registrant"), meta: ownerFields ? tf("fieldsShort", { n: ownerFields }) : undefined };
      case "price":
        return { label: t("priceScore"), meta: pricingSummary(result) };
      case "network":
        return { label: t("networkInfo") };
      default:
        return { label: t("sourcesShort"), meta: `${elapsed} ms`, dot: warnings.length > 0 };
    }
  };

  const mobileTabLabel = (id: SectionTab) =>
    id === "overview" ? t("tabOverview") : id === "dns" ? t("tabDns") : id === "owner" ? t("tabOwner") : id === "price" ? t("tabPrice") : id === "network" ? t("network") : t("tabSource");

  const lowerExtra = (() => {
    if (!result) return null;
    if (activeLower === "dns" && result.enrichment?.dnsviz?.url) return <DNSVizLink url={result.enrichment.dnsviz.url} />;
    if (activeLower === "owner" && ownerSources.length) {
      return (
        <span className="source-caption">
          {t("source")}
          <SourceTags sources={ownerSources} />
        </span>
      );
    }
    if (activeLower === "price") return <span className="section-meta">{pricingMeta(result)}</span>;
    if (activeLower === "source" && result.source?.primary) {
      const others = usedSources.filter((source) => source !== result.source.primary).map(sourceName);
      return (
        <span className="section-meta">
          {sourceName(result.source.primary)} {t("primarySource")}
          {others.length ? ` · ${others.join(" + ")} ${t("supplementary")}` : ""}
        </span>
      );
    }
    return null;
  })();

  return (
    <>
      <Head>
        <title>{title}</title>
        <meta property="og:title" content={title} />
        <meta property="og:image" content={`/api/og?query=${encodeURIComponent(result?.normalizedQuery || state.query)}`} />
        <meta name="twitter:card" content="summary_large_image" />
      </Head>
      <main className="lookup-workbench">
        <header className="lookup-topbar tool-sidebar" aria-label={t("lookupToolbox")}>
          <div className="topbar-search">
            <BrandMark />
            <form className="mini-search tool-panel" onSubmit={submitMiniSearch}>
              <SearchIcon size={15} className="mini-search-icon" />
              <input
                id="lookup-mini-search"
                name="query"
                value={searchValue}
                onChange={(event) => setSearchValue(event.target.value)}
                aria-label={t("searchQuery")}
                autoComplete="off"
                spellCheck={false}
              />
              <select className="source-select" aria-label={t("source")} value={state.sourceMode} onChange={(event) => switchSource(event.target.value as SourceMode)}>
                <option value="all">{t("all")}</option>
                <option value="rdap">RDAP</option>
                <option value="whois">WHOIS</option>
              </select>
              <button disabled={isLoading} type="submit">{isLoading ? t("searching") : t("search")}</button>
            </form>
          </div>
          <div className="topbar-source">
            <SourceToggle value={state.sourceMode} onChange={switchSource} />
          </div>
          <div className="topbar-tail">
            <div className="topbar-options">
              <label className="inline-check" title={t("exactDomainHint")}>
                <input type="checkbox" checked={parseBool(state.options.exactDomain)} onChange={(event) => switchExactDomain(event.target.checked)} />
                <span>{t("exactDomain")}</span>
              </label>
              <label className="inline-check" title={t("forceAIHint")}>
                <input type="checkbox" checked={parseBool(state.options.ai)} onChange={(event) => switchForceAI(event.target.checked)} />
                <span>{t("forceAI")}</span>
              </label>
            </div>
            <nav className="topbar-nav" aria-label={t("siteNav")}>
              <Link href="/docs">{t("docs")}</Link>
              <Link href="/status">{t("status")}</Link>
              <AppControls />
            </nav>
          </div>
        </header>

        <section className="tool-stage" aria-label={t("lookupWorkspace")} aria-busy={isLoading ? "true" : undefined}>
          {isLoading && (
            <div className="stage-loading loading-panel" aria-live="polite">
              <span className="loading-bar" aria-hidden="true" />
              <span className="loading-text">
                {t("liveLookup")} <span className="mono">{searchValue}</span>
              </span>
            </div>
          )}

          {!state.response.ok || !result ? (
            <LookupErrorPanel response={state.response} status={state.httpStatus} onRetry={state.query ? () => void runLookup(state.query, state.sourceMode, state.options, false) : undefined} />
          ) : (
            <>
              <section className="status-strip result-hero" data-tab={activeMobile} aria-label={result.normalizedQuery}>
                <div className="hero-head">
                  <div className="hero-badges">
                    <StatusBadge status={result.status} />
                    <span className="type-tag">{kindLabel(result.type, t)}</span>
                    {result.registry?.name && (
                      <span className="hero-meta">
                        {t("registryLabel")} {result.registry.name}
                      </span>
                    )}
                    <span className="hero-meta">
                      {usedSources.map(sourceName).join(" + ") || sourceName(result.source?.primary)} · <span className="mono">{elapsed} ms</span>
                    </span>
                    {warnings.length > 0 && (
                      <button type="button" className="warn-pill" onClick={goSources} aria-label={`${warningText}, ${t("viewSources")}`}>
                        <WarnIcon size={13} />
                        <span className="warn-long">{warningText}</span>
                        <span className="warn-short">{warnings.length}</span>
                      </button>
                    )}
                  </div>
                  <div className="hero-title">
                    <h1>{result.normalizedQuery}</h1>
                    <button type="button" className="icon-button ghost" aria-label={t("copyDomain")} title={t("copyDomain")} onClick={() => copyValue(result.normalizedQuery)}>
                      <CopyIcon size={16} />
                    </button>
                  </div>
                </div>

                <div className="hero-actions">
                  <section className="action-bar" aria-label="Result actions">
                    <button type="button" className="btn action-btn" onClick={shareResult}>
                      <LinkIcon size={15} className="btn-icon" />
                      {t("share")}
                    </button>
                    <button type="button" className="btn action-btn" onClick={() => copy(rawText(result), t("copied"))}>
                      <FileIcon size={15} className="btn-icon" />
                      {t("copyRaw")}
                    </button>
                    <button type="button" className="btn action-btn" onClick={downloadResult}>
                      <DownloadIcon size={15} className="btn-icon" />
                      {t("downloadJson")}
                    </button>
                    <div className="share-menu">
                      <button type="button" className="btn action-btn" aria-expanded={shareMenuOpen} onClick={() => setShareMenuOpen((open) => !open)}>
                        <ImageIcon size={15} className="btn-icon" />
                        {t("shareImage")}
                      </button>
                      {shareMenuOpen && (
                        <div className="share-menu-panel">
                          <button type="button" onClick={() => { setShareMenuOpen(false); void downloadOGImage(); }}>{t("downloadImage")}</button>
                          <a href={ogImageURL} target="_blank" rel="noreferrer" onClick={() => setShareMenuOpen(false)}>{t("openImage")}</a>
                          <button type="button" onClick={() => { setShareMenuOpen(false); void copy(result.normalizedQuery, t("copied")); }}>{t("copyQuery")}</button>
                        </div>
                      )}
                    </div>
                  </section>
                </div>

                <div className="mobile-tabs result-tabs" role="tablist" aria-label={t("resultSections")}>
                  {(["overview", ...lowerTabs] as SectionTab[]).map((id) => (
                    <TabButton key={id} id={id} active={activeMobile === id} label={mobileTabLabel(id)} dot={id === "source" && warnings.length > 0} onSelect={selectTab} />
                  ))}
                </div>

                <div className="result-section hero-overview" id="section-overview" data-section="overview" data-active="true" data-mobile-active={activeMobile === "overview"}>
                  {isDomain && result.status === "unregistered" ? (
                    <p className="available-note">{t("availableHint")}</p>
                  ) : isDomain ? (
                    <DomainMetrics result={result} />
                  ) : (
                    <NetworkMetrics result={result} />
                  )}
                  {isDomain && result.status !== "unregistered" ? <LockBar result={result} /> : <StatusList result={result} />}
                  <p className="hero-meta-line">
                    {result.registry?.name && (
                      <span>
                        {t("registryLabel")} <strong>{result.registry.name}</strong>
                      </span>
                    )}
                    <span>{usedSources.map(sourceName).join(" + ")}</span>
                    <span>
                      {t("elapsed")} <strong className="mono">{elapsed} ms</strong>
                    </span>
                  </p>
                  {warnings.length > 0 && (
                    <button type="button" className="warn-banner" onClick={goSources}>
                      <WarnIcon size={15} />
                      <strong>{warningText}</strong>
                      <span className="spacer" />
                      <span>{t("viewSources")} ›</span>
                    </button>
                  )}
                </div>
              </section>

              <div className="result-lower" data-kind={isDomain ? "domain" : "network"}>
                <div className="lower-tabs result-tabs" role="tablist" aria-label={t("resultSections")}>
                  {lowerTabs.map((id) => {
                    const info = lowerTabLabel(id);
                    return <TabButton key={id} id={id} active={activeLower === id} label={info.label} meta={info.meta} dot={info.dot} onSelect={selectTab} />;
                  })}
                  <span className="spacer" />
                  <span className="lower-tabs-extra">{lowerExtra}</span>
                </div>
                <div className="lower-col">
                  {isDomain ? (
                    <>
                      {section("dns", <DNSSection result={result} pending={dnsPending} loadingError={enrichmentError} onCopy={copyValue} />)}
                      {section("price", <PriceSection result={result} pending={pricingPending} loadingError={enrichmentError} />)}
                    </>
                  ) : (
                    section("network", <NetworkSection result={result} />)
                  )}
                </div>
                <div className="lower-col">
                  {section(
                    "owner",
                    <RegistrantSection
                      result={result}
                      aiLoading={aiState.loading && aiState.identity === currentAIIdentity}
                      aiError={aiState.identity === currentAIIdentity ? aiState.error : undefined}
                      icpDomain={isDomain ? icpDomain : undefined}
                      icpState={icpState}
                      onICPLookup={() => void runICPLookup()}
                      onCopy={copyValue}
                    />,
                  )}
                  {/* Raw evidence (rawWhois / rawRdap) and request diagnostics live in the sources section and the raw drawer. */}
                  {section("source", <SourcesSection result={result} warnings={warnings} onOpenRaw={(next) => setRawTab(next)} />)}
                </div>
              </div>
            </>
          )}
        </section>

        <footer className="lookup-footer">
          <span className="shortcut-hint">
            {t("keys")}
            <span><kbd>/</kbd> {t("shortcutSearch")}</span>
            <span><kbd>C</kbd> {t("share")}</span>
            <span><kbd>R</kbd> {t("copyRaw")}</span>
            <span><kbd>J</kbd> {t("downloadJson")}</span>
            <span><kbd>O</kbd> {t("shareImage")}</span>
          </span>
          <span>Whoice v{packageInfo.version}</span>
        </footer>

        <div className={`toast tool-action-state ${actionState ? "is-on" : ""}`} role="status" aria-live="polite">
          {actionState}
        </div>

        {result && rawTab && (
          <RawDrawer result={result} tab={rawTab} onTabChange={setRawTab} onClose={() => setRawTab(null)} onCopy={copyValue} pageQuery={state.query} />
        )}
      </main>
    </>
  );
}

