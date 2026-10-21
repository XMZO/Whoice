import Head from "next/head";
import Link from "next/link";
import type { GetServerSideProps } from "next";
import { useRouter } from "next/router";
import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import packageInfo from "../../package.json";
import { AppControls } from "@/components/AppControls";
import { BrandMark } from "@/components/BrandMark";
import { BanIcon, CheckCircleIcon, CopyIcon, HelpIcon, DownloadIcon, ExternalIcon, FileIcon, LinkIcon, SearchIcon, WarnIcon } from "@/components/Icons";
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
  CurrencyToggle,
  TRUNCATED,
  TRUNCATED_DETAIL,
  pricingSummary,
  registrantFieldCount,
  Skel,
  type ICPState,
} from "@/components/ResultSections";
import { analyzeRegistration, appendLookupOptions, enrichLookup, getCapabilities, lookupICP, lookupStream, normalizeLookupInput, type LookupOptions } from "@/lib/api";
import { writeHistory } from "@/lib/history";
import { useI18n, type I18nKey } from "@/lib/i18n";
import { diagnostic } from "@/lib/diagnostic";
import { kindLabel, sourceName, sourceTag } from "@/lib/resultModel";
import { t3, useT3, type T3 } from "@/lib/t3";
import type { APIResponse, LookupResult, QueryType } from "@/lib/types";

type SectionTab = "overview" | "dns" | "owner" | "price" | "source" | "network";


type Props = {
  query: string;
  /** True when the page was served without a result; the browser streams it. */
  pending: boolean;
  response: APIResponse;
  httpStatus: number;
  sourceMode: SourceMode;
  options: LookupOptions;
  icpAutoQuery: boolean;
};

type SourceMode = "all" | "rdap" | "whois";

type LookupState = {
  query: string;
  /** Waiting for the final result; response.result may hold a preview. */
  pending: boolean;
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
  title: T3;
  message: T3;
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
        pending: false,
        httpStatus: 400,
        sourceMode,
        options: serializableOptions,
        icpAutoQuery,
        response: {
          ok: false,
          error: { code: "query_required", message: diagnostic("Query is required.") },
        },
      },
    };
  }

  // The lookup itself runs in the browser as a stream, so navigation is
  // instant and the first source to answer is shown right away.
  return { props: { query, pending: true, httpStatus: 200, response: { ok: true }, sourceMode, options: serializableOptions, icpAutoQuery } };
};

function isDNSWarning(warning: string) {
  return warning.startsWith("DNS ") || warning.startsWith("Registry/WHOIS nameservers differ");
}

// Parser notes about a single provider's reply; the provider row already shows them.
function isProviderWarning(warning: string) {
  return /^(RDAP returned HTTP \d+|empty (RDAP|WHOIS) response|invalid RDAP JSON)$/.test(warning);
}

function rawText(result: LookupResult) {
  return [result.raw.whois, result.raw.whoisWeb, result.raw.rdap, result.raw.dns].filter(Boolean).join("\n\n");
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

const GATEWAY_ERROR: { title: T3; message: T3 } = {
  title: t3("Lookup API unavailable", "查询 API 不可用", "查詢 API 無法使用"),
  message: t3(
    "Whoice could not reach the lookup API or received a gateway error page instead of JSON.",
    "无法连接查询 API，或收到了网关错误页而不是 JSON。",
    "無法連線查詢 API，或收到了閘道錯誤頁而不是 JSON。",
  ),
};

// Titles for API error codes; the raw API message is shown underneath as a diagnostic.
const ERROR_TITLES: Record<string, T3> = {
  query_required: t3("Enter something to look up", "请输入查询内容", "請輸入查詢內容"),
  invalid_query: t3("This query is not a domain, IP, CIDR, or ASN", "无法识别的查询内容", "無法辨識的查詢內容"),
  invalid_domain: t3("This domain name is not valid", "域名格式无效", "網域格式無效"),
  option_not_allowed: t3("Custom servers are not allowed on this instance", "此实例不允许自定义服务器", "此實例不允許自訂伺服器"),
  rate_limited: t3("Too many lookups, try again shortly", "查询过于频繁，请稍后再试", "查詢過於頻繁，請稍後再試"),
  unauthorized: t3("Sign-in is required for lookups", "查询需要登录", "查詢需要登入"),
  ip_not_allowed: t3("Your address is not allowed to use the API", "当前地址不允许使用 API", "目前位址不允許使用 API"),
  api_disabled: t3("The lookup API is disabled", "查询 API 已关闭", "查詢 API 已關閉"),
  api_endpoint_disabled: t3("The lookup API is disabled", "查询 API 已关闭", "查詢 API 已關閉"),
  service_unavailable: t3("The lookup service is not ready", "查询服务尚未就绪", "查詢服務尚未就緒"),
};

// Explanations for errors caused by the input itself; other errors get the
// generic source/API hint.
const INPUT_HINT = t3(
  "Check the spelling. Enter a domain (example.com), an IP address, a CIDR range, or an ASN (AS13335).",
  "请检查拼写。可以输入域名（example.com）、IP 地址、CIDR 网段或 ASN（AS13335）。",
  "請檢查拼寫。可以輸入網域（example.com）、IP 位址、CIDR 網段或 ASN（AS13335）。",
);

const ERROR_MESSAGES: Record<string, T3> = {
  query_required: INPUT_HINT,
  invalid_query: INPUT_HINT,
  invalid_domain: INPUT_HINT,
  rate_limited: t3("Wait for the rate-limit window to reset, then search again.", "请等待限流窗口重置后再查询。", "請等待限流視窗重置後再查詢。"),
};

const GENERIC_ERROR: { title: T3; message: T3 } = {
  title: t3("Lookup failed", "查询失败", "查詢失敗"),
  message: t3("Switch source mode or check whether the lookup API is running.", "可以切换数据来源，或检查查询 API 是否在运行。", "可以切換資料來源，或檢查查詢 API 是否在執行。"),
};

function errorView(response: APIResponse, status: number): ErrorViewModel {
  const code = response.error?.code || "";
  const message = response.error?.message || "";
  if (status === 502 || code === "api_unreachable" || code === "invalid_json_response" || code === "html_error_response") {
    return { eyebrow: `HTTP ${status || 502}`, ...GATEWAY_ERROR, detail: message };
  }
  return {
    eyebrow: status ? `HTTP ${status}` : code,
    title: ERROR_TITLES[code] || GENERIC_ERROR.title,
    message: ERROR_MESSAGES[code] || GENERIC_ERROR.message,
    detail: [code, message].filter(Boolean).join(": "),
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

// Each status has its own hue and icon so it reads at a glance:
// unregistered = green check (free), registered = blue dot (taken, plain fact),
// reserved = red slash (cannot be registered), unknown = grey question.
function StatusBadge({ status }: { status: string }) {
  const { t } = useI18n();
  const icon =
    status === "unregistered" ? (
      <CheckCircleIcon size={14} />
    ) : status === "registered" ? (
      <span className="status-badge-dot" aria-hidden="true" />
    ) : status === "reserved" ? (
      <BanIcon size={14} />
    ) : status === "error" ? (
      <WarnIcon size={13} />
    ) : (
      <HelpIcon size={14} />
    );
  return (
    <span className={`status-badge status-badge-${statusLabelKey[status] ? status : "unknown"}`}>
      {icon}
      {t(statusLabelKey[status] || "statusUnknown")}
    </span>
  );
}

// Registry lifecycle stage worth a badge. Per RFC 3915 a domain in redemption
// carries redemptionPeriod (with pendingDelete); pendingDelete alone means the
// redemption window is over and the registry is about to release the name.
function lifecycleStage(statuses: LookupResult["statuses"] | undefined): "redemption" | "pendingDelete" | null {
  const codes = new Set((Array.isArray(statuses) ? statuses : []).map((status) => (status.label || status.code || "").toLowerCase().replace(/^.*#/, "").replace(/[\s_-]/g, "")));
  if (codes.has("redemptionperiod")) return "redemption";
  if (codes.has("pendingdelete")) return "pendingDelete";
  return null;
}

function MarketTags({ result }: { result: LookupResult }) {
  const pick = useT3();
  const sale = result.enrichment?.forSale;
  const stage = lifecycleStage(result.statuses);
  return (
    <>
      {sale && (
        <span
          className="pill pill-accent"
          title={pick(
            t3(
              `Every nameserver points to ${sale.market}'s for-sale page: the owner has it listed there. Price and availability are on ${sale.market}.`,
              `全部域名服务器指向 ${sale.market} 的出售页，持有人已在该平台挂牌出售；价格和能否购买以平台为准`,
              `全部網域伺服器指向 ${sale.market} 的出售頁，持有人已在該平台掛牌出售；價格和能否購買以平台為準`,
            ),
          )}
        >
          {pick(t3(`For sale · ${sale.market}`, `出售中 · ${sale.market}`, `出售中 · ${sale.market}`))}
        </span>
      )}
      {stage === "redemption" && (
        <span
          className="pill pill-red"
          title={pick(
            t3(
              "Expired and deleted by the registrar (registry status redemptionPeriod); the previous owner can still restore it before it is released.",
              "已过期并被注册商删除（注册局状态 redemptionPeriod），原持有人仍可赎回；期满后进入待删除",
              "已過期並被註冊商刪除（註冊局狀態 redemptionPeriod），原持有人仍可贖回；期滿後進入待刪除",
            ),
          )}
        >
          {pick(t3("Redemption period", "赎回期", "贖回期"))}
        </span>
      )}
      {stage === "pendingDelete" && (
        <span
          className="pill pill-red"
          title={pick(
            t3(
              "The registry is about to delete this name (status pendingDelete, usually within 5 days); it can then be registered again.",
              "注册局即将删除此域名（状态 pendingDelete，通常在 5 天内），删除后可重新注册",
              "註冊局即將刪除此網域（狀態 pendingDelete，通常在 5 天內），刪除後可重新註冊",
            ),
          )}
        >
          {pick(t3("Pending delete", "待删除", "待刪除"))}
        </span>
      )}
    </>
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

// Stand-in result rendered while the first source is still on its way: the
// page shows the real result layout (tabs, cards, panels) at once and every
// field fills in place as sources answer, so nothing jumps.
function placeholderResult(query: string): LookupResult {
  const value = normalizeLookupInput(query);
  const type: QueryType = /^as\d+$/i.test(value)
    ? "asn"
    : value.includes("/")
      ? "cidr"
      : value.includes(":")
        ? "ipv6"
        : /^\d{1,3}(\.\d{1,3}){3}$/.test(value)
          ? "ipv4"
          : "domain";
  return {
    query: value,
    normalizedQuery: value,
    type,
    status: "unknown",
    source: { used: [], errors: [] },
    domain: { name: type === "domain" ? value : undefined, reserved: false, registered: false },
    registry: {},
    registrar: {},
    dates: {},
    statuses: [],
    nameservers: [],
    dnssec: {},
    registrant: {},
    network: {},
    enrichment: {},
    raw: {},
    meta: { elapsedMs: 0, providers: [] },
  } as LookupResult;
}

function LookupErrorPanel({ response, status, onRetry }: { response: APIResponse; status: number; onRetry?: () => void }) {
  const { t } = useI18n();
  const pick = useT3();
  const view = errorView(response, status);
  return (
    <section className="error-panel">
      <span className="status-badge status-badge-error">
        <WarnIcon size={13} />
        {view.eyebrow}
      </span>
      <h1>{pick(view.title)}</h1>
      <p className="muted">{pick(view.message)}</p>
      {view.detail && <pre className="error-detail">{view.detail}</pre>}
      {onRetry && (
        <button type="button" className="btn btn-primary" onClick={onRetry}>
          {t("retry")}
        </button>
      )}
    </section>
  );
}


export default function LookupPage({ query, pending, response, httpStatus, sourceMode, options, icpAutoQuery }: Props) {
  const router = useRouter();
  const [state, setState] = useState<LookupState>({ query, pending, response, httpStatus, sourceMode, options, nonce: 0 });
  const [searchValue, setSearchValue] = useState(query);
  const [isLoading, setIsLoading] = useState(false);
  const handledURLRef = useRef(pending ? "" : lookupUrl(query, sourceMode, options));
  const inflightURLRef = useRef("");
  const lookupAbortRef = useRef<AbortController | null>(null);
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
  const [icpState, setICPState] = useState<ICPState>({ domain: "", loading: false, requested: false });
  const [aiState, setAIState] = useState<AIState>({ key: "", loading: false, requested: false });
  const [enrichmentState, setEnrichmentState] = useState<EnrichmentState>({ key: "", loading: false, requested: false });
  const { t, tf, locale } = useI18n();
  const pick = useT3();
  const [tab, setTab] = useState<SectionTab>("overview");
  const [rawTab, setRawTab] = useState<RawTab | null>(null);
  const pageURL = useMemo(() => lookupUrl(state.query, state.sourceMode, state.options), [state.options, state.query, state.sourceMode]);
  const absolutePageURL = typeof window === "undefined" ? pageURL : window.location.href;
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
  // Each warning is shown once, next to what it is about: DNS warnings in the
  // DNS card, provider failures in their source row, the rest under sources.
  // RDAP/WHOIS servers fail often; while another source answered, a failed one
  // only greys out its row instead of raising a warning.
  const dnsWarnings = metaWarnings.filter(isDNSWarning);
  const providers = result?.meta?.providers || [];
  const quietProviders = providers.some((provider) => provider.status === "ok" && provider.source !== "dns");
  const failedProviders = new Set(providers.filter((provider) => provider.status === "error").map((provider) => provider.source));
  const loudMetaWarnings = metaWarnings.filter((warning) => !(quietProviders && isProviderWarning(warning)));
  const loudSourceErrors = sourceErrors.filter((error) => !(quietProviders && failedProviders.has(error.source)));
  const warnings = [
    ...(enrichmentError ? [`enrichment: ${enrichmentError}`] : []),
    ...loudMetaWarnings,
    ...loudSourceErrors.map((error) => `${error.source}: ${error.error}`),
  ];
  const sourceWarnings = [
    ...(enrichmentError ? [`enrichment: ${enrichmentError}`] : []),
    ...loudMetaWarnings.filter((warning) => !isDNSWarning(warning)),
    ...sourceErrors.filter((error) => !failedProviders.has(error.source)).map((error) => `${error.source}: ${error.error}`),
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
    if (pending) {
      void runLookup(query, sourceMode, options, false);
      return;
    }
    setState((current) => ({
      query,
      pending: false,
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
  }, [httpStatus, options, pending, query, response, router.asPath, router.isReady, sourceMode]);

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
    if (!aiArmedRef.current || state.pending) return;
    if (!parseBool(state.options.ai) || !result || result.type !== "domain") return;
    const key = aiRequestKey(result, state.nonce);
    if (!key || aiState.key !== key || aiState.requested || aiState.loading) return;
    aiArmedRef.current = false;
    void runAIAnalysis(result, key, state.nonce);
  }, [aiState.key, aiState.loading, aiState.requested, result, state.nonce, state.options.ai, state.pending]);

  useEffect(() => {
    if (state.pending || !result?.meta?.pendingEnrichments?.length) return;
    const key = enrichmentRequestKey(result, state.nonce);
    if (!key || enrichmentState.key !== key || enrichmentState.loading || enrichmentState.requested) return;
    void runDeferredEnrichment(result, key);
  }, [enrichmentState.key, enrichmentState.loading, enrichmentState.requested, result, state.nonce, state.pending]);

  useEffect(() => {
    if (!router.isReady) return;
    const next = lookupParamsFromPath(router.asPath);
    if (!next.query) return;
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
      if (rawTab) return;
      if (event.key === "/") {
        event.preventDefault();
        document.getElementById("lookup-mini-search")?.focus();
      }
      if (!result) return;
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
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [absolutePageURL, rawTab, result, t]);

  async function runLookup(nextQuery: string, nextSourceMode = state.sourceMode, nextOptions = state.options, updateURL = true, armAI = true, force = false) {
    const trimmed = normalizeLookupInput(nextQuery);
    if (!trimmed) return;
    const requestOptions = {
      ...nextOptions,
      rdap: nextSourceMode === "rdap" ? "1" : undefined,
      whois: nextSourceMode === "whois" ? "1" : undefined,
    };
    const serializableOptions = cleanOptions(requestOptions);
    const nextURL = lookupUrl(trimmed, nextSourceMode, serializableOptions);
    // Automatic triggers skip a duplicate of the lookup in flight; an explicit
    // submit always restarts it. Either way a new lookup replaces the old one.
    if (!force && inflightURLRef.current === nextURL) return;
    lookupAbortRef.current?.abort();
    const controller = new AbortController();
    lookupAbortRef.current = controller;
    inflightURLRef.current = nextURL;
    handledURLRef.current = nextURL;
    aiArmedRef.current = armAI && parseBool(serializableOptions.ai);
    const nonce = Date.now();
    const settle = (next: Pick<LookupState, "response" | "httpStatus">) =>
      setState((current) => (current.nonce === nonce ? { ...current, ...next, pending: false } : current));
    setIsLoading(true);
    setAIState({ key: "", loading: false, requested: false });
    setEnrichmentState({ key: "", loading: false, requested: false });
    setState({ query: trimmed, pending: true, response: { ok: true }, httpStatus: 200, sourceMode: nextSourceMode, options: serializableOptions, nonce });
    setSearchValue(trimmed);
    if (updateURL && typeof window !== "undefined") {
      void router.push(nextURL, undefined, { shallow: true, scroll: false });
    }
    try {
      const { status, body } = await lookupStream(
        trimmed,
        requestOptions,
        (preview) => {
          if (controller.signal.aborted) return;
          setState((current) => (current.nonce === nonce && current.pending ? { ...current, response: { ok: true, result: preview } } : current));
        },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      settle({ response: body, httpStatus: status });
      if (body.ok) {
        writeHistory(trimmed);
      }
    } catch (error) {
      if (controller.signal.aborted) return;
      aiArmedRef.current = false;
      settle({
        httpStatus: 502,
        response: {
          ok: false,
          error: {
            code: "api_unreachable",
            message: error instanceof Error ? error.message : diagnostic("Lookup API is unreachable."),
          },
        },
      });
    } finally {
      if (lookupAbortRef.current === controller) {
        lookupAbortRef.current = null;
        inflightURLRef.current = "";
        setIsLoading(false);
      }
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
    // Drop focus so the on-screen keyboard closes and the result is visible.
    (document.activeElement as HTMLElement | null)?.blur();
    void runLookup(searchValue, state.sourceMode, state.options, true, true, true);
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

  // Until the first source answers, the page renders the result layout around a
  // placeholder so tabs and panels are there at once and stay put.
  const skeleton = state.pending && !result;
  const view = result || (skeleton ? placeholderResult(state.query) : undefined);
  const expectedSources: string[] = state.sourceMode === "rdap" ? ["rdap"] : state.sourceMode === "whois" ? ["whois"] : ["rdap", "whois"];
  const answeredSources = new Set((view?.meta?.providers || []).map((provider) => provider.source));
  const pendingSources = state.pending ? expectedSources.filter((source) => !answeredSources.has(source as never)) : [];
  const truncatedSources = (view?.meta?.providers || []).filter((provider) => provider.status === "stopped").map((provider) => provider.source);
  const isDomain = view?.type === "domain";
  const lowerTabs: SectionTab[] = isDomain ? ["dns", "owner", "price", "source"] : ["network", "owner", "source"];
  const activeLower: SectionTab = lowerTabs.includes(tab) ? tab : lowerTabs[0];
  const activeMobile: SectionTab = tab === "overview" || lowerTabs.includes(tab) ? tab : "overview";
  const copyValue = (value: string) => void copy(value, t("copied"));
  const usedSources = Array.isArray(view?.source?.used) ? view.source.used : [];
  const elapsed = view?.meta?.elapsedMs ?? 0;
  const warningText = warnings.length === 1 ? t("warningOne") : tf("warningMany", { n: warnings.length });
  const ownerFields = view ? registrantFieldCount(view) : 0;
  const ownerSources = view
    ? Array.from(new Set(Object.values(view.registrant?.fieldSources || {}).flat().map((item) => sourceTag(item.source)).filter(Boolean)))
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
    if (!view) return { label: id };
    switch (id) {
      case "dns":
        return { label: t("dns"), meta: view.enrichment?.dns?.elapsedMs !== undefined ? `${view.enrichment.dns.elapsedMs} ms` : undefined };
      case "owner":
        return { label: t("registrant"), meta: ownerFields ? tf("fieldsShort", { n: ownerFields }) : undefined };
      case "price":
        return { label: t("priceScore"), meta: pricingSummary(view, locale) };
      case "network":
        return { label: t("networkInfo") };
      default:
        return { label: t("sourcesShort"), meta: `${elapsed} ms`, dot: warnings.length > 0 };
    }
  };

  const mobileTabLabel = (id: SectionTab) =>
    id === "overview" ? t("tabOverview") : id === "dns" ? t("tabDns") : id === "owner" ? t("tabOwner") : id === "price" ? t("tabPrice") : id === "network" ? t("network") : t("tabSource");

  const lowerExtra = (() => {
    if (!view) return null;
    if (activeLower === "dns" && view.enrichment?.dnsviz?.url) return <DNSVizLink url={view.enrichment.dnsviz.url} />;
    if (activeLower === "price" && view.enrichment?.pricing?.fx) return <CurrencyToggle fx={view.enrichment.pricing.fx} />;
    if (activeLower === "owner" && ownerSources.length) {
      return (
        <span className="source-caption">
          {t("source")}
          <SourceTags sources={ownerSources} />
        </span>
      );
    }
    if (activeLower === "source" && view.source?.primary) {
      const others = usedSources.filter((source) => source !== view.source.primary).map(sourceName);
      return (
        <span className="section-meta">
          {sourceName(view.source.primary)} {t("primarySource")}
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
                onKeyDown={(event) => {
                  // Mobile keyboards turn Enter into "next" when another form
                  // field (the source select) follows, so submit explicitly.
                  if (event.key === "Enter" && !event.nativeEvent.isComposing) {
                    event.preventDefault();
                    event.currentTarget.form?.requestSubmit();
                  }
                }}
                aria-label={t("searchQuery")}
                autoComplete="off"
                autoCapitalize="none"
                autoCorrect="off"
                enterKeyHint="search"
                spellCheck={false}
              />
              <select className="source-select" aria-label={t("source")} value={state.sourceMode} onChange={(event) => switchSource(event.target.value as SourceMode)}>
                <option value="all">{t("all")}</option>
                <option value="rdap">RDAP</option>
                <option value="whois">WHOIS</option>
              </select>
              <button type="submit">{isLoading ? t("searching") : t("search")}</button>
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
          {!state.response.ok || !view ? (
            <LookupErrorPanel response={state.response} status={state.httpStatus} onRetry={state.query ? () => void runLookup(state.query, state.sourceMode, state.options, false, true, true) : undefined} />
          ) : (
            <>
              <section className={`status-strip result-hero${skeleton ? " lookup-pending" : ""}`} data-tab={activeMobile} aria-label={view.normalizedQuery}>
                <div className="hero-head">
                  <div className="hero-badges">
                    {skeleton ? (
                      <span className="status-badge status-badge-unknown pulse" role="status">
                        <span className="status-badge-dot" aria-hidden="true" />
                        {t("searching")}
                      </span>
                    ) : (
                      <StatusBadge status={view.status} />
                    )}
                    {truncatedSources.length > 0 && (
                      <span className="pill pill-amber" title={`${truncatedSources.map(sourceName).join(" · ")}: ${pick(TRUNCATED_DETAIL)}`}>
                        {pick(TRUNCATED)} · {truncatedSources.map(sourceName).join(" · ")}
                      </span>
                    )}
                    <MarketTags result={view} />
                    {state.pending && (
                      <span className="pill pill-amber pulse" role="status" title={pendingSources.map(sourceName).join(" · ")}>
                        {skeleton ? "" : `${pick(t3("Updating", "正在补全", "正在補全"))} · `}
                        {pendingSources.map(sourceName).join(" · ")}
                      </span>
                    )}
                    <span className="type-tag">{kindLabel(view.type, t)}</span>
                    {view.registry?.name && (
                      <span className="hero-meta">
                        {t("registryLabel")} {view.registry.name}
                      </span>
                    )}
                    {!skeleton && (
                      <span className="hero-meta">
                        {usedSources.map(sourceName).join(" + ") || sourceName(view.source?.primary)} · <span className="mono">{elapsed} ms</span>
                      </span>
                    )}
                    {warnings.length > 0 && (
                      <button type="button" className="warn-pill" onClick={goSources} aria-label={`${warningText}, ${t("viewSources")}`}>
                        <WarnIcon size={13} />
                        <span className="warn-long">{warningText}</span>
                        <span className="warn-short">{warnings.length}</span>
                      </button>
                    )}
                  </div>
                  <div className="hero-title">
                    <h1>
                      {isDomain ? (
                        <a className="hero-domain-link" href={`https://${view.normalizedQuery}`} target="_blank" rel="noopener noreferrer" title={pick(t3("Open the website in a new tab", "在新标签页打开网站", "在新分頁開啟網站"))}>
                          {view.normalizedQuery}
                          <ExternalIcon size={16} className="hero-domain-icon" />
                        </a>
                      ) : (
                        view.normalizedQuery
                      )}
                    </h1>
                    <button type="button" className="icon-button ghost" aria-label={t("copyDomain")} title={t("copyDomain")} onClick={() => copyValue(view.normalizedQuery)}>
                      <CopyIcon size={16} />
                    </button>
                  </div>
                </div>

                <div className="hero-actions">
                  <section className="action-bar" aria-label={pick(t3("Result actions", "结果操作", "結果操作"))}>
                    <button type="button" className="btn action-btn" disabled={skeleton} onClick={shareResult}>
                      <LinkIcon size={15} className="btn-icon" />
                      {t("share")}
                    </button>
                    <button type="button" className="btn action-btn" disabled={skeleton} onClick={() => copy(rawText(view), t("copied"))}>
                      <FileIcon size={15} className="btn-icon" />
                      {t("copyRaw")}
                    </button>
                    <button type="button" className="btn action-btn" disabled={skeleton} onClick={downloadResult}>
                      <DownloadIcon size={15} className="btn-icon" />
                      {t("downloadJson")}
                    </button>
                  </section>
                </div>

                <div className="mobile-tabs result-tabs" role="tablist" aria-label={t("resultSections")}>
                  {(["overview", ...lowerTabs] as SectionTab[]).map((id) => (
                    <TabButton key={id} id={id} active={activeMobile === id} label={mobileTabLabel(id)} dot={id === "source" && warnings.length > 0} onSelect={selectTab} />
                  ))}
                </div>

                <div className="result-section hero-overview" id="section-overview" data-section="overview" data-active="true" data-mobile-active={activeMobile === "overview"}>
                  {isDomain && view.status === "unregistered" ? (
                    <p className="available-note">{t("availableHint")}</p>
                  ) : isDomain ? (
                    <DomainMetrics result={view} pending={state.pending} />
                  ) : (
                    <NetworkMetrics result={view} pending={state.pending} />
                  )}
                  {isDomain && view.status !== "unregistered" ? <LockBar result={view} pending={state.pending} /> : <StatusList result={view} />}
                  <p className="hero-meta-line">
                    {view.registry?.name && (
                      <span>
                        {t("registryLabel")} <strong>{view.registry.name}</strong>
                      </span>
                    )}
                    <span>{usedSources.map(sourceName).join(" + ")}</span>
                    <span>
                      {t("elapsed")} {skeleton ? <Skel width="3em" /> : <strong className="mono">{elapsed} ms</strong>}
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
                      {section("dns", <DNSSection result={view} pending={dnsPending || (state.pending && !view.enrichment?.dns)} loadingError={enrichmentError} notes={dnsWarnings} onCopy={copyValue} />)}
                      {section("price", <PriceSection result={view} pending={pricingPending || (state.pending && !view.enrichment?.pricing)} loadingError={enrichmentError} />)}
                    </>
                  ) : (
                    section("network", <NetworkSection result={view} />)
                  )}
                </div>
                <div className="lower-col">
                  {section(
                    "owner",
                    <RegistrantSection
                      result={view}
                      pending={state.pending}
                      aiLoading={aiState.loading && aiState.identity === currentAIIdentity}
                      aiError={aiState.identity === currentAIIdentity ? aiState.error : undefined}
                      icpDomain={isDomain ? icpDomain || view.normalizedQuery : undefined}
                      icpState={icpState}
                      onICPLookup={() => void runICPLookup(icpDomain || view.normalizedQuery)}
                      onCopy={copyValue}
                    />,
                  )}
                  {/* Raw evidence (rawWhois / rawRdap) and request diagnostics live in the sources section and the raw drawer. */}
                  {section("source", <SourcesSection result={view} warnings={sourceWarnings} pendingSources={pendingSources} onOpenRaw={(next) => setRawTab(next)} />)}
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

