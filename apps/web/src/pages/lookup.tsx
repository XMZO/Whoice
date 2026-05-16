import Head from "next/head";
import Link from "next/link";
import type { GetServerSideProps } from "next";
import { useRouter } from "next/router";
import { FormEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { AppControls } from "@/components/AppControls";
import { analyzeRegistration, appendLookupOptions, enrichLookup, getAPIBase, getCapabilities, lookup, lookupICP, normalizeLookupInput, type LookupOptions } from "@/lib/api";
import { writeHistory } from "@/lib/history";
import { useI18n } from "@/lib/i18n";
import { renderResultPlugins } from "@/lib/resultPlugins";
import type { APIResponse, ICPResult, LookupResult } from "@/lib/types";

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

type ICPState = {
  domain: string;
  loading: boolean;
  requested: boolean;
  httpStatus?: number;
  result?: ICPResult;
  errorCode?: string;
  error?: string;
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

function Row({ label, value }: { label: string; value?: ReactNode }) {
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

function SourceHint({
  source,
  confidence,
  evidence,
  value,
}: {
  source?: string;
  confidence?: number;
  evidence?: string;
  value?: string;
}) {
  if (!source && confidence === undefined && !evidence) return null;
  const isAI = source?.startsWith("ai");
  const label = isAI ? "AI" : source;
  const parts = [
    source,
    value ? `value: ${value}` : "",
    confidence !== undefined ? `confidence ${Math.round(confidence * 100)}%` : "",
    evidence ? `evidence: ${evidence}` : "",
  ].filter(Boolean);
  return (
    <span className={isAI ? "source-hint ai-source" : "source-hint"} title={parts.join("\n")}>
      {label}
      {confidence !== undefined ? ` ${Math.round(confidence * 100)}%` : ""}
    </span>
  );
}

type RegistrationSource = NonNullable<LookupResult["registrant"]["extra"]>[number];

function RegistrationSourceBadges({ sources }: { sources?: RegistrationSource[] }) {
  const values = Array.isArray(sources) ? sources.filter((source) => source.source || source.confidence !== undefined || source.evidence || source.value) : [];
  if (!values.length) return null;
  return (
    <div className="registration-source-list">
      {values.map((source, index) => (
        <details className="source-popover" key={`${source.source || "source"}-${source.value || ""}-${index}`}>
          <summary className={source.source?.startsWith("ai") ? "source-hint ai-source" : "source-hint"}>
            {sourceLabel(source.source)}
            {source.confidence !== undefined ? ` ${Math.round(source.confidence * 100)}%` : ""}
          </summary>
          <span className="source-popover-body">
            {source.value && <span><strong>Value</strong>{source.value}</span>}
            {source.source && <span><strong>Source</strong>{source.source}</span>}
            {source.confidence !== undefined && <span><strong>Confidence</strong>{Math.round(source.confidence * 100)}%</span>}
            {source.evidence && <span><strong>Evidence</strong>{source.evidence}</span>}
          </span>
        </details>
      ))}
    </div>
  );
}

function sourceLabel(source?: string) {
  if (!source) return "Source";
  if (source.startsWith("ai")) return "AI";
  if (source === "whois") return "WHOIS";
  if (source === "rdap") return "RDAP";
  if (source === "whoisWeb") return "Web";
  return source;
}

function RawBlock({ title, value }: { title: string; value?: string }) {
  if (!value) return null;
  return (
    <details className="panel raw-panel">
      <summary className="panel-summary">
        <h2>{title}</h2>
        <span>{formatByteCount(value.length)}</span>
      </summary>
      <pre>{value}</pre>
    </details>
  );
}

function formatByteCount(value: number) {
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  if (value >= 1024) return `${Math.round(value / 1024)} KB`;
  return `${value} B`;
}

function hasNetwork(result: LookupResult) {
  return Boolean(result.network.range || result.network.cidr || result.network.name || result.network.type || result.network.originAS || result.network.country);
}

function hasRegistration(result: LookupResult) {
  const registrant = result.registrant || {};
  return Boolean(
    registrant.name ||
    registrant.organization ||
    registrant.country ||
    registrant.province ||
    registrant.city ||
    registrant.address ||
    registrant.postalCode ||
    registrant.email ||
    registrant.phone ||
    registrant.extra?.length
  );
}

function ActionValue({
  value,
  href,
  onCopy,
  displayValue,
  className,
}: {
  value?: string;
  href?: string;
  onCopy?: (value: string) => void;
  displayValue?: ReactNode;
  className?: string;
}) {
  const text = value?.trim();
  if (!text) return null;
  return (
    <span className={className ? `action-value ${className}` : "action-value"} title={displayValue ? text : undefined}>
      {href ? (
        <a href={href} target="_blank" rel="noreferrer">{displayValue || text}</a>
      ) : (
        <span>{displayValue || text}</span>
      )}
      {onCopy && (
        <button type="button" className="inline-copy" onClick={() => onCopy(text)} title="Copy" aria-label={`Copy ${text}`}>
          Copy
        </button>
      )}
    </span>
  );
}

function RegistrationValue({
  value,
  source,
  confidence,
  evidence,
  sources,
  onCopy,
}: {
  value?: string;
  source?: string;
  confidence?: number;
  evidence?: string;
  sources?: RegistrationSource[];
  onCopy?: (value: string) => void;
}) {
  const text = value?.trim();
  if (!text) return null;
  const fieldSources = sources?.length ? sources : source || confidence !== undefined || evidence ? [{ label: "", value: text, source, confidence, evidence }] : undefined;
  return (
    <div className="registration-value">
      <ActionValue value={text} onCopy={onCopy} />
      <RegistrationSourceBadges sources={fieldSources} />
    </div>
  );
}

function RegistrationRow({
  label,
  value,
  registrant,
  fieldKey,
  onCopy,
}: {
  label: string;
  value?: string;
  registrant: LookupResult["registrant"];
  fieldKey: string;
  onCopy?: (value: string) => void;
}) {
  if (!value?.trim()) return null;
  const sources = registrant.fieldSources?.[fieldKey];
  return (
    <Row
      label={label}
      value={
        <RegistrationValue
          value={value}
          source={registrant.source}
          confidence={registrant.confidence}
          evidence={registrant.evidence}
          sources={sources}
          onCopy={onCopy}
        />
      }
    />
  );
}

function externalDomainURL(value?: string) {
  const text = value?.trim();
  if (!text) return undefined;
  return `https://${text}`;
}

function safeExternalURL(value?: string) {
  const text = value?.trim();
  if (!text) return undefined;
  if (/^https?:\/\//i.test(text)) return text;
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?:\/.*)?$/i.test(text)) return `https://${text}`;
  return undefined;
}

function DNSPanel({ result, pending, onCopy }: { result: LookupResult; pending?: boolean; onCopy?: (value: string) => void }) {
  const { t } = useI18n();
  const dns = result.enrichment?.dns;
  const hasRecords = Boolean(dns?.cname || dns?.a?.length || dns?.aaaa?.length || dns?.mx?.length || dns?.ns?.length);
  const registryNs = dns?.registryNs?.length ? dns.registryNs : result.nameservers.map((ns) => ns.host).filter(Boolean);
  const liveNs = dns?.ns || [];
  const mergedNs = mergeNameserverValues(registryNs, liveNs);

  return (
    <section className="panel dns-panel">
      <div className="panel-head">
        <h2>{t("dns")}</h2>
        <div className="panel-status-slot">
          {pending && !dns ? <span className="source-hint ai-pending">loading</span> : <DNSResolverBadges resolvers={dns?.resolvers} />}
        </div>
      </div>
      <dl className="detail-list">
        <Row
          label={t("nameservers")}
          value={
            mergedNs.length ? (
              <NameserverBlock registryNs={registryNs} liveNs={liveNs} mismatch={dns?.nsMismatch} nameservers={result.nameservers} onCopy={onCopy} />
            ) : (
              <span className="muted">{t("noNameservers")}</span>
            )
          }
        />
        {pending && !dns ? (
          <DNSPendingRows />
        ) : hasRecords ? (
          <>
            <Row label="CNAME" value={dns?.cname} />
            <Row label="A" value={dns?.a?.length ? <DNSAddressGroup title="A" addresses={dns.a} /> : undefined} />
            <Row label="AAAA" value={dns?.aaaa?.length ? <DNSAddressGroup title="AAAA" addresses={dns.aaaa} /> : undefined} />
            <Row label="MX" value={dns?.mx?.length ? <DNSValueGroup title="MX" values={dns.mx.map((item) => `${item.pref} ${item.host}`)} /> : undefined} />
            <Row label="DNS ms" value={dns?.elapsedMs} />
          </>
        ) : (
          <Row label="Records" value={<span className="muted">{t("noDns")}</span>} />
        )}
      </dl>
    </section>
  );
}

function DNSPendingRows() {
  return (
    <>
      <Row label="Records" value={<span className="muted">DNS records are updating in the background.</span>} />
      <Row label="A" value={<PendingLine />} />
      <Row label="AAAA" value={<PendingLine />} />
      <Row label="MX" value={<PendingLine />} />
      <Row label="DNS ms" value={<PendingLine compact />} />
    </>
  );
}

function PendingLine({ compact }: { compact?: boolean }) {
  return <span className={compact ? "pending-line compact" : "pending-line"} aria-hidden="true" />;
}

function ICPPanel({
  domain,
  state,
  onLookup,
}: {
  domain?: string;
  state: ICPState;
  onLookup: () => void;
}) {
  if (!domain) return null;
  const records = state.result?.records || [];
  const found = state.result?.status === "found" && records.length > 0;
  const checked = state.requested && !state.loading;
  const notFound = state.result?.status === "not_found" && !state.error;
  const unavailable = Boolean(state.error);
  return (
    <section className="panel icp-panel">
      <div className="panel-head">
        <h2>ICP备案</h2>
        <button type="button" className="inline-action compact" onClick={onLookup} disabled={state.loading}>
          {state.loading ? "查询中" : checked ? "刷新" : "查询"}
        </button>
      </div>
      {!state.requested ? (
        <p className="muted">手动查询，不影响 WHOIS 结果。</p>
      ) : state.loading ? (
        <p className="muted">正在查询工信部备案信息</p>
      ) : unavailable ? (
        <p className="muted">{icpErrorMessage(state)}</p>
      ) : found ? (
        <details className="icp-details">
          <summary>
            <span className="status-pill ok">已备案</span>
            <span>{records[0].serviceLicence || records[0].mainLicence || domain}</span>
            {state.result?.cached && <span className="muted">cached</span>}
          </summary>
          <div className="icp-record-list">
            {records.map((record, index) => (
              <dl className="detail-list icp-record" key={`${record.domain}-${record.serviceLicence}-${index}`}>
                <Row label="域名" value={record.domain || domain} />
                <Row label="主办单位" value={record.unitName} />
                <Row label="主体性质" value={record.natureName} />
                <Row label="主体备案号" value={record.mainLicence} />
                <Row label="网站备案号" value={record.serviceLicence} />
                <Row label="网站名称" value={record.serviceName} />
                <Row label="审核时间" value={record.updateRecordTime} />
              </dl>
            ))}
          </div>
        </details>
      ) : notFound ? (
        <p className="muted">没有备案信息。</p>
      ) : (
        <p className="muted">没有备案信息。</p>
      )}
    </section>
  );
}

function icpErrorMessage(state: ICPState) {
  if (state.errorCode === "icp_disabled" || state.httpStatus === 503) {
    return "备案查询未启用。";
  }
  if (state.errorCode === "icp_route_missing" || state.httpStatus === 404) {
    return "备案接口未接入当前运行的服务，请重启 Web/API 或更新镜像。";
  }
  if (state.errorCode === "api_unreachable") {
    return "备案查询暂不可用：后端 API 无法连接。";
  }
  if (state.errorCode === "icp_invalid_response") {
    return state.error || "备案接口返回了非 JSON 响应，请重启 Web/API 后再试。";
  }
  return state.error ? `备案查询暂不可用：${state.error}` : "备案查询暂不可用。";
}

function NSComparison({
  registryNs,
  dnsNs,
  mismatch,
  nameservers,
  onCopy,
}: {
  registryNs?: string[];
  dnsNs?: string[];
  mismatch?: boolean;
  nameservers: LookupResult["nameservers"];
  onCopy?: (value: string) => void;
}) {
  const liveNs = dnsNs || [];
  const whoisNs = registryNs || [];
  if (!liveNs.length && !whoisNs.length) return null;
  if (!mismatch) {
    return <DNSValueGroup title="NS" values={liveNs.length ? liveNs : whoisNs} onCopy={onCopy} />;
  }
  return (
    <div className="ns-compare">
      <div className="ns-warning">WHOIS/RDAP NS and live DNS NS differ</div>
      <details className="ns-evidence">
        <summary>
          <span>Show NS evidence</span>
          <span className="muted">{whoisNs.length} registry / {liveNs.length} live</span>
        </summary>
        <div className="ns-evidence-grid">
          <div>
            <strong>WHOIS/RDAP NS <span>{whoisNs.length}</span></strong>
            <NSList values={whoisNs} nameservers={nameservers} onCopy={onCopy} grouped />
          </div>
          <div>
            <strong>Live DNS NS <span>{liveNs.length}</span></strong>
            <NSList values={liveNs} nameservers={nameservers} onCopy={onCopy} grouped />
          </div>
        </div>
      </details>
    </div>
  );
}

function NSList({
  values,
  nameservers,
  onCopy,
  grouped,
}: {
  values: string[];
  nameservers?: LookupResult["nameservers"];
  onCopy?: (value: string) => void;
  grouped?: boolean;
}) {
  if (!values.length) return <span className="muted">none</span>;
  if (grouped) {
    return <NameserverGroupedList values={values} nameservers={nameservers} onCopy={onCopy} />;
  }
  return (
    <span className="dns-record-list">
      {values.map((value) => (
        <span key={value} className="dns-record-item">
          <ActionValue value={value} onCopy={onCopy} />
          {nameservers ? <NameserverAddresses host={value} nameservers={nameservers} /> : null}
        </span>
      ))}
    </span>
  );
}

function NameserverGroupedList({ values, nameservers, onCopy }: { values: string[]; nameservers?: LookupResult["nameservers"]; onCopy?: (value: string) => void }) {
  const groups = groupNameserversBySuffix(values);
  return (
    <span className="ns-compact-list">
      {groups.map((group) => (
        <span className="ns-group" key={group.suffix}>
          <span className="ns-group-suffix" title={group.suffix}>{group.suffix}</span>
          <span className="ns-group-hosts">
            {group.items.map((item) => (
              <button type="button" className="ns-host-chip" key={item.host} onClick={() => onCopy?.(item.host)} title={item.host} aria-label={`Copy ${item.host}`}>
                {item.label}
              </button>
            ))}
          </span>
          {nameservers && (
            <span className="ns-group-addresses">
              {group.items.map((item) => (
                <NameserverAddresses key={item.host} host={item.host} nameservers={nameservers} />
              ))}
            </span>
          )}
        </span>
      ))}
    </span>
  );
}

function groupNameserversBySuffix(values: string[]) {
  const groups = new Map<string, { suffix: string; items: { host: string; label: string }[] }>();
  for (const value of values) {
    const host = normalizeNameserverHost(value);
    if (!host) continue;
    const labels = host.split(".");
    const suffix = labels.length >= 3 ? labels.slice(1).join(".") : host;
    const label = labels.length >= 3 ? labels[0] : host;
    const group = groups.get(suffix) || { suffix, items: [] };
    group.items.push({ host, label });
    groups.set(suffix, group);
  }
  return Array.from(groups.values()).sort((a, b) => a.suffix.localeCompare(b.suffix));
}

function NameserverBlock({
  registryNs,
  liveNs,
  mismatch,
  nameservers,
  onCopy,
}: {
  registryNs?: string[];
  liveNs?: string[];
  mismatch?: boolean;
  nameservers: LookupResult["nameservers"];
  onCopy?: (value: string) => void;
}) {
  const merged = mergeNameserverValues(registryNs || [], liveNs || []);

  if (merged.length === 0) return null;
  if (mismatch) {
    return <NSComparison registryNs={registryNs} dnsNs={liveNs} mismatch nameservers={nameservers} onCopy={onCopy} />;
  }
  return (
    <div className="nameserver-list">
      {merged.map((host) => (
        <span key={host} className="nameserver-item">
          <ActionValue value={formatNameserverLabel(host, nameservers)} onCopy={() => onCopy?.(host)} />
          <NameserverAddresses host={host} nameservers={nameservers} />
        </span>
      ))}
    </div>
  );
}

function mergeNameserverValues(...groups: string[][]) {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const group of groups) {
    for (const value of group) {
      const normalized = normalizeNameserverHost(value);
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      out.push(normalized);
    }
  }
  return out.sort();
}

function normalizeNameserverHost(value: string) {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

function formatNameserverLabel(host: string, nameservers: LookupResult["nameservers"]) {
  const matched = nameservers.find((ns) => normalizeNameserverHost(ns.host) === host);
  return matched?.brand ? `${host} - ${brandLabel(matched.brand)}` : host;
}

function NameserverAddresses({ host, nameservers }: { host: string; nameservers: LookupResult["nameservers"] }) {
  const matched = nameservers.find((ns) => normalizeNameserverHost(ns.host) === host);
  const addresses = Array.isArray(matched?.addresses) ? matched.addresses.filter(Boolean) : [];
  if (!addresses.length) return null;
  return (
    <span className="nameserver-addresses">
      {addresses.map((address) => (
        <span className="ns-address-chip" key={address}>IP {address}</span>
      ))}
    </span>
  );
}

function DNSResolverBadges({ resolvers }: { resolvers?: NonNullable<LookupResult["enrichment"]["dns"]>["resolvers"] }) {
  if (!resolvers?.length) return null;
  const groups = groupDNSResolvers(resolvers);
  return (
    <div className="dns-resolver-badges">
      {groups.map((group) => (
        <div key={group.key} className="resolver-group">
          <ResolverIcon source={group.source} resolver={group.resolver} endpoint={group.endpoint} status={group.status} count={group.items.length} />
          <div className="resolver-tooltip" role="tooltip">
            {group.items.map((resolver) => {
              const meta = resolverMeta(resolver.source, resolver.resolver, resolver.endpoint);
              const status = resolver.status || "ok";
              return (
                <div key={`${resolver.source}-${resolver.resolver}-${resolver.endpoint || ""}`} className={`resolver-tooltip-row resolver-status-${status}`}>
                  <ResolverIcon source={resolver.source} resolver={resolver.resolver} endpoint={resolver.endpoint} status={status} compact />
                  <span className="resolver-tooltip-main">{resolver.endpoint || resolver.resolver}</span>
                  <span className="resolver-tooltip-status">{resolverStatusLabel(status)}</span>
                  {resolver.error && <span className="resolver-tooltip-error">{resolver.error}</span>}
                  <span className="sr-only">{meta.title}</span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

type DNSResolverInfo = NonNullable<NonNullable<LookupResult["enrichment"]["dns"]>["resolvers"]>[number];

function groupDNSResolvers(resolvers: DNSResolverInfo[]) {
  const map = new Map<string, { key: string; source?: string; resolver?: string; endpoint?: string; status?: string; items: DNSResolverInfo[] }>();
  for (const resolver of resolvers) {
    const meta = resolverMeta(resolver.source, resolver.resolver, resolver.endpoint);
    const key = `${resolver.source || ""}-${meta.kind}`;
    const existing = map.get(key);
    if (existing) {
      existing.items.push(resolver);
      existing.status = mergeResolverStatus(existing.status, resolver.status);
      continue;
    }
    map.set(key, {
      key,
      source: resolver.source,
      resolver: resolver.source === "udp" ? "udp" : resolver.resolver,
      endpoint: resolver.endpoint,
      status: resolver.status,
      items: [resolver],
    });
  }
  return Array.from(map.values());
}

function DNSAddressGroup({ title, addresses }: { title: string; addresses?: NonNullable<LookupResult["enrichment"]["dns"]>["a"] }) {
  if (!addresses?.length) return null;
  const summary = addresses.length === 1 ? addresses[0].ip : `${addresses.length} records`;
  return (
    <details className="dns-record-group">
      <summary>
        <span>{summary}</span>
        {addresses.length > 1 && <span className="muted">{title}</span>}
      </summary>
      <div className="dns-record-list">
        {addresses.map((address) => (
          <span key={`${address.ip}-${address.source || ""}-${address.resolver || ""}`} className="dns-record-item">
            <span>{address.ip}</span>
            <ResolverBadge source={address.source} resolver={address.resolver} endpoint={address.endpoint} compact />
          </span>
        ))}
      </div>
    </details>
  );
}

function ResolverBadge({
  source,
  resolver,
  endpoint,
  status,
  compact,
}: {
  source?: string;
  resolver?: string;
  endpoint?: string;
  status?: string;
  compact?: boolean;
}) {
  if (!source && !resolver) return null;
  const resolvers = splitResolverValues(resolver);
  const endpoints = splitResolverValues(endpoint);
  const items = resolvers.length > 0 ? resolvers : [resolver || endpoint || ""];
  const mergedStatus = status || "ok";
  return (
    <span className="resolver-group inline-resolver-group">
      <ResolverIcon source={source} resolver={items.join(", ")} endpoint={endpoint} status={mergedStatus} compact={compact} />
      <div className="resolver-tooltip" role="tooltip">
        {items.map((item, index) => {
          const itemEndpoint = endpoints[index] || endpoint;
          return (
            <div key={`${source}-${item}-${itemEndpoint || ""}-${index}`} className={`resolver-tooltip-row resolver-status-${mergedStatus}`}>
              <ResolverIcon source={source} resolver={item} endpoint={itemEndpoint} status={mergedStatus} compact />
              <span className="resolver-tooltip-main">{itemEndpoint || item}</span>
              <span className="resolver-tooltip-status">{resolverStatusLabel(mergedStatus)}</span>
            </div>
          );
        })}
      </div>
    </span>
  );
}

function DNSValueGroup({ title, values, onCopy }: { title: string; values?: string[]; onCopy?: (value: string) => void }) {
  if (!values?.length) return null;
  const summary = values.length === 1 ? values[0] : `${values.length} records`;
  return (
    <details className="dns-record-group">
      <summary>
        <span>{summary}</span>
        {values.length > 1 && <span className="muted">{title}</span>}
      </summary>
      <div className="dns-record-list">
        {values.map((value) => (
          <span key={value} className="dns-record-item">
            {onCopy ? <ActionValue value={value} onCopy={onCopy} /> : value}
          </span>
        ))}
      </div>
    </details>
  );
}

function ResolverIcon({
  source,
  resolver,
  endpoint,
  compact,
  status,
  count,
}: {
  source?: string;
  resolver?: string;
  endpoint?: string;
  compact?: boolean;
  status?: string;
  count?: number;
}) {
  if (!source && !resolver) return null;
  const parts = splitResolverValues(resolver);
  const endpoints = splitResolverValues(endpoint);
  if (parts.length > 1) {
    return (
      <span className="resolver-icon-stack">
        {parts.map((part, index) => (
          <ResolverIcon key={`${part}-${index}`} source={source} resolver={part} endpoint={endpoints[index] || endpoint} compact={compact} status={status} />
        ))}
      </span>
    );
  }
  const meta = resolverMeta(source, resolver, endpoint);
  const title = [meta.title, resolverStatusLabel(status), count && count > 1 ? `${count} resolvers` : ""].filter(Boolean).join(" - ");
  return (
    <span className={`resolver-icon resolver-${meta.kind} resolver-status-${status || "ok"}${compact ? " compact" : ""}`} tabIndex={0} aria-label={title}>
      {meta.label}{count && count > 1 ? <span className="resolver-count">{count}</span> : null}
    </span>
  );
}

function splitResolverValues(value?: string) {
  return (value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function resolverMeta(source?: string, resolver?: string, endpoint?: string) {
  const value = (resolver || "").toLowerCase();
  const sourceLabel = (source || "").toUpperCase();
  if (source === "udp" && value === "udp") {
    return { kind: "udp", label: "U", title: "UDP DNS resolvers" };
  }
  if (source === "doh") {
    if (value.includes("cloudflare")) return { kind: "cf", label: "CF", title: endpoint || "https://cloudflare-dns.com/dns-query" };
    if (value.includes("google")) return { kind: "google", label: "G", title: endpoint || "https://dns.google/resolve" };
    if (value.includes("doh.pub")) return { kind: "tencent", label: "T", title: endpoint || "https://doh.pub/dns-query" };
    if (value.includes("alidns")) return { kind: "ali", label: "A", title: endpoint || "https://dns.alidns.com/dns-query" };
    return { kind: "doh", label: "D", title: endpoint || resolver || "DoH" };
  }
  return { kind: "udp", label: "U", title: [sourceLabel, resolver].filter(Boolean).join(" ") };
}

function mergeResolverStatus(current?: string, incoming?: string) {
  if (current === "error" || incoming === "error") return "error";
  if (current === "empty" || incoming === "empty") return "empty";
  return current || incoming || "ok";
}

function resolverStatusLabel(status?: string) {
  if (status === "error") return "failed";
  if (status === "empty") return "no answer";
  return "answered";
}

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

function RegistrationPanel({ result, aiLoading, aiError, onCopy }: { result: LookupResult; aiLoading?: boolean; aiError?: string; onCopy?: (value: string) => void }) {
  const { t } = useI18n();
  const registrant = result.registrant || {};
  const extras = Array.isArray(registrant.extra) ? registrant.extra.filter((field) => field.label && field.value) : [];
  const ai = result.meta?.ai;
  return (
    <section className="panel registration-panel">
      <div className="panel-head">
        <h2>{t("registration")}</h2>
        {aiLoading && <span className="source-hint ai-pending">{t("aiAnalyzing")}</span>}
        {!aiLoading && aiError && <span className="source-hint ai-error" title={aiError}>AI error</span>}
        {ai && (
          <span className={`source-hint ${ai.status === "error" ? "ai-error" : "ai-source"}`} title={[ai.provider, ai.model, ai.reason, ai.error].filter(Boolean).join("\n")}>
            AI {ai.status}{ai.cached ? " cached" : ""}
          </span>
        )}
      </div>
      {!hasRegistration(result) ? (
        <p className="muted">{aiLoading ? t("aiChecking") : t("noRegistration")}</p>
      ) : (
        <dl className="detail-list registration-list">
          <RegistrationRow label="Name" fieldKey="name" value={registrant.name} registrant={registrant} onCopy={onCopy} />
          <RegistrationRow label="Organization" fieldKey="organization" value={registrant.organization} registrant={registrant} onCopy={onCopy} />
          <RegistrationRow label="Country" fieldKey="country" value={registrant.country} registrant={registrant} />
          <RegistrationRow label="Province" fieldKey="province" value={registrant.province} registrant={registrant} />
          <RegistrationRow label="City" fieldKey="city" value={registrant.city} registrant={registrant} />
          <RegistrationRow label="Address" fieldKey="address" value={registrant.address} registrant={registrant} onCopy={onCopy} />
          <RegistrationRow label="Postal Code" fieldKey="postalCode" value={registrant.postalCode} registrant={registrant} />
          <RegistrationRow label="Email" fieldKey="email" value={registrant.email} registrant={registrant} onCopy={onCopy} />
          <RegistrationRow label="Phone" fieldKey="phone" value={registrant.phone} registrant={registrant} onCopy={onCopy} />
          {extras.length > 0 && (
            <Row
              label="Registry Fields"
              value={
                <div className="registration-extra-list">
                  {extras.map((field, index) => (
                    <div key={`${field.label}-${field.value}-${index}`} className="registration-extra-item">
                      <span className="registration-extra-label">{field.label}</span>
                      <ActionValue value={field.value} onCopy={onCopy} />
                      <RegistrationSourceBadges sources={[field]} />
                    </div>
                  ))}
                </div>
              }
            />
          )}
        </dl>
      )}
    </section>
  );
}

function NetworkPanel({ result }: { result: LookupResult }) {
  const { t } = useI18n();
  return (
    <section className="panel network-panel">
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

function SummaryPanel({ result, onCopy }: { result: LookupResult; onCopy?: (value: string) => void }) {
  const { t } = useI18n();
  return (
    <section className="panel summary-panel">
      <div className="panel-head">
        <h2>{t("summary")}</h2>
      </div>
      <dl className="detail-list">
        <Row label="Domain" value={<ActionValue value={result.domain.name} href={externalDomainURL(result.domain.name)} onCopy={onCopy} />} />
        <Row label="Unicode" value={<ActionValue value={result.domain.unicodeName} href={externalDomainURL(result.domain.unicodeName)} onCopy={onCopy} />} />
        <Row
          label="Registrar"
          value={
            result.registrar.name ? (
              <span className="registration-value">
                <ActionValue value={result.registrar.name} href={safeExternalURL(result.registrar.url)} />
                <SourceHint source={result.registrar.source} confidence={result.registrar.confidence} evidence={result.registrar.evidence} />
              </span>
            ) : (
              <span className="status-pill off">Not parsed</span>
            )
          }
        />
        <Row label="Registrar Brand" value={brandLabel(result.registrar.brand)} />
        <Row label="IANA ID" value={result.registrar.ianaId} />
        <Row label="Registrar Country" value={result.registrar.country} />
        <Row label="Created" value={result.dates.createdAt} />
        <Row label="Expires" value={result.dates.expiresAt} />
        <Row label="Updated" value={result.dates.updatedAt} />
        <Row label="Age days" value={result.dates.ageDays} />
        <Row label="Remaining days" value={result.dates.remainingDays} />
        <Row label="DNSSEC" value={result.dnssec.text} />
      </dl>
    </section>
  );
}

function StatusPanel({ statuses }: { statuses: LookupResult["statuses"] }) {
  const { t } = useI18n();
  return (
    <section className="panel status-panel">
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
  );
}

function StatusStrip({ result, onCopy }: { result: LookupResult; onCopy?: (value: string) => void }) {
  return (
    <section className={`status-strip status-${result.status}`}>
      <div>
        <p className="eyebrow">{result.type}</p>
        <h1>
          <ActionValue value={result.normalizedQuery} href={result.type === "domain" ? externalDomainURL(result.domain.unicodeName || result.normalizedQuery) : undefined} onCopy={onCopy} />
        </h1>
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
  value,
  onChange,
  exactDomain,
  onExactDomainChange,
  forceAI,
  onForceAIChange,
}: {
  value: SourceMode;
  onChange: (value: SourceMode) => void;
  exactDomain: boolean;
  onExactDomainChange: (value: boolean) => void;
  forceAI: boolean;
  onForceAIChange: (value: boolean) => void;
}) {
  const { t } = useI18n();
  const sourceOptions: { value: SourceMode; label: string }[] = [
    { value: "all", label: "All" },
    { value: "rdap", label: "RDAP" },
    { value: "whois", label: "WHOIS" },
  ];

  return (
    <div className="source-bar source-tabs">
      <div className="source-toggle" role="radiogroup" aria-label="Lookup source">
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
      <label className="inline-check" title={t("exactDomainHint")}>
        <input type="checkbox" checked={exactDomain} onChange={(event) => onExactDomainChange(event.target.checked)} />
        <span>{t("exactDomain")}</span>
      </label>
      <label className="inline-check" title={t("forceAIHint")}>
        <input type="checkbox" checked={forceAI} onChange={(event) => onForceAIChange(event.target.checked)} />
        <span>{t("forceAI")}</span>
      </label>
    </div>
  );
}

function LookupErrorPanel({ response, status }: { response: APIResponse; status: number }) {
  const view = errorView(response, status);
  return (
    <section className="panel error-panel">
      <p className="eyebrow">{view.eyebrow}</p>
      <h1>{view.title}</h1>
      <p className="muted">{view.message}</p>
      {view.detail && <pre className="error-detail">{view.detail}</pre>}
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
  const { t } = useI18n();
  const pageURL = useMemo(() => lookupUrl(state.query, state.sourceMode, state.options), [state.options, state.query, state.sourceMode]);
  const absolutePageURL = typeof window === "undefined" ? pageURL : window.location.href;
  const ogImageURL = `/api/og?query=${encodeURIComponent(result?.normalizedQuery || state.query)}`;
  const icpDomain = result?.type === "domain" ? result.domain.registeredDomain || result.domain.name || result.normalizedQuery : "";
  const currentAIIdentity = aiIdentity(result, state.nonce);
  const currentEnrichmentIdentity = enrichmentIdentity(result, state.nonce);
  const pendingEnrichments = result?.meta?.pendingEnrichments || [];
  const rememberedEnrichments = enrichmentState.identity === currentEnrichmentIdentity && enrichmentState.requested ? enrichmentState.names || [] : [];
  const visibleEnrichments = pendingEnrichments.length ? pendingEnrichments : rememberedEnrichments;
  const pendingDetailEnrichments = visibleEnrichments.filter((name) => name !== "dns");
  const enrichmentLoading = enrichmentState.loading && enrichmentState.identity === currentEnrichmentIdentity;
  const enrichmentError = enrichmentState.identity === currentEnrichmentIdentity ? enrichmentState.error : undefined;
  const detailTools = result ? renderResultPlugins("details", result, { pending: pendingDetailEnrichments, enrichmentLoading, enrichmentError, lockSlots: true }) : [];
  const debugTools = result ? renderResultPlugins("debug", result) : [];
  const showEnrichmentZone = Boolean(result);
  const dnsPending = Boolean(result && pendingEnrichments.includes("dns"));
  const hasEvidence = Boolean(result && (debugTools.length || result.raw.whois || result.raw.whoisWeb || result.raw.rdap));
  const enrichmentStatus = enrichmentLoading
    ? visibleEnrichments.join(", ") || "running"
    : enrichmentError
      ? "error"
      : visibleEnrichments.length
        ? "ready"
        : "idle";

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
  }, [absolutePageURL, result, t]);

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

  return (
    <>
      <Head>
        <title>{title}</title>
        <meta property="og:title" content={title} />
        <meta property="og:image" content={`/api/og?query=${encodeURIComponent(result?.normalizedQuery || state.query)}`} />
        <meta name="twitter:card" content="summary_large_image" />
      </Head>
      <main className="shell result-shell result-workbench-shell">
        <nav className="top-nav">
          <Link href="/" className="brand">Whoice</Link>
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <AppControls />
          </div>
        </nav>

        <div className="lookup-workbench">
          <aside className="tool-sidebar" aria-label="Lookup toolbox">
            <section className="tool-panel tool-panel-search">
              <div className="tool-panel-head">
                <p className="eyebrow">Lookup</p>
                <span className={`status-pill ${isLoading ? "" : "is-ghost"}`} aria-hidden={!isLoading}>
                  Live
                </span>
              </div>
              <form className="mini-search tool-search" onSubmit={submitMiniSearch}>
                <input id="lookup-mini-search" name="query" value={searchValue} onChange={(event) => setSearchValue(event.target.value)} aria-label="Search query" />
                <button disabled={isLoading} type="submit">{isLoading ? "Searching" : "Search"}</button>
              </form>
              {state.query && (
                <SourceLinks
                  value={state.sourceMode}
                  exactDomain={parseBool(state.options.exactDomain)}
                  forceAI={parseBool(state.options.ai)}
                  onChange={switchSource}
                  onExactDomainChange={switchExactDomain}
                  onForceAIChange={switchForceAI}
                />
              )}
            </section>

            {result && (
              <section className="tool-panel">
                <div className="tool-panel-head">
                  <p className="eyebrow">Session</p>
                  <span className={`status-pill status-dot status-dot-${result.status}`}>{result.status}</span>
                </div>
                <div className="tool-facts">
                  <span><strong>Type</strong>{result.type}</span>
                  {result.source.primary && <span><strong>Primary</strong>{result.source.primary}</span>}
                  <span><strong>Elapsed</strong>{result.meta.elapsedMs} ms</span>
                  <span><strong>Evidence</strong>{rawText(result) ? "available" : "empty"}</span>
                  <span title={enrichmentError}><strong>Enrich</strong>{enrichmentStatus}</span>
                </div>
              </section>
            )}

            {result && (
              <section className="tool-panel">
                <div className="tool-panel-head">
                  <p className="eyebrow">Output</p>
                  <span className={`tool-action-state ${actionState ? "" : "is-ghost"}`} aria-live="polite">
                    {actionState || "Ready"}
                  </span>
                </div>
                <section className="action-bar tool-action-bar" aria-label="Result actions">
                  <div className="share-menu">
                    <button type="button" onClick={() => setShareMenuOpen((open) => !open)}>{t("share")}</button>
                    {shareMenuOpen && (
                      <div className="share-menu-panel">
                        <button type="button" onClick={shareResult}>{t("copyUrl")}</button>
                        <button type="button" onClick={() => copy(result.normalizedQuery, t("copied"))}>{t("copyQuery")}</button>
                        <button type="button" onClick={downloadOGImage}>{t("downloadImage")}</button>
                        <a href={ogImageURL} target="_blank" rel="noreferrer">{t("openImage")}</a>
                      </div>
                    )}
                  </div>
                  <button type="button" onClick={() => copy(rawText(result), t("copied"))}>{t("copyRaw")}</button>
                  <button type="button" onClick={downloadResult}>{t("downloadJson")}</button>
                </section>
              </section>
            )}

            <section className="tool-panel shortcut-panel">
              <p className="eyebrow">Keys</p>
              <span className="shortcut-hint">
                <kbd>/</kbd> search <kbd>S</kbd> share <kbd>C</kbd> URL <kbd>R</kbd> raw <kbd>J</kbd> JSON <kbd>O</kbd> image
              </span>
            </section>
          </aside>

          <section className="tool-stage" aria-label="Lookup result workspace">
            {isLoading && (
              <section className="panel loading-panel floating-loading-panel" aria-live="polite">
                <p className="eyebrow">Live lookup</p>
                <h2>{searchValue}</h2>
              </section>
            )}

            {!state.response.ok || !result ? (
              <LookupErrorPanel response={state.response} status={state.httpStatus} />
            ) : (
              <>
                <StatusStrip result={result} onCopy={(value) => copy(value, t("copied"))} />
                <div className="result-sections tool-stage-sections">
                  <section className="tool-zone">
                    <div className="tool-zone-head">
                      <span className="tool-zone-index">01</span>
                      <div>
                        <h2>Overview</h2>
                        <p>Identity, registrar, and live DNS context.</p>
                      </div>
                    </div>
                    <div className="result-band result-band-primary zone-body-overview">
                      <SummaryPanel result={result} onCopy={(value) => copy(value, t("copied"))} />
                      {result.type === "domain" ? <DNSPanel result={result} pending={dnsPending} onCopy={(value) => copy(value, t("copied"))} /> : <NetworkPanel result={result} />}
                    </div>
                  </section>

                  <section className="tool-zone">
                    <div className="tool-zone-head">
                      <span className="tool-zone-index">02</span>
                      <div>
                        <h2>Ownership</h2>
                        <p>Registrant fields, AI assistance, ICP, and domain state.</p>
                      </div>
                    </div>
                    <div className="result-band result-band-secondary zone-body-ownership">
                      {result.type === "domain" && (
                        <RegistrationPanel
                          result={result}
                          aiLoading={aiState.loading && aiState.identity === currentAIIdentity}
                          aiError={aiState.identity === currentAIIdentity ? aiState.error : undefined}
                          onCopy={(value) => copy(value, t("copied"))}
                        />
                      )}
                      {result.type === "domain" && <ICPPanel domain={icpDomain} state={icpState} onLookup={() => void runICPLookup()} />}
                      <StatusPanel statuses={statuses} />
                    </div>
                  </section>

                  {showEnrichmentZone && (
                    <section className="tool-zone">
                      <div className="tool-zone-head">
                        <span className="tool-zone-index">03</span>
                        <div>
                          <h2>Enrichment</h2>
                          <p>Plugins and provider-specific diagnostics.</p>
                        </div>
                      </div>
                      <div className="result-grid enrichment-grid zone-body-enrichment">
                        {detailTools}
                        <div className="plugin-shell">
                          <section className={`panel warning-panel ${(sourceErrors.length > 0 || metaWarnings.length > 0 || enrichmentError) ? "" : "is-empty"}`}>
                            <div className="panel-head">
                              <h2>{t("warnings")}</h2>
                            </div>
                            {(sourceErrors.length > 0 || metaWarnings.length > 0 || enrichmentError) ? (
                              <ul>
                                {enrichmentError && <li>enrichment: {enrichmentError}</li>}
                                {metaWarnings.map((warning) => (
                                  <li key={warning}>{warning}</li>
                                ))}
                                {sourceErrors.map((error) => (
                                  <li key={`${error.source}-${error.error}`}>{error.source}: {error.error}</li>
                                ))}
                              </ul>
                            ) : (
                              <p className="muted">No provider warnings for this lookup.</p>
                            )}
                          </section>
                        </div>
                      </div>
                    </section>
                  )}

                  <section className="tool-zone">
                    <div className="tool-zone-head">
                      <span className="tool-zone-index">04</span>
                      <div>
                        <h2>Evidence</h2>
                        <p>Raw responses and request diagnostics for verification.</p>
                      </div>
                    </div>
                    <div className="evidence-stack zone-body-evidence">
                      {debugTools}
                      {hasEvidence ? null : <section className="panel evidence-placeholder"><p className="muted">No raw provider evidence for this lookup.</p></section>}
                      <RawBlock title={t("rawWhois")} value={result.raw.whois} />
                      <RawBlock title="WHOIS Web" value={result.raw.whoisWeb} />
                      <RawBlock title={t("rawRdap")} value={result.raw.rdap} />
                    </div>
                  </section>
                </div>
              </>
            )}
          </section>
        </div>
      </main>
    </>
  );
}
