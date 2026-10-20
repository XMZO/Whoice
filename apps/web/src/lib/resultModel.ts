import type { I18nKey } from "./i18n";
import type { LookupResult } from "./types";

type Translate = (key: I18nKey) => string;
type TranslateFormat = (key: I18nKey, vars: Record<string, string | number>) => string;

export type InputKind = "domain" | "ipv4" | "ipv6" | "cidr" | "asn" | "url";

export function detectInputKind(value: string): InputKind {
  const text = value.trim();
  if (/^https?:\/\//i.test(text)) return "url";
  if (/^AS\d+$/i.test(text)) return "asn";
  if (/\/\d{1,3}$/.test(text)) return "cidr";
  if (text.includes(":")) return "ipv6";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text)) return "ipv4";
  return "domain";
}

export function kindLabel(kind: string, t: Translate) {
  switch (kind) {
    case "domain":
      return t("typeDomain");
    case "ipv4":
      return "IPv4";
    case "ipv6":
      return "IPv6";
    case "cidr":
      return "CIDR";
    case "asn":
      return "ASN";
    case "url":
      return "URL";
    default:
      return kind.toUpperCase();
  }
}

export type FlowStep = { full: string; short: string };

export type InputInfo = {
  kind: InputKind;
  label: string;
  route: string;
  steps: [FlowStep, FlowStep, FlowStep, FlowStep];
};

// Describes how a typed query will be routed, for the home page preview. Only uses
// local knowledge (type detection and suffix); the real routing happens in the API.
export function describeInput(value: string, t: Translate, tf: TranslateFormat): InputInfo {
  const text = value.trim();
  const kind = detectInputKind(text);
  const label = kindLabel(kind, t);
  if (kind === "domain" || kind === "url") {
    const host = kind === "url" ? text.replace(/^https?:\/\//i, "").split(/[/?#:]/)[0] : text;
    const labels = host.toLowerCase().split(".").filter(Boolean);
    const tld = labels.length > 1 ? `.${labels[labels.length - 1]}` : "";
    const registry = tf("registryOf", { tld: tld || "TLD" });
    const route = kind === "url" ? `${t("routeExtract")} ${host}` : tld ? `${t("routeSuffix")} ${tld}` : t("routeNeedFull");
    return {
      kind,
      label,
      route,
      steps: [
        { full: kind === "url" ? `URL\n${t("typeDomain")} ${host}` : tld ? `${label}\n${t("routeSuffix")} ${tld}` : label, short: tld ? `${label} ${tld}` : label },
        { full: `IANA Bootstrap\n${registry}`, short: registry },
        { full: "RDAP\nWHOIS", short: "RDAP · WHOIS" },
        { full: t("flowParseDomain"), short: t("flowParseDomainShort") },
      ],
    };
  }
  if (kind === "asn") {
    return {
      kind,
      label,
      route: t("routeRir"),
      steps: [
        { full: t("typeAsnLong"), short: label },
        { full: "IANA Bootstrap\nRIR", short: "RIR" },
        { full: "RDAP", short: "RDAP" },
        { full: t("flowParseAsn"), short: t("flowParseAsnShort") },
      ],
    };
  }
  const noun = kind === "cidr" ? t("kindRange") : t("kindAddress");
  return {
    kind,
    label,
    route: t("routeRir"),
    steps: [
      { full: `${label} ${noun}`, short: label },
      { full: "IANA Bootstrap\nRIR", short: "RIR" },
      { full: "RDAP", short: "RDAP" },
      { full: t("flowParseIp"), short: t("flowParseIpShort") },
    ],
  };
}

export function normalizeHost(value: string) {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

const MULTI_LABEL_SUFFIXES = new Set(["co.uk", "org.uk", "com.cn", "net.cn", "org.cn", "com.au", "net.au", "co.jp", "ne.jp", "com.br", "com.tw", "com.hk", "co.kr"]);

// Approximates the registrable part of a hostname for grouping purposes only.
export function hostSuffix(host: string) {
  const labels = normalizeHost(host).split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_LABEL_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels.slice(-3).join(".");
  return lastTwo;
}

const NS_PROVIDERS: { match: RegExp; name: string }[] = [
  { match: /awsdns-\d+\./, name: "Amazon Route 53" },
  { match: /\.nsone\.net$/, name: "NS1" },
  { match: /\.ns\.cloudflare\.com$/, name: "Cloudflare" },
  { match: /\.googledomains\.com$|\.google\.com$/, name: "Google" },
  { match: /\.azure-dns\./, name: "Azure DNS" },
  { match: /\.akam\.net$|\.akamaiedge\.net$/, name: "Akamai" },
  { match: /\.dynect\.net$/, name: "Dyn" },
  { match: /\.ultradns\./, name: "UltraDNS" },
  { match: /\.dnspod\.net$|\.dnspod\.com$/, name: "DNSPod" },
  { match: /\.alidns\.com$|\.hichina\.com$/, name: "Alibaba Cloud DNS" },
  { match: /\.domaincontrol\.com$/, name: "GoDaddy" },
  { match: /\.registrar-servers\.com$/, name: "Namecheap" },
  { match: /\.verisign-grs\.com$|\.gtld-servers\.net$/, name: "Verisign" },
];

const MX_PROVIDERS: { match: RegExp; name: string }[] = [
  { match: /(^|\.)google\.com$|googlemail\.com$/, name: "Google" },
  { match: /\.outlook\.com$/, name: "Microsoft 365" },
  { match: /\.qq\.com$/, name: "Tencent" },
  { match: /\.aliyun\.com$|\.mxhichina\.com$/, name: "Alibaba Mail" },
  { match: /\.icloud\.com$/, name: "iCloud" },
  { match: /\.zoho\.(com|eu)$/, name: "Zoho" },
  { match: /\.pphosted\.com$/, name: "Proofpoint" },
  { match: /\.mimecast\.com$/, name: "Mimecast" },
];

function providerName(host: string, table: { match: RegExp; name: string }[]) {
  const value = normalizeHost(host);
  return table.find((entry) => entry.match.test(value))?.name;
}

export type HostGroup = {
  key: string;
  name: string;
  color: string;
  hosts: string[];
  // When every host shares the same tail after its first label, the tail is shown dimmed once.
  heads?: string[];
  tail?: string;
};

const GROUP_COLORS = ["var(--ns-brand-1)", "var(--ns-brand-2)", "var(--ns-brand-3)", "var(--ns-brand-4)", "var(--ns-brand-5)", "var(--ns-brand-6)"];

function sharedTail(hosts: string[]) {
  if (hosts.length < 2) return undefined;
  const tails = hosts.map((host) => host.split(".").slice(1).join("."));
  if (!tails[0] || tails.some((tail) => tail !== tails[0])) return undefined;
  return { heads: hosts.map((host) => host.split(".")[0]), tail: `.${tails[0]}` };
}

export function groupNameservers(hosts: string[], nameservers: LookupResult["nameservers"] = []): HostGroup[] {
  const groups = new Map<string, HostGroup>();
  for (const raw of hosts) {
    const host = normalizeHost(raw);
    if (!host) continue;
    const brand = nameservers.find((ns) => normalizeHost(ns.host) === host)?.brand;
    const name = brand?.name || providerName(host, NS_PROVIDERS) || hostSuffix(host);
    const group = groups.get(name) || { key: name, name, color: brand?.color || "", hosts: [] };
    if (!group.hosts.includes(host)) group.hosts.push(host);
    groups.set(name, group);
  }
  return Array.from(groups.values()).map((group, index) => ({
    ...group,
    hosts: group.hosts.sort(),
    color: group.color || GROUP_COLORS[index % GROUP_COLORS.length],
    ...sharedTail(group.hosts.slice().sort()),
  }));
}

export type MXGroup = {
  key: string;
  name: string;
  color: string;
  records: { pref: number; host: string; head: string }[];
  tail?: string;
};

export function groupMX(records: { host: string; pref: number }[] = []): MXGroup[] {
  const groups = new Map<string, { name: string; records: { pref: number; host: string }[] }>();
  for (const record of records) {
    const host = normalizeHost(record.host || "");
    if (!host) continue;
    const name = providerName(host, MX_PROVIDERS) || hostSuffix(host);
    const group = groups.get(name) || { name, records: [] };
    group.records.push({ pref: record.pref, host });
    groups.set(name, group);
  }
  return Array.from(groups.values()).map((group, index) => {
    const sorted = group.records.sort((a, b) => a.pref - b.pref || a.host.localeCompare(b.host));
    const suffix = hostSuffix(sorted[0].host);
    // Dim the longest tail shared by every host, but only when it is longer than the bare suffix.
    const tailParts = sorted[0].host.split(".");
    let tail = "";
    for (let size = tailParts.length - 1; size >= 2; size -= 1) {
      const candidate = `.${tailParts.slice(-size).join(".")}`;
      if (sorted.every((record) => record.host.endsWith(candidate) && record.host.length > candidate.length)) {
        tail = candidate;
        break;
      }
    }
    if (sorted.length < 2 || tail.length <= suffix.length + 1) tail = "";
    return {
      key: group.name,
      name: group.name,
      color: GROUP_COLORS[(index + 2) % GROUP_COLORS.length],
      records: sorted.map((record) => ({ ...record, head: tail ? record.host.slice(0, -tail.length) : record.host })),
      tail: tail || undefined,
    };
  });
}

export type ResolverInfo = {
  source?: string;
  resolver?: string;
  endpoint?: string;
  status?: string;
  error?: string;
};

export function resolverKind(source?: string, resolver?: string) {
  const value = `${resolver || ""}`.toLowerCase();
  if (source === "doh") {
    if (value.includes("cloudflare")) return "cf";
    if (value.includes("google")) return "google";
    if (value.includes("doh.pub")) return "tencent";
    if (value.includes("alidns")) return "ali";
    return "doh";
  }
  return "udp";
}

export function resolverName(resolver: ResolverInfo, t: Translate, detailed = false) {
  const kind = resolverKind(resolver.source, resolver.resolver);
  const suffix = detailed ? " DoH" : "";
  switch (kind) {
    case "cf":
      return `Cloudflare${suffix}`;
    case "google":
      return `Google${suffix}`;
    case "tencent":
      return `${t("resolverTencent")}${suffix}`;
    case "ali":
      return `${t("resolverAli")}${suffix}`;
    case "doh":
      return resolver.resolver || "DoH";
    default:
      return detailed && resolver.resolver ? `UDP ${resolver.resolver}` : "UDP";
  }
}

function splitValues(value?: string) {
  return (value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

// Resolver attribution on an address is a comma-joined list; expand it to provider names.
export function addressProviders(address: { source?: string; resolver?: string; endpoint?: string }, t: Translate) {
  const sources = splitValues(address.source).map((item) => item.toLowerCase());
  const resolvers = splitValues(address.resolver);
  const names = new Set<string>();
  resolvers.forEach((resolver, index) => {
    const isIP = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(resolver) || resolver.includes(":") || resolver === "system";
    const source = isIP ? "udp" : sources[index] || (sources.includes("doh") ? "doh" : sources[0]);
    names.add(resolverName({ source, resolver }, t));
  });
  if (!resolvers.length && sources.length) sources.forEach((source) => names.add(source.toUpperCase()));
  return Array.from(names);
}

export function agreeingProviders(addresses: { source?: string; resolver?: string; endpoint?: string }[], t: Translate) {
  if (!addresses.length) return [];
  const sets = addresses.map((address) => new Set(addressProviders(address, t)));
  return Array.from(sets[0]).filter((name) => sets.every((set) => set.has(name)));
}

export type ResolverStatusItem = { key: string; label: string; status: "ok" | "empty" | "error"; detail?: string };

export function resolverStatusItems(resolvers: ResolverInfo[] = [], t: Translate, detailed: boolean): ResolverStatusItem[] {
  if (detailed) {
    return resolvers.map((resolver, index) => ({
      key: `${resolver.source}-${resolver.resolver}-${index}`,
      label: resolverName(resolver, t, true),
      status: (resolver.status as ResolverStatusItem["status"]) || "ok",
      detail: resolver.error || resolver.endpoint,
    }));
  }
  const groups = new Map<string, ResolverStatusItem & { count: number }>();
  for (const resolver of resolvers) {
    const name = resolverName(resolver, t);
    const status = (resolver.status as ResolverStatusItem["status"]) || "ok";
    const key = `${name}-${status}`;
    const current = groups.get(key);
    if (current) {
      current.count += 1;
      current.detail = [current.detail, resolver.error || resolver.resolver].filter(Boolean).join("\n");
      continue;
    }
    groups.set(key, { key, label: name, status, count: 1, detail: resolver.error || resolver.endpoint || resolver.resolver });
  }
  return Array.from(groups.values()).map((group) => ({ ...group, label: group.count > 1 ? `${group.label} ×${group.count}` : group.label }));
}

export type LockOp = "delete" | "transfer" | "update" | "renew";
export type LockItem = { op: LockOp; locked: boolean; code: string; description?: string };

const LOCK_OPS: LockOp[] = ["delete", "transfer", "update", "renew"];

function statusKey(value?: string) {
  return (value || "").toLowerCase().replace(/https?:\/\/icann\.org\/epp#/i, "").replace(/[^a-z]/g, "");
}

export function lockModel(statuses: LookupResult["statuses"] = []) {
  const byKey = new Map(statuses.map((status) => [statusKey(status.code || status.label), status]));
  const build = (scope: "client" | "server"): LockItem[] =>
    LOCK_OPS.map((op) => {
      const code = `${scope}${op[0].toUpperCase()}${op.slice(1)}Prohibited`;
      const status = byKey.get(code.toLowerCase());
      return { op, locked: Boolean(status), code, description: status?.description };
    });
  const registrar = build("client");
  const registry = build("server");
  const hold = ["clienthold", "serverhold"].some((key) => byKey.has(key));
  return { registrar, registry, registryAny: registry.some((item) => item.locked), hold };
}

export function lockOpLabel(op: LockOp, t: Translate) {
  return t(op === "delete" ? "opDelete" : op === "transfer" ? "opTransfer" : op === "update" ? "opUpdate" : "opRenew");
}

export function formatTimestamp(value?: string) {
  if (!value) return "";
  return value.replace("T", " ").replace(/\.\d+Z$/, "Z");
}

export function formatBytes(value?: number) {
  if (value === undefined || value === null) return "";
  if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${value} B`;
}

export function textBytes(value?: string) {
  if (!value) return 0;
  return new TextEncoder().encode(value).length;
}

export function relativeTime(timestamp: number, now: number, tf: TranslateFormat, t: Translate) {
  const seconds = Math.max(0, Math.round((now - timestamp) / 1000));
  if (seconds < 60) return t("agoJustNow");
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return tf("agoMinutes", { n: minutes });
  const hours = Math.round(minutes / 60);
  if (hours < 24) return tf("agoHours", { n: hours });
  const days = Math.round(hours / 24);
  if (days === 1) return t("agoYesterday");
  if (days < 7) return tf("agoDays", { n: days });
  if (days < 14) return t("agoLastWeek");
  if (days < 60) return tf("agoDays", { n: days });
  const months = Math.round(days / 30);
  if (months < 12) return tf("agoMonths", { n: months });
  return tf("agoYears", { n: Math.round(days / 365) });
}

export function sinceLabel(value: string | undefined, tf: TranslateFormat, t: Translate) {
  if (!value) return undefined;
  const time = Date.parse(value);
  if (Number.isNaN(time)) return undefined;
  return relativeTime(time, Date.now(), tf, t);
}

export function countryName(value: string | undefined, locale: string) {
  const text = value?.trim();
  if (!text) return undefined;
  if (!/^[A-Za-z]{2}$/.test(text)) return text;
  try {
    const names = new Intl.DisplayNames([locale], { type: "region" });
    const name = names.of(text.toUpperCase());
    return name && name !== text.toUpperCase() ? `${name} (${text.toUpperCase()})` : text.toUpperCase();
  } catch {
    return text.toUpperCase();
  }
}

export function displayServer(value?: string) {
  if (!value) return "";
  return value.replace(/^https?:\/\//i, "").replace(/\/domain\/[^/]+$|\/(ip|autnum)\/[^/]+$/i, "").replace(/\/$/, "");
}

export function sourceName(source?: string) {
  if (source === "rdap") return "RDAP";
  if (source === "whois") return "WHOIS";
  if (source === "whoisWeb") return "WHOIS Web";
  return source || "";
}

export function sourceTag(source?: string) {
  if (!source) return "";
  if (source.startsWith("ai")) return "AI";
  return sourceName(source);
}

export function safeExternalURL(value?: string) {
  const text = value?.trim();
  if (!text) return undefined;
  if (/^https?:\/\//i.test(text)) return text;
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?:\/.*)?$/i.test(text)) return `https://${text}`;
  return undefined;
}

export function prettyRaw(value?: string) {
  if (!value) return "";
  const text = value.trim();
  if (!text.startsWith("{") && !text.startsWith("[")) return value;
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return value;
  }
}
