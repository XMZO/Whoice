import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { createPortal } from "react-dom";
import {
  BuildingIcon,
  CalendarIcon,
  ClockIcon,
  ExternalIcon,
  FileIcon,
  GlobeIcon,
  LockIcon,
  NetworkIcon,
  RefreshIcon,
  SearchIcon,
  ShieldIcon,
  TagIcon,
  TerminalIcon,
  UserIcon,
  WarnIcon,
} from "@/components/Icons";
import { useI18n } from "@/lib/i18n";
import { t3, useT3, type T3 } from "@/lib/t3";
import {
  agreeingProviders,
  countryName,
  displayServer,
  formatBytes,
  formatTimestamp,
  groupMX,
  groupNameservers,
  lockModel,
  lockOpLabel,
  normalizeHost,
  relativeTime,
  resolverStatusItems,
  safeExternalURL,
  sinceLabel,
  sourceName,
  sourceTag,
} from "@/lib/resultModel";
import type { FXRates, ICPResult, LookupResult, PricingOffer } from "@/lib/types";
import { convertAmount, useDisplayCurrency, type DisplayCurrency } from "@/lib/currency";
import type { RawTab } from "@/components/RawDrawer";

type RegistrationSource = NonNullable<LookupResult["registrant"]["extra"]>[number];

export type ICPState = {
  domain: string;
  loading: boolean;
  requested: boolean;
  httpStatus?: number;
  result?: ICPResult;
  errorCode?: string;
  error?: string;
};

function SectionHead({ icon, title, meta, children, id }: { icon: ReactNode; title: string; meta?: ReactNode; children?: ReactNode; id: string }) {
  return (
    <div className="section-head">
      <span className="icon-tile" aria-hidden="true">{icon}</span>
      <h2 id={id}>{title}</h2>
      {meta !== undefined && meta !== null && meta !== "" && <span className="section-meta">{meta}</span>}
      <span className="spacer" />
      {children}
    </div>
  );
}

/** Compact warning list: each entry is clamped to two lines, full text on hover. */
export function WarningList({ warnings }: { warnings: string[] }) {
  const { t } = useI18n();
  if (!warnings.length) return null;
  return (
    <div className="warning-note warning-panel" role="note">
      <WarnIcon size={15} />
      <span>
        <strong>{t("warningLabel")}</strong>
        <ul className="warning-items">
          {warnings.map((warning) => (
            <li key={warning} title={warning}>
              {warning}
            </li>
          ))}
        </ul>
      </span>
    </div>
  );
}

export function SourceTags({ sources }: { sources: string[] }) {
  if (!sources.length) return null;
  return (
    <>
      {sources.map((source) => (
        <span key={source} className={source === "AI" ? "src-tag src-tag-ai" : "src-tag"}>{source}</span>
      ))}
    </>
  );
}

/** Placeholder for a value that is still on its way; it takes the value's line. */
export function Skel({ width = "6em" }: { width?: string }) {
  return <span className="skel" style={{ width }} aria-hidden="true" />;
}

/* ---------- Hero metrics and locks ---------- */

// Every metric keeps the same three lines (label, value, sub) whether or not
// the value has arrived, so streamed fields fill in without resizing cards.
// A name value (registrar, network) passes `fit` so a long one shrinks to fit
// its card instead of being cut off.
function Metric({ icon, label, value, sub, tone, badge, title, fit }: { icon: ReactNode; label: string; value: ReactNode; sub?: ReactNode; tone?: "ok" | "warn" | "danger"; badge?: string; title?: string; fit?: string }) {
  return (
    <div className={`metric${tone ? ` metric-${tone}` : ""}`}>
      <span className="metric-icon" aria-hidden="true">{icon}</span>
      <span className="metric-body">
        <span className="metric-label">{label}</span>
        <strong className={fit ? "metric-value fit" : "metric-value"} title={title} style={fit ? ({ "--chars": fit.length + 2 } as CSSProperties) : undefined}>
          {value}
          {badge && <span className="metric-badge">{badge}</span>}
        </strong>
        <span className="metric-sub">{sub}</span>
      </span>
    </div>
  );
}

function expiryTone(days?: number): "ok" | "warn" | "danger" | undefined {
  if (days === undefined || days === null) return undefined;
  if (days <= 30) return "danger";
  if (days <= 90) return "warn";
  return "ok";
}

export function DomainMetrics({ result, pending }: { result: LookupResult; pending?: boolean }) {
  const { t, tf, locale } = useI18n();
  const registrar = result.registrar || {};
  const dates = result.dates || {};
  const country = countryName(registrar.country, locale);
  const registrarSub = [registrar.ianaId ? `IANA ${registrar.ianaId}` : "", country].filter(Boolean).join(" · ");
  const ageDays = dates.ageDays;
  const years = ageDays !== undefined && ageDays !== null ? Math.floor(ageDays / 365.25) : undefined;
  const ageValue = years === undefined ? (pending ? <Skel /> : t("notProvided")) : years >= 1 ? tf("durYears", { n: years }) : tf("durDays", { n: ageDays ?? 0 });
  const ageBadge = ageDays === undefined || ageDays === null ? undefined : ageDays < 90 ? t("newDomain") : ageDays >= 3650 ? t("oldDomain") : ageDays >= 1095 ? t("matureDomain") : undefined;
  const remaining = dates.remainingDays;
  const remainingValue = remaining === undefined || remaining === null ? (pending ? <Skel /> : t("notProvided")) : remaining < 0 ? tf("expiredDays", { n: Math.abs(remaining) }) : tf("durDays", { n: remaining });
  const updated = sinceLabel(dates.updatedAt, tf, t);
  const registrarSite = registrar.name ? safeExternalURL(registrar.url || registrar.brand?.website) : "";
  const registrarValue = registrarSite ? (
    <a className="metric-link" href={registrarSite} target="_blank" rel="noopener noreferrer" title={registrarSite}>
      {registrar.name}
      <ExternalIcon size={13} className="metric-link-icon" />
    </a>
  ) : (
    registrar.name || (pending ? <Skel width="8em" /> : t("noRegistrar"))
  );
  const stamp = (value?: string) => (value ? <span className="mono">{formatTimestamp(value)}</span> : pending ? <Skel width="5.5em" /> : undefined);
  return (
    <div className="metric-grid summary-panel">
      <Metric icon={<BuildingIcon />} label={t("registrar")} value={registrarValue} title={registrar.name} fit={registrar.name} sub={registrarSub || (pending && !registrar.name ? <Skel width="4em" /> : undefined)} />
      <Metric icon={<CalendarIcon />} label={t("registrationAge")} value={ageValue} badge={ageBadge} sub={stamp(dates.createdAt)} />
      <Metric icon={<ClockIcon />} label={t("remainingValidity")} value={remainingValue} tone={expiryTone(remaining)} sub={stamp(dates.expiresAt)} />
      <Metric icon={<RefreshIcon />} label={t("lastUpdated")} value={updated || (pending ? <Skel /> : t("notProvided"))} sub={stamp(dates.updatedAt)} />
    </div>
  );
}

export function NetworkMetrics({ result, pending }: { result: LookupResult; pending?: boolean }) {
  const { t, locale } = useI18n();
  const network = result.network || {};
  const country = countryName(network.country, locale);
  const missing = pending ? <Skel /> : t("notProvided");
  return (
    <div className="metric-grid summary-panel">
      <Metric icon={<NetworkIcon />} label={t("range")} value={network.cidr || network.range ? <span className="mono">{network.cidr || network.range}</span> : missing} fit={network.cidr || network.range} sub={network.cidr && network.range ? <span className="mono">{network.range}</span> : undefined} />
      <Metric icon={<BuildingIcon />} label={t("entityName")} value={network.name || missing} title={network.name} fit={network.name} sub={network.type} />
      <Metric icon={<GlobeIcon />} label={t("country")} value={country || missing} />
      <Metric icon={<TagIcon />} label={t("originAs")} value={network.originAS ? <span className="mono">{network.originAS}</span> : missing} />
    </div>
  );
}

// Registrar and registry lock explanations. English falls back to the API's EPP description.
const LOCK_HELP: Record<string, T3> = {
  clienttransferprohibited: t3("The registrar has locked the domain against transfer.", "注册商已锁定域名，禁止转移", "註冊商已鎖定網域，禁止轉移"),
  clientdeleteprohibited: t3("The registrar has locked the domain against deletion.", "注册商已锁定域名，禁止删除", "註冊商已鎖定網域，禁止刪除"),
  clientupdateprohibited: t3("The registrar has locked the domain against updates.", "注册商已锁定域名，禁止更新", "註冊商已鎖定網域，禁止更新"),
  clientrenewprohibited: t3("The registrar has locked the domain against renewal.", "注册商已锁定域名，禁止续费", "註冊商已鎖定網域，禁止續費"),
  servertransferprohibited: t3("The registry has locked the domain against transfer.", "注册局已锁定域名，禁止转移", "註冊局已鎖定網域，禁止轉移"),
  serverdeleteprohibited: t3("The registry has locked the domain against deletion.", "注册局已锁定域名，禁止删除", "註冊局已鎖定網域，禁止刪除"),
  serverupdateprohibited: t3("The registry has locked the domain against updates.", "注册局已锁定域名，禁止更新", "註冊局已鎖定網域，禁止更新"),
  serverrenewprohibited: t3("The registry has locked the domain against renewal.", "注册局已锁定域名，禁止续费", "註冊局已鎖定網域，禁止續費"),
};

function lockTitle(code: string, locked: boolean, pick: (value: T3) => string, notSet: string) {
  const help = LOCK_HELP[code.toLowerCase()];
  return `${code} · ${locked ? (help ? pick(help) : "") : notSet}`.replace(/ · $/, "");
}

export function LockBar({ result, pending }: { result: LookupResult; pending?: boolean }) {
  const { t, tf } = useI18n();
  const pick = useT3();
  const statuses = Array.isArray(result.statuses) ? result.statuses : [];
  const model = lockModel(statuses);
  const signed = result.dnssec?.signed ?? /^(signed|yes|true)/i.test(result.dnssec?.text || "");
  const dnssecKnown = result.dnssec?.signed !== undefined || Boolean(result.dnssec?.text);
  // Until a registry source answers, the locks are unknown, not "unlocked".
  const waiting = Boolean(pending && !statuses.length);
  return (
    <div className="lock-bar status-panel">
      <span className="lock-title">
        <ShieldIcon className="lock-title-icon" />
        {t("securityLocks")}
      </span>
      <span className="lock-group">
        <span className="lock-label">{t("registrarLock")}</span>
        <span className="lock-tags">
          {waiting && model.registrar.map((item) => <span key={item.op} className="lock-tag skel-tag" aria-hidden="true" />)}
          {!waiting && model.registrar.map((item) => {
            const op = lockOpLabel(item.op, t);
            return item.locked ? (
              <span key={item.op} className="lock-tag locked" title={lockTitle(item.code, true, pick, t("notSet"))}>
                <LockIcon />
                <span className="lock-text-long">{tf("lockedOp", { op })}</span>
                <span className="lock-text-short">{op}</span>
              </span>
            ) : (
              <span key={item.op} className="lock-tag unlocked" title={lockTitle(item.code, false, pick, t("notSet"))}>
                <span className="lock-text-long">{tf("unlockedOp", { op })}</span>
                <span className="lock-text-short">{op}</span>
              </span>
            );
          })}
          {model.hold && <span className="lock-tag hold">{t("holdTag")}</span>}
        </span>
      </span>
      <span className="lock-group">
        <span className="lock-label">{t("registryLock")}</span>
        <span className="lock-tags">
          {waiting ? (
            <Skel width="4em" />
          ) : model.registryAny ? (
            model.registry
              .filter((item) => item.locked)
              .map((item) => {
                const op = lockOpLabel(item.op, t);
                return (
                  <span key={item.op} className="lock-tag locked" title={lockTitle(item.code, true, pick, t("notSet"))}>
                    <LockIcon />
                    <span className="lock-text-long">{tf("lockedOp", { op })}</span>
                    <span className="lock-text-short">{op}</span>
                  </span>
                );
              })
          ) : (
            <span className="lock-value">{t("notSet")}</span>
          )}
        </span>
      </span>
      <span className="lock-group">
        <span className="lock-label">DNSSEC</span>
        <span className="lock-value mono-cjk">{dnssecKnown ? (signed ? t("dnssecSigned") : t("dnssecUnsigned")) : pending ? <Skel width="4em" /> : t("notProvided")}</span>
      </span>
    </div>
  );
}

export function StatusList({ result }: { result: LookupResult }) {
  const { t } = useI18n();
  const statuses = Array.isArray(result.statuses) ? result.statuses : [];
  if (!statuses.length) return null;
  return (
    <div className="lock-bar status-panel">
      <span className="lock-title">
        <ShieldIcon className="lock-title-icon" />
        {t("status")}
      </span>
      <span className="lock-tags">
        {statuses.map((status) => (
          <span key={`${status.code}-${status.source || ""}`} className="lock-tag neutral" title={status.description}>
            {status.label || status.code}
          </span>
        ))}
      </span>
    </div>
  );
}

/* ---------- DNS ---------- */

function RecordRow({ type, children, align = "center" }: { type: string; children: ReactNode; align?: "center" | "start" }) {
  return (
    <div className={`record-row align-${align}`}>
      <span className="record-type">{type}</span>
      <div className="record-body">{children}</div>
    </div>
  );
}

function GroupTitle({ color, name, meta }: { color: string; name: string; meta: string }) {
  return (
    <span className="group-title">
      <span className="dot" style={{ background: color }} aria-hidden="true" />
      <span className="group-name">{name}</span>
      <span className="group-meta">{meta}</span>
    </span>
  );
}

export function DNSSection({
  result,
  pending,
  loadingError,
  notes = [],
  showHeader = true,
  onCopy,
}: {
  result: LookupResult;
  pending?: boolean;
  loadingError?: string;
  notes?: string[];
  showHeader?: boolean;
  onCopy: (value: string) => void;
}) {
  const { t, tf } = useI18n();
  const pick = useT3();
  const dns = result.enrichment?.dns;
  // Every nameserver serves a marketplace's for-sale page (see enrichment.forSale).
  const saleTag = result.enrichment?.forSale ? ` · ${pick(t3(`${result.enrichment.forSale.market} for-sale page`, `${result.enrichment.forSale.market} 出售页`, `${result.enrichment.forSale.market} 出售頁`))}` : "";
  const nameservers = Array.isArray(result.nameservers) ? result.nameservers : [];
  const registryNs = dns?.registryNs?.length ? dns.registryNs : nameservers.map((ns) => ns.host).filter(Boolean);
  const liveNs = Array.isArray(dns?.ns) ? dns.ns : [];
  const allNs = Array.from(new Set([...registryNs, ...liveNs].map(normalizeHost).filter(Boolean)));
  const groups = groupNameservers(allNs, nameservers);
  const sep = t("listSep");
  const a = Array.isArray(dns?.a) ? dns.a : [];
  const aaaa = Array.isArray(dns?.aaaa) ? dns.aaaa : [];
  const mx = groupMX(Array.isArray(dns?.mx) ? dns.mx : []);
  const resolvers = Array.isArray(dns?.resolvers) ? dns.resolvers : [];
  const answered = resolvers.filter((resolver) => (resolver.status || "ok") === "ok").length;
  const dnsvizURL = result.enrichment?.dnsviz?.url;
  const nsConsistency = registryNs.length && liveNs.length ? (dns?.nsMismatch ? t("nsDiffer") : t("nsConsistent")) : "";

  const addressLine = (records: typeof a, emptyText: string) => {
    if (!records.length) return <span className="muted">{emptyText}</span>;
    const agree = agreeingProviders(records, t);
    return (
      <span className="address-line">
        <span className="address-list">
          {records.map((record) => (
            <button type="button" key={record.ip} className="mono-chip" onClick={() => onCopy(record.ip)} title={record.ip}>
              {record.ip}
            </button>
          ))}
        </span>
        {agree.length >= 2 && <span className="address-note">{tf("resolversAgree", { list: agree.join(sep) })}</span>}
      </span>
    );
  };

  return (
    <section className="result-card dns-panel" aria-labelledby="h-dns" aria-busy={pending ? "true" : undefined}>
      {showHeader && (
        <SectionHead id="h-dns" icon={<GlobeIcon size={15} />} title={t("dns")} meta={dns?.elapsedMs !== undefined ? <span className="mono">{dns.elapsedMs} ms</span> : undefined}>
          {dnsvizURL && <DNSVizLink url={dnsvizURL} />}
        </SectionHead>
      )}
      {!showHeader && <h2 id="h-dns" className="sr-only">{t("dns")}</h2>}
      <div className="dns-head-narrow">
        <strong>{t("dns")}</strong>
        {dns?.elapsedMs !== undefined && <span className="section-meta mono">{dns.elapsedMs} ms</span>}
        <span className="spacer" />
        {dnsvizURL && <DNSVizLink url={dnsvizURL} />}
      </div>
      <RecordRow type="NS" align="start">
        {groups.length ? (
          <>
            <span className="ns-summary">
              {tf("nsSummary", { n: allNs.length })}
              {nsConsistency && ` · ${nsConsistency}`}
            </span>
            <div className="ns-groups">
              {groups.map((group) => (
                <div className="ns-group" key={group.key}>
                  <GroupTitle color={group.color} name={group.name} meta={tf("unitHosts", { n: group.hosts.length }) + saleTag} />
                  {group.heads && group.tail ? (
                    <span className="host-line">
                      {group.heads.map((head, index) => (
                        <span key={head}>
                          {index > 0 && <span className="host-sep"> · </span>}
                          <button type="button" className="host-copy" onClick={() => onCopy(group.hosts[index])} title={group.hosts[index]}>
                            {head}
                          </button>
                        </span>
                      ))}
                      <span className="host-tail">{group.tail}</span>
                    </span>
                  ) : (
                    <span className="host-list">
                      {group.hosts.map((host) => (
                        <button type="button" key={host} className="host-copy" onClick={() => onCopy(host)} title={host}>
                          {host}
                        </button>
                      ))}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </>
        ) : pending ? (
          <span className="pending-line short" aria-hidden="true" />
        ) : (
          <span className="muted">{t("noNameservers")}</span>
        )}
      </RecordRow>
      {pending && !dns ? (
        <div className="pending-block" role="status">
          <span className="muted">{t("dnsUpdating")}</span>
          <span className="pending-line" />
          <span className="pending-line short" />
          <span className="pending-line" />
        </div>
      ) : loadingError && !dns ? (
        <p className="section-note warn-text">{t("enrichmentFailed")}</p>
      ) : dns ? (
        <>
          {dns.cname && (
            <RecordRow type="CNAME">
              <span className="mono">{dns.cname}</span>
            </RecordRow>
          )}
          <RecordRow type="A">{addressLine(a, t("noRecords"))}</RecordRow>
          <RecordRow type="AAAA">{addressLine(aaaa, t("noAAAA"))}</RecordRow>
          <RecordRow type="MX" align="start">
            {mx.length ? (
              mx.map((group) => (
                <div className="mx-group" key={group.key}>
                  <GroupTitle color={group.color} name={group.name} meta={tf("mxSummary", { n: group.records.length })} />
                  <span className="mx-list">
                    {group.records.map((record) => (
                      <span className="mx-item" key={`${record.pref}-${record.host}`} title={record.host}>
                        <span className="mx-pref">{record.pref}</span>
                        <span className="mx-host-wide">{record.head}</span>
                        <span className="mx-host-full">{record.host}</span>
                      </span>
                    ))}
                    {group.tail && <span className="host-tail mx-tail">{group.tail}</span>}
                  </span>
                </div>
              ))
            ) : (
              <span className="muted">{t("noRecords")}</span>
            )}
          </RecordRow>
          {resolvers.length > 0 && (
            <div className="resolver-line">
              <span className="resolver-caption">
                {t("resolversLabel")}
                <span className="resolver-caption-count"> · {tf("resolversAnswered", { a: answered, n: resolvers.length })}</span>
              </span>
              <span className="resolver-items resolver-items-grouped">
                {resolverStatusItems(resolvers, t, false).map((item) => (
                  <ResolverDot key={item.key} label={item.label} status={item.status} source={item.source} detail={item.detail} />
                ))}
              </span>
              <span className="resolver-items resolver-items-detailed">
                {resolverStatusItems(resolvers, t, true).map((item) => (
                  <ResolverDot key={item.key} label={item.label} status={item.status} source={item.source} detail={item.detail} />
                ))}
              </span>
            </div>
          )}
        </>
      ) : (
        <RecordRow type="A">
          <span className="muted">{t("noDns")}</span>
        </RecordRow>
      )}
      <WarningList warnings={notes} />
    </section>
  );
}

// "empty" means the resolver answered without records, which is not a
// failure: DoH resolvers are asked for addresses only (a mail-only domain has
// none), UDP resolvers for A/AAAA, CNAME, MX and NS.
const RESOLVER_EMPTY_DOH = t3("no address", "无地址记录", "無位址記錄");
const RESOLVER_EMPTY_UDP = t3("no records", "无记录", "無記錄");
const RESOLVER_EMPTY_HINT = t3(
  "Answered, but the name has no matching records",
  "已正常回答，但该名称没有对应记录",
  "已正常回答，但該名稱沒有對應記錄",
);

function ResolverDot({ label, status, source, detail }: { label: string; status: string; source?: string; detail?: string }) {
  const { t } = useI18n();
  const pick = useT3();
  const failed = status === "error";
  const empty = status === "empty";
  const suffix = failed
    ? /timeout|deadline/i.test(detail || "")
      ? t("dnsTimeout")
      : t("resolverFailed")
    : empty
      ? pick(source === "doh" ? RESOLVER_EMPTY_DOH : RESOLVER_EMPTY_UDP)
      : "";
  const tooltip = empty ? [pick(RESOLVER_EMPTY_HINT), detail].filter(Boolean).join("\n") : detail;
  return (
    <span className={`resolver-group resolver-dot ${failed ? "is-failed" : empty ? "is-empty" : ""}`} tabIndex={tooltip ? 0 : undefined}>
      <span className="dot" aria-hidden="true" />
      {label}
      {suffix && ` ${suffix}`}
      {tooltip && (
        <span className="resolver-tooltip" role="tooltip">
          {tooltip}
        </span>
      )}
    </span>
  );
}

export function DNSVizLink({ url }: { url: string }) {
  const { t } = useI18n();
  return (
    <a className="btn btn-sm btn-accent-text" href={url} target="_blank" rel="noreferrer">
      {t("openDNSViz")}
      <ExternalIcon size={12} />
    </a>
  );
}

/* ---------- Pricing ---------- */

function formatMoney(value: number | undefined, currency: string, locale: string) {
  if (value === undefined || value === null) return undefined;
  try {
    return new Intl.NumberFormat(locale, { currency, style: "currency" }).format(value);
  } catch {
    return `${value} ${currency}`;
  }
}

export function pricingSummary(result: LookupResult, locale: string) {
  const pricing = result.enrichment?.pricing;
  if (!pricing) return undefined;
  const currency = pricing.currency || "USD";
  const price = pricing.registerOffer?.price ?? pricing.register;
  return formatMoney(price, pricing.registerOffer?.currency || currency, locale);
}

function moneyText(value: number | undefined, currency: string, locale: string) {
  // Intl joins a currency code with a no-break space; a plain space lets a
  // long amount ("IDR 987,654,322") wrap between code and number.
  return formatMoney(value, currency, locale)?.replace(/\u00a0/g, " ");
}

function longestPart(value: string) {
  return Math.max(...value.split(/ +/).map((part) => part.length), 1);
}

function PriceTile({ label, offer, fallbackCurrency, displayCurrency, fx }: { label: string; offer?: PricingOffer; fallbackCurrency: string; displayCurrency: DisplayCurrency; fx?: FXRates }) {
  const { locale } = useI18n();
  const original = offer?.currency || fallbackCurrency;
  const originalText = moneyText(offer?.price, original, locale);
  const converted = original.toUpperCase() === displayCurrency ? undefined : convertAmount(offer?.price, original, displayCurrency, fx);
  const convertedText = converted === undefined ? undefined : `≈ ${moneyText(converted, displayCurrency, locale)}`;
  const main = convertedText || originalText || "—";
  const href = safeExternalURL(offer?.website);
  return (
    <div className="price-tile">
      <span className="price-label">{label}</span>
      {/* --chars lets CSS shrink long amounts (e.g. ₫1,234,567,890) to the tile width. */}
      {/* Converted amounts are sized as one line including "≈ " (a fallback-font
          glyph wider than one mono cell, so counted twice); only when even the
          minimum size is too wide does the line break after "≈". */}
      <strong className="price-value" title={main} style={{ "--chars": convertedText ? main.length + 1 : longestPart(main) } as CSSProperties}>
        {main}
      </strong>
      {convertedText && originalText && (
        <span className="price-original" title={originalText} style={{ "--chars": longestPart(originalText) } as CSSProperties}>
          {originalText}
        </span>
      )}
      {offer?.registrar ? (
        href ? (
          <a className="price-registrar" href={href} target="_blank" rel="noreferrer">{offer.registrar}</a>
        ) : (
          <span className="price-registrar">{offer.registrar}</span>
        )
      ) : (
        <span className="price-registrar muted">&nbsp;</span>
      )}
    </div>
  );
}

/** CNY / USD switch for converted prices; shared across the page. */
export function CurrencyToggle({ fx }: { fx?: FXRates }) {
  const { locale } = useI18n();
  const pick = useT3();
  const [currency, setCurrency] = useDisplayCurrency(locale);
  if (!fx) return null;
  const when = fx.cachedAt ? formatTimestamp(fx.cachedAt) : "";
  const detail = [
    `${pick(t3("Rates", "汇率", "匯率"))}: ${fx.source || "—"}`,
    fx.updatedAt ? `${pick(t3("Rate date", "汇率日期", "匯率日期"))}: ${fx.updatedAt.slice(0, 10)}` : "",
    when ? `${pick(t3("Cached at", "缓存于", "快取於"))} ${when}` : "",
  ]
    .filter(Boolean)
    .join("\n");
  return (
    <span className="currency-switch">
      <FXTag fx={fx} title={detail} />
      <span className="currency-toggle" role="group" aria-label={pick(t3("Show prices in", "价格换算为", "價格換算為"))}>
        {(["CNY", "USD"] as DisplayCurrency[]).map((code) => (
          <button key={code} type="button" aria-pressed={currency === code} className={currency === code ? "active" : undefined} onClick={() => setCurrency(code)}>
            {code}
          </button>
        ))}
      </span>
    </span>
  );
}

function FXTag({ fx, title }: { fx: FXRates; title: string }) {
  const { t, tf } = useI18n();
  const pick = useT3();
  const timestamp = fx.cachedAt ? Date.parse(fx.cachedAt) : NaN;
  return (
    <span className="pill pill-xs" title={title}>
      {pick(t3("Rates", "汇率", "匯率"))}
      {Number.isNaN(timestamp) ? "" : ` · ${relativeTime(timestamp, Date.now(), tf, t)}`}
    </span>
  );
}

/** Marks data served from a server-side cache (pricing, ICP). */
function CacheTag({ cachedAt }: { cachedAt?: string }) {
  const { t, tf } = useI18n();
  const pick = useT3();
  if (!cachedAt) return null;
  const timestamp = Date.parse(cachedAt);
  if (Number.isNaN(timestamp)) return null;
  return (
    <span className="pill pill-xs" title={`${pick(t3("Cached at", "缓存于", "快取於"))} ${formatTimestamp(cachedAt)}`}>
      {pick(t3("Cached", "缓存", "快取"))} · {relativeTime(timestamp, Date.now(), tf, t)}
    </span>
  );
}

export function PriceSection({ result, pending, loadingError, showHeader = true }: { result: LookupResult; pending?: boolean; loadingError?: string; showHeader?: boolean }) {
  const { t, locale } = useI18n();
  const pricing = result.enrichment?.pricing;
  const [displayCurrency] = useDisplayCurrency(locale);
  const fx = pricing?.fx;
  const moz = result.enrichment?.moz;
  const currency = pricing?.currency || "USD";
  const offer = (value?: PricingOffer, price?: number) => value ?? (price === undefined ? undefined : { price, currency, registrar: pricing?.provider });
  const register = offer(pricing?.registerOffer, pricing?.register);
  const renew = offer(pricing?.renewOffer, pricing?.renew);
  const transfer = offer(pricing?.transferOffer, pricing?.transfer);
  const mozMeta = [moz?.source, moz?.updatedAt?.slice(0, 10)].filter(Boolean).join(" · ");
  return (
    <section className="result-card price-panel plugin-shell" aria-labelledby="h-price" aria-busy={pending ? "true" : undefined}>
      {showHeader ? (
        <SectionHead id="h-price" icon={<TagIcon size={15} />} title={t("priceScore")}>
          <CacheTag cachedAt={pricing?.cachedAt} />
          <CurrencyToggle fx={fx} />
        </SectionHead>
      ) : (
        <h2 id="h-price" className="sr-only">{t("priceScore")}</h2>
      )}
      <div className="price-head-narrow">
        <strong>{t("priceTitle")}</strong>
        <CacheTag cachedAt={pricing?.cachedAt} />
        <CurrencyToggle fx={fx} />
      </div>
      {pricing ? (
        <div className="price-grid">
          <PriceTile label={t("register")} offer={register} fallbackCurrency={currency} displayCurrency={displayCurrency} fx={fx} />
          <PriceTile label={t("renew")} offer={renew} fallbackCurrency={currency} displayCurrency={displayCurrency} fx={fx} />
          <PriceTile label={t("transfer")} offer={transfer} fallbackCurrency={currency} displayCurrency={displayCurrency} fx={fx} />
          {moz && (
            <div className="price-tile moz-tile">
              <span className="price-label">{t("mozWeight")}</span>
              <strong className="price-value">DA {moz.domainAuthority ?? "—"}</strong>
              <span className="price-sub">
                PA {moz.pageAuthority ?? "—"} · {t("mozSpam")} {moz.spamScore ?? "—"}
              </span>
            </div>
          )}
        </div>
      ) : pending ? (
        <div className="pending-block" role="status">
          <span className="muted">{t("pricingUpdating")}</span>
          <div className="price-grid" aria-hidden="true">
            <span className="pending-tile" />
            <span className="pending-tile" />
            <span className="pending-tile" />
          </div>
        </div>
      ) : (
        <p className="section-note">{loadingError ? t("enrichmentFailed") : t("noPricing")}</p>
      )}
      {moz && (
        <div className="moz-bars">
          <div className="moz-bars-head">
            <strong>{t("mozWeight")}</strong>
            <span className="section-meta">{[mozMeta, t("outOf100")].filter(Boolean).join(" · ")}</span>
          </div>
          <MozBar label={t("mozDA")} value={moz.domainAuthority} />
          <MozBar label={t("mozPA")} value={moz.pageAuthority} />
          <MozBar label={t("mozSpam")} value={moz.spamScore} good />
        </div>
      )}
    </section>
  );
}

function MozBar({ label, value, good }: { label: string; value?: number; good?: boolean }) {
  const width = Math.max(0, Math.min(100, value ?? 0));
  return (
    <div className="moz-bar">
      <span className="moz-bar-label">{label}</span>
      <span className="moz-bar-track" aria-hidden="true">
        <span className={good ? "moz-bar-fill good" : "moz-bar-fill"} style={{ width: `${width}%` }} />
      </span>
      <strong>{value ?? "—"}</strong>
    </div>
  );
}

/* ---------- Registrant ---------- */

function fieldSourceList(registrant: LookupResult["registrant"], keys: string[]) {
  const sources = new Set<string>();
  for (const key of keys) {
    for (const item of registrant.fieldSources?.[key] || []) {
      const tag = sourceTag(item.source);
      if (tag) sources.add(tag);
    }
  }
  if (!sources.size && registrant.source) sources.add(sourceTag(registrant.source));
  return Array.from(sources);
}

export function registrantFieldCount(result: LookupResult) {
  return registrantRows(result, (key) => key, "en").length;
}

type RegistrantRow = { key: string; label: string; value: string; sourceKeys: string[]; strong?: boolean; muted?: boolean };

function registrantRows(result: LookupResult, t: (key: any) => string, locale: string): RegistrantRow[] {
  const registrant = result.registrant || {};
  const rows: RegistrantRow[] = [];
  const push = (key: string, label: string, value: string | undefined, sourceKeys: string[], extra: Partial<RegistrantRow> = {}) => {
    const text = value?.trim();
    if (text) rows.push({ key, label, value: text, sourceKeys, ...extra });
  };
  push("name", t("name"), registrant.name, ["name"], { strong: true });
  push("organization", t("organization"), registrant.organization, ["organization"], { strong: !registrant.name });
  const location = [registrant.city, registrant.province, countryName(registrant.country, locale)].filter(Boolean).join(", ");
  push("location", t("location"), location, ["city", "province", "country"]);
  push("address", t("address"), [registrant.address, registrant.postalCode].filter(Boolean).join(" "), ["address", "postalCode"]);
  push("email", t("email"), registrant.email, ["email"]);
  push("phone", t("phone"), registrant.phone, ["phone"], { muted: /redacted|privacy|隐私|隱私/i.test(registrant.phone || "") });
  return rows;
}

function linkifyValue(value: string) {
  const match = value.match(/(https?:\/\/[^\s]+|[a-z0-9-]+(?:\.[a-z0-9-]+)+\/[^\s]*)/i);
  if (!match || match.index === undefined) return value;
  const href = safeExternalURL(match[0]);
  if (!href) return value;
  return (
    <>
      {value.slice(0, match.index)}
      <a href={href} target="_blank" rel="noreferrer">{match[0]}</a>
      {value.slice(match.index + match[0].length)}
    </>
  );
}

function SourcePopovers({ sources }: { sources?: RegistrationSource[] }) {
  const values = Array.isArray(sources) ? sources.filter((source) => source.source || source.confidence !== undefined || source.evidence) : [];
  if (!values.length) return null;
  return (
    <>
      {values.map((source, index) => (
        <SourcePopover key={`${source.source || "source"}-${index}`} source={source} />
      ))}
    </>
  );
}

const POPOVER_GAP = 6;
const POPOVER_MARGIN = 12;

/**
 * Source tag with a details popover. The popover is portaled to <body> and
 * positioned against the tag, so scrolling cards cannot clip it. Hover
 * previews it on desktop; a click pins it until an outside click, Escape,
 * scroll, or resize. Touch screens get a bottom sheet.
 */
function SourcePopover({ source }: { source: RegistrationSource }) {
  const pick = useT3();
  const tagRef = useRef<HTMLButtonElement>(null);
  const bodyRef = useRef<HTMLSpanElement>(null);
  const [pinned, setPinned] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [style, setStyle] = useState<CSSProperties>({ visibility: "hidden" });
  const open = pinned || hovered;
  const sheet = typeof window !== "undefined" && window.matchMedia("(hover: none) and (pointer: coarse)").matches;

  useLayoutEffect(() => {
    if (!open || sheet) return;
    const tag = tagRef.current?.getBoundingClientRect();
    const body = bodyRef.current?.getBoundingClientRect();
    if (!tag || !body) return;
    const below = tag.bottom + POPOVER_GAP;
    const top = below + body.height > window.innerHeight - POPOVER_MARGIN && tag.top - POPOVER_GAP - body.height > POPOVER_MARGIN ? tag.top - POPOVER_GAP - body.height : below;
    const left = Math.max(POPOVER_MARGIN, Math.min(tag.left, window.innerWidth - body.width - POPOVER_MARGIN));
    setStyle({ left, top });
  }, [open, sheet]);

  useEffect(() => {
    if (!pinned) return;
    const close = () => setPinned(false);
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (tagRef.current?.contains(target) || bodyRef.current?.contains(target)) return;
      close();
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    const onScroll = (event: Event) => {
      if (bodyRef.current?.contains(event.target as Node)) return;
      close();
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", close);
    };
  }, [pinned]);

  useEffect(() => {
    if (!open) setStyle({ visibility: "hidden" });
  }, [open]);

  return (
    <span className="source-popover" onMouseEnter={() => !sheet && setHovered(true)} onMouseLeave={() => setHovered(false)}>
      <button
        ref={tagRef}
        type="button"
        className={source.source?.startsWith("ai") ? "src-tag src-tag-ai" : "src-tag"}
        aria-expanded={pinned}
        onClick={() => setPinned((value) => !value)}
      >
        {sourceTag(source.source) || "?"}
        {source.confidence !== undefined && source.source?.startsWith("ai") ? ` ${Math.round(source.confidence * 100)}%` : ""}
      </button>
      {open &&
        createPortal(
          <span ref={bodyRef} className="source-popover-body" data-sheet={sheet || undefined} style={sheet ? undefined : style} role="dialog">
            {source.value && <span><strong>{pick(t3("Value", "值", "值"))}</strong>{source.value}</span>}
            {source.source && <span><strong>{pick(t3("Source", "来源", "來源"))}</strong>{source.source}</span>}
            {source.confidence !== undefined && <span><strong>{pick(t3("Confidence", "置信度", "信賴度"))}</strong>{Math.round(source.confidence * 100)}%</span>}
            {source.evidence && <span><strong>{pick(t3("Evidence", "依据", "依據"))}</strong>{source.evidence}</span>}
          </span>,
          document.body,
        )}
    </span>
  );
}

const AI_STATUS: Record<string, T3> = {
  ok: t3("AI ok", "AI 已应用", "AI 已套用"),
  ignored: t3("AI ignored", "AI 已跳过", "AI 已略過"),
  error: t3("AI error", "AI 出错", "AI 出錯"),
};

const CACHED = t3("cached", "缓存", "快取");

export function RegistrantSection({
  result,
  aiLoading,
  aiError,
  icpDomain,
  icpState,
  onICPLookup,
  onCopy,
  pending,
  showHeader = true,
}: {
  result: LookupResult;
  pending?: boolean;
  aiLoading?: boolean;
  aiError?: string;
  icpDomain?: string;
  icpState: ICPState;
  onICPLookup: () => void;
  onCopy: (value: string) => void;
  showHeader?: boolean;
}) {
  const { t, tf, locale } = useI18n();
  const pick = useT3();
  const registrant = result.registrant || {};
  const rows = registrantRows(result, t, locale);
  const extras = Array.isArray(registrant.extra) ? registrant.extra.filter((field) => field.label && field.value) : [];
  const ai = result.meta?.ai;
  const allSources = fieldSourceList(registrant, ["name", "organization", "city", "province", "country", "address", "postalCode", "email", "phone"]);
  const hasAIStatus = Boolean(aiLoading || aiError || ai);
  const aiBadge = (
    <>
      {aiLoading && <span className="pill pill-amber pulse">{t("aiAnalyzing")}</span>}
      {!aiLoading && aiError && <span className="pill pill-red" title={aiError}>{pick(AI_STATUS.error)}</span>}
      {ai && (
        <span className={`pill ${ai.status === "error" ? "pill-red" : "pill-accent"}`} title={[ai.reason, ai.error, ai.applied?.length ? ai.applied.join(", ") : ""].filter(Boolean).join("\n")}>
          {AI_STATUS[ai.status] ? pick(AI_STATUS[ai.status]) : `AI ${ai.status}`}
          {ai.cached ? ` · ${pick(CACHED)}` : ""}
        </span>
      )}
    </>
  );
  return (
    <section className="result-card registration-panel" aria-labelledby="h-owner">
      {showHeader ? (
        <SectionHead id="h-owner" icon={<UserIcon size={15} />} title={t("registrant")} meta={rows.length ? tf("publicFields", { n: rows.length + extras.length }) : undefined}>
          {allSources.length > 0 && (
            <span className="source-caption">
              {t("source")}
              <SourceTags sources={allSources} />
            </span>
          )}
        </SectionHead>
      ) : (
        <h2 id="h-owner" className="sr-only">{t("registrant")}</h2>
      )}
      {hasAIStatus && <div className="section-inline-badges">{aiBadge}</div>}
      {rows.length === 0 && extras.length === 0 ? (
        aiLoading ? (
          <p className="section-note">{t("aiChecking")}</p>
        ) : pending ? (
          <div className="pending-block" role="status" aria-label={t("searching")}>
            <span className="pending-line" />
            <span className="pending-line short" />
            <span className="pending-line" />
            <span className="pending-line short" />
          </div>
        ) : (
          <RegistrarContact result={result} />
        )
      ) : (
        <dl className="kv-list">
          {rows.map((row) => {
            // Combined rows (location = province + country) list each source once.
            const sources = row.sourceKeys
              .flatMap((key) => registrant.fieldSources?.[key] || [])
              .filter((item, index, all) => all.findIndex((other) => other.source === item.source) === index);
            const fallback = !sources.length && registrant.source ? [{ label: row.label, value: row.value, source: registrant.source, confidence: registrant.confidence, evidence: registrant.evidence }] : sources;
            return (
              <div className="kv-row" key={row.key}>
                <dt>{row.label}</dt>
                <dd className={row.strong ? "strong" : row.muted ? "muted" : undefined}>
                  <span className="kv-value" onDoubleClick={() => onCopy(row.value)}>{linkifyValue(row.value)}</span>
                  <SourcePopovers sources={fallback} />
                </dd>
              </div>
            );
          })}
          {extras.map((field, index) => (
            <div className="kv-row" key={`${field.label}-${index}`}>
              <dt>{field.label}</dt>
              <dd>
                <span className="kv-value">{linkifyValue(field.value)}</span>
                <SourcePopovers sources={[field]} />
              </dd>
            </div>
          ))}
        </dl>
      )}
      {icpDomain && <ICPBlock domain={icpDomain} state={icpState} filing={result.enrichment?.icpFiling} onLookup={onICPLookup} />}
      {/* The contact block above already names the registrar when no registrant is public. */}
      {!(rows.length === 0 && extras.length === 0 && (result.registrar?.email || result.registrar?.phone || result.registrar?.address)) && <RegistrarDetails result={result} />}
    </section>
  );
}

/**
 * Shown when no registrant field is public: many registries (CoCCA's .sb,
 * GDPR-redacted gTLDs) only publish the registrar, who is the way to reach
 * the holder.
 */
function RegistrarContact({ result }: { result: LookupResult }) {
  const { t, locale } = useI18n();
  const pick = useT3();
  const registrar = result.registrar || {};
  const hasContact = Boolean(registrar.email || registrar.phone || registrar.address);
  if (!registrar.name || !hasContact) return <p className="section-note">{t("noRegistration")}</p>;
  const website = safeExternalURL(registrar.url || registrar.brand?.website);
  return (
    <div className="registrar-contact">
      <p className="section-note">
        {pick(t3(
          "The registry does not publish the registrant. Reach the holder through the registrar:",
          "注册局未公开注册人信息，可通过注册商联系持有人：",
          "註冊局未公開註冊人資訊，可透過註冊商聯絡持有人：",
        ))}
      </p>
      <dl className="kv-list compact">
        <div className="kv-row">
          <dt>{t("registrar")}</dt>
          <dd className="strong">{website ? <a href={website} target="_blank" rel="noopener noreferrer">{registrar.name}</a> : registrar.name}</dd>
        </div>
        {registrar.email && (
          <div className="kv-row">
            <dt>{pick(t3("Email", "邮箱", "電子郵件"))}</dt>
            <dd><a href={`mailto:${registrar.email}`}>{registrar.email}</a></dd>
          </div>
        )}
        {registrar.phone && (
          <div className="kv-row">
            <dt>{pick(t3("Phone", "电话", "電話"))}</dt>
            <dd className="mono">{registrar.phone}</dd>
          </div>
        )}
        {registrar.address && (
          <div className="kv-row">
            <dt>{pick(t3("Address", "地址", "地址"))}</dt>
            <dd>{[registrar.address, countryName(registrar.country, locale)].filter(Boolean).join(", ")}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

function RegistrarDetails({ result }: { result: LookupResult }) {
  const { t, locale } = useI18n();
  const registrar = result.registrar || {};
  if (!registrar.name && !registrar.ianaId) return null;
  const website = safeExternalURL(registrar.url || registrar.brand?.website);
  return (
    <div className="detail-block narrow-only">
      <strong className="detail-block-title">{t("registrar")}</strong>
      <dl className="kv-list compact">
        {registrar.name && (
          <div className="kv-row">
            <dt>{t("entityName")}</dt>
            <dd>
              <span className="dot" style={{ background: registrar.brand?.color || "var(--ns-brand-6)" }} aria-hidden="true" />
              {registrar.name}
              {registrar.source && <SourceTags sources={[sourceTag(registrar.source)]} />}
            </dd>
          </div>
        )}
        {registrar.ianaId && (
          <div className="kv-row"><dt>IANA ID</dt><dd className="mono">{registrar.ianaId}</dd></div>
        )}
        {registrar.country && (
          <div className="kv-row"><dt>{t("country")}</dt><dd>{countryName(registrar.country, locale)}</dd></div>
        )}
        {website && (
          <div className="kv-row"><dt>{t("website")}</dt><dd><a href={website} target="_blank" rel="noreferrer">{website.replace(/^https?:\/\//, "").replace(/\/$/, "")}</a></dd></div>
        )}
        {registrar.whoisServer && (
          <div className="kv-row"><dt>WHOIS</dt><dd className="mono">{registrar.whoisServer}</dd></div>
        )}
      </dl>
    </div>
  );
}

function icpErrorMessage(state: ICPState, t: (key: any) => string) {
  if (state.errorCode === "icp_disabled" || state.httpStatus === 503) return t("icpDisabled");
  if (state.errorCode === "icp_route_missing" || state.httpStatus === 404) return t("icpRouteMissing");
  if (state.errorCode === "api_unreachable") return t("icpUnreachable");
  return state.error ? `${t("icpUnavailable")}: ${state.error}` : t("icpUnavailable");
}

// Whether the suffix is on MIIT's ICP-fileable list. It is a property of the
// suffix, known without querying the filing system.
function ICPFilingTag({ filing }: { filing?: LookupResult["enrichment"]["icpFiling"] }) {
  const pick = useT3();
  if (!filing) return null;
  const suffix = `.${filing.suffix}`;
  return filing.eligible ? (
    <span
      className="pill pill-accent"
      title={pick(t3(`${suffix} is on MIIT's list of ICP-fileable suffixes`, `${suffix} 在工信部可备案后缀名单内`, `${suffix} 在工信部可備案後綴名單內`))}
    >
      {pick(t3("Fileable suffix", "后缀可备案", "後綴可備案"))}
    </span>
  ) : (
    <span
      className="pill pill-dashed"
      title={pick(t3(`${suffix} is not on MIIT's list of ICP-fileable suffixes`, `${suffix} 不在工信部可备案后缀名单内，无法办理 ICP 备案`, `${suffix} 不在工信部可備案後綴名單內，無法辦理 ICP 備案`))}
    >
      {pick(t3("Suffix not fileable", "后缀不可备案", "後綴不可備案"))}
    </span>
  );
}

function ICPBlock({ domain, state, filing, onLookup }: { domain: string; state: ICPState; filing?: LookupResult["enrichment"]["icpFiling"]; onLookup: () => void }) {
  const { t } = useI18n();
  const pick = useT3();
  const records = state.result?.records || [];
  const found = state.result?.status === "found" && records.length > 0;
  const checked = state.requested && !state.loading;
  const summary = !state.requested
    ? t("icpNotQueried")
    : state.loading
      ? t("icpLoading")
      : state.error
        ? icpErrorMessage(state, t)
        : found
          ? records[0].serviceLicence || records[0].mainLicence || domain
          : t("icpNone");
  return (
    <div className={`icp-block icp-panel ${state.error ? "is-error" : ""}`}>
      <div className="icp-row">
        <span className="icp-glyph" aria-hidden="true">{pick(t3("ICP", "备", "備"))}</span>
        <span className="icp-text">
          <strong>
            {t("icpTitle")}
            <ICPFilingTag filing={filing} />
            {found && <span className="pill pill-green">{t("icpFound")}</span>}
            {state.result?.cached && <CacheTag cachedAt={state.result.cachedAt} />}
          </strong>
          <span className="icp-summary">{summary}</span>
        </span>
        <button type="button" className="btn btn-outline-accent" onClick={onLookup} disabled={state.loading}>
          <SearchIcon size={13} />
          {state.loading ? t("icpQuerying") : checked ? t("icpRefresh") : t("icpQuery")}
        </button>
      </div>
      {found && (
        <dl className="kv-list compact icp-records">
          {records.slice(0, 2).map((record, index) => (
            <div className="icp-record" key={`${record.serviceLicence}-${index}`}>
              {record.unitName && <div className="kv-row"><dt>{t("icpUnit")}</dt><dd>{record.unitName}</dd></div>}
              {record.natureName && <div className="kv-row"><dt>{t("icpNature")}</dt><dd>{record.natureName}</dd></div>}
              {record.mainLicence && <div className="kv-row"><dt>{t("icpMainLicence")}</dt><dd className="mono">{record.mainLicence}</dd></div>}
              {record.serviceName && <div className="kv-row"><dt>{t("icpServiceName")}</dt><dd>{record.serviceName}</dd></div>}
              {record.updateRecordTime && <div className="kv-row"><dt>{t("icpReviewed")}</dt><dd className="mono">{record.updateRecordTime}</dd></div>}
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

/* ---------- Network (IP / ASN) ---------- */

export function NetworkSection({ result, showHeader = true }: { result: LookupResult; showHeader?: boolean }) {
  const { t, locale } = useI18n();
  const network = result.network || {};
  const rows: [string, string | undefined, boolean?][] = [
    [t("range"), network.range, true],
    [t("cidr"), network.cidr, true],
    [t("entityName"), network.name],
    [t("type"), network.type],
    [t("originAs"), network.originAS, true],
    [t("country"), countryName(network.country, locale)],
  ];
  const present = rows.filter(([, value]) => value);
  return (
    <section className="result-card network-panel dns-panel" aria-labelledby="h-network">
      {showHeader ? <SectionHead id="h-network" icon={<NetworkIcon size={15} />} title={t("networkInfo")} /> : <h2 id="h-network" className="sr-only">{t("networkInfo")}</h2>}
      {present.length ? (
        <dl className="kv-list">
          {present.map(([label, value, mono]) => (
            <div className="kv-row" key={label}>
              <dt>{label}</dt>
              <dd className={mono ? "mono" : undefined}>{value}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="section-note">{t("noNetwork")}</p>
      )}
    </section>
  );
}

/* ---------- Sources ---------- */

export const TRUNCATED = t3("Truncated", "已截断", "已截斷");
export const TRUNCATED_DETAIL = t3(
  "Truncated: DNS confirmed the result first, so the lookup stopped waiting for this server (its suffix is on the DNS-first list).",
  "已截断：DNS 已先确认结果，不再等待该服务器（后缀在“DNS 优先”名单中）。",
  "已截斷：DNS 已先確認結果，不再等待該伺服器（後綴在「DNS 優先」名單中）。",
);

const rawLabelKey: Partial<Record<string, "rawRdap" | "rawWhois">> = { rdap: "rawRdap", whois: "rawWhois", whoisWeb: "rawWhois" };

const SOURCE_ORDER = ["rdap", "whois", "whoisWeb", "dns"];

export function SourcesSection({
  result,
  warnings,
  pendingSources = [],
  onOpenRaw,
  showHeader = true,
}: {
  result: LookupResult;
  warnings: string[];
  /** Sources still being queried; they keep their row while they run. */
  pendingSources?: string[];
  onOpenRaw: (tab: RawTab) => void;
  showHeader?: boolean;
}) {
  const { t } = useI18n();
  const pick = useT3();
  const providers = Array.isArray(result.meta?.providers) ? result.meta.providers : [];
  const primary = result.source?.primary;
  const listed = new Set(providers.map((item) => item.source));
  const waiting = pendingSources.filter((source) => !listed.has(source as never));
  const used = Array.isArray(result.source?.used) ? result.source.used : [];
  const rawFor = (source: string) => (source === "rdap" ? result.raw?.rdap : source === "whois" ? result.raw?.whois : source === "whoisWeb" ? result.raw?.whoisWeb : source === "dns" ? result.raw?.dns : undefined);
  const missing = (["rdap", "whois", "whoisWeb", "dns"] as const).filter((source) => !listed.has(source) && (used.includes(source) || rawFor(source)));
  const unused = (["rdap", "whois", "whoisWeb"] as const).filter((source) => !listed.has(source) && !used.includes(source) && !rawFor(source) && !waiting.includes(source));
  // Rows keep a fixed source order, so streamed answers fill rows in place.
  const rank = (source: string) => {
    const index = SOURCE_ORDER.indexOf(source);
    return index < 0 ? SOURCE_ORDER.length : index;
  };
  const registry = result.registry || {};
  // A failed source is only greyed out while another registry source answered.
  const quiet = providers.some((item) => item.status === "ok" && item.source !== "dns");
  return (
    <section id="evidence" className="result-card sources-panel" aria-labelledby="h-evidence">
      {showHeader ? (
        <SectionHead id="h-evidence" icon={<TerminalIcon size={15} />} title={t("sourcesTitle")} meta={<>{t("totalElapsed")} <span className="mono">{result.meta.elapsedMs} ms</span></>} />
      ) : (
        <h2 id="h-evidence" className="sr-only">{t("sourcesTitle")}</h2>
      )}
      <div className="sources-head-narrow">
        <strong>{t("sourcesShort")}</strong>
        <span className="section-meta">{t("totalElapsed")} <span className="mono">{result.meta.elapsedMs} ms</span></span>
      </div>
      {/* Provider rows double as request diagnostics: server, HTTP status, size, latency. */}
      <div className="trace-list">
        {[
        ...providers.map((provider) => {
          const raw = rawFor(provider.source);
          const meta = [provider.statusCode ? `HTTP ${provider.statusCode}` : "", formatBytes(provider.bytes), `${provider.elapsedMs} ms`].filter(Boolean).join(" · ");
          return { source: provider.source, node: (
            <div className={`trace-row trace-${provider.status}${quiet && provider.status === "error" ? " trace-quiet" : ""}`} key={`${provider.source}-${provider.server || provider.elapsedMs}`}>
              <span className="trace-name">
                <span className={`dot ${provider.status === "ok" ? "dot-ok" : provider.status === "error" ? (quiet ? "dot-hollow" : "dot-error") : provider.status === "stopped" ? "dot-stopped" : "dot-hollow"}`} aria-hidden="true" />
                {sourceName(provider.source)}
                {provider.source === primary && <span className="pill pill-accent pill-xs">{t("primarySource")}</span>}
              </span>
              <span className="trace-detail">
                <span className="trace-server">{displayServer(provider.server) || "—"}</span>
                <span className="trace-meta" title={provider.status === "stopped" ? provider.error : undefined}>
                  {provider.status === "error"
                    ? `${t("providerFailed")} · ${provider.error || meta}`
                    : provider.status === "stopped"
                      ? pick(TRUNCATED_DETAIL)
                      : provider.status === "skipped"
                        ? provider.error || t("notUsed")
                        : meta}
                </span>
              </span>
              {raw ? (
                <button type="button" className="btn btn-sm" onClick={() => onOpenRaw(provider.source as RawTab)} title={rawLabelKey[provider.source] ? t(rawLabelKey[provider.source]!) : undefined}>
                  <FileIcon size={13} className="btn-icon" />
                  {t("viewRaw")}
                </button>
              ) : (
                <span />
              )}
            </div>
          ) };
        }),
        ...missing.map((source) => ({ source, node: (
          <div className="trace-row trace-ok" key={source}>
            <span className="trace-name">
              <span className="dot dot-ok" aria-hidden="true" />
              {sourceName(source)}
              {source === primary && <span className="pill pill-accent pill-xs">{t("primarySource")}</span>}
            </span>
            <span className="trace-detail">
              <span className="trace-server">{displayServer(source === "rdap" ? registry.rdapServer : source === "whois" ? registry.whoisServer : "") || "—"}</span>
              <span className="trace-meta">{formatBytes(rawFor(source)?.length)}</span>
            </span>
            {rawFor(source) ? (
              <button type="button" className="btn btn-sm" onClick={() => onOpenRaw(source)}>
                <FileIcon size={13} className="btn-icon" />
                {t("viewRaw")}
              </button>
            ) : (
              <span />
            )}
          </div>
        ) })),
        ...waiting.map((source) => ({ source, node: (
          <div className="trace-row trace-pending" key={source} role="status">
            <span className="trace-name">
              <span className="dot dot-hollow pulse" aria-hidden="true" />
              {sourceName(source)}
            </span>
            <span className="trace-detail">
              <span className="trace-server">{displayServer(source === "rdap" ? registry.rdapServer : source === "whois" ? registry.whoisServer : "") || "—"}</span>
              <span className="trace-meta">{t("searching")}</span>
            </span>
            <span />
          </div>
        ) })),
        ...unused.map((source) => ({ source, node: (
          <div className="trace-row trace-unused" key={source}>
            <span className="trace-name">
              <span className="dot dot-hollow" aria-hidden="true" />
              {sourceName(source)}
            </span>
            <span className="trace-meta">{t("notUsed")}</span>
          </div>
        ) })),
        ]
          .sort((x, y) => rank(x.source) - rank(y.source))
          .map((row) => row.node)}
      </div>
      <WarningList warnings={warnings} />
      {(registry.name || registry.rdapServer || registry.whoisServer) && (
        <div className="detail-block narrow-only">
          <strong className="detail-block-title">{t("registryLabel")}</strong>
          <dl className="kv-list compact">
            {registry.name && <div className="kv-row"><dt>{t("entityName")}</dt><dd>{registry.name}</dd></div>}
            {registry.website && <div className="kv-row"><dt>{t("website")}</dt><dd><a href={safeExternalURL(registry.website)} target="_blank" rel="noreferrer">{registry.website.replace(/^https?:\/\//, "")}</a></dd></div>}
            {registry.rdapServer && <div className="kv-row"><dt>RDAP</dt><dd className="mono">{displayServer(registry.rdapServer)}</dd></div>}
            {registry.whoisServer && <div className="kv-row"><dt>WHOIS</dt><dd className="mono">{registry.whoisServer}</dd></div>}
          </dl>
        </div>
      )}
    </section>
  );
}
