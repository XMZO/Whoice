import type { ReactNode } from "react";
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
import type { ICPResult, LookupResult, PricingOffer } from "@/lib/types";
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

/* ---------- Hero metrics and locks ---------- */

function Metric({ icon, label, value, sub, tone, badge }: { icon: ReactNode; label: string; value: ReactNode; sub?: ReactNode; tone?: "ok" | "warn" | "danger"; badge?: string }) {
  return (
    <div className={`metric${tone ? ` metric-${tone}` : ""}`}>
      <span className="metric-icon" aria-hidden="true">{icon}</span>
      <span className="metric-body">
        <span className="metric-label">{label}</span>
        <strong className="metric-value">
          {value}
          {badge && <span className="metric-badge">{badge}</span>}
        </strong>
        {sub && <span className="metric-sub">{sub}</span>}
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

export function DomainMetrics({ result }: { result: LookupResult }) {
  const { t, tf, locale } = useI18n();
  const registrar = result.registrar || {};
  const dates = result.dates || {};
  const country = countryName(registrar.country, locale);
  const registrarSub = [registrar.ianaId ? `IANA ${registrar.ianaId}` : "", country].filter(Boolean).join(" · ");
  const ageDays = dates.ageDays;
  const years = ageDays !== undefined && ageDays !== null ? Math.floor(ageDays / 365.25) : undefined;
  const ageValue = years === undefined ? t("notProvided") : years >= 1 ? tf("durYears", { n: years }) : tf("durDays", { n: ageDays ?? 0 });
  const ageBadge = ageDays === undefined || ageDays === null ? undefined : ageDays < 90 ? t("newDomain") : ageDays >= 3650 ? t("oldDomain") : ageDays >= 1095 ? t("matureDomain") : undefined;
  const remaining = dates.remainingDays;
  const remainingValue = remaining === undefined || remaining === null ? t("notProvided") : remaining < 0 ? tf("expiredDays", { n: Math.abs(remaining) }) : tf("durDays", { n: remaining });
  const updated = sinceLabel(dates.updatedAt, tf, t);
  return (
    <div className="metric-grid summary-panel">
      <Metric icon={<BuildingIcon />} label={t("registrar")} value={registrar.name || t("noRegistrar")} sub={registrarSub || undefined} />
      <Metric icon={<CalendarIcon />} label={t("registrationAge")} value={ageValue} badge={ageBadge} sub={<span className="mono">{formatTimestamp(dates.createdAt)}</span>} />
      <Metric icon={<ClockIcon />} label={t("remainingValidity")} value={remainingValue} tone={expiryTone(remaining)} sub={<span className="mono">{formatTimestamp(dates.expiresAt)}</span>} />
      <Metric icon={<RefreshIcon />} label={t("lastUpdated")} value={updated || t("notProvided")} sub={<span className="mono">{formatTimestamp(dates.updatedAt)}</span>} />
    </div>
  );
}

export function NetworkMetrics({ result }: { result: LookupResult }) {
  const { t, locale } = useI18n();
  const network = result.network || {};
  const country = countryName(network.country, locale);
  return (
    <div className="metric-grid summary-panel">
      <Metric icon={<NetworkIcon />} label={t("range")} value={<span className="mono">{network.cidr || network.range || t("notProvided")}</span>} sub={network.cidr && network.range ? <span className="mono">{network.range}</span> : undefined} />
      <Metric icon={<BuildingIcon />} label={t("entityName")} value={network.name || t("notProvided")} sub={network.type} />
      <Metric icon={<GlobeIcon />} label={t("country")} value={country || t("notProvided")} />
      <Metric icon={<TagIcon />} label={t("originAs")} value={<span className="mono">{network.originAS || t("notProvided")}</span>} />
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

export function LockBar({ result }: { result: LookupResult }) {
  const { t, tf } = useI18n();
  const pick = useT3();
  const statuses = Array.isArray(result.statuses) ? result.statuses : [];
  const model = lockModel(statuses);
  const signed = result.dnssec?.signed ?? /^(signed|yes|true)/i.test(result.dnssec?.text || "");
  const dnssecKnown = result.dnssec?.signed !== undefined || Boolean(result.dnssec?.text);
  return (
    <div className="lock-bar status-panel">
      <span className="lock-title">
        <ShieldIcon className="lock-title-icon" />
        {t("securityLocks")}
      </span>
      <span className="lock-group">
        <span className="lock-label">{t("registrarLock")}</span>
        <span className="lock-tags">
          {model.registrar.map((item) => {
            const op = lockOpLabel(item.op, t);
            return item.locked ? (
              <span key={item.op} className="lock-tag locked" title={lockTitle(item.code, true, pick, t("notSet"))}>
                <LockIcon />
                <span className="lock-text-long">{tf("lockedOp", { op })}</span>
                <span className="lock-text-short">{op}</span>
              </span>
            ) : (
              <span key={item.op} className="lock-tag unlocked" title={lockTitle(item.code, false, pick, t("notSet"))}>
                {tf("unlockedOp", { op })}
              </span>
            );
          })}
          {model.hold && <span className="lock-tag hold">{t("holdTag")}</span>}
        </span>
      </span>
      <span className="lock-group">
        <span className="lock-label">{t("registryLock")}</span>
        <span className="lock-tags">
          {model.registryAny ? (
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
        <span className="lock-value mono-cjk">{dnssecKnown ? (signed ? t("dnssecSigned") : t("dnssecUnsigned")) : t("notProvided")}</span>
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
  const dns = result.enrichment?.dns;
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
                  <GroupTitle color={group.color} name={group.name} meta={tf("unitHosts", { n: group.hosts.length })} />
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
                  <ResolverDot key={item.key} label={item.label} status={item.status} detail={item.detail} />
                ))}
              </span>
              <span className="resolver-items resolver-items-detailed">
                {resolverStatusItems(resolvers, t, true).map((item) => (
                  <ResolverDot key={item.key} label={item.label} status={item.status} detail={item.detail} />
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

function ResolverDot({ label, status, detail }: { label: string; status: string; detail?: string }) {
  const { t } = useI18n();
  const failed = status !== "ok";
  const suffix = status === "error" ? (/timeout|deadline/i.test(detail || "") ? t("dnsTimeout") : t("resolverFailed")) : status === "empty" ? t("resolverNoAnswer") : "";
  return (
    <span className={`resolver-group resolver-dot ${failed ? "is-failed" : ""}`} tabIndex={detail ? 0 : undefined}>
      <span className="dot" aria-hidden="true" />
      {label}
      {suffix && ` ${suffix}`}
      {detail && (
        <span className="resolver-tooltip" role="tooltip">
          {detail}
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

function PriceTile({ label, offer, fallbackCurrency }: { label: string; offer?: PricingOffer; fallbackCurrency: string }) {
  const { locale } = useI18n();
  const value = formatMoney(offer?.price, offer?.currency || fallbackCurrency, locale);
  const href = safeExternalURL(offer?.website);
  return (
    <div className="price-tile">
      <span className="price-label">{label}</span>
      <strong className="price-value">{value || "—"}</strong>
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
  const { t } = useI18n();
  const pricing = result.enrichment?.pricing;
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
        </SectionHead>
      ) : (
        <h2 id="h-price" className="sr-only">{t("priceScore")}</h2>
      )}
      <div className="price-head-narrow">
        <strong>{t("priceTitle")}</strong>
        <CacheTag cachedAt={pricing?.cachedAt} />
      </div>
      {pricing ? (
        <div className="price-grid">
          <PriceTile label={t("register")} offer={register} fallbackCurrency={currency} />
          <PriceTile label={t("renew")} offer={renew} fallbackCurrency={currency} />
          <PriceTile label={t("transfer")} offer={transfer} fallbackCurrency={currency} />
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
  const pick = useT3();
  const values = Array.isArray(sources) ? sources.filter((source) => source.source || source.confidence !== undefined || source.evidence) : [];
  if (!values.length) return null;
  return (
    <>
      {values.map((source, index) => (
        <details className="source-popover" key={`${source.source || "source"}-${index}`}>
          <summary className={source.source?.startsWith("ai") ? "src-tag src-tag-ai" : "src-tag"}>
            {sourceTag(source.source) || "?"}
            {source.confidence !== undefined && source.source?.startsWith("ai") ? ` ${Math.round(source.confidence * 100)}%` : ""}
          </summary>
          <span className="source-popover-body">
            {source.value && <span><strong>{pick(t3("Value", "值", "值"))}</strong>{source.value}</span>}
            {source.source && <span><strong>{pick(t3("Source", "来源", "來源"))}</strong>{source.source}</span>}
            {source.confidence !== undefined && <span><strong>{pick(t3("Confidence", "置信度", "信賴度"))}</strong>{Math.round(source.confidence * 100)}%</span>}
            {source.evidence && <span><strong>{pick(t3("Evidence", "依据", "依據"))}</strong>{source.evidence}</span>}
          </span>
        </details>
      ))}
    </>
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
  showHeader = true,
}: {
  result: LookupResult;
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
        <span className={`pill ${ai.status === "error" ? "pill-red" : "pill-accent"}`} title={[ai.provider, ai.model, ai.reason, ai.error, ai.applied?.length ? ai.applied.join(", ") : ""].filter(Boolean).join("\n")}>
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
        <p className="section-note">{aiLoading ? t("aiChecking") : t("noRegistration")}</p>
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
      {icpDomain && <ICPBlock domain={icpDomain} state={icpState} onLookup={onICPLookup} />}
      <RegistrarDetails result={result} />
    </section>
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

function ICPBlock({ domain, state, onLookup }: { domain: string; state: ICPState; onLookup: () => void }) {
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

const rawLabelKey: Partial<Record<string, "rawRdap" | "rawWhois">> = { rdap: "rawRdap", whois: "rawWhois", whoisWeb: "rawWhois" };

export function SourcesSection({
  result,
  warnings,
  onOpenRaw,
  showHeader = true,
}: {
  result: LookupResult;
  warnings: string[];
  onOpenRaw: (tab: RawTab) => void;
  showHeader?: boolean;
}) {
  const { t } = useI18n();
  const providers = Array.isArray(result.meta?.providers) ? result.meta.providers : [];
  const primary = result.source?.primary;
  const ordered = providers.slice().sort((a, b) => (a.source === primary ? -1 : b.source === primary ? 1 : 0));
  const listed = new Set(providers.map((item) => item.source));
  const used = Array.isArray(result.source?.used) ? result.source.used : [];
  const rawFor = (source: string) => (source === "rdap" ? result.raw?.rdap : source === "whois" ? result.raw?.whois : source === "whoisWeb" ? result.raw?.whoisWeb : source === "dns" ? result.raw?.dns : undefined);
  const missing = (["rdap", "whois", "whoisWeb", "dns"] as const).filter((source) => !listed.has(source) && (used.includes(source) || rawFor(source)));
  const unused = (["rdap", "whois", "whoisWeb"] as const).filter((source) => !listed.has(source) && !used.includes(source) && !rawFor(source));
  const registry = result.registry || {};
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
        {ordered.map((provider) => {
          const raw = rawFor(provider.source);
          const meta = [provider.statusCode ? `HTTP ${provider.statusCode}` : "", formatBytes(provider.bytes), `${provider.elapsedMs} ms`].filter(Boolean).join(" · ");
          return (
            <div className={`trace-row trace-${provider.status}`} key={`${provider.source}-${provider.server || provider.elapsedMs}`}>
              <span className="trace-name">
                <span className={`dot ${provider.status === "ok" ? "dot-ok" : provider.status === "error" ? "dot-error" : "dot-hollow"}`} aria-hidden="true" />
                {sourceName(provider.source)}
                {provider.source === primary && <span className="pill pill-accent pill-xs">{t("primarySource")}</span>}
              </span>
              <span className="trace-detail">
                <span className="trace-server">{displayServer(provider.server) || "—"}</span>
                <span className="trace-meta">{provider.status === "error" ? `${t("providerFailed")} · ${provider.error || meta}` : provider.status === "skipped" ? provider.error || t("notUsed") : meta}</span>
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
          );
        })}
        {missing.map((source) => (
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
        ))}
        {unused.map((source) => (
          <div className="trace-row trace-unused" key={source}>
            <span className="trace-name">
              <span className="dot dot-hollow" aria-hidden="true" />
              {sourceName(source)}
            </span>
            <span className="trace-meta">{t("notUsed")}</span>
          </div>
        ))}
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
