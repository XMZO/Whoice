import type { CSSProperties, ReactNode } from "react";
import type { LookupResult, PricingOffer } from "./types";

export type ResultPluginSlot = "details" | "debug";

export type ResultPlugin = {
  id: string;
  slot: ResultPluginSlot;
  order: number;
  enabled: (result: LookupResult) => boolean;
  render: (result: LookupResult) => ReactNode;
};

export type ResultPluginRenderOptions = {
  pending?: string[];
  enrichmentLoading?: boolean;
  enrichmentError?: string;
  lockSlots?: boolean;
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

function statusesOf(result: LookupResult) {
  return Array.isArray(result.statuses) ? result.statuses : [];
}

function nameserversOf(result: LookupResult) {
  return Array.isArray(result.nameservers) ? result.nameservers : [];
}

function EPPStatusPanel({ result }: { result: LookupResult }) {
  const enriched = statusesOf(result).filter((status) => status.description || status.category || status.url);
  if (enriched.length === 0) return null;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>EPP Details</h2>
      </div>
      <div className="plugin-list">
        {enriched.map((status) => (
          <div className="plugin-item" key={`${status.code}-${status.source || ""}`}>
            <strong>{status.label || status.code}</strong>
            {status.category && <span>{status.category}</span>}
            {status.description && <p>{status.description}</p>}
          </div>
        ))}
      </div>
    </section>
  );
}

function BrandPanel({ result }: { result: LookupResult }) {
  const registrarBrand = result.registrar?.brand;
  const nsBrands = nameserversOf(result).filter((ns) => ns.brand);
  if (!registrarBrand && nsBrands.length === 0) return null;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Brands</h2>
      </div>
      <dl className="detail-list">
        <Row label="Registrar" value={<BrandValue name={registrarBrand?.name} color={registrarBrand?.color} />} />
        <Row
          label="Nameservers"
          value={
            <span className="brand-stack">
              {nsBrands.map((ns) => (
                <span key={ns.host}>
                  {ns.host} <BrandValue name={ns.brand?.name} color={ns.brand?.color} />
                </span>
              ))}
            </span>
          }
        />
      </dl>
    </section>
  );
}

function BrandValue({ name, color }: { name?: string; color?: string }) {
  if (!name) return null;
  const style = color ? ({ "--brand-swatch": color } as CSSProperties) : undefined;
  return (
    <span className="brand-value">
      {color && <span className="brand-swatch" style={style} aria-hidden="true" />}
      {name}
    </span>
  );
}

function DNSVizPanel({ result }: { result: LookupResult }) {
  const url = result.enrichment?.dnsviz?.url;
  if (!url) return null;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>DNSViz</h2>
      </div>
      <p className="muted">External DNSSEC and delegation diagnostics for this domain.</p>
      <a className="inline-action" href={url} target="_blank" rel="noreferrer">
        Open DNSViz
      </a>
    </section>
  );
}

function PricingPanel({ result }: { result: LookupResult }) {
  const pricing = result.enrichment?.pricing;
  if (!pricing) return null;
  const currency = pricing.currency || "USD";
  const register = pricing.registerOffer ?? fallbackPricingOffer(pricing.register, currency, pricing.provider);
  const renew = pricing.renewOffer ?? fallbackPricingOffer(pricing.renew, currency, pricing.provider);
  const transfer = pricing.transferOffer ?? fallbackPricingOffer(pricing.transfer, currency, pricing.provider);
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Pricing</h2>
      </div>
      <div className="metric-grid">
        <PricingMetric label="Register" offer={register} fallbackCurrency={currency} />
        <PricingMetric label="Renew" offer={renew} fallbackCurrency={currency} />
        <PricingMetric label="Transfer" offer={transfer} fallbackCurrency={currency} />
      </div>
      <dl className="detail-list compact-details">
        <Row label="Provider" value={pricing.provider} />
        <Row label="Source" value={pricing.source} />
        <Row label="Updated" value={pricing.updatedAt} />
      </dl>
    </section>
  );
}

function PricingMetric({
  label,
  offer,
  fallbackCurrency,
}: {
  label: string;
  offer?: PricingOffer;
  fallbackCurrency: string;
}) {
  const currency = offer?.currency || fallbackCurrency;
  const price = offer?.price;
  const value = formatMoney(price, currency);
  const registrar = offer?.registrar;
  const secondary = registrar ? (
    offer?.website ? (
      <a href={offer.website} target="_blank" rel="noreferrer">
        {registrar}
      </a>
    ) : (
      registrar
    )
  ) : null;
  return <Metric label={label} value={value} hint={secondary} />;
}

function MozPanel({ result }: { result: LookupResult }) {
  const moz = result.enrichment?.moz;
  if (!moz) return null;
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Moz</h2>
      </div>
      <div className="metric-grid">
        <Metric label="DA" value={moz.domainAuthority} />
        <Metric label="PA" value={moz.pageAuthority} />
        <Metric label="Spam" value={moz.spamScore} />
      </div>
      <dl className="detail-list compact-details">
        <Row label="Source" value={moz.source} />
        <Row label="Updated" value={moz.updatedAt} />
      </dl>
    </section>
  );
}

function DeferredPanel({
  title,
  name,
  loading,
  error,
}: {
  title: string;
  name: string;
  loading?: boolean;
  error?: string;
}) {
  const message = error
    ? `${title} data did not update.`
    : loading
      ? `${title} is updating in the background.`
      : `${title} data is not available for this result.`;
  const stateClass = error ? "is-error" : loading ? "is-loading" : "is-empty";
  return (
    <section className={`panel deferred-panel ${stateClass}`} aria-busy={loading ? "true" : undefined}>
      <div className="panel-head">
        <h2>{title}</h2>
        <div className="panel-status-slot">
          <span className={`source-hint ${error ? "ai-error" : loading ? "ai-pending" : ""}`}>{error ? "error" : loading ? "loading" : "empty"}</span>
        </div>
      </div>
      <p className="muted">{message}</p>
      {loading && (
        <div className="metric-grid pending-metric-grid" aria-hidden="true">
          <span className="pending-metric" />
          <span className="pending-metric" />
          <span className="pending-metric" />
        </div>
      )}
      <span className="sr-only">{name} enrichment placeholder</span>
    </section>
  );
}

function Metric({
  label,
  value,
  hint,
}: {
  label: string;
  value?: string | number;
  hint?: ReactNode;
}) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <div className="metric-item">
      <span>{label}</span>
      <strong>{value}</strong>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

function fallbackPricingOffer(price: number | undefined, currency: string, registrar?: string): PricingOffer | undefined {
  if (price === undefined || price === null) return undefined;
  return { price, currency, registrar };
}

function formatMoney(value: number | undefined, currency: string) {
  if (value === undefined || value === null) return undefined;
  return new Intl.NumberFormat("en", { currency, style: "currency" }).format(value);
}

function ProviderTracePanel({ result }: { result: LookupResult }) {
  const traces = Array.isArray(result.meta?.providers) ? result.meta.providers : [];
  if (traces.length === 0) return null;
  return (
    <details className="panel diagnostic-panel">
      <summary className="panel-summary">
        <h2>Provider Trace</h2>
        <span>{traces.length} providers</span>
      </summary>
      <div className="trace-list">
        {traces.map((trace) => (
          <div className={`trace-item trace-${trace.status}`} key={`${trace.source}-${trace.server || trace.error || trace.elapsedMs}`}>
            <div>
              <strong>{trace.source}</strong>
              <span>{trace.status}</span>
            </div>
            <dl>
              <Row label="Server" value={trace.server} />
              <Row label="HTTP" value={trace.statusCode} />
              <Row label="Bytes" value={trace.bytes} />
              <Row label="Elapsed" value={`${trace.elapsedMs} ms`} />
              <Row label="Error" value={trace.error} />
            </dl>
          </div>
        ))}
      </div>
    </details>
  );
}

export const resultPlugins: ResultPlugin[] = [
  {
    id: "epp-status",
    slot: "details",
    order: 20,
    enabled: (result) => statusesOf(result).some((status) => Boolean(status.description || status.category)),
    render: (result) => <EPPStatusPanel result={result} />,
  },
  {
    id: "brands",
    slot: "details",
    order: 30,
    enabled: (result) => Boolean(result.registrar?.brand || nameserversOf(result).some((ns) => ns.brand)),
    render: (result) => <BrandPanel result={result} />,
  },
  {
    id: "dnsviz",
    slot: "details",
    order: 40,
    enabled: (result) => Boolean(result.enrichment?.dnsviz?.url),
    render: (result) => <DNSVizPanel result={result} />,
  },
  {
    id: "pricing",
    slot: "details",
    order: 50,
    enabled: (result) => Boolean(result.enrichment?.pricing),
    render: (result) => <PricingPanel result={result} />,
  },
  {
    id: "moz",
    slot: "details",
    order: 60,
    enabled: (result) => Boolean(result.enrichment?.moz),
    render: (result) => <MozPanel result={result} />,
  },
  {
    id: "provider-trace",
    slot: "debug",
    order: 10,
    enabled: (result) => Boolean(result.meta?.providers?.length),
    render: (result) => <ProviderTracePanel result={result} />,
  },
];

export function renderResultPlugins(slot: ResultPluginSlot, result: LookupResult, options: ResultPluginRenderOptions = {}) {
  const rendered = resultPlugins
    .filter((plugin) => plugin.slot === slot && plugin.enabled(result))
    .map((plugin) => ({ id: plugin.id, order: plugin.order, node: plugin.render(result) }));

  if (slot === "details") {
    const pending = new Set(options.pending || []);
    const present = new Set(rendered.map((item) => item.id));
    for (const item of [
      { id: "epp-status", names: ["epp"], title: "EPP Details", order: 20 },
      { id: "brands", names: ["brand", "brands"], title: "Brands", order: 30 },
      { id: "dnsviz", names: ["dnsviz"], title: "DNSViz", order: 40 },
      { id: "pricing", names: ["pricing"], title: "Pricing", order: 50 },
      { id: "moz", names: ["moz"], title: "Moz", order: 60 },
    ]) {
      const isPending = item.names.some((name) => pending.has(name));
      if ((!options.lockSlots && !isPending) || present.has(item.id)) continue;
      rendered.push({
        id: `${item.id}-pending`,
        order: item.order,
        node: <DeferredPanel title={item.title} name={item.names[0]} loading={isPending && options.enrichmentLoading} error={isPending ? options.enrichmentError : undefined} />,
      });
    }
  }

  return rendered
    .sort((a, b) => a.order - b.order)
    .map((item) => <div className="plugin-shell" key={item.id}>{item.node}</div>);
}
