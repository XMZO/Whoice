import Head from "next/head";
import Link from "next/link";
import type { GetServerSideProps } from "next";
import { AppControls } from "@/components/AppControls";
import { getServerAPIBase } from "@/lib/serverApi";
import type { APIResponse } from "@/lib/types";
import { useI18n } from "@/lib/i18n";

type Capabilities = NonNullable<APIResponse["capabilities"]>;

type HealthResponse = {
  ok?: boolean;
  version?: string;
  time?: string;
};

type PluginInfo = {
  kind: string;
  name: string;
  version: string;
  enabled: boolean;
};

type VersionResponse = {
  version?: string;
  data?: Record<string, string>;
  capabilities?: Capabilities;
  plugins?: PluginInfo[];
};

type FetchState<T> = {
  ok: boolean;
  status: number;
  data?: T;
  error?: string;
};

type Props = {
  health: FetchState<HealthResponse>;
  version: FetchState<VersionResponse>;
  capabilities: FetchState<APIResponse>;
};

async function fetchJSON<T>(path: string): Promise<FetchState<T>> {
  const base = getServerAPIBase().replace(/\/$/, "");
  try {
    const response = await fetch(`${base}${path}`, { headers: { accept: "application/json" }, cache: "no-store" });
    const text = await response.text();
    const data = text ? (JSON.parse(text) as T) : undefined;
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      error: error instanceof Error ? error.message : "Lookup API is unreachable.",
    };
  }
}

export const getServerSideProps: GetServerSideProps<Props> = async () => {
  const [health, version, capabilities] = await Promise.all([
    fetchJSON<HealthResponse>("/api/health"),
    fetchJSON<VersionResponse>("/api/version"),
    fetchJSON<APIResponse>("/api/capabilities"),
  ]);

  return {
    props: {
      health,
      version,
      capabilities,
    },
  };
};

function boolLabel(value?: boolean) {
  if (value === undefined) return "unknown";
  return value ? "enabled" : "disabled";
}

function StatusPill({ ok, children }: { ok: boolean; children: string }) {
  return <span className={ok ? "status-pill ok" : "status-pill off"}>{children}</span>;
}

function CapabilityGrid({ capabilities }: { capabilities?: Capabilities }) {
  const enrichment = capabilities?.enrichment || {};
  const core = [
    ["RDAP", capabilities?.rdap],
    ["WHOIS", capabilities?.whois],
    ["WHOIS Web", capabilities?.whoisWeb],
    ["Custom servers", capabilities?.customServers],
    ["Rate limit", capabilities?.rateLimit],
  ] as const;
  const enrichers = Object.entries(enrichment).sort(([left], [right]) => left.localeCompare(right));

  return (
    <div className="capability-grid" aria-label="Runtime capabilities">
      {core.map(([name, enabled]) => (
        <div className="capability-item" key={name}>
          <span>{name}</span>
          <StatusPill ok={Boolean(enabled)}>{boolLabel(enabled)}</StatusPill>
        </div>
      ))}
      <div className="capability-item">
        <span>Auth</span>
        <StatusPill ok={Boolean(capabilities?.auth && capabilities.auth !== "none")}>{capabilities?.auth || "unknown"}</StatusPill>
      </div>
      {enrichers.map(([name, enabled]) => (
        <div className="capability-item" key={name}>
          <span>{name}</span>
          <StatusPill ok={enabled}>{boolLabel(enabled)}</StatusPill>
        </div>
      ))}
    </div>
  );
}

function PluginList({ plugins }: { plugins?: PluginInfo[] }) {
  const groups = (plugins || []).reduce<Record<string, PluginInfo[]>>((acc, plugin) => {
    acc[plugin.kind] = acc[plugin.kind] || [];
    acc[plugin.kind].push(plugin);
    return acc;
  }, {});
  const entries = Object.entries(groups).sort(([left], [right]) => left.localeCompare(right));

  if (entries.length === 0) {
    return <p className="muted">No plugin descriptors were reported.</p>;
  }

  return (
    <div className="plugin-groups" aria-label="Runtime plugins">
      {entries.map(([kind, items]) => (
        <section className="plugin-group" key={kind}>
          <h3>{kind}</h3>
          <div className="plugin-list compact">
            {items
              .slice()
              .sort((left, right) => left.name.localeCompare(right.name))
              .map((plugin) => (
                <div className="plugin-item compact" key={`${plugin.kind}-${plugin.name}`}>
                  <strong>{plugin.name}</strong>
                  <span>{plugin.version}</span>
                  <StatusPill ok={plugin.enabled}>{plugin.enabled ? "enabled" : "disabled"}</StatusPill>
                </div>
              ))}
          </div>
        </section>
      ))}
    </div>
  );
}

export default function StatusPage({ health, version, capabilities }: Props) {
  const { t } = useI18n();
  const apiCaps = version.data?.capabilities || capabilities.data?.capabilities;
  const healthOK = health.ok && Boolean(health.data?.ok);
  const apiVersion = version.data?.version || health.data?.version || "unknown";

  return (
    <>
      <Head>
        <title>Status | Whoice</title>
      </Head>
      <main className="shell docs-shell">
        <nav className="top-nav">
          <Link href="/" className="brand">Whoice</Link>
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <AppControls />
          </div>
        </nav>

        <section className="status-strip">
          <div>
            <p className="eyebrow">Runtime</p>
            <h1>System status</h1>
          </div>
          <div className="status-badges">
            <StatusPill ok={healthOK}>{healthOK ? "healthy" : "degraded"}</StatusPill>
            <span>api {apiVersion}</span>
            {health.data?.time && <span>{health.data.time}</span>}
          </div>
        </section>

        {!healthOK && (
          <section className="panel error-panel">
            <p className="eyebrow">API</p>
            <h1>Lookup API is not healthy</h1>
            <p className="muted">{health.error || `HTTP ${health.status}`}</p>
          </section>
        )}

        <section className="panel">
          <div className="panel-head">
            <h2>Capabilities</h2>
          </div>
          <CapabilityGrid capabilities={apiCaps} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>Plugins</h2>
          </div>
          <PluginList plugins={version.data?.plugins} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>API endpoints</h2>
          </div>
          <div className="endpoint-list">
            {["/api/health", "/api/version", "/api/capabilities", "/api/metrics"].map((endpoint) => (
              <a href={endpoint} key={endpoint}>
                <span>{endpoint}</span>
                <span>same-origin proxy</span>
              </a>
            ))}
          </div>
        </section>
      </main>
    </>
  );
}
