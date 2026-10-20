import Head from "next/head";
import Link from "next/link";
import type { GetServerSideProps } from "next";
import { useEffect, useState } from "react";
import { AppControls } from "@/components/AppControls";
import { BrandMark } from "@/components/BrandMark";
import { getServerAPIBase } from "@/lib/serverApi";
import type { APIResponse, ConfigStatus } from "@/lib/types";
import { diagnostic } from "@/lib/diagnostic";
import { useI18n } from "@/lib/i18n";
import { t3, useT3 } from "@/lib/t3";

const TEXT = {
  title: t3("Status", "状态", "狀態"),
  eyebrow: t3("Runtime", "运行时", "執行時"),
  heading: t3("System status", "系统状态", "系統狀態"),
  healthy: t3("healthy", "正常", "正常"),
  degraded: t3("degraded", "异常", "異常"),
  unknown: t3("unknown", "未知", "未知"),
  enabled: t3("enabled", "已启用", "已啟用"),
  disabled: t3("disabled", "已关闭", "已關閉"),
  apiUnhealthy: t3("Lookup API is not healthy", "查询 API 状态异常", "查詢 API 狀態異常"),
  capabilities: t3("Capabilities", "功能", "功能"),
  capabilitiesLabel: t3("Runtime capabilities", "运行时功能", "執行時功能"),
  customServers: t3("Custom servers", "自定义服务器", "自訂伺服器"),
  rateLimit: t3("Rate limit", "限流", "限流"),
  auth: t3("Auth", "鉴权", "驗證"),
  plugins: t3("Plugins", "插件", "外掛"),
  pluginsLabel: t3("Runtime plugins", "运行时插件", "執行時外掛"),
  noPlugins: t3("No plugin descriptors were reported.", "API 未报告任何插件。", "API 未回報任何外掛。"),
  configuration: t3("Configuration", "配置", "設定"),
  hotReloadOk: t3("hot reload ok", "热加载正常", "熱載入正常"),
  rolledBack: t3("rolled back", "已回滚", "已回滾"),
  rolledBackNote: t3(
    "The current config file has an error. Whoice is temporarily using the last valid runtime config loaded at {time}.",
    "当前配置文件有错误，Whoice 暂时使用 {time} 加载的上一份有效配置。",
    "目前設定檔有錯誤，Whoice 暫時使用 {time} 載入的上一份有效設定。",
  ),
  earlier: t3("an earlier time", "更早的时间", "更早的時間"),
  file: t3("File", "文件", "檔案"),
  loaded: t3("Loaded", "加载时间", "載入時間"),
  checked: t3("Checked", "检查时间", "檢查時間"),
  errorTime: t3("Error time", "出错时间", "出錯時間"),
  error: t3("Error", "错误", "錯誤"),
  endpoints: t3("API endpoints", "API 接口", "API 介面"),
  sameOrigin: t3("same-origin proxy", "同源代理", "同源代理"),
};

type Capabilities = NonNullable<APIResponse["capabilities"]>;

type HealthResponse = {
  ok?: boolean;
  version?: string;
  time?: string;
  config?: ConfigStatus;
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
  config?: ConfigStatus;
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
      error: error instanceof Error ? error.message : diagnostic("Lookup API is unreachable."),
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

function useBoolLabel() {
  const pick = useT3();
  return (value?: boolean) => pick(value === undefined ? TEXT.unknown : value ? TEXT.enabled : TEXT.disabled);
}

function StatusPill({ ok, children }: { ok: boolean; children: string }) {
  return <span className={ok ? "status-pill ok" : "status-pill off"}>{children}</span>;
}

function CapabilityGrid({ capabilities }: { capabilities?: Capabilities }) {
  const pick = useT3();
  const boolLabel = useBoolLabel();
  const enrichment = capabilities?.enrichment || {};
  const core = [
    ["RDAP", capabilities?.rdap],
    ["WHOIS", capabilities?.whois],
    ["WHOIS Web", capabilities?.whoisWeb],
    [pick(TEXT.customServers), capabilities?.customServers],
    [pick(TEXT.rateLimit), capabilities?.rateLimit],
  ] as const;
  const enrichers = Object.entries(enrichment).sort(([left], [right]) => left.localeCompare(right));

  return (
    <div className="capability-grid" aria-label={pick(TEXT.capabilitiesLabel)}>
      {core.map(([name, enabled]) => (
        <div className="capability-item" key={name}>
          <span>{name}</span>
          <StatusPill ok={Boolean(enabled)}>{boolLabel(enabled)}</StatusPill>
        </div>
      ))}
      <div className="capability-item">
        <span>{pick(TEXT.auth)}</span>
        <StatusPill ok={Boolean(capabilities?.auth && capabilities.auth !== "none")}>{capabilities?.auth || pick(TEXT.unknown)}</StatusPill>
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
  const pick = useT3();
  const boolLabel = useBoolLabel();
  const groups = (plugins || []).reduce<Record<string, PluginInfo[]>>((acc, plugin) => {
    acc[plugin.kind] = acc[plugin.kind] || [];
    acc[plugin.kind].push(plugin);
    return acc;
  }, {});
  const entries = Object.entries(groups).sort(([left], [right]) => left.localeCompare(right));

  if (entries.length === 0) {
    return <p className="muted">{pick(TEXT.noPlugins)}</p>;
  }

  return (
    <div className="plugin-groups" aria-label={pick(TEXT.pluginsLabel)}>
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
                  <StatusPill ok={plugin.enabled}>{boolLabel(plugin.enabled)}</StatusPill>
                </div>
              ))}
          </div>
        </section>
      ))}
    </div>
  );
}

function ConfigNotice({ config }: { config?: ConfigStatus }) {
  const pick = useT3();
  if (!config) return null;
  if (config.status !== "error") {
    return (
      <section className="panel config-panel">
        <div className="panel-head">
          <h2>{pick(TEXT.configuration)}</h2>
          <StatusPill ok>{pick(TEXT.hotReloadOk)}</StatusPill>
        </div>
        <div className="config-facts">
          {config.path && <span><strong>{pick(TEXT.file)}</strong>{config.path}</span>}
          {config.loadedAt && <span><strong>{pick(TEXT.loaded)}</strong>{config.loadedAt}</span>}
          {config.lastCheckedAt && <span><strong>{pick(TEXT.checked)}</strong>{config.lastCheckedAt}</span>}
        </div>
      </section>
    );
  }
  return (
    <section className="panel warning-panel config-panel">
      <div className="panel-head">
        <h2>{pick(TEXT.configuration)}</h2>
        <StatusPill ok={false}>{pick(TEXT.rolledBack)}</StatusPill>
      </div>
      <p>{pick(TEXT.rolledBackNote, { time: config.usingLoadedAt || config.loadedAt || pick(TEXT.earlier) })}</p>
      <div className="config-facts">
        {config.path && <span><strong>{pick(TEXT.file)}</strong>{config.path}</span>}
        {config.lastErrorAt && <span><strong>{pick(TEXT.errorTime)}</strong>{config.lastErrorAt}</span>}
        {config.lastError && <span className="config-error"><strong>{pick(TEXT.error)}</strong>{config.lastError}</span>}
      </div>
    </section>
  );
}

export default function StatusPage({ health, version, capabilities }: Props) {
  const { t } = useI18n();
  const pick = useT3();
  const [liveVersion, setLiveVersion] = useState(version);
  const apiCaps = liveVersion.data?.capabilities || capabilities.data?.capabilities;
  const configStatus = liveVersion.data?.config || health.data?.config || capabilities.data?.config;
  const configOK = configStatus?.status !== "error";
  const apiReachable = health.ok && Boolean(health.data?.ok);
  const healthOK = apiReachable && configOK;
  const apiVersion = liveVersion.data?.version || health.data?.version || pick(TEXT.unknown);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const response = await fetch("/api/version", { headers: { accept: "application/json" }, cache: "no-store" });
        const data = (await response.json()) as VersionResponse;
        if (active) setLiveVersion({ ok: response.ok, status: response.status, data });
      } catch (error) {
        if (active) {
          setLiveVersion({
            ok: false,
            status: 502,
            error: error instanceof Error ? error.message : diagnostic("Lookup API is unreachable."),
          });
        }
      }
    };
    const timer = window.setInterval(refresh, 3000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <>
      <Head>
        <title>{`${pick(TEXT.title)} | Whoice`}</title>
      </Head>
      <main className="shell docs-shell">
        <nav className="top-nav">
          <BrandMark />
          <div className="nav-links">
            <Link href="/docs">{t("docs")}</Link>
            <Link href="/status">{t("status")}</Link>
            <Link href="/admin">{t("adminPanel")}</Link>
            <AppControls />
          </div>
        </nav>

        <section className="status-strip">
          <div>
            <p className="eyebrow">{pick(TEXT.eyebrow)}</p>
            <h1>{pick(TEXT.heading)}</h1>
          </div>
          <div className="status-badges">
            <StatusPill ok={healthOK}>{pick(healthOK ? TEXT.healthy : TEXT.degraded)}</StatusPill>
            <span>API {apiVersion}</span>
            {health.data?.time && <span>{health.data.time}</span>}
          </div>
        </section>

        {!apiReachable && (
          <section className="panel error-panel">
            <p className="eyebrow">API</p>
            <h1>{pick(TEXT.apiUnhealthy)}</h1>
            <p className="muted">{health.error || `HTTP ${health.status}`}</p>
          </section>
        )}

        <ConfigNotice config={configStatus} />

        <section className="panel">
          <div className="panel-head">
            <h2>{pick(TEXT.capabilities)}</h2>
          </div>
          <CapabilityGrid capabilities={apiCaps} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>{pick(TEXT.plugins)}</h2>
          </div>
          <PluginList plugins={liveVersion.data?.plugins} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h2>{pick(TEXT.endpoints)}</h2>
          </div>
          <div className="endpoint-list">
            {["/api/health", "/api/version", "/api/capabilities", "/api/metrics"].map((endpoint) => (
              <a href={endpoint} key={endpoint}>
                <span>{endpoint}</span>
                <span>{pick(TEXT.sameOrigin)}</span>
              </a>
            ))}
          </div>
        </section>
      </main>
    </>
  );
}
