import { useEffect, useState } from "react";
import { adminApi, readPath, type AdminConfig, type AdminStatus } from "@/lib/admin/api";
import { useAdminText } from "@/lib/admin/text";

function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatTime(value?: string) {
  return value ? value.replace("T", " ").replace(/\+00:00$|Z$/, " UTC") : "—";
}

export function OverviewSection({ config }: { config: AdminConfig }) {
  const { at } = useAdminText();
  const [status, setStatus] = useState<AdminStatus | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const load = () =>
      adminApi
        .status()
        .then((next) => active && (setStatus(next), setError("")))
        .catch((reason: Error) => active && setError(reason.message));
    load();
    const timer = window.setInterval(load, 10000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const lookups = status?.stats.lookups;
  const rate = lookups && lookups.total ? `${Math.round((lookups.succeeded / lookups.total) * 100)}%` : "—";
  const latency = lookups?.latencyMs && lookups.latencyMs.count ? `${Math.round(lookups.latencyMs.sum / lookups.latencyMs.count)} ms` : "—";
  const providers = Object.entries(status?.stats.providers || {});
  const plugins = status?.plugins || [];
  const overrides = Object.entries(config.envLocked);
  const configOk = config.config.status !== "error";

  return (
    <div className="adm-groups">
      {error && <p className="adm-alert">{error}</p>}
      <section className="adm-group">
        <h3 className="adm-group-title">{at("service")}</h3>
        <div className="adm-stats">
          <div className="adm-stat"><span>{at("version")}</span><strong className="mono">{status?.version || "—"}</strong></div>
          <div className="adm-stat"><span>{at("uptime")}</span><strong>{status ? formatUptime(status.stats.uptimeSec) : "—"}</strong></div>
          <div className="adm-stat"><span>{at("lookups")}</span><strong>{lookups ? lookups.total.toLocaleString() : "—"}</strong></div>
          <div className="adm-stat"><span>{at("successRate")}</span><strong>{rate}</strong></div>
          <div className="adm-stat"><span>{at("avgLatency")}</span><strong>{latency}</strong></div>
          <div className="adm-stat"><span>{at("plugins")}</span><strong>{status ? at("pluginsEnabled", { n: plugins.filter((plugin) => plugin.enabled).length, total: plugins.length }) : "—"}</strong></div>
        </div>
      </section>

      <section className="adm-group">
        <h3 className="adm-group-title">{at("configuration")}</h3>
        {!configOk && (
          <p className="adm-alert">
            {at("configError")}
            {config.config.lastError && <span className="mono adm-alert-detail">{config.config.lastError}</span>}
          </p>
        )}
        <dl className="adm-kv">
          <div><dt>{at("configFile")}</dt><dd className="mono">{config.editor.path || "—"}</dd></div>
          <div><dt>{at("loadedAt")}</dt><dd>{formatTime(config.config.loadedAt)}{configOk && <span className="adm-pill adm-pill-ok">{at("configHealthy")}</span>}</dd></div>
          <div><dt>{at("listen")}</dt><dd><span className="mono">{String(readPath(config.settings, "server.addr") ?? "")}</span><span className="adm-hint">{at("startupOnly")}</span></dd></div>
          <div><dt>{at("dataDir")}</dt><dd><span className="mono">{String(readPath(config.settings, "server.data_dir") ?? "")}</span></dd></div>
          <div>
            <dt>{at("envOverrides")}</dt>
            <dd>{overrides.length ? overrides.map(([path, env]) => <span key={path} className="adm-pill mono" title={env}>{path}</span>) : at("noOverrides")}</dd>
          </div>
        </dl>
      </section>

      {providers.length > 0 && (
        <section className="adm-group">
          <h3 className="adm-group-title">{at("sources")}</h3>
          <table className="adm-table">
            <thead>
              <tr><th>{at("provider")}</th><th>{at("requests")}</th><th>{at("failures")}</th><th>{at("avgLatency")}</th></tr>
            </thead>
            <tbody>
              {providers.map(([name, counters]) => (
                <tr key={name}>
                  <td>{name}</td>
                  <td className="mono">{counters.total ?? 0}</td>
                  <td className="mono">{counters.failed ?? 0}</td>
                  <td className="mono">{counters.latencyMs?.count ? `${Math.round(counters.latencyMs.sum / counters.latencyMs.count)} ms` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
