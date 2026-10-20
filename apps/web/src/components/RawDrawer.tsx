import { useEffect, useMemo, useRef, useState } from "react";
import { CloseIcon, CopyIcon, DownloadIcon, FileIcon } from "@/components/Icons";
import { useI18n } from "@/lib/i18n";
import { displayServer, formatBytes, prettyRaw, textBytes } from "@/lib/resultModel";
import type { LookupResult } from "@/lib/types";

export type RawTab = "rdap" | "whois" | "whoisWeb" | "json";

type TabInfo = {
  id: RawTab;
  label: string;
  size: string;
  url: string;
  meta: string;
  text: string;
  filename: string;
};

export function RawDrawer({
  result,
  tab,
  onTabChange,
  onClose,
  onCopy,
  pageQuery,
}: {
  result: LookupResult;
  tab: RawTab;
  onTabChange: (tab: RawTab) => void;
  onClose: () => void;
  onCopy: (value: string) => void;
  pageQuery: string;
}) {
  const { t } = useI18n();
  const closeRef = useRef<HTMLButtonElement>(null);
  const [lastFocus] = useState(() => (typeof document === "undefined" ? null : (document.activeElement as HTMLElement | null)));

  const tabs = useMemo<TabInfo[]>(() => {
    const providers = Array.isArray(result.meta?.providers) ? result.meta.providers : [];
    const provider = (source: string) => providers.find((item) => item.source === source);
    const out: TabInfo[] = [];
    const rdap = provider("rdap");
    if (result.raw?.rdap) {
      out.push({
        id: "rdap",
        label: "RDAP",
        size: formatBytes(rdap?.bytes ?? textBytes(result.raw.rdap)),
        url: rdap?.server || result.registry?.rdapServer || "",
        meta: [rdap?.statusCode ? `HTTP ${rdap.statusCode}` : "", rdap?.contentType, rdap ? `${rdap.elapsedMs} ms` : ""].filter(Boolean).join(" · "),
        text: prettyRaw(result.raw.rdap),
        filename: `${result.normalizedQuery}.rdap.json`,
      });
    }
    const whois = provider("whois");
    if (result.raw?.whois) {
      const server = whois?.server || result.registry?.whoisServer || "";
      out.push({
        id: "whois",
        label: "WHOIS",
        size: formatBytes(whois?.bytes ?? textBytes(result.raw.whois)),
        url: server && !server.includes(":") ? `${server}:43` : server,
        meta: ["TCP 43", whois ? `${whois.elapsedMs} ms` : ""].filter(Boolean).join(" · "),
        text: result.raw.whois,
        filename: `${result.normalizedQuery}.whois.txt`,
      });
    }
    const web = provider("whoisWeb");
    if (result.raw?.whoisWeb) {
      out.push({
        id: "whoisWeb",
        label: "WHOIS Web",
        size: formatBytes(web?.bytes ?? textBytes(result.raw.whoisWeb)),
        url: displayServer(web?.server),
        meta: [web?.statusCode ? `HTTP ${web.statusCode}` : "", web ? `${web.elapsedMs} ms` : ""].filter(Boolean).join(" · "),
        text: result.raw.whoisWeb,
        filename: `${result.normalizedQuery}.whois-web.txt`,
      });
    }
    out.push({
      id: "json",
      label: t("structuredJson"),
      size: "LookupResult",
      url: `/api/lookup?query=${encodeURIComponent(pageQuery)}`,
      meta: `${t("mergedResult")} · ${result.meta.elapsedMs} ms`,
      text: JSON.stringify(result, null, 2),
      filename: `${result.normalizedQuery}.whoice.json`,
    });
    return out;
  }, [pageQuery, result, t]);

  const current = tabs.find((item) => item.id === tab) || tabs[0];
  const lines = useMemo(() => current.text.split("\n"), [current.text]);

  useEffect(() => {
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = overflow;
      lastFocus?.focus?.();
    };
  }, [lastFocus, onClose]);

  function download() {
    const blob = new Blob([current.text], { type: current.id === "whois" || current.id === "whoisWeb" ? "text/plain" : "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = current.filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="raw-overlay">
      <button type="button" className="raw-scrim" aria-label={t("close")} tabIndex={-1} onClick={onClose} />
      <aside className="raw-drawer raw-panel" role="dialog" aria-modal="true" aria-labelledby="raw-drawer-title">
        <div className="raw-drawer-head">
          <span className="icon-tile" aria-hidden="true"><FileIcon size={15} /></span>
          <h2 id="raw-drawer-title">{t("rawTitle")}</h2>
          <span className="raw-drawer-query">{result.normalizedQuery}</span>
          <span className="spacer" />
          <button ref={closeRef} type="button" className="icon-button" aria-label={t("close")} onClick={onClose}>
            <CloseIcon size={14} />
          </button>
        </div>
        <div className="raw-tabs" role="tablist" aria-label={t("rawFormats")}>
          {tabs.map((item) => (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={item.id === current.id}
              className={item.id === current.id ? "raw-tab active" : "raw-tab"}
              onClick={() => onTabChange(item.id)}
            >
              {item.label}
              <span className="tab-meta">{item.size}</span>
            </button>
          ))}
        </div>
        <div className="raw-info" key={`info-${current.id}`}>
          <span className="raw-info-text">
            <span className="raw-info-url">{current.url}</span>
            <span className="raw-info-meta">{current.meta}</span>
          </span>
          <button type="button" className="btn btn-sm" onClick={() => onCopy(current.text)}>
            <CopyIcon size={13} className="btn-icon" />
            {t("copy")}
          </button>
          <button type="button" className="btn btn-sm" onClick={download}>
            <DownloadIcon size={13} className="btn-icon" />
            {t("download")}
          </button>
        </div>
        <pre className="raw-body" key={`body-${current.id}`} tabIndex={0}>
          {lines.map((line, index) => (
            <span className="raw-line" key={index}>
              {line || " "}
            </span>
          ))}
        </pre>
      </aside>
    </div>
  );
}
