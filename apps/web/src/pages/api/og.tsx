import { ImageResponse } from "next/og";
import { getServerAPIBase } from "@/lib/serverApi";
import type { LookupResult } from "@/lib/types";

export const config = { runtime: "edge" };

type DisplayResult = Pick<LookupResult, "normalizedQuery" | "type" | "status" | "registrar" | "dates" | "nameservers" | "source">;

function clampDimension(value: string | null, fallback: number) {
  const parsed = Number.parseInt(value || "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, 320), 2400);
}

function detectType(query: string) {
  if (!query) return "lookup";
  if (/^AS\d+$/i.test(query)) return "asn";
  if (query.includes("/")) return "cidr";
  if (query.includes(":")) return "ipv6";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(query)) return "ipv4";
  return "domain";
}

async function fetchResult(query: string): Promise<DisplayResult | null> {
  if (!query) return null;
  const apiBase = getServerAPIBase();
  try {
    const res = await fetch(`${apiBase.replace(/\/$/, "")}/api/lookup?query=${encodeURIComponent(query)}`, {
      headers: { accept: "application/json" },
      cache: "no-store",
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.ok && data?.result ? data.result : null;
  } catch {
    return null;
  }
}

function dateOnly(value?: string) {
  if (!value) return "";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toISOString().slice(0, 10);
}

export default async function handler(req: Request) {
  const url = new URL(req.url);
  const query = (url.searchParams.get("query") || url.searchParams.get("q") || "").trim();
  const theme = url.searchParams.get("theme") === "dark" ? "dark" : "light";
  const width = clampDimension(url.searchParams.get("w"), 1200);
  const height = clampDimension(url.searchParams.get("h"), 630);
  const result = await fetchResult(query);

  const isDark = theme === "dark";
  const bg = isDark ? "#101213" : "#f7f3ed";
  const fg = isDark ? "#f7f7f4" : "#161a1d";
  const muted = isDark ? "#a6b0ad" : "#66706c";
  const panel = isDark ? "#191d1f" : "#fffdf8";
  const border = isDark ? "#33403c" : "#d8d0c4";
  const accent = isDark ? "#62d2a2" : "#0f766e";
  const warn = "#d97706";

  const displayQuery = result?.normalizedQuery || query || "Whoice";
  const type = result?.type || detectType(query);
  const status = result?.status || (query ? "unknown" : "ready");
  const registrar = result?.registrar?.brand?.name || result?.registrar?.name || "";
  const expires = dateOnly(result?.dates?.expiresAt);
  const nameservers = result?.nameservers?.slice(0, 3).map((ns) => ns.brand?.name || ns.host) || [];
  const source = result?.source?.used?.join(" + ") || "rdap + whois";
  const statusColor = status === "registered" ? accent : status === "unregistered" ? warn : muted;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          padding: 64,
          background: bg,
          color: fg,
          fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 18 }}>
            <div
              style={{
                width: 58,
                height: 58,
                borderRadius: 12,
                background: accent,
                color: isDark ? "#07110d" : "#ffffff",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 800,
                fontSize: 28,
              }}
            >
              W
            </div>
            <div style={{ display: "flex", flexDirection: "column" }}>
              <span style={{ fontSize: 30, fontWeight: 800 }}>Whoice</span>
              <span style={{ fontSize: 20, color: muted }}>Modular WHOIS and RDAP lookup</span>
            </div>
          </div>
          <div
            style={{
              border: `1px solid ${border}`,
              borderRadius: 999,
              padding: "12px 20px",
              color: muted,
              fontSize: 22,
              textTransform: "uppercase",
            }}
          >
            {type}
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 28 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <span style={{ color: statusColor, fontSize: 24, textTransform: "uppercase", fontWeight: 800 }}>{status}</span>
            <div style={{ fontSize: 76, fontWeight: 900, lineHeight: 1.05, maxWidth: 980, overflow: "hidden" }}>{displayQuery}</div>
          </div>

          <div style={{ display: "flex", gap: 18 }}>
            <InfoCard label="Registrar" value={registrar || "Not parsed"} panel={panel} border={border} muted={muted} />
            <InfoCard label="Expires" value={expires || "Unknown"} panel={panel} border={border} muted={muted} />
            <InfoCard label="Source" value={source} panel={panel} border={border} muted={muted} />
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", color: muted, fontSize: 22 }}>
          <span>{nameservers.length ? nameservers.join(" / ") : "Evidence-first lookup, raw data included"}</span>
          <span>whoice.local</span>
        </div>
      </div>
    ),
    { width, height },
  );
}

function InfoCard({ label, value, panel, border, muted }: { label: string; value: string; panel: string; border: string; muted: string }) {
  return (
    <div
      style={{
        flex: 1,
        minWidth: 0,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        padding: 22,
        border: `1px solid ${border}`,
        borderRadius: 8,
        background: panel,
      }}
    >
      <span style={{ color: muted, fontSize: 18, textTransform: "uppercase" }}>{label}</span>
      <span style={{ fontSize: 26, fontWeight: 800, overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis" }}>{value}</span>
    </div>
  );
}
