import type { NextApiRequest, NextApiResponse } from "next";
import { getServerAPIBase } from "@/lib/serverApi";

const ALLOWED_PATHS = new Set(["health", "version", "capabilities", "metrics", "icp", "lookup/enrich", "admin/config"]);

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function firstHeader(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value;
}

function forwardedFor(req: NextApiRequest) {
  const existing = firstHeader(req.headers["x-forwarded-for"]);
  const remote = req.socket.remoteAddress;
  if (existing && remote) return `${existing}, ${remote}`;
  return existing || remote || "";
}

function wantsJSON(path: string) {
  return path !== "metrics";
}

function looksLikeJSON(contentType: string | null) {
  return Boolean(contentType?.toLowerCase().includes("application/json"));
}

function looksLikeHTML(text: string) {
  return /<!doctype html|<html[\s>]/i.test(text);
}

function sendUpstream(res: NextApiResponse, path: string, status: number, text: string, contentType: string | null) {
  res.setHeader("Cache-Control", "no-store");
  if (!wantsJSON(path) || looksLikeJSON(contentType)) {
    if (contentType) res.setHeader("Content-Type", contentType);
    res.status(status).send(text);
    return;
  }
  res.status(status || 502).json({
    ok: false,
    error: {
      code: looksLikeHTML(text) ? "html_error_response" : "invalid_json_response",
      message: looksLikeHTML(text)
        ? `Upstream API returned an HTML error page instead of JSON (HTTP ${status || 502}).`
        : `Upstream API returned a non-JSON response (HTTP ${status || 502}).`,
      details: [text.slice(0, 500)],
    },
  });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const method = req.method || "GET";
  const parts = Array.isArray(req.query.upstream) ? req.query.upstream : [];
  const path = parts.join("/");
  const reservedConfigEditorWrite = path === "admin/config" && method === "PATCH";
  const lookupEnrichWrite = path === "lookup/enrich" && method === "POST";

  if (method !== "GET" && !reservedConfigEditorWrite && !lookupEnrichWrite) {
    res.setHeader("Allow", path === "admin/config" ? "GET, PATCH" : path === "lookup/enrich" ? "POST" : "GET");
    res.status(405).json({ ok: false, error: { code: "method_not_allowed", message: "Method is not allowed." } });
    return;
  }

  if (!ALLOWED_PATHS.has(path)) {
    res.status(404).json({ ok: false, error: { code: "not_found", message: "API endpoint is not proxied by the web app." } });
    return;
  }

  const target = new URL(`/api/${path}`, getServerAPIBase().replace(/\/$/, "") + "/");
  const query = req.url?.split("?")[1] || "";
  if (query) target.search = query;

  try {
    const headers: Record<string, string> = { accept: path === "metrics" ? "text/plain" : "application/json" };
    for (const name of ["authorization", "cookie", "x-api-key", "x-whoice-password", "x-request-id"]) {
      const value = firstHeader(req.headers[name]);
      if (value) headers[name] = value;
    }
    const contentType = firstHeader(req.headers["content-type"]);
    if (contentType && (reservedConfigEditorWrite || lookupEnrichWrite)) headers["content-type"] = contentType;
    const xForwardedFor = forwardedFor(req);
    if (xForwardedFor) headers["x-forwarded-for"] = xForwardedFor;
    if (req.headers.host) headers["x-forwarded-host"] = firstHeader(req.headers.host) || "";

    // Reserved for a future Web config editor. The API currently returns 501,
    // but the same-origin proxy path is intentionally wired now so a later UI
    // can add restricted controls or source-file editing without reshaping URLs.
    const upstream = await fetch(target, { method, headers, body: reservedConfigEditorWrite || lookupEnrichWrite ? JSON.stringify(req.body || {}) : undefined, cache: "no-store" });
    upstream.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (!HOP_BY_HOP_HEADERS.has(lower) && lower !== "content-type" && lower !== "content-length") {
        res.setHeader(key, value);
      }
    });
    const text = await upstream.text();
    sendUpstream(res, path, upstream.status, text, upstream.headers.get("content-type"));
  } catch (error) {
    res.status(502).json({
      ok: false,
      error: {
        code: "api_unreachable",
        message: error instanceof Error ? error.message : "Lookup API is unreachable.",
      },
    });
  }
}
