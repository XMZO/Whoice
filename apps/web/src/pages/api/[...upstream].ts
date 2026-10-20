import type { NextApiRequest, NextApiResponse } from "next";
import { getServerAPIBase } from "@/lib/serverApi";

// Same-origin routes the browser may reach, with the methods each accepts.
const ROUTES: Record<string, string[]> = {
  health: ["GET"],
  version: ["GET"],
  capabilities: ["GET"],
  metrics: ["GET"],
  icp: ["GET"],
  "lookup/enrich": ["POST"],
  "admin/session": ["GET"],
  "admin/login": ["POST"],
  "admin/logout": ["POST"],
  "admin/password": ["POST"],
  "admin/status": ["GET"],
  "admin/config": ["GET", "PATCH"],
};

const FORWARDED_HEADERS = ["authorization", "cookie", "x-api-key", "x-whoice-password", "x-whoice-admin", "x-request-id"];

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
  const methods = ROUTES[path];

  if (!methods) {
    res.status(404).json({ ok: false, error: { code: "not_found", message: "API endpoint is not proxied by the web app." } });
    return;
  }

  if (!methods.includes(method)) {
    res.setHeader("Allow", methods.join(", "));
    res.status(405).json({ ok: false, error: { code: "method_not_allowed", message: "Method is not allowed." } });
    return;
  }
  const hasBody = method !== "GET";

  const target = new URL(`/api/${path}`, getServerAPIBase().replace(/\/$/, "") + "/");
  const query = req.url?.split("?")[1] || "";
  if (query) target.search = query;

  try {
    const headers: Record<string, string> = { accept: path === "metrics" ? "text/plain" : "application/json" };
    for (const name of FORWARDED_HEADERS) {
      const value = firstHeader(req.headers[name]);
      if (value) headers[name] = value;
    }
    const contentType = firstHeader(req.headers["content-type"]);
    if (contentType && hasBody) headers["content-type"] = contentType;
    const xForwardedFor = forwardedFor(req);
    if (xForwardedFor) headers["x-forwarded-for"] = xForwardedFor;
    if (req.headers.host) headers["x-forwarded-host"] = firstHeader(req.headers.host) || "";
    // Lets the API mark the admin session cookie Secure when the site is served over HTTPS.
    const proto = firstHeader(req.headers["x-forwarded-proto"]) || ((req.socket as { encrypted?: boolean }).encrypted ? "https" : "");
    if (proto) headers["x-forwarded-proto"] = proto;

    const upstream = await fetch(target, { method, headers, body: hasBody ? JSON.stringify(req.body || {}) : undefined, cache: "no-store" });
    upstream.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (!HOP_BY_HOP_HEADERS.has(lower) && lower !== "content-type" && lower !== "content-length" && lower !== "set-cookie") {
        res.setHeader(key, value);
      }
    });
    const cookies = upstream.headers.getSetCookie();
    if (cookies.length) res.setHeader("Set-Cookie", cookies);
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
