import type { NextApiRequest, NextApiResponse } from "next";
import { getServerAPIBase } from "@/lib/serverApi";

export const config = {
  api: {
    bodyParser: {
      sizeLimit: "8mb",
    },
  },
};

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

function looksLikeJSON(contentType: string | null) {
  return Boolean(contentType?.toLowerCase().includes("application/json"));
}

function looksLikeHTML(text: string) {
  return /<!doctype html|<html[\s>]/i.test(text);
}

function sendUpstreamJSON(res: NextApiResponse, status: number, text: string, contentType: string | null) {
  res.setHeader("Cache-Control", "no-store");
  if (looksLikeJSON(contentType)) {
    res.setHeader("Content-Type", contentType || "application/json");
    res.status(status).send(text);
    return;
  }
  res.status(status || 502).json({
    ok: false,
    error: {
      code: looksLikeHTML(text) ? "html_error_response" : "invalid_json_response",
      message: looksLikeHTML(text)
        ? `AI lookup API returned an HTML error page instead of JSON (HTTP ${status || 502}).`
        : `AI lookup API returned a non-JSON response (HTTP ${status || 502}).`,
      details: [text.slice(0, 500)],
    },
  });
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ ok: false, error: { code: "method_not_allowed", message: "Method is not allowed." } });
    return;
  }

  const target = new URL("/api/lookup/ai", getServerAPIBase().replace(/\/$/, "") + "/");
  try {
    const headers: Record<string, string> = { accept: "application/json", "content-type": "application/json" };
    for (const name of ["authorization", "cookie", "x-api-key", "x-whoice-password", "x-request-id"]) {
      const value = firstHeader(req.headers[name]);
      if (value) headers[name] = value;
    }
    const xForwardedFor = forwardedFor(req);
    if (xForwardedFor) headers["x-forwarded-for"] = xForwardedFor;
    if (req.headers.host) headers["x-forwarded-host"] = firstHeader(req.headers.host) || "";

    const upstream = await fetch(target, {
      method: "POST",
      headers,
      body: JSON.stringify(req.body || {}),
      cache: "no-store",
    });
    upstream.headers.forEach((value, key) => {
      const lower = key.toLowerCase();
      if (!HOP_BY_HOP_HEADERS.has(lower) && lower !== "content-type" && lower !== "content-length") {
        res.setHeader(key, value);
      }
    });
    const text = await upstream.text();
    sendUpstreamJSON(res, upstream.status, text, upstream.headers.get("content-type"));
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
