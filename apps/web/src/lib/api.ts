import type { APIResponse, ICPResponse, LookupResult } from "./types";

export type LookupOptions = {
  rdap?: string;
  whois?: string;
  rdapServer?: string;
  whoisServer?: string;
  whoisFollow?: string;
  exactDomain?: string;
  ai?: string;
  fast?: string;
};

export function normalizeLookupInput(value: string) {
  let output = "";
  for (const char of value.trim()) {
    if (/\s/.test(char) || /[\u0000-\u001f\u007f]/.test(char)) continue;
    output += ",，。．｡".includes(char) ? "." : char;
  }
  return output.trim();
}

export function normalizeLookupOptions(options: LookupOptions = {}): LookupOptions {
  return {
    rdap: options.rdap,
    whois: options.whois,
    rdapServer: options.rdapServer ? normalizeLookupInput(options.rdapServer) : undefined,
    whoisServer: options.whoisServer ? normalizeLookupInput(options.whoisServer) : undefined,
    whoisFollow: options.whoisFollow?.trim(),
    exactDomain: options.exactDomain,
    ai: options.ai,
    fast: options.fast,
  };
}

export function getAPIBase() {
  if (typeof window !== "undefined") {
    return "";
  }
  return process.env.WHOICE_WEB_API_BASE || process.env.NEXT_PUBLIC_WHOICE_API_BASE || (process.env.NODE_ENV === "production" ? "http://lookup-api:8080" : "http://localhost:8080");
}

export function appendLookupOptions(params: URLSearchParams, options: LookupOptions = {}) {
  const normalized = normalizeLookupOptions(options);
  if (normalized.rdap) params.set("rdap", normalized.rdap);
  if (normalized.whois) params.set("whois", normalized.whois);
  if (normalized.rdapServer) params.set("rdap_server", normalized.rdapServer);
  if (normalized.whoisServer) params.set("whois_server", normalized.whoisServer);
  if (normalized.whoisFollow) params.set("whois_follow", normalized.whoisFollow);
  if (normalized.exactDomain) params.set("exact_domain", normalized.exactDomain);
  if (normalized.ai) params.set("ai", normalized.ai);
  if (normalized.fast) params.set("fast", normalized.fast);
  return params;
}

function looksLikeHTML(text: string) {
  return /<!doctype html|<html[\s>]/i.test(text);
}

async function readAPIResponse(response: Response, context: string): Promise<APIResponse> {
  const text = await response.text();
  const status = response.status || 502;
  if (!text.trim()) {
    return {
      ok: false,
      error: {
        code: "empty_response",
        message: `${context} returned an empty response (HTTP ${status}).`,
      },
    };
  }
  try {
    return JSON.parse(text) as APIResponse;
  } catch {
    const html = looksLikeHTML(text);
    return {
      ok: false,
      error: {
        code: html ? "html_error_response" : "invalid_json_response",
        message: html
          ? `${context} returned an HTML error page instead of JSON (HTTP ${status}).`
          : `${context} returned a non-JSON response (HTTP ${status}).`,
        details: [text.slice(0, 500)],
      },
    };
  }
}

export async function lookup(query: string, options: LookupOptions = {}) {
  const params = new URLSearchParams({ query: normalizeLookupInput(query) });
  appendLookupOptions(params, options);

  const base = getAPIBase().replace(/\/$/, "");
  const response = await fetch(`${base}/api/lookup?${params.toString()}`, { cache: "no-store" });
  const body = await readAPIResponse(response, "Lookup API");
  normalizeAPIResponse(body);
  return { status: response.status, body };
}

export async function getCapabilities() {
  const base = getAPIBase().replace(/\/$/, "");
  const response = await fetch(`${base}/api/capabilities`, { headers: { accept: "application/json" }, cache: "no-store" });
  const body = await readAPIResponse(response, "Capabilities API");
  return { status: response.status, body };
}

export async function analyzeRegistration(result: LookupResult, force = true) {
  const base = getAPIBase().replace(/\/$/, "");
  const response = await fetch(`${base}/api/lookup/ai`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ result, force }),
    cache: "no-store",
  });
  const body = await readAPIResponse(response, "AI lookup API");
  normalizeAPIResponse(body);
  return { status: response.status, body };
}

export async function enrichLookup(result: LookupResult) {
  const base = getAPIBase().replace(/\/$/, "");
  const response = await fetch(`${base}/api/lookup/enrich`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ result }),
    cache: "no-store",
  });
  const body = await readAPIResponse(response, "Enrichment API");
  normalizeAPIResponse(body);
  return { status: response.status, body };
}

export async function lookupICP(domain: string) {
  const params = new URLSearchParams({ domain: normalizeLookupInput(domain) });
  const base = getAPIBase().replace(/\/$/, "");
  const response = await fetch(`${base}/api/icp?${params.toString()}`, { cache: "no-store" });
  const text = await response.text();
  let body: ICPResponse;
  try {
    body = JSON.parse(text) as ICPResponse;
  } catch {
    const html = looksLikeHTML(text);
    body = {
      ok: false,
      error: {
        code: response.status === 404 ? "icp_route_missing" : "icp_invalid_response",
        message: html
          ? `ICP endpoint returned an HTML error page (HTTP ${response.status}). Restart the Web dev server after route changes.`
          : text.slice(0, 300) || `ICP lookup failed with HTTP ${response.status}`,
      },
    };
  }
  if (body.result) {
    body.result.records = Array.isArray(body.result.records) ? body.result.records : [];
  }
  return { status: response.status, body };
}

export function normalizeAPIResponse(body: APIResponse) {
  if (!body.result) return body;
  normalizeLookupResult(body.result);
  return body;
}

export function normalizeLookupResult(result: LookupResult) {
  result.statuses = Array.isArray(result.statuses) ? result.statuses : [];
  result.nameservers = Array.isArray(result.nameservers) ? result.nameservers : [];
  result.source = result.source || { used: [] };
  result.source.used = Array.isArray(result.source.used) ? result.source.used : [];
  result.source.errors = Array.isArray(result.source.errors) ? result.source.errors : [];
  result.domain = result.domain || { reserved: false, registered: false };
  result.registry = result.registry || {};
  result.registrar = result.registrar || {};
  result.dates = result.dates || {};
  result.dnssec = result.dnssec || {};
  result.registrant = result.registrant || {};
  result.registrant.extra = Array.isArray(result.registrant.extra) ? result.registrant.extra : [];
  result.registrant.fieldSources = result.registrant.fieldSources && typeof result.registrant.fieldSources === "object" ? result.registrant.fieldSources : {};
  result.network = result.network || {};
  result.enrichment = result.enrichment || {};
  result.raw = result.raw || {};
  result.meta = result.meta || { elapsedMs: 0 };
  result.meta.providers = Array.isArray(result.meta.providers) ? result.meta.providers : [];
  result.meta.warnings = Array.isArray(result.meta.warnings) ? result.meta.warnings : [];
  result.meta.pendingEnrichments = Array.isArray(result.meta.pendingEnrichments) ? result.meta.pendingEnrichments : [];
  if (result.meta.ai) {
    result.meta.ai.applied = Array.isArray(result.meta.ai.applied) ? result.meta.ai.applied : [];
  }
  return result;
}
