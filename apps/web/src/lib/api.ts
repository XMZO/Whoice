import type { APIResponse, LookupResult } from "./types";

export type LookupOptions = {
  rdap?: string;
  whois?: string;
  rdapServer?: string;
  whoisServer?: string;
  whoisFollow?: string;
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
  };
}

export function getAPIBase() {
  if (typeof window !== "undefined") {
    return "";
  }
  return process.env.WHOICE_WEB_API_BASE || process.env.NEXT_PUBLIC_WHOICE_API_BASE || "http://localhost:8080";
}

export function appendLookupOptions(params: URLSearchParams, options: LookupOptions = {}) {
  const normalized = normalizeLookupOptions(options);
  if (normalized.rdap) params.set("rdap", normalized.rdap);
  if (normalized.whois) params.set("whois", normalized.whois);
  if (normalized.rdapServer) params.set("rdap_server", normalized.rdapServer);
  if (normalized.whoisServer) params.set("whois_server", normalized.whoisServer);
  if (normalized.whoisFollow) params.set("whois_follow", normalized.whoisFollow);
  return params;
}

export async function lookup(query: string, options: LookupOptions = {}) {
  const params = new URLSearchParams({ query: normalizeLookupInput(query) });
  appendLookupOptions(params, options);

  const base = getAPIBase().replace(/\/$/, "");
  const response = await fetch(`${base}/api/lookup?${params.toString()}`, { cache: "no-store" });
  const body = (await response.json()) as APIResponse;
  normalizeAPIResponse(body);
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
  result.network = result.network || {};
  result.enrichment = result.enrichment || {};
  result.raw = result.raw || {};
  result.meta = result.meta || { elapsedMs: 0 };
  result.meta.providers = Array.isArray(result.meta.providers) ? result.meta.providers : [];
  result.meta.warnings = Array.isArray(result.meta.warnings) ? result.meta.warnings : [];
  return result;
}
