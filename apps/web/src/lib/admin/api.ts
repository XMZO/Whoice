// Browser client for the admin API. Requests go through the web app's same-origin
// proxy; the session lives in an HttpOnly cookie set by the API.

export type Settings = Record<string, Record<string, unknown>>;

export type SecretState = {
  site_password: boolean;
  api_tokens: number;
  ai_api_key: boolean;
  webhook_url: boolean;
};

export type ConfigStatus = {
  status: string;
  path?: string;
  loadedAt?: string;
  lastError?: string;
  lastErrorAt?: string;
  rolledBack?: boolean;
};

export type EditorStatus = {
  status: string;
  path?: string;
  writable: boolean;
  reason?: string;
};

export type AdminConfig = {
  settings: Settings;
  secrets: SecretState;
  envLocked: Record<string, string>;
  editor: EditorStatus;
  config: ConfigStatus;
  saved?: string[];
};

export type AdminStatus = {
  version: string;
  config: ConfigStatus;
  capabilities: Record<string, unknown>;
  plugins: { kind: string; name: string; enabled: boolean }[];
  stats: {
    startedAt: string;
    uptimeSec: number;
    lookups: LookupCounters;
    providers?: Record<string, LookupCounters & { skipped?: number }>;
  };
};

export type LookupCounters = {
  total: number;
  succeeded: number;
  failed: number;
  lastElapsedMs?: number;
  latencyMs?: { sum: number; count: number };
};

export class AdminError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (init.method && init.method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-Whoice-Admin"] = "1";
  }
  let response: Response;
  try {
    response = await fetch(`/api/admin/${path}`, { ...init, headers, credentials: "same-origin", cache: "no-store" });
  } catch (error) {
    throw new AdminError(0, "network", error instanceof Error ? error.message : "Network error");
  }
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.ok === false) {
    throw new AdminError(response.status, body.error?.code || "error", body.error?.message || `HTTP ${response.status}`);
  }
  return body as T;
}

export const adminApi = {
  session: () => request<{ authenticated: boolean; passwordFromEnv: boolean }>("session"),
  login: (password: string) => request<{ authenticated: boolean }>("login", { method: "POST", body: JSON.stringify({ password }) }),
  logout: () => request<{ authenticated: boolean }>("logout", { method: "POST", body: "{}" }),
  changePassword: (current: string, next: string) => request<{ ok: boolean }>("password", { method: "POST", body: JSON.stringify({ current, next }) }),
  status: () => request<AdminStatus>("status"),
  config: () => request<AdminConfig>("config"),
  save: (settings: Settings) => request<AdminConfig>("config", { method: "PATCH", body: JSON.stringify({ settings }) }),
};

// Settings are addressed by dotted paths such as "ai.model" or "api.endpoints.lookup".
export function readPath(settings: Settings, path: string): unknown {
  return path.split(".").reduce<unknown>((node, key) => (node && typeof node === "object" ? (node as Record<string, unknown>)[key] : undefined), settings);
}

export function buildPatch(values: Record<string, unknown>): Settings {
  const patch: Settings = {};
  for (const [path, value] of Object.entries(values)) {
    const keys = path.split(".");
    let node: Record<string, unknown> = patch;
    keys.slice(0, -1).forEach((key) => {
      node[key] = (node[key] as Record<string, unknown>) || {};
      node = node[key] as Record<string, unknown>;
    });
    node[keys[keys.length - 1]] = value;
  }
  return patch;
}
