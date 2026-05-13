export type HistoryItem = {
  query: string;
  type: string;
  timestamp: number;
};

export function detectLookupType(query: string) {
  const value = query.trim();
  if (/^AS\d+$/i.test(value)) return "asn";
  if (/\/\d{1,3}$/.test(value)) return "cidr";
  if (value.includes(":")) return "ipv6";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return "ipv4";
  return "domain";
}

export function readHistory(): HistoryItem[] {
  if (typeof window === "undefined") return [];
  try {
    const value = localStorage.getItem("whoice.history");
    if (!value) return [];
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.slice(0, 12) : [];
  } catch {
    return [];
  }
}

export function writeHistory(query: string) {
  if (typeof window === "undefined") return [];
  const item = { query, type: detectLookupType(query), timestamp: Date.now() };
  const next = [item, ...readHistory().filter((entry) => entry.query !== query)].slice(0, 24);
  localStorage.setItem("whoice.history", JSON.stringify(next));
  return next;
}
