export type QueryType = "domain" | "ipv4" | "ipv6" | "asn" | "cidr" | "url" | "unknown";

export type ResultStatus =
  | "registered"
  | "unregistered"
  | "reserved"
  | "unknown"
  | "error";

export type SourceName = "rdap" | "whois" | "whoisWeb";

export type Brand = {
  name: string;
  slug?: string;
  color?: string;
};

export type LookupResult = {
  query: string;
  normalizedQuery: string;
  type: QueryType;
  status: ResultStatus;
  source: {
    primary?: SourceName;
    used: SourceName[];
    errors?: { source: SourceName; server?: string; error: string }[];
  };
  domain: {
    name?: string;
    unicodeName?: string;
    punycodeName?: string;
    suffix?: string;
    registeredDomain?: string;
    reserved: boolean;
    registered: boolean;
  };
  registry: {
    name?: string;
    website?: string;
    whoisServer?: string;
    rdapServer?: string;
  };
  registrar: {
    name?: string;
    url?: string;
    ianaId?: string;
    country?: string;
    whoisServer?: string;
    rdapServer?: string;
    brand?: Brand;
    source?: string;
    confidence?: number;
    evidence?: string;
  };
  dates: {
    createdAt?: string;
    updatedAt?: string;
    expiresAt?: string;
    availableAt?: string;
    ageDays?: number;
    remainingDays?: number;
  };
  statuses: { code: string; label?: string; category?: string; description?: string; url?: string; source?: string }[];
  nameservers: { host: string; brand?: Brand }[];
  dnssec: { signed?: boolean; text?: string };
  registrant: {
    name?: string;
    organization?: string;
    country?: string;
    province?: string;
    city?: string;
    address?: string;
    postalCode?: string;
    email?: string;
    phone?: string;
    extra?: { label: string; value: string; source?: string; confidence?: number; evidence?: string }[];
    fieldSources?: Record<string, { label: string; value: string; source?: string; confidence?: number; evidence?: string }[]>;
    source?: string;
    confidence?: number;
    evidence?: string;
  };
  network: {
    cidr?: string;
    range?: string;
    name?: string;
    type?: string;
    originAS?: string;
    country?: string;
  };
  enrichment: {
    dns?: {
      a?: { ip: string; version: "ipv4" | "ipv6"; reverse?: string; source?: "udp" | "doh" | "system"; resolver?: string; endpoint?: string }[];
      aaaa?: { ip: string; version: "ipv4" | "ipv6"; reverse?: string; source?: "udp" | "doh" | "system"; resolver?: string; endpoint?: string }[];
      cname?: string;
      mx?: { host: string; pref: number }[];
      ns?: string[];
      registryNs?: string[];
      nsMismatch?: boolean;
      resolvers?: { source: "udp" | "doh" | "system"; resolver: string; endpoint?: string; status?: "ok" | "empty" | "error"; error?: string }[];
      elapsedMs?: number;
    };
    dnsviz?: {
      url: string;
    };
    pricing?: {
      register?: number;
      renew?: number;
      transfer?: number;
      currency?: string;
      provider?: string;
      source?: string;
      updatedAt?: string;
    };
    moz?: {
      domainAuthority?: number;
      pageAuthority?: number;
      spamScore?: number;
      source?: string;
      updatedAt?: string;
    };
  };
  raw: {
    whois?: string;
    rdap?: string;
    whoisWeb?: string;
  };
  meta: {
    elapsedMs: number;
    warnings?: string[];
    traceId?: string;
    providers?: {
      source: SourceName;
      status: "ok" | "error" | "skipped";
      server?: string;
      query?: string;
      statusCode?: number;
      contentType?: string;
      bytes?: number;
      elapsedMs: number;
      error?: string;
    }[];
    ai?: {
      provider?: string;
      model?: string;
      status: string;
      cached?: boolean;
      elapsedMs?: number;
      attempts?: number;
      applied?: string[];
      error?: string;
    };
  };
};

export type ResultMeta = LookupResult["meta"];

export type ICPRecord = {
  domain?: string;
  domainId?: number;
  unitName?: string;
  natureName?: string;
  mainLicence?: string;
  serviceLicence?: string;
  serviceName?: string;
  contentTypeName?: string;
  limitAccess?: string;
  updateRecordTime?: string;
};

export type ICPResult = {
  domain: string;
  status: "found" | "not_found" | "error";
  records?: ICPRecord[];
  source?: string;
  cached: boolean;
  cachedAt?: string;
  expiresAt?: string;
  elapsedMs?: number;
  message?: string;
};

export type APIResponse = {
  ok: boolean;
  result?: LookupResult;
  error?: {
    code: string;
    message: string;
    details?: string[];
  };
  capabilities?: {
    rdap: boolean;
    whois: boolean;
    whoisWeb: boolean;
    customServers: boolean;
    auth: string;
    rateLimit: boolean;
    icpAutoQuery: boolean;
    enrichment: Record<string, boolean>;
  };
  meta?: ResultMeta;
};

export type ICPResponse = {
  ok: boolean;
  result?: ICPResult;
  error?: {
    code: string;
    message: string;
    details?: string[];
  };
  meta?: ResultMeta;
};
