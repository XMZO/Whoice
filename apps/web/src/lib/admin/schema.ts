// Declarative description of every setting the admin panel edits. Each field maps to
// a dotted path in whoice.toml; sections render from this list, so adding a setting
// means adding one entry here.

export type T3 = readonly [en: string, zhCN: string, zhTW: string];

type Base = { path: string; label: T3; hint?: T3; wide?: boolean; visibleWhen?: (get: (path: string) => unknown) => boolean };

export type Field =
  | (Base & { type: "toggle" })
  | (Base & { type: "text"; placeholder?: string; mono?: boolean })
  | (Base & { type: "number"; min?: number; max?: number; step?: number })
  | (Base & { type: "duration"; cache?: boolean })
  | (Base & { type: "select"; options: { value: string; label: T3 }[] })
  | (Base & { type: "list"; placeholder?: string })
  | (Base & { type: "secret"; secret: "site_password" | "ai_api_key" | "webhook_url" })
  | (Base & { type: "tokens" })
  | (Base & { type: "prompt" });

export type Group = { title?: T3; fields: Field[] };

export type SectionId = "overview" | "lookup" | "dns" | "enrichment" | "ai" | "icp" | "access" | "monitor" | "account";

export type Section = { id: SectionId; title: T3; description: T3; groups: Group[] };

const toggle = (path: string, label: T3, hint?: T3): Field => ({ type: "toggle", path, label, hint });
const duration = (path: string, label: T3, hint?: T3, cache = false): Field => ({ type: "duration", path, label, hint, cache });

const endpoint = (key: string, label: T3): Field => toggle(`api.endpoints.${key}`, label);

export const SETTINGS_SECTIONS: Section[] = [
  {
    id: "lookup",
    title: ["Lookup", "查询", "查詢"],
    description: ["Sources, timeouts, and custom servers", "数据来源、超时与自定义服务器", "資料來源、逾時與自訂伺服器"],
    groups: [
      {
        title: ["Sources", "数据来源", "資料來源"],
        fields: [
          toggle("lookup.rdap_enabled", ["RDAP", "RDAP", "RDAP"]),
          toggle("lookup.whois_enabled", ["WHOIS", "WHOIS", "WHOIS"]),
          toggle("lookup.whois_web_enabled", ["WHOIS Web fallback", "WHOIS Web 备用", "WHOIS Web 備用"], ["Scrapes registry websites for selected TLDs", "部分后缀从注册局网页获取", "部分後綴從註冊局網頁取得"]),
          toggle("lookup.fast_response", ["Fast first response", "先返回主结果", "先回傳主結果"], ["DNS and pricing load afterwards", "DNS 与价格随后补充", "DNS 與價格隨後補充"]),
        ],
      },
      {
        title: ["Timing", "时间", "時間"],
        fields: [
          duration("lookup.timeout", ["Total timeout", "总超时", "總逾時"]),
          duration("lookup.provider_timeout", ["Per-source timeout", "单个来源超时", "單一來源逾時"]),
          { type: "number", path: "lookup.whois_follow_limit", label: ["WHOIS referral depth", "WHOIS 跟随层数", "WHOIS 跟隨層數"], hint: ["0 disables referral follow", "0 表示不跟随", "0 表示不跟隨"], min: 0, max: 5 },
        ],
      },
      {
        title: ["Custom servers", "自定义服务器", "自訂伺服器"],
        fields: [
          toggle("server.allow_custom_servers", ["Allow custom servers", "允许自定义服务器", "允許自訂伺服器"], ["Users may set rdap_server / whois_server", "允许请求指定 rdap_server / whois_server", "允許請求指定 rdap_server / whois_server"]),
          toggle("server.allow_private_servers", ["Allow private addresses", "允许内网地址", "允許內網位址"], ["Only for private deployments", "仅适用于内部部署", "僅適用於內部部署"]),
        ],
      },
    ],
  },
  {
    id: "dns",
    title: ["DNS", "DNS", "DNS"],
    description: ["Resolver pools and DNS enrichment", "解析器与 DNS 补充信息", "解析器與 DNS 補充資訊"],
    groups: [
      {
        fields: [
          toggle("dns.enabled", ["DNS enrichment", "DNS 解析", "DNS 解析"]),
          toggle("dns.dnsviz_enabled", ["DNSViz link", "DNSViz 链接", "DNSViz 連結"]),
          toggle("dns.filter_fake_ip", ["Hide fake-IP answers", "过滤 fake-IP", "過濾 fake-IP"], ["198.18.0.0/15, when real answers exist", "仅在有正常结果时隐藏 198.18.0.0/15", "僅在有正常結果時隱藏 198.18.0.0/15"]),
          duration("dns.timeout", ["Timeout", "超时", "逾時"]),
        ],
      },
      {
        title: ["Resolvers", "解析器", "解析器"],
        fields: [
          { type: "list", path: "dns.ipv4_resolvers", label: ["IPv4 resolvers", "IPv4 解析器", "IPv4 解析器"], placeholder: "1.1.1.1" },
          { type: "list", path: "dns.ipv6_resolvers", label: ["IPv6 resolvers", "IPv6 解析器", "IPv6 解析器"], hint: ["Leave empty if Docker has no IPv6", "Docker 未启用 IPv6 时留空", "Docker 未啟用 IPv6 時留空"], placeholder: "2606:4700:4700::1111" },
          { type: "list", path: "dns.doh_resolvers", label: ["DoH endpoints", "DoH 地址", "DoH 位址"], placeholder: "https://dns.google/resolve", wide: true },
        ],
      },
    ],
  },
  {
    id: "enrichment",
    title: ["Enrichment", "补充信息", "補充資訊"],
    description: ["Optional context added to results", "附加到结果的可选信息", "附加到結果的可選資訊"],
    groups: [
      {
        fields: [
          toggle("enrichment.epp", ["EPP status", "EPP 状态说明", "EPP 狀態說明"]),
          toggle("enrichment.registrar", ["Registrar metadata", "注册商信息", "註冊商資訊"], ["From the ICANN registrar list", "来自 ICANN 注册商列表", "來自 ICANN 註冊商列表"]),
          toggle("enrichment.brands", ["Brand recognition", "服务商识别", "服務商識別"]),
          toggle("enrichment.pricing", ["Registration prices", "注册价格", "註冊價格"]),
          toggle("enrichment.moz", ["Moz scores", "Moz 评分", "Moz 評分"], ["Local data/enrichment/moz.json only", "仅使用本地 moz.json", "僅使用本機 moz.json"]),
        ],
      },
      {
        title: ["Public Suffix List", "公共后缀列表", "公共後綴列表"],
        fields: [
          toggle("public_suffix.auto_update", ["Download at startup", "启动时下载", "啟動時下載"]),
          { type: "text", path: "public_suffix.url", label: ["Source URL", "下载地址", "下載位址"], mono: true, wide: true },
          duration("public_suffix.update_timeout", ["Download timeout", "下载超时", "下載逾時"]),
        ],
      },
    ],
  },
  {
    id: "ai",
    title: ["AI parsing", "AI 解析", "AI 解析"],
    description: ["Model used for non-standard WHOIS records", "解析非标准 WHOIS 记录的模型", "解析非標準 WHOIS 紀錄的模型"],
    groups: [
      {
        title: ["Model", "模型", "模型"],
        fields: [
          toggle("ai.enabled", ["Enable AI parsing", "启用 AI 解析", "啟用 AI 解析"]),
          {
            type: "select",
            path: "ai.provider",
            label: ["Provider", "接口类型", "介面類型"],
            options: [
              { value: "openai-compatible", label: ["OpenAI-compatible", "OpenAI 兼容", "OpenAI 相容"] },
              { value: "ollama", label: ["Ollama", "Ollama", "Ollama"] },
            ],
          },
          { type: "text", path: "ai.base_url", label: ["Base URL", "接口地址", "介面位址"], placeholder: "https://api.example.com/v1", mono: true },
          { type: "text", path: "ai.model", label: ["Model", "模型名称", "模型名稱"], mono: true },
          { type: "secret", path: "ai.api_key", secret: "ai_api_key", label: ["API key", "API 密钥", "API 金鑰"] },
          duration("ai.timeout", ["Timeout", "超时", "逾時"]),
        ],
      },
      {
        title: ["Behavior", "行为", "行為"],
        fields: [
          duration("ai.cache_ttl", ["Cache TTL", "缓存时长", "快取時長"], ["0 disables, forever never expires", "0 不缓存，forever 永久", "0 不快取，forever 永久"], true),
          { type: "number", path: "ai.min_confidence", label: ["Minimum confidence", "最低置信度", "最低信賴度"], min: 0, max: 1, step: 0.01 },
          { type: "number", path: "ai.temperature", label: ["Temperature", "温度", "溫度"], min: 0, max: 2, step: 0.1 },
          { type: "number", path: "ai.max_output_tokens", label: ["Max output tokens", "最大输出 token", "最大輸出 token"], min: 1 },
          { type: "number", path: "ai.max_input_chars", label: ["Max input characters", "最大输入字符", "最大輸入字元"], min: 1 },
          { type: "number", path: "ai.max_attempts", label: ["Attempts", "尝试次数", "嘗試次數"], min: 1, max: 3 },
        ],
      },
      {
        title: ["Scope and prompt", "范围与提示词", "範圍與提示詞"],
        fields: [
          { type: "list", path: "ai.ignore_suffixes", label: ["Skipped suffixes", "跳过的后缀", "略過的後綴"], hint: ["Parsers handle these reliably", "这些后缀由规则解析", "這些後綴由規則解析"], placeholder: "com" },
          { type: "list", path: "ai.ignore_regex", label: ["Skipped suffix patterns", "跳过的后缀正则", "略過的後綴正規式"], placeholder: "^k12\\." },
          { type: "prompt", path: "ai.prompt", label: ["System prompt", "系统提示词", "系統提示詞"], wide: true },
        ],
      },
    ],
  },
  {
    id: "icp",
    title: ["ICP filing", "ICP 备案", "ICP 備案"],
    description: ["MIIT filing lookup and caching", "工信部备案查询与缓存", "工信部備案查詢與快取"],
    groups: [
      {
        fields: [
          toggle("icp.enabled", ["Enable ICP lookup", "启用备案查询", "啟用備案查詢"]),
          toggle("icp.auto_query", ["Query automatically", "自动查询", "自動查詢"], ["Otherwise users click to query", "否则由用户手动查询", "否則由使用者手動查詢"]),
          toggle("icp.captcha_enabled", ["Solve captchas", "处理验证码", "處理驗證碼"]),
          { type: "number", path: "icp.captcha_retries", label: ["Captcha retries", "验证码重试", "驗證碼重試"], min: 0, max: 10 },
          { type: "text", path: "icp.upstream_url", label: ["Upstream service", "上游服务", "上游服務"], hint: ["ICP_Query-compatible; replaces direct MIIT access", "兼容 ICP_Query，替代直连工信部", "相容 ICP_Query，取代直連工信部"], placeholder: "http://127.0.0.1:16181", mono: true, wide: true },
        ],
      },
      {
        title: ["Caching", "缓存", "快取"],
        fields: [
          duration("icp.timeout", ["Timeout", "超时", "逾時"]),
          duration("icp.cache_ttl", ["Found results", "有备案结果", "有備案結果"], undefined, true),
          duration("icp.negative_cache_ttl", ["Empty results", "无备案结果", "無備案結果"], undefined, true),
          duration("icp.error_cache_ttl", ["Errors", "查询出错", "查詢出錯"], undefined, true),
        ],
      },
      {
        title: ["Advanced", "高级", "進階"],
        fields: [
          { type: "list", path: "icp.blocklist", label: ["Hidden domains", "隐藏的域名", "隱藏的網域"], hint: ["Exact names or *.example.com", "精确域名或 *.example.com", "精確網域或 *.example.com"], placeholder: "*.example.com" },
          { type: "text", path: "icp.base_url", label: ["MIIT API URL", "工信部接口地址", "工信部介面位址"], mono: true },
          { type: "number", path: "icp.page_size", label: ["Page size", "每页条数", "每頁筆數"], min: 1 },
        ],
      },
    ],
  },
  {
    id: "access",
    title: ["Access", "访问控制", "存取控制"],
    description: ["Visitor authentication, rate limits, and API exposure", "访客鉴权、限流与接口开放", "訪客驗證、限流與介面開放"],
    groups: [
      {
        title: ["Visitor authentication", "访客鉴权", "訪客驗證"],
        fields: [
          {
            type: "select",
            path: "auth.mode",
            label: ["Mode", "方式", "方式"],
            options: [
              { value: "none", label: ["Public", "公开", "公開"] },
              { value: "password", label: ["Site password", "站点密码", "網站密碼"] },
              { value: "token", label: ["API tokens", "API Token", "API Token"] },
            ],
          },
          { type: "secret", path: "auth.site_password", secret: "site_password", label: ["Site password", "站点密码", "網站密碼"], visibleWhen: (get) => get("auth.mode") === "password" },
          { type: "tokens", path: "auth.api_tokens", label: ["API tokens", "API Token", "API Token"], visibleWhen: (get) => get("auth.mode") === "token" || get("auth.mode") === "bearer" },
        ],
      },
      {
        title: ["Rate limit", "限流", "限流"],
        fields: [
          toggle("rate_limit.enabled", ["Limit anonymous lookups", "限制匿名查询", "限制匿名查詢"]),
          { type: "text", path: "rate_limit.anon", label: ["Limit", "频率", "頻率"], hint: ["count/window, e.g. 60/min", "次数/时间，如 60/min", "次數/時間，如 60/min"], mono: true },
        ],
      },
      {
        title: ["API exposure", "接口开放", "介面開放"],
        fields: [
          toggle("server.trust_proxy", ["Trust reverse proxy", "信任反向代理", "信任反向代理"], ["Use X-Forwarded-For as the client IP", "以 X-Forwarded-For 作为客户端 IP", "以 X-Forwarded-For 作為用戶端 IP"]),
          { type: "list", path: "api.ip_allowlist", label: ["IP allowlist", "IP 白名单", "IP 白名單"], hint: ["Empty allows every address", "留空表示不限制", "留空表示不限制"], placeholder: "10.0.0.0/8" },
          endpoint("lookup", ["Lookup", "查询", "查詢"]),
          endpoint("lookup_enrich", ["Deferred enrichment", "延迟补充", "延遲補充"]),
          endpoint("lookup_ai", ["AI analysis", "AI 分析", "AI 分析"]),
          endpoint("icp", ["ICP lookup", "备案查询", "備案查詢"]),
          endpoint("health", ["Health", "健康检查", "健康檢查"]),
          endpoint("version", ["Version", "版本", "版本"]),
          endpoint("capabilities", ["Capabilities", "功能开关", "功能開關"]),
          endpoint("metrics", ["Metrics endpoint", "指标接口", "指標介面"]),
          endpoint("admin_status", ["Admin status", "管理状态", "管理狀態"]),
        ],
      },
    ],
  },
  {
    id: "monitor",
    title: ["Monitoring", "监控", "監控"],
    description: ["Metrics and lookup event reporting", "指标与查询事件上报", "指標與查詢事件回報"],
    groups: [
      {
        fields: [
          toggle("metrics.enabled", ["Prometheus metrics", "Prometheus 指标", "Prometheus 指標"], ["Served at /api/metrics", "通过 /api/metrics 提供", "透過 /api/metrics 提供"]),
          {
            type: "select",
            path: "observability.reporter",
            label: ["Event reporter", "事件上报", "事件回報"],
            options: [
              { value: "none", label: ["Off", "关闭", "關閉"] },
              { value: "log", label: ["Log", "日志", "日誌"] },
              { value: "webhook", label: ["Webhook", "Webhook", "Webhook"] },
              { value: "log,webhook", label: ["Log and webhook", "日志与 Webhook", "日誌與 Webhook"] },
            ],
          },
          { type: "secret", path: "observability.webhook_url", secret: "webhook_url", label: ["Webhook URL", "Webhook 地址", "Webhook 位址"], hint: ["Trusted internal endpoints only", "仅限可信的内部地址", "僅限可信的內部位址"], visibleWhen: (get) => String(get("observability.reporter") || "").includes("webhook") },
          duration("observability.timeout", ["Webhook timeout", "Webhook 超时", "Webhook 逾時"]),
        ],
      },
    ],
  },
];

export const NAV: { id: SectionId; title: T3 }[] = [
  { id: "overview", title: ["Overview", "概览", "概覽"] },
  ...SETTINGS_SECTIONS.map(({ id, title }) => ({ id, title })),
  { id: "account", title: ["Account", "账户", "帳戶"] },
];

export function allFields(): Field[] {
  return SETTINGS_SECTIONS.flatMap((section) => section.groups.flatMap((group) => group.fields));
}

export function fieldsOf(id: SectionId): Field[] {
  return SETTINGS_SECTIONS.find((section) => section.id === id)?.groups.flatMap((group) => group.fields) || [];
}
