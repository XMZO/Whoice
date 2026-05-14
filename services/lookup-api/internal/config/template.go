package config

import "strings"

func DefaultTemplate(dataDir string) string {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || dataDir == "." {
		dataDir = "data"
	}
	return `# Whoice configuration
# Generated on first startup when this file does not exist.
# Edit this file while the API is running; changes hot-reload automatically.
# If a change is invalid, Whoice keeps using the last valid runtime config and reports the error in logs and /status.
# Startup is stricter: an invalid config file prevents the API from starting.
# Fun bit: this file may also contain a base64-encoded TOML document; Whoice will decode and use it automatically.
# 首次启动自动生成。API 运行中修改会自动热加载。
# 如果改错，程序会继续使用上一次可用的运行时配置，并在日志和 /status 提示错误；不会自动改回这个文件。
# 启动时如果配置文件本身有误，API 会拒绝启动。
# 彩蛋：这个文件也可以直接写成整份 TOML 的 base64 编码，Whoice 会自动解码后使用。
#
# Duration values use Go duration syntax: "500ms", "3s", "10m", "72h".
# Cache TTL values also accept: "0"/"none"/"off" for no cache, or "forever" for no expiry.
# List values can be emptied with [] in this file. Environment list overrides can use "none".
# 时间写法使用 Go duration：例如 "500ms"、"3s"、"10m"、"72h"。
# 缓存 TTL 额外支持："0"/"none"/"off" 表示不缓存，"forever" 表示永久。
# 列表在 TOML 里可设为 []；环境变量覆盖时可用 "none" 禁用列表。

[server]
# API listen address inside the process/container.
# Docker Compose maps host ports separately, so usually do not change this for compose installs.
# This value is startup-only; changing it at runtime is rejected until the API process/container restarts.
# API 在进程/容器内监听的地址；Compose 的宿主机端口在 docker-compose.yml 里映射。
# 这是启动期配置；运行中修改会被拒绝，需要重启 API 进程/容器才会生效。
addr = ":8080"
# Runtime data directory: generated config, cache, mounted snapshots, brand/enrichment data.
# In Docker this is normally /data; in local dev it is ./data.
# 运行时数据目录：配置、缓存、挂载快照、品牌/增强数据。Docker 通常是 /data，本地开发通常是 ./data。
data_dir = "` + escapeTOMLString(dataDir) + `"
# Trust X-Forwarded-For for rate limit/log client IPs. Enable only behind a trusted reverse proxy.
# 是否信任反代传来的 X-Forwarded-For，用于限流和日志；只应在可信反代后启用。
trust_proxy = true
# Allow user supplied rdap_server/whois_server from API/Web advanced controls.
# Kept off by default because arbitrary upstream servers can create SSRF risk.
# 是否允许用户在高级选项里指定 RDAP/WHOIS server。默认关闭，避免 SSRF 风险。
allow_custom_servers = false
# Also allow private/loopback/link-local custom server targets.
# Only use in an admin-only local lab, never on a public instance.
# 是否允许自定义 server 指向内网/本机地址。只适合管理员本地环境，公开服务不要开启。
allow_private_servers = false

[api]
# Master switch for HTTP API routes. If false, all /api/* routes return not found.
# HTTP API 总开关。设为 false 后所有 /api/* 路由都会返回不可用。
enabled = true
# Optional IP/CIDR allowlist for every API route. Empty means no IP restriction.
# When trust_proxy = true, X-Forwarded-For is used; otherwise the direct TCP remote address is used.
# API 全局 IP/CIDR 白名单。空数组表示不限制。
# trust_proxy = true 时使用 X-Forwarded-For，否则使用直连来源地址。
ip_allowlist = []

[api.endpoints]
# Per-endpoint switches. Use these to expose only the routes you want.
# health/version/capabilities are useful for deployment checks and the Web UI.
# lookup_enrich is the background follow-up route for slow DNS/pricing/Moz enrichment.
# 单接口开关。可以只开放你需要的 API。
# health/version/capabilities 常用于部署检查和 Web UI。
# lookup_enrich 是 Web 后台补 DNS/价格/Moz 等慢增强的接口。
health = true
version = true
capabilities = true
metrics = true
lookup = true
lookup_ai = true
lookup_enrich = true
icp = true
admin = true
admin_status = true
admin_config = true

[auth]
# Lookup endpoints can be public ("none"), password protected, or bearer/API-token protected.
# mode = "password" accepts X-Whoice-Password, Bearer, or whoice_password cookie.
# mode = "token" accepts Authorization: Bearer, X-API-Key, or ?token=.
# 查询接口认证模式：none/password/token。
# password 支持 X-Whoice-Password、Bearer、或 whoice_password cookie。
# token 支持 Authorization: Bearer、X-API-Key、或 ?token=。
mode = "none"
# Used only when mode = "password". Keep empty when auth is disabled.
# 仅 mode = "password" 时使用；未启用认证时保持空。
site_password = ""
# Used only when mode = "token". Multiple tokens are allowed for rotation.
# 仅 mode = "token" 时使用；可配置多个 token 方便轮换。
api_tokens = []

[lookup]
# Total wall-clock budget for one lookup request, including providers and enrichment.
# 一次查询的总超时预算，包含 provider 和增强流程。
timeout = "15s"
# Per-provider upstream timeout for RDAP/WHOIS/WHOIS Web.
# 单个上游 provider 的超时时间。
provider_timeout = "10s"
# RDAP and WHOIS are both enabled by default. The Web UI/API can still choose one source per request.
# RDAP/WHOIS 默认都开；前端/API 仍可按单次请求选择来源。
rdap_enabled = true
whois_enabled = true
# WHOIS Web fallback is useful for some TLDs but depends on external web/API shapes, so it is off by default.
# WHOIS Web fallback 对部分后缀有用，但依赖外部网页/API 结构，默认关闭。
whois_web_enabled = false
# Number of registrar WHOIS referral hops to follow by default. 0 disables referral follow.
# 默认跟随 registrar WHOIS referral 的次数；0 表示不跟随。
whois_follow_limit = 1
# Return the parsed RDAP/WHOIS result first and let the Web UI call /api/lookup/enrich for slower DNS/pricing/Moz data.
# This makes first paint much faster when DNS/DoH or external enrichment is slow. Set false to wait for all enrichment in /api/lookup.
# 先返回 RDAP/WHOIS 主结果，再由 Web 调 /api/lookup/enrich 补 DNS/价格/Moz 等较慢数据。
# DNS/DoH 或外部增强慢时首屏会快很多；设为 false 则 /api/lookup 等全部增强完成再返回。
fast_response = true

[dns]
# DNS enrichment runs after the main WHOIS/RDAP result. It should not be required for lookup success.
# DNS 增强在主查询之后执行，不应成为 WHOIS/RDAP 成功的前置条件。
enabled = true
# DNS resolver budget. Lower is snappier; higher may help slow networks.
# DNS 解析超时。调低更快，调高更适合慢网络。
timeout = "3s"
# Every listed resolver is sampled, so regional differences can be shown.
# 会采样每一个解析器，方便看出国内外/不同 DoH 的差异。
# Built-in defaults include Cloudflare, Google, and ByteDance/Volcengine public IPv4 DNS.
# 内置默认包含 Cloudflare、Google、字节跳动/火山引擎公共 IPv4 DNS。
ipv4_resolvers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "180.184.1.1", "180.184.2.2"]
# Built-in IPv6 resolvers include Cloudflare and Google.
# 内置 IPv6 解析器包含 Cloudflare 和 Google。
ipv6_resolvers = ["2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844"]
# DoH resolvers are sampled as well. Tencent and AliDNS are kept after CF/Google for China-friendly fallback.
# DoH 也会逐个采样。腾讯/阿里放在 CF/Google 后面，方便国内网络 fallback。
doh_resolvers = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
  "https://doh.pub/dns-query",
  "https://dns.alidns.com/dns-query",
]
# Hide 198.18.0.0/15 fake-IP answers only when a normal replacement exists.
# If every answer is fake-IP, Whoice keeps it and adds a warning instead of silently deleting all A records.
# 仅当存在正常替代结果时隐藏 198.18.0.0/15 fake-IP；如果全是 fake-IP，会保留并给 warning，避免误判为空。
filter_fake_ip = true
# Add a DNSViz diagnostic link for domain results. This is just a link, not an extra network call.
# 为域名结果添加 DNSViz 诊断链接；这里只生成链接，不额外请求 DNSViz。
dnsviz_enabled = true

[enrichment]
# Optional result enrichers. They add context after WHOIS/RDAP and never decide lookup success.
# 可选结果增强项：在 WHOIS/RDAP 主查询后补充信息，失败只会产生 warning，不会让主查询失败。
# epp: Explain domain status codes such as clientTransferProhibited.
# epp：解释域名状态码，例如 clientTransferProhibited。
epp = true
# registrar: Fill registrar URL, IANA ID, country, WHOIS/RDAP server from ICANN/local registrar data.
# registrar：用 ICANN/本地注册商数据补全注册商官网、IANA ID、国家、WHOIS/RDAP server。
registrar = true
# brands: Add lightweight brand labels/colors for known registrars and nameserver providers.
# brands：给已知注册商和 NS 服务商加品牌标签/颜色；只影响展示，不影响查询。
brands = false
# pricing: Add new-registration/renewal/transfer prices by suffix.
# Current source is an in-memory Miqingju public snapshot refreshed periodically, with data/pricing/pricing.json fallback.
# Config intentionally stays a simple on/off switch so pricing providers can be swapped later without changing this file.
# pricing：按后缀补充新购/续费/转入最低价。
# 当前使用米情局公开快照并定期刷新，失败时回退 data/pricing/pricing.json。
# 这里故意只保留开关，之后换价格源不需要改公开配置格式。
pricing = false
# moz: Add optional local Moz-like authority metrics from data/enrichment/moz.json only.
# moz：从本地 data/enrichment/moz.json 补充 Moz 风格权重指标；不会实时请求外部 Moz API。
moz = false

[ai]
# Optional. Runs asynchronously from the Web UI and never blocks the main lookup.
# 可选。Web 后台异步调用，不阻塞主 WHOIS/RDAP 查询。
enabled = false
# Currently supported: openai-compatible. Use base_url without the trailing /chat/completions.
# 当前支持 openai-compatible；base_url 写到 /v1 这一级，不要包含 /chat/completions。
provider = "openai-compatible"
base_url = ""
# Secret. Prefer setting this only on your own machine/server; do not commit real keys.
# 密钥。只应放在自己的机器/服务器上，不要提交真实 key。
api_key = ""
model = ""
# AI call timeout. Main lookup is already returned before this is called from the Web UI.
# AI 调用超时；Web UI 会在主查询返回后再异步调用。
timeout = "8s"
# Cache only structured AI analysis, not WHOIS/RDAP/DNS results.
# 只缓存 AI 结构化分析，不缓存 WHOIS/RDAP/DNS 查询结果。
cache_ttl = "168h"
# Raw evidence sent to the model is truncated to this many characters.
# 发送给模型的原始证据最多截断到这个字符数。
max_input_chars = 16000
# Fields below this confidence are ignored when applying AI output.
# 低于该置信度的 AI 字段不会应用到结果。
min_confidence = 0.68
# Keep temperature low so the model returns concise deterministic JSON.
# 温度保持低，减少废话和非 JSON 输出。
temperature = 0
# Keep enough room for JSON, but not enough for long reasoning.
# 给 JSON 留足空间，但不鼓励长篇推理。
max_output_tokens = 700
# Total attempts, including the first request. 1-3 is allowed.
# 总尝试次数，包含第一次请求；允许 1-3。
max_attempts = 3
# Skip AI for suffixes that deterministic parsers usually handle well.
# Exact suffixes are case-insensitive; use [] to disable all suffix ignores.
# 对解析规则稳定的常见后缀跳过 AI，减少慢请求和模型消耗。
# 精确后缀不区分大小写；设为 [] 表示完全不按后缀跳过。
ignore_suffixes = [` + tomlStringList(DefaultAIIgnoreSuffixes()) + `]
# Optional regex ignore rules. Patterns run against the lower-case suffix without a leading dot, for example "^k12\\.".
# Leave [] empty unless you really need pattern-based suffix groups.
# 可选正则忽略规则。匹配对象是不带开头点的小写后缀，例如 "^k12\\."。
# 不需要模式匹配时保持 []。
ignore_regex = []
# AI prompt used as the system message. The default is written here so it can be reviewed and edited.
# Setting prompt = "" is also valid and means "use this same built-in default prompt".
# AI 系统提示词。默认值写在这里，方便审查和修改。
# 如果设成 prompt = ""，也会使用同一份内置默认提示词。
prompt = '''` + DefaultAIPrompt + `'''

[icp]
# ICP filing lookup is separate from main lookup. Positive/empty/error cache TTLs differ.
# 备案查询独立于主查询；命中、空结果、错误结果分别缓存。
enabled = true
# false means the Web UI shows a manual query button; true queries after the main result loads.
# false 表示前端显示手动查询按钮；true 表示主结果加载后自动查备案。
auto_query = false
timeout = "8s"
# Positive ICP cache. Use "0"/"none" to disable, or "forever" for permanent cache.
# 备案命中结果缓存。可用 "0"/"none" 禁用，或 "forever" 永久缓存。
cache_ttl = "72h"
# Empty/not-found cache; shorter than positive cache to avoid hiding new filings for too long.
# 空结果缓存；比命中缓存短，避免新备案长期被旧空结果遮住。
negative_cache_ttl = "12h"
# Error cache; intentionally short because MIIT/captcha/network failures are often temporary.
# 错误结果缓存；故意较短，因为工信部/验证码/网络失败通常是临时的。
error_cache_ttl = "10m"
# Direct MIIT API base URL. Change only if MIIT endpoint changes.
# 工信部直连 API 地址；只有接口变化时才需要改。
base_url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api"
# Optional ICP_Query-compatible upstream, for example "http://127.0.0.1:16181".
# If set, Whoice calls /query/web?search=domain on that service and still applies its own cache/blocklist.
# 可选 ICP_Query 兼容上游，例如 "http://127.0.0.1:16181"。
# 设置后会请求该服务的 /query/web?search=domain，同时仍使用 Whoice 自己的缓存和隐藏名单。
upstream_url = ""
# Direct MIIT mode may need slider-captcha token flow. Disable only when using a trusted upstream.
# 工信部直连可能需要滑块验证码 token；使用可信上游时可以关闭。
captcha_enabled = true
captcha_retries = 3
page_size = 10
# Hidden ICP blocklist. Exact domains and "*.example.com" patterns return the same empty-looking result as a normal miss.
# 隐蔽备案隐藏名单。支持精确域名和 "*.example.com"，命中时返回看起来像正常未查到的结果。
blocklist = []

[rate_limit]
# Fixed-window in-memory rate limit for lookup endpoints. Best for single-node public/self-hosted use.
# 单机内存固定窗口限流，适合单节点公开/自部署实例。
enabled = false
# Format: count/window. Window supports s/sec/second, m/min/minute, h/hour.
# 格式：次数/窗口。窗口支持 s/sec/second、m/min/minute、h/hour。
anon = "60/min"

[metrics]
# Expose /api/metrics in Prometheus text format.
# 是否开放 Prometheus 文本格式的 /api/metrics。
enabled = true

[observability]
# none, log, webhook, or both. Reporters run asynchronously after lookup.
# 可选 none/log/webhook/both；reporter 在查询结束后异步执行。
reporter = "none"
# Used when reporter = "webhook" or "both". Only point this at trusted internal endpoints.
# reporter = webhook/both 时使用；只应指向可信内网端点。
webhook_url = ""
timeout = "2s"

[public_suffix]
# Optional startup refresh. Keep off if startup must not depend on publicsuffix.org.
# 可选启动时刷新；需要离线稳定启动时保持关闭。
auto_update = false
# Public Suffix List source used only when auto_update = true.
# 仅 auto_update = true 时使用的 PSL 下载地址。
url = "https://publicsuffix.org/list/public_suffix_list.dat"
update_timeout = "5s"
`
}

func escapeTOMLString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func tomlStringList(values []string) string {
	if len(values) == 0 {
		return ""
	}
	escaped := make([]string, 0, len(values))
	for _, value := range values {
		escaped = append(escaped, `"`+escapeTOMLString(value)+`"`)
	}
	return strings.Join(escaped, ", ")
}
