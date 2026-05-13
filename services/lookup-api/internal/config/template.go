package config

import "strings"

func DefaultTemplate(dataDir string) string {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || dataDir == "." {
		dataDir = "data"
	}
	return `# Whoice configuration
# Generated on first startup when this file does not exist.
# Edit this file, then restart the API container.
# 首次启动自动生成。修改后重启 API 容器生效。

[server]
addr = ":8080"
data_dir = "` + escapeTOMLString(dataDir) + `"
trust_proxy = true
allow_custom_servers = false
allow_private_servers = false

[auth]
# none, password, or token.
# 可选 none/password/token。
mode = "none"
site_password = ""
api_tokens = []

[lookup]
timeout = "15s"
provider_timeout = "10s"
rdap_enabled = true
whois_enabled = true
whois_web_enabled = false
whois_follow_limit = 1

[dns]
enabled = true
timeout = "3s"
# Every listed resolver is sampled, so regional differences can be shown.
# 会采样每一个解析器，方便看出国内外/不同 DoH 的差异。
ipv4_resolvers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "180.184.1.1", "180.184.2.2"]
ipv6_resolvers = ["2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844"]
doh_resolvers = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
  "https://doh.pub/dns-query",
  "https://dns.alidns.com/dns-query",
]
filter_fake_ip = true
dnsviz_enabled = true

[enrichment]
epp = true
registrar = true
brands = false
pricing = false
moz = false

[ai]
# Optional. Runs asynchronously from the Web UI and never blocks the main lookup.
# 可选。Web 后台异步调用，不阻塞主 WHOIS/RDAP 查询。
enabled = false
provider = "openai-compatible"
base_url = ""
api_key = ""
model = ""
timeout = "8s"
cache_ttl = "168h"
max_input_chars = 16000
min_confidence = 0.68
temperature = 0
max_output_tokens = 700
# Total attempts, including the first request. 1-3 is allowed.
# 总尝试次数，包含第一次请求；允许 1-3。
max_attempts = 3
prompt = ""

[icp]
# ICP filing lookup is separate from main lookup. Positive/empty/error cache TTLs differ.
# 备案查询独立于主查询；命中、空结果、错误结果分别缓存。
enabled = true
auto_query = false
timeout = "8s"
cache_ttl = "72h"
negative_cache_ttl = "12h"
error_cache_ttl = "10m"
base_url = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api"
upstream_url = ""
captcha_enabled = true
captcha_retries = 3
page_size = 10
blocklist = []

[rate_limit]
enabled = false
anon = "60/min"

[metrics]
enabled = true

[observability]
reporter = "none"
webhook_url = ""
timeout = "2s"

[public_suffix]
# Optional startup refresh. Keep off if startup must not depend on publicsuffix.org.
# 可选启动时刷新；需要离线稳定启动时保持关闭。
auto_update = false
url = "https://publicsuffix.org/list/public_suffix_list.dat"
update_timeout = "5s"
`
}

func escapeTOMLString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}
