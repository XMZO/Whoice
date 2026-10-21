# Whoice

[English](./README.md) | 简体中文

Whoice 是可自托管的 WHOIS / RDAP 查询服务，支持域名、IP 地址、CIDR 网段和 ASN，由 Go 查询 API 与 Next.js Web 界面组成。

- **查询**：并行查询 RDAP 与 WHOIS 并合并结果；支持 WHOIS Web 备用来源、referral 跟随、非 UTF-8 解码，内置 30 多个注册局的专用解析器。
- **补充信息**：多解析器 DNS（UDP 与 DoH，逐条记录比对）、EPP 锁定状态、DNSSEC、ICANN 注册商信息、注册商与 NS 服务商识别、DNSViz 链接、注册价格、Moz 评分。
- **可选模块**：ICP 备案查询、AI 解析非标准 WHOIS、密码或 Token 鉴权、限流、Prometheus 指标。
- **管理面板**：`/admin`，单密码登录，可在网页上修改全部运行配置并立即生效。
- **Web 界面**：结论优先的结果页与原文查看器，支持简体中文、繁體中文、English，浅色与深色主题，快捷键，JSON 导出，各来源返回即显示的流式结果，以及运行状态页 `/status`。
- **实时性**：查询结果从不缓存，只复用变化缓慢的参考数据（bootstrap 文件、服务器映射、ICP 结果、AI 分析）。

## 部署

镜像发布在 GHCR，支持 Linux `amd64` 与 `arm64`。新建目录后启动：

```sh
mkdir whoice && cd whoice
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/XMZO/Whoice/main/deploy/compose/docker-compose.yml
docker compose up -d
```

| 服务 | 地址 | 用途 |
|---|---|---|
| Web 界面 | `127.0.0.1:18081` | 浏览器访问；API 请求经同源代理转发 |
| 查询 API | `127.0.0.1:18080` | 直接调用 API |

两个端口都只绑定本机。对外提供服务时请通过反向代理，例如 Caddy：

```caddyfile
whois.example.com {
	reverse_proxy 127.0.0.1:18081
}
```

如需直接对外暴露端口，把 `docker-compose.yml` 中 `ports` 的 `127.0.0.1` 改为 `0.0.0.0`。

API 首次启动时会生成 `./data/whoice.toml`。所有配置和运行数据都保存在 compose 文件同级的 `./data` 目录。

**更新**

```sh
docker compose pull && docker compose up -d
```

**IPv6**：compose 网络 `whoice` 开启了 IPv6，需要 Docker daemon 支持 IPv6（`daemon.json` 中 `"ipv6": true`）。如果 daemon 未开启 IPv6，可以开启后重建网络（`docker compose down && docker network rm whoice; docker compose up -d`），或在 `[dns]` 中设置 `ipv6_resolvers = []` 关闭 IPv6 直连探测。DoH 仍会通过 IPv4 返回 AAAA 记录。

## 管理面板

打开 `/admin`，用管理密码登录。API 首次启动时会随机生成密码，并在日志中打印一次：

```sh
docker compose logs lookup-api | grep "admin panel password"
```

面板显示服务状态，并可修改下文所有配置项（启动期配置 `server.addr`、`server.data_dir` 除外）。保存时会先校验，再写回 `data/whoice.toml`（旧文件保留为 `whoice.toml.bak`），并立即生效。密码可以在面板中修改，也可以用环境变量 `WHOICE_ADMIN_PASSWORD` 指定，或通过以下命令重置：

```sh
docker compose exec lookup-api /app/whoice-api reset-admin-password
```

## 配置

配置可以在管理面板中修改，也可以直接编辑 `data/whoice.toml`。自动生成的文件对每个选项都有注释。修改后自动热加载，只有 `server.addr` 需要重启。配置有误时，API 继续使用上一份有效配置，并在 `/status` 和查询警告中提示错误。该文件也可以是 base64 编码的 TOML。

| 配置段 | 内容 |
|---|---|
| `[server]` | 监听地址、数据目录、`trust_proxy`、自定义与内网查询服务器 |
| `[api]` | 各接口开关与 IP 白名单 |
| `[auth]` | `none`、`password`（站点密码）或 `token`（API Token） |
| `[lookup]` | 超时、RDAP / WHOIS / WHOIS Web 开关、referral 层数、DNS 优先的后缀（WHOIS 连不上的注册局） |
| `[dns]` | 解析器池（IPv4、IPv6、DoH）、fake-IP 过滤、DNSViz 链接 |
| `[enrichment]` | EPP、注册商、服务商识别、价格（按后缀缓存，默认 7 天；按每日公开汇率换算人民币/美元，汇率缓存 1 天）、Moz |
| `[ai]` | OpenAI 兼容接口或 Ollama 地址、模型、提示词、缓存 |
| `[icp]` | ICP 备案查询、缓存、验证码处理、上游服务 |
| `[rate_limit]` | 匿名访问的固定窗口限流，如 `60/min` |
| `[metrics]`、`[observability]` | `/api/metrics` 与查询事件上报（日志或 webhook） |
| `[public_suffix]` | 启动时可选下载 Public Suffix List |

多数配置也可以用环境变量设置（`WHOICE_AUTH_MODE`、`WHOICE_LOOKUP_TIMEOUT`、`WHOICE_ALLOW_CUSTOM_SERVERS` 等）。

**示例**

```toml
[auth]
mode = "token"
api_tokens = ["change-me"]

[rate_limit]
enabled = true
anon = "60/min"

[ai]
enabled = true
provider = "openai-compatible"          # 或 "ollama"
base_url = "https://api.example.com/v1"
api_key = "..."
model = "..."
```

**说明**

- **自定义服务器**：`rdap_server`、`whois_server`、`whois_follow` 参数默认拒绝，需设置 `allow_custom_servers = true`；内网与回环地址还需 `allow_private_servers = true`。详见 [SECURITY.md](./docs/SECURITY.md)。
- **AI 解析**：在主结果返回后运行，只补充解析器未填的字段；缓存的是 AI 分析结果，不是查询结果。设置 `cache_ttl = "0"` 关闭缓存。
- **ICP 备案**：使用独立接口，不会拖慢 WHOIS 与 RDAP 结果。界面默认手动查询，设置 `auto_query = true` 后自动查询。设置 `upstream_url` 可改用兼容 ICP_Query 的服务，而不直接请求工信部。
- **DNS**：每次都会请求所有已配置的解析器，以发现分区解析差异。将某个解析器列表设为 `none` 即可关闭。

## 数据覆盖

参考数据已内置在镜像中。放在 `./data` 下的文件优先生效：

| 路径 | 覆盖内容 |
|---|---|
| `rdap-bootstrap/{dns,ipv4,ipv6,asn}.json`、`extra.json` | IANA RDAP bootstrap 及本地补充 |
| `whois-servers/iana.json`、`extra.json` | WHOIS 服务器映射 |
| `public-suffix/public_suffix_list.dat`、`extra.dat` | Public Suffix List 及本地补充 |
| `registrars/icann-accredited-registrars.csv` | ICANN 注册商信息 |
| `brands/brand-map.json` | 注册商与 NS 服务商识别规则 |
| `pricing/pricing.json` | 本地价格备用数据 |
| `enrichment/moz.json` | 本地 Moz 数据 |

若某个后缀找不到 RDAP 服务器，API 会回退到在线 IANA bootstrap。

## API

| 接口 | 说明 |
|---|---|
| `GET /api/lookup` | 查询，返回 `{ ok, result, error, meta }` |
| `POST /api/lookup/enrich` | 对结果做延迟补充（DNS、价格） |
| `POST /api/lookup/ai` | 后台 AI 注册信息分析 |
| `GET /api/icp?domain=` | ICP 备案查询 |
| `GET /api/health`、`/api/version`、`/api/capabilities` | 健康检查、版本与插件、功能开关 |
| `GET /api/metrics` | Prometheus 指标 |
| `/api/admin/*` | 管理面板接口（需管理密码或登录会话） |

查询参数：`query`（域名、IP、CIDR、ASN 或 URL）；`rdap=1` 或 `whois=1` 只使用单一来源；`exact_domain=1` 不缩减到可注册域；`stream=1` 以 NDJSON 逐个来源返回预览（Web 界面使用此方式）；`rdap_server`、`whois_server`、`whois_follow` 用于自定义服务器。

```sh
curl "http://127.0.0.1:18080/api/lookup?query=example.com"
```

响应结构定义在 [`packages/schema`](./packages/schema)。Web 界面的 `/docs` 页面提供 API 参考。

## 开发

环境要求：Go 1.26、Node.js 24、pnpm 10。

```sh
pnpm install
pnpm dev:api    # API 运行在 :8080，并生成 ./data/whoice.toml
pnpm dev:web    # Web 界面运行在 :18081
```

| 命令 | 检查内容 |
|---|---|
| `pnpm test` | 除端到端测试外的全部检查 |
| `pnpm test:api` | Go 单元测试 |
| `pnpm test:web` | TypeScript、主题约束检查与 i18n 门禁 |
| `pnpm test:schema` | JSON Schema、OpenAPI 与 fixture 契约 |
| `pnpm test:data` | 数据快照清单、哈希与路由 |
| `pnpm test:pre5`、`pnpm test:phase5` | 架构与生产化约束 |
| `pnpm test:e2e` | Playwright 桌面与移动端测试 |

i18n 门禁（`pnpm test:i18n`）会在 Web 界面出现未经翻译的可见文字时报错。共用文案用 `lib/i18n.tsx` 的 `t("key")`（三种语言必须都定义），页面专属文案用 `t3("English", "简体中文", "繁體中文")`。

实时 WHOIS 检查默认跳过，可用 `WHOICE_LIVE_WHOIS_SMOKE=1 go test ./services/lookup-api/internal/providers/whois -run TestLiveWHOISSmoke` 运行。API 响应结构有意变更后，用 `WHOICE_UPDATE_RUNTIME_FIXTURES=1` 重新生成 runtime fixture。用 `pnpm update:psl` 更新 Public Suffix List。

本地构建镜像：

```sh
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.build.yml up --build
```

## 发布

推送版本 tag（如 `v0.1.0`）会发布 `ghcr.io/xmzo/whoice-lookup-api` 与 `ghcr.io/xmzo/whoice-web`。各架构在 GitHub 托管的原生 runner 上构建后合并为多架构镜像，不使用 QEMU 模拟。

## 文档

- [docs/OPERATIONS.md](./docs/OPERATIONS.md)：健康检查、指标、事件上报、发布、回滚与数据更新
- [docs/SECURITY.md](./docs/SECURITY.md)：自定义服务器、鉴权、限流与 webhook 上报
- [docs/IMPLEMENTATION_STATUS.md](./docs/IMPLEMENTATION_STATUS.md)：已实现功能与计划对照
- [docs/COMPATIBILITY_BACKLOG.md](./docs/COMPATIBILITY_BACKLOG.md)：解析器与 WHOIS Web 覆盖待办
- [PLAN.md](./PLAN.md)：架构与路线图
