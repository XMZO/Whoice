# Whoice 项目计划书

> 目标：建设一个集合 `whois-domain-lookup` 的 TLD 兼容性、访问控制、手动服务器能力，以及 `next-whois` 的现代 UI、多类型查询、缓存、分享、i18n、增强信息能力的新一代 WHOIS/RDAP 查询平台。

本文档不是“功能清单堆砌”，而是项目的工程蓝图。每个计划项都必须回答：

- 为什么必要
- 为什么这是当前最佳方案
- 替代方案为什么暂不采用
- 如何做到模块化、可插拔、可降级

## 0. 参考项目与 unofficial 目录

本项目仓库内的 `unofficial/` 目录用于存放参考项目源码：

```txt
unofficial/
  whois-domain-lookup/           # PHP 项目，重点参考 TLD 兼容、parser、数据源、访问控制
  next-whois/                    # Next.js 项目，重点参考现代 UI、多类型查询、i18n、缓存、OG、增强信息
```

### 使用原则

- `unofficial/` 是参考资料区，不是 Whoice 的运行时代码。
- 新项目不得直接依赖 `unofficial/` 内的源码、依赖或构建产物。
- 可以阅读、对比、迁移思路、重写实现、提取测试样本和数据结构经验。
- 迁移任何功能前，都要先判断它是否符合 Whoice 的插件化边界。
- 迁移 parser 或数据源规则时，必须落到 Whoice 自己的模块、fixture 和测试里。
- 如果保留第三方项目原始文件，必须尊重其许可证和署名要求。

### 必要性

两个参考项目刚好互补：

- `unofficial/whois-domain-lookup` 对特殊 TLD、WHOIS Web fallback、server data、reserved/unregistered 判断很有价值。
- `unofficial/next-whois` 对多类型查询、现代交互、i18n、动态 OG、缓存、增强信息很有价值。

把它们放进 `unofficial/`，可以让后续开发随时对照真实实现，而不是依赖记忆或外部仓库状态。

### 当前最佳方案

保留 `unofficial/` 作为“本地参考镜像”，但 Whoice 采用干净重构：

- 架构按 Whoice 的 Go API + Next.js Web 重新设计。
- 功能按模块重写。
- 兼容性按 fixture 验证后逐步迁移。
- UI 体验只借鉴交互结果，不照搬组件结构。

### 替代方案为什么暂不采用

- 直接 fork 其中一个项目：会继承原项目架构边界，无法自然得到两个项目的集合。
- 把两个项目代码混入主源码：会形成 PHP、TS、Go 混杂依赖，长期维护困难。
- 不保留本地参考：后续迁移 parser 和行为细节时成本更高。

## 1. 项目定位

### 1.1 产品目标

Whoice 是一个面向个人、开发者、域名投资者、运维人员和 API 使用者的查询工具，支持：

- 域名 WHOIS/RDAP 查询
- IPv4、IPv6 查询
- ASN 查询
- CIDR 查询
- 原始数据展示和结构化解析
- TLD 特化兼容
- 可选缓存、鉴权、增强信息、分享图片、PWA、多语言

### 1.2 设计目标

- 查询核心稳定：WHOIS TCP 43、RDAP HTTP、IP/ASN 查询都应可控、可限时、可观测。
- 模块化可插拔：所有非核心能力都通过接口挂载，禁用后系统仍能查询。
- Docker-first：公开部署时优先保证 TCP WHOIS 稳定，不把核心能力绑死在 serverless。
- UI 和查询核心分离：前端只消费统一 JSON，不关心数据来自 WHOIS、RDAP 还是增强模块。
- 兼容性可演进：先建立 parser 框架和测试样本，再逐步迁移特殊 TLD 规则。

### 1.3 非目标

- 不在第一阶段做微服务拆分。
- 不在第一阶段追求全量 TLD 特化 parser 迁移。
- 不把 Redis、Moz、价格 API 设为必需依赖。
- 不为了“技术统一”强行全 Go 或全 TypeScript。

## 2. 总体技术路线

### 2.1 推荐架构

采用：

```txt
Next.js Web + Go Lookup API + 可选 Redis
```

这是一个“前后端分离的模块化单体”架构：

- Web 负责体验、展示、i18n、主题、历史、PWA、OG、文档页。
- Go API 负责查询、解析、缓存、鉴权、限流、插件调度。
- Redis 是可选缓存层，没有 Redis 时自动退化为 memory/noop cache。

### 2.2 为什么 Go 后端是必要的

WHOIS 不是普通 REST API。它依赖 TCP 43，行为不统一，响应慢且易超时。Go 对这类网络 I/O 很合适：

- `net.Dialer`、`context.Context`、timeout、并发控制天然好用。
- 单二进制部署简单，Docker 镜像小。
- 长连接、限流、熔断、取消请求都比 serverless API route 更可控。
- 后续做高并发查询时，Go 的资源占用更稳定。

### 2.3 为什么前端仍用 Next.js

WHOIS 工具的体验层需要：

- 结果页 SEO
- 动态 OG 图片
- PWA
- i18n
- 主题切换
- 交互式文档
- 浏览器 localStorage 历史

这些是 Next.js 的舒适区。用 Go 做前端会牺牲开发效率和体验生态。

### 2.4 替代方案评估

| 方案 | 结论 | 原因 |
|---|---|---|
| 全 TypeScript monorepo | 可行但不是最佳长期方案 | 复用前端类型方便，但 TCP WHOIS、长期 API 服务、Docker 运维不如 Go 稳 |
| 全 Go | 不推荐 | 后端优秀，但现代 Web UI、i18n、PWA、OG 开发成本高 |
| 纯 Next.js API Routes | 不推荐作为主方案 | serverless 环境对 TCP WHOIS、长 timeout、依赖和并发不够稳定 |
| 微服务架构 | 暂不采用 | 项目前期复杂度主要是规则和解析，不是服务规模 |
| PHP 延续方案 | 不推荐新项目采用 | 部署简单，但类型系统、现代 UI、并发查询和插件化扩展不占优 |

## 3. 仓库结构规划

建议初始目录：

```txt
Whoice/
  unofficial/                    # 两个参考项目的本地镜像，只读参考，不作为运行时代码
    whois-domain-lookup/
    next-whois/

  apps/
    web/                         # Next.js 前端
      src/
        app/ or pages/
        components/
        features/
        lib/
        locales/
      public/
      package.json

  services/
    lookup-api/                  # Go 查询 API
      cmd/whoice-api/
      internal/
        app/
        config/
        http/
        lookup/
        model/
        plugin/
        providers/
        parsers/
        merger/
        enrich/
        cache/
        auth/
        ratelimit/
        observability/
        data/
      go.mod

  packages/
    schema/                      # OpenAPI、JSON Schema、共享协议
    fixtures/                    # parser golden fixtures
    data/                        # 生成后的 PSL / IANA / registrar 数据快照

  docs/
    architecture/
    api/
    decisions/

  scripts/
    update-data/
    generate-schema/
    test-fixtures/

  deploy/
    docker/
    compose/
    nginx/

  PLAN.md
  README.md
```

### 必要性

把 Web、API、schema、fixtures、deploy 明确分开，能避免后续“前端组件里混查询规则”“API 里混页面逻辑”的问题。

### 当前最佳方案

单仓库多应用比多仓库更适合早期开发：

- 一个 PR 能同时改 API、schema、UI。
- fixtures 和 schema 可以被前后端共享。
- 发布流程可统一管理。

### 暂不采用的方案

- 不拆多个 git repo：早期协调成本高。
- 不把 Go 代码放进 Next.js 项目目录：会让部署、测试、依赖边界混乱。

### 插拔边界

模块边界由 API schema 和 Go interface 定义；Web 只依赖 HTTP JSON，不直接导入 Go 逻辑。

## 4. 核心请求流

```txt
Browser / API Client
        |
        v
Next.js Web or direct API client
        |
        v
Go lookup-api
        |
        +--> Auth plugin
        +--> Rate limit plugin
        +--> Cache plugin
        |
        v
Query Normalizer
        |
        +--> RDAP Provider
        +--> WHOIS Provider
        +--> WHOIS Web Provider
        +--> IP/ASN Provider
        |
        v
Parser Registry
        |
        v
Merger
        |
        v
Enrichment Pipeline
        |
        v
Unified Result JSON
```

## 5. 统一数据模型计划

### 5.1 查询类型

```go
type QueryType string

const (
  QueryDomain QueryType = "domain"
  QueryIPv4   QueryType = "ipv4"
  QueryIPv6   QueryType = "ipv6"
  QueryASN    QueryType = "asn"
  QueryCIDR   QueryType = "cidr"
  QueryURL    QueryType = "url"
  QueryUnknown QueryType = "unknown"
)
```

### 5.2 统一结果模型

```json
{
  "query": "example.com",
  "normalizedQuery": "example.com",
  "type": "domain",
  "status": "registered",
  "source": {
    "primary": "rdap",
    "used": ["rdap", "whois"],
    "errors": []
  },
  "domain": {
    "name": "example.com",
    "unicodeName": "example.com",
    "punycodeName": "example.com",
    "suffix": "com",
    "registeredDomain": "example.com",
    "reserved": false,
    "registered": true
  },
  "registry": {
    "name": "",
    "website": "",
    "whoisServer": "",
    "rdapServer": ""
  },
  "registrar": {
    "name": "",
    "url": "",
    "ianaId": "",
    "whoisServer": "",
    "rdapServer": "",
    "brand": null
  },
  "dates": {
    "createdAt": "",
    "updatedAt": "",
    "expiresAt": "",
    "availableAt": "",
    "ageDays": null,
    "remainingDays": null
  },
  "statuses": [
    {
      "code": "clientTransferProhibited",
      "label": "Client Transfer Prohibited",
      "category": "client",
      "description": "",
      "url": "https://icann.org/epp#clientTransferProhibited"
    }
  ],
  "nameservers": [
    {
      "host": "ns1.example.com",
      "brand": null
    }
  ],
  "dnssec": {
    "signed": null,
    "text": ""
  },
  "registrant": {
    "organization": "",
    "country": "",
    "province": "",
    "email": "",
    "phone": ""
  },
  "network": {
    "cidr": "",
    "range": "",
    "name": "",
    "type": "",
    "originAS": "",
    "country": ""
  },
  "enrichment": {
    "pricing": null,
    "moz": null
  },
  "raw": {
    "whois": "",
    "rdap": ""
  },
  "meta": {
    "cached": false,
    "elapsedMs": 0,
    "warnings": [],
    "traceId": ""
  }
}
```

### 必要性

两个参考项目的主要差异就在数据模型。`whois-domain-lookup` 的模型偏域名，`next-whois` 的模型加入了 IP/ASN、价格、Moz、registrant。新项目必须先统一模型，否则 UI、API、parser 会互相牵扯。

### 当前最佳方案

采用“宽模型 + 空值降级”：

- 域名结果填 `domain`、`registrar`、`dates`。
- IP/ASN 结果填 `network`。
- 没有配置增强服务时 `enrichment` 为 `null`。
- 原始响应统一放 `raw`。

这样 API 稳定，UI 判断简单。

### 替代方案

- 分别设计 DomainResult、IPResult、ASNResult：类型更精确，但 API 消费复杂。
- 完全扁平字段：简单但会污染命名，长期不可维护。

### 插拔边界

所有 provider、parser、enricher 都只产出或修改统一 `LookupResult`。插件不得直接返回自定义顶层结构；自定义内容必须放在 `extensions` 或 `enrichment` 子树。

## 6. 模块计划

## 6.1 Query Normalizer

### 职责

- 接收用户输入。
- 去除协议、路径、端口、空白、多余点。
- 识别 domain、IPv4、IPv6、ASN、CIDR、URL。
- IDN unicode/punycode 转换。
- public suffix 解析。
- 生成 normalized query。

### 必要性

输入清洗是所有查询的入口。如果这里不统一，后面 provider、cache key、history、OG、API 都会出现不一致。

### 当前最佳方案

Go 后端实现一份权威 normalizer，前端只做轻量提示，不承担最终判断。

推荐依赖：

- `net/netip`：IPv4、IPv6、CIDR 判断。
- `golang.org/x/net/idna`：IDN 转换。
- `golang.org/x/net/publicsuffix` 或内置 PSL 数据：域名 suffix 解析。

### 替代方案

- 前后端各写一份：容易行为不一致。
- 完全依赖正则：IPv6、IDN、URL 边界会很脆。
- 直接沿用 tldts：TS 生态好，但核心判断应在后端。

### 插拔设计

```go
type Normalizer interface {
  Normalize(ctx context.Context, input string) (*NormalizedQuery, error)
}
```

后续可插入：

- 自定义保留域名规则
- 私有后缀规则
- 企业内网域名规则

## 6.2 Lookup Orchestrator

### 职责

- 根据 query type 决定调用哪些 provider。
- 控制并发、timeout、fallback、重试。
- 收集原始数据、错误、耗时。
- 调用 parser、merger、enrichment。

### 必要性

不能让 HTTP handler 直接调用 RDAP/WHOIS，否则查询策略会分散，后续加入缓存、fallback、观测会很痛苦。

### 当前最佳方案

Orchestrator 是核心服务层，采用策略配置：

```yaml
lookup:
  timeout: 15s
  rdapFirst: true
  parallelDomainLookup: true
  whoisFallback: true
  whoisWebFallback: true
  maxWhoisFollow: 1
```

域名查询默认 RDAP 和 WHOIS 并发，RDAP 优先合并：

- RDAP 成功：作为主结果。
- WHOIS 成功：补充 registrar server、原始数据、特殊字段。
- RDAP 失败 WHOIS 成功：WHOIS 结果兜底。
- 二者都失败：返回结构化错误。

### 替代方案

- 串行 RDAP 后 WHOIS：更省资源，但慢，用户体验差。
- 只 RDAP：现代但覆盖不全。
- 只 WHOIS：传统但结构化弱，IP/ASN RDAP 优势丢失。

### 插拔设计

```go
type Provider interface {
  Name() string
  Supports(q NormalizedQuery) bool
  Lookup(ctx context.Context, q NormalizedQuery, opts LookupOptions) (*RawResponse, error)
}

type Orchestrator interface {
  Lookup(ctx context.Context, input string, opts LookupOptions) (*LookupResult, error)
}
```

Provider 可通过注册表挂载：

```go
registry.RegisterProvider(rdapProvider)
registry.RegisterProvider(whoisProvider)
registry.RegisterProvider(whoisWebProvider)
```

## 6.3 RDAP Provider

### 职责

- 查询域名 RDAP。
- 查询 IP RDAP。
- 查询 ASN/autnum RDAP。
- 支持 IANA bootstrap 数据。
- 支持手动 `rdap-server`。
- 校验 JSON content type 并保留原始 JSON。

### 必要性

RDAP 是现代标准，结构化程度高，对 IP/ASN 支持更自然。它应是主数据源。

### 当前最佳方案

自写 RDAP HTTP client：

- 控制 User-Agent。
- 支持 bootstrap。
- 支持 timeout。
- 支持 404 作为未注册/未找到状态，而不是普通异常。
- 支持重定向。
- 支持非标准 content type 容错。

### 替代方案

- 依赖 node-rdap：前端项目方便，但 Go 后端不适用。
- 依赖大型 Go RDAP 库：短期省事，但特殊行为难掌控。

### 插拔设计

```go
type RDAPBootstrap interface {
  ServerForDomain(tld string) (string, bool)
  ServerForIP(ip netip.Addr) (string, bool)
  ServerForASN(asn uint32) (string, bool)
}
```

bootstrap 数据源可切换：

- embedded static data
- local file
- remote auto-updated file

## 6.4 WHOIS Provider

### 职责

- TCP 43 查询。
- 根据 TLD 选择 WHOIS server。
- 支持手动 `whois-server`。
- 支持 query template。
- 支持 follow registrar whois。
- 处理编码转换。
- timeout、重试、错误归类。

### 必要性

大量 TLD 或注册商数据仍依赖 WHOIS。仅 RDAP 会损失覆盖率。

### 当前最佳方案

Go 自写 TCP client：

- 不先引入 whois 大库。
- 行为简单可控。
- 可按 TLD 配 query template。
- 可记录每一跳 server 和 raw response。

### 替代方案

- 直接用第三方 whois 库：快，但行为黑盒，后面处理特殊 TLD 会受限。
- 继承 PHP socket 逻辑：思路可借鉴，代码不迁移。

### 插拔设计

```go
type WHOISServerResolver interface {
  Resolve(q NormalizedQuery, opts LookupOptions) (*WHOISServer, error)
}

type WHOISClient interface {
  Query(ctx context.Context, server WHOISServer, query string) (*RawResponse, error)
}
```

Server 数据可插拔：

- IANA whois server snapshot
- extra whois server json
- user override
- runtime admin override

## 6.5 WHOIS Web Provider

### 职责

处理没有公开 WHOIS server 或 WHOIS 质量很差的 TLD，通过官网接口或网页抓取补充数据。

### 必要性

这是 `whois-domain-lookup` 的强项。很多 ccTLD 的可用性来自这类 fallback。

### 当前最佳方案

阶段内不迁移全部网页 scraper，避免把核心兼容性绑定到大量易碎页面结构。按价值逐步迁移：

1. 高频 TLD。
2. 没有 RDAP/WHOIS 的 TLD。
3. 已有 PHP 实现且稳定的 TLD。
4. 优先选择稳定 JSON/API fallback；网页 XPath scraper 只有在没有其他方案、且可隔离测试时才加入。

当前落地：

- `NoticeModule` 覆盖只适合人工跳转的官方页面。
- `.dz`、`.ni`、`.vn` 采用稳定 API 型 fallback，输出标准 WHOIS-like raw body。
- 每个 fallback 模块必须有隔离测试，不依赖 `unofficial/` 运行时代码。

### 替代方案

- 第一阶段全迁移：工作量大，容易引入大量脆弱 scraper。
- 完全不做：会丢掉参考项目最重要的兼容性优势。

### 插拔设计

```go
type WebFallbackProvider interface {
  Provider
  TLDs() []string
}
```

每个 web fallback 独立模块：

```txt
providers/whoisweb/
  registry.go
  ba.go
  ph.go
  vn.go
  ...
```

每个模块必须有 fixture 测试，避免官网改版时无声失败。

## 6.6 Parser Registry

### 职责

- 把 raw WHOIS/RDAP 转换为统一模型。
- 通用 parser 处理大多数情况。
- 特殊 TLD parser 覆盖异常格式。
- 支持 parser 优先级。
- 输出 parse confidence 和 warnings。

### 必要性

WHOIS 最大难点不是查询，而是解析。没有 registry，特殊规则会散落在代码各处。

### 当前最佳方案

分三层：

```txt
RDAP Parser       # 结构化 JSON，优先级最高
Generic WHOIS     # 通用 key-value / regex parser
TLD Parser        # 特殊 TLD 覆盖
```

Parser 接口：

```go
type Parser interface {
  Name() string
  Supports(input ParseInput) bool
  Priority() int
  Parse(ctx context.Context, input ParseInput) (*PartialResult, error)
}
```

### 替代方案

- 一个巨大 parser：短期快，长期不可维护。
- 每个 TLD 都写 parser：过度工程，测试成本太高。

### 插拔设计

Parser 通过注册：

```go
parsers.Register(GenericWHOISParser{})
parsers.Register(RDAPParser{})
parsers.Register(TLDParserCOM{})
parsers.Register(TLDParserUK{})
parsers.Register(TLDParserIT{})
parsers.Register(TLDParserEU{})
parsers.Register(TLDParserBE{})
```

每个 parser 只能产出 `PartialResult`，不能直接决定最终状态；最终由 Merger 统一裁决。

当前迁移进度：已参考 `unofficial/whois-domain-lookup` 的 TLD parser 分层思路，并结合 `unofficial/next-whois` 对常见 TLD 的格式识别经验，重写 UK、JP、FR、CN、BR、IT、EU、BE、PL、CZ、HU、SK、RO、DE、NL、CA、AU、SE/NU、FI、KR、AT、RU/SU、EE、BG、KG、TR、HK、TW、SI、UA、ID。每个新增 parser 都作为独立可插拔模块注册，并配套 raw/expected golden fixture；schema 校验会把这些 fixture 转成 API response 样本，避免 parser、API、Web 类型漂移。后续继续按“高价值 TLD + 真实样本 + schema fixture 校验”的节奏迁移。

## 6.7 Merger

### 职责

- 合并 RDAP、WHOIS、WHOIS Web、IP/ASN 结果。
- 解决字段冲突。
- 标记数据来源。
- 计算最终状态 registered/unregistered/reserved/unknown/error。

### 必要性

多数据源必然冲突。比如 RDAP 返回注册商，WHOIS 返回更具体的 registrar whois server。合并规则必须集中。

### 当前最佳方案

采用字段级优先级：

| 字段 | 优先级 |
|---|---|
| domain name | RDAP > WHOIS parser > normalized query |
| registration status | RDAP 404 > reserved parser > WHOIS unavailable parser > registered parser |
| dates | RDAP > TLD parser > generic WHOIS |
| registrar | RDAP > WHOIS registrar parser > ICANN CSV enrichment |
| raw data | 全部保留 |
| network fields | IP/ASN RDAP > WHOIS IP parser |

### 替代方案

- 简单 RDAP 覆盖 WHOIS：会丢掉 WHOIS 独有字段。
- 简单 WHOIS 覆盖 RDAP：结构化质量下降。
- 让 parser 自己合并：规则分散。

### 插拔设计

```go
type MergeRule interface {
  Field() string
  Merge(current, incoming FieldValue) FieldValue
}
```

早期可内置规则，后续开放自定义规则。

## 6.8 Enrichment Pipeline

### 职责

在基础查询之后追加增强信息：

- EPP 状态解释
- 注册商品牌识别
- NS 品牌识别
- ICANN registrar 补全
- 域名价格
- Moz DA/PA/Spam
- DNSViz 链接

### 必要性

增强功能提升体验，但不应该影响主查询成功率。必须作为可选 pipeline。

### 当前最佳方案

Enricher 统一接口：

```go
type Enricher interface {
  Name() string
  Enabled(cfg Config) bool
  Supports(result *LookupResult) bool
  Enrich(ctx context.Context, result *LookupResult) error
}
```

Pipeline 行为：

- 每个 enricher 独立 timeout。
- 失败只写 warning，不让主查询失败。
- 可配置启用/禁用。
- 可配置并发执行或串行执行。

### 替代方案

- 查询过程中直接调用价格/Moz：会拖慢主查询。
- UI 自己调用增强 API：前端复杂，API key 泄漏风险。

### 插拔设计

```yaml
enrich:
  epp: true
  brands: true
  registrarCsv: true
  pricing:
    enabled: false
    provider: nazhumi
  moz:
    enabled: false
```

## 6.9 Cache / Freshness Layer

### 职责

- 保证 WHOIS/RDAP 查询结果实时。
- 合并同一瞬间的重复 live 查询。
- 缓存慢变化静态数据。
- 避免缓存错误和过期域名状态。

### 必要性

WHOIS/RDAP 查询慢、外部服务不稳定，也可能被限流。但域名状态、到期时间、转移状态对用户来说有强时效性，查询结果缓存会让工具失去可信度。Whoice 因此把“加速”从结果缓存改为 fresh-first：每次查询都打实时 provider，只缓存 RDAP bootstrap、registrar CSV、brand map、WHOIS server list 等慢变化数据。

### 当前最佳方案

Freshness adapter：

```go
type InflightGroup interface {
  Do(ctx context.Context, key string, fn func(context.Context) (*LookupResult, error)) (*LookupResult, error)
}
```

实现：

- In-process singleflight：生产和单机都默认启用，只合并并发中的相同请求。
- Static data registry：RDAP bootstrap、registrar CSV、brand map、WHOIS server list 可内置、挂载或自动更新。
- No result cache：不保存 WHOIS/RDAP 查询结果，不保存错误结果。

缓存策略：

| 数据 | 策略 |
|---|---|
| registered domain | 不缓存，每次 live lookup |
| unregistered domain | 不缓存，每次 live lookup |
| timeout/error | 不缓存 |
| IP/ASN | 不缓存结果，只缓存 RDAP bootstrap 数据 |
| static data | 按版本长期缓存，可挂载覆盖 |

### 替代方案

- Redis/Memory result cache：速度更快，但会牺牲 WHOIS 时效性，和项目定位冲突。
- stale-while-revalidate：体验好，但用户看到的仍可能是旧状态，不作为默认方案。
- 只用 HTTP CDN cache：无法细分错误和内部 provider 结果。

### 插拔设计

结果缓存不作为第一阶段插件暴露。后续如果确实要给高流量公开站点提供缓存，也必须默认关闭，并在 API/UI 中明确显示 `fresh=false`、缓存时间和刷新入口。

```txt
WHOICE_RESULT_CACHE_ENABLED=false
WHOICE_STATIC_DATA_DIR=/data
```

## 6.10 Auth 与访问控制

### 职责

- 站点访问密码。
- API Bearer Token。
- 可选匿名访问。
- 可选 admin token。

### 必要性

`whois-domain-lookup` 有访问控制，这是自部署工具很实用的功能。新项目应保留并扩展。

### 当前最佳方案

分层：

- Web password：用于页面访问。
- API token：用于程序调用。
- Admin token：未来用于刷新缓存、查看健康状态、更新数据。

### 替代方案

- 只做页面密码：API 不安全。
- 完整 OAuth：过度复杂，不适合第一阶段。

### 插拔设计

```go
type AuthProvider interface {
  Authenticate(ctx context.Context, r *http.Request) (*Principal, error)
}
```

实现：

- NoopAuth
- PasswordAuth
- BearerTokenAuth
- Future: OIDCAuth

## 6.11 Rate Limit

### 职责

- 限制匿名 API 频率。
- 防止滥用 WHOIS/RDAP。
- 区分页面和 API。
- 区分 token。

### 必要性

公开 WHOIS 服务很容易被刷。没有限流会伤害外部 WHOIS/RDAP 服务，也会拖垮自身。

### 当前最佳方案

Token bucket：

- 内存版用于单实例。
- Redis 版用于多实例。

### 替代方案

- 只依赖 Nginx/Cloudflare：部署依赖外部设施，应用自身不可控。
- 第一阶段完全不做：公开部署风险高。

### 插拔设计

```go
type RateLimiter interface {
  Allow(ctx context.Context, key string, cost int) (Decision, error)
}
```

## 6.12 Data Registry

### 职责

管理静态数据：

- Public Suffix List
- IANA RDAP bootstrap
- WHOIS server list
- extra server list
- ICANN registrar CSV
- EPP status mapping
- registrar/NS brand mapping
- parser/API schema fixture samples

### 必要性

这些数据会更新，且直接影响查询结果。必须版本化、可更新、可回滚。

### 当前最佳方案

数据作为 repo snapshot + 自动更新脚本：

- 默认内置数据，离线可运行。
- 运行时先读同级 `./data` 挂载目录，再回退到 embedded snapshot。
- 定时 GitHub Action 拉取更新。
- 更新后跑数据格式校验、schema fixture 校验和基础查询测试。
- 品牌识别参考 `unofficial/next-whois` 的 registrar/NS UI 经验，但落为 Whoice 自己的 `brand-map.json`，避免把品牌规则写死在页面里。
- WHOIS server map 参考 `unofficial/whois-domain-lookup` 的 IANA/extra 数据，但在 Whoice 内落为 embedded/file loader，支持 CentralNic 等二级后缀优先匹配。

### 替代方案

- 每次运行时远程拉取：启动慢且不稳定。
- 完全手写维护：容易过期。

### 插拔设计

```go
type DataSource interface {
  Name() string
  Load(ctx context.Context) (*DataBundle, error)
}
```

支持：

- EmbeddedDataSource
- FileDataSource
- RemoteDataSource

## 6.13 API Layer

### 职责

提供稳定 HTTP API。

初始接口：

```txt
GET /api/lookup?query=example.com
GET /api/lookup?query=example.com&whois=1&rdap=1
GET /api/lookup?query=example.com&whois_server=whois.example.net
GET /api/lookup?query=example.com&rdap_server=https://rdap.example.net
GET /api/og?query=example.com
GET /api/servers?type=whois&tld=com
GET /api/health
GET /api/version
```

### 必要性

API 是项目能力的核心出口，前端也应通过 API 使用结果。

### 当前最佳方案

Go API 使用 `net/http` + `chi`：

- 简洁。
- 无重框架依赖。
- middleware 生态足够。

### 替代方案

- Gin/Fiber：也可行，但没必要引入更重风格。
- gRPC：内部服务有用，但公开 API 不如 HTTP JSON 友好。

### 插拔设计

HTTP middleware 均可插拔：

- auth middleware
- rate limit middleware
- request id middleware
- logging middleware
- CORS middleware

## 6.14 Web UI

### 职责

- 搜索首页。
- 结果页。
- 历史记录。
- 高级查询选项。
- 原始数据面板。
- API 文档页。
- 动态 OG 图片入口。
- 语言、主题、PWA。
- 插件化增强信息展示。
- 查询来源、缓存、错误、warning 的透明展示。

### 必要性

`next-whois` 的核心优势在体验。新项目如果只有 API，就没有集合两者优点。

但 UI 不是简单“换皮”。Whoice 的 UI 必须解决三个问题：

1. 普通用户要一眼知道“这个域名/IP/ASN 是什么状态”。
2. 技术用户要快速看到证据：WHOIS、RDAP、server、raw response、parser warning。
3. 自部署用户要能控制能力：数据源开关、自定义 server、缓存、鉴权、增强模块。

所以 Whoice 的 UI 定位应是：

```txt
一个查询工作台，而不是一个营销首页。
一个证据透明的 domain intelligence console，而不是只给出结论的漂亮卡片。
```

### 当前最佳方案

Next.js + Tailwind + shadcn/ui：

- 组件成熟。
- 文档页、OG、PWA、i18n 都有现成生态。
- 与 `next-whois` 的功能迁移路径平滑。

UI 应取两个参考项目的精华，但不照搬任一方。

### 6.14.1 从 `unofficial/whois-domain-lookup` 提取的 UI 精华

#### 值得吸收

1. **首屏直接可用**

   `whois-domain-lookup` 打开就是搜索框，没有复杂导航，也没有营销内容。这一点非常适合查询工具。

   Whoice 应保留这个原则：

   - 首页第一视觉必须是搜索。
   - 不做大 hero。
   - 不把介绍文字放在主流程前面。
   - 示例、历史、文档入口都应服务搜索，而不是抢占搜索。

2. **状态结论清晰**

   PHP 项目的结果页先给出 message：

   - registered
   - unregistered
   - reserved
   - unknown
   - error

   这是非常正确的交互顺序。Whoice 应继续把“结论”放在结果页最上方。

   但要升级为更结构化的状态摘要：

   ```txt
   google.com
   Registered · Active · RDAP primary · WHOIS supplemental · cached 12m ago
   ```

3. **WHOIS/RDAP 开关简单直观**

   PHP 项目的 WHOIS/RDAP toggle 很直接，适合保留。

   Whoice 应将其升级为数据源控制：

   - Basic mode：Auto / RDAP only / WHOIS only。
   - Advanced mode：WHOIS server override、RDAP server override、follow depth、disable web fallback。

4. **原始数据作为一等信息**

   PHP 项目把 raw WHOIS/RDAP 放在结果页，并支持 tab 和复制。这是查询工具的可信来源。

   Whoice 必须保留：

   - Raw WHOIS tab。
   - Raw RDAP tab。
   - Copy raw。
   - Download raw。
   - Linkify URL/email。
   - JSON viewer。

   并进一步增强：

   - 显示 raw 来源 server。
   - 显示每个 provider 的耗时。
   - 显示 parser warning。
   - 显示字段来源，例如 `Registrar: RDAP`、`WHOIS Server: WHOIS follow`。

5. **信息分区朴素可靠**

   PHP 项目按 Registry、Registrar、Dates、Status and DNS 分区，用户容易扫描。

   Whoice 应保留这种稳定信息架构，但要适配更多查询类型：

   - Summary
   - Domain
   - Registry
   - Registrar
   - Dates
   - Status
   - Nameservers
   - DNSSEC
   - Registrant
   - Network
   - Raw Evidence

#### 不应照搬的问题

- 页面能力偏域名，不适合 IP/ASN/CIDR。
- UI 语言固定，不能满足 i18n。
- 历史、分享、API docs、主题手动切换不足。
- 结果卡片在信息变多时会变长，需要更强的布局系统。
- 原始数据复制很好，但缺少“来源解释”和“字段级 provenance”。

#### Whoice 的取舍

Whoice 应继承它的“可信、清楚、直达”，但不要继承它的“单页堆叠限制”。

```txt
保留：简单、结论先行、raw data、数据源控制。
改造：多类型查询、响应式布局、插件面板、字段来源、更多操作。
```

### 6.14.2 从 `unofficial/next-whois` 提取的 UI 精华

#### 值得吸收

1. **搜索框是产品核心**

   `next-whois` 的 SearchBox 支持历史、建议、常见 TLD、类型识别和快捷键。这非常适合 Whoice。

   Whoice 搜索框应支持：

   - domain / IPv4 / IPv6 / ASN / CIDR 自动识别。
   - URL 粘贴自动提取 host。
   - 历史建议。
   - 常见 TLD 补全。
   - `/` 聚焦搜索。
   - `Esc` 失焦或清空。
   - `Enter` 查询。
   - 查询类型 badge。

2. **历史记录有实际价值**

   WHOIS 工具经常重复查同一批域名/IP。历史不是装饰，是效率功能。

   Whoice 应支持：

   - localStorage 历史。
   - 按日期分组。
   - 按查询类型过滤。
   - 删除单条。
   - 清空历史。
   - 配置历史上限。

3. **多类型查询结果**

   `next-whois` 能展示 domain、IP、ASN、CIDR 的不同字段，这是 Whoice 必须继承的方向。

   Whoice UI 应根据 `result.type` 动态显示：

   - Domain result layout。
   - IP network layout。
   - ASN layout。
   - CIDR layout。
   - Unknown/error layout。

4. **分享和 OG 图片**

   查询结果经常被截图或转发。动态 OG、复制图片、下载 PNG 很有价值。

   Whoice 应保留：

   - Share menu。
   - Copy URL。
   - Copy API URL。
   - Download PNG。
   - Copy image。
   - Image preview。

   但生成图片不应塞满所有字段，只展示结论和核心证据。

5. **主题、语言、PWA 和 Docs**

   这些不是查询核心，但它们决定工具是否可长期使用。

   Whoice 应保留：

   - Light / Dark / System。
   - i18n。
   - PWA install。
   - 内置 API docs。
   - API 示例和响应 schema。

6. **EPP 状态解释和品牌识别**

   `next-whois` 的 EPP status、人类可读解释、Registrar/NS branding 能降低理解成本。

   Whoice 应吸收，但必须插件化：

   - EPP enrichment disabled 时，只显示原始状态。
   - Brand enrichment disabled 时，只显示文本。
   - Pricing/Moz disabled 时，不占 UI 空间。

#### 不应照搬的问题

- 结果页文件过大，UI、品牌映射、分享、raw panel、业务判断混在一起，后续维护困难。
- 视觉上偏“展示型”，对高频技术查询可以再紧凑一些。
- 高级查询控制不够突出，WHOIS/RDAP server override 不是核心交互。
- 大量增强信息可能压过原始证据，容易让工具看起来像“评分页”而不是“查询页”。
- 图标和品牌数据直接堆在页面文件里，不利于插件化。

#### Whoice 的取舍

Whoice 应继承它的“现代交互和完整体验”，但要把功能拆到 feature 和 plugin renderer。

```txt
保留：搜索体验、历史、快捷键、i18n、主题、分享、docs、品牌/EPP 展示。
改造：结果页信息密度、组件边界、增强模块插拔、高级查询控制。
```

### 6.14.3 Whoice 自己的 UI 思考

Whoice 的 UI 不应只是两个项目的合集，而应建立自己的产品结构。

#### UI 核心原则

1. **Query first**

   搜索永远是主角。首页、结果页、错误页都要能立即再次查询。

2. **Conclusion first, evidence always**

   先给结论，再给证据。所有结论都能追溯到 RDAP/WHOIS/raw data。

3. **Progressive disclosure**

   普通用户默认看到摘要。技术用户可以展开 raw、provider trace、server override、parser details。

4. **Plugin-aware layout**

   UI 不假设所有功能都存在。Redis、Moz、pricing、brand、EPP、auth、rate limit 都可能关闭。

5. **Dense but calm**

   结果页应适合扫描，不做大块装饰，不做营销式 hero。颜色用于状态和层级，不用于炫技。

6. **No card maze**

   可以使用面板和卡片，但不做卡片套卡片。重复实体用列表，页面区域用 full-width section 或布局列。

7. **Source transparency**

   用户应知道：

   - 结果来自 RDAP 还是 WHOIS。
   - 是否命中缓存。
   - 哪些 provider 失败。
   - 哪些字段由 parser 推断。
   - 哪些增强信息来自第三方。

#### 信息架构

##### 首页

```txt
Top Nav
  Whoice
  Docs
  API
  Theme
  Language
  GitHub

Main Search
  [ domain, IP, ASN, CIDR, or URL...              Search ]
  Query type preview
  Advanced disclosure

Below Search
  Recent queries
  Quick examples
  Optional API status
```

首页不做大段说明。说明和 API 文档进入 `/docs`。

##### 结果页 desktop

```txt
Sticky Top
  Compact search bar
  Data source mode
  Share / Copy / Docs

Status Strip
  Query
  Result status
  Query type
  Source badges
  Cache badge
  Elapsed time
  Warning count

Main Grid
  Left / Main
    Summary
    Domain or Network details
    Dates
    Status
    Nameservers
    Registrant

  Right / Inspector
    Registrar / Registry
    Provider trace
    Enrichment panels
    Actions

Bottom / Evidence
    Raw WHOIS
    Raw RDAP
    Parsed JSON
    Debug warnings
```

##### 结果页 mobile

```txt
Sticky Search

Tabs
  Summary
  Details
  Raw
  Share
  Debug
```

移动端避免长页面里到处找 raw data，Raw 应作为单独 tab。

#### 关键页面

1. `/`

   搜索首页和历史。

2. `/lookup/[query]`

   结果页。URL 应可分享。

3. `/docs`

   API 文档。

4. `/settings`

   本地设置：语言、主题、历史上限、默认数据源、是否显示 debug。

5. `/login`

   站点密码模式下的登录页。

6. `/status`

   可选。显示 API 健康状态、数据版本、启用插件。

#### 组件层级

```txt
components/
  primitives/             # Button, Input, Tabs, Badge, Tooltip, Dialog
  layout/                 # AppShell, TopNav, ResultLayout, MobileTabs
  lookup/
    SearchBox
    QueryTypeBadge
    SourceModeControl
    AdvancedLookupPanel
    StatusStrip
    ProviderTrace
    RawEvidencePanel
  result/
    SummaryPanel
    DomainPanel
    NetworkPanel
    RegistrarPanel
    RegistryPanel
    DatesPanel
    StatusPanel
    NameserverPanel
    RegistrantPanel
  enrich/
    EppStatusRenderer
    BrandBadge
    PricingPanel
    MozPanel
  actions/
    ShareMenu
    CopyButton
    DownloadButton
    OgPreviewDialog
  docs/
    ApiEndpointDoc
    SchemaViewer
    CodeExample
```

#### 必要性

把 result、lookup、enrich、actions 拆开，能防止 `next-whois` 那种结果页单文件膨胀问题。

#### 最佳性判断

这比“按页面写组件”更适合插件化。增强模块可以只提供自己的 renderer，不污染核心结果页。

#### 插件化 UI renderer

增强模块应能注册自己的前端展示入口：

```ts
type ResultPanelSlot =
  | "summary"
  | "details"
  | "inspector"
  | "raw"
  | "debug";

type ResultPanelPlugin = {
  id: string;
  slot: ResultPanelSlot;
  order: number;
  enabled: (ctx: UIContext) => boolean;
  render: (props: { result: LookupResult }) => React.ReactNode;
};
```

例子：

- EPP 插件注册到 `details`。
- Brand 插件注册到 `registrar` 和 `nameserver` 子组件。
- Moz 插件注册到 `inspector`。
- Pricing 插件注册到 `inspector`。
- Provider trace 插件注册到 `debug`。

第一阶段不需要动态加载远程 UI 插件，只需要本地注册机制。

### 6.14.4 视觉系统

#### 视觉定位

Whoice 应是：

```txt
quiet, technical, trustworthy, fast
```

而不是：

```txt
marketing, decorative, playful, heavy
```

#### 色彩

基础色：

- neutral / zinc 作为主界面。
- blue 只作为链接和信息色。
- green / amber / red / purple 用于状态。

状态色建议：

| 状态 | 色彩 |
|---|---|
| registered / active | green |
| unregistered / available | blue |
| reserved | amber |
| expired / error | red |
| pending / transfer / grace | purple or amber |
| unknown | neutral |

#### 字体

- UI：Geist Sans 或 Inter。
- Raw data / code：Geist Mono 或 JetBrains Mono。
- 不使用花哨 display font 作为核心 UI 字体。

#### 图标

使用 lucide-react 或现有 shadcn 生态兼容图标。按钮能用图标表达时优先图标 + tooltip：

- Search
- Copy
- Download
- Share
- Refresh
- External link
- Settings
- History
- Raw data
- Warning

文字按钮只用于明确命令，比如 `Search`、`Sign in`、`Run lookup`。

#### 形状和间距

- 控件 radius 以 `6px - 8px` 为主。
- 不使用过大圆角作为默认风格。
- 结果区密度适中，移动端要保证文本不挤压。
- 面板可以有边框，但少用重阴影。

#### 动效

动效只服务状态变化：

- 搜索框 focus。
- 历史建议出现。
- tab 切换。
- copy success。
- loading。

不做大范围页面漂移动效，避免影响工具感。

### 6.14.5 关键交互设计

#### 搜索交互

搜索框是命令入口：

```txt
input: https://example.com/path?a=1
normalized: example.com
type: domain
```

```txt
input: AS15169
normalized: AS15169
type: asn
```

```txt
input: 1.1.1.0/24
normalized: 1.1.1.0/24
type: cidr
```

搜索建议优先级：

1. 当前输入直接查询。
2. 历史匹配。
3. 常见补全。
4. 示例查询。

#### 高级查询

高级区默认折叠，避免吓到普通用户。

包含：

- Data source: Auto / RDAP / WHOIS。
- WHOIS server override。
- RDAP server override。
- WHOIS follow depth。
- Web fallback toggle。
- Bypass cache。
- Show debug。

安全限制：

- 如果后端禁用 custom server，UI 显示 disabled 和原因。
- 如果用户不是 admin，不显示危险项或以只读方式显示。

#### 结果状态

状态摘要必须显示：

- query。
- normalized query。
- type。
- final status。
- primary source。
- used sources。
- cached。
- elapsed。
- warnings。

示例：

```txt
example.com
Registered · Domain · RDAP primary · WHOIS supplemental · 824 ms · cached
```

#### Raw Evidence

Raw panel 是证据面板，不是附属品。

必须支持：

- WHOIS。
- RDAP。
- Parsed result。
- Provider trace。
- Copy。
- Download。
- Wrap lines。
- Search within raw。
- Collapse long notices。

#### 错误页

错误页不只显示错误。

应显示：

- 错误类型。
- 哪些 provider 失败。
- 是否是 timeout。
- 是否是 unsupported TLD。
- 可以尝试的操作：RDAP only、WHOIS only、manual server、bypass cache。

### 6.14.6 响应式策略

#### Desktop

- 结果页使用主内容 + inspector 双栏。
- Raw evidence 放底部 full width，适合横向滚动。
- Provider trace 可在右侧 inspector 中显示摘要。

#### Tablet

- 主内容单栏。
- inspector 面板折叠到 sections。
- Raw evidence 仍保持独立 section。

#### Mobile

- 使用 tabs。
- 搜索栏 sticky。
- Summary 第一屏必须完整可见。
- Raw data 使用独立 tab，避免长 raw 挤压详情。
- 分享和高级操作放入 action sheet。

### 6.14.7 可访问性和可用性

必须满足：

- 所有图标按钮有 `aria-label` 和 tooltip。
- 键盘可操作所有菜单和 tab。
- 搜索建议支持上下键。
- 状态不只靠颜色表达，必须有文本。
- raw data 可选择、可复制。
- loading 不阻断浏览历史结果。
- 文本在移动端不能溢出按钮或面板。

### 6.14.8 UI 功能开关

UI 必须根据 API 返回的 capabilities 渲染：

```json
{
  "capabilities": {
    "rdap": true,
    "whois": true,
    "whoisWeb": true,
    "customServers": false,
    "cache": true,
    "auth": "password",
    "enrichment": {
      "epp": true,
      "brands": true,
      "pricing": false,
      "moz": false
    }
  }
}
```

这样可以保证：

- 自部署关闭某功能时，UI 不出现无效入口。
- Vercel RDAP-only 模式下，WHOIS 相关 UI 自动降级。
- 增强插件未启用时，不出现空卡片。

### 6.14.9 UI 实施顺序

#### UI Phase A：工具骨架

- App shell。
- Top nav。
- SearchBox。
- Result status strip。
- Basic result panels。
- RawEvidencePanel。

#### UI Phase B：效率能力

- History。
- Search suggestions。
- Hotkeys。
- Advanced lookup panel。
- Copy/download raw。

#### UI Phase C：现代体验

- Theme switch。
- i18n。
- PWA。
- Docs。
- Share menu。
- OG preview。

#### UI Phase D：插件展示

- EPP status renderer。
- Registrar/NS brand renderer。
- Pricing panel。
- Moz panel。
- Provider trace/debug panel。

### 替代方案

- SvelteKit：体验好，但参考项目复用成本更高。
- Vue/Nuxt：可行，但当前参考代码是 React/Next。
- Go template：不适合复杂交互。
- 直接照搬 `next-whois` 页面：短期快，但页面会过大，且插件化边界不清。
- 直接照搬 `whois-domain-lookup` 页面：清爽但承载不了多类型查询和增强模块。

### 插拔设计

前端 feature 目录：

```txt
features/
  lookup/
  history/
  theme/
  i18n/
  pwa/
  share/
  docs/
  enrichment/
  raw-evidence/
  advanced-lookup/
  provider-trace/
```

每个 feature 都应能独立启停或隐藏入口。

UI 插件与后端插件的关系：

- 后端插件决定是否有数据。
- 前端插件决定如何展示数据。
- 前端不得假设后端插件一定存在。
- 后端返回 `capabilities` 和 `result.enrichment`，前端按能力渲染。

## 6.15 Dynamic OG / Image Export

### 职责

- 生成查询结果分享图。
- 支持宽高、主题、语言。
- 支持下载 PNG、复制图片、复制图片链接。

### 必要性

这不是核心查询能力，但对现代工具传播和分享很有价值。

### 当前最佳方案

OG 生成放在 Next.js web 层：

- 使用 `next/og` 或 Satori。
- 直接复用前端设计 token。
- Go API 不承担图像渲染。

### 替代方案

- Go 后端生成图片：可行但字体、布局、国际化成本高。
- 第一阶段不做：可以，但既然目标是两项目集合，应在第二阶段纳入。

### 插拔设计

OG 只依赖 `/api/lookup` 返回的数据。没有 Go API 时可显示基础品牌图。

## 6.16 i18n

### 职责

- 多语言 UI。
- 多语言 API 文档。
- 可选多语言 EPP 描述。

### 必要性

WHOIS 工具用户跨语言明显，`next-whois` 已经证明这项功能适合该产品。

### 当前最佳方案

前端 i18n 独立实现，语言文件放 `apps/web/src/locales`。

首批语言：

- en
- zh-CN
- zh-TW

后续再补：

- ja
- ko
- de
- fr
- ru

### 替代方案

- 第一阶段全量八语言：维护压力大。
- 后端负责翻译所有字段：没有必要，查询数据本身多为原文。

### 插拔设计

增强模块输出稳定 code，前端根据 locale 渲染 label/description。

## 6.17 Observability

### 职责

- request id。
- structured log。
- 查询耗时。
- provider 耗时。
- cache hit。
- parser warning。
- 错误分类。

### 必要性

WHOIS/RDAP 失败经常来自外部服务。没有观测，很难判断是代码问题、网络问题还是上游问题。

### 当前最佳方案

第一阶段实现：

- JSON log。
- trace id。
- `/api/health`。
- `/api/version`。
- provider elapsed。

后续再接 OpenTelemetry。

### 替代方案

- 一开始上完整 OTel + Prometheus：可以，但会拖慢 MVP。
- 只用 printf：后续排障痛苦。

### 插拔设计

```go
type Reporter interface {
  LookupStarted(...)
  ProviderFinished(...)
  LookupFinished(...)
}
```

默认 noop，可启用 log reporter、metrics reporter。

## 7. 插件系统总设计

### 7.1 插件分类

```txt
Provider Plugin    # 产生原始数据
Parser Plugin      # 解析原始数据
Enricher Plugin    # 增强结构化结果
Cache Plugin       # 缓存实现
Auth Plugin        # 鉴权实现
RateLimit Plugin   # 限流实现
DataSource Plugin  # 数据源实现
Reporter Plugin    # 观测实现
```

### 7.2 插件原则

- 插件必须可禁用。
- 插件失败不得导致不相关功能失败。
- 插件不得直接操作 HTTP response。
- 插件不得读取未声明的全局配置。
- 插件必须有独立 timeout。
- 插件输出必须进入统一模型。
- 插件必须声明名称、版本、能力、依赖。

### 7.3 插件注册方式

第一阶段采用编译期注册：

```go
func RegisterDefaults(r *plugin.Registry) {
  r.Providers.Register(rdap.New())
  r.Providers.Register(whois.New())
  r.Parsers.Register(parser.NewRDAP())
  r.Parsers.Register(parser.NewGenericWHOIS())
  r.Enrichers.Register(epp.New())
}
```

### 为什么不第一阶段做动态插件

Go 动态插件跨平台体验差，Windows 和 Docker 多平台发布会复杂。HTTP 外挂插件又会引入微服务复杂度。编译期注册是当前最佳方案。

### 后续扩展

如果未来确实需要第三方插件：

- 优先支持进程外 HTTP plugin。
- 每个 plugin 有 manifest。
- plugin 通过 JSON schema 交换数据。

## 8. 配置计划

### 8.1 单文件 TOML 配置

首次启动会生成 `data/whoice.toml`（Docker 内为 `/data/whoice.toml`），带简洁必要注释。常规部署不再依赖 `.env` 或 compose 的大段 `environment`，所有运行时功能都在配置文件中按 section 管理：

```toml
[server]
addr = ":8080"
data_dir = "/data"
trust_proxy = true
allow_custom_servers = false
allow_private_servers = false

[auth]
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
ipv4_resolvers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "180.184.1.1", "180.184.2.2"]
ipv6_resolvers = ["2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888", "2001:4860:4860::8844"]
doh_resolvers = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve", "https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
filter_fake_ip = true
dnsviz_enabled = true

[enrichment]
epp = true
registrar = true
brands = false
pricing = false
moz = false

[ai]
enabled = false
provider = "openai-compatible"
base_url = ""
api_key = ""
model = ""
timeout = "8s"
cache_ttl = "168h"
temperature = 0
max_output_tokens = 700
prompt = ""

[icp]
enabled = true
auto_query = false
cache_ttl = "72h"
negative_cache_ttl = "12h"
error_cache_ttl = "10m"
upstream_url = ""
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
auto_update = false
url = "https://publicsuffix.org/list/public_suffix_list.dat"
update_timeout = "5s"
```

### 必要性

自部署用户需要简单配置；高级功能需要能独立打开/关闭。单个 TOML 文件比 `.env` 更适合 DNS resolver 列表、ICP 缓存、AI 参数、黑名单、插件开关等结构化配置，也更方便用户备份和审阅。

### 当前最佳方案

TOML 配置文件 + 少量隐藏环境变量逃生口：

- Docker 和本地开发首次运行自动生成默认配置。
- compose 只负责镜像、端口、挂载和网络，不承载业务配置。
- `WHOICE_CONFIG`、`WHOICE_CONFIG_AUTO_CREATE=false`、`WHOICE_WEB_API_BASE` 这类环境变量仅作为调试/特殊部署逃生口，不作为推荐路径。

### 替代方案

- YAML：可读但缩进坑更多，注释模板长了以后更容易被误改。
- JSON：机器友好但不能自然保留注释，不适合自部署用户手改。
- 只环境变量：复杂规则可读性差，compose 会膨胀成配置清单，不符合单文件部署体验。

### 插拔设计

每个插件只读取自己的 config section。

## 9. 部署计划

### 9.1 推荐生产部署

```txt
docker compose
  web          Next.js
  lookup-api   Go API
  redis        optional
  nginx        optional reverse proxy
```

默认 `deploy/compose/docker-compose.yml` 不做本地 build，而是拉取预构建镜像：

```txt
ghcr.io/xmzo/whoice-web:latest
ghcr.io/xmzo/whoice-lookup-api:latest
platforms: linux/amd64, linux/arm64
```

默认端口采用“开发/部署都好记、又不抢常见端口”的方案：

- 本地开发 Web：`http://localhost:18081`，可用 `WHOICE_WEB_PORT` 覆盖。
- 本地开发 API：`http://localhost:8080`，保持 Go 服务常规默认。
- Docker 对外 Web：`0.0.0.0:18081`。
- Docker 对外 API：`0.0.0.0:18080`。
- Docker 内部 Web/API：`8081` / `8080`，仅供 compose 网络和 healthcheck 使用。

自部署用户在 Debian VPS 上只需要：

```sh
curl -fsSL -o docker-compose.yml https://raw.githubusercontent.com/XMZO/Whoice/main/deploy/compose/docker-compose.yml
docker compose up -d
```

首次启动生成 `./data/whoice.toml`，所有功能开关和密钥都写在这个文件里。需要本地改 Dockerfile 或离线构建时，才叠加 `deploy/compose/docker-compose.build.yml`。

### 9.1.1 多架构镜像发布

每次发布版本 tag，例如当前稳定版 `v0.01` 或未来 semver 稳定版 `v0.1.0`，GitHub Actions 自动用 Buildx 构建并推送：

- `linux/amd64`：普通 x86_64 Debian VPS。
- `linux/arm64`：ARM Debian VPS、Ampere、Oracle ARM、树莓派类环境。
- `whoice-web` 和 `whoice-lookup-api` 同版本发布。
- 短版本发布保留原始标签，例如 `v0.01`，并同时更新 `latest`，所以单文件 compose 直接使用 `latest`。
- 稳定 semver 发布保留 `v0.1.0`，并额外生成 `0.1.0`、`0.1`、`latest`。
- 镜像构建使用原生 runner：amd64 用 `ubuntu-latest`，arm64 用 `ubuntu-24.04-arm`，最后合并 multi-arch manifest；不使用 QEMU 模拟构建。

### 必要性

用户的主要部署目标是 Linux Debian VPS。VPS 上临时编译 Next.js 和 Go 镜像会消耗 CPU、内存、磁盘和时间，低配机器尤其容易卡在 `pnpm install` 或 Next build。预构建 multi-arch 镜像让部署路径变成拉取镜像和启动容器，失败面更小，也更适合后续写一键升级脚本。

### 当前最佳方案

使用 GHCR + GitHub Actions + Docker Buildx。GHCR 和源码仓库权限天然集成；Buildx 原生输出 multi-arch manifest；Compose 不指定 `platform`，Docker 会按 VPS 架构自动拉取 amd64 或 arm64 镜像。

### 替代方案

- VPS 本地 build：简单但浪费资源，低配 Debian 机器体验差。
- 只发布 amd64：会挡住 ARM VPS，后期再补会影响用户信任。
- Docker Hub：可行，但需要额外账号和 token；当前项目在 GitHub，GHCR 更顺。
- 单镜像合并 Web/API：部署更少容器，但升级、伸缩、日志和故障隔离不如双镜像清晰。

### 9.2 单容器部署

为了降低部署门槛，可提供单容器镜像：

```txt
whoice:latest
  supervisord or tiny process manager
    - lookup-api
    - next start
```

### 9.3 Vercel 部署

Vercel 可作为 Web 部署目标，但不作为完整查询服务的最佳运行环境：

- Web 部署到 Vercel。
- 查询 API 指向独立 Go 服务。
- 或只启用 RDAP-only 轻量模式。

### 必要性

WHOIS TCP 43 和 serverless 天然不完全匹配。Docker-first 保证完整功能，Vercel 保证低门槛体验。

### 替代方案

- 只 Vercel：完整 WHOIS 功能不稳。
- 只 Docker：降低了前端部署灵活性。

### 插拔设计

Web 通过 `WHOICE_WEB_API_BASE` 指向任意 API。API 不关心 Web 部署在哪里。

## 10. 测试计划

### 10.1 Go API 测试

- Normalizer 单元测试。
- WHOIS server resolver 测试。
- RDAP bootstrap 测试。
- Parser golden tests。
- Merger conflict tests。
- Cache adapter contract tests。
- Auth/rate limit middleware tests。

### 10.2 Parser Fixtures

结构：

```txt
packages/fixtures/
  whois/
    com/
      registered.raw
      registered.expected.json
      unregistered.raw
      unregistered.expected.json
    uk/
    cn/
  rdap/
    domain/
    ip/
    asn/
```

### 10.3 Web 测试

- Vitest：utils 和数据映射。
- Playwright：搜索、结果页、主题、i18n、历史、分享。
- 截图回归：关键 viewport。

### 必要性

Parser 规则非常容易被小改动破坏。没有 fixtures，TLD 兼容性无法长期维护。

### 当前最佳方案

优先投入 parser golden tests，而不是追求 UI 全覆盖。

### 替代方案

- 只手工查几个域名：不可持续。
- 一开始 E2E 覆盖所有 TLD：成本过高。

### 插拔设计

每个 parser plugin 必须带 fixtures。CI 自动发现并执行。

## 11. 数据更新计划

### 数据源

- Public Suffix List
- IANA RDAP bootstrap
- ICANN registrar CSV
- WHOIS server extra list
- Registrar/NS brand map

### 更新流程

```txt
GitHub Action scheduled
  |
  +--> download data
  +--> validate manifests, hashes, formats, embedded sync
  +--> run data diff
  +--> run smoke tests
  +--> commit if changed
  +--> tag data version when important sources changed
```

### 必要性

RDAP server、PSL 和 registrar 数据会变化。自动更新能降低维护成本。

### 当前最佳方案

沿用 `whois-domain-lookup` 的数据快照思路，但补上格式校验和 smoke tests。

### 替代方案

- 运行时更新：不可控。
- 手动更新：容易过期。

### 插拔设计

Data source loader 支持 embedded/file/remote，运行时可选择。

当前已落地的最小闭环：

- `packages/data/rdap-bootstrap/*.json` 是可审查 IANA RDAP bootstrap 快照，并同步进 embedded snapshot。
- `packages/data/registrars/icann-accredited-registrars.csv` 是可审查 ICANN registrar metadata 快照，并同步进 embedded snapshot。
- `packages/data/brands/brand-map.json` 覆盖 registrar/NS brand map。
- `packages/data/whois-servers/iana.json` 与 `packages/data/whois-servers/extra.json` 覆盖 WHOIS server map。
- `packages/data/public-suffix/public_suffix_list.dat` 与 `extra.dat` 覆盖 PSL 与紧急 overlay。
- `pnpm test:data` 校验 manifest sha256、格式、embedded sync、关键 PSL/WHOIS 二级后缀路由。
- WHOIS server resolver 有离线模板测试覆盖 Verisign、DENIC、JPRS、Punktum DK 等 query template；真实 TCP 43 smoke 通过 `WHOICE_LIVE_WHOIS_SMOKE=1` 手动启用。
- JSON Schema 校验会把真实 parser expected fixtures 转成 API response 样本，防止 parser、schema、Web types 漂移。

## 12. 安全计划

### 12.1 输入安全

- 限制 query 长度。
- 禁止控制字符。
- 手动 server 参数做严格校验。
- RDAP server 只允许 http/https。
- WHOIS server 只允许 host:port，不允许任意协议。

### 12.2 SSRF 防护

手动 `rdap-server` 和 WHOIS Web fallback 有 SSRF 风险。

策略：

- 默认关闭公共用户手动 server。
- 允许配置 `ALLOW_CUSTOM_SERVERS=true`。
- 禁止访问 private IP、loopback、link-local，除非 admin 模式。
- DNS resolve 后校验 IP。

### 12.3 Raw data 展示

- 前端所有 raw text 必须 HTML escape。
- linkify 只在安全处理后运行。
- JSON viewer 不直接 `innerHTML` 未可信内容。

### 必要性

WHOIS/RDAP 原始数据来自外部服务，不能信任。

### 当前最佳方案

安全默认值保守，高级能力通过显式配置打开。

### 替代方案

- 默认允许所有自定义 server：方便但风险高。
- 完全禁止自定义 server：丢掉参考项目的重要能力。

### 插拔设计

Server policy 独立接口：

```go
type ServerPolicy interface {
  AllowWHOIS(ctx context.Context, host string) error
  AllowRDAP(ctx context.Context, url string) error
}
```

## 13. API 响应计划

### 13.1 成功响应

```json
{
  "ok": true,
  "result": {},
  "meta": {
    "elapsedMs": 1234,
    "cached": false,
    "traceId": "..."
  }
}
```

### 13.2 错误响应

```json
{
  "ok": false,
  "error": {
    "code": "lookup_timeout",
    "message": "Lookup timed out.",
    "details": []
  },
  "meta": {
    "elapsedMs": 15000,
    "traceId": "..."
  }
}
```

### 必要性

参考项目 API 风格不同。新项目要从第一天稳定 API 契约。

### 当前最佳方案

统一 `ok/result/error/meta`，比 `code/msg/data` 或 `status/result/error` 更清晰。

### 替代方案

- 沿用 PHP `code/msg/data`：简单但表达力弱。
- 沿用 next-whois `status/time/result`：可行，但 meta 扩展不够自然。

### 插拔设计

插件 warnings 放 `result.meta.warnings`，不会破坏顶层 API。

## 14. 版本与兼容计划

### 版本策略

- API schema 使用 semver。
- 数据快照单独版本。
- Web 和 API 镜像同版本发布。
- 每个版本 tag 自动发布 Linux `amd64` 和 `arm64` 镜像。
- Compose 默认使用预构建镜像，本地 build 作为 override。

### 必要性

API 用户需要稳定契约；数据更新不应等同功能更新。

### 当前最佳方案

```txt
app version: v0.01
schema version: 2026-05-11
data version: 2026-05-11
```

### 替代方案

- 只有一个 VERSION：无法区分数据变化和代码变化。

### 插拔设计

`/api/version` 返回插件列表和版本。

## 15. 路线图

## Phase 0：架构骨架

### 目标

建立项目结构和核心接口，不追求功能完整。

### 任务

- 初始化 monorepo。
- 建立 Go API 服务。
- 建立 Next.js Web。
- 定义 OpenAPI/JSON Schema。
- 定义统一模型。
- 定义插件 registry。
- 建立 Docker Compose。

### 必要性

先定边界，后写功能。否则很容易重蹈两个参考项目各自的耦合问题。

### 最佳性判断

这是最低风险的起步方式：先把骨架跑通，避免一上来陷入 parser 细节。

## Phase 1：核心查询 MVP

### 目标

实现可用查询服务。

### 功能

- domain 查询。
- IPv4/IPv6 查询。
- ASN 查询。
- CIDR 查询。
- RDAP provider。
- WHOIS provider。
- generic WHOIS parser。
- RDAP parser。
- merger。
- raw data 展示。
- `/api/lookup`。
- 基础 Web 搜索页和结果页。

### 必要性

这是产品最小闭环。没有这个闭环，其他功能都是装饰。

### 最佳性判断

先做通用能力，不先迁移大量 TLD 特化 parser。这样能更快验证架构是否正确。

## Phase 2：体验层

### 功能

- 搜索历史。
- 快捷键。
- 明暗/系统主题。
- i18n：en、zh-CN、zh-TW。
- API docs 页面。
- PWA。
- Dynamic OG。
- 分享菜单。
- 复制 URL、复制原始数据、下载图片。

### 必要性

这些是 `next-whois` 的产品优势，能显著提高日常使用体验。

### 最佳性判断

放在核心查询之后做，避免 UI 先行导致后端模型反复变化。

## Phase 3：兼容性增强

### 功能

- TLD parser registry 扩展。
- 迁移高价值 PHP parser。
- WHOIS Web fallback 框架。
- 迁移高价值 WHOIS Web provider。
- reserved/unregistered 判断增强。
- 手动 WHOIS/RDAP server。
- ICANN registrar CSV 补全。

### 必要性

这是 `whois-domain-lookup` 的核心价值。没有这阶段，新项目只是 next-whois 的重写。

### 最佳性判断

在已有 fixtures 和 parser registry 后迁移，能避免规则失控。

### 完成口径

Phase 3 的完成标准不是迁移所有 ccTLD 和所有网页 scraper，而是完成兼容性能力闭环：

- TLD parser registry 已可扩展，并有高价值 TLD 特化 parser 作为样板。
- 每个新增 parser 都有 raw/expected golden fixture，并进入 schema API response 校验链路。
- WHOIS Web fallback 是独立 provider/plugin，已迁移稳定 API 型高价值模块并配隔离测试。
- reserved/unregistered 判断吸收 `unofficial/whois-domain-lookup` 的核心关键词，并有回归测试。
- 手动 WHOIS/RDAP server override、server data 覆盖、ICANN registrar CSV 补全已落地。
- 后续新增 TLD 或网页 scraper 属于兼容性扩展维护，不再阻塞 Phase 3 阶段完成。

## Phase 4：可选增强

### 功能

- Fresh-first singleflight，不缓存 WHOIS/RDAP 结果。
- Rate limit。
- Password/Bearer auth。
- EPP 状态说明。
- Registrar/NS brand。
- Pricing。
- Moz。
- DNSViz 链接。

### 必要性

这些功能不是主查询必需，但对公开服务、自部署和高级用户有价值。

### 最佳性判断

全部作为插件，不让任何一个外部服务成为主流程依赖。

## Phase 5：生产化

### 功能

- Observability。
- Async lookup reporter adapters：`log`、`webhook`、组合模式，默认关闭。
- Admin health/status。
- 数据自动更新。
- CI fixtures。
- Runtime API contract fixtures for RDAP, WHOIS, WHOIS Web, IP, and error envelopes.
- Playwright smoke tests。
- Release workflow。
- Docker multi-arch。
- 安全文档。

### 必要性

项目若要长期运行，必须可观测、可更新、可验证。

### 最佳性判断

在核心功能稳定后生产化，避免过早把维护体系搭在不稳定模型上。

## 16. 关键风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| WHOIS 格式过于混乱 | parser 不稳定 | golden fixtures + TLD parser registry |
| RDAP/WHOIS 上游限流 | 查询失败 | fresh-first singleflight + rate limit + user-agent + timeout |
| 自定义 server SSRF | 安全风险 | server policy + 默认关闭公网自定义 |
| Web fallback 易失效 | 兼容性回退 | 独立 provider + fixture + warning |
| 增强服务拖慢查询 | 用户体验差 | enrichment 独立 timeout + 可禁用 |
| 数据源过期 | 查询不准 | 定时更新 + schema validation |
| 前后端模型漂移 | UI/API bug | JSON Schema/OpenAPI 生成类型 |
| 一开始过度设计 | 迟迟不能用 | 分阶段，每阶段有可运行产物 |

## 17. 第一批必须做的接口

### Go interfaces

```go
type Normalizer interface {
  Normalize(ctx context.Context, input string) (*NormalizedQuery, error)
}

type Provider interface {
  Name() string
  Supports(q NormalizedQuery) bool
  Lookup(ctx context.Context, q NormalizedQuery, opts LookupOptions) (*RawResponse, error)
}

type Parser interface {
  Name() string
  Supports(input ParseInput) bool
  Priority() int
  Parse(ctx context.Context, input ParseInput) (*PartialResult, error)
}

type Merger interface {
  Merge(ctx context.Context, parts []PartialResult) (*LookupResult, error)
}

type Enricher interface {
  Name() string
  Enabled(cfg Config) bool
  Supports(result *LookupResult) bool
  Enrich(ctx context.Context, result *LookupResult) error
}

type Cache interface {
  Get(ctx context.Context, key string) (*LookupResult, bool, error)
  Set(ctx context.Context, key string, value *LookupResult, ttl time.Duration) error
}

type AuthProvider interface {
  Authenticate(ctx context.Context, r *http.Request) (*Principal, error)
}

type RateLimiter interface {
  Allow(ctx context.Context, key string, cost int) (Decision, error)
}
```

### 必要性

这些接口是插件化的地基。没有接口，模块化只是目录拆分。

### 最佳性判断

接口保持小而稳定，只描述能力，不泄漏具体实现。

## 18. 初始功能优先级

### P0

- Go API skeleton
- Next.js skeleton
- unified schema
- normalizer
- RDAP domain/ip/asn
- WHOIS domain
- generic parser
- result page
- raw data panel
- Docker Compose

### P1

- cache adapter
- auth
- rate limit
- EPP enrichment
- i18n
- history
- docs
- OG

### P2

- TLD parser migration
- WHOIS Web fallback
- registrar/NS brand
- pricing
- Moz
- advanced server override UI

## 19. 明确保留两个参考项目的价值

### 从 `unofficial/whois-domain-lookup` 吸收

- TLD 特化 parser 思路。
- WHOIS server data + extra data。
- RDAP server data + extra data。
- WHOIS Web fallback。
- Access control。
- 手动指定 WHOIS/RDAP server。
- reserved/unregistered 细分。
- 原始数据 linkify/JSON viewer 思路。

### 从 `unofficial/next-whois` 吸收

- 多类型查询：domain/IP/ASN/CIDR。
- 现代 UI。
- 历史记录。
- 快捷键。
- i18n。
- 主题切换。
- PWA。
- API docs。
- Dynamic OG。
- EPP 状态解释。
- Registrar/NS branding。
- 缓存交互思路仅保留为可选历史参考；Whoice 默认不缓存 WHOIS/RDAP 查询结果。
- Pricing/Moz optional enrichment。

## 20. 最终建议

Whoice 最合适的起点不是“把两个项目功能一次性全实现”，而是：

1. 先建 Go 查询核心和统一模型。
2. 再接 Next.js 体验层。
3. 然后按 fixtures 迁移兼容性规则。
4. 最后把增强能力全部作为插件接入。

这条路线能同时满足：

- 功能最终覆盖两个项目的集合。
- 查询核心比纯 Next.js 更稳定。
- UI 比纯 Go/PHP 更现代。
- 每个能力都可插拔、可降级。
- 后续扩展不会把系统拧成一团。
