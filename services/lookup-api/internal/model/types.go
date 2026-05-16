package model

import "time"

type QueryType string

const (
	QueryDomain  QueryType = "domain"
	QueryIPv4    QueryType = "ipv4"
	QueryIPv6    QueryType = "ipv6"
	QueryASN     QueryType = "asn"
	QueryCIDR    QueryType = "cidr"
	QueryURL     QueryType = "url"
	QueryUnknown QueryType = "unknown"
)

type ResultStatus string

const (
	StatusRegistered   ResultStatus = "registered"
	StatusUnregistered ResultStatus = "unregistered"
	StatusReserved     ResultStatus = "reserved"
	StatusUnknown      ResultStatus = "unknown"
	StatusError        ResultStatus = "error"
)

type SourceName string

const (
	SourceRDAP     SourceName = "rdap"
	SourceWHOIS    SourceName = "whois"
	SourceWHOISWeb SourceName = "whoisWeb"
)

type NormalizedQuery struct {
	Input            string    `json:"input"`
	Query            string    `json:"query"`
	UnicodeQuery     string    `json:"unicodeQuery,omitempty"`
	Type             QueryType `json:"type"`
	Host             string    `json:"host,omitempty"`
	Suffix           string    `json:"suffix,omitempty"`
	RegisteredDomain string    `json:"registeredDomain,omitempty"`
	ASN              uint32    `json:"asn,omitempty"`
}

type LookupOptions struct {
	UseRDAP         bool
	UseWHOIS        bool
	RDAPServer      string
	WHOISServer     string
	WHOISFollow     int
	ExactDomain     bool
	ForceAI         bool
	FastResponse    bool
	FastResponseSet bool
	ProviderLimit   time.Duration
	LookupLimit     time.Duration
}

type RawResponse struct {
	Source      SourceName `json:"source"`
	Server      string     `json:"server"`
	Query       string     `json:"query"`
	Body        string     `json:"body"`
	ContentType string     `json:"contentType,omitempty"`
	StatusCode  int        `json:"statusCode,omitempty"`
	ElapsedMs   int64      `json:"elapsedMs"`
	Error       string     `json:"error,omitempty"`
}

type SourceInfo struct {
	Primary SourceName    `json:"primary,omitempty"`
	Used    []SourceName  `json:"used"`
	Errors  []SourceError `json:"errors,omitempty"`
}

type SourceError struct {
	Source SourceName `json:"source"`
	Server string     `json:"server,omitempty"`
	Error  string     `json:"error"`
}

type DomainInfo struct {
	Name             string `json:"name,omitempty"`
	UnicodeName      string `json:"unicodeName,omitempty"`
	PunycodeName     string `json:"punycodeName,omitempty"`
	Suffix           string `json:"suffix,omitempty"`
	RegisteredDomain string `json:"registeredDomain,omitempty"`
	Reserved         bool   `json:"reserved"`
	Registered       bool   `json:"registered"`
}

type RegistryInfo struct {
	Name        string `json:"name,omitempty"`
	Website     string `json:"website,omitempty"`
	WHOISServer string `json:"whoisServer,omitempty"`
	RDAPServer  string `json:"rdapServer,omitempty"`
}

type RegistrarInfo struct {
	Name        string   `json:"name,omitempty"`
	URL         string   `json:"url,omitempty"`
	IANAID      string   `json:"ianaId,omitempty"`
	Country     string   `json:"country,omitempty"`
	WHOISServer string   `json:"whoisServer,omitempty"`
	RDAPServer  string   `json:"rdapServer,omitempty"`
	Brand       *Brand   `json:"brand,omitempty"`
	Source      string   `json:"source,omitempty"`
	Confidence  *float64 `json:"confidence,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
}

type Brand struct {
	Name    string   `json:"name"`
	Slug    string   `json:"slug,omitempty"`
	Color   string   `json:"color,omitempty"`
	Logo    string   `json:"logo,omitempty"`
	Website string   `json:"website,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

type DateInfo struct {
	CreatedAt     string `json:"createdAt,omitempty"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	AvailableAt   string `json:"availableAt,omitempty"`
	AgeDays       *int   `json:"ageDays,omitempty"`
	RemainingDays *int   `json:"remainingDays,omitempty"`
}

type DomainStatus struct {
	Code        string `json:"code"`
	Label       string `json:"label,omitempty"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	Source      string `json:"source,omitempty"`
}

type Nameserver struct {
	Host      string   `json:"host"`
	Addresses []string `json:"addresses,omitempty"`
	Brand     *Brand   `json:"brand,omitempty"`
}

type DNSSECInfo struct {
	Signed *bool  `json:"signed,omitempty"`
	Text   string `json:"text,omitempty"`
}

type RegistrationField struct {
	Label      string   `json:"label"`
	Value      string   `json:"value"`
	Source     string   `json:"source,omitempty"`
	Confidence *float64 `json:"confidence,omitempty"`
	Evidence   string   `json:"evidence,omitempty"`
}

type RegistrantInfo struct {
	Name         string                         `json:"name,omitempty"`
	Organization string                         `json:"organization,omitempty"`
	Country      string                         `json:"country,omitempty"`
	Province     string                         `json:"province,omitempty"`
	City         string                         `json:"city,omitempty"`
	Address      string                         `json:"address,omitempty"`
	PostalCode   string                         `json:"postalCode,omitempty"`
	Email        string                         `json:"email,omitempty"`
	Phone        string                         `json:"phone,omitempty"`
	Extra        []RegistrationField            `json:"extra,omitempty"`
	FieldSources map[string][]RegistrationField `json:"fieldSources,omitempty"`
	Source       string                         `json:"source,omitempty"`
	Confidence   *float64                       `json:"confidence,omitempty"`
	Evidence     string                         `json:"evidence,omitempty"`
}

type NetworkInfo struct {
	CIDR     string `json:"cidr,omitempty"`
	Range    string `json:"range,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	OriginAS string `json:"originAS,omitempty"`
	Country  string `json:"country,omitempty"`
}

type EnrichmentInfo struct {
	Pricing *PricingInfo `json:"pricing,omitempty"`
	Moz     *MozInfo     `json:"moz,omitempty"`
	DNS     *DNSInfo     `json:"dns,omitempty"`
	DNSViz  *DNSVizInfo  `json:"dnsviz,omitempty"`
}

type PricingInfo struct {
	Register      *float64      `json:"register,omitempty"`
	Renew         *float64      `json:"renew,omitempty"`
	Transfer      *float64      `json:"transfer,omitempty"`
	Currency      string        `json:"currency,omitempty"`
	Provider      string        `json:"provider,omitempty"`
	Source        string        `json:"source,omitempty"`
	UpdatedAt     string        `json:"updatedAt,omitempty"`
	RegisterOffer *PricingOffer `json:"registerOffer,omitempty"`
	RenewOffer    *PricingOffer `json:"renewOffer,omitempty"`
	TransferOffer *PricingOffer `json:"transferOffer,omitempty"`
}

type PricingOffer struct {
	Registrar string   `json:"registrar,omitempty"`
	Website   string   `json:"website,omitempty"`
	Logo      string   `json:"logo,omitempty"`
	Price     *float64 `json:"price,omitempty"`
	Currency  string   `json:"currency,omitempty"`
	PriceCNY  *float64 `json:"priceCny,omitempty"`
}

type MozInfo struct {
	DomainAuthority int    `json:"domainAuthority,omitempty"`
	PageAuthority   int    `json:"pageAuthority,omitempty"`
	SpamScore       int    `json:"spamScore,omitempty"`
	Source          string `json:"source,omitempty"`
	UpdatedAt       string `json:"updatedAt,omitempty"`
}

type DNSVizInfo struct {
	URL string `json:"url"`
}

type DNSInfo struct {
	A          []DNSAddress      `json:"a,omitempty"`
	AAAA       []DNSAddress      `json:"aaaa,omitempty"`
	CNAME      string            `json:"cname,omitempty"`
	MX         []DNSMX           `json:"mx,omitempty"`
	NS         []string          `json:"ns,omitempty"`
	RegistryNS []string          `json:"registryNs,omitempty"`
	NSMismatch bool              `json:"nsMismatch,omitempty"`
	Resolvers  []DNSResolverInfo `json:"resolvers,omitempty"`
	ElapsedMs  int64             `json:"elapsedMs,omitempty"`
}

type DNSAddress struct {
	IP       string `json:"ip"`
	Version  string `json:"version"`
	Reverse  string `json:"reverse,omitempty"`
	Source   string `json:"source,omitempty"`
	Resolver string `json:"resolver,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

type DNSResolverInfo struct {
	Source   string `json:"source"`
	Resolver string `json:"resolver"`
	Endpoint string `json:"endpoint,omitempty"`
	Status   string `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
}

type DNSMX struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

type RawData struct {
	WHOIS    string `json:"whois,omitempty"`
	RDAP     string `json:"rdap,omitempty"`
	WHOISWeb string `json:"whoisWeb,omitempty"`
}

type ResultMeta struct {
	ElapsedMs          int64           `json:"elapsedMs"`
	Warnings           []string        `json:"warnings,omitempty"`
	TraceID            string          `json:"traceId,omitempty"`
	PendingEnrichments []string        `json:"pendingEnrichments,omitempty"`
	Providers          []ProviderTrace `json:"providers,omitempty"`
	AI                 *AITrace        `json:"ai,omitempty"`
}

type ProviderTrace struct {
	Source      SourceName `json:"source"`
	Status      string     `json:"status"`
	Server      string     `json:"server,omitempty"`
	Query       string     `json:"query,omitempty"`
	StatusCode  int        `json:"statusCode,omitempty"`
	ContentType string     `json:"contentType,omitempty"`
	Bytes       int        `json:"bytes,omitempty"`
	ElapsedMs   int64      `json:"elapsedMs"`
	Error       string     `json:"error,omitempty"`
}

type AITrace struct {
	Provider  string   `json:"provider,omitempty"`
	Model     string   `json:"model,omitempty"`
	Status    string   `json:"status"`
	Cached    bool     `json:"cached,omitempty"`
	ElapsedMs int64    `json:"elapsedMs,omitempty"`
	Attempts  int      `json:"attempts,omitempty"`
	Applied   []string `json:"applied,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Error     string   `json:"error,omitempty"`
}

type LookupResult struct {
	Query           string         `json:"query"`
	NormalizedQuery string         `json:"normalizedQuery"`
	Type            QueryType      `json:"type"`
	Status          ResultStatus   `json:"status"`
	Source          SourceInfo     `json:"source"`
	Domain          DomainInfo     `json:"domain"`
	Registry        RegistryInfo   `json:"registry"`
	Registrar       RegistrarInfo  `json:"registrar"`
	Dates           DateInfo       `json:"dates"`
	Statuses        []DomainStatus `json:"statuses"`
	Nameservers     []Nameserver   `json:"nameservers"`
	DNSSEC          DNSSECInfo     `json:"dnssec"`
	Registrant      RegistrantInfo `json:"registrant"`
	Network         NetworkInfo    `json:"network"`
	Enrichment      EnrichmentInfo `json:"enrichment"`
	Raw             RawData        `json:"raw"`
	Meta            ResultMeta     `json:"meta"`
}

type PartialResult struct {
	Source      SourceName
	Status      ResultStatus
	Domain      DomainInfo
	Registry    RegistryInfo
	Registrar   RegistrarInfo
	Dates       DateInfo
	Statuses    []DomainStatus
	Nameservers []Nameserver
	DNSSEC      DNSSECInfo
	Registrant  RegistrantInfo
	Network     NetworkInfo
	Raw         RawData
	Warnings    []string
}

type Capabilities struct {
	API            bool            `json:"api"`
	APIEndpoints   map[string]bool `json:"apiEndpoints"`
	APIIPAllowlist bool            `json:"apiIpAllowlist"`
	RDAP           bool            `json:"rdap"`
	WHOIS          bool            `json:"whois"`
	WHOISWeb       bool            `json:"whoisWeb"`
	CustomServers  bool            `json:"customServers"`
	Auth           string          `json:"auth"`
	RateLimit      bool            `json:"rateLimit"`
	ICPAutoQuery   bool            `json:"icpAutoQuery"`
	Enrichment     map[string]bool `json:"enrichment"`
}

type PluginInfo struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
}

type APIResponse struct {
	OK           bool          `json:"ok"`
	Result       *LookupResult `json:"result,omitempty"`
	Error        *APIError     `json:"error,omitempty"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
	Meta         *ResultMeta   `json:"meta,omitempty"`
	Config       *ConfigStatus `json:"config,omitempty"`
}

type APIError struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
}

type ConfigStatus struct {
	Status        string `json:"status"`
	Path          string `json:"path,omitempty"`
	LoadedAt      string `json:"loadedAt,omitempty"`
	LastCheckedAt string `json:"lastCheckedAt,omitempty"`
	LastAttemptAt string `json:"lastAttemptAt,omitempty"`
	LastErrorAt   string `json:"lastErrorAt,omitempty"`
	LastError     string `json:"lastError,omitempty"`
	RolledBack    bool   `json:"rolledBack,omitempty"`
	UsingLoadedAt string `json:"usingLoadedAt,omitempty"`
}

type ConfigEditorStatus struct {
	Status              string   `json:"status"`
	Path                string   `json:"path,omitempty"`
	Format              string   `json:"format"`
	Writable            bool     `json:"writable"`
	SourceReadable      bool     `json:"sourceReadable"`
	Surfaces            []string `json:"surfaces"`
	SupportedOperations []string `json:"supportedOperations"`
	Reason              string   `json:"reason,omitempty"`
}
