package icp

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xmzo/whoice/services/lookup-api/internal/config"
)

type ResultStatus string

const (
	StatusFound    ResultStatus = "found"
	StatusNotFound ResultStatus = "not_found"
	StatusError    ResultStatus = "error"
)

type Record struct {
	Domain           string `json:"domain,omitempty"`
	DomainID         int64  `json:"domainId,omitempty"`
	UnitName         string `json:"unitName,omitempty"`
	NatureName       string `json:"natureName,omitempty"`
	MainLicence      string `json:"mainLicence,omitempty"`
	ServiceLicence   string `json:"serviceLicence,omitempty"`
	ServiceName      string `json:"serviceName,omitempty"`
	ContentTypeName  string `json:"contentTypeName,omitempty"`
	LimitAccess      string `json:"limitAccess,omitempty"`
	UpdateRecordTime string `json:"updateRecordTime,omitempty"`
}

type Result struct {
	Domain    string       `json:"domain"`
	Status    ResultStatus `json:"status"`
	Records   []Record     `json:"records,omitempty"`
	Source    string       `json:"source,omitempty"`
	Cached    bool         `json:"cached"`
	CachedAt  string       `json:"cachedAt,omitempty"`
	ExpiresAt string       `json:"expiresAt,omitempty"`
	ElapsedMs int64        `json:"elapsedMs,omitempty"`
	Message   string       `json:"message,omitempty"`
}

type Client struct {
	cfg        config.Config
	httpClient *http.Client
	baseURL    string
	upstream   string

	mu          sync.Mutex
	authToken   string
	tokenExpiry time.Time
	cache       map[string]cacheEntry
	calls       map[string]*call
	cacheFile   string
}

type cacheEntry struct {
	Result    Result    `json:"result"`
	ExpiresAt time.Time `json:"expiresAt"`
	CachedAt  time.Time `json:"cachedAt"`
}

type call struct {
	done   chan struct{}
	result Result
	err    error
}

func NewClient(cfg config.Config) *Client {
	baseURL := strings.TrimRight(cfg.ICPBaseURL, "/")
	if baseURL == "" {
		baseURL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api"
	}
	client := &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.ICPTimeout,
		},
		baseURL:  baseURL,
		upstream: strings.TrimRight(strings.TrimSpace(cfg.ICPUpstreamURL), "/"),
		cache:    map[string]cacheEntry{},
		calls:    map[string]*call{},
	}
	if cfg.DataDir != "" {
		client.cacheFile = cachePath(cfg.DataDir)
		client.loadCache()
	}
	return client
}

func (c *Client) Enabled() bool {
	return c != nil && c.cfg.ICPEnabled
}

func (c *Client) Query(ctx context.Context, domain string) (Result, error) {
	start := time.Now()
	domain = normalizeDomain(domain)
	if domain == "" {
		return Result{Status: StatusError, Message: "domain is required"}, errors.New("domain is required")
	}
	if !c.Enabled() {
		return Result{Domain: domain, Status: StatusError, Message: "ICP lookup is disabled"}, errors.New("ICP lookup is disabled")
	}
	if c.isBlocked(domain) {
		return c.notFound(domain, start), nil
	}
	if cached, ok := c.getCached(domain); ok {
		return cached, nil
	}
	return c.doSingleflight(ctx, domain, func(ctx context.Context) (Result, error) {
		if cached, ok := c.getCached(domain); ok {
			return cached, nil
		}
		result, err := c.queryFresh(ctx, domain, start)
		c.store(domain, result, ttlForResult(c.cfg, result, err))
		return result, err
	})
}

func (c *Client) doSingleflight(ctx context.Context, domain string, fn func(context.Context) (Result, error)) (Result, error) {
	c.mu.Lock()
	if existing, ok := c.calls[domain]; ok {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return Result{Domain: domain, Status: StatusError, Message: ctx.Err().Error()}, ctx.Err()
		case <-existing.done:
			return existing.result, existing.err
		}
	}
	call := &call{done: make(chan struct{})}
	c.calls[domain] = call
	c.mu.Unlock()

	call.result, call.err = fn(ctx)
	close(call.done)

	c.mu.Lock()
	delete(c.calls, domain)
	c.mu.Unlock()

	return call.result, call.err
}

func (c *Client) queryFresh(ctx context.Context, domain string, start time.Time) (Result, error) {
	if c.upstream != "" {
		return c.queryUpstream(ctx, domain, start)
	}
	if c.cfg.ICPCaptchaEnabled {
		return c.queryWithCaptcha(ctx, domain, start)
	}
	return c.queryWithoutCaptcha(ctx, domain, start)
}

func (c *Client) queryWithoutCaptcha(ctx context.Context, domain string, start time.Time) (Result, error) {
	token, headers, err := c.getToken(ctx)
	if err != nil {
		return Result{Domain: domain, Status: StatusError, Source: "miit", ElapsedMs: time.Since(start).Milliseconds(), Message: "ICP token request failed"}, err
	}
	payload := c.queryPayload(domain)
	body, _ := json.Marshal(payload)
	headers["Content-Type"] = "application/json"
	headers["token"] = token
	headers["sign"] = c.cfg.ICPSign

	resBody, err := c.post(ctx, c.baseURL+"/icpAbbreviateInfo/queryByCondition/", body, headers)
	if err != nil {
		return Result{Domain: domain, Status: StatusError, Source: "miit", ElapsedMs: time.Since(start).Milliseconds(), Message: "ICP query request failed"}, err
	}
	if looksBlocked(resBody) {
		err := errors.New("MIIT protection blocked this request")
		return Result{Domain: domain, Status: StatusError, Source: "miit", ElapsedMs: time.Since(start).Milliseconds(), Message: "ICP query was temporarily blocked"}, err
	}
	result := parseMIITResult(domain, resBody)
	result.ElapsedMs = time.Since(start).Milliseconds()
	if result.Source == "" {
		result.Source = "miit"
	}
	if result.Status == StatusError {
		return result, errors.New(firstNonEmpty(result.Message, "ICP query failed"))
	}
	return result, nil
}

func (c *Client) queryWithCaptcha(ctx context.Context, domain string, start time.Time) (Result, error) {
	var lastErr error
	retries := maxInt(c.cfg.ICPCaptchaRetries, 1)
	for attempt := 0; attempt < retries; attempt++ {
		uuid, token, sign, headers, err := c.checkCaptcha(ctx)
		if err != nil {
			lastErr = err
			continue
		}
		payload := c.queryPayload(domain)
		body, _ := json.Marshal(payload)
		headers["Content-Type"] = "application/json"
		headers["uuid"] = uuid
		headers["token"] = token
		headers["sign"] = sign

		resBody, err := c.post(ctx, c.baseURL+"/icpAbbreviateInfo/queryByCondition", body, headers)
		if err != nil {
			lastErr = err
			continue
		}
		if looksBlocked(resBody) {
			lastErr = errors.New("MIIT protection blocked this request")
			continue
		}
		result := parseMIITResult(domain, resBody)
		result.ElapsedMs = time.Since(start).Milliseconds()
		if result.Source == "" {
			result.Source = "miit-captcha"
		}
		if result.Status == StatusError {
			lastErr = errors.New(firstNonEmpty(result.Message, "ICP query failed"))
			continue
		}
		return result, nil
	}
	message := "ICP captcha query failed"
	if lastErr != nil {
		message = lastErr.Error()
	}
	return Result{Domain: domain, Status: StatusError, Source: "miit-captcha", ElapsedMs: time.Since(start).Milliseconds(), Message: message}, lastErr
}

func (c *Client) queryUpstream(ctx context.Context, domain string, start time.Time) (Result, error) {
	target, err := c.icpQueryURL(domain)
	if err != nil {
		return Result{Domain: domain, Status: StatusError, Source: "icp-query", ElapsedMs: time.Since(start).Milliseconds(), Message: "invalid ICP upstream URL"}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return Result{Domain: domain, Status: StatusError, Source: "icp-query", ElapsedMs: time.Since(start).Milliseconds(), Message: "ICP upstream request failed"}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", baseHeaders()["User-Agent"])
	res, err := c.httpClient.Do(req)
	if err != nil {
		return Result{Domain: domain, Status: StatusError, Source: "icp-query", ElapsedMs: time.Since(start).Milliseconds(), Message: "ICP upstream is unreachable"}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return Result{Domain: domain, Status: StatusError, Source: "icp-query", ElapsedMs: time.Since(start).Milliseconds(), Message: "ICP upstream response read failed"}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		err := fmt.Errorf("ICP upstream returned HTTP %d", res.StatusCode)
		return Result{Domain: domain, Status: StatusError, Source: "icp-query", ElapsedMs: time.Since(start).Milliseconds(), Message: err.Error()}, err
	}
	result := parseMIITResult(domain, body)
	if result.Source == "" || result.Source == "miit" {
		result.Source = "icp-query"
	}
	result.ElapsedMs = time.Since(start).Milliseconds()
	if result.Status == StatusError {
		return result, errors.New(firstNonEmpty(result.Message, "ICP upstream query failed"))
	}
	return result, nil
}

func (c *Client) icpQueryURL(domain string) (string, error) {
	raw := c.upstream
	if raw == "" {
		return "", errors.New("ICP upstream URL is empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("ICP upstream URL must include scheme and host")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/query/web"
	}
	query := parsed.Query()
	query.Set("search", domain)
	query.Set("pageNum", "1")
	query.Set("pageSize", fmt.Sprint(maxInt(c.cfg.ICPPageSize, 1)))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (c *Client) queryPayload(domain string) map[string]any {
	return map[string]any{
		"pageNum":     "1",
		"pageSize":    fmt.Sprint(maxInt(c.cfg.ICPPageSize, 1)),
		"unitName":    domain,
		"serviceType": 1,
	}
}

func (c *Client) checkCaptcha(ctx context.Context) (string, string, string, map[string]string, error) {
	token, headers, err := c.getToken(ctx)
	if err != nil {
		return "", "", "", nil, err
	}
	headers["Content-Type"] = "application/json"
	headers["token"] = token
	clientUID := "point-" + randomUUIDLike()
	body, _ := json.Marshal(map[string]string{"clientUid": clientUID})

	resBody, err := c.post(ctx, c.baseURL+"/image/getCheckImagePoint", body, headers)
	if err != nil {
		return "", "", "", nil, err
	}
	if looksBlocked(resBody) {
		return "", "", "", nil, errors.New("MIIT protection blocked captcha request")
	}
	var challenge struct {
		Code    int    `json:"code"`
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
		Message string `json:"message"`
		Params  struct {
			UUID       string `json:"uuid"`
			BigImage   string `json:"bigImage"`
			SmallImage string `json:"smallImage"`
		} `json:"params"`
	}
	if err := json.Unmarshal(resBody, &challenge); err != nil {
		return "", "", "", nil, err
	}
	if challenge.Code != 200 || !challenge.Success {
		return "", "", "", nil, errors.New(firstNonEmpty(challenge.Message, challenge.Msg, "captcha challenge failed"))
	}
	offset, err := matchSliderOffset(challenge.Params.SmallImage, challenge.Params.BigImage)
	if err != nil {
		return "", "", "", nil, err
	}

	checkBody, _ := json.Marshal(map[string]string{
		"key":   challenge.Params.UUID,
		"value": strconv.Itoa(offset),
	})
	checkHeaders := cloneHeaders(headers)
	checkHeaders["uuid"] = challenge.Params.UUID
	resBody, err = c.post(ctx, c.baseURL+"/image/checkImage", checkBody, checkHeaders)
	if err != nil {
		return "", "", "", nil, err
	}
	if looksBlocked(resBody) {
		return "", "", "", nil, errors.New("MIIT protection blocked captcha validation")
	}
	var checked struct {
		Code    int             `json:"code"`
		Success bool            `json:"success"`
		Msg     string          `json:"msg"`
		Message string          `json:"message"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(resBody, &checked); err != nil {
		return "", "", "", nil, err
	}
	if checked.Code != 200 || !checked.Success {
		return "", "", "", nil, errors.New(firstNonEmpty(checked.Message, checked.Msg, "captcha validation failed"))
	}
	sign := strings.Trim(string(checked.Params), `"`)
	if sign == "" || sign == "null" {
		return "", "", "", nil, errors.New("captcha sign missing")
	}
	queryHeaders := baseHeaders()
	return challenge.Params.UUID, token, sign, queryHeaders, nil
}

func (c *Client) getToken(ctx context.Context) (string, map[string]string, error) {
	headers := baseHeaders()

	c.mu.Lock()
	if c.authToken != "" && time.Now().Before(c.tokenExpiry) {
		token := c.authToken
		c.mu.Unlock()
		return token, headers, nil
	}
	c.mu.Unlock()

	timestamp := time.Now().UnixMilli()
	hash := md5.Sum([]byte("testtest" + fmt.Sprint(timestamp)))
	payload := fmt.Sprintf("authKey=%s&timeStamp=%d", hex.EncodeToString(hash[:]), timestamp)
	headers["Content-Type"] = "application/x-www-form-urlencoded"

	body, err := c.post(ctx, c.baseURL+"/auth", []byte(payload), headers)
	if err != nil {
		return "", nil, err
	}
	if looksBlocked(body) {
		return "", nil, errors.New("MIIT protection blocked token request")
	}
	var parsed struct {
		Params struct {
			Bussiness string `json:"bussiness"`
			Business  string `json:"business"`
			Expire    int64  `json:"expire"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", nil, err
	}
	token := firstNonEmpty(parsed.Params.Bussiness, parsed.Params.Business)
	if token == "" {
		return "", nil, errors.New("MIIT token missing")
	}
	expire := parsed.Params.Expire
	if expire <= 0 {
		expire = int64((10 * time.Minute) / time.Millisecond)
	}
	expiry := time.Now().Add(time.Duration(expire) * time.Millisecond).Add(-30 * time.Second)

	c.mu.Lock()
	c.authToken = token
	c.tokenExpiry = expiry
	c.mu.Unlock()

	return token, baseHeaders(), nil
}

func (c *Client) post(ctx context.Context, url string, body []byte, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Length", fmt.Sprint(len(body)))
	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return resBody, fmt.Errorf("MIIT returned HTTP %d", res.StatusCode)
	}
	return resBody, nil
}

func parseMIITResult(domain string, body []byte) Result {
	var envelope struct {
		Code    int    `json:"code"`
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
		Message string `json:"message"`
		Params  struct {
			List []map[string]any `json:"list"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return Result{Domain: domain, Status: StatusError, Source: "miit", Message: "invalid ICP response"}
	}
	if envelope.Code != 200 || (!envelope.Success && envelope.Params.List == nil) {
		message := firstNonEmpty(envelope.Message, envelope.Msg, "ICP query failed")
		if strings.Contains(message, "没有") || strings.Contains(message, "未查询") || strings.Contains(message, "无数据") {
			return Result{Domain: domain, Status: StatusNotFound, Source: "miit", Message: "no ICP record found"}
		}
		return Result{Domain: domain, Status: StatusError, Source: "miit", Message: message}
	}
	records := normalizeRecords(envelope.Params.List)
	if len(records) == 0 {
		return Result{Domain: domain, Status: StatusNotFound, Source: "miit", Message: "no ICP record found"}
	}
	return Result{Domain: domain, Status: StatusFound, Source: "miit", Records: records}
}

func normalizeRecords(items []map[string]any) []Record {
	seen := map[string]bool{}
	var records []Record
	for _, item := range items {
		record := Record{
			Domain:           stringValue(item, "domain"),
			DomainID:         int64Value(item, "domainId"),
			UnitName:         stringValue(item, "unitName"),
			NatureName:       stringValue(item, "natureName"),
			MainLicence:      stringValue(item, "mainLicence"),
			ServiceLicence:   stringValue(item, "serviceLicence"),
			ServiceName:      stringValue(item, "serviceName"),
			ContentTypeName:  stringValue(item, "contentTypeName"),
			LimitAccess:      stringValue(item, "limitAccess"),
			UpdateRecordTime: stringValue(item, "updateRecordTime"),
		}
		key := strings.ToLower(record.Domain + "|" + record.ServiceLicence + "|" + record.UnitName)
		if key == "||" || seen[key] {
			continue
		}
		seen[key] = true
		records = append(records, record)
	}
	return records
}

func baseHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36 Edg/101.0.1210.32",
		"Origin":     "https://beian.miit.gov.cn",
		"Referer":    "https://beian.miit.gov.cn/",
		"Cookie":     "__jsluid_s=" + randomHex(16),
		"Accept":     "application/json, text/plain, */*",
	}
}

func cloneHeaders(headers map[string]string) map[string]string {
	clone := make(map[string]string, len(headers))
	for key, value := range headers {
		clone[key] = value
	}
	return clone
}

func (c *Client) notFound(domain string, start time.Time) Result {
	return Result{
		Domain:    domain,
		Status:    StatusNotFound,
		Source:    "miit",
		Cached:    false,
		ElapsedMs: time.Since(start).Milliseconds(),
		Message:   "no ICP record found",
	}
}

func normalizeDomain(value string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
}

func looksBlocked(body []byte) bool {
	text := string(body)
	return strings.Contains(text, "当前访问疑似黑客攻击") || strings.Contains(text, "创宇盾")
}

func stringValue(item map[string]any, key string) string {
	value, ok := item[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func int64Value(item map[string]any, key string) int64 {
	value, ok := item[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		var parsed int64
		_, _ = fmt.Sscan(v, &parsed)
		return parsed
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func maxInt(value, min int) int {
	if value < min {
		return min
	}
	return value
}

func randomHex(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func randomUUIDLike() string {
	hexValue := randomHex(16)
	if len(hexValue) < 32 {
		return hexValue
	}
	return fmt.Sprintf("%s-%s-4%s-%s-%s",
		hexValue[0:8],
		hexValue[8:12],
		hexValue[13:16],
		hexValue[16:20],
		hexValue[20:32],
	)
}

func matchSliderOffset(smallImageB64, bigImageB64 string) (int, error) {
	bigImg, err := decodeBase64Image(bigImageB64)
	if err != nil {
		return 0, fmt.Errorf("decode captcha background: %w", err)
	}
	smallImg, err := decodeBase64Image(smallImageB64)
	if err != nil {
		return 0, fmt.Errorf("decode captcha slider: %w", err)
	}
	bigBounds := bigImg.Bounds()
	smallBounds := smallImg.Bounds()
	sw, sh := smallBounds.Dx(), smallBounds.Dy()
	w, h := bigBounds.Dx()/2, bigBounds.Dy()/2
	minSide := int(math.Max(4, float64(minInt(sw, sh))*0.25))
	if w <= 0 || h <= 0 || minSide <= 0 {
		return 0, errors.New("captcha images are too small")
	}

	colors := make([][]int, h)
	counts := map[int]int{}
	for y := 0; y < h; y++ {
		colors[y] = make([]int, w)
		for x := 0; x < w; x++ {
			r, g, b, _ := bigImg.At(bigBounds.Min.X+x*2, bigBounds.Min.Y+y*2).RGBA()
			id := quantizeColor(uint8(r>>8), uint8(g>>8), uint8(b>>8))
			colors[y][x] = id
			counts[id]++
		}
	}

	topColors := topColorIDs(counts, 5)
	bestArea := 0
	bestX := 0
	for _, colorID := range topColors {
		colRun := make([]int, w)
		for y := 0; y < h; y++ {
			row := make([]bool, w)
			for x := 0; x < w; x++ {
				if colors[y][x] == colorID {
					colRun[x]++
				} else {
					colRun[x] = 0
				}
				row[x] = colRun[x] >= minSide
			}
			start := -1
			for x := 0; x <= w; x++ {
				active := x < w && row[x]
				if active && start < 0 {
					start = x
				}
				if (!active || x == w) && start >= 0 {
					end := x
					runW := end - start
					if start > sw/4 && runW > 0 {
						runH := colRun[start]
						ratio := float64(runW) / math.Max(1, float64(runH))
						area := runW * runH
						if ratio > 0.7 && ratio < 1.4 && area > bestArea {
							bestArea = area
							bestX = start
						}
					}
					start = -1
				}
			}
		}
	}
	if bestArea == 0 {
		return 0, errors.New("captcha gap was not found")
	}
	return bestX * 2, nil
}

func decodeBase64Image(value string) (image.Image, error) {
	value = strings.TrimSpace(value)
	if comma := strings.Index(value, ","); comma > 0 && strings.HasPrefix(value[:comma], "data:") {
		value = value[comma+1:]
	}
	reader := strings.NewReader(value)
	decoder := base64Decoder{reader: reader}
	img, _, err := image.Decode(&decoder)
	return img, err
}

type base64Decoder struct {
	reader *strings.Reader
	buf    []byte
}

func (d *base64Decoder) Read(p []byte) (int, error) {
	if len(d.buf) == 0 {
		encoded, err := io.ReadAll(d.reader)
		if err != nil {
			return 0, err
		}
		decoded, err := decodeBase64String(string(encoded))
		if err != nil {
			return 0, err
		}
		d.buf = decoded
	}
	if len(d.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func decodeBase64String(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64StdDecode(value); err == nil {
		return decoded, nil
	}
	return base64RawStdDecode(value)
}

func base64StdDecode(value string) ([]byte, error) {
	return base64Encoding(false).DecodeString(value)
}

func base64RawStdDecode(value string) ([]byte, error) {
	return base64Encoding(true).DecodeString(value)
}

func base64Encoding(raw bool) *base64.Encoding {
	if raw {
		return base64.RawStdEncoding
	}
	return base64.StdEncoding
}

func quantizeColor(r, g, b uint8) int {
	rr := int(r/4) * 4
	gg := int(g/4) * 4
	bb := int(b/4) * 4
	return rr + gg*256 + bb*65536
}

func topColorIDs(counts map[int]int, limit int) []int {
	type colorCount struct {
		id    int
		count int
	}
	items := make([]colorCount, 0, len(counts))
	for id, count := range counts {
		items = append(items, colorCount{id: id, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].count > items[j].count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]int, 0, len(items))
	for _, item := range items {
		out = append(out, item.id)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
