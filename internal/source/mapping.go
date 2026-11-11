package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"easy_proxies/internal/config"
)

const maxMappingBodySize = 10 << 20

// MappingProvider is a generic space-mapping API shell. It contains no
// platform-specific logic: endpoint, credentials, search query and response
// field mapping are all supplied by the user in config.yaml.
type MappingProvider struct {
	cfg     config.MappingProviderConfig
	global  config.MappingSourcesConfig
	client  *http.Client
	limiter *Limiter
}

// NewMappingProviders builds one provider per user-defined entry.
func NewMappingProviders(global config.MappingSourcesConfig, client *http.Client) []Provider {
	limiter := NewLimiter(global.RatePerMin)
	entries := append([]config.MappingProviderConfig(nil), global.Providers...)
	// Built-in presets are expanded into ordinary provider configs, so they
	// share the exact same request/parse path as custom providers.
	for _, pr := range EnsureMappingPresets(global.Presets) {
		if !pr.Enabled {
			continue
		}
		built, err := BuildPreset(pr)
		if err != nil {
			continue
		}
		duplicate := false
		for _, existing := range entries {
			if existing.Name == built.Name {
				duplicate = true
				break
			}
		}
		if !duplicate {
			entries = append(entries, built)
		}
	}
	providers := make([]Provider, 0, len(entries))
	for _, p := range entries {
		if strings.TrimSpace(p.Name) == "" {
			continue
		}
		providers = append(providers, &MappingProvider{
			cfg: p, global: global, client: client, limiter: limiter,
		})
	}
	return providers
}

func (p *MappingProvider) Name() string { return "mapping:" + p.cfg.Name }

func (p *MappingProvider) Enabled() bool { return p.global.Enabled && p.cfg.Enabled }

func (p *MappingProvider) Fetch(ctx context.Context) ([]config.NodeConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(p.cfg.Endpoint) == "" {
		return nil, fmt.Errorf("endpoint is empty")
	}
	maxPages, start := 1, 1
	if p.cfg.Pagination.Enabled {
		maxPages = config.ClampInt(p.cfg.Pagination.MaxPages, 1, 1, 20)
		start = p.cfg.Pagination.Start
		if start < 0 {
			start = 1
		}
	}
	limit := p.cfg.MaxResults
	if limit <= 0 {
		limit = p.global.MaxResults
	}
	if limit <= 0 {
		limit = 200
	}

	nodes := make([]config.NodeConfig, 0)
	for page := 0; page < maxPages; page++ {
		pageNodes, err := p.fetchPage(ctx, start+page)
		if err != nil {
			return nil, err
		}
		if len(pageNodes) == 0 {
			break
		}
		nodes = append(nodes, pageNodes...)
		if len(nodes) >= limit {
			nodes = nodes[:limit]
			break
		}
	}
	return nodes, nil
}

func (p *MappingProvider) fetchPage(ctx context.Context, page int) ([]config.NodeConfig, error) {
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	u, err := url.Parse(p.cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("endpoint must use http or https")
	}

	key := config.ResolveMappingKey(p.cfg.Auth)
	authType := strings.ToLower(strings.TrimSpace(p.cfg.Auth.Type))
	if key == "" && authType != "" && authType != "none" {
		return nil, fmt.Errorf("credential missing: set env %q or auth.key_value", p.cfg.Auth.KeyEnv)
	}

	params := url.Values{}
	for k, v := range u.Query() {
		params[k] = append([]string(nil), v...)
	}
	if p.cfg.QueryParam != "" && p.cfg.Query != "" {
		params.Set(p.cfg.QueryParam, encodeMappingQuery(p.cfg.Query, p.cfg.QueryEncoding))
	}
	for k, v := range p.cfg.ExtraParams {
		params.Set(k, v)
	}
	if p.cfg.Pagination.Enabled {
		if p.cfg.Pagination.Param != "" {
			params.Set(p.cfg.Pagination.Param, strconv.Itoa(page))
		}
		if p.cfg.Pagination.SizeParam != "" && p.cfg.Pagination.Size > 0 {
			params.Set(p.cfg.Pagination.SizeParam, strconv.Itoa(p.cfg.Pagination.Size))
		}
	}
	if authType == "query" {
		name := p.cfg.Auth.KeyName
		if name == "" {
			name = "key"
		}
		params.Set(name, key)
	}

	method := strings.ToUpper(strings.TrimSpace(p.cfg.Method))
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	isJSONBody := false
	if strings.TrimSpace(p.cfg.BodyTemplate) != "" {
		size := strconv.Itoa(p.cfg.MaxResults)
		if v, ok := p.cfg.ExtraParams["size"]; ok && strings.TrimSpace(v) != "" {
			size = v
		} else if p.cfg.Pagination.Size > 0 {
			size = strconv.Itoa(p.cfg.Pagination.Size)
		}
		start := "0"
		if v, ok := p.cfg.ExtraParams["start"]; ok && strings.TrimSpace(v) != "" {
			start = v
		}
		rendered, err := config.RenderMappingBody(p.cfg.BodyTemplate, map[string]string{
			"query": p.cfg.Query,
			"key":   key,
			"size":  size,
			"start": start,
			"page":  strconv.Itoa(page),
		})
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(rendered)
		isJSONBody = true
	} else if method == http.MethodPost || method == http.MethodPut {
		body = strings.NewReader(params.Encode())
	} else {
		u.RawQuery = params.Encode()
	}
	if !isJSONBody {
		u.RawQuery = params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		if isJSONBody {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	switch authType {
	case "header":
		name := p.cfg.Auth.KeyName
		if name == "" {
			name = "X-Api-Key"
		}
		req.Header.Set(name, key)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+key)
	case "basic":
		password := ""
		if p.cfg.Auth.PasswordEnv != "" {
			password = strings.TrimSpace(os.Getenv(p.cfg.Auth.PasswordEnv))
		}
		req.SetBasicAuth(p.cfg.Auth.Username, password)
	}

	client := p.client
	if client == nil {
		client = &http.Client{Timeout: config.ParseDuration(p.global.Timeout, 20*time.Second)}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMappingBodySize))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d from mapping API", resp.StatusCode)
	}
	if err := checkMappingBusinessError(data, p.cfg.Response); err != nil {
		return nil, err
	}
	if delay := config.ParseDuration(p.cfg.RequestInterval, 0); delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return p.parseResponse(data)
}

// checkMappingBusinessError catches failures returned inside an HTTP 200 body.
func checkMappingBusinessError(data []byte, resp config.MappingResponse) error {
	path := strings.TrimSpace(resp.ErrorPath)
	if path == "" {
		return nil
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	raw := getPath(root, path)
	value := asString(raw)
	want := strings.TrimSpace(resp.SuccessValue)
	if want == "" {
		want = "false"
	}
	if strings.EqualFold(value, want) {
		return nil
	}
	message := ""
	if msgPath := strings.TrimSpace(resp.MessagePath); msgPath != "" {
		message = asString(getPath(root, msgPath))
	}
	if message == "" {
		message = fmt.Sprintf("%s=%s (want %s)", path, value, want)
	}
	return fmt.Errorf("mapping API error: %s", message)
}

// encodeMappingQuery applies the platform-specific base64 variant. Empty
// encoding leaves the query untouched for custom providers.
func encodeMappingQuery(query, encoding string) string {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "std":
		return base64.StdEncoding.EncodeToString([]byte(query))
	case "url":
		return base64.URLEncoding.EncodeToString([]byte(query))
	default:
		return query
	}
}

func (p *MappingProvider) parseResponse(data []byte) ([]config.NodeConfig, error) {
	format := strings.ToLower(strings.TrimSpace(p.cfg.Response.Format))
	if format == "" {
		format = "json"
	}
	f := p.cfg.Response.Fields
	defaultProto := f.DefaultProtocol
	if defaultProto == "" {
		defaultProto = "http"
	}

	var entries []any
	switch format {
	case "json":
		entries = extractJSONEntries(data, p.cfg.Response.ResultsPath)
	case "text":
		for _, line := range extractTextEntries(data, p.cfg.Response.TextPattern) {
			entries = append(entries, line)
		}
	default:
		return nil, fmt.Errorf("unsupported response format %q", format)
	}

	nodes := make([]config.NodeConfig, 0, len(entries))
	for _, item := range entries {
		var host, portStr, proto, user, pass, name string
		switch t := item.(type) {
		case string:
			h, port, pr, u, pw, ok := parseHostPort(t)
			if !ok {
				continue
			}
			host, portStr, proto, user, pass = h, strconv.Itoa(port), pr, u, pw
		default:
			host = normalizeHost(fieldOf(item, f.Host))
			portStr = fieldOf(item, f.Port)
			proto = fieldOf(item, f.Protocol)
			user = fieldOf(item, f.Username)
			pass = fieldOf(item, f.Password)
			name = fieldOf(item, f.Name)
		}
		port := normalizePort(portStr)
		if host == "" || port == 0 || strings.ContainsAny(host, "<> \t") {
			continue
		}
		uri := buildProxyURI(allowedProtocol(proto, defaultProto), host, port, user, pass)
		if uri == "" {
			continue
		}
		label := name
		if label == "" {
			label = fmt.Sprintf("%s-%s-%d", p.cfg.Name, host, port)
		}
		label = safeLabel(label)
		nodes = append(nodes, config.NodeConfig{
			Name:         label,
			URI:          uri + "#" + label,
			Source:       config.NodeSourceMapping,
			SourceDetail: p.cfg.Name,
			Tags:         []string{"mapping", p.cfg.Name},
			DeclaredIP:   host,
		})
	}
	return nodes, nil
}
