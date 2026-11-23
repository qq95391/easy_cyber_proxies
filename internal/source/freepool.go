package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/config"
)

const maxFreeBodySize = 4 << 20

// Fetcher mirrors proxy_pool's BaseFetcher idea: one source yields a list of
// "host:port" entries. It is an interface so Go plugins can be registered in
// code, while the config-driven fetcher covers the common case.
type Fetcher interface {
	Name() string
	Fetch(ctx context.Context) ([]string, error)
}

// FetcherFunc adapts a function into a Fetcher.
type FetcherFunc struct {
	name string
	fn   func(context.Context) ([]string, error)
}

func (f FetcherFunc) Name() string { return f.name }

func (f FetcherFunc) Fetch(ctx context.Context) ([]string, error) { return f.fn(ctx) }

var (
	pluginMu sync.RWMutex
	plugins  = make(map[string]Fetcher)
)

// RegisterFetcher adds a code-defined free proxy source.
func RegisterFetcher(f Fetcher) {
	if f == nil {
		return
	}
	pluginMu.Lock()
	defer pluginMu.Unlock()
	plugins[f.Name()] = f
}

// RegisteredFetchers lists code-defined source names.
func RegisteredFetchers() []string {
	pluginMu.RLock()
	defer pluginMu.RUnlock()
	out := make([]string, 0, len(plugins))
	for name := range plugins {
		out = append(out, name)
	}
	return out
}

// FreePoolProvider aggregates all enabled free sources and optionally consumes
// an external proxy_pool API. Unlike proxy_pool itself, verification is NOT
// performed here: every candidate goes through the unified verifier.
type FreePoolProvider struct {
	cfg      config.FreePoolConfig
	client   *http.Client
	limiter  *Limiter
	fetchers []Fetcher
}

// NewFreePoolProvider builds the provider from configuration.
func NewFreePoolProvider(cfg config.FreePoolConfig, client *http.Client) Provider {
	limiter := NewLimiter(cfg.RatePerMin)
	if client == nil {
		client = &http.Client{Timeout: config.ParseDuration(cfg.Timeout, 10*time.Second)}
	}
	p := &FreePoolProvider{cfg: cfg, client: client, limiter: limiter}
	for _, f := range cfg.Fetchers {
		if !f.Enabled || strings.TrimSpace(f.URL) == "" {
			continue
		}
		p.fetchers = append(p.fetchers, &configuredFetcher{cfg: f, client: client, limiter: limiter})
	}
	pluginMu.RLock()
	for name, f := range plugins {
		p.fetchers = append(p.fetchers, renameFetcher(name, f))
	}
	pluginMu.RUnlock()
	if cfg.ExternalAPI.Enabled && strings.TrimSpace(cfg.ExternalAPI.BaseURL) != "" {
		p.fetchers = append(p.fetchers, &externalPoolFetcher{cfg: cfg.ExternalAPI, client: client, limiter: limiter})
	}
	return p
}

func renameFetcher(name string, f Fetcher) Fetcher {
	return FetcherFunc{name: name, fn: f.Fetch}
}

func (p *FreePoolProvider) Name() string { return "freepool" }

func (p *FreePoolProvider) Enabled() bool { return p.cfg.Enabled }

func (p *FreePoolProvider) Fetch(ctx context.Context) ([]config.NodeConfig, error) {
	type result struct {
		name    string
		entries []string
		err     error
	}
	results := make(chan result, len(p.fetchers))
	sem := make(chan struct{}, config.ClampInt(p.cfg.Concurrency, 4, 1, 32))
	var wg sync.WaitGroup
	for _, f := range p.fetchers {
		wg.Add(1)
		go func(f Fetcher) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			entries, err := f.Fetch(ctx)
			results <- result{name: f.Name(), entries: entries, err: err}
		}(f)
	}
	wg.Wait()
	close(results)

	limit := p.cfg.MaxResults
	if limit <= 0 {
		limit = 200
	}
	nodes := make([]config.NodeConfig, 0)
	seen := make(map[string]bool)
	var firstErr error
	for res := range results {
		if res.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", res.name, res.err)
			}
			continue
		}
		for _, entry := range res.entries {
			host, port, proto, user, pass, ok := parseHostPort(entry)
			if !ok || strings.ContainsAny(host, "<> \t") {
				continue
			}
			origin := config.NodeSourceFreePool
			if strings.HasPrefix(res.name, "external:") {
				origin = config.NodeSourceExternalPool
			}
			fallback := "http"
			if origin == config.NodeSourceFreePool {
				for _, f := range p.cfg.Fetchers {
					if res.name == "free:"+f.Name && f.Protocol != "" {
						fallback = f.Protocol
						break
					}
				}
			}
			uri := buildProxyURI(allowedProtocol(proto, fallback), host, port, user, pass)
			label := safeLabel(fmt.Sprintf("%s-%s-%d", res.name, host, port))
			key := config.DedupeKey(uri)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			nodes = append(nodes, config.NodeConfig{
				Name:         label,
				URI:          uri + "#" + label,
				Source:       origin,
				SourceDetail: res.name,
				Tags:         []string{"freepool", res.name},
			})
			if len(nodes) >= limit {
				break
			}
		}
		if len(nodes) >= limit {
			break
		}
	}
	if len(nodes) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return nodes, nil
}

type configuredFetcher struct {
	cfg     config.FreeFetcherConfig
	client  *http.Client
	limiter *Limiter
}

func (f *configuredFetcher) Name() string { return "free:" + f.cfg.Name }

func (f *configuredFetcher) Fetch(ctx context.Context) ([]string, error) {
	if err := f.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "easy-proxies/extension")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFreeBodySize))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return parseFreeEntries(data, f.cfg.Format, f.cfg.JSONPath, f.cfg.TextPattern), nil
}

func parseFreeEntries(data []byte, format, jsonPath, pattern string) []string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		out := make([]string, 0)
		for _, item := range extractJSONEntries(data, jsonPath) {
			var s string
			switch t := item.(type) {
			case string:
				s = t
			case map[string]any:
				host := normalizeHost(asString(getPath(t, "host")))
				ip := normalizeHost(asString(getPath(t, "ip")))
				if host == "" {
					host = ip
				}
				port := asString(getPath(t, "port"))
				if host != "" && port != "" {
					s = host + ":" + port
				} else {
					s = asString(getPath(t, "proxy"))
				}
			default:
				s = asString(t)
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return extractTextEntries(data, pattern)
	}
}

type externalPoolFetcher struct {
	cfg     config.ExternalPoolConfig
	client  *http.Client
	limiter *Limiter
}

func (f *externalPoolFetcher) Name() string { return "external:proxy_pool" }

func (f *externalPoolFetcher) Fetch(ctx context.Context) ([]string, error) {
	base := strings.TrimRight(f.cfg.BaseURL, "/")
	getPath := f.cfg.GetPath
	if getPath == "" {
		getPath = "/get/"
	}
	batch := config.ClampInt(f.cfg.Batch, 20, 1, 200)
	client := f.client
	if timeout := config.ParseDuration(f.cfg.Timeout, 0); timeout > 0 {
		copyClient := *client
		copyClient.Timeout = timeout
		client = &copyClient
	}
	out := make([]string, 0, batch)
	for i := 0; i < batch; i++ {
		if err := f.limiter.Wait(ctx); err != nil {
			return out, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+getPath, nil)
		if err != nil {
			return out, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return out, err
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			return out, readErr
		}
		var payload map[string]any
		if err := json.Unmarshal(data, &payload); err != nil {
			continue
		}
		if code, ok := payload["code"].(float64); ok && code == 0 {
			break
		}
		proxy := asString(payload["proxy"])
		if proxy == "" {
			break
		}
		out = append(out, proxy)
	}
	return out, nil
}
