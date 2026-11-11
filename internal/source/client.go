package source

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"easy_proxies/internal/config"
)

// NewOutboundClient builds the shared HTTP client used by extension sources.
// All outbound requests use the configured default proxy, except the special
// targets listed in no_proxy which always bypass any proxy.
func NewOutboundClient(cfg config.ExtensionConfig, timeout time.Duration) *http.Client {
	var fixed *url.URL
	if raw := strings.TrimSpace(cfg.OutboundProxy); raw != "" {
		if u, err := url.Parse(raw); err == nil && (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "socks5") {
			fixed = u
		}
	}
	noProxy := cfg.Verification.NoProxyHosts()
	transport := &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			host := req.URL.Hostname()
			for _, entry := range noProxy {
				if entry == "" {
					continue
				}
				if strings.EqualFold(host, entry) || strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(entry)) {
					return nil, nil
				}
			}
			if fixed != nil {
				return fixed, nil
			}
			return http.ProxyFromEnvironment(req)
		},
		MaxIdleConns:        16,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
	return &http.Client{Transport: transport, Timeout: timeout}
}
