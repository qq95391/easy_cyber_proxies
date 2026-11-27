// Package verify implements full-dimension proxy verification against public
// echo services. It complements (does not replace) easy_proxies' built-in
// health checks by adding exit IP, anonymity, handshake, throughput, DNS leak
// risk, region and stability dimensions.
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"easy_proxies/internal/config"
)

// Result is the outcome of one verification round.
type Result struct {
	Proxy          string          `json:"proxy"`
	Node           string          `json:"node,omitempty"`
	Reachable      bool            `json:"reachable"`
	Protocol       string          `json:"protocol"`
	Handshake      string          `json:"handshake"`
	ExitIP         string          `json:"exit_ip"`
	DirectIP       string          `json:"direct_ip"`
	Anonymity      string          `json:"anonymity"`
	DNSLeakRisk    bool            `json:"dns_leak_risk"`
	LatencyMS      int64           `json:"latency_ms"`
	TotalMS        int64           `json:"total_ms"`
	SpeedBPS       int64           `json:"speed_bps"`
	Region         string          `json:"region"`
	CountryCode    string          `json:"country_code"`
	SuccessRate    float64         `json:"success_rate"`
	Score          int             `json:"score"`
	Grade          string          `json:"grade"`
	Checks         map[string]bool `json:"checks"`
	Skipped        string          `json:"skipped,omitempty"`
	Error          string          `json:"error,omitempty"`
	CheckedAt      string          `json:"checked_at"`
	NoProxyTargets []string        `json:"no_proxy_targets,omitempty"`
	// Genuine / MITM dimensions (added for mapping-sourced candidates).
	DeclaredIP      string   `json:"declared_ip,omitempty"`
	Genuine         bool     `json:"genuine"`
	GenuineReasons  []string `json:"genuine_reasons,omitempty"`
	MITMSuspected   bool     `json:"mitm_suspected"`
	MITMReasons     []string `json:"mitm_reasons,omitempty"`
	CertFingerprint string   `json:"cert_fingerprint,omitempty"`
	CertIssuer      string   `json:"cert_issuer,omitempty"`
	TLSVersion      string   `json:"tls_version,omitempty"`
	BodyHashMatch   *bool    `json:"body_hash_match,omitempty"`
}

// Verifier performs the verification. It is safe for concurrent use.
type Verifier struct {
	cfg         config.VerificationConfig
	direct      *http.Client
	limiter     *rateLimiter
	baselines   *baselineCache
	mu          sync.RWMutex
	directIP    string
	directIPSet bool
}

// New builds a verifier with defensive defaults.
func New(cfg config.VerificationConfig) *Verifier {
	if cfg.EchoIPURL == "" {
		cfg.EchoIPURL = "https://httpbin.org/ip"
	}
	if cfg.EchoHeadersURL == "" {
		cfg.EchoHeadersURL = "https://httpbin.org/headers"
	}
	if cfg.EchoDownloadURL == "" {
		cfg.EchoDownloadURL = "https://httpbin.org/bytes/65536"
	}
	if cfg.RegionURL == "" {
		cfg.RegionURL = "http://ip-api.com/json/{ip}?fields=country,countryCode,query"
	}
	if cfg.DirectIPURL == "" {
		cfg.DirectIPURL = cfg.EchoIPURL
	}
	// Apply safe defaults for the newly added authenticity / MITM dimensions.
	// Explicit zero values in YAML are indistinguishable from "unset", so only
	// fill the target fields when they are empty.
	if cfg.Authenticity.CheckURL == "" {
		cfg.Authenticity.CheckURL = config.DefaultAuthenticityConfig().CheckURL
	}
	if cfg.Authenticity.ExpectKeyword == "" && cfg.Authenticity.ExpectSHA256 == "" {
		cfg.Authenticity.ExpectKeyword = config.DefaultAuthenticityConfig().ExpectKeyword
	}
	if cfg.MITM.ProbeURL == "" {
		cfg.MITM.ProbeURL = config.DefaultMITMConfig().ProbeURL
	}
	if cfg.MITM.Action == "" {
		cfg.MITM.Action = "reject"
	}
	timeout := config.ParseDuration(cfg.Timeout, 8*time.Second)
	cfg.Concurrency = config.ClampInt(cfg.Concurrency, 32, 1, 256)
	cfg.Retries = config.ClampInt(cfg.Retries, 3, 1, 10)
	cfg.RatePerMin = config.ClampInt(cfg.RatePerMin, 600, 1, 100000)
	cfg.MaxFailures = config.ClampInt(cfg.MaxFailures, 3, 1, 100)
	if cfg.MinScore <= 0 || cfg.MinScore > 100 {
		cfg.MinScore = 40
	}
	return &Verifier{
		cfg:       cfg,
		direct:    &http.Client{Timeout: timeout},
		limiter:   newRateLimiter(cfg.RatePerMin),
		baselines: newBaselineCache(),
	}
}

// Config returns the effective (defaulted) configuration.
func (v *Verifier) Config() config.VerificationConfig { return v.cfg }

// MinScore is the threshold used by the orchestrator for admission.
func (v *Verifier) MinScore() int { return v.cfg.MinScore }

// MaxFailures is the number of consecutive failed rechecks before eviction.
func (v *Verifier) MaxFailures() int { return v.cfg.MaxFailures }

// VerifyNode verifies a node. localURL, when provided, is the already-landed
// local mixed port (http://user:pass@127.0.0.1:PORT) and works for every
// upstream protocol, including vmess/vless/trojan.
func (v *Verifier) VerifyNode(ctx context.Context, n config.NodeConfig, localURL string) Result {
	target := localURL
	if strings.TrimSpace(target) == "" {
		target = n.URI
	}
	res := v.verify(ctx, target, n)
	res.Node = n.Name
	return res
}

// Verify verifies an arbitrary proxy URL (upstream http/socks5 or a local
// landed http/socks5 port). Manually supplied URLs have no declared IP.
func (v *Verifier) Verify(ctx context.Context, proxyURL string) Result {
	return v.verify(ctx, proxyURL, config.NodeConfig{})
}

func (v *Verifier) verify(ctx context.Context, proxyURL string, node config.NodeConfig) Result {
	now := time.Now()
	res := Result{
		Proxy:     redactProxyURL(proxyURL),
		Checks:    make(map[string]bool),
		CheckedAt: now.Format(time.RFC3339),
		Grade:     "D",
	}
	res.NoProxyTargets = v.cfg.NoProxyHosts()

	u, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil {
		res.Error = "invalid proxy url: " + err.Error()
		return res
	}
	res.Protocol = strings.ToLower(u.Scheme)
	switch res.Protocol {
	case "socks5", "socks5h", "socks", "http", "https":
		// supported below
	default:
		res.Skipped = "protocol " + res.Protocol + " requires a local landed mixed port"
		return res
	}

	timeout := config.ParseDuration(v.cfg.Timeout, 8*time.Second)
	transport, err := buildTransport(u, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	defer transport.CloseIdleConnections()

	// Anonymity comparison baseline (direct, never through the tested proxy).
	directIP := v.getDirectIP(ctx)
	res.DirectIP = directIP
	res.Checks["direct_ip"] = directIP != ""

	// 1. Connectivity + exit IP + latency + stability.
	retryInterval := config.ParseDuration(v.cfg.RetryInterval, 200*time.Millisecond)
	success, total := 0, 0
	var latencySum int64
	for i := 0; i < v.cfg.Retries; i++ {
		total++
		start := time.Now()
		body, err := v.doGet(ctx, client, v.cfg.EchoIPURL)
		elapsed := time.Since(start).Milliseconds()
		if err == nil {
			success++
			latencySum += elapsed
			ip := parseExitIP(body)
			if ip != "" {
				res.ExitIP = ip
			}
		} else if res.Error == "" {
			res.Error = err.Error()
		}
		if i+1 < v.cfg.Retries {
			select {
			case <-ctx.Done():
			case <-time.After(retryInterval):
			}
		}
	}
	res.Reachable = success > 0 && res.ExitIP != ""
	res.Checks["connectivity"] = success > 0
	res.Checks["exit_ip"] = res.ExitIP != ""
	res.SuccessRate = 0
	if total > 0 {
		res.SuccessRate = float64(success) / float64(total)
	}
	if success > 0 {
		res.LatencyMS = latencySum / int64(success)
	}
	res.TotalMS = time.Since(now).Milliseconds()

	// Handshake classification. A successful HTTPS request through an HTTP
	// proxy implies CONNECT; a successful request through SOCKS5 implies the
	// SOCKS5 negotiation completed.
	if res.Reachable {
		switch res.Protocol {
		case "socks5", "socks5h", "socks":
			res.Handshake = "socks5"
		case "http", "https":
			if strings.HasPrefix(strings.ToLower(v.cfg.EchoIPURL), "https://") {
				res.Handshake = "http_connect"
			} else {
				res.Handshake = "http_absolute_form"
			}
		}
		res.Checks["handshake"] = true
	}

	// DNS leak risk: plain socks5 (not socks5h) resolves names locally.
	res.DNSLeakRisk = res.Protocol == "socks5" || res.Protocol == "socks"
	res.Checks["dns_leak"] = true

	// 2. Anonymity via echo of request headers.
	if res.Reachable && v.cfg.EchoHeadersURL != "" {
		if body, err := v.doGet(ctx, client, v.cfg.EchoHeadersURL); err == nil {
			res.Anonymity = classifyAnonymity(body, res.ExitIP, directIP)
			res.Checks["anonymity"] = true
		} else {
			res.Anonymity = "unknown"
		}
	} else {
		res.Anonymity = "unknown"
	}

	// 3. Throughput sample.
	if res.Reachable && v.cfg.EchoDownloadURL != "" {
		start := time.Now()
		if body, err := v.doGet(ctx, client, v.cfg.EchoDownloadURL); err == nil && len(body) > 0 {
			secs := time.Since(start).Seconds()
			if secs > 0 {
				res.SpeedBPS = int64(float64(len(body)) / secs)
			}
			res.Checks["throughput"] = true
		}
	}

	// 4. Region from the observed exit IP (not from the node's server IP).
	if !v.cfg.RegionDisabled && res.ExitIP != "" {
		regionURL := strings.ReplaceAll(v.cfg.RegionURL, "{ip}", res.ExitIP)
		if body, err := v.doGet(ctx, client, regionURL); err == nil {
			res.Region, res.CountryCode = parseRegion(body)
			res.Checks["region"] = true
		}
	}

	// 5. Authenticity: prove the candidate really forwards traffic and that
	// the observed exit matches the IP claimed by the mapping result.
	if res.Reachable {
		v.checkAuthenticity(ctx, &res, node, proxyURL)
		// 6. Malicious-MITM detection against a direct trusted baseline.
		v.checkMITM(ctx, &res, proxyURL)
	}

	res.Score, res.Grade = score(res)
	return res
}

func (v *Verifier) doGet(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("empty verification target")
	}
	if err := v.limiter.wait(ctx); err != nil {
		return nil, err
	}
	// Special targets always bypass the tested proxy, per the proxy policy.
	if u, err := url.Parse(rawURL); err == nil && matchesNoProxy(u.Hostname(), v.cfg.NoProxyHosts()) {
		client = v.direct
	}
	timeout := config.ParseDuration(v.cfg.Timeout, 8*time.Second)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "easy-proxies-verifier/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("echo http %d", resp.StatusCode)
	}
	return data, nil
}

func (v *Verifier) getDirectIP(ctx context.Context) string {
	v.mu.RLock()
	if v.directIPSet {
		ip := v.directIP
		v.mu.RUnlock()
		return ip
	}
	v.mu.RUnlock()
	client := v.direct
	timeout := config.ParseDuration(v.cfg.Timeout, 8*time.Second)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, v.cfg.DirectIPURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	ip := parseExitIP(data)
	v.mu.Lock()
	v.directIP, v.directIPSet = ip, true
	v.mu.Unlock()
	return ip
}

func buildTransport(u *url.URL, timeout time.Duration) (*http.Transport, error) {
	base := &http.Transport{
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		MaxIdleConns:          2,
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		base.Proxy = http.ProxyURL(u)
		return base, nil
	case "socks5", "socks5h", "socks":
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		proxyAddr := u.Host
		if !strings.Contains(proxyAddr, ":") {
			proxyAddr = net.JoinHostPort(proxyAddr, "1080")
		}
		base.Proxy = nil
		base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			// Keep a handle on the underlying TCP socket: the SOCKS5 handshake
			// runs inside proxy.Dialer.Dial and honours no context, so closing
			// this socket is the only way to abort it on cancellation.
			var raw net.Conn
			var rawMu sync.Mutex
			forward := dialFunc(func(network2, addr2 string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(dialCtx, network2, addr2)
				if err == nil {
					rawMu.Lock()
					raw = conn
					rawMu.Unlock()
				}
				return conn, err
			})
			dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, forward)
			if err != nil {
				return nil, fmt.Errorf("socks dialer: %w", err)
			}
			type outcome struct {
				conn net.Conn
				err  error
			}
			ch := make(chan outcome, 1)
			verifyDialInflight.Add(1)
			go func() {
				c, e := dialer.Dial(network, addr)
				ch <- outcome{c, e}
			}()
			// harvest drains the dial result and closes a connection that
			// arrived after the caller gave up. Without this the socket stays
			// ESTABLISHED forever (GC never closes file descriptors).
			harvest := func() {
				go func() {
					o := <-ch
					verifyDialInflight.Add(-1)
					if o.conn != nil {
						_ = o.conn.Close()
						verifyDialHarvested.Add(1)
					}
				}()
			}
			select {
			case o := <-ch:
				verifyDialInflight.Add(-1)
				if o.conn != nil && ctx.Err() != nil {
					_ = o.conn.Close()
					verifyDialHarvested.Add(1)
					return nil, ctx.Err()
				}
				return o.conn, o.err
			case <-dialCtx.Done():
				verifyDialLeaks.Add(1)
				rawMu.Lock()
				if raw != nil {
					_ = raw.Close()
				}
				rawMu.Unlock()
				harvest()
				return nil, dialCtx.Err()
			}
		}
		return base, nil
	default:
		return nil, fmt.Errorf("unsupported verification scheme %q", u.Scheme)
	}
}

func parseExitIP(data []byte) string {
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err == nil {
		for _, key := range []string{"origin", "ip", "query"} {
			if s := strings.TrimSpace(asString(payload[key])); s != "" {
				if idx := strings.Index(s, ","); idx != -1 {
					s = strings.TrimSpace(s[:idx])
				}
				if net.ParseIP(s) != nil {
					return s
				}
			}
		}
	}
	s := strings.TrimSpace(string(data))
	if net.ParseIP(s) != nil {
		return s
	}
	return ""
}

func classifyAnonymity(data []byte, exitIP, directIP string) string {
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err == nil {
		headers, _ := payload["headers"].(map[string]any)
		if headers == nil {
			headers = payload
		}
		for key := range headers {
			lower := strings.ToLower(key)
			for _, marker := range []string{"x-forwarded-for", "forwarded", "via", "x-proxy-id", "x-real-ip", "client-ip", "proxy-connection"} {
				if strings.Contains(lower, marker) {
					return "transparent"
				}
			}
		}
	}
	if directIP != "" && exitIP != "" && directIP == exitIP {
		return "transparent"
	}
	return "high"
}

func parseRegion(data []byte) (string, string) {
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", ""
	}
	country := asString(payload["country"])
	code := asString(payload["countryCode"])
	if code == "" {
		code = asString(payload["country_code"])
	}
	return country, code
}

func score(r Result) (int, string) {
	if !r.Reachable {
		return 0, "D"
	}
	s := 0
	s += 30
	s += int(r.SuccessRate * 20)
	switch {
	case r.LatencyMS <= 200:
		s += 15
	case r.LatencyMS <= 500:
		s += 12
	case r.LatencyMS <= 1000:
		s += 8
	case r.LatencyMS <= 2000:
		s += 4
	}
	switch r.Anonymity {
	case "high":
		s += 20
	case "anonymous":
		s += 12
	case "transparent":
		// Transparent proxies leak client information; they earn no anonymity
		// points so a slow/unstable one cannot reach the admission threshold.
		s += 0
	default:
		s += 8
	}
	if r.Handshake != "" {
		s += 10
	}
	if r.SpeedBPS > 0 {
		s += 5
	}
	// Genuine / MITM dimensions are hard gates: a hijacked or non-forwarding
	// candidate must never be presented as a high-quality proxy.
	if r.Checks["genuine"] && !r.Genuine {
		s -= 40
	}
	if r.MITMSuspected {
		s -= 60
	}
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	grade := "D"
	switch {
	case s >= 80:
		grade = "A"
	case s >= 60:
		grade = "B"
	case s >= 40:
		grade = "C"
	}
	return s, grade
}

func matchesNoProxy(host string, list []string) bool {
	for _, entry := range list {
		if entry == "" {
			continue
		}
		if strings.EqualFold(host, entry) || strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(entry)) {
			return true
		}
	}
	return false
}

func redactProxyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "invalid"
	}
	if u.User != nil {
		u.User = url.User("***")
	}
	return u.String()
}

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

// rateLimiter is a dependency-free requests-per-minute throttle.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newRateLimiter(perMin int) *rateLimiter {
	l := &rateLimiter{}
	if perMin > 0 {
		l.interval = time.Minute / time.Duration(perMin)
	}
	return l
}

func (l *rateLimiter) wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	delay := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
