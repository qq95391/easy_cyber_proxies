package verify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/config"
)

// probeSnapshot is the observable result of one request to a trusted target,
// used both as the direct (no-proxy) baseline and as the through-proxy sample.
type probeSnapshot struct {
	Status          int
	BodyHash        string
	BodyLength      int
	CertFingerprint string
	SPKIFingerprint string
	Issuer          string
	Subject         string
	Serial          string
	TLSVersion      string
	ALPN            string
	Location        string
	Headers         http.Header
	Body            []byte
	fetchedAt       time.Time
}

type baselineCache struct {
	mu     sync.Mutex
	items  map[string]*probeSnapshot
	expiry time.Duration
}

func newBaselineCache() *baselineCache {
	return &baselineCache{items: make(map[string]*probeSnapshot), expiry: 10 * time.Minute}
}

func (c *baselineCache) get(key string) *probeSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.items[key]
	if item == nil || time.Since(item.fetchedAt) > c.expiry {
		return nil
	}
	return item
}

func (c *baselineCache) put(key string, item *probeSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = item
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hashCert(cert *x509.Certificate) string {
	return hashBytes(cert.Raw)
}

func hashSPKI(cert *x509.Certificate) string {
	return hashBytes(cert.RawSubjectPublicKeyInfo)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// collectProbe performs one GET with strict redirect handling and records the
// TLS peer certificate, response body hash and headers. The caller supplies a
// client that is either direct or routed through the candidate proxy.
func collectProbe(ctx context.Context, client *http.Client, target string) (*probeSnapshot, error) {
	if strings.TrimSpace(target) == "" {
		return nil, errors.New("empty probe target")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "easy-proxies-probe/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	snap := &probeSnapshot{
		Status: resp.StatusCode, BodyHash: hashBytes(body), BodyLength: len(body),
		Location: resp.Header.Get("Location"), Headers: resp.Header.Clone(),
		Body: body, fetchedAt: time.Now(),
	}
	if state := resp.TLS; state != nil {
		snap.TLSVersion = tlsVersionName(state.Version)
		snap.ALPN = state.NegotiatedProtocol
		if len(state.PeerCertificates) > 0 {
			leaf := state.PeerCertificates[0]
			snap.CertFingerprint = hashCert(leaf)
			snap.SPKIFingerprint = hashSPKI(leaf)
			snap.Issuer = leaf.Issuer.String()
			snap.Subject = leaf.Subject.String()
			snap.Serial = leaf.SerialNumber.String()
		}
	}
	return snap, nil
}

// newProbeClient builds a client with strict TLS verification. Redirects are
// never followed so an HTTPS->HTTP downgrade can be detected.
func newProbeClient(transport *http.Transport, timeout time.Duration) *http.Client {
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig.InsecureSkipVerify = false
		if transport.TLSClientConfig.MinVersion == 0 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (v *Verifier) directProbeClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return newProbeClient(transport, timeout)
}

func (v *Verifier) proxyProbeClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil {
		return nil, err
	}
	transport, err := buildTransport(u, timeout)
	if err != nil {
		return nil, err
	}
	return newProbeClient(transport, timeout), nil
}

// directBaseline returns the trusted snapshot for a target, cached briefly so
// a large candidate set does not hammer the trusted endpoint.
func (v *Verifier) directBaseline(ctx context.Context, target string, timeout time.Duration) (*probeSnapshot, error) {
	if cached := v.baselines.get(target); cached != nil {
		return cached, nil
	}
	snap, err := collectProbe(ctx, v.directProbeClient(timeout), target)
	if err != nil {
		return nil, err
	}
	v.baselines.put(target, snap)
	return snap, nil
}

// checkAuthenticity decides whether the candidate really is a forwarding
// proxy rather than a honeypot, interception page or plain HTTP service.
func (v *Verifier) checkAuthenticity(ctx context.Context, res *Result, node config.NodeConfig, proxyURL string) {
	cfg := v.cfg.Authenticity
	if !cfg.IsEnabled() {
		return
	}
	res.DeclaredIP = strings.TrimSpace(node.DeclaredIP)
	res.Genuine = true
	res.Checks["genuine"] = true

	appendReason := func(format string, args ...any) {
		res.Genuine = false
		res.GenuineReasons = append(res.GenuineReasons, fmt.Sprintf(format, args...))
	}
	if cfg.RequireExitDiffers {
		if res.DirectIP == "" || res.ExitIP == "" {
			appendReason("缺少出口 IP 或直连 IP，无法确认真实转发")
		} else if res.ExitIP == res.DirectIP {
			appendReason("出口 IP 与直连 IP 相同，未发生转发")
		}
	}
	if cfg.RequireDeclaredMatch && res.DeclaredIP != "" {
		if res.ExitIP == "" {
			appendReason("缺少出口 IP，无法与测绘宣称 IP 比对")
		} else if res.ExitIP != res.DeclaredIP {
			appendReason("出口 IP %s 与测绘宣称 IP %s 不一致", res.ExitIP, res.DeclaredIP)
		}
	}
	if strings.TrimSpace(cfg.CheckURL) == "" {
		return
	}
	// Special targets must never be routed through the tested proxy.
	if u, err := url.Parse(cfg.CheckURL); err == nil && matchesNoProxy(u.Hostname(), v.cfg.NoProxyHosts()) {
		return
	}
	timeout := config.ParseDuration(v.cfg.Timeout, 8*time.Second)
	client, err := v.proxyProbeClient(proxyURL, timeout)
	if err != nil {
		// A client/target failure is an environment problem, not evidence that
		// the proxy is fake. Skip this dimension instead of rejecting the node.
		res.Checks["genuine_probe"] = false
		return
	}
	if err := v.limiter.wait(ctx); err != nil {
		res.Checks["genuine_probe"] = false
		return
	}
	snap, err := collectProbe(ctx, client, cfg.CheckURL)
	if err != nil {
		res.Checks["genuine_probe"] = false
		return
	}
	res.Checks["genuine_probe"] = true
	if cfg.CheckStatus && (snap.Status < 200 || snap.Status >= 300) {
		appendReason("真实性探测返回 HTTP %d", snap.Status)
	}
	if !cfg.FollowRedirect && snap.Location != "" {
		appendReason("真实性探测被重定向至 %s", snap.Location)
	}
	if cfg.ExpectSHA256 != "" {
		if !strings.EqualFold(snap.BodyHash, cfg.ExpectSHA256) {
			appendReason("响应体哈希不匹配（可能被替换或注入）")
		}
	} else if cfg.ExpectKeyword != "" {
		if !strings.Contains(string(snap.Body), cfg.ExpectKeyword) {
			appendReason("响应体缺少期望关键字 %q", cfg.ExpectKeyword)
		}
	}
}

// checkMITM implements the five-layer malicious-MITM detection. Deadpool has
// NO such detection (it sets InsecureSkipVerify), so this is entirely our own.
func (v *Verifier) checkMITM(ctx context.Context, res *Result, proxyURL string) {
	cfg := v.cfg.MITM
	if !cfg.IsEnabled() {
		return
	}
	res.Checks["mitm"] = true
	timeout := config.ParseDuration(v.cfg.Timeout, 8*time.Second)
	target := cfg.ProbeURL
	if u, err := url.Parse(target); err == nil && matchesNoProxy(u.Hostname(), v.cfg.NoProxyHosts()) {
		res.MITMReasons = append(res.MITMReasons, "探测目标位于免代理列表，已跳过 MITM 判定")
		return
	}

	baseline, err := v.directBaseline(ctx, target, timeout)
	if err != nil {
		// A baseline failure means we cannot make a trustworthy judgement.
		res.MITMReasons = append(res.MITMReasons, "可信基线获取失败: "+err.Error())
		return
	}
	client, err := v.proxyProbeClient(proxyURL, timeout)
	if err != nil {
		res.MITMReasons = append(res.MITMReasons, "MITM 探测客户端不可用: "+err.Error())
		return
	}
	if err := v.limiter.wait(ctx); err != nil {
		return
	}
	sample, err := collectProbe(ctx, client, target)
	if err != nil {
		// L1: strict certificate verification failing through the proxy is a
		// strong MITM signal (self-signed / unknown CA / hostname mismatch).
		if cfg.VerifyCertificate && isCertificateError(err) {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "TLS 证书校验失败（疑似中间人）: "+err.Error())
		} else {
			res.MITMReasons = append(res.MITMReasons, "MITM 探测请求失败: "+err.Error())
		}
		return
	}

	res.CertFingerprint = sample.CertFingerprint
	res.CertIssuer = sample.Issuer
	res.TLSVersion = sample.TLSVersion

	compareProbeSnapshots(baseline, sample, cfg, res)
}

// compareProbeSnapshots implements L2-L5 against the trusted direct baseline.
func compareProbeSnapshots(baseline, sample *probeSnapshot, cfg config.MITMConfig, res *Result) {
	// L2: certificate / public-key baseline comparison. SPKI and issuer are
	// strong signals; a differing serial with the same SPKI is normal
	// certificate rotation and is recorded but never treated as MITM.
	if cfg.CompareCertBaseline {
		if sample.SPKIFingerprint != "" && baseline.SPKIFingerprint != "" &&
			sample.SPKIFingerprint != baseline.SPKIFingerprint {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "证书公钥 SPKI 与直连基线不一致")
		}
		if sample.Issuer != "" && baseline.Issuer != "" && sample.Issuer != baseline.Issuer {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "证书签发者与直连基线不一致")
		}
		if sample.Subject != "" && baseline.Subject != "" && sample.Subject != baseline.Subject {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "证书主体与直连基线不一致")
		}
		if sample.TLSVersion != "" && baseline.TLSVersion != "" && sample.TLSVersion != baseline.TLSVersion {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "TLS 版本与直连基线不一致，疑似降级")
		}
		if sample.ALPN != "" && baseline.ALPN != "" && sample.ALPN != baseline.ALPN {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "ALPN 与直连基线不一致")
		}
	}

	// L3: response body integrity.
	if cfg.CompareBodyHash {
		match := sample.BodyHash == baseline.BodyHash
		res.BodyHashMatch = &match
		if !match {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "响应体哈希与直连基线不一致，疑似内容篡改")
		}
	}

	// L4: injected proxy headers and HTTPS->HTTP downgrade.
	if cfg.CheckHeaders {
		for _, name := range []string{
			"Via", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
			"X-Proxy-Id", "Proxy-Connection", "X-Real-Ip",
		} {
			if sample.Headers.Get(name) != "" {
				res.MITMSuspected = true
				res.MITMReasons = append(res.MITMReasons, "检测到代理注入响应头 "+name)
			}
		}
		if sample.Location != "" && strings.HasPrefix(strings.ToLower(sample.Location), "http://") {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "检测到 HTTPS 降级重定向")
		}
		if declared := sample.Headers.Get("Content-Length"); declared != "" && declared != fmt.Sprintf("%d", sample.BodyLength) {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "Content-Length 与响应体长度不一致")
		}
	}

	// L5: explicit allow / deny lists.
	if len(cfg.TrustedFingerprints) > 0 && sample.CertFingerprint != "" {
		trusted := false
		for _, fp := range cfg.TrustedFingerprints {
			if strings.EqualFold(strings.TrimSpace(fp), sample.CertFingerprint) {
				trusted = true
				break
			}
		}
		if !trusted {
			res.MITMSuspected = true
			res.MITMReasons = append(res.MITMReasons, "证书指纹不在可信白名单中")
		}
	}
	if sample.CertFingerprint != "" {
		for _, fp := range cfg.BlacklistFingerprints {
			if strings.EqualFold(strings.TrimSpace(fp), sample.CertFingerprint) {
				res.MITMSuspected = true
				res.MITMReasons = append(res.MITMReasons, "证书指纹命中黑名单")
			}
		}
	}
	if res.ExitIP != "" {
		for _, ip := range cfg.BlacklistIPs {
			if strings.EqualFold(strings.TrimSpace(ip), res.ExitIP) {
				res.MITMSuspected = true
				res.MITMReasons = append(res.MITMReasons, "出口 IP 命中黑名单")
			}
		}
	}
	if res.MITMSuspected {
		res.CertFingerprint = sample.CertFingerprint
	}
}

func isCertificateError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range []string{
		"certificate", "x509", "tls:", "unknown authority", "self-signed",
		"hostname", "cert", "handshake",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
