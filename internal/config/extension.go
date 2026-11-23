package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Extended node origins. The upstream enum stays untouched so existing
// behaviour (inline / nodes_file / subscription) is preserved.
const (
	NodeSourceMapping      NodeSource = "mapping"
	NodeSourceFreePool     NodeSource = "freepool"
	NodeSourceExternalPool NodeSource = "external_pool"
)

// ExtensionConfig is the configuration root for the second-development
// features: pluggable sources (subscription enhancements, space-mapping API
// shell, free proxy pool) and full-dimension proxy verification.
type ExtensionConfig struct {
	Enabled       bool                 `yaml:"enabled" json:"enabled"`
	OutboundProxy string               `yaml:"outbound_proxy" json:"outbound_proxy"`
	CacheFile     string               `yaml:"cache_file" json:"cache_file"`
	Mapping       MappingSourcesConfig `yaml:"mapping" json:"mapping"`
	FreePool      FreePoolConfig       `yaml:"freepool" json:"freepool"`
	Verification  VerificationConfig   `yaml:"verification" json:"verification"`
}

// MappingSourcesConfig controls the generic, configuration-driven space
// mapping shell. No platform is hardcoded: endpoint, credentials, query and
// response mapping are all supplied by the user.
type MappingSourcesConfig struct {
	Enabled     bool                    `yaml:"enabled" json:"enabled"`
	Interval    string                  `yaml:"interval" json:"interval"`
	Timeout     string                  `yaml:"timeout" json:"timeout"`
	Concurrency int                     `yaml:"concurrency" json:"concurrency"`
	MaxResults  int                     `yaml:"max_results" json:"max_results"`
	RatePerMin  int                     `yaml:"rate_limit_per_min" json:"rate_limit_per_min"`
	Providers   []MappingProviderConfig `yaml:"providers" json:"providers"`
	// Presets are the built-in FOFA / Hunter / Quake templates. They are plain
	// configuration, not hardcoded platform clients, and stay fully editable.
	Presets []MappingPresetConfig `yaml:"presets" json:"presets"`
}

// MappingPresetConfig is one built-in mapping platform. Only KeyEnv (the name
// of an environment variable) is stored; plaintext credentials never reach
// the config file or the WebUI.
type MappingPresetConfig struct {
	Platform string `yaml:"platform" json:"platform"` // fofa | hunter | quake
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	KeyEnv   string `yaml:"key_env" json:"key_env"`
	EmailEnv string `yaml:"email_env" json:"email_env"` // FOFA legacy compatibility only
	Query    string `yaml:"query" json:"query"`
	Size     int    `yaml:"size" json:"size"`
	Encoding string `yaml:"encoding" json:"encoding"` // std | url (base64 variant for qbase64/search)
}

// DefaultMappingPresets returns the three built-in, disabled-by-default
// templates. Endpoint/auth/query/pagination/field mapping values are derived
// from the Deadpool v1.8 reference implementation (design facts only).
func DefaultMappingPresets() []MappingPresetConfig {
	return []MappingPresetConfig{
		{
			Platform: "fofa", Enabled: false, KeyEnv: "FOFA_KEY", EmailEnv: "",
			Query: `protocol=="socks5" && country="CN" && banner="Method:No Authentication"`,
			Size:  300, Encoding: "url",
		},
		{
			Platform: "hunter", Enabled: false, KeyEnv: "HUNTER_API_KEY", EmailEnv: "",
			Query: `protocol=="socks5"&&protocol.banner="No authentication"&&ip.country="CN"`,
			Size:  200, Encoding: "url",
		},
		{
			Platform: "quake", Enabled: false, KeyEnv: "QUAKE_TOKEN", EmailEnv: "",
			Query: `service:socks5  AND country: "CN" AND response:"No authentication"`,
			Size:  500, Encoding: "url",
		},
	}
}

// MappingProviderConfig describes one user-defined mapping API provider.
type MappingProviderConfig struct {
	Name       string            `yaml:"name" json:"name"`
	Enabled    bool              `yaml:"enabled" json:"enabled"`
	Endpoint   string            `yaml:"endpoint" json:"endpoint"`
	Method     string            `yaml:"method" json:"method"`
	Auth       MappingAuthConfig `yaml:"auth" json:"auth"`
	QueryParam string            `yaml:"query_param" json:"query_param"`
	Query      string            `yaml:"query" json:"query"`
	// QueryEncoding transforms the raw query before it is placed in params:
	// "" (plain), "std" (base64.StdEncoding) or "url" (base64.URLEncoding).
	QueryEncoding string `yaml:"query_encoding" json:"query_encoding"`
	// BodyTemplate is a JSON request body template for POST APIs. Placeholders:
	// {query} (JSON-escaped), {size}, {start}, {page}, {key}.
	BodyTemplate string            `yaml:"body_template" json:"body_template"`
	ExtraParams  map[string]string `yaml:"extra_params" json:"extra_params"`
	Pagination   PaginationConfig  `yaml:"pagination" json:"pagination"`
	Response     MappingResponse   `yaml:"response" json:"response"`
	// RequestInterval throttles consecutive pages (Hunter needs ~3s).
	RequestInterval string `yaml:"request_interval" json:"request_interval"`
	Interval        string `yaml:"interval" json:"interval"`
	MaxResults      int    `yaml:"max_results" json:"max_results"`
}

// MappingAuthConfig supports query / header / bearer / basic authentication.
// Prefer KeyEnv so secrets stay out of config files and logs.
type MappingAuthConfig struct {
	Type        string `yaml:"type" json:"type"`
	KeyName     string `yaml:"key_name" json:"key_name"`
	KeyEnv      string `yaml:"key_env" json:"key_env"`
	KeyValue    string `yaml:"key_value" json:"-"`
	Username    string `yaml:"username" json:"username"`
	PasswordEnv string `yaml:"password_env" json:"password_env"`
}

// PaginationConfig is optional and entirely user-defined.
type PaginationConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	Param     string `yaml:"param" json:"param"`
	Start     int    `yaml:"start" json:"start"`
	MaxPages  int    `yaml:"max_pages" json:"max_pages"`
	SizeParam string `yaml:"size_param" json:"size_param"`
	Size      int    `yaml:"size" json:"size"`
}

// MappingResponse describes how to extract proxy entries from an API response.
// ResultsPath uses dot notation; numeric segments index arrays, e.g. "data.assets".
type MappingResponse struct {
	Format      string        `yaml:"format" json:"format"`
	ResultsPath string        `yaml:"results_path" json:"results_path"`
	TextPattern string        `yaml:"text_pattern" json:"text_pattern"`
	Fields      MappingFields `yaml:"fields" json:"fields"`
	// ErrorPath / SuccessValue detect platform-level business errors that are
	// returned inside an HTTP 200 body (FOFA error, Quake code, Hunter code).
	ErrorPath    string `yaml:"error_path" json:"error_path"`
	SuccessValue string `yaml:"success_value" json:"success_value"`
	MessagePath  string `yaml:"message_path" json:"message_path"`
}

// MappingFields maps response fields to proxy URI parts. Empty paths mean
// "not configured"; DefaultProtocol is used when the API has no protocol field.
type MappingFields struct {
	Host            string `yaml:"host" json:"host"`
	Port            string `yaml:"port" json:"port"`
	Protocol        string `yaml:"protocol" json:"protocol"`
	Username        string `yaml:"username" json:"username"`
	Password        string `yaml:"password" json:"password"`
	Name            string `yaml:"name" json:"name"`
	DefaultProtocol string `yaml:"default_protocol" json:"default_protocol"`
}

// FreePoolConfig implements the proxy_pool-style free proxy acquisition.
// Built-in fetchers are opt-in (disabled by default) because free sources are
// unreliable and frequently disappear.
type FreePoolConfig struct {
	Enabled     bool                `yaml:"enabled" json:"enabled"`
	Interval    string              `yaml:"interval" json:"interval"`
	Timeout     string              `yaml:"timeout" json:"timeout"`
	Concurrency int                 `yaml:"concurrency" json:"concurrency"`
	MaxResults  int                 `yaml:"max_results" json:"max_results"`
	RatePerMin  int                 `yaml:"rate_limit_per_min" json:"rate_limit_per_min"`
	Fetchers    []FreeFetcherConfig `yaml:"fetchers" json:"fetchers"`
	ExternalAPI ExternalPoolConfig  `yaml:"external_api" json:"external_api"`
}

// FreeFetcherConfig is a declarative equivalent of proxy_pool's BaseFetcher.
type FreeFetcherConfig struct {
	Name        string `yaml:"name" json:"name"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	URL         string `yaml:"url" json:"url"`
	Format      string `yaml:"format" json:"format"`
	JSONPath    string `yaml:"json_path" json:"json_path"`
	TextPattern string `yaml:"text_pattern" json:"text_pattern"`
	Protocol    string `yaml:"protocol" json:"protocol"`
}

// ExternalPoolConfig optionally consumes an already deployed proxy_pool API.
type ExternalPoolConfig struct {
	Enabled   bool   `yaml:"enabled" json:"enabled"`
	BaseURL   string `yaml:"base_url" json:"base_url"`
	GetPath   string `yaml:"get_path" json:"get_path"`
	CountPath string `yaml:"count_path" json:"count_path"`
	Batch     int    `yaml:"batch" json:"batch"`
	Timeout   string `yaml:"timeout" json:"timeout"`
}

// VerificationConfig controls full-dimension verification against public echo
// services. Every target is overridable so no third-party service is mandatory.
type VerificationConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	EchoIPURL       string `yaml:"echo_ip_url" json:"echo_ip_url"`
	EchoHeadersURL  string `yaml:"echo_headers_url" json:"echo_headers_url"`
	EchoDownloadURL string `yaml:"echo_download_url" json:"echo_download_url"`
	RegionURL       string `yaml:"region_url" json:"region_url"`
	RegionDisabled  bool   `yaml:"region_disabled" json:"region_disabled"`
	DirectIPURL     string `yaml:"direct_ip_url" json:"direct_ip_url"`
	Timeout         string `yaml:"timeout" json:"timeout"`
	Concurrency     int    `yaml:"concurrency" json:"concurrency"`
	Retries         int    `yaml:"retries" json:"retries"`
	RetryInterval   string `yaml:"retry_interval" json:"retry_interval"`
	RatePerMin      int    `yaml:"rate_limit_per_min" json:"rate_limit_per_min"`
	MinScore        int    `yaml:"min_score" json:"min_score"`
	RecheckInterval string `yaml:"recheck_interval" json:"recheck_interval"`
	MaxFailures     int    `yaml:"max_failures" json:"max_failures"`
	NoProxy         string `yaml:"no_proxy" json:"no_proxy"`
	// Authenticity proves a mapped candidate really is a forwarding proxy,
	// and MITM detects upstream TLS/content interception. Both are opt-in
	// additions to the existing verification dimensions.
	Authenticity AuthenticityConfig `yaml:"authenticity" json:"authenticity"`
	MITM         MITMConfig         `yaml:"mitm" json:"mitm"`
}

// AuthenticityConfig controls "is this a real proxy" checks.
type AuthenticityConfig struct {
	// Enabled is a pointer so an omitted value defaults to true while an
	// explicit false still disables the checks.
	Enabled *bool `yaml:"enabled" json:"enabled"`
	// RequireExitDiffers: exit IP must differ from the direct (no-proxy) IP.
	RequireExitDiffers bool `yaml:"require_exit_differs" json:"require_exit_differs"`
	// RequireDeclaredMatch: exit IP must equal the IP claimed by the mapping
	// result (only checked when the source supplied a declared IP).
	RequireDeclaredMatch bool `yaml:"require_declared_match" json:"require_declared_match"`
	// CheckURL / ExpectKeyword / ExpectSHA256 detect interception pages,
	// honeypots and fixed injected content. ExpectSHA256 wins when set.
	CheckURL       string `yaml:"check_url" json:"check_url"`
	ExpectKeyword  string `yaml:"expect_keyword" json:"expect_keyword"`
	ExpectSHA256   string `yaml:"expect_sha256" json:"expect_sha256"`
	FollowRedirect bool   `yaml:"follow_redirect" json:"follow_redirect"`
	CheckStatus    bool   `yaml:"check_status" json:"check_status"`
	// Action: "reject" (default), "mark" (tag only), "downgrade" (penalise).
	Action string `yaml:"action" json:"action"`
}

// MITMConfig controls the five-layer malicious-MITM detection.
type MITMConfig struct {
	Enabled *bool `yaml:"enabled" json:"enabled"`
	// ProbeURL must be a trusted HTTPS endpoint reachable both directly and
	// through the candidate proxy; the direct result is the trusted baseline.
	ProbeURL              string   `yaml:"probe_url" json:"probe_url"`
	VerifyCertificate     bool     `yaml:"verify_certificate" json:"verify_certificate"`
	CompareCertBaseline   bool     `yaml:"compare_cert_baseline" json:"compare_cert_baseline"`
	CompareBodyHash       bool     `yaml:"compare_body_hash" json:"compare_body_hash"`
	CheckHeaders          bool     `yaml:"check_headers" json:"check_headers"`
	TrustedFingerprints   []string `yaml:"trusted_fingerprints" json:"trusted_fingerprints"`
	BlacklistIPs          []string `yaml:"blacklist_ips" json:"blacklist_ips"`
	BlacklistFingerprints []string `yaml:"blacklist_fingerprints" json:"blacklist_fingerprints"`
	// Action: "reject" (default), "mark" (tag only), "downgrade" (penalise).
	Action string `yaml:"action" json:"action"`
}

// DefaultAuthenticityConfig returns safe defaults for proxy genuineness.
func boolPtr(v bool) *bool { return &v }

// IsEnabled reports the effective switch. Omitted config defaults to true.
func (c AuthenticityConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// IsEnabled reports the effective switch. Omitted config defaults to true.
func (c MITMConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

func DefaultAuthenticityConfig() AuthenticityConfig {
	return AuthenticityConfig{
		Enabled: boolPtr(true), RequireExitDiffers: true, RequireDeclaredMatch: true,
		CheckURL: "https://www.baidu.com/robots.txt", ExpectKeyword: "Baiduspider",
		FollowRedirect: false, CheckStatus: true, Action: "reject",
	}
}

// DefaultMITMConfig returns safe defaults for malicious-MITM detection.
func DefaultMITMConfig() MITMConfig {
	return MITMConfig{
		Enabled: boolPtr(true), ProbeURL: "https://www.baidu.com/robots.txt",
		VerifyCertificate: true, CompareCertBaseline: true,
		CompareBodyHash: true, CheckHeaders: true, Action: "reject",
	}
}

// ParseDuration parses a Go duration string, falling back to def on empty or
// invalid values. Keeping extension durations as strings avoids depending on
// yaml.v3's duration decoding behaviour.
func ParseDuration(value string, def time.Duration) time.Duration {
	v := strings.TrimSpace(value)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// ClampInt keeps user supplied integers within a safe range.
func ClampInt(value, def, min, max int) int {
	if value <= 0 {
		value = def
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// ResolveMappingKey reads a credential from the environment first, then from
// the explicit (discouraged) config value.
func ResolveMappingKey(auth MappingAuthConfig) string {
	if auth.KeyEnv != "" {
		if v := strings.TrimSpace(os.Getenv(auth.KeyEnv)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(auth.KeyValue)
}

// NoProxyHosts returns the comma separated list of targets that must bypass
// any proxy entirely.
func (c VerificationConfig) NoProxyHosts() []string {
	var out []string
	for _, part := range strings.Split(c.NoProxy, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ValidateExtensionConfig rejects malformed user-supplied configuration before
// it is persisted or applied to the running orchestrator.
func ValidateExtensionConfig(ext ExtensionConfig) error {
	if ext.OutboundProxy != "" {
		u, err := url.Parse(ext.OutboundProxy)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			return fmt.Errorf("extension.outbound_proxy must be http/https/socks5 URL")
		}
	}
	for _, pair := range [][2]string{
		{ext.Mapping.Interval, "mapping.interval"},
		{ext.Mapping.Timeout, "mapping.timeout"},
		{ext.FreePool.Interval, "freepool.interval"},
		{ext.FreePool.Timeout, "freepool.timeout"},
		{ext.FreePool.ExternalAPI.Timeout, "freepool.external_api.timeout"},
		{ext.Verification.Timeout, "verification.timeout"},
		{ext.Verification.RetryInterval, "verification.retry_interval"},
		{ext.Verification.RecheckInterval, "verification.recheck_interval"},
	} {
		value, field := pair[0], pair[1]
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("extension.%s: %w", field, err)
		}
	}

	seen := make(map[string]bool)
	for _, p := range ext.Mapping.Providers {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			return fmt.Errorf("mapping provider name cannot be empty")
		}
		if seen["mapping:"+name] {
			return fmt.Errorf("duplicated mapping provider %q", name)
		}
		seen["mapping:"+name] = true
		if p.Enabled {
			if u, err := url.Parse(p.Endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("mapping provider %q: endpoint must be a valid http(s) URL", name)
			}
		}
		switch strings.ToLower(strings.TrimSpace(p.Auth.Type)) {
		case "", "none", "query", "header", "bearer", "basic":
		default:
			return fmt.Errorf("mapping provider %q: unsupported auth type %q", name, p.Auth.Type)
		}
		switch strings.ToLower(strings.TrimSpace(p.Response.Format)) {
		case "", "json", "text":
		default:
			return fmt.Errorf("mapping provider %q: unsupported response format %q", name, p.Response.Format)
		}
		if strings.TrimSpace(p.Response.TextPattern) != "" {
			if _, err := regexp.Compile(p.Response.TextPattern); err != nil {
				return fmt.Errorf("mapping provider %q: invalid text_pattern: %w", name, err)
			}
		}
		switch strings.ToLower(strings.TrimSpace(p.QueryEncoding)) {
		case "", "std", "url":
		default:
			return fmt.Errorf("mapping provider %q: query_encoding must be empty, std or url", name)
		}
		if strings.TrimSpace(p.BodyTemplate) != "" {
			if _, err := RenderMappingBody(p.BodyTemplate, map[string]string{
				"query": "", "size": "1", "start": "0", "page": "1", "key": "",
			}); err != nil {
				return fmt.Errorf("mapping provider %q: invalid body_template: %w", name, err)
			}
		}
	}
	presetSeen := make(map[string]bool)
	for _, pr := range ext.Mapping.Presets {
		platform := strings.ToLower(strings.TrimSpace(pr.Platform))
		switch platform {
		case "fofa", "hunter", "quake":
		default:
			return fmt.Errorf("unknown mapping preset %q", pr.Platform)
		}
		if presetSeen[platform] {
			return fmt.Errorf("duplicated mapping preset %q", platform)
		}
		presetSeen[platform] = true
		if pr.KeyEnv == "" && pr.Enabled {
			return fmt.Errorf("mapping preset %q: key_env is required when enabled", platform)
		}
		if pr.Size < 1 || pr.Size > 10000 {
			return fmt.Errorf("mapping preset %q: size must be 1..10000", platform)
		}
		switch strings.ToLower(strings.TrimSpace(pr.Encoding)) {
		case "", "std", "url":
		default:
			return fmt.Errorf("mapping preset %q: encoding must be std or url", platform)
		}
	}
	for _, f := range ext.FreePool.Fetchers {
		name := strings.TrimSpace(f.Name)
		if name == "" {
			return fmt.Errorf("free fetcher name cannot be empty")
		}
		if seen["free:"+name] {
			return fmt.Errorf("duplicated free fetcher %q", name)
		}
		seen["free:"+name] = true
		if f.Enabled {
			if u, err := url.Parse(f.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("free fetcher %q: url must be a valid http(s) URL", name)
			}
		}
		switch strings.ToLower(strings.TrimSpace(f.Format)) {
		case "", "text", "json":
		default:
			return fmt.Errorf("free fetcher %q: unsupported format %q", name, f.Format)
		}
	}
	v := ext.Verification
	if v.Concurrency < 0 || v.Concurrency > 1024 || v.Retries < 0 || v.Retries > 20 ||
		v.RatePerMin < 0 || v.RatePerMin > 100000 || v.MinScore < 0 || v.MinScore > 100 ||
		v.MaxFailures < 0 || v.MaxFailures > 100 {
		return fmt.Errorf("verification numeric settings out of range")
	}
	if v.Authenticity.IsEnabled() && strings.TrimSpace(v.Authenticity.CheckURL) != "" {
		if u, err := url.Parse(v.Authenticity.CheckURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("verification.authenticity.check_url must be a valid http(s) URL")
		}
	}
	for _, pair := range [][2]string{
		{v.Authenticity.Action, "verification.authenticity.action"},
		{v.MITM.Action, "verification.mitm.action"},
	} {
		switch strings.ToLower(strings.TrimSpace(pair[0])) {
		case "", "reject", "mark", "downgrade":
		default:
			return fmt.Errorf("%s must be reject, mark or downgrade", pair[1])
		}
	}
	if v.MITM.IsEnabled() && strings.TrimSpace(v.MITM.ProbeURL) != "" {
		// An empty value is filled by verify.New with the safe default, so only
		// validate an explicitly configured target.
		u, err := url.Parse(v.MITM.ProbeURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("verification.mitm.probe_url must be a valid https URL")
		}
	}
	return nil
}

// SanitizeExtensionConfig returns a WebUI-safe copy. Secrets supplied through
// auth.key_value are never returned to the browser; key_env (the name of an
// environment variable) is safe to display.
func SanitizeExtensionConfig(ext ExtensionConfig) ExtensionConfig {
	out := ext
	out.Mapping.Providers = append([]MappingProviderConfig(nil), ext.Mapping.Providers...)
	for i := range out.Mapping.Providers {
		out.Mapping.Providers[i].ExtraParams = copyStringMap(out.Mapping.Providers[i].ExtraParams)
		out.Mapping.Providers[i].Auth.KeyValue = ""
	}
	out.Mapping.Presets = append([]MappingPresetConfig(nil), ext.Mapping.Presets...)
	out.FreePool.Fetchers = append([]FreeFetcherConfig(nil), ext.FreePool.Fetchers...)
	out.Verification.MITM.TrustedFingerprints = append([]string(nil), ext.Verification.MITM.TrustedFingerprints...)
	out.Verification.MITM.BlacklistIPs = append([]string(nil), ext.Verification.MITM.BlacklistIPs...)
	out.Verification.MITM.BlacklistFingerprints = append([]string(nil), ext.Verification.MITM.BlacklistFingerprints...)
	return out
}

// renderBodyTemplate expands a JSON request-body template. {query}/{key} are
// JSON-escaped strings; {size}/{start}/{page} are numeric literals. The result
// is validated so a malformed template is rejected before any request is sent.
func RenderMappingBody(tpl string, values map[string]string) (string, error) {
	quoted := func(v string) string {
		b, _ := json.Marshal(v)
		return string(b)
	}
	num := func(v string) string {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return "0"
		}
		return strconv.Itoa(n)
	}
	body := strings.NewReplacer(
		"{query}", quoted(values["query"]),
		"{key}", quoted(values["key"]),
		"{size}", num(values["size"]),
		"{start}", num(values["start"]),
		"{page}", num(values["page"]),
	).Replace(tpl)
	if !json.Valid([]byte(body)) {
		return "", errors.New("body_template must produce valid JSON")
	}
	return body, nil
}

func copyStringMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// SaveExtensionSettings persists only the extension section. It deliberately
// leaves nodes, subscriptions and core settings untouched, mirroring
// SaveSubscriptionSettings.
func (c *Config) SaveExtensionSettings(ext ExtensionConfig) error {
	if c == nil || c.filePath == "" {
		return errors.New("config file path is unknown")
	}
	if err := ValidateExtensionConfig(ext); err != nil {
		return err
	}
	return updateConfigFile(c.filePath, func(saved *Config) {
		saved.Extension = ext
	})
}
