package config

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const extClashYAML = `proxies:
  - name: s5
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: u
    password: p
  - name: h1
    type: http
    server: 1.2.3.4
    port: 8080
`

func TestExtClashSocks5Mapping(t *testing.T) {
	nodes, err := ParseSubscriptionContent(extClashYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d: %+v", len(nodes), nodes)
	}
	if !strings.HasPrefix(nodes[0].URI, "socks5://u:p@127.0.0.1:1080") {
		t.Fatalf("socks5 mapping missing: %q", nodes[0].URI)
	}
	if !strings.HasPrefix(nodes[1].URI, "http://1.2.3.4:8080") {
		t.Fatalf("http mapping broken: %q", nodes[1].URI)
	}
}

func TestExtBase64WrappedClashYAML(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(extClashYAML))
	nodes, err := ParseSubscriptionContent(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("base64-wrapped Clash YAML lost structure, got %d nodes: %+v", len(nodes), nodes)
	}
	if !strings.HasPrefix(nodes[0].URI, "socks5://") {
		t.Fatalf("first node should be socks5: %q", nodes[0].URI)
	}
}

func TestExtLocalFileSubscription(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub.yaml")
	if err := os.WriteFile(path, []byte(extClashYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	nodes, err := fetchSubscriptionWithClient(context.Background(), nil, path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("local file subscription got %d nodes", len(nodes))
	}
}

func TestExtInlineSubscription(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(extClashYAML))
	nodes, err := fetchSubscriptionWithClient(context.Background(), nil, "inline:"+encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("inline subscription got %d nodes", len(nodes))
	}
}

func TestExtConfigUnmarshal(t *testing.T) {
	raw := `extension:
  enabled: true
  outbound_proxy: "http://127.0.0.1:7897"
  mapping:
    enabled: true
    interval: 6h
    providers:
      - name: fixture
        enabled: true
        endpoint: "https://example.invalid/api"
        auth:
          type: query
          key_name: key
          key_env: MY_MAPPING_KEY
        query_param: q
        query: 'protocol="socks5"'
        pagination:
          enabled: true
          param: page
          max_pages: 2
        response:
          format: json
          results_path: results
          fields:
            host: "0"
            port: "1"
            default_protocol: socks5
  freepool:
    enabled: true
    interval: 5m
    fetchers:
      - name: demo
        enabled: false
        url: ""
        format: text
    external_api:
      enabled: false
      base_url: "http://127.0.0.1:5010"
  verification:
    enabled: true
    timeout: 8s
    retries: 3
    min_score: 40
    no_proxy: "example.com,.internal"
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Extension.Enabled || !cfg.Extension.Mapping.Enabled {
		t.Fatal("extension/mapping not enabled")
	}
	if len(cfg.Extension.Mapping.Providers) != 1 || cfg.Extension.Mapping.Providers[0].Auth.KeyEnv != "MY_MAPPING_KEY" {
		t.Fatalf("provider mapping broken: %+v", cfg.Extension.Mapping.Providers)
	}
	if cfg.Extension.Mapping.Providers[0].Response.Fields.DefaultProtocol != "socks5" {
		t.Fatal("field mapping broken")
	}
	if len(cfg.Extension.Verification.NoProxyHosts()) != 2 {
		t.Fatalf("no_proxy parsing broken: %+v", cfg.Extension.Verification.NoProxyHosts())
	}
	if ParseDuration("6h", time.Hour) != 6*time.Hour {
		t.Fatal("duration parsing broken")
	}
	if ParseDuration("bogus", time.Hour) != time.Hour {
		t.Fatal("invalid duration should fall back to default")
	}
}
