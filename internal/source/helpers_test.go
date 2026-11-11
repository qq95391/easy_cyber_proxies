package source

import (
	"context"
	"testing"

	"easy_proxies/internal/config"
)

func TestExtGetPathWithArrayIndex(t *testing.T) {
	root := map[string]any{
		"results": []any{
			[]any{"1.2.3.4", "8080", "http"},
		},
	}
	if got := asString(getPath(root, "results.0.0")); got != "1.2.3.4" {
		t.Fatalf("host path = %q, want 1.2.3.4", got)
	}
	if got := asString(getPath(root, "results.0.2")); got != "http" {
		t.Fatalf("protocol path = %q, want http", got)
	}
	if getPath(root, "results.9.0") != nil {
		t.Fatal("out of range index should be nil")
	}
}

func TestExtParseHostPort(t *testing.T) {
	host, port, proto, user, pass, ok := parseHostPort("socks5://u:p@127.0.0.1:1080")
	if !ok || host != "127.0.0.1" || port != 1080 || proto != "socks5" || user != "u" || pass != "p" {
		t.Fatalf("unexpected parse: %q %d %q %q %q %v", host, port, proto, user, pass, ok)
	}
	if _, _, _, _, _, ok := parseHostPort("not-a-proxy"); ok {
		t.Fatal("invalid entry accepted")
	}
}

func TestExtSafeLabelAndURI(t *testing.T) {
	if got := safeLabel("机场 节点/01"); got == "" {
		t.Fatal("empty label")
	}
	uri := buildProxyURI("socks5", "127.0.0.1", 1080, "u", "p")
	if uri != "socks5://u:p@127.0.0.1:1080" {
		t.Fatalf("uri = %q", uri)
	}
}

func TestExtMappingProviderJSONArray(t *testing.T) {
	cfg := config.MappingProviderConfig{
		Name: "fixture", Enabled: true, Endpoint: "http://example.invalid/api",
		Response: config.MappingResponse{
			Format: "json", ResultsPath: "results",
			Fields: config.MappingFields{Host: "0", Port: "1", Protocol: "2", DefaultProtocol: "http"},
		},
	}
	p := &MappingProvider{cfg: cfg, global: config.MappingSourcesConfig{Enabled: true}, limiter: NewLimiter(0)}
	body := []byte(`{"results":[["1.2.3.4","8080","http"],["5.6.7.8","1080","socks5"]]}`)
	nodes, err := p.parseResponse(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Source != config.NodeSourceMapping {
		t.Fatalf("unexpected source %q", nodes[0].Source)
	}
}

func TestExtLimiterNoThrottle(t *testing.T) {
	l := NewLimiter(0)
	if err := l.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}
