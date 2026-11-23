package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDedupeKeyUsesEndpointAndProtocol(t *testing.T) {
	cases := []struct{ uri, want string }{
		{"vless://a@Ex.COM:443?type=ws#n1", "ex.com:443|vless"},
		{"vless://b@ex.com:443?type=tcp#n2", "ex.com:443|vless"},
		{"http://ex.com:8080#x", "ex.com:8080|http"},
		{"https://ex.com", "ex.com:443|https"},
		{"socks5://1.2.3.4:1080", "1.2.3.4:1080|socks5"},
		{"socks5://1.2.3.4#no-port", "1.2.3.4:1080|socks5"},
	}
	for _, tc := range cases {
		if got := DedupeKey(tc.uri); got != tc.want {
			t.Fatalf("DedupeKey(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}

	// Same host:port with different protocols must stay distinct.
	if DedupeKey("http://ex.com:443") == DedupeKey("https://ex.com:443") {
		t.Fatal("different protocols on one port must not collapse")
	}
}

func TestDedupeKeyParsesEncodedPayloads(t *testing.T) {
	vmess := base64.RawURLEncoding.EncodeToString([]byte(`{"add":"vm.example.com","port":"8443","id":"x","ps":"n"}`))
	if got := DedupeKey("vmess://" + vmess); got != "vm.example.com:8443|vmess" {
		t.Fatalf("vmess key = %q", got)
	}
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw@ss.example.com:8388"))
	if got := DedupeKey("ss://" + ss); got != "ss.example.com:8388|ss" {
		t.Fatalf("ss key = %q", got)
	}
	if got := DedupeKey("ss://aes-128-gcm:pw@ss.example.com:8388#label"); got != "ss.example.com:8388|ss" {
		t.Fatalf("sip002 ss key = %q", got)
	}
}

func TestDedupeNodesKeepsFirstAndCountsDrops(t *testing.T) {
	nodes := []NodeConfig{
		{URI: "http://a.com:1#first"},
		{URI: "http://a.com:1#second"},
		{URI: "socks5://a.com:1#other-proto"},
	}
	out, dropped := DedupeNodes(nodes)
	if dropped != 1 || len(out) != 2 {
		t.Fatalf("dropped=%d kept=%d", dropped, len(out))
	}
	if !strings.HasSuffix(out[0].URI, "#first") {
		t.Fatalf("first occurrence must win ties: %s", out[0].URI)
	}
}

func TestDedupeNodesPriorityPrefersUsable(t *testing.T) {
	nodes := []NodeConfig{
		{URI: "vless://a@b.com:443#down"},
		{URI: "vless://a@b.com:443#up"},
	}
	out, dropped := DedupeNodesWithPriority(nodes, func(n NodeConfig) bool {
		return strings.HasSuffix(n.URI, "#up")
	})
	if dropped != 1 || len(out) != 1 {
		t.Fatalf("dropped=%d kept=%d", dropped, len(out))
	}
	if !strings.HasSuffix(out[0].URI, "#up") {
		t.Fatalf("usable node must win: %s", out[0].URI)
	}
}
