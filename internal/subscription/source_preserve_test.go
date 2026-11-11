package subscription

import (
	"testing"

	"easy_proxies/internal/config"
)

// A subscription refresh must replace only its own slice. Inline, nodes_file
// and extension-sourced nodes are owned elsewhere and used to be dropped,
// which removed mapping/freepool nodes until the next extension publication.
func TestExtCreateConfigPreservesNonSubscriptionSources(t *testing.T) {
	base := &config.Config{Nodes: []config.NodeConfig{
		{Name: "inline-1", URI: "http://127.0.0.1:1", Source: config.NodeSourceInline},
		{Name: "file-1", URI: "http://127.0.0.1:2", Source: config.NodeSourceFile},
		{Name: "map-1", URI: "socks5://127.0.0.1:3", Source: config.NodeSourceMapping},
		{Name: "free-1", URI: "http://127.0.0.1:4", Source: config.NodeSourceFreePool},
		{Name: "stale-sub", URI: "http://127.0.0.1:5", Source: config.NodeSourceSubscription},
	}}
	fresh := []config.NodeConfig{
		{Name: "new-sub", URI: "http://127.0.0.1:6"},
	}

	got := createConfig(base, fresh)

	want := map[string]config.NodeSource{
		"inline-1": config.NodeSourceInline,
		"file-1":   config.NodeSourceFile,
		"map-1":    config.NodeSourceMapping,
		"free-1":   config.NodeSourceFreePool,
		"new-sub":  config.NodeSourceSubscription,
	}
	seen := make(map[string]config.NodeSource, len(got.Nodes))
	for _, n := range got.Nodes {
		if _, dup := seen[n.Name]; dup {
			t.Fatalf("duplicated node %q after refresh", n.Name)
		}
		seen[n.Name] = n.Source
	}
	for name, source := range want {
		actual, ok := seen[name]
		if !ok {
			t.Fatalf("node %q was dropped by subscription refresh", name)
		}
		if actual != source {
			t.Fatalf("node %q source = %q, want %q", name, actual, source)
		}
	}
	if _, ok := seen["stale-sub"]; ok {
		t.Fatal("stale subscription node was not replaced")
	}
}

// The nodes file written back to disk must still contain only the freshly
// fetched subscription nodes, not the preserved extension nodes.
func TestExtCreateConfigKeepsSubscriptionCacheSemantics(t *testing.T) {
	base := &config.Config{Nodes: []config.NodeConfig{
		{Name: "map-1", URI: "socks5://127.0.0.1:3", Source: config.NodeSourceMapping},
	}}
	got := createConfig(base, []config.NodeConfig{{Name: "sub-1", URI: "http://127.0.0.1:9"}})

	var subscriptionNodes int
	for _, n := range got.Nodes {
		if n.Source == config.NodeSourceSubscription {
			subscriptionNodes++
		}
	}
	if subscriptionNodes != 1 {
		t.Fatalf("subscription nodes = %d, want 1", subscriptionNodes)
	}
	if len(got.Nodes) != 2 {
		t.Fatalf("total nodes = %d, want 2 (1 preserved + 1 subscription)", len(got.Nodes))
	}
}
