package builder

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"easy_proxies/internal/config"
)

func dualStackConfig(nodes []config.NodeConfig, fallback string) *config.Config {
	return &config.Config{
		// A legacy value must be ignored: dual-stack is fixed.
		LogLevel:  "error",
		Listener:  config.ListenerConfig{Address: "127.0.0.1", Port: 2323},
		MultiPort: config.MultiPortConfig{Address: "127.0.0.1", BasePort: 24000},
		Pool:      config.PoolConfig{Mode: "sequential", Fallback: fallback},
		Nodes:     nodes,
	}
}

func TestNormalizeForcesDualStack(t *testing.T) {
	cfg := dualStackConfig([]config.NodeConfig{{Name: "one", URI: "http://127.0.0.1:8080"}}, "")
	if err := cfg.NormalizeWithPortMap(nil); err != nil {
		t.Fatal(err)
	}
	if cfg.Nodes[0].Port == 0 {
		t.Fatal("per-node port must be assigned in dual-stack")
	}
}

func TestBuildAlwaysEnablesPoolAndPerNodeInbounds(t *testing.T) {
	cfg := dualStackConfig([]config.NodeConfig{{Name: "one", URI: "http://127.0.0.1:8080"}}, "")
	if err := cfg.NormalizeWithPortMap(nil); err != nil {
		t.Fatal(err)
	}
	opts, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var poolEntry, perNode bool
	for _, in := range opts.Inbounds {
		if in.Type != C.TypeMixed {
			continue
		}
		if mixed, ok := in.Options.(*option.HTTPMixedInboundOptions); ok && mixed.ListenPort == cfg.Nodes[0].Port {
			perNode = true
			continue
		}
		poolEntry = true
	}
	if !perNode {
		t.Fatalf("per-node inbound missing: %+v", opts.Inbounds)
	}
	if !poolEntry {
		t.Fatalf("shared pool inbound missing: %+v", opts.Inbounds)
	}
}

func TestEmptyPoolWithDirectFallbackBootsDirect(t *testing.T) {
	cfg := dualStackConfig(nil, "direct")
	if err := cfg.NormalizeWithPortMap(nil); err != nil {
		t.Fatalf("empty pool must be legal with fallback=direct: %v", err)
	}
	opts, err := Build(cfg)
	if err != nil {
		t.Fatalf("build must fall back to direct: %v", err)
	}
	if opts.Route == nil || opts.Route.Final != "direct" {
		t.Fatalf("route final = %+v", opts.Route)
	}
	foundDirect := false
	for _, ob := range opts.Outbounds {
		if ob.Type == C.TypeDirect && ob.Tag == "direct" {
			foundDirect = true
		}
	}
	if !foundDirect {
		t.Fatalf("direct outbound missing: %+v", opts.Outbounds)
	}
}

func TestEmptyPoolWithoutDirectFallbackStillFails(t *testing.T) {
	cfg := dualStackConfig(nil, "none")
	if err := cfg.NormalizeWithPortMap(nil); err == nil {
		t.Fatal("empty pool without fallback=direct must be rejected")
	}
}
