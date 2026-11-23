package ext

import (
	"testing"

	"easy_proxies/internal/config"
)

type fakeRuntime struct {
	cfg     *config.Config
	reloads int
}

func (f *fakeRuntime) CurrentConfig() *config.Config { return f.cfg }

func (f *fakeRuntime) CurrentPortMap() map[string]uint16 { return nil }

func (f *fakeRuntime) ReloadWithPortMap(next *config.Config, _ map[string]uint16) error {
	f.reloads++
	f.cfg = next
	return nil
}

func inlineNode(uri string) config.NodeConfig {
	return config.NodeConfig{Name: "inline", URI: uri, Source: config.NodeSourceInline}
}

func extNode(uri string) config.NodeConfig {
	return config.NodeConfig{Name: "ext", URI: uri, Source: config.NodeSourceFreePool}
}

func TestApplyToRuntimeSkipsUnchangedNodeSet(t *testing.T) {
	ext := extNode("http://1.2.3.4:8080")
	rt := &fakeRuntime{cfg: &config.Config{Nodes: []config.NodeConfig{inlineNode("http://9.9.9.9:8080"), ext}}}

	o := &Orchestrator{}
	if err := o.applyToRuntime(rt, []config.NodeConfig{ext}); err != nil {
		t.Fatal(err)
	}
	if rt.reloads != 0 {
		t.Fatalf("unchanged node set must not reload, got %d reload(s)", rt.reloads)
	}
}

func TestApplyToRuntimeReloadsOnChangedNodeSet(t *testing.T) {
	rt := &fakeRuntime{cfg: &config.Config{Nodes: []config.NodeConfig{
		inlineNode("http://9.9.9.9:8080"), extNode("http://1.2.3.4:8080"),
	}}}

	o := &Orchestrator{}
	if err := o.applyToRuntime(rt, []config.NodeConfig{extNode("http://5.6.7.8:8080")}); err != nil {
		t.Fatal(err)
	}
	if rt.reloads != 1 {
		t.Fatalf("changed node set must reload once, got %d", rt.reloads)
	}
}

func TestApplyToRuntimeReloadsOnCredentialRotation(t *testing.T) {
	rt := &fakeRuntime{cfg: &config.Config{Nodes: []config.NodeConfig{
		extNode("vless://uuid-a@h.example.com:443?type=ws"),
	}}}

	o := &Orchestrator{}
	if err := o.applyToRuntime(rt, []config.NodeConfig{
		extNode("vless://uuid-b@h.example.com:443?type=ws"),
	}); err != nil {
		t.Fatal(err)
	}
	if rt.reloads != 1 {
		t.Fatalf("credential rotation must reload once, got %d", rt.reloads)
	}
}

func TestSameNodeSetIgnoresOrderAndDisplayNames(t *testing.T) {
	a := []config.NodeConfig{
		{URI: "http://1.2.3.4:8080#first"},
		{URI: "socks5://1.2.3.4:1080#second"},
	}
	b := []config.NodeConfig{
		{URI: "socks5://1.2.3.4:1080#renamed"},
		{URI: "http://1.2.3.4:8080#also-renamed"},
	}
	if !sameNodeSet(a, b) {
		t.Fatal("order and display names must not matter")
	}
	if sameNodeSet(a, b[:1]) {
		t.Fatal("different cardinality must not compare equal")
	}
}
