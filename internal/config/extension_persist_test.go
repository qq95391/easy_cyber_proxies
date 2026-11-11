package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtSaveExtensionSettingsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := `mode: pool
listener:
  address: 0.0.0.0
  port: 2323
  username: user
  password: pass
management:
  enabled: true
  listen: 0.0.0.0:9091
  password: ""
subscriptions:
  - inline:aGVsbG8=
nodes:
  - uri: "http://127.0.0.1:1#seed"
extension:
  enabled: false
  verification:
    enabled: false
    min_score: 10
`
	if err := os.WriteFile(path, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Nodes) != 1 || len(cfg.Subscriptions) != 1 {
		t.Fatalf("baseline config changed: nodes=%d subs=%d", len(cfg.Nodes), len(cfg.Subscriptions))
	}

	next := cfg.Extension
	next.Enabled = true
	next.OutboundProxy = "http://127.0.0.1:7897"
	next.Verification.Enabled = true
	next.Verification.MinScore = 55
	next.Mapping.Providers = []MappingProviderConfig{{
		Name: "fixture", Enabled: true, Endpoint: "https://example.invalid/api",
		Method: "GET", Auth: MappingAuthConfig{Type: "query", KeyEnv: "MY_KEY"},
		Response: MappingResponse{Format: "json", ResultsPath: "results"},
	}}
	if err := cfg.SaveExtensionSettings(next); err != nil {
		t.Fatal(err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Extension.Enabled || reloaded.Extension.OutboundProxy != "http://127.0.0.1:7897" {
		t.Fatalf("extension section not persisted: %+v", reloaded.Extension)
	}
	if reloaded.Extension.Verification.MinScore != 55 || len(reloaded.Extension.Mapping.Providers) != 1 {
		t.Fatalf("nested extension fields lost: %+v", reloaded.Extension)
	}
	if len(reloaded.Nodes) != 1 || len(reloaded.Subscriptions) != 1 {
		t.Fatalf("unrelated sections were damaged: nodes=%d subs=%d", len(reloaded.Nodes), len(reloaded.Subscriptions))
	}
	if reloaded.Listener.Username != "user" {
		t.Fatal("listener settings damaged")
	}
}
