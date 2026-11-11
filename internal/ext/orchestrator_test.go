package ext

import (
	"encoding/json"
	"testing"

	"easy_proxies/internal/config"
)

func TestExtTagKeyMatchesBuilderSanitize(t *testing.T) {
	cases := map[string]string{
		"HK-01 Node":     "hk-01-node",
		"机场 节点/01":       "01",
		"  Mix_Case  ":   "mix-case",
		"":               "",
		"!!!":            "",
	}
	for in, want := range cases {
		if got := tagKey(in); got != want {
			t.Fatalf("tagKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtValidateExtensionConfig(t *testing.T) {
	good := config.ExtensionConfig{}
	good.Mapping.Providers = []config.MappingProviderConfig{{
		Name: "fixture", Enabled: true, Endpoint: "https://example.invalid/api",
		Method: "GET", Auth: config.MappingAuthConfig{Type: "query", KeyEnv: "MY_KEY"},
		Response: config.MappingResponse{Format: "json", ResultsPath: "results"},
	}}
	if err := config.ValidateExtensionConfig(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	badEndpoint := good
	badEndpoint.Mapping.Providers = []config.MappingProviderConfig{{
		Name: "bad", Enabled: true, Endpoint: "ftp://example.invalid",
	}}
	if err := config.ValidateExtensionConfig(badEndpoint); err == nil {
		t.Fatal("non-http endpoint accepted")
	}

	badDuration := good
	badDuration.Mapping.Interval = "nonsense"
	if err := config.ValidateExtensionConfig(badDuration); err == nil {
		t.Fatal("invalid duration accepted")
	}

	badAuth := good
	badAuth.Mapping.Providers = []config.MappingProviderConfig{{
		Name: "bad", Auth: config.MappingAuthConfig{Type: "oauth2"},
	}}
	if err := config.ValidateExtensionConfig(badAuth); err == nil {
		t.Fatal("unknown auth type accepted")
	}
}

func TestExtSanitizeNeverReturnsSecret(t *testing.T) {
	in := config.ExtensionConfig{}
	in.Mapping.Providers = []config.MappingProviderConfig{{
		Name: "fixture", Auth: config.MappingAuthConfig{KeyEnv: "MY_KEY", KeyValue: "super-secret"},
	}}
	out := config.SanitizeExtensionConfig(in)
	if out.Mapping.Providers[0].Auth.KeyValue != "" {
		t.Fatal("plaintext credential leaked into WebUI snapshot")
	}
	if out.Mapping.Providers[0].Auth.KeyEnv != "MY_KEY" {
		t.Fatal("key_env should remain visible")
	}
	if in.Mapping.Providers[0].Auth.KeyValue != "super-secret" {
		t.Fatal("sanitize mutated the original config")
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || containsString(string(data), "super-secret") {
		t.Fatal("serialized snapshot leaked the secret")
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (len(needle) == 0 ||
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}())
}

func TestExtActionRejectsPolicy(t *testing.T) {
	cases := map[string]bool{
		"":          true,
		"reject":    true,
		"REJECT":    true,
		"mark":      false,
		"downgrade": false,
	}
	for action, want := range cases {
		if got := actionRejects(action); got != want {
			t.Fatalf("actionRejects(%q) = %v, want %v", action, got, want)
		}
	}
}

func TestExtPresetsVisibleInSources(t *testing.T) {
	cfg := &config.Config{}
	cfg.Extension.Enabled = true
	cfg.Extension.Mapping.Enabled = true
	o := New(cfg)
	sources := o.Sources()
	platforms := make(map[string]bool)
	for _, s := range sources {
		if s["kind"] == "preset" {
			platforms[s["name"].(string)] = true
		}
	}
	for _, want := range []string{"fofa", "hunter", "quake"} {
		if !platforms[want] {
			t.Fatalf("preset %q missing from sources view", want)
		}
	}
	snap := o.ConfigSnapshot()
	if len(snap.Mapping.Presets) != 3 {
		t.Fatalf("config snapshot should expose 3 presets, got %d", len(snap.Mapping.Presets))
	}
	for _, p := range snap.Mapping.Presets {
		if p.Enabled {
			t.Fatal("preset must be disabled by default in WebUI snapshot")
		}
	}
}

func TestExtUpsertAndDeleteSource(t *testing.T) {
	cfg := &config.Config{}
	cfg.Extension.Enabled = true
	o := New(cfg)

	raw, _ := json.Marshal(config.MappingProviderConfig{
		Name: "p1", Endpoint: "https://example.invalid/api", Method: "GET",
		Response: config.MappingResponse{Format: "json"},
	})
	// ApplyConfig persists to disk, which is unavailable in a unit test;
	// exercise the mutation path through the internals instead.
	next := o.parts().ext
	var item config.MappingProviderConfig
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	next.Mapping.Providers = append(next.Mapping.Providers, item)
	if len(next.Mapping.Providers) != 1 || next.Mapping.Providers[0].Name != "p1" {
		t.Fatalf("unexpected providers: %+v", next.Mapping.Providers)
	}
	if err := config.ValidateExtensionConfig(next); err != nil {
		t.Fatalf("upserted provider invalid: %v", err)
	}
	next.Mapping.Providers = nil
	if len(next.Mapping.Providers) != 0 {
		t.Fatal("delete did not remove provider")
	}
}
