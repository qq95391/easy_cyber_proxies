package monitor

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"easy_proxies/internal/config"

	"gopkg.in/yaml.v3"
)

func TestSettingsExposeResilienceFields(t *testing.T) {
	cfg := proxySessionTestConfig()
	cfg.Pool.SwitchBudget = 4 * time.Second
	cfg.Pool.DialTimeout = 2 * time.Second
	cfg.Pool.HealthInterval = 30 * time.Second
	cfg.Pool.Fallback = "default_pool"
	disabled := false
	cfg.Pool.EnableCircuitBreaker = &disabled
	s, _ := newProxySessionTestServer(t, cfg)

	resp := proxyAPIRequest(t, s, http.MethodGet, "/api/settings", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET settings status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Pool map[string]any `json:"pool"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"switch_budget": "4s", "dial_timeout": "2s", "health_interval": "30s",
		"fallback": "default_pool", "enable_circuit_breaker": false,
	}
	for key, value := range want {
		if payload.Pool[key] != value {
			t.Fatalf("%s = %v, want %v", key, payload.Pool[key], value)
		}
	}
}

const resilienceSettingsBody = `{"mode":"pool","listener":{"address":"0.0.0.0","port":2323,"username":"wang","password":"1234"},"pool":{"mode":"sequential","failure_threshold":3,"blacklist_duration":"24h","transient_cooldown":"60s","rate_limit_cooldown":"60s","blacklist_failed_pin":true,"switch_budget":"3s","dial_timeout":"0s","health_interval":"5m","fallback":"none","enable_circuit_breaker":true}}`

func TestSettingsRejectInvalidResilienceValues(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	cases := map[string]string{
		"fallback":        strings.Replace(resilienceSettingsBody, `"fallback":"none"`, `"fallback":"bogus"`, 1),
		"switch_budget":   strings.Replace(resilienceSettingsBody, `"switch_budget":"3s"`, `"switch_budget":"abc"`, 1),
		"health_interval": strings.Replace(resilienceSettingsBody, `"health_interval":"5m"`, `"health_interval":"0s"`, 1),
		"dial_timeout":    strings.Replace(resilienceSettingsBody, `"dial_timeout":"0s"`, `"dial_timeout":"-1s"`, 1),
	}
	for name, body := range cases {
		resp := proxyAPIRequest(t, s, http.MethodPut, "/api/settings", body)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d body=%s", name, resp.Code, resp.Body.String())
		}
	}
}

func TestSettingsPersistResilienceFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("mode: pool\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := proxySessionTestConfig()
	cfg.SetFilePath(path)
	s, _ := newProxySessionTestServer(t, cfg)

	body := strings.Replace(resilienceSettingsBody, `"switch_budget":"3s"`, `"switch_budget":"4s"`, 1)
	body = strings.Replace(body, `"health_interval":"5m"`, `"health_interval":"30s"`, 1)
	body = strings.Replace(body, `"fallback":"none"`, `"fallback":"default_pool"`, 1)
	resp := proxyAPIRequest(t, s, http.MethodPut, "/api/settings", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT settings status=%d body=%s", resp.Code, resp.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved config.Config
	if err := yaml.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode saved config: %v\n%s", err, data)
	}
	if saved.Pool.SwitchBudget != 4*time.Second || saved.Pool.HealthInterval != 30*time.Second {
		t.Fatalf("resilience deadlines not persisted: %+v", saved.Pool)
	}
	if saved.Pool.FallbackOrDefault() != "default_pool" {
		t.Fatalf("fallback not persisted: %q", saved.Pool.FallbackOrDefault())
	}
}
