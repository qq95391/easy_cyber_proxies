package monitor

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"easy_proxies/internal/config"
)

// The legacy mode switch is gone: dual-stack is fixed, so a saved mode must be
// normalized away instead of silently selecting a topology.
func TestSettingsIgnoreLegacyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("mode: pool\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := proxySessionTestConfig()
	cfg.SetFilePath(path)
	s, _ := newProxySessionTestServer(t, cfg)

	body := `{"mode":"multi-port","listener":{"address":"0.0.0.0","port":2323,"username":"wang","password":"1234"}}`
	resp := proxyAPIRequest(t, s, http.MethodPut, "/api/settings", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT settings status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = proxyAPIRequest(t, s, http.MethodGet, "/api/settings", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET settings status=%d", resp.Code)
	}
	var payload struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Mode != config.ModeDualStack {
		t.Fatalf("mode = %q, want %q", payload.Mode, config.ModeDualStack)
	}
}
