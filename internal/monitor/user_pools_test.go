package monitor

import (
	"net/http"
	"testing"

	"easy_proxies/internal/config"
)

// The legacy config.yaml user_pools writer is retired. The endpoint stays as a
// read-only compatibility shim so old bookmarks/scripts get a clear 410 instead
// of a confusing 404, while account-owned pools keep working.
func TestLegacyUserPoolsWriterIsRetired(t *testing.T) {
	config.SetUserPools(nil)
	config.SetAccountPools(nil)
	t.Cleanup(func() {
		config.SetAccountPools(nil)
		config.PublishUserPools(nil)
	})

	cfg, _ := loadProxySettingsFixture(t)
	s, _ := newProxySessionTestServer(t, cfg)

	resp := proxyAPIRequest(t, s, http.MethodGet, "/api/pool/user-pools", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", resp.Code, resp.Body.String())
	}
	decoded := decodeProxyResponse(t, resp)
	if decoded["deprecated"] != true {
		t.Fatalf("GET must advertise deprecation: %+v", decoded)
	}
	if pools, ok := decoded["pools"].([]any); !ok || len(pools) != 0 {
		t.Fatalf("GET must return an empty legacy pool list: %+v", decoded)
	}

	body := `{"pools":[{"name":"A","users":["alice"],"nodes":["n1","n2"]}]}`
	resp = proxyAPIRequest(t, s, http.MethodPut, "/api/pool/user-pools", body)
	if resp.Code != http.StatusGone {
		t.Fatalf("PUT must be rejected with 410, got %d body=%s", resp.Code, resp.Body.String())
	}
	if len(config.LoadUserPools()) != 0 {
		t.Fatal("retired writer must not publish legacy pools")
	}
}

func TestAccountPoolsSurviveLegacyWriterRetirement(t *testing.T) {
	config.SetUserPools(nil)
	config.SetAccountPools([]config.UserPoolConfig{
		{Name: "accounts", Users: []string{"alice"}, Nodes: []string{"n1"}},
	})
	t.Cleanup(func() {
		config.SetAccountPools(nil)
		config.PublishUserPools(nil)
	})

	// A core rebuild must not drop account-owned pools.
	config.PublishUserPools(nil)
	allow, name, matched := config.MatchUserPool("alice")
	if !matched || name != "accounts" || !allow["n1"] || allow["n2"] {
		t.Fatalf("account pool lost after rebuild: allow=%v name=%q matched=%v", allow, name, matched)
	}

	cfg, _ := loadProxySettingsFixture(t)
	s, _ := newProxySessionTestServer(t, cfg)
	if resp := proxyAPIRequest(t, s, http.MethodPut, "/api/pool/user-pools", `{"pools":[]}`); resp.Code != http.StatusGone {
		t.Fatalf("PUT status=%d", resp.Code)
	}
	if _, _, matched := config.MatchUserPool("alice"); !matched {
		t.Fatal("legacy writer must not disturb account-owned pools")
	}
}
