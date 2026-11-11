package monitor

import (
	"net/http"
	"testing"

	"easy_proxies/internal/config"
)

func TestExtUserPoolsAPI(t *testing.T) {
	config.SetUserPools(nil)
	t.Cleanup(func() { config.SetUserPools(nil) })

	cfg, path := loadProxySettingsFixture(t)
	s, _ := newProxySessionTestServer(t, cfg)

	resp := proxyAPIRequest(t, s, http.MethodGet, "/api/pool/user-pools", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", resp.Code, resp.Body.String())
	}
	decoded := decodeProxyResponse(t, resp)
	if pools, ok := decoded["pools"].([]any); ok && len(pools) != 0 {
		t.Fatalf("expected no pools initially, got %v", pools)
	}

	body := `{"pools":[` +
		`{"name":"A","users":["alice"],"nodes":["n1","n2","n3"]},` +
		`{"name":"B","users":["bob"],"nodes":["n1","n2","n3","n4","n5"]}]}`
	resp = proxyAPIRequest(t, s, http.MethodPut, "/api/pool/user-pools", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", resp.Code, resp.Body.String())
	}

	allow, name, matched := config.MatchUserPool("alice")
	if !matched || name != "A" || len(allow) != 3 {
		t.Fatalf("A pool not published: matched=%v name=%q allow=%v", matched, name, allow)
	}
	allow, name, matched = config.MatchUserPool("bob")
	if !matched || name != "B" || len(allow) != 5 {
		t.Fatalf("B pool not published: matched=%v name=%q allow=%v", matched, name, allow)
	}

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Pool.UserPools) != 2 {
		t.Fatalf("pools not persisted: %+v", loaded.Pool.UserPools)
	}
	if loaded.Pool.UserPools[0].Name != "A" || len(loaded.Pool.UserPools[0].Nodes) != 3 {
		t.Fatalf("persisted pool A wrong: %+v", loaded.Pool.UserPools[0])
	}
}

func TestExtUserPoolsRejectsDuplicateNames(t *testing.T) {
	config.SetUserPools(nil)
	t.Cleanup(func() { config.SetUserPools(nil) })

	cfg, _ := loadProxySettingsFixture(t)
	s, _ := newProxySessionTestServer(t, cfg)

	resp := proxyAPIRequest(t, s, http.MethodPut, "/api/pool/user-pools",
		`{"pools":[{"name":"A","users":["x"]},{"name":"A","users":["y"]}]}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("duplicate names status=%d body=%s", resp.Code, resp.Body.String())
	}
	if len(config.LoadUserPools()) != 0 {
		t.Fatal("rejected request must not publish pools")
	}
}
