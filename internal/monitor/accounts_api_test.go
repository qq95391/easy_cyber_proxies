package monitor

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"easy_proxies/internal/accounts"
	"easy_proxies/internal/config"
)

func TestAccountsCRUDAPIWorkChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store := accounts.New(path, config.AccountsFile{})
	restore := accounts.SetDefault(store)
	t.Cleanup(func() {
		restore()
		config.SetAccountPools(nil)
		config.PublishUserPools(nil)
	})
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())

	resp := proxyAPIRequest(t, s, http.MethodPost, "/api/accounts/pools",
		`{"name":"team-a","nodes":["n1","n2"],"fallback":"none"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("create pool status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = proxyAPIRequest(t, s, http.MethodPost, "/api/accounts/users",
		`{"username":"alice","password":"pw","pool":"team-a"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("create user status=%d body=%s", resp.Code, resp.Body.String())
	}

	resp = proxyAPIRequest(t, s, http.MethodGet, "/api/accounts", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("overview status=%d", resp.Code)
	}
	var overview struct {
		Users []map[string]any `json:"users"`
		Pools []map[string]any `json:"pools"`
		Audit []map[string]any `json:"audit"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if len(overview.Users) != 1 || len(overview.Pools) != 1 || len(overview.Audit) < 2 {
		t.Fatalf("overview incomplete: %+v", overview)
	}
	if strings.Contains(resp.Body.String(), "password_hash") || strings.Contains(resp.Body.String(), `"pw"`) {
		t.Fatal("overview leaked a credential")
	}

	resp = proxyAPIRequest(t, s, http.MethodDelete, "/api/accounts/pools/team-a", "")
	if resp.Code == http.StatusOK {
		t.Fatal("deleting a pool that still owns users must be refused")
	}
	resp = proxyAPIRequest(t, s, http.MethodPut, "/api/accounts/users/alice",
		`{"password":"rotated","pool":"team-a"}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("update user status=%d body=%s", resp.Code, resp.Body.String())
	}
	if _, ok := store.Authenticate("alice", "rotated", true); !ok {
		t.Fatal("rotated credential did not take effect immediately")
	}
	resp = proxyAPIRequest(t, s, http.MethodDelete, "/api/accounts/users/alice", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("delete user status=%d body=%s", resp.Code, resp.Body.String())
	}
	resp = proxyAPIRequest(t, s, http.MethodDelete, "/api/accounts/pools/team-a", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("delete pool after user removal status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAccountsEditAPIUpdatesPoolsAndQuotas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store := accounts.New(path, config.AccountsFile{})
	restore := accounts.SetDefault(store)
	t.Cleanup(func() {
		restore()
		config.SetAccountPools(nil)
		config.PublishUserPools(nil)
	})
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())

	if resp := proxyAPIRequest(t, s, http.MethodPost, "/api/accounts/pools",
		`{"name":"team-a","nodes":["n1"],"fallback":"none"}`); resp.Code != http.StatusOK {
		t.Fatalf("create pool: %d %s", resp.Code, resp.Body.String())
	}
	if resp := proxyAPIRequest(t, s, http.MethodPut, "/api/accounts/pools/team-a",
		`{"name":"team-a","nodes":["n1","n2"],"fallback":"default_pool","enabled":false,"note":"edge"}`); resp.Code != http.StatusOK {
		t.Fatalf("edit pool: %d %s", resp.Code, resp.Body.String())
	}
	if resp := proxyAPIRequest(t, s, http.MethodPost, "/api/accounts/users",
		`{"username":"alice","password":"pw","pool":"team-a","max_sessions":5,"max_conns":2,"note":"first"}`); resp.Code != http.StatusOK {
		t.Fatalf("create user: %d %s", resp.Code, resp.Body.String())
	}
	if resp := proxyAPIRequest(t, s, http.MethodPut, "/api/accounts/users/alice",
		`{"display_name":"Alice","pool":"team-a","max_sessions":8,"max_conns":4,"note":"edited","enabled":true}`); resp.Code != http.StatusOK {
		t.Fatalf("edit user: %d %s", resp.Code, resp.Body.String())
	}
	resp := proxyAPIRequest(t, s, http.MethodGet, "/api/accounts", "")
	var overview struct {
		Users []map[string]any `json:"users"`
		Pools []map[string]any `json:"pools"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if len(overview.Pools) != 1 || len(overview.Users) != 1 {
		t.Fatalf("unexpected overview: %+v", overview)
	}
	pool, user := overview.Pools[0], overview.Users[0]
	if pool["fallback"] != "default_pool" || pool["enabled"] != false || pool["note"] != "edge" {
		t.Fatalf("pool edit lost: %+v", pool)
	}
	if nodes, ok := pool["nodes"].([]any); !ok || len(nodes) != 2 {
		t.Fatalf("pool nodes not updated: %+v", pool)
	}
	if user["max_sessions"] != float64(8) || user["max_conns"] != float64(4) || user["note"] != "edited" {
		t.Fatalf("user quota edit lost: %+v", user)
	}
	if _, ok := store.Authenticate("alice", "pw", true); !ok {
		t.Fatal("editing without a password must keep the credential valid")
	}
}

func TestAccountsAPIRejectsInvalidInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store := accounts.New(path, config.AccountsFile{})
	restore := accounts.SetDefault(store)
	t.Cleanup(func() {
		restore()
		config.SetAccountPools(nil)
		config.PublishUserPools(nil)
	})
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())

	for _, body := range []string{
		`{"username":"","password":"pw"}`,
		`{"username":"ok","password":""}`,
		`{"username":"ok","password":"pw","pool":"missing"}`,
		`{"username":"ok","password":"pw","expires_at":"not-a-date"}`,
	} {
		resp := proxyAPIRequest(t, s, http.MethodPost, "/api/accounts/users", body)
		if resp.Code == http.StatusOK {
			t.Fatalf("invalid input accepted: %s", body)
		}
	}
}
