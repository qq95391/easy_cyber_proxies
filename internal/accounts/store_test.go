package accounts

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"easy_proxies/internal/config"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store := New(path, config.AccountsFile{})
	restore := SetDefault(store)
	t.Cleanup(func() {
		restore()
		config.SetAccountPools(nil)
		config.PublishUserPools(nil)
	})
	return store
}

func TestCreateAuthenticateAndSessionSuffix(t *testing.T) {
	store := testStore(t)
	view, err := store.CreateUser(UserInput{Username: "wang.name", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", view), "secret") {
		t.Fatal("view must never expose a password or hash")
	}
	if _, ok := store.Authenticate("wang.name", "secret", true); !ok {
		t.Fatal("exact credentials must authenticate")
	}
	if session, ok := store.Authenticate("wang.name.s1", "secret", true); !ok || session != "s1" {
		t.Fatalf("session suffix failed: session=%q ok=%v", session, ok)
	}
	if _, ok := store.Authenticate("wang.name.s1", "secret", false); ok {
		t.Fatal("session suffix must be rejected when session routing is disabled")
	}
	if _, ok := store.Authenticate("wang.name", "wrong", true); ok {
		t.Fatal("wrong password must be rejected")
	}
}

func TestOneUserOnePoolAndDeleteGuard(t *testing.T) {
	store := testStore(t)
	if _, err := store.CreatePool(PoolInput{Name: "team-a", Nodes: []string{"n1", "n1", "n2"}, Fallback: "default_pool"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(UserInput{Username: "alice", Password: "pw", Pool: "team-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUser(UserInput{Username: "bob", Password: "pw", Pool: "missing"}); err == nil {
		t.Fatal("a user must not reference a non-existent pool")
	}
	if err := store.DeletePool("team-a"); err == nil {
		t.Fatal("deleting a pool that still owns users must be refused")
	}
	allow, name, matched := config.MatchUserPool("alice")
	if !matched || name != "team-a" || !allow["n1"] || allow["n3"] {
		t.Fatalf("hot-published pool wrong: allow=%v name=%q matched=%v", allow, name, matched)
	}
	pools := store.Pools()
	if len(pools) != 1 || len(pools[0].Nodes) != 2 || pools[0].Fallback != "default_pool" {
		t.Fatalf("pool normalization wrong: %+v", pools)
	}
	if err := store.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeletePool("team-a"); err != nil {
		t.Fatalf("pool should be deletable after its users are gone: %v", err)
	}
}

func TestUpdateRotatesCredentialAndHonoursState(t *testing.T) {
	store := testStore(t)
	if _, err := store.CreateUser(UserInput{Username: "carol", Password: "old"}); err != nil {
		t.Fatal(err)
	}
	disabled := false
	view, err := store.UpdateUser("carol", UserInput{Password: "new", Enabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	if view.CredentialVersion != 2 {
		t.Fatalf("credential version must increment: %d", view.CredentialVersion)
	}
	if _, ok := store.Authenticate("carol", "old", true); ok {
		t.Fatal("old credential must be revoked")
	}
	if _, ok := store.Authenticate("carol", "new", true); ok {
		t.Fatal("disabled user must be rejected")
	}
	enabled := true
	if _, err := store.UpdateUser("carol", UserInput{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Authenticate("carol", "new", true); !ok {
		t.Fatal("re-enabled user must authenticate with the rotated credential")
	}
}

func TestExpiryRejectsNewConnections(t *testing.T) {
	store := testStore(t)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if _, err := store.CreateUser(UserInput{Username: "expired", Password: "pw", ExpiresAt: past}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Authenticate("expired", "pw", true); ok {
		t.Fatal("expired account must be rejected")
	}
}

func TestPersistenceAuditAndCredentialHygiene(t *testing.T) {
	store := testStore(t)
	if _, err := store.CreateUser(UserInput{Username: "dave", Password: "top-secret"}); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.Authenticate("dave", "top-secret", true); !ok {
		t.Fatal("credentials must survive a restart")
	}
	audit := reloaded.Audit()
	if len(audit) == 0 || audit[0].Action != "create_user" {
		t.Fatalf("audit missing: %+v", audit)
	}
	for _, record := range audit {
		if strings.Contains(record.Target+record.Action, "top-secret") {
			t.Fatal("audit leaked a credential")
		}
	}
	for _, view := range reloaded.Users() {
		if strings.Contains(view.Username, "top-secret") {
			t.Fatal("user view leaked a credential")
		}
	}
}

func TestEmptyStoreFallsBackToLegacy(t *testing.T) {
	restore := SetDefault(&Store{})
	defer restore()
	if _, ok := Default().Authenticate("anyone", "any", true); ok {
		t.Fatal("an empty account store must not authenticate anything")
	}
}
