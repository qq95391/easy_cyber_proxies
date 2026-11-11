package pool

import (
	"strings"
	"testing"
	"time"

	"easy_proxies/internal/config"

	N "github.com/sagernet/sing/common/network"
)

func newUserPoolTestPool(t *testing.T, tags ...string) *poolOutbound {
	t.Helper()
	nodes := make([]*sessionTestOutbound, 0, len(tags))
	for _, tag := range tags {
		nodes = append(nodes, newSessionTestOutbound(tag))
	}
	return newSessionTestPool(nil, nodes...)
}

func TestExtUserPoolRestrictsSelection(t *testing.T) {
	config.SetUserPools(nil)
	t.Cleanup(func() { config.SetUserPools(nil) })
	config.SetUserPools([]config.UserPoolConfig{
		{Name: "A", Users: []string{"alice"}, Nodes: []string{"n1", "n2", "n3"}},
		{Name: "B", Users: []string{"bob"}, Nodes: []string{"n4", "n5", "n6", "n7", "n8"}},
	})

	p := newUserPoolTestPool(t, "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8")
	allowedA := map[string]bool{"n1": true, "n2": true, "n3": true}
	for i := 0; i < 30; i++ {
		member, err := p.pickMemberFiltered(N.NetworkTCP, nil, "", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if !allowedA[member.tag] {
			t.Fatalf("alice selected %q outside her 3-node pool", member.tag)
		}
	}
	allowedB := map[string]bool{"n4": true, "n5": true, "n6": true, "n7": true, "n8": true}
	for i := 0; i < 30; i++ {
		member, err := p.pickMemberFiltered(N.NetworkTCP, nil, "", "bob")
		if err != nil {
			t.Fatal(err)
		}
		if !allowedB[member.tag] {
			t.Fatalf("bob selected %q outside his 5-node pool", member.tag)
		}
	}
}

func TestExtUserPoolUnmatchedUsesAllNodes(t *testing.T) {
	config.SetUserPools(nil)
	t.Cleanup(func() { config.SetUserPools(nil) })
	config.SetUserPools([]config.UserPoolConfig{
		{Name: "A", Users: []string{"alice"}, Nodes: []string{"n1"}},
	})

	p := newUserPoolTestPool(t, "n1", "n2", "n3")
	seen := make(map[string]bool)
	for i := 0; i < 30; i++ {
		member, err := p.pickMemberFiltered(N.NetworkTCP, nil, "", "carol")
		if err != nil {
			t.Fatal(err)
		}
		seen[member.tag] = true
	}
	if !seen["n2"] || !seen["n3"] {
		t.Fatalf("default pool did not use all nodes: %+v", seen)
	}
}

func TestExtUserPoolNoFallbackWhenPoolExhausted(t *testing.T) {
	config.SetUserPools(nil)
	t.Cleanup(func() { config.SetUserPools(nil) })
	config.SetUserPools([]config.UserPoolConfig{
		{Name: "A", Users: []string{"alice"}, Nodes: []string{"n1", "n2"}},
	})

	p := newUserPoolTestPool(t, "n1", "n2", "n3", "n4")
	now := time.Now()
	for _, member := range p.members {
		if member.tag == "n1" || member.tag == "n2" {
			member.shared.blacklisted = true
			member.shared.blacklistedUntil = now.Add(time.Hour)
		}
	}

	_, err := p.pickMemberFiltered(N.NetworkTCP, nil, "", "alice")
	if err == nil {
		t.Fatal("expected an error when every node in the pool is unavailable")
	}
	if !strings.Contains(err.Error(), "user pool") {
		t.Fatalf("error should identify the exhausted pool, got %v", err)
	}
}

func TestExtUserPoolDoesNotAffectPinnedNodeOutsidePool(t *testing.T) {
	config.SetUserPools(nil)
	t.Cleanup(func() { config.SetUserPools(nil) })
	config.SetUserPools([]config.UserPoolConfig{
		{Name: "A", Users: []string{"alice"}, Nodes: []string{"n1"}},
	})

	p := newUserPoolTestPool(t, "n1", "n2")
	// A stale pin pointing at n2 must not smuggle the user outside the pool.
	member, err := p.pickMemberForSession(N.NetworkTCP, nil, "identity-n2", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if member.tag != "n1" {
		t.Fatalf("stale out-of-pool pin selected %q, want n1", member.tag)
	}
}
