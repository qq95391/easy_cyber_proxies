package config

import "testing"

func TestExtNormalizeUserPools(t *testing.T) {
	in := []UserPoolConfig{
		{Name: "  A  ", Users: []string{" alice ", "alice", ""}, Nodes: []string{" a ", "a", ""}},
		{Name: "", Users: []string{"x"}},
		{Name: "B", Users: nil},
		{Name: "C", Users: []string{"carol"}},
	}
	out := NormalizeUserPools(in)
	if len(out) != 2 {
		t.Fatalf("want 2 valid pools, got %d: %+v", len(out), out)
	}
	if out[0].Name != "A" || len(out[0].Users) != 1 || out[0].Users[0] != "alice" {
		t.Fatalf("users not normalized: %+v", out[0])
	}
	if len(out[0].Nodes) != 1 || out[0].Nodes[0] != "a" {
		t.Fatalf("nodes not normalized: %+v", out[0])
	}
	if len(out[1].Nodes) != 0 {
		t.Fatalf("empty node list must stay empty (full node set): %+v", out[1])
	}
}

func TestExtMatchUserPoolExplicitSubsets(t *testing.T) {
	SetUserPools(nil)
	t.Cleanup(func() { SetUserPools(nil) })
	SetUserPools([]UserPoolConfig{
		{Name: "A", Users: []string{"alice"}, Nodes: []string{"n1", "n2", "n3"}},
		{Name: "B", Users: []string{"bob"}, Nodes: []string{"n1", "n2", "n3", "n4", "n5"}},
	})

	allow, name, matched := MatchUserPool("alice")
	if !matched || name != "A" {
		t.Fatalf("alice matched=%v name=%q", matched, name)
	}
	if len(allow) != 3 || !allow["n1"] || allow["n4"] {
		t.Fatalf("A pool allowlist wrong: %+v", allow)
	}

	allow, name, matched = MatchUserPool("bob")
	if !matched || name != "B" || len(allow) != 5 {
		t.Fatalf("B pool wrong: matched=%v name=%q allow=%+v", matched, name, allow)
	}

	// Unmatched users fall back to the default pool (all nodes).
	if _, _, matched = MatchUserPool("carol"); matched {
		t.Fatal("carol should use the default pool")
	}
	if _, _, matched = MatchUserPool(""); matched {
		t.Fatal("empty username must use the default pool")
	}
}

func TestExtMatchUserPoolEmptyNodesMeansAll(t *testing.T) {
	SetUserPools(nil)
	t.Cleanup(func() { SetUserPools(nil) })
	SetUserPools([]UserPoolConfig{{Name: "all", Users: []string{"dave"}}})

	allow, name, matched := MatchUserPool("dave")
	if !matched || name != "all" {
		t.Fatalf("dave matched=%v name=%q", matched, name)
	}
	if allow != nil {
		t.Fatalf("pool without nodes must mean full set, got %+v", allow)
	}
}

func TestExtSetUserPoolsCopies(t *testing.T) {
	SetUserPools(nil)
	t.Cleanup(func() { SetUserPools(nil) })
	src := []UserPoolConfig{{Name: "A", Users: []string{"alice"}, Nodes: []string{"n1"}}}
	SetUserPools(src)
	src[0].Name = "mutated"
	if got := LoadUserPools(); len(got) != 1 || got[0].Name != "A" {
		t.Fatalf("store must not alias caller slice: %+v", got)
	}
}
