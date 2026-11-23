package quality

import (
	"path/filepath"
	"testing"
)

func TestUpsertEvictsOldestAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node_quality.json")
	store := New(2)
	store.SetPath(path)
	store.Upsert(Record{Key: "a", Name: "a", CheckedAt: "2026-01-01T00:00:00Z"})
	store.Upsert(Record{Key: "b", Name: "b", CheckedAt: "2026-01-02T00:00:00Z"})
	store.Upsert(Record{Key: "c", Name: "c", CheckedAt: "2026-01-03T00:00:00Z"})

	if _, ok := store.Get("a"); ok {
		t.Fatal("oldest record must be evicted when capacity is exceeded")
	}
	if len(store.All()) != 2 {
		t.Fatalf("capacity not enforced: %+v", store.All())
	}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	loaded := New(10)
	if err := loaded.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Get("c"); !ok {
		t.Fatal("saved record not loaded back")
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	store := New(10)
	if err := store.Load(filepath.Join(t.TempDir(), "absent.json")); err != nil {
		t.Fatalf("missing sidecar must not error: %v", err)
	}
	if len(store.All()) != 0 {
		t.Fatal("expected empty store")
	}
}
