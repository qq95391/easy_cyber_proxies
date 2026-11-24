package logs

import (
	"fmt"
	"strings"
	"testing"
)

func TestLevelThresholdAndAtLeast(t *testing.T) {
	if !LevelWarn.AtLeast(LevelInfo) || LevelDebug.AtLeast(LevelWarn) {
		t.Fatal("level ordering is wrong")
	}
	b := New(10)
	b.SetMinLevel(LevelInfo)
	b.Add(Entry{Level: LevelDebug, Category: "verify", Message: "per-node detail"})
	b.Add(Entry{Level: LevelInfo, Category: "refresh", Message: "summary"})
	if got := b.Query(LevelDebug, "all", "", 10); len(got) != 1 || got[0].Message != "summary" {
		t.Fatalf("DEBUG detail must be dropped by default: %+v", got)
	}
	b.SetMinLevel(LevelDebug)
	b.Add(Entry{Level: LevelDebug, Category: "verify", Message: "enabled detail"})
	if got := b.Query(LevelDebug, "all", "", 10); len(got) != 2 {
		t.Fatalf("DEBUG threshold should retain detail: %+v", got)
	}
}

func TestRingsAreBoundedAndIndependent(t *testing.T) {
	b := New(3)
	b.SetMinLevel(LevelDebug)
	for i := 0; i < 6; i++ {
		b.Add(Entry{Level: LevelInfo, Category: "access", Message: fmt.Sprintf("access-%d", i)})
	}
	b.Add(Entry{Level: LevelInfo, Category: "refresh", Message: "refresh-summary"})
	access := b.Query(LevelDebug, "access", "", 10)
	if len(access) != 3 || access[0].Message != "access-5" || access[2].Message != "access-3" {
		t.Fatalf("access ring must keep newest 3: %+v", access)
	}
	general := b.Query(LevelDebug, "refresh", "", 10)
	if len(general) != 1 || general[0].Message != "refresh-summary" {
		t.Fatalf("access burst must not evict general entries: %+v", general)
	}
}

func TestQueryFiltersByLevelCategoryAndKeyword(t *testing.T) {
	b := New(20)
	b.SetMinLevel(LevelDebug)
	b.Add(Entry{
		Level: LevelWarn, Category: "access", Source: "node-1",
		Message: "tcp alice -> example.com:443 via node-1 failed",
		Fields:  map[string]any{"target": "example.com:443", "result": "failed"},
	})
	b.Add(Entry{Level: LevelInfo, Category: "refresh", Message: "refresh done sources=fofa:300,free:15"})

	if got := b.Query(LevelWarn, "all", "", 10); len(got) != 1 || got[0].Level != LevelWarn {
		t.Fatalf("min level filter wrong: %+v", got)
	}
	if got := b.Query(LevelError, "all", "", 10); len(got) != 0 {
		t.Fatalf("ERROR filter should be empty: %+v", got)
	}
	if got := b.Query(LevelDebug, "access", "", 10); len(got) != 1 || got[0].Category != "access" {
		t.Fatalf("category filter wrong: %+v", got)
	}
	for _, needle := range []string{"example.com", "NODE-1", "target", "FOFA:300", "failed"} {
		if got := b.Query(LevelDebug, "all", needle, 10); len(got) != 1 {
			t.Fatalf("keyword %q did not match exactly one entry: %+v", needle, got)
		}
	}
	if got := b.Query(LevelDebug, "all", "not-present", 10); len(got) != 0 {
		t.Fatalf("unknown keyword must match nothing: %+v", got)
	}
}

func TestSanitizeErrorStripsQueryAndCredentials(t *testing.T) {
	in := `request failed: Get "https://fofa.info/api/v1/search/all?key=SECRET123&qbase64=abc": context deadline exceeded`
	out := SanitizeError(in)
	if strings.Contains(out, "SECRET123") || strings.Contains(out, "qbase64") || strings.Contains(out, "key=") {
		t.Fatalf("credentials leaked: %s", out)
	}
	if !strings.Contains(out, "https://fofa.info/api/v1/search/all") || !strings.Contains(out, "context deadline exceeded") {
		t.Fatalf("useful context lost: %s", out)
	}
}
