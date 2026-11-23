package pool

import (
	"context"
	"strings"
	"testing"

	"easy_proxies/internal/logs"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestLogAccessRecordsTargetDomainNodeAndClient(t *testing.T) {
	previous := logs.Default().MinLevel()
	logs.Default().SetMinLevel(logs.LevelDebug)
	t.Cleanup(func() { logs.Default().SetMinLevel(previous) })

	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Source:      M.ParseSocksaddr("198.51.100.10:12345"),
		InboundType: "mixed",
	})
	if md := adapter.ContextFrom(ctx); md != nil {
		md.User = "alice.session-1"
	}

	logAccess(ctx, "tcp", M.ParseSocksaddr("example.com:443"), "node-1", "ok", 1, "", 12.5)

	entries := logs.Default().Query(logs.LevelDebug, "access", "example.com", 10)
	if len(entries) != 1 {
		t.Fatalf("expected one access entry, got %+v", entries)
	}
	e := entries[0]
	if e.Level != logs.LevelInfo || e.Category != "access" || e.Source != "node-1" {
		t.Fatalf("entry shape wrong: %+v", e)
	}
	want := map[string]any{
		"target": "example.com:443", "node": "node-1", "user": "alice.session-1",
		"client": "198.51.100.10:12345", "result": "ok", "network": "tcp",
	}
	for key, value := range want {
		if e.Fields[key] != value {
			t.Fatalf("field %s = %v, want %v", key, e.Fields[key], value)
		}
	}
}

func TestLogAccessMarksFailuresAsWarnAndSanitizesErrors(t *testing.T) {
	previous := logs.Default().MinLevel()
	logs.Default().SetMinLevel(logs.LevelDebug)
	t.Cleanup(func() { logs.Default().SetMinLevel(previous) })

	logAccess(context.Background(), "tcp", M.ParseSocksaddr("203.0.113.9:80"),
		"node-2", "failed", 2, `dial failed: Get "https://api.example/get?token=SECRET": timeout`, 30)

	entries := logs.Default().Query(logs.LevelDebug, "access", "203.0.113.9", 10)
	if len(entries) != 1 || entries[0].Level != logs.LevelWarn {
		t.Fatalf("failed access must be WARN: %+v", entries)
	}
	errText, _ := entries[0].Fields["error"].(string)
	if strings.Contains(errText, "SECRET") || strings.Contains(errText, "token=") {
		t.Fatalf("error leaked credentials: %s", errText)
	}
}
