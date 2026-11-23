package monitor

import (
	"encoding/json"
	"net/http"
	"testing"

	"easy_proxies/internal/logs"
)

func TestLogsAPIStructuredQuery(t *testing.T) {
	previous := logs.Default().MinLevel()
	logs.Default().SetMinLevel(logs.LevelDebug)
	t.Cleanup(func() { logs.Default().SetMinLevel(previous) })

	logs.Default().Add(logs.Entry{
		Level: logs.LevelWarn, Category: "access", Source: "node-1",
		Message: "tcp alice -> example.com:443 via node-1 failed",
		Fields:  map[string]any{"target": "example.com:443"},
	})
	logs.Default().Add(logs.Entry{
		Level: logs.LevelInfo, Category: "refresh",
		Message: "refresh done sources=fofa:5,free:15 admitted=0 rejected=timeout:20",
	})

	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	decode := func(path string) map[string]any {
		resp := proxyAPIRequest(t, s, http.MethodGet, path, "")
		if resp.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, resp.Code, resp.Body.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		return payload
	}

	base := decode("/api/logs")
	if _, ok := base["logs"].(string); !ok {
		t.Fatal("legacy text log field must stay for compatibility")
	}
	entries, ok := base["entries"].([]any)
	if !ok || len(entries) < 2 {
		t.Fatalf("structured entries missing: %+v", base)
	}
	if base["min_level"] != "DEBUG" {
		t.Fatalf("min level not reported: %+v", base)
	}

	if got := decode("/api/logs?level=WARN&category=access&q=example.com"); got["total"] != float64(1) {
		t.Fatalf("combined filters wrong: %+v", got)
	}
	if got := decode("/api/logs?level=ERROR"); got["total"] != float64(0) {
		t.Fatalf("ERROR filter should be empty: %+v", got)
	}
	if got := decode("/api/logs?category=refresh"); got["total"] != float64(1) {
		t.Fatalf("category filter wrong: %+v", got)
	}
	if got := decode("/api/logs?q=not-present"); got["total"] != float64(0) {
		t.Fatalf("keyword filter wrong: %+v", got)
	}
}
