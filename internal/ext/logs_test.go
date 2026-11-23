package ext

import (
	"strings"
	"testing"

	"easy_proxies/internal/config"
	"easy_proxies/internal/logs"
	"easy_proxies/internal/source"
	"easy_proxies/internal/verify"
)

func TestJoinCountsAndSourceLabels(t *testing.T) {
	if got := joinCounts(map[string]int{"free": 15, "fofa": 300}); got != "fofa:300,free:15" {
		t.Fatalf("unstable ordering: %s", got)
	}
	for provider, want := range map[string]string{
		"mapping:fofa": "fofa", "mapping:quake": "quake",
		"freepool": "free", "external:proxy_pool": "free", "other": "other",
	} {
		if got := shortSource(provider); got != want {
			t.Fatalf("shortSource(%q) = %q, want %q", provider, got, want)
		}
	}
	if got := nodeSourceShort(config.NodeConfig{Source: config.NodeSourceFreePool}); got != "free" {
		t.Fatalf("free node label = %q", got)
	}
	if got := nodeSourceShort(config.NodeConfig{Source: config.NodeSourceMapping, SourceDetail: "fofa-preset"}); got != "fofa" {
		t.Fatalf("fofa node label = %q", got)
	}
}

func TestClassifyRejection(t *testing.T) {
	auth := config.AuthenticityConfig{Action: "reject"}
	mitm := config.MITMConfig{Action: "reject"}
	cases := []struct {
		name string
		res  verify.Result
		want string
	}{
		{"timeout", verify.Result{Reachable: false, Error: "dial timeout"}, "timeout"},
		{"unreachable", verify.Result{Reachable: false, Error: "connection refused"}, "unreachable"},
		{"score", verify.Result{Reachable: true, Score: 10}, "score_below_min"},
		{"mitm", verify.Result{Reachable: true, Score: 90, MITMSuspected: true}, "mitm"},
		{"authenticity", verify.Result{Reachable: true, Score: 90, Checks: map[string]bool{"genuine": true}, Genuine: false}, "authenticity"},
	}
	for _, tc := range cases {
		if got := classifyRejection(tc.res, 40, auth, mitm); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRefreshSummaryLogsCountsReasonsAndSanitizedErrors(t *testing.T) {
	previous := logs.Default().MinLevel()
	logs.Default().SetMinLevel(logs.LevelDebug)
	t.Cleanup(func() { logs.Default().SetMinLevel(previous) })

	collection := source.Collection{
		Nodes: make([]config.NodeConfig, 20),
		Outcomes: []source.Outcome{
			{Provider: "mapping:fofa", Nodes: 15, Enabled: true},
			{Provider: "freepool", Nodes: 10, Enabled: true,
				Error: `request failed: Get "https://fofa.info/api/v1/search/all?key=SECRET123&qbase64=abc": timeout`},
		},
	}
	admitted := []config.NodeConfig{
		{Name: "a", Source: config.NodeSourceMapping, SourceDetail: "fofa-preset"},
		{Name: "b", Source: config.NodeSourceFreePool},
	}
	reasons := map[string]int{"score_below_min": 12, "timeout": 6}

	(&Orchestrator{}).logRefreshSummary(collection, admitted, reasons)

	summaries := logs.Default().Query(logs.LevelDebug, "refresh", "refresh done", 10)
	if len(summaries) == 0 {
		t.Fatal("no INFO refresh summary emitted")
	}
	msg := summaries[0].Message
	for _, want := range []string{
		"candidates=20", "sources=fofa:15,free:10", "admitted=2",
		"admitted_by=fofa:1,free:1", "deduped=5",
		"rejected=score_below_min:12,timeout:6",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("summary missing %q: %s", want, msg)
		}
	}
	warnings := logs.Default().Query(logs.LevelWarn, "refresh", "provider failed", 10)
	if len(warnings) == 0 {
		t.Fatal("provider error should be logged as WARN")
	}
	if strings.Contains(warnings[0].Message, "SECRET123") || strings.Contains(warnings[0].Message, "qbase64") {
		t.Fatalf("provider error leaked credentials: %s", warnings[0].Message)
	}
}
