package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRerouteCountAndDurationContract(t *testing.T) {
	c := New()
	c.IncRequest()
	c.RecordReroute("hk-01", "jp-02", "dial_failed", "tcp", "A", 120)

	snap := c.Snapshot(time.Minute)
	if snap.Summary.RerouteTotal != 1 {
		t.Fatalf("reroute_total=%d, want 1", snap.Summary.RerouteTotal)
	}
	if snap.Summary.RerouteAvgMs != 120 {
		t.Fatalf("reroute_avg_ms=%v, want 120", snap.Summary.RerouteAvgMs)
	}
	if snap.Summary.RerouteP95Ms == 0 || snap.Summary.RerouteP99Ms == 0 {
		t.Fatalf("quantiles must be derived from histogram: %+v", snap.Summary)
	}
	if len(snap.ByNode) != 1 || snap.ByNode[0].Tag != "jp-02" || snap.ByNode[0].AvgMs != 120 {
		t.Fatalf("by_node wrong: %+v", snap.ByNode)
	}
	if len(snap.Events) != 1 || snap.Events[0].Type != "reroute" {
		t.Fatalf("events wrong: %+v", snap.Events)
	}
}

func TestFailedRerouteCountsButExcludedFromDuration(t *testing.T) {
	c := New()
	c.IncRequest()
	c.RecordRerouteAttempt("hk-01", "jp-02", "timeout", "tcp", "A")

	snap := c.Snapshot(time.Minute)
	if snap.Summary.RerouteTotal != 1 {
		t.Fatalf("a failed re-selection must still count as a reroute, got %d", snap.Summary.RerouteTotal)
	}
	if snap.Summary.RerouteAvgMs != 0 || snap.Summary.RerouteP99Ms != 0 {
		t.Fatalf("failed reroute must not skew duration: %+v", snap.Summary)
	}
}

func TestWindowAggregationAndRate(t *testing.T) {
	c := New()
	for i := 0; i < 10; i++ {
		c.IncRequest()
	}
	c.RecordReroute("a", "b", "reset", "tcp", "", 50)
	c.IncClientVisibleFailure()
	c.IncFirstTrySuccess()
	c.ObserveE2E(75)

	snap := c.Snapshot(time.Minute)
	if snap.Summary.Requests != 10 || snap.Summary.Failures != 1 {
		t.Fatalf("window counts wrong: %+v", snap.Summary)
	}
	if snap.Summary.ClientVisibleFailureRate != 0.1 || snap.Summary.SuccessRate != 0.9 {
		t.Fatalf("rates wrong: %+v", snap.Summary)
	}
	if snap.Summary.RerouteRate != 0.1 {
		t.Fatalf("reroute rate wrong: %+v", snap.Summary)
	}
}

func TestCircuitAndNodeLifecycle(t *testing.T) {
	c := New()
	c.RecordCircuitTransition("n1", "closed", "open")
	c.RecordHalfOpenProbe("n1", "success")
	c.IncNodeEvicted("n1")
	c.IncNodeRecovered("n1")
	c.IncReload(3)
	c.IncDegrade("queue")
	c.SetAvailableNodes(4)
	c.SetQueueDepth(2)

	snap := c.Snapshot(time.Minute)
	if snap.Summary.CircuitTransitions != 1 || snap.Summary.HalfOpenSuccess != 1 {
		t.Fatalf("circuit metrics wrong: %+v", snap.Summary)
	}
	if snap.Summary.NodeEvictions != 1 || snap.Summary.NodeRecoveries != 1 {
		t.Fatalf("node lifecycle wrong: %+v", snap.Summary)
	}
	if snap.Summary.ReloadDisconnectedConns != 3 || snap.Summary.Degrades != 1 {
		t.Fatalf("reload/degrade wrong: %+v", snap.Summary)
	}
	if snap.Summary.AvailableNodes != 4 || snap.Summary.QueueDepth != 2 {
		t.Fatalf("gauges wrong: %+v", snap.Summary)
	}
}

func TestEventsBoundedAndCredentialFree(t *testing.T) {
	c := New()
	for i := 0; i < defaultEvents+25; i++ {
		c.IncDegrade("reason")
	}
	snap := c.Snapshot(time.Minute)
	if len(snap.Events) != defaultEvents {
		t.Fatalf("events not bounded: %d", len(snap.Events))
	}
	for _, ev := range snap.Events {
		if strings.Contains(strings.ToLower(ev.Detail), "password") {
			t.Fatalf("event leaked a credential: %+v", ev)
		}
	}
}

func TestPrometheusExposition(t *testing.T) {
	c := New()
	c.RecordReroute("a", "b", "dial_failed", "tcp", "A", 30)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "proxy_reroute_total") || !strings.Contains(body, "proxy_reroute_duration_ms") {
		t.Fatalf("prometheus exposition missing metrics: %s", body[:min(len(body), 400)])
	}
}

func TestParseWindow(t *testing.T) {
	if ParseWindow("5m") != 5*time.Minute || ParseWindow("1h") != time.Hour || ParseWindow("bogus") != time.Minute {
		t.Fatal("window parsing contract broken")
	}
}

func TestSetDefaultRestores(t *testing.T) {
	original := Default()
	restore := SetDefault(New())
	if Default() == original {
		t.Fatal("SetDefault did not replace the collector")
	}
	restore()
	if Default() != original {
		t.Fatal("restore did not reinstate the original collector")
	}
}
