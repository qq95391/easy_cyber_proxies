package ext

import (
	"testing"
	"time"

	"easy_proxies/internal/config"
)

func newScheduleTestOrchestrator() *Orchestrator {
	return &Orchestrator{
		lastFetch:   make(map[string]time.Time),
		lastSuccess: make(map[string]time.Time),
		failStreak:  make(map[string]int),
		negCache:    make(map[string]negEntry),
	}
}

func TestRetryBackoffGrowsAndCaps(t *testing.T) {
	cases := []struct {
		streak int
		want   time.Duration
	}{
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{8, time.Hour}, // capped at 1h
		{20, time.Hour},
	}
	for _, tc := range cases {
		if got := retryBackoff(tc.streak); got != tc.want {
			t.Fatalf("retryBackoff(%d) = %v, want %v", tc.streak, got, tc.want)
		}
	}
}

func TestDueUsesAttemptTimeForFailingProvider(t *testing.T) {
	o := newScheduleTestOrchestrator()
	ext := config.ExtensionConfig{} // freepool interval defaults to 5m

	// A successful provider waits the full configured interval.
	o.lastFetch["freepool"] = time.Now().Add(-2 * time.Minute)
	if o.due("freepool", ext) {
		t.Fatal("2m < 5m: not due yet")
	}

	// A failing provider retries on backoff, so it becomes due earlier.
	o.failStreak["freepool"] = 2 // 2m backoff
	o.lastFetch["freepool"] = time.Now().Add(-3 * time.Minute)
	if !o.due("freepool", ext) {
		t.Fatal("3m > 2m backoff: failing provider should be due")
	}

	// But it must not be due on every scheduler tick.
	o.lastFetch["freepool"] = time.Now().Add(-30 * time.Second)
	if o.due("freepool", ext) {
		t.Fatal("30s < 2m backoff: must not refetch on every tick")
	}
}

func TestNegativeCacheTTLPerReason(t *testing.T) {
	if got := negativeCacheTTL("timeout"); got != 10*time.Minute {
		t.Fatalf("timeout ttl = %v", got)
	}
	if got := negativeCacheTTL("unreachable"); got != 30*time.Minute {
		t.Fatalf("unreachable ttl = %v", got)
	}
	if got := negativeCacheTTL("score_below_min"); got != time.Hour {
		t.Fatalf("score ttl = %v", got)
	}
	if got := negativeCacheTTL("mitm"); got != 24*time.Hour {
		t.Fatalf("mitm ttl = %v", got)
	}
}

func TestPruneNegCacheDropsExpired(t *testing.T) {
	o := newScheduleTestOrchestrator()
	now := time.Now()
	o.negCache["fresh"] = negEntry{until: now.Add(time.Minute), reason: "timeout"}
	o.negCache["stale"] = negEntry{until: now.Add(-time.Minute), reason: "timeout"}
	o.pruneNegCacheLocked(now)
	if _, ok := o.negCache["fresh"]; !ok {
		t.Fatal("fresh entry removed")
	}
	if _, ok := o.negCache["stale"]; ok {
		t.Fatal("expired entry kept")
	}
}

func TestRejectRingIsBoundedAndNewestFirst(t *testing.T) {
	o := newScheduleTestOrchestrator()
	for i := 0; i < rejectRingSize+5; i++ {
		o.appendRejectLocked(RejectRecord{Node: "n"})
	}
	if len(o.rejects) != rejectRingSize {
		t.Fatalf("ring length = %d, want %d", len(o.rejects), rejectRingSize)
	}
	recent := o.RecentRejects()
	if len(recent) != rejectRingSize {
		t.Fatalf("recent length = %d", len(recent))
	}
	if recent[0].At == "" && recent[0].Node != "n" {
		t.Fatal("unexpected record")
	}
}
