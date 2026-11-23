package config

import (
	"testing"
	"time"
)

func TestPoolResilienceDefaults(t *testing.T) {
	var p PoolConfig
	if p.SwitchBudgetOrDefault() != 3*time.Second {
		t.Fatalf("switch budget default = %v", p.SwitchBudgetOrDefault())
	}
	if p.DialTimeoutOrDefault() != 0 {
		t.Fatal("dial timeout must be opt-in")
	}
	if p.HealthIntervalOrDefault() != 5*time.Minute {
		t.Fatalf("health interval default = %v", p.HealthIntervalOrDefault())
	}
	if !p.CircuitBreakerEnabled() {
		t.Fatal("circuit breaker must be enabled by default")
	}
	disabled := false
	p.EnableCircuitBreaker = &disabled
	if p.CircuitBreakerEnabled() {
		t.Fatal("explicit false must disable the breaker")
	}
}

func TestPoolConfiguredResilienceValues(t *testing.T) {
	p := PoolConfig{
		SwitchBudget:   1500 * time.Millisecond,
		DialTimeout:    800 * time.Millisecond,
		HealthInterval: 30 * time.Second,
		Fallback:       "default_pool",
	}
	if p.SwitchBudgetOrDefault() != 1500*time.Millisecond || p.DialTimeoutOrDefault() != 800*time.Millisecond {
		t.Fatalf("configured deadlines lost: %+v", p)
	}
	if p.HealthIntervalOrDefault() != 30*time.Second || p.FallbackOrDefault() != "default_pool" {
		t.Fatalf("configured policy lost: %+v", p)
	}
}

func TestFallbackNormalization(t *testing.T) {
	for value, want := range map[string]string{"": "none", "bogus": "none", "direct": "direct", "default_pool": "default_pool"} {
		if got := (PoolConfig{Fallback: value}).FallbackOrDefault(); got != want {
			t.Fatalf("PoolConfig(%q) = %q, want %q", value, got, want)
		}
		pools := NormalizeUserPools([]UserPoolConfig{{Name: "A", Users: []string{"u"}, Fallback: value}})
		if len(pools) != 1 || pools[0].Fallback != want {
			t.Fatalf("UserPoolConfig(%q) normalized to %+v, want %q", value, pools, want)
		}
	}
}
