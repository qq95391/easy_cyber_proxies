package pool

import (
	"errors"
	"testing"
	"time"

	"github.com/sony/gobreaker/v2"
)

func TestBreakerThreeStates(t *testing.T) {
	b := newBreakerSet(true, 2, 20*time.Millisecond)
	for i := 0; i < 2; i++ {
		done, err := b.Allow("n1")
		if err != nil {
			t.Fatalf("attempt %d was rejected prematurely: %v", i, err)
		}
		done(errors.New("dial failed"))
	}
	if !b.IsOpen("n1") {
		t.Fatal("breaker must open after the configured consecutive failures")
	}
	if _, err := b.Allow("n1"); !errors.Is(err, gobreaker.ErrOpenState) {
		t.Fatalf("open breaker must reject before any dial, got %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	done, err := b.Allow("n1")
	if err != nil {
		t.Fatalf("half-open must allow exactly one probe: %v", err)
	}
	if _, secondErr := b.Allow("n1"); !errors.Is(secondErr, gobreaker.ErrTooManyRequests) {
		t.Fatalf("half-open must reject additional requests, got %v", secondErr)
	}
	done(nil)
	if b.IsOpen("n1") {
		t.Fatal("a successful half-open probe must close the breaker")
	}
}

func TestBreakerDisabledNeverRejects(t *testing.T) {
	b := newBreakerSet(false, 1, time.Millisecond)
	for i := 0; i < 5; i++ {
		done, err := b.Allow("n1")
		if err != nil {
			t.Fatalf("disabled breaker rejected a dial: %v", err)
		}
		done(errors.New("dial failed"))
	}
}

func TestNilBreakerIsSafe(t *testing.T) {
	var b *breakerSet
	done, err := b.Allow("n1")
	if err != nil {
		t.Fatalf("nil breaker must be a no-op, got %v", err)
	}
	done(nil)
	b.Finish("n1", nil)
	if b.IsOpen("n1") {
		t.Fatal("nil breaker must never report open")
	}
}

func TestNormalizeOptionsResilienceDefaults(t *testing.T) {
	got := normalizeOptions(Options{Members: []string{"a", "b"}})
	if got.SwitchBudget != 3*time.Second {
		t.Fatalf("switch budget default = %v", got.SwitchBudget)
	}
	if got.CircuitThreshold != 5 || got.CircuitTimeout != defaultTransientCooldown {
		t.Fatalf("breaker defaults wrong: %+v", got)
	}
	if got.DialTimeout != 0 {
		t.Fatal("dial timeout must stay opt-in to preserve legacy behaviour")
	}
}
