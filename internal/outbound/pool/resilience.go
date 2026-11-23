package pool

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"easy_proxies/internal/metrics"

	"github.com/sagernet/sing/common/metadata"
	"github.com/sony/gobreaker/v2"
)

// breakerSet owns one three-state circuit breaker per node tag. It is an
// additional gate in front of the existing shared-state blacklist/cooldown
// logic, so a node that is failing repeatedly stops being selected before a
// real request has to discover it.
type breakerSet struct {
	mu        sync.Mutex
	breakers  map[string]*gobreaker.TwoStepCircuitBreaker[struct{}]
	enabled   bool
	threshold uint32
	timeout   time.Duration
}

func newBreakerSet(enabled bool, threshold int, timeout time.Duration) *breakerSet {
	if threshold < 1 {
		threshold = 5
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &breakerSet{
		breakers:  make(map[string]*gobreaker.TwoStepCircuitBreaker[struct{}]),
		enabled:   enabled,
		threshold: uint32(threshold),
		timeout:   timeout,
	}
}

func (b *breakerSet) forNode(tag string) *gobreaker.TwoStepCircuitBreaker[struct{}] {
	// Tests and lightweight fixtures may construct a pool without newPool.
	if b == nil || !b.enabled {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if cb := b.breakers[tag]; cb != nil {
		return cb
	}
	threshold := b.threshold
	cb := gobreaker.NewTwoStepCircuitBreaker[struct{}](gobreaker.Settings{
		Name:        tag,
		MaxRequests: 1,
		Timeout:     b.timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= threshold
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			metrics.Default().RecordCircuitTransition(name, stateLabel(from), stateLabel(to))
			logCircuitTransition(name, stateLabel(from), stateLabel(to))
			switch to {
			case gobreaker.StateOpen:
				metrics.Default().IncNodeEvicted(name)
			case gobreaker.StateClosed:
				if from == gobreaker.StateHalfOpen {
					metrics.Default().IncNodeRecovered(name)
				}
			}
		},
		IsSuccessful: func(err error) bool {
			return err == nil || isBreakerRejection(err)
		},
	})
	b.breakers[tag] = cb
	return cb
}

// Allow returns a completion callback plus a rejection error. Rejections are
// not node failures: they mean the breaker deliberately skipped the dial.
func (b *breakerSet) Allow(tag string) (func(error), error) {
	cb := b.forNode(tag)
	if cb == nil {
		return func(error) {}, nil
	}
	return cb.Allow()
}

// Finish records a half-open probe result for observability.
func (b *breakerSet) Finish(tag string, err error) {
	cb := b.forNode(tag)
	if cb == nil || cb.State() != gobreaker.StateHalfOpen {
		return
	}
	result := "success"
	if err != nil && !isBreakerRejection(err) {
		result = "failure"
	}
	metrics.Default().RecordHalfOpenProbe(tag, result)
}

// IsOpen lets selection skip nodes whose breaker is open.
func (b *breakerSet) IsOpen(tag string) bool {
	cb := b.forNode(tag)
	return cb != nil && cb.State() == gobreaker.StateOpen
}

const (
	queueWaitTick     = 50 * time.Millisecond
	maxQueueWaitTicks = 6
)

// waitForRecoverableNode waits one tick inside the switch budget. It returns
// false as soon as the budget is exhausted.
func waitForRecoverableNode(ctx context.Context) bool {
	timer := time.NewTimer(queueWaitTick)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

// dialMember applies the per-dial deadline and the breaker gate. A breaker
// rejection is returned as an error so the caller can skip the node without
// recording it as an upstream failure.
func (p *poolOutbound) dialMember(ctx context.Context, member *memberState, network string, destination metadata.Socksaddr) (net.Conn, error) {
	done, allowErr := p.breakers.Allow(member.tag)
	if allowErr != nil {
		return nil, allowErr
	}
	dialCtx := ctx
	if p.options.DialTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, p.options.DialTimeout)
		defer cancel()
	}
	conn, err := member.outbound.DialContext(dialCtx, network, destination)
	p.breakers.Finish(member.tag, err)
	done(err)
	return conn, err
}

func isBreakerRejection(err error) bool {
	return errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests)
}

func stateLabel(state gobreaker.State) string {
	switch state {
	case gobreaker.StateClosed:
		return "closed"
	case gobreaker.StateHalfOpen:
		return "half_open"
	case gobreaker.StateOpen:
		return "open"
	default:
		return "unknown"
	}
}
