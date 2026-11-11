// Package source provides a unified, failure-isolated abstraction for every
// proxy node origin: subscriptions, space-mapping APIs and free proxy pools.
package source

import (
	"context"
	"sync"
	"time"

	"easy_proxies/internal/config"
)

// Provider is implemented by every node origin. A failing provider must not
// discard nodes obtained by other providers.
type Provider interface {
	Name() string
	Enabled() bool
	Fetch(ctx context.Context) ([]config.NodeConfig, error)
}

// Outcome records one provider's result of a collection round.
type Outcome struct {
	Provider  string `json:"provider"`
	Enabled   bool   `json:"enabled"`
	Nodes     int    `json:"nodes"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	FetchedAt string `json:"fetched_at,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
}

// Collection is a merged, de-duplicated snapshot plus per-provider outcomes.
type Collection struct {
	Nodes       []config.NodeConfig `json:"nodes"`
	Outcomes    []Outcome           `json:"outcomes"`
	CollectedAt time.Time           `json:"collected_at"`
}

// Registry runs providers concurrently and keeps the last good result per
// provider, so a rate-limited or failing API never shrinks the whole pool.
type Registry struct {
	mu          sync.RWMutex
	providers   []Provider
	lastGood    map[string][]config.NodeConfig
	lastOutcome map[string]Outcome
	nodes       []config.NodeConfig
	outcomes    []Outcome
	collectedAt time.Time
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		lastGood:    make(map[string][]config.NodeConfig),
		lastOutcome: make(map[string]Outcome),
	}
}

// Register adds a provider. Duplicated names are rejected.
func (r *Registry) Register(p Provider) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.providers {
		if existing.Name() == p.Name() {
			return
		}
	}
	r.providers = append(r.providers, p)
}

// Providers returns the currently registered provider names and states.
func (r *Registry) Providers() []map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]map[string]any, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, map[string]any{"name": p.Name(), "enabled": p.Enabled()})
	}
	return out
}

// Collect runs every enabled provider concurrently. allow may filter providers
// that are not yet due (per-source scheduling). Partial success is kept;
// providers that fail or are skipped reuse their last good result.
func (r *Registry) Collect(ctx context.Context, concurrency int, allow func(Provider) bool) Collection {
	r.mu.RLock()
	providers := append([]Provider(nil), r.providers...)
	r.mu.RUnlock()

	if concurrency <= 0 {
		concurrency = 4
	}
	type result struct {
		name    string
		nodes   []config.NodeConfig
		err     error
		took    time.Duration
		skipped bool
	}
	results := make(chan result, len(providers))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, p := range providers {
		if !p.Enabled() || (allow != nil && !allow(p)) {
			results <- result{name: p.Name(), skipped: true}
			continue
		}
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			nodes, err := p.Fetch(ctx)
			results <- result{name: p.Name(), nodes: nodes, err: err, took: time.Since(start)}
		}(p)
	}
	wg.Wait()
	close(results)

	collected := make(map[string]result, len(providers))
	for res := range results {
		collected[res.name] = res
	}

	now := time.Now()
	outcomes := make([]Outcome, 0, len(providers))
	merged := make([]config.NodeConfig, 0)
	seen := make(map[string]bool)

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range providers {
		res := collected[p.Name()]
		o := Outcome{Provider: p.Name(), Enabled: p.Enabled(), ElapsedMS: res.took.Milliseconds()}
		switch {
		case res.skipped:
			o.Skipped = true
			cached := r.lastGood[p.Name()]
			o.Nodes = len(cached)
			merged = append(merged, cached...)
		case res.err != nil:
			o.Error = res.err.Error()
			cached := r.lastGood[p.Name()]
			o.Nodes = len(cached)
			merged = append(merged, cached...)
		default:
			o.Nodes = len(res.nodes)
			o.FetchedAt = now.Format(time.RFC3339)
			r.lastGood[p.Name()] = append([]config.NodeConfig(nil), res.nodes...)
			merged = append(merged, res.nodes...)
		}
		r.lastOutcome[p.Name()] = o
		outcomes = append(outcomes, o)
	}

	deduped := make([]config.NodeConfig, 0, len(merged))
	for i := range merged {
		n := merged[i]
		key := n.NodeKey()
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, n)
	}
	r.nodes = deduped
	r.outcomes = outcomes
	r.collectedAt = now
	return Collection{Nodes: append([]config.NodeConfig(nil), deduped...), Outcomes: outcomes, CollectedAt: now}
}

// Snapshot returns the last collection without triggering network activity.
func (r *Registry) Snapshot() Collection {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return Collection{
		Nodes:       append([]config.NodeConfig(nil), r.nodes...),
		Outcomes:    append([]Outcome(nil), r.outcomes...),
		CollectedAt: r.collectedAt,
	}
}

// Limiter is a small, dependency-free requests-per-minute throttle.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewLimiter builds a limiter. perMin <= 0 disables throttling.
func NewLimiter(perMin int) *Limiter {
	l := &Limiter{}
	if perMin > 0 {
		l.interval = time.Minute / time.Duration(perMin)
	}
	return l
}

// Wait blocks until the next request slot is available.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
