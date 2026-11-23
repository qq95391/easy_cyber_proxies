// Package metrics collects reliability indicators for the proxy pool and
// exposes them both as JSON (management UI) and Prometheus text.
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	windowSeconds = 3600
	defaultEvents = 100
)

var durationBuckets = []float64{1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000}

// Event is one bounded, credential-free reliability record.
type Event struct {
	TS       time.Time `json:"ts"`
	Type     string    `json:"type"`
	From     string    `json:"from,omitempty"`
	To       string    `json:"to,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Pool     string    `json:"pool,omitempty"`
	Protocol string    `json:"protocol,omitempty"`
	Duration float64   `json:"duration_ms,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

type secondStats struct {
	stamp      int64
	requests   int64
	failures   int64
	reroutes   int64
	durSum     float64
	durCount   int64
	durMax     float64
	hist       []uint64
	degrades   int64
	evictions  int64
	recoveries int64
	reloads    int64
	disconns   int64
}

func newSecondStats(stamp int64) secondStats {
	return secondStats{stamp: stamp, hist: make([]uint64, len(durationBuckets))}
}

type nodeAccum struct {
	Tag           string  `json:"tag"`
	RerouteTotal  int64   `json:"reroute_total"`
	DurationSum   float64 `json:"-"`
	DurationCount int64   `json:"-"`
	AvgMs         float64 `json:"avg_ms"`
	CircuitState  string  `json:"circuit_state,omitempty"`
	Evictions     int64   `json:"evictions"`
	Recoveries    int64   `json:"recoveries"`
}

// Summary is the windowed view consumed by the management UI.
type Summary struct {
	Window                   string  `json:"window"`
	Requests                 int64   `json:"requests"`
	Failures                 int64   `json:"failures"`
	SuccessRate              float64 `json:"success_rate"`
	ClientVisibleFailureRate float64 `json:"client_visible_failure_rate"`
	RerouteTotal             int64   `json:"reroute_total"`
	RerouteRate              float64 `json:"reroute_rate"`
	RerouteAvgMs             float64 `json:"reroute_avg_ms"`
	RerouteP95Ms             float64 `json:"reroute_p95_ms"`
	RerouteP99Ms             float64 `json:"reroute_p99_ms"`
	RerouteMaxMs             float64 `json:"reroute_max_ms"`
	RerouteExhausted         int64   `json:"reroute_exhausted"`
	CircuitTransitions       int64   `json:"circuit_transitions"`
	HalfOpenSuccess          int64   `json:"half_open_success"`
	HalfOpenFailure          int64   `json:"half_open_failure"`
	NodeEvictions            int64   `json:"node_evictions"`
	NodeRecoveries           int64   `json:"node_recoveries"`
	Degrades                 int64   `json:"degrades"`
	Reloads                  int64   `json:"reloads"`
	ReloadDisconnectedConns  int64   `json:"reload_disconnected_conns"`
	AvailableNodes           float64 `json:"available_nodes"`
	QueueDepth               float64 `json:"queue_depth"`
	StickyHitRate            float64 `json:"sticky_hit_rate"`
	ForcedConnRebuilds       int64   `json:"forced_conn_rebuilds"`
}

// SnapshotData is the /api/metrics response body.
type SnapshotData struct {
	Summary Summary       `json:"summary"`
	ByNode  []nodeAccum   `json:"by_node"`
	Events  []Event       `json:"events"`
	Series  []SeriesPoint `json:"series"`
}

// SeriesPoint is one time bucket for the UI charts.
type SeriesPoint struct {
	TS       int64   `json:"ts"`
	Reroutes int64   `json:"reroutes"`
	AvgMs    float64 `json:"avg_ms"`
	Failures int64   `json:"failures"`
}

// Collector owns a private registry so the management server can expose
// /metrics without importing the default process collectors twice.
type Collector struct {
	reg *prometheus.Registry

	rerouteTotal      *prometheus.CounterVec
	rerouteDuration   *prometheus.HistogramVec
	requests          prometheus.Counter
	failures          prometheus.Counter
	firstTrySuccess   prometheus.Counter
	rerouteExhausted  prometheus.Counter
	e2eDuration       prometheus.Histogram
	circuitTransition *prometheus.CounterVec
	halfOpenProbe     *prometheus.CounterVec
	nodeEvicted       prometheus.Counter
	nodeRecovered     prometheus.Counter
	degrades          prometheus.Counter
	reloads           prometheus.Counter
	reloadDisconns    prometheus.Counter
	stickyHits        prometheus.Counter
	stickyMisses      prometheus.Counter
	forcedRebuilds    prometheus.Counter
	availableNodes    prometheus.Gauge
	queueDepth        prometheus.Gauge

	mu      sync.Mutex
	seconds [windowSeconds]secondStats
	events  []Event
	nodes   map[string]*nodeAccum
}

// New builds an isolated collector.
func New() *Collector {
	c := &Collector{
		reg:    prometheus.NewRegistry(),
		events: make([]Event, 0, defaultEvents),
		nodes:  make(map[string]*nodeAccum),
	}
	c.rerouteTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_reroute_total",
		Help: "Number of times a call moved to another node after a node failure.",
	}, []string{"from", "to", "reason", "protocol", "pool"})
	c.rerouteDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_reroute_duration_ms",
		Help:    "Time from failure detection to successful forwarding on the new node.",
		Buckets: durationBuckets,
	}, []string{"protocol", "pool"})
	c.requests = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_requests_total", Help: "Client requests entering the pool."})
	c.failures = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_client_visible_failures_total", Help: "Failures observed by the caller."})
	c.firstTrySuccess = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_first_try_success_total", Help: "Requests that succeeded without a reroute."})
	c.rerouteExhausted = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_reroute_exhausted_total", Help: "Reroutes that exhausted the switch budget."})
	c.e2eDuration = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "proxy_e2e_latency_ms", Help: "End-to-end latency.", Buckets: durationBuckets})
	c.circuitTransition = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "proxy_circuit_transitions_total", Help: "Circuit breaker state transitions."}, []string{"node", "from", "to"})
	c.halfOpenProbe = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "proxy_half_open_probes_total", Help: "Half-open probe results."}, []string{"node", "result"})
	c.nodeEvicted = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_node_evicted_total", Help: "Nodes removed from selection."})
	c.nodeRecovered = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_node_recovered_total", Help: "Nodes returned to selection."})
	c.degrades = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_degrade_total", Help: "Fallback/degradation activations."})
	c.reloads = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_reload_total", Help: "Core reloads."})
	c.reloadDisconns = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_reload_disconnected_conns_total", Help: "Connections forcibly closed by a reload."})
	c.stickyHits = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_sticky_hits_total", Help: "Requests served by an existing session binding."})
	c.stickyMisses = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_sticky_misses_total", Help: "Requests that had to create a new binding."})
	c.forcedRebuilds = prometheus.NewCounter(prometheus.CounterOpts{Name: "proxy_forced_conn_rebuilds_total", Help: "Long-lived connections forcibly rebuilt."})
	c.availableNodes = prometheus.NewGauge(prometheus.GaugeOpts{Name: "proxy_available_nodes", Help: "Currently selectable nodes."})
	c.queueDepth = prometheus.NewGauge(prometheus.GaugeOpts{Name: "proxy_queue_depth", Help: "Requests waiting for a node."})
	c.reg.MustRegister(
		c.rerouteTotal, c.rerouteDuration, c.requests, c.failures, c.firstTrySuccess,
		c.rerouteExhausted, c.e2eDuration, c.circuitTransition, c.halfOpenProbe,
		c.nodeEvicted, c.nodeRecovered, c.degrades, c.reloads, c.reloadDisconns,
		c.stickyHits, c.stickyMisses, c.forcedRebuilds, c.availableNodes, c.queueDepth,
	)
	return c
}

var (
	defaultMu   sync.RWMutex
	defaultColl = New()
)

// Default returns the process-wide collector. SetDefault exists for tests.
func Default() *Collector {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defaultColl
}

// SetDefault replaces the process-wide collector and returns a restore func.
func SetDefault(c *Collector) func() {
	defaultMu.Lock()
	previous := defaultColl
	if c == nil {
		c = New()
	}
	defaultColl = c
	defaultMu.Unlock()
	return func() {
		defaultMu.Lock()
		defaultColl = previous
		defaultMu.Unlock()
	}
}

// Handler serves Prometheus text exposition.
func (c *Collector) Handler() http.Handler {
	return promhttp.HandlerFor(c.reg, promhttp.HandlerOpts{})
}

func (c *Collector) second(now int64) *secondStats {
	idx := now % windowSeconds
	if c.seconds[idx].stamp != now {
		c.seconds[idx] = newSecondStats(now)
	}
	return &c.seconds[idx]
}

func (c *Collector) addEvent(ev Event) {
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}
	if len(c.events) >= defaultEvents {
		copy(c.events, c.events[1:])
		c.events = c.events[:len(c.events)-1]
	}
	c.events = append(c.events, ev)
}

func bucketIndex(ms float64) int {
	for i, upper := range durationBuckets {
		if ms <= upper {
			return i
		}
	}
	return len(durationBuckets) - 1
}

// IncRequest records one client request.
func (c *Collector) IncRequest() {
	c.requests.Inc()
	c.mu.Lock()
	c.second(time.Now().Unix()).requests++
	c.mu.Unlock()
}

// IncFirstTrySuccess records a request that needed no reroute.
func (c *Collector) IncFirstTrySuccess() { c.firstTrySuccess.Inc() }

// ObserveE2E records end-to-end latency in milliseconds.
func (c *Collector) ObserveE2E(ms float64) { c.e2eDuration.Observe(ms) }

// IncClientVisibleFailure records a failure the caller actually observed.
func (c *Collector) IncClientVisibleFailure() {
	c.failures.Inc()
	c.mu.Lock()
	c.second(time.Now().Unix()).failures++
	c.mu.Unlock()
}

// IncRerouteExhausted records a reroute that ran out of switch budget.
func (c *Collector) IncRerouteExhausted() { c.rerouteExhausted.Inc() }

// RecordReroute records one successful move to a different node.
func (c *Collector) RecordReroute(from, to, reason, protocol, pool string, durationMs float64) {
	c.rerouteTotal.WithLabelValues(from, to, reason, protocol, pool).Inc()
	c.rerouteDuration.WithLabelValues(protocol, pool).Observe(durationMs)
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.second(time.Now().Unix())
	s.reroutes++
	s.durSum += durationMs
	s.durCount++
	if durationMs > s.durMax {
		s.durMax = durationMs
	}
	s.hist[bucketIndex(durationMs)]++
	n := c.nodes[to]
	if n == nil {
		n = &nodeAccum{Tag: to}
		c.nodes[to] = n
	}
	n.RerouteTotal++
	n.DurationSum += durationMs
	n.DurationCount++
	c.addEvent(Event{Type: "reroute", From: from, To: to, Reason: reason, Protocol: protocol, Pool: pool, Duration: durationMs})
}

// RecordRerouteAttempt records a move to another node that did not succeed.
// It counts as a reroute but is deliberately excluded from duration statistics.
func (c *Collector) RecordRerouteAttempt(from, to, reason, protocol, pool string) {
	c.rerouteTotal.WithLabelValues(from, to, reason, protocol, pool).Inc()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.second(time.Now().Unix()).reroutes++
	c.addEvent(Event{Type: "reroute_failed", From: from, To: to, Reason: reason, Protocol: protocol, Pool: pool})
}

// RecordCircuitTransition records a breaker state change.
func (c *Collector) RecordCircuitTransition(node, from, to string) {
	c.circuitTransition.WithLabelValues(node, from, to).Inc()
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.node(node)
	n.CircuitState = to
	c.addEvent(Event{Type: "circuit", From: from, To: to, Detail: node})
}

// RecordHalfOpenProbe records a half-open probe result.
func (c *Collector) RecordHalfOpenProbe(node, result string) {
	c.halfOpenProbe.WithLabelValues(node, result).Inc()
}

func (c *Collector) node(tag string) *nodeAccum {
	n := c.nodes[tag]
	if n == nil {
		n = &nodeAccum{Tag: tag}
		c.nodes[tag] = n
	}
	return n
}

// IncNodeEvicted records a node removed from selection.
func (c *Collector) IncNodeEvicted(tag string) {
	c.nodeEvicted.Inc()
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.second(time.Now().Unix())
	s.evictions++
	c.node(tag).Evictions++
	c.addEvent(Event{Type: "node_evicted", To: tag})
}

// IncNodeRecovered records a node returned to selection.
func (c *Collector) IncNodeRecovered(tag string) {
	c.nodeRecovered.Inc()
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.second(time.Now().Unix())
	s.recoveries++
	c.node(tag).Recoveries++
	c.addEvent(Event{Type: "node_recovered", To: tag})
}

// IncDegrade records a fallback activation.
func (c *Collector) IncDegrade(reason string) {
	c.degrades.Inc()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.second(time.Now().Unix()).degrades++
	c.addEvent(Event{Type: "degrade", Reason: reason})
}

// IncReload records a core reload and its forcibly closed connections.
func (c *Collector) IncReload(disconnected int) {
	c.reloads.Inc()
	if disconnected > 0 {
		c.reloadDisconns.Add(float64(disconnected))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.second(time.Now().Unix())
	s.reloads++
	s.disconns += int64(disconnected)
	c.addEvent(Event{Type: "reload", Detail: "disconnected=" + itoa(disconnected)})
}

// IncStickyHit / IncStickyMiss track session binding reuse.
func (c *Collector) IncStickyHit()  { c.stickyHits.Inc() }
func (c *Collector) IncStickyMiss() { c.stickyMisses.Inc() }

// IncForcedConnRebuild records a long-lived connection rebuilt because of
// a reload or upstream failure. This is the inverse of zero-perception.
func (c *Collector) IncForcedConnRebuild() { c.forcedRebuilds.Inc() }

// SetAvailableNodes / SetQueueDepth publish pool gauges.
func (c *Collector) SetAvailableNodes(n int) { c.availableNodes.Set(float64(n)) }
func (c *Collector) SetQueueDepth(n int)     { c.queueDepth.Set(float64(n)) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func quantile(hist []uint64, q float64) float64 {
	var total uint64
	for _, v := range hist {
		total += v
	}
	if total == 0 {
		return 0
	}
	target := float64(total) * q
	lower := 0.0
	var cumulative uint64
	for i, v := range hist {
		prev := cumulative
		cumulative += v
		upper := durationBuckets[i]
		if float64(cumulative) < target {
			lower = upper
			continue
		}
		within := v
		if within == 0 {
			return upper
		}
		fraction := (target - float64(prev)) / float64(within)
		if fraction < 0 {
			fraction = 0
		}
		if fraction > 1 {
			fraction = 1
		}
		return lower + (upper-lower)*fraction
	}
	return durationBuckets[len(durationBuckets)-1]
}

// Snapshot aggregates the requested window into a UI-friendly payload.
func (c *Collector) Snapshot(window time.Duration) SnapshotData {
	if window <= 0 || window > time.Hour {
		window = time.Minute
	}
	now := time.Now().Unix()
	from := now - int64(window/time.Second)
	label := window.String()

	c.mu.Lock()
	defer c.mu.Unlock()

	var requests, failures, reroutes int64
	var durSum, durMax float64
	var durCount int64
	hist := make([]uint64, len(durationBuckets))
	var degrades, evictions, recoveries, reloads, disconns int64
	series := make([]SeriesPoint, 0, 64)
	for i := 0; i < windowSeconds; i++ {
		s := c.seconds[i]
		if s.stamp == 0 || s.stamp < from || s.stamp > now {
			continue
		}
		requests += s.requests
		failures += s.failures
		reroutes += s.reroutes
		durSum += s.durSum
		durCount += s.durCount
		if s.durMax > durMax {
			durMax = s.durMax
		}
		for j, v := range s.hist {
			hist[j] += v
		}
		degrades += s.degrades
		evictions += s.evictions
		recoveries += s.recoveries
		reloads += s.reloads
		disconns += s.disconns
		if window <= 5*time.Minute && s.stamp%5 == 0 {
			avg := 0.0
			if s.durCount > 0 {
				avg = s.durSum / float64(s.durCount)
			}
			series = append(series, SeriesPoint{TS: s.stamp, Reroutes: s.reroutes, AvgMs: avg, Failures: s.failures})
		}
	}

	avg := 0.0
	if durCount > 0 {
		avg = durSum / float64(durCount)
	}
	successRate, visibleRate, rerouteRate := 0.0, 0.0, 0.0
	if requests > 0 {
		successRate = float64(requests-failures) / float64(requests)
		visibleRate = float64(failures) / float64(requests)
		rerouteRate = float64(reroutes) / float64(requests)
	}
	stickyRate := 0.0
	hits := counterValue(c.stickyHits)
	misses := counterValue(c.stickyMisses)
	if hits+misses > 0 {
		stickyRate = hits / (hits + misses)
	}

	nodes := make([]nodeAccum, 0, len(c.nodes))
	for _, n := range c.nodes {
		copy := *n
		if copy.DurationCount > 0 {
			copy.AvgMs = copy.DurationSum / float64(copy.DurationCount)
		}
		nodes = append(nodes, copy)
	}
	sortNodes(nodes)

	events := make([]Event, len(c.events))
	copy(events, c.events)

	return SnapshotData{
		Summary: Summary{
			Window:                   label,
			Requests:                 requests,
			Failures:                 failures,
			SuccessRate:              successRate,
			ClientVisibleFailureRate: visibleRate,
			RerouteTotal:             reroutes,
			RerouteRate:              rerouteRate,
			RerouteAvgMs:             avg,
			RerouteP95Ms:             quantile(hist, 0.95),
			RerouteP99Ms:             quantile(hist, 0.99),
			RerouteMaxMs:             durMax,
			RerouteExhausted:         int64(counterValue(c.rerouteExhausted)),
			CircuitTransitions:       int64(c.gatherVec("proxy_circuit_transitions_total", nil)),
			HalfOpenSuccess:          int64(c.gatherVec("proxy_half_open_probes_total", map[string]string{"result": "success"})),
			HalfOpenFailure:          int64(c.gatherVec("proxy_half_open_probes_total", map[string]string{"result": "failure"})),
			NodeEvictions:            evictions,
			NodeRecoveries:           recoveries,
			Degrades:                 degrades,
			Reloads:                  reloads,
			ReloadDisconnectedConns:  disconns,
			AvailableNodes:           gaugeValue(c.availableNodes),
			QueueDepth:               gaugeValue(c.queueDepth),
			StickyHitRate:            stickyRate,
			ForcedConnRebuilds:       int64(counterValue(c.forcedRebuilds)),
		},
		ByNode: nodes,
		Events: events,
		Series: series,
	}
}

func sortNodes(nodes []nodeAccum) {
	for i := 1; i < len(nodes); i++ {
		for j := i; j > 0 && nodes[j].RerouteTotal > nodes[j-1].RerouteTotal; j-- {
			nodes[j], nodes[j-1] = nodes[j-1], nodes[j]
		}
	}
}

// ParseWindow converts the UI window query into a duration.
func ParseWindow(value string) time.Duration {
	switch value {
	case "5m":
		return 5 * time.Minute
	case "1h":
		return time.Hour
	default:
		return time.Minute
	}
}
