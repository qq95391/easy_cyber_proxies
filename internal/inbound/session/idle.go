package session

import (
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"easy_proxies/internal/logs"
)

const (
	defaultIdleTimeout = 20 * time.Minute
	minReapInterval    = 50 * time.Millisecond
	maxReapInterval    = 15 * time.Second
	statsLogInterval   = 60 * time.Second
)

// connEntry tracks one accepted client connection. lastSeen is refreshed on
// every byte transferred, so only truly idle (zero-byte) connections expire.
type connEntry struct {
	id        uint64
	peer      string
	goroutine uint64
	opened    time.Time
	lastSeen  atomic.Int64 // unix nano
	conn      net.Conn
	closed    atomic.Bool
}

func (e *connEntry) touch() {
	e.lastSeen.Store(time.Now().UnixNano())
}

func (e *connEntry) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, e.lastSeen.Load()))
}

// connRegistry keeps the live connection set plus aggregate counters. The
// reaper scans this map instead of spawning a goroutine per connection.
type connRegistry struct {
	idle    atomic.Int64 // nanoseconds; 0 disables reaping
	seq     atomic.Uint64
	current atomic.Int64
	total   atomic.Uint64
	mu      sync.Mutex
	conns   map[uint64]*connEntry
	started sync.Once
}

var connStats = newConnRegistry(defaultIdleTimeout)

func newConnRegistry(idle time.Duration) *connRegistry {
	r := &connRegistry{conns: make(map[uint64]*connEntry)}
	if idle < 0 {
		idle = 0
	}
	r.idle.Store(int64(idle))
	return r
}

// ConfigureIdleTimeout installs the configured timeout and starts the shared
// reaper exactly once. Called for every inbound rebuild, so a reload can change
// the timeout without spawning extra goroutines.
func ConfigureIdleTimeout(idle time.Duration) {
	if idle < 0 {
		idle = 0
	}
	connStats.idle.Store(int64(idle))
	connStats.started.Do(func() { go connStats.reaper() })
}

// wrapIdleConn registers the connection and returns an activity-tracking
// wrapper. Registration happens even when the timeout is disabled so the
// active/total counters stay accurate.
func wrapIdleConn(conn net.Conn) net.Conn {
	return connStats.wrap(conn)
}

func (r *connRegistry) timeout() time.Duration {
	return time.Duration(r.idle.Load())
}

func (r *connRegistry) wrap(conn net.Conn) net.Conn {
	if conn == nil {
		return conn
	}
	peer := ""
	if addr := conn.RemoteAddr(); addr != nil {
		peer = addr.String()
	}
	entry := &connEntry{
		id:        r.seq.Add(1),
		peer:      peer,
		goroutine: currentGoroutineID(),
		opened:    time.Now(),
		conn:      conn,
	}
	entry.touch()

	r.mu.Lock()
	r.conns[entry.id] = entry
	r.mu.Unlock()
	active := r.current.Add(1)
	total := r.total.Add(1)

	logs.Default().Add(logs.Entry{
		Level: logs.LevelDebug, Category: "conn", Source: peer,
		Message: "connection open",
		Fields: map[string]any{
			"conn_id": entry.id, "goroutine": entry.goroutine, "peer": peer,
			"active": active, "total": total, "idle_timeout": r.timeout().String(),
		},
	})
	return &idleConn{Conn: conn, reg: r, entry: entry}
}

func (r *connRegistry) remove(entry *connEntry, reason string) {
	if entry == nil || !entry.closed.CompareAndSwap(false, true) {
		return
	}
	r.mu.Lock()
	delete(r.conns, entry.id)
	r.mu.Unlock()

	active := r.current.Add(-1)
	level := logs.LevelInfo
	if reason == "idle" {
		level = logs.LevelWarn
	}
	now := time.Now()
	logs.Default().Add(logs.Entry{
		Level: level, Category: "conn", Source: entry.peer,
		Message: "connection " + reason,
		Fields: map[string]any{
			"conn_id": entry.id, "goroutine": entry.goroutine, "peer": entry.peer,
			"duration_ms": now.Sub(entry.opened).Milliseconds(),
			"idle_ms":     entry.idleFor(now).Milliseconds(),
			"active":      active, "total": r.total.Load(), "reason": reason,
		},
	})
}

// reapOnce closes connections whose last activity is older than the timeout.
// Exported behaviour is exercised deterministically in tests.
func (r *connRegistry) reapOnce(now time.Time) int {
	timeout := r.timeout()
	if timeout <= 0 {
		return 0
	}
	var stale []*connEntry
	r.mu.Lock()
	for _, entry := range r.conns {
		if entry.idleFor(now) >= timeout {
			stale = append(stale, entry)
		}
	}
	r.mu.Unlock()

	for _, entry := range stale {
		r.remove(entry, "idle")
		_ = entry.conn.Close()
	}
	return len(stale)
}

func (r *connRegistry) logStats() {
	active := r.current.Load()
	total := r.total.Load()
	logs.Default().Add(logs.Entry{
		Level: logs.LevelInfo, Category: "conn",
		Message: "connections active=" + strconv.FormatInt(active, 10) + " total=" + strconv.FormatUint(total, 10),
		Fields: map[string]any{
			"active": active, "total": total, "idle_timeout": r.timeout().String(),
		},
	})
}

func (r *connRegistry) reaper() {
	interval := reapInterval(r.timeout())
	lastStats := time.Now()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for now := range ticker.C {
		if r.timeout() > 0 {
			r.reapOnce(now)
		}
		if now.Sub(lastStats) >= statsLogInterval {
			lastStats = now
			r.logStats()
		}
	}
}

func reapInterval(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return maxReapInterval
	}
	interval := timeout / 4
	if interval < minReapInterval {
		interval = minReapInterval
	}
	if interval > maxReapInterval {
		interval = maxReapInterval
	}
	return interval
}

// currentGoroutineID is used as the "thread id" in logs; Go schedules
// goroutines on threads, so this is the closest stable identifier.
func currentGoroutineID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	text := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	if idx := strings.IndexByte(text, ' '); idx > 0 {
		text = text[:idx]
	}
	id, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// idleConn refreshes activity on every successful read/write. Half-close
// helpers are forwarded so tunnel teardown keeps working.
type idleConn struct {
	net.Conn
	reg   *connRegistry
	entry *connEntry
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.entry.touch()
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.entry.touch()
	}
	return n, err
}

func (c *idleConn) Close() error {
	c.reg.remove(c.entry, "closed")
	return c.Conn.Close()
}

func (c *idleConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func (c *idleConn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return nil
}
