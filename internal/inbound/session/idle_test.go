package session

import (
	"net"
	"testing"
	"time"
)

func TestIdleReaperClosesSilentConnection(t *testing.T) {
	reg := newConnRegistry(50 * time.Millisecond)
	server, client := net.Pipe()
	defer client.Close()

	wrapped := reg.wrap(server)
	if got := reg.current.Load(); got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := wrapped.Read(buf)
		readErr <- err
	}()

	time.Sleep(80 * time.Millisecond)
	if closed := reg.reapOnce(time.Now()); closed != 1 {
		t.Fatalf("reapOnce closed %d connections, want 1", closed)
	}

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("blocked read should fail after the idle close")
		}
	case <-time.After(time.Second):
		t.Fatal("idle close did not unblock the reader")
	}
	if got := reg.current.Load(); got != 0 {
		t.Fatalf("active = %d after reap, want 0", got)
	}
}

func TestIdleReaperKeepsActiveConnection(t *testing.T) {
	reg := newConnRegistry(150 * time.Millisecond)
	server, client := net.Pipe()
	defer client.Close()

	wrapped := reg.wrap(server)
	defer wrapped.Close()

	reg.mu.Lock()
	var entry *connEntry
	for _, item := range reg.conns {
		entry = item
	}
	reg.mu.Unlock()
	entry.touch()

	if closed := reg.reapOnce(time.Now()); closed != 0 {
		t.Fatalf("recent activity must not be reaped, closed=%d", closed)
	}

	time.Sleep(200 * time.Millisecond)
	if closed := reg.reapOnce(time.Now()); closed != 1 {
		t.Fatalf("stale connection must be reaped, closed=%d", closed)
	}
}

func TestIdleDisabledNeverReaps(t *testing.T) {
	reg := newConnRegistry(0)
	server, client := net.Pipe()
	defer client.Close()
	wrapped := reg.wrap(server)
	defer wrapped.Close()

	time.Sleep(50 * time.Millisecond)
	if closed := reg.reapOnce(time.Now()); closed != 0 {
		t.Fatalf("disabled reaper closed %d connections", closed)
	}
}

func TestConnStatsTrackActiveAndTotal(t *testing.T) {
	reg := newConnRegistry(time.Minute)
	var wrapped []net.Conn
	var peers []net.Conn
	for i := 0; i < 3; i++ {
		server, client := net.Pipe()
		wrapped = append(wrapped, reg.wrap(server))
		peers = append(peers, client)
	}
	defer func() {
		for _, conn := range peers {
			_ = conn.Close()
		}
	}()

	if got := reg.total.Load(); got != 3 {
		t.Fatalf("total = %d, want 3", got)
	}
	if got := reg.current.Load(); got != 3 {
		t.Fatalf("active = %d, want 3", got)
	}

	_ = wrapped[0].Close()
	_ = wrapped[1].Close()
	if got := reg.current.Load(); got != 1 {
		t.Fatalf("active = %d after two closes, want 1", got)
	}
	if got := reg.total.Load(); got != 3 {
		t.Fatalf("total must not change on close, got %d", got)
	}

	// A second Close on the same connection must not double-decrement.
	_ = wrapped[0].Close()
	if got := reg.current.Load(); got != 1 {
		t.Fatalf("active = %d after duplicate close, want 1", got)
	}
}

func TestReapIntervalBounds(t *testing.T) {
	if got := reapInterval(0); got != maxReapInterval {
		t.Fatalf("disabled interval = %v", got)
	}
	if got := reapInterval(20 * time.Minute); got != maxReapInterval {
		t.Fatalf("long timeout interval = %v, want cap %v", got, maxReapInterval)
	}
	if got := reapInterval(100 * time.Millisecond); got < minReapInterval {
		t.Fatalf("short timeout interval = %v, below floor %v", got, minReapInterval)
	}
}
