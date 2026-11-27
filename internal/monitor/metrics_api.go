package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"easy_proxies/internal/metrics"
	"easy_proxies/internal/verify"
)

// metricsEnvelope flattens runtime stats next to the collector snapshot.
type metricsEnvelope struct {
	metrics.SnapshotData
	VerifyInflight      int64 `json:"verify_inflight"`
	VerifyDialAbandoned int64 `json:"verify_dial_abandoned"`
	VerifyDialHarvested int64 `json:"verify_dial_harvested"`
	OpenFileDescriptors int   `json:"open_fds"`
}

// withRuntimeStats merges process/socket counters that the metrics collector
// does not own. Leaked verification sockets are otherwise invisible in the UI.
func withRuntimeStats(snapshot metrics.SnapshotData) any {
	inflight, abandoned, harvested := verify.DialStats()
	return metricsEnvelope{
		SnapshotData:        snapshot,
		VerifyInflight:      inflight,
		VerifyDialAbandoned: abandoned,
		VerifyDialHarvested: harvested,
		OpenFileDescriptors: openFileDescriptors(),
	}
}

// OpenFileDescriptors exposes the process fd count for the fd watermark watcher.
func OpenFileDescriptors() int { return openFileDescriptors() }

// openFileDescriptors returns the process fd count on Linux and 0 elsewhere.
func openFileDescriptors() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}

// handleMetrics serves the windowed reliability snapshot consumed by the UI.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.mgr != nil {
		available := 0
		for _, node := range s.mgr.Snapshot() {
			if node.Available && !node.Blacklisted {
				available++
			}
		}
		metrics.Default().SetAvailableNodes(available)
	}
	window := metrics.ParseWindow(r.URL.Query().Get("window"))
	writeJSON(w, withRuntimeStats(metrics.Default().Snapshot(window)))
}

// handleMetricsStream pushes the same snapshot over SSE. Browsers pause the
// stream on hidden tabs; the request context and server lifecycle both cancel it.
func (s *Server) handleMetricsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeStatusJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			payload, err := json.Marshal(withRuntimeStats(metrics.Default().Snapshot(time.Minute)))
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
