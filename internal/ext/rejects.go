package ext

import "time"

const rejectRingSize = 200

// negEntry suppresses a candidate until the given time.
type negEntry struct {
	until  time.Time
	reason string
}

// RejectRecord is one per-node verification rejection kept for diagnostics.
// It never contains credentials: node is the display name, error is sanitized.
type RejectRecord struct {
	At        string `json:"at"`
	Node      string `json:"node"`
	Reason    string `json:"reason"`
	Score     int    `json:"score"`
	MinScore  int    `json:"min_score"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error,omitempty"`
}

// negativeCacheTTL keeps a persistently bad candidate out of the dial path for
// a while. Timeouts are short (the node may recover), hard rejections are long.
func negativeCacheTTL(reason string) time.Duration {
	switch reason {
	case "timeout":
		return 10 * time.Minute
	case "unreachable":
		return 30 * time.Minute
	case "score_below_min":
		return time.Hour
	case "mitm", "authenticity":
		return 24 * time.Hour
	default:
		return 10 * time.Minute
	}
}

func (o *Orchestrator) appendRejectLocked(record RejectRecord) {
	if len(o.rejects) >= rejectRingSize {
		copy(o.rejects, o.rejects[1:])
		o.rejects[len(o.rejects)-1] = record
		return
	}
	o.rejects = append(o.rejects, record)
}

// RecentRejects returns the newest-first copy of the rejection ring.
func (o *Orchestrator) RecentRejects() []RejectRecord {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]RejectRecord, 0, len(o.rejects))
	for i := len(o.rejects) - 1; i >= 0; i-- {
		out = append(out, o.rejects[i])
	}
	return out
}

func (o *Orchestrator) pruneNegCacheLocked(now time.Time) {
	for key, entry := range o.negCache {
		if !now.Before(entry.until) {
			delete(o.negCache, key)
		}
	}
	// Hard cap so a flood of unique candidates cannot grow the map forever.
	if len(o.negCache) > 5000 {
		o.negCache = make(map[string]negEntry)
	}
}
