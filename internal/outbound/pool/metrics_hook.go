package pool

import "strings"

// failureReason maps a dial error to the stable reason labels used by the
// reroute metrics. It is deliberately separate from classifyFailure: the
// latter drives blacklisting, this one drives observability only.
func failureReason(err error) string {
	if err == nil {
		return "dial_failed"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "429"), strings.Contains(msg, "rate limit"), strings.Contains(msg, "ratelimit"):
		return "rate_limited"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "no healthy"), strings.Contains(msg, "unavailable"):
		return "node_unavailable"
	case strings.Contains(msg, "reset"), strings.Contains(msg, "refused"):
		return "connection_reset"
	default:
		return "dial_failed"
	}
}
