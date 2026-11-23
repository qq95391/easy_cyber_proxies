package pool

import (
	"context"
	"fmt"

	"easy_proxies/internal/logs"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// logAccess records one connection-level entry (Clash/Zashboard style): who
// accessed which domain or IP through which upstream node, and the outcome.
// Target domains are intentionally kept verbatim; credentials are never used.
func logAccess(ctx context.Context, network string, destination M.Socksaddr, node, result string, attempt int, errText string, elapsedMs float64) {
	client, user, inbound := "", "", ""
	if md := adapter.ContextFrom(ctx); md != nil {
		if md.Source.IsValid() {
			client = md.Source.String()
		}
		user = md.User
		inbound = md.InboundType
	}
	target := destination.String()
	fields := map[string]any{
		"client": client, "user": user, "target": target, "node": node,
		"network": network, "inbound": inbound, "attempt": attempt,
		"result": result, "elapsed_ms": elapsedMs,
	}
	if errText != "" {
		fields["error"] = logs.SanitizeError(errText)
	}
	level := logs.LevelInfo
	if result != "ok" {
		level = logs.LevelWarn
	}
	logs.Default().Add(logs.Entry{
		Level: level, Category: "access", Source: node,
		Message: fmt.Sprintf("%s %s -> %s via %s %s", network, user, target, node, result),
		Fields:  fields,
	})
}

func logReroute(from, to, reason, protocol string, elapsedMs float64) {
	logs.Default().Add(logs.Entry{
		Level: logs.LevelInfo, Category: "reroute", Source: to,
		Message: fmt.Sprintf("reroute %s -> %s reason=%s %.1fms", from, to, reason, elapsedMs),
		Fields: map[string]any{
			"from": from, "to": to, "reason": reason,
			"protocol": protocol, "elapsed_ms": elapsedMs,
		},
	})
}

func logCircuitTransition(node, from, to string) {
	level := logs.LevelInfo
	if to == "open" {
		level = logs.LevelWarn
	}
	logs.Default().Add(logs.Entry{
		Level: level, Category: "circuit", Source: node,
		Message: fmt.Sprintf("circuit %s: %s -> %s", node, from, to),
		Fields:  map[string]any{"from": from, "to": to},
	})
}
