package app

import (
	"context"
	"fmt"
	"time"

	"easy_proxies/internal/logs"
	"easy_proxies/internal/monitor"
)

// fdWarnThreshold is a soft watermark: crossing it usually means upstream
// sockets (for example leaked verification dials) are not being released.
const fdWarnThreshold = 4096

// watchFileDescriptors logs a warning when the process fd count stays above the
// watermark. It only observes; it never restarts the core or drops connections.
func watchFileDescriptors(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fds := monitor.OpenFileDescriptors()
			if fds <= 0 {
				continue
			}
			if fds >= fdWarnThreshold && !warned {
				warned = true
				message := fmt.Sprintf("open file descriptors=%d (threshold %d); check for leaked upstream sockets", fds, fdWarnThreshold)
				fmt.Printf("[warn] %s\n", message)
				logs.Default().Add(logs.Entry{
					Level: logs.LevelWarn, Category: "conn", Message: message,
					Fields: map[string]any{"open_fds": fds, "threshold": fdWarnThreshold},
				})
			} else if fds < fdWarnThreshold/2 {
				warned = false
			}
		}
	}
}
