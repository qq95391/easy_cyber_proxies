package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"easy_proxies/internal/accounts"
	"easy_proxies/internal/boxmgr"
	"easy_proxies/internal/config"
	"easy_proxies/internal/ext"
	"easy_proxies/internal/logs"
	"easy_proxies/internal/monitor"
	"easy_proxies/internal/quality"
	"easy_proxies/internal/subscription"
)

// Run builds the runtime components from config and blocks until shutdown.
func Run(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("application requires config")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Structured log detail follows the configured log level. DEBUG enables
	// per-node verification detail; INFO keeps only bounded aggregates.
	logs.Default().SetMinLevel(logs.ParseLevel(cfg.LogLevel))
	// Strict-verification results survive restarts; a missing sidecar is normal.
	if path := cfg.NodeQualityPath(); path != "" {
		if err := quality.Default().Load(path); err != nil {
			fmt.Printf("[quality] load failed: %v\n", err)
		}
	}
	// Build extension sources before the first sing-box build so freshly
	// collected nodes are included in the initial runtime configuration.
	extMgr := ext.New(cfg)
	if extMgr.Enabled() {
		if extNodes, err := extMgr.InitialNodes(ctx); err != nil {
			fmt.Printf("[extension] initial fetch: %v\n", err)
		} else if len(extNodes) > 0 {
			cfg.Nodes = append(cfg.Nodes, extNodes...)
		}
	}
	// Load independent accounts before the first sing-box build so their pool
	// rules are part of the initial routing snapshot.
	if store, err := accounts.Load(cfg.AccountsPath()); err != nil {
		fmt.Printf("[accounts] load failed: %v\n", err)
	} else {
		accounts.SetDefault(store)
	}

	// Build monitor config
	proxyUsername := cfg.Listener.Username
	proxyPassword := cfg.Listener.Password
	if config.ModeDualStack == "multi-port" || config.ModeDualStack == "hybrid" {
		proxyUsername = cfg.MultiPort.Username
		proxyPassword = cfg.MultiPort.Password
	}

	monitorCfg := monitor.Config{
		Enabled:          cfg.ManagementEnabled(),
		Listen:           cfg.Management.Listen,
		ProbeTarget:      cfg.Management.ProbeTarget,
		Password:         cfg.Management.Password,
		ProxyUsername:    proxyUsername,
		ProxyPassword:    proxyPassword,
		ExternalIP:       cfg.ExternalIP,
		ProbeConcurrency: cfg.ProbeConcurrencyOrDefault(),
	}
	if extMgr.Enabled() {
		// Inject before Start(): the box manager may block waiting for its
		// first health check when no upstream node is reachable yet.
		monitorCfg.ExtensionHandler = extMgr
		monitorCfg.ExtensionMeta = extMgr
	}

	// Create and start BoxManager
	boxMgr := boxmgr.New(cfg, monitorCfg)
	if err := boxMgr.Start(ctx); err != nil {
		_ = boxMgr.Close()
		return fmt.Errorf("start box manager: %w", err)
	}
	defer boxMgr.Close()

	// Wire up config to monitor server for settings API
	if server := boxMgr.MonitorServer(); server != nil {
		server.SetConfig(cfg)
	}

	// Always create SubscriptionManager so WebUI can hot-reload subscription config
	subMgr := subscription.New(cfg, boxMgr)
	defer subMgr.Stop()

	// Keep the manual-refresh worker available even when the periodic timer is
	// disabled or URLs are configured later through the management interface.
	subMgr.Start()

	// Wire up subscription manager to monitor server for API endpoints
	if server := boxMgr.MonitorServer(); server != nil {
		server.SetSubscriptionRefresher(subMgr)
	}

	// Extension sources publish freshly verified nodes through the same
	// runtime reload path, and reuse the existing management server.
	if extMgr.Enabled() {
		extMgr.SetRuntime(boxMgr)
		if server := boxMgr.MonitorServer(); server != nil {
			server.SetExtensionHandler(extMgr)
		}
		extMgr.Start(ctx)
		defer extMgr.Stop()
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-ctx.Done():
		fmt.Println("Context cancelled, initiating graceful shutdown...")
	case sig := <-sigCh:
		fmt.Printf("Received %s, initiating graceful shutdown...\n", sig)
	}

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Graceful shutdown sequence
	if extMgr.Enabled() {
		fmt.Println("Stopping extension orchestrator...")
		extMgr.Stop()
	}

	fmt.Println("Stopping subscription manager...")
	if subMgr != nil {
		subMgr.Stop()
	}

	fmt.Println("Stopping box manager...")
	if err := boxMgr.Close(); err != nil {
		fmt.Printf("Error closing box manager: %v\n", err)
	}

	// Wait for connections to drain
	fmt.Println("Waiting for connections to drain...")
	select {
	case <-time.After(2 * time.Second):
		fmt.Println("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		fmt.Println("Shutdown timeout exceeded, forcing exit")
	}

	return nil
}
