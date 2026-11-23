// Package ext wires the second-development features into easy_proxies:
// pluggable sources (space-mapping shell + free proxy pool), full-dimension
// verification, runtime publication and the management API.
//
// The WebUI is the upstream single-file console; this package exposes JSON
// endpoints only, so index.html owns all presentation.
package ext

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/config"
	"easy_proxies/internal/logs"
	"easy_proxies/internal/source"
	"easy_proxies/internal/verify"
)

// Runtime is the subset of boxmgr.Manager used to publish refreshed nodes.
type Runtime interface {
	CurrentConfig() *config.Config
	CurrentPortMap() map[string]uint16
	ReloadWithPortMap(*config.Config, map[string]uint16) error
}

// Status is the extension subsystem snapshot exposed via the API.
type Status struct {
	Enabled         bool                      `json:"enabled"`
	LastRefresh     string                    `json:"last_refresh,omitempty"`
	LastError       string                    `json:"last_error,omitempty"`
	Candidates      int                       `json:"candidates"`
	Admitted        int                       `json:"admitted"`
	Providers       []map[string]any          `json:"providers"`
	Plugins         []string                  `json:"plugins"`
	Outcomes        []source.Outcome          `json:"outcomes"`
	Results         []verify.Result           `json:"results"`
	Verification    config.VerificationConfig `json:"verification"`
	RecheckInterval string                    `json:"recheck_interval"`
	CacheFile       string                    `json:"cache_file"`
}

// runtimeParts is an immutable snapshot of the hot-swappable components.
// ApplyConfig replaces them under the same lock, so readers never observe a
// half-updated configuration.
type runtimeParts struct {
	ext      config.ExtensionConfig
	registry *source.Registry
	verifier *verify.Verifier
}

// Orchestrator owns sources, verification, caching and runtime publication.
type Orchestrator struct {
	// cfg is read-only here: it supplies the config file path and listener
	// credentials. The live extension section lives in ext below.
	cfg *config.Config

	mu          sync.RWMutex
	ext         config.ExtensionConfig
	registry    *source.Registry
	verifier    *verify.Verifier
	runtime     Runtime
	results     map[string]verify.Result
	failures    map[string]int
	admitted    []config.NodeConfig
	candidates  int
	outcomes    []source.Outcome
	lastRefresh time.Time
	lastError   string
	lastFetch   map[string]time.Time
	running     bool

	refreshMu sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func buildRegistry(ext config.ExtensionConfig) *source.Registry {
	client := source.NewOutboundClient(ext, config.ParseDuration(ext.Mapping.Timeout, 20*time.Second))
	registry := source.NewRegistry()
	for _, p := range source.NewMappingProviders(ext.Mapping, client) {
		registry.Register(p)
	}
	registry.Register(source.NewFreePoolProvider(ext.FreePool, client))
	return registry
}

// New builds the orchestrator. It performs no network activity.
func New(cfg *config.Config) *Orchestrator {
	if cfg == nil {
		cfg = &config.Config{}
	}
	ext := cfg.Extension
	ext.Mapping.Presets = source.EnsureMappingPresets(ext.Mapping.Presets)
	return &Orchestrator{
		cfg:       cfg,
		ext:       ext,
		registry:  buildRegistry(ext),
		verifier:  verify.New(ext.Verification),
		results:   make(map[string]verify.Result),
		failures:  make(map[string]int),
		lastFetch: make(map[string]time.Time),
	}
}

func (o *Orchestrator) parts() runtimeParts {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return runtimeParts{ext: o.ext, registry: o.registry, verifier: o.verifier}
}

// SetRuntime injects the box manager after it has started.
func (o *Orchestrator) SetRuntime(r Runtime) {
	o.mu.Lock()
	o.runtime = r
	o.mu.Unlock()
}

// Enabled reports whether extensions are active.
func (o *Orchestrator) Enabled() bool { return o.parts().ext.Enabled }

func cachePathOf(ext config.ExtensionConfig) string {
	name := strings.TrimSpace(ext.CacheFile)
	if name == "" {
		name = "extension_nodes.txt"
	}
	return name
}

func (o *Orchestrator) cachePath() string { return cachePathOf(o.parts().ext) }

// InitialNodes is called before boxmgr starts, so extension nodes can be
// included in the very first runtime build. On a cold/failed fetch it falls
// back to the on-disk cache.
func (o *Orchestrator) InitialNodes(ctx context.Context) ([]config.NodeConfig, error) {
	if !o.parts().ext.Enabled {
		return nil, nil
	}
	nodes, err := o.refresh(ctx, nil)
	if len(nodes) > 0 {
		return nodes, nil
	}
	cached, cacheErr := o.loadCache()
	if cacheErr == nil && len(cached) > 0 {
		o.mu.Lock()
		o.admitted = append([]config.NodeConfig(nil), cached...)
		o.mu.Unlock()
		return cached, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// Start launches per-source scheduling and periodic rechecks.
func (o *Orchestrator) Start(ctx context.Context) {
	if !o.parts().ext.Enabled {
		return
	}
	o.mu.Lock()
	if o.running {
		o.mu.Unlock()
		return
	}
	o.running = true
	o.ctx, o.cancel = context.WithCancel(ctx)
	o.mu.Unlock()

	o.wg.Add(1)
	go o.loop()
}

// Stop terminates background work.
func (o *Orchestrator) Stop() {
	o.mu.RLock()
	cancel := o.cancel
	running := o.running
	o.mu.RUnlock()
	if !running || cancel == nil {
		return
	}
	cancel()
	o.wg.Wait()
	o.mu.Lock()
	o.running = false
	o.mu.Unlock()
}

func (o *Orchestrator) loop() {
	defer o.wg.Done()
	scheduler := time.NewTicker(time.Minute)
	defer scheduler.Stop()
	var lastRecheck time.Time
	for {
		select {
		case <-o.ctx.Done():
			return
		case <-scheduler.C:
			p := o.parts()
			filter := func(pr source.Provider) bool { return o.due(pr.Name(), p.ext) }
			if _, err := o.refresh(o.ctx, filter); err != nil {
				log.Printf("[extension] scheduled refresh: %v", err)
			}
			if p.ext.Verification.Enabled {
				interval := config.ParseDuration(p.ext.Verification.RecheckInterval, 10*time.Minute)
				if time.Since(lastRecheck) >= interval {
					o.recheck(o.ctx)
					lastRecheck = time.Now()
				}
			}
		}
	}
}

func (o *Orchestrator) intervalFor(name string, ext config.ExtensionConfig) time.Duration {
	if strings.HasPrefix(name, "mapping:") {
		return config.ParseDuration(ext.Mapping.Interval, 6*time.Hour)
	}
	return config.ParseDuration(ext.FreePool.Interval, 5*time.Minute)
}

func (o *Orchestrator) due(name string, ext config.ExtensionConfig) bool {
	o.mu.RLock()
	last := o.lastFetch[name]
	o.mu.RUnlock()
	return time.Since(last) >= o.intervalFor(name, ext)
}

// RefreshNow forces a full collection, verification and publication.
func (o *Orchestrator) RefreshNow(ctx context.Context) (int, error) {
	nodes, err := o.refresh(ctx, nil)
	return len(nodes), err
}

func (o *Orchestrator) refresh(ctx context.Context, filter func(source.Provider) bool) ([]config.NodeConfig, error) {
	o.refreshMu.Lock()
	defer o.refreshMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	p := o.parts()
	concurrency := config.ClampInt(p.ext.FreePool.Concurrency, 4, 1, 32)
	collection := p.registry.Collect(ctx, concurrency, filter)
	admitted, reasons := o.verifyAndFilter(ctx, collection.Nodes, p.verifier, p.ext)
	o.logRefreshSummary(collection, admitted, reasons)
	if err := o.saveCache(admitted); err != nil {
		log.Printf("[extension] cache write: %v", err)
	}

	now := time.Time{}
	for _, out := range collection.Outcomes {
		if out.FetchedAt != "" {
			if parsed, err := time.Parse(time.RFC3339, out.FetchedAt); err == nil && parsed.After(now) {
				now = parsed
			}
		}
	}
	o.mu.Lock()
	o.candidates = len(collection.Nodes)
	o.admitted = append([]config.NodeConfig(nil), admitted...)
	o.outcomes = append([]source.Outcome(nil), collection.Outcomes...)
	if !now.IsZero() {
		o.lastRefresh = now
		for _, out := range collection.Outcomes {
			if out.FetchedAt != "" && out.Error == "" {
				o.lastFetch[out.Provider] = now
			}
		}
	}
	o.lastError = ""
	runtime := o.runtime
	o.mu.Unlock()

	if runtime != nil && len(admitted) > 0 {
		if err := o.applyToRuntime(runtime, admitted); err != nil {
			o.mu.Lock()
			o.lastError = err.Error()
			o.mu.Unlock()
			return admitted, err
		}
	}
	return admitted, nil
}

func (o *Orchestrator) recheck(ctx context.Context) {
	o.refreshMu.Lock()
	defer o.refreshMu.Unlock()
	p := o.parts()
	o.mu.RLock()
	nodes := append([]config.NodeConfig(nil), o.admitted...)
	runtime := o.runtime
	o.mu.RUnlock()
	if len(nodes) == 0 {
		return
	}
	admitted, _ := o.verifyAndFilter(ctx, nodes, p.verifier, p.ext)
	_ = o.saveCache(admitted)
	o.mu.Lock()
	o.admitted = append([]config.NodeConfig(nil), admitted...)
	o.mu.Unlock()
	if runtime != nil && len(admitted) > 0 {
		if err := o.applyToRuntime(runtime, admitted); err != nil {
			log.Printf("[extension] recheck publish: %v", err)
		}
	}
}

func (o *Orchestrator) verifyAndFilter(ctx context.Context, nodes []config.NodeConfig, ver *verify.Verifier, ext config.ExtensionConfig) ([]config.NodeConfig, map[string]int) {
	reasons := make(map[string]int)
	if !ext.Verification.Enabled {
		return append([]config.NodeConfig(nil), nodes...), reasons
	}
	portMap := map[string]uint16{}
	o.mu.RLock()
	runtime := o.runtime
	o.mu.RUnlock()
	if runtime != nil {
		portMap = runtime.CurrentPortMap()
	}
	concurrency := ver.Config().Concurrency
	type job struct {
		node config.NodeConfig
		res  verify.Result
	}
	jobs := make(chan job, len(nodes))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n config.NodeConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			jobs <- job{node: n, res: ver.VerifyNode(ctx, n, o.localURLFor(n, portMap))}
		}(n)
	}
	wg.Wait()
	close(jobs)

	minScore := ver.MinScore()
	maxFailures := ver.MaxFailures()
	authCfg := ext.Verification.Authenticity
	mitmCfg := ext.Verification.MITM
	admitted := make([]config.NodeConfig, 0, len(nodes))
	for j := range jobs {
		key := j.node.NodeKey()
		pass := j.res.Skipped != "" || (j.res.Reachable && j.res.Score >= minScore)
		// Hard gate: candidates that are not real forwarding proxies or that
		// show malicious-MITM signals are not admitted (unless action=mark).
		if j.res.Checks["genuine"] && !j.res.Genuine && actionRejects(authCfg.Action) {
			pass = false
		}
		if j.res.MITMSuspected && actionRejects(mitmCfg.Action) {
			pass = false
		}
		if !pass {
			reason := classifyRejection(j.res, minScore, authCfg, mitmCfg)
			reasons[reason]++
			// Per-node detail stays DEBUG so the default threshold cannot flood
			// the buffer; the INFO summary carries the aggregated distribution.
			logs.Default().Add(logs.Entry{
				Level: logs.LevelDebug, Category: "verify", Source: nodeSourceShort(j.node),
				Message: fmt.Sprintf("rejected %s reason=%s", safeNodeName(j.node), reason),
				Fields: map[string]any{
					"reason": reason, "score": j.res.Score, "min_score": minScore,
					"reachable": j.res.Reachable, "mitm": j.res.MITMSuspected, "genuine": j.res.Genuine,
				},
			})
		}
		o.mu.Lock()
		o.results[key] = j.res
		if pass {
			o.failures[key] = 0
			admitted = append(admitted, j.node)
		} else {
			o.failures[key]++
			if o.failures[key] >= maxFailures {
				delete(o.results, key)
			}
		}
		o.mu.Unlock()
	}
	return admitted, reasons
}

func classifyRejection(res verify.Result, minScore int, authCfg config.AuthenticityConfig, mitmCfg config.MITMConfig) string {
	switch {
	case res.MITMSuspected && actionRejects(mitmCfg.Action):
		return "mitm"
	case res.Checks["genuine"] && !res.Genuine && actionRejects(authCfg.Action):
		return "authenticity"
	case !res.Reachable && isTimeoutText(res.Error):
		return "timeout"
	case !res.Reachable:
		return "unreachable"
	case res.Score < minScore:
		return "score_below_min"
	default:
		return "other"
	}
}

func isTimeoutText(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline")
}

func safeNodeName(n config.NodeConfig) string {
	if n.Name != "" {
		return n.Name
	}
	if n.SourceDetail != "" {
		return n.SourceDetail
	}
	return string(n.Source)
}

// shortSource maps provider names to compact labels used in log summaries.
func shortSource(provider string) string {
	if strings.HasPrefix(provider, "mapping:") {
		return strings.TrimPrefix(provider, "mapping:")
	}
	if provider == "freepool" || strings.HasPrefix(provider, "external:") {
		return "free"
	}
	return provider
}

func nodeSourceShort(n config.NodeConfig) string {
	detail := strings.ToLower(n.SourceDetail)
	for _, name := range []string{"fofa", "hunter", "quake"} {
		if strings.Contains(detail, name) {
			return name
		}
	}
	switch n.Source {
	case config.NodeSourceFreePool, config.NodeSourceExternalPool:
		return "free"
	case config.NodeSourceMapping:
		return "mapping"
	default:
		return "other"
	}
}

func joinCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+":"+strconv.Itoa(counts[key]))
	}
	return strings.Join(parts, ",")
}

// logRefreshSummary emits one bounded INFO line with per-source counts,
// admitted distribution and aggregated rejection reasons, plus sanitized
// provider errors as WARN entries.
func (o *Orchestrator) logRefreshSummary(collection source.Collection, admitted []config.NodeConfig, reasons map[string]int) {
	sources := make(map[string]int)
	admittedBy := make(map[string]int)
	rawTotal := 0
	for _, out := range collection.Outcomes {
		sources[shortSource(out.Provider)] += out.Nodes
		rawTotal += out.Nodes
		if out.Error != "" {
			logs.Default().Add(logs.Entry{
				Level: logs.LevelWarn, Category: "refresh", Source: shortSource(out.Provider),
				Message: "provider failed: " + logs.SanitizeError(out.Error),
			})
		}
	}
	for _, n := range admitted {
		admittedBy[nodeSourceShort(n)]++
	}
	deduped := rawTotal - len(collection.Nodes)
	if deduped < 0 {
		deduped = 0
	}
	if len(sources) == 0 {
		sources["none"] = 0
	}
	if len(admittedBy) == 0 {
		admittedBy["none"] = 0
	}
	if len(reasons) == 0 {
		reasons["none"] = 0
	}
	sourceText := joinCounts(sources)
	admittedText := joinCounts(admittedBy)
	reasonText := joinCounts(reasons)
	logs.Default().Add(logs.Entry{
		Level: logs.LevelInfo, Category: "refresh",
		Message: fmt.Sprintf("refresh done candidates=%d sources=%s admitted=%d admitted_by=%s deduped=%d rejected=%s",
			len(collection.Nodes), sourceText, len(admitted), admittedText, deduped, reasonText),
		Fields: map[string]any{
			"candidates": len(collection.Nodes), "sources": sourceText,
			"admitted": len(admitted), "admitted_by": admittedText,
			"deduped": deduped, "reasons": reasonText,
		},
	})
}

// localURLFor maps a node to its landed local mixed port when the upstream
// protocol cannot be verified directly (vmess/vless/trojan/...).
func (o *Orchestrator) localURLFor(n config.NodeConfig, portMap map[string]uint16) string {
	if u, err := url.Parse(n.URI); err == nil {
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks", "socks5", "socks5h":
			return ""
		}
	}
	port := portMap[n.NodeKey()]
	if port == 0 {
		return ""
	}
	user, pass := o.cfg.MultiPort.Username, o.cfg.MultiPort.Password
	if user == "" {
		user, pass = o.cfg.Listener.Username, o.cfg.Listener.Password
	}
	local := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))}
	if user != "" {
		if pass != "" {
			local.User = url.UserPassword(user, pass)
		} else {
			local.User = url.User(user)
		}
	}
	return local.String()
}

func isExtensionSource(s config.NodeSource) bool {
	return s == config.NodeSourceMapping || s == config.NodeSourceFreePool || s == config.NodeSourceExternalPool
}

// actionRejects reports whether a failed authenticity/MITM check removes the
// candidate. Empty action defaults to reject; "mark" only tags, "downgrade"
// relies on the score penalty.
func actionRejects(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "mark", "downgrade":
		return false
	default:
		return true
	}
}

func (o *Orchestrator) applyToRuntime(runtime Runtime, admitted []config.NodeConfig) error {
	current := runtime.CurrentConfig()
	if current == nil {
		return errors.New("runtime configuration is unavailable")
	}
	candidate := *current
	base := make([]config.NodeConfig, 0, len(current.Nodes)+len(admitted))
	for _, n := range current.Nodes {
		if isExtensionSource(n.Source) {
			continue
		}
		base = append(base, n)
	}
	base = append(base, admitted...)
	if len(base) == 0 {
		return errors.New("refusing to publish an empty node set")
	}
	candidate.Nodes = base
	// Rechecks usually produce the same node set. Rebuilding the core tears
	// down every live connection, so skip it when the effective nodes are
	// unchanged; only quality/cache data needs refreshing.
	if sameNodeSet(current.Nodes, candidate.Nodes) {
		log.Printf("[extension] node set unchanged; skipping core reload to keep active connections")
		return nil
	}
	return runtime.ReloadWithPortMap(&candidate, runtime.CurrentPortMap())
}

// sameNodeSet compares the effective node identities (endpoint + protocol +
// credentials), ignoring order and display names. Credential rotation must
// still trigger a reload, so this uses NodeKey rather than DedupeKey.
func sameNodeSet(a, b []config.NodeConfig) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, n := range a {
		seen[nodeIdentity(n)]++
	}
	for _, n := range b {
		key := nodeIdentity(n)
		if seen[key] == 0 {
			return false
		}
		seen[key]--
	}
	return true
}

func nodeIdentity(n config.NodeConfig) string {
	if key := n.NodeKey(); key != "" {
		return key
	}
	return config.DedupeKey(n.URI)
}

func (o *Orchestrator) saveCache(nodes []config.NodeConfig) error {
	path := o.cachePath()
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	var b strings.Builder
	for _, n := range nodes {
		if strings.TrimSpace(n.URI) == "" {
			continue
		}
		b.WriteString(n.URI)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func (o *Orchestrator) loadCache() ([]config.NodeConfig, error) {
	f, err := os.Open(o.cachePath())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	nodes := make([]config.NodeConfig, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !config.IsProxyURI(line) {
			continue
		}
		name := ""
		if idx := strings.LastIndex(line, "#"); idx != -1 {
			name = strings.TrimSpace(line[idx+1:])
		}
		if name == "" {
			name = "cached"
		}
		nodes = append(nodes, config.NodeConfig{
			Name: name, URI: line, Source: config.NodeSourceFreePool,
			SourceDetail: "cache", Tags: []string{"cache"},
		})
	}
	return nodes, scanner.Err()
}

// Status returns a JSON-friendly snapshot.
func (o *Orchestrator) Status() Status {
	o.mu.RLock()
	defer o.mu.RUnlock()
	results := make([]verify.Result, 0, len(o.results))
	for _, r := range o.results {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Score > results[j].Score })
	status := Status{
		Enabled:         o.ext.Enabled,
		Candidates:      o.candidates,
		Admitted:        len(o.admitted),
		Providers:       o.registry.Providers(),
		Plugins:         source.RegisteredFetchers(),
		Outcomes:        append([]source.Outcome(nil), o.outcomes...),
		Results:         results,
		Verification:    o.verifier.Config(),
		RecheckInterval: o.ext.Verification.RecheckInterval,
		CacheFile:       cachePathOf(o.ext),
	}
	if !o.lastRefresh.IsZero() {
		status.LastRefresh = o.lastRefresh.Format(time.RFC3339)
	}
	status.LastError = o.lastError
	return status
}

// ConfigSnapshot returns the WebUI-safe extension configuration.
func (o *Orchestrator) ConfigSnapshot() config.ExtensionConfig {
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := config.SanitizeExtensionConfig(o.ext)
	out.Mapping.Presets = source.EnsureMappingPresets(out.Mapping.Presets)
	return out
}

// ApplyConfig persists a configuration section and rebuilds the live sources
// so the change takes effect immediately (no restart required).
func (o *Orchestrator) ApplyConfig(next config.ExtensionConfig) error {
	o.mu.RLock()
	current := o.ext
	o.mu.RUnlock()

	// The WebUI never receives key_value; keep any existing secret rather than
	// wiping it when a section is saved.
	for i := range next.Mapping.Providers {
		if next.Mapping.Providers[i].Auth.KeyValue != "" {
			continue
		}
		for _, old := range current.Mapping.Providers {
			if old.Name == next.Mapping.Providers[i].Name {
				next.Mapping.Providers[i].Auth.KeyValue = old.Auth.KeyValue
				break
			}
		}
	}
	next.Mapping.Presets = source.EnsureMappingPresets(next.Mapping.Presets)
	if err := config.ValidateExtensionConfig(next); err != nil {
		return err
	}
	if o.cfg == nil {
		return errors.New("config file path is unknown")
	}
	if err := o.cfg.SaveExtensionSettings(next); err != nil {
		return err
	}

	registry := buildRegistry(next)
	verifier := verify.New(next.Verification)
	o.mu.Lock()
	o.ext = next
	o.registry = registry
	o.verifier = verifier
	o.lastFetch = make(map[string]time.Time)
	o.mu.Unlock()
	log.Printf("[extension] configuration saved; sources rebuilt")

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if _, err := o.RefreshNow(ctx); err != nil {
			log.Printf("[extension] refresh after config change: %v", err)
		}
	}()
	return nil
}

// Sources returns a unified view of every node source for the source-health
// panel. All four kinds are node sources, so they belong in one place.
func (o *Orchestrator) Sources() []map[string]any {
	p := o.parts()
	status := o.Status()
	byName := make(map[string]source.Outcome)
	for _, oc := range status.Outcomes {
		byName[oc.Provider] = oc
	}
	aggregate := byName["freepool"]
	list := make([]map[string]any, 0)
	// Built-in presets appear alongside custom providers so the health panel
	// shows every node source in one place.
	for _, pr := range source.EnsureMappingPresets(p.ext.Mapping.Presets) {
		list = append(list, map[string]any{
			"kind": "preset", "name": pr.Platform,
			"enabled": p.ext.Mapping.Enabled && pr.Enabled,
			"target":  pr.Platform, "query": pr.Query, "key_env": pr.KeyEnv,
			"nodes":      byName["mapping:"+pr.Platform].Nodes,
			"error":      byName["mapping:"+pr.Platform].Error,
			"fetched_at": byName["mapping:"+pr.Platform].FetchedAt,
		})
	}
	for _, pr := range p.ext.Mapping.Providers {
		oc := byName["mapping:"+pr.Name]
		list = append(list, map[string]any{
			"kind": "mapping", "name": pr.Name,
			"enabled": p.ext.Mapping.Enabled && pr.Enabled,
			"target":  pr.Endpoint, "query": pr.Query,
			"key_env": pr.Auth.KeyEnv, "nodes": oc.Nodes,
			"error": oc.Error, "fetched_at": oc.FetchedAt,
		})
	}
	for _, f := range p.ext.FreePool.Fetchers {
		list = append(list, map[string]any{
			"kind": "freepool", "name": f.Name,
			"enabled": p.ext.FreePool.Enabled && f.Enabled,
			"target":  f.URL, "nodes": aggregate.Nodes,
			"error": aggregate.Error, "fetched_at": aggregate.FetchedAt,
		})
	}
	if p.ext.FreePool.ExternalAPI.Enabled {
		list = append(list, map[string]any{
			"kind": "external_api", "name": "proxy_pool",
			"enabled": true, "target": p.ext.FreePool.ExternalAPI.BaseURL,
			"nodes": aggregate.Nodes, "error": aggregate.Error,
			"fetched_at": aggregate.FetchedAt,
		})
	}
	return list
}

// UpsertSource adds or replaces one source, then applies the whole config.
func (o *Orchestrator) UpsertSource(kind string, raw json.RawMessage) error {
	next := o.parts().ext
	switch kind {
	case "mapping":
		var item config.MappingProviderConfig
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("mapping source: %w", err)
		}
		if strings.TrimSpace(item.Name) == "" {
			return errors.New("mapping source name is required")
		}
		found := false
		for i := range next.Mapping.Providers {
			if next.Mapping.Providers[i].Name == item.Name {
				next.Mapping.Providers[i] = item
				found = true
				break
			}
		}
		if !found {
			next.Mapping.Providers = append(next.Mapping.Providers, item)
		}
	case "freepool":
		var item config.FreeFetcherConfig
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("free source: %w", err)
		}
		if strings.TrimSpace(item.Name) == "" {
			return errors.New("free source name is required")
		}
		found := false
		for i := range next.FreePool.Fetchers {
			if next.FreePool.Fetchers[i].Name == item.Name {
				next.FreePool.Fetchers[i] = item
				found = true
				break
			}
		}
		if !found {
			next.FreePool.Fetchers = append(next.FreePool.Fetchers, item)
		}
	case "external_api":
		var item config.ExternalPoolConfig
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("external api: %w", err)
		}
		next.FreePool.ExternalAPI = item
	case "preset":
		var item config.MappingPresetConfig
		if err := json.Unmarshal(raw, &item); err != nil {
			return fmt.Errorf("preset: %w", err)
		}
		if strings.TrimSpace(item.Platform) == "" {
			return errors.New("preset platform is required")
		}
		next.Mapping.Presets = source.EnsureMappingPresets(next.Mapping.Presets)
		found := false
		for i := range next.Mapping.Presets {
			if next.Mapping.Presets[i].Platform == item.Platform {
				next.Mapping.Presets[i] = item
				found = true
				break
			}
		}
		if !found {
			next.Mapping.Presets = append(next.Mapping.Presets, item)
		}
	default:
		return fmt.Errorf("unknown source kind %q", kind)
	}
	return o.ApplyConfig(next)
}

// DeleteSource removes one source by kind and name.
func (o *Orchestrator) DeleteSource(kind, name string) error {
	next := o.parts().ext
	switch kind {
	case "mapping":
		out := make([]config.MappingProviderConfig, 0, len(next.Mapping.Providers))
		for _, p := range next.Mapping.Providers {
			if p.Name != name {
				out = append(out, p)
			}
		}
		next.Mapping.Providers = out
	case "freepool":
		out := make([]config.FreeFetcherConfig, 0, len(next.FreePool.Fetchers))
		for _, f := range next.FreePool.Fetchers {
			if f.Name != name {
				out = append(out, f)
			}
		}
		next.FreePool.Fetchers = out
	case "external_api":
		next.FreePool.ExternalAPI = config.ExternalPoolConfig{}
	case "preset":
		// Presets are fixed platform templates: "delete" disables them rather
		// than removing the row, so the WebUI can always re-enable a platform.
		next.Mapping.Presets = source.EnsureMappingPresets(next.Mapping.Presets)
		for i := range next.Mapping.Presets {
			if next.Mapping.Presets[i].Platform == name {
				next.Mapping.Presets[i].Enabled = false
			}
		}
	default:
		return fmt.Errorf("unknown source kind %q", kind)
	}
	return o.ApplyConfig(next)
}

// tagKey mirrors builder.sanitizeTag so runtime node tags can be matched to
// extension nodes without importing the builder package.
func tagKey(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return ""
	}
	segments := strings.FieldsFunc(lower, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	return strings.Trim(strings.Join(segments, "-"), "-")
}

// NodeMetaMap returns per-node extension metadata keyed by tag and name so the
// dashboard can enrich existing rows without changing the nodes array shape.
func (o *Orchestrator) NodeMetaMap() map[string]map[string]any {
	o.mu.RLock()
	admitted := append([]config.NodeConfig(nil), o.admitted...)
	results := make(map[string]verify.Result, len(o.results))
	for k, v := range o.results {
		results[k] = v
	}
	runtime := o.runtime
	o.mu.RUnlock()

	metaFor := func(n config.NodeConfig) map[string]any {
		meta := map[string]any{
			"source":        string(n.Source),
			"source_detail": n.SourceDetail,
			"tags":          n.Tags,
			"declared_ip":   n.DeclaredIP,
		}
		if r, ok := results[n.NodeKey()]; ok {
			meta["verification"] = r
		}
		return meta
	}
	put := func(out map[string]map[string]any, n config.NodeConfig, meta map[string]any) {
		for _, key := range []string{n.Name, tagKey(n.Name)} {
			if key != "" {
				out[key] = meta
			}
		}
	}

	out := make(map[string]map[string]any)
	for _, n := range admitted {
		put(out, n, metaFor(n))
	}
	// Upstream nodes (subscription / inline / nodes_file) are part of the same
	// table, so label them too. Extension nodes always win on key collisions.
	if runtime != nil {
		if current := runtime.CurrentConfig(); current != nil {
			for _, n := range current.Nodes {
				if isExtensionSource(n.Source) {
					continue
				}
				key := tagKey(n.Name)
				if key == "" {
					continue
				}
				if _, exists := out[key]; exists {
					continue
				}
				put(out, n, metaFor(n))
			}
		}
	}
	return out
}

// Access returns landed per-node proxy URLs for the session-routing tab.
// Full URLs are returned only to the authenticated WebUI and are never logged.
func (o *Orchestrator) Access() map[string]any {
	o.mu.RLock()
	admitted := append([]config.NodeConfig(nil), o.admitted...)
	results := make(map[string]verify.Result, len(o.results))
	for k, v := range o.results {
		results[k] = v
	}
	runtime := o.runtime
	o.mu.RUnlock()

	var portMap map[string]uint16
	if runtime != nil {
		portMap = runtime.CurrentPortMap()
	}
	user, pass := o.cfg.MultiPort.Username, o.cfg.MultiPort.Password
	if user == "" {
		user, pass = o.cfg.Listener.Username, o.cfg.Listener.Password
	}
	host := strings.TrimSpace(o.cfg.ExternalIP)
	if host == "" {
		host = "127.0.0.1"
	}
	auth := ""
	maskedAuth := ""
	if user != "" {
		if pass != "" {
			auth = url.UserPassword(user, pass).String() + "@"
			maskedAuth = url.UserPassword(user, "******").String() + "@"
		} else {
			auth = url.User(user).String() + "@"
			maskedAuth = auth
		}
	}
	items := make([]map[string]any, 0)
	for _, n := range admitted {
		port := portMap[n.NodeKey()]
		if port == 0 {
			continue
		}
		addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
		grade, score := "", 0
		if r, ok := results[n.NodeKey()]; ok {
			grade, score = r.Grade, r.Score
		}
		items = append(items, map[string]any{
			"name": n.Name, "port": port, "source": string(n.Source),
			"grade": grade, "score": score,
			"http_url":      "http://" + auth + addr,
			"socks5_url":    "socks5://" + auth + addr,
			"masked_http":   "http://" + maskedAuth + addr,
			"masked_socks5": "socks5://" + maskedAuth + addr,
		})
	}
	return map[string]any{"items": items, "count": len(items)}
}

// ServeHTTP implements the extension JSON API consumed by the upstream console.
func (o *Orchestrator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimSpace(r.URL.Path), "/")
	switch {
	case path == "/api/ext/status" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, o.Status())
	case path == "/api/ext/providers" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"providers": o.Status().Providers, "plugins": source.RegisteredFetchers(),
		})
	case path == "/api/ext/results" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"results": o.Status().Results})
	case path == "/api/ext/sources" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"sources": o.Sources()})
	case path == "/api/ext/sources" && r.Method == http.MethodPost:
		var req struct {
			Kind string          `json:"kind"`
			Item json.RawMessage `json:"item"`
		}
		if err := decodeJSON(w, r, &req); err != nil {
			return
		}
		if err := o.UpsertSource(req.Kind, req.Item); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sources": o.Sources()})
	case path == "/api/ext/sources" && r.Method == http.MethodDelete:
		kind := r.URL.Query().Get("kind")
		name := r.URL.Query().Get("name")
		if err := o.DeleteSource(kind, name); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sources": o.Sources()})
	case path == "/api/ext/config" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, o.ConfigSnapshot())
	case path == "/api/ext/config" && r.Method == http.MethodPut:
		var next config.ExtensionConfig
		if err := decodeJSON(w, r, &next); err != nil {
			return
		}
		if err := o.ApplyConfig(next); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"config": o.ConfigSnapshot(), "message": "已保存并立即生效"})
	case path == "/api/ext/access" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, o.Access())
	case path == "/api/ext/refresh" && r.Method == http.MethodPost:
		count, err := o.RefreshNow(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "admitted": count})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"admitted": count})
	case path == "/api/ext/recheck" && r.Method == http.MethodPost:
		o.recheck(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"admitted": o.Status().Admitted})
	case path == "/api/ext/verify" && r.Method == http.MethodGet:
		raw := strings.TrimSpace(r.URL.Query().Get("proxy"))
		if raw == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "proxy parameter required"})
			return
		}
		writeJSON(w, http.StatusOK, o.parts().verifier.Verify(r.Context(), raw))
	default:
		http.NotFound(w, r)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误: " + err.Error()})
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}
