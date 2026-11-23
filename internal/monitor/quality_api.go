package monitor

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/config"
	"easy_proxies/internal/quality"
	"easy_proxies/internal/verify"
)

// handleNodeQuality exposes the latest strict-verification records.
func (s *Server) handleNodeQuality(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]any{"records": quality.Default().All()})
}

// handleVerifyNodes runs full-dimension verification on demand. It is an
// operator action: results only feed the quality store, never the routing
// state, and it never triggers a core reload.
func (s *Server) handleVerifyNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !sameOriginMutation(r) {
		writeStatusJSON(w, http.StatusForbidden, map[string]any{"error": "跨站请求已拒绝"})
		return
	}
	var req struct {
		Tags []string `json:"tags"`
		All  bool     `json:"all"`
	}
	if err := decodeManagementJSON(w, r, 1<<20, &req); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	s.cfgMu.RLock()
	if s.cfgSrc == nil {
		s.cfgMu.RUnlock()
		writeStatusJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "运行时配置不可用"})
		return
	}
	all := append([]config.NodeConfig(nil), s.cfgSrc.Nodes...)
	verCfg := s.cfgSrc.Extension.Verification
	listener := s.cfgSrc.Listener
	multi := s.cfgSrc.MultiPort
	s.cfgMu.RUnlock()

	nodes := selectVerifyNodes(all, req.Tags, req.All)
	if len(nodes) == 0 {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "未选中任何节点"})
		return
	}
	const maxBatch = 200
	if len(nodes) > maxBatch {
		nodes = nodes[:maxBatch]
	}

	ver := verify.New(verCfg)
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	type outcome struct {
		node   config.NodeConfig
		result verify.Result
	}
	results := make(chan outcome, len(nodes))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(node config.NodeConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			local := localVerifyURL(node, listener, multi)
			results <- outcome{node: node, result: ver.VerifyNode(ctx, node, local)}
		}(node)
	}
	wg.Wait()
	close(results)

	verified, skipped := 0, 0
	for item := range results {
		if item.result.Skipped != "" {
			skipped++
		}
		quality.Default().Upsert(quality.Record{
			Key: nodeQualityKey(item.node), Name: item.node.Name,
			Score: item.result.Score, Grade: item.result.Grade,
			CheckedAt: item.result.CheckedAt, Result: item.result,
		})
		verified++
	}
	_ = quality.Default().Save()
	writeJSON(w, map[string]any{
		"message":  "严格验证完成",
		"verified": verified,
		"skipped":  skipped,
	})
}

func selectVerifyNodes(nodes []config.NodeConfig, tags []string, all bool) []config.NodeConfig {
	if all {
		return append([]config.NodeConfig(nil), nodes...)
	}
	if len(tags) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(tags))
	for _, tag := range tags {
		wanted[tag] = true
	}
	out := make([]config.NodeConfig, 0, len(tags))
	for _, node := range nodes {
		if wanted[node.Name] || wanted[nodeQualityKey(node)] {
			out = append(out, node)
		}
	}
	return out
}

func nodeQualityKey(node config.NodeConfig) string {
	if key := node.NodeKey(); key != "" {
		return key
	}
	return config.DedupeKey(node.URI)
}

// localVerifyURL maps non-HTTP/SOCKS nodes onto their per-node listener port.
// Endpoints without an assigned port return "", which makes the verifier report
// the protocol as skipped instead of faking a result.
func localVerifyURL(node config.NodeConfig, listener config.ListenerConfig, multi config.MultiPortConfig) string {
	if parsed, err := url.Parse(node.URI); err == nil {
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https", "socks", "socks5", "socks5h":
			return ""
		}
	}
	if node.Port == 0 {
		return ""
	}
	user, pass := multi.Username, multi.Password
	if user == "" {
		user, pass = listener.Username, listener.Password
	}
	local := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(int(node.Port))),
	}
	if user != "" {
		if pass != "" {
			local.User = url.UserPassword(user, pass)
		} else {
			local.User = url.User(user)
		}
	}
	return local.String()
}
