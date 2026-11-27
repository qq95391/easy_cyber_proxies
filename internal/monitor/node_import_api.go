package monitor

import (
	"net/http"
	"sort"
	"strings"

	"easy_proxies/internal/config"
	"easy_proxies/internal/quality"
)

// handleNodePreview parses a Clash YAML document or a list of proxy URLs and
// returns a deduplicated preview. Nothing is persisted here.
func (s *Server) handleNodePreview(w http.ResponseWriter, r *http.Request) {
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
		Mode string   `json:"mode"`
		YAML string   `json:"yaml"`
		URLs []string `json:"urls"`
	}
	if err := decodeManagementJSON(w, r, 4<<20, &req); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}

	var nodes []config.NodeConfig
	switch strings.ToLower(strings.TrimSpace(req.Mode)) {
	case "clash", "yaml":
		parsed, err := config.ParseClashProxies([]byte(req.YAML))
		if err != nil {
			writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		nodes = parsed
	default:
		for _, raw := range req.URLs {
			if uri := strings.TrimSpace(raw); uri != "" {
				nodes = append(nodes, config.NodeConfig{URI: uri})
			}
		}
	}
	if len(nodes) == 0 {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "未解析到任何节点"})
		return
	}

	seen := make(map[string]bool, len(nodes))
	duplicates := 0
	items := make([]map[string]any, 0, len(nodes))
	for _, node := range nodes {
		key := config.DedupeKey(node.URI)
		duplicate := seen[key]
		if duplicate {
			duplicates++
		} else {
			seen[key] = true
		}
		name := strings.TrimSpace(node.Name)
		if name == "" {
			name = config.ExtractNodeName(node.URI)
		}
		items = append(items, map[string]any{
			"name": name, "uri": node.URI, "key": key, "duplicate": duplicate,
		})
	}
	writeJSON(w, map[string]any{
		"items": items,
		"summary": map[string]any{
			"total": len(items), "unique": len(seen), "duplicate": duplicates,
		},
	})
}

// batchDeleteFilter selects "invalid" nodes by runtime state or quality score.
type batchDeleteFilter struct {
	Blacklisted bool `json:"blacklisted"`
	Unreachable bool `json:"unreachable"`
	BelowScore  bool `json:"below_score"`
	MinScore    int  `json:"min_score"`
}

// handleNodeBatchDelete removes nodes by explicit names or by an invalid-node
// filter. dry_run returns the matched set so the UI can confirm first.
func (s *Server) handleNodeBatchDelete(w http.ResponseWriter, r *http.Request) {
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
		Names  []string           `json:"names"`
		Filter *batchDeleteFilter `json:"filter"`
		DryRun bool               `json:"dry_run"`
	}
	if err := decodeManagementJSON(w, r, 1<<20, &req); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}

	targets := make(map[string]bool, len(req.Names))
	for _, name := range req.Names {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			targets[trimmed] = true
		}
	}
	if filter := req.Filter; filter != nil && s.mgr != nil {
		byName := make(map[string]quality.Record)
		for _, record := range quality.Default().All() {
			if record.Name != "" {
				byName[record.Name] = record
			}
		}
		minScore := filter.MinScore
		if minScore <= 0 {
			minScore = 40
		}
		for _, snap := range s.mgr.Snapshot() {
			name := snap.Name
			if name == "" {
				name = snap.Tag
			}
			if name == "" {
				continue
			}
			if filter.Blacklisted && snap.Blacklisted {
				targets[name] = true
			}
			if filter.Unreachable && !snap.Available {
				targets[name] = true
			}
			if filter.BelowScore {
				if record, ok := byName[name]; ok && record.Score < minScore {
					targets[name] = true
				}
			}
		}
	}
	nameList := make([]string, 0, len(targets))
	for name := range targets {
		nameList = append(nameList, name)
	}
	sort.Strings(nameList)
	if len(nameList) == 0 {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "未匹配到任何无效节点"})
		return
	}
	if req.DryRun {
		writeJSON(w, map[string]any{"dry_run": true, "count": len(nameList), "matched": nameList})
		return
	}

	nodeMgr := s.nodeManager()
	if !ensureNodeManager(w, nodeMgr) {
		return
	}
	deleted := make([]string, 0, len(nameList))
	failed := make([]map[string]any, 0)
	for _, name := range nameList {
		if err := nodeMgr.DeleteNode(r.Context(), name); err != nil {
			failed = append(failed, map[string]any{"name": name, "error": err.Error()})
			continue
		}
		deleted = append(deleted, name)
	}
	writeJSON(w, map[string]any{
		"message": "无效节点已删除，请重载核心生效",
		"deleted": len(deleted),
		"failed":  failed,
		"names":   deleted,
	})
}

// handleNodeBatch creates nodes transactionally: any failure rolls back the
// nodes created by this request so a partial import cannot be left behind.
func (s *Server) handleNodeBatch(w http.ResponseWriter, r *http.Request) {
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
		Nodes []nodePayload `json:"nodes"`
	}
	if err := decodeManagementJSON(w, r, 4<<20, &req); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return
	}
	const maxBatch = 500
	if len(req.Nodes) == 0 {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "未提交任何节点"})
		return
	}
	if len(req.Nodes) > maxBatch {
		req.Nodes = req.Nodes[:maxBatch]
	}
	nodeMgr := s.nodeManager()
	if !ensureNodeManager(w, nodeMgr) {
		return
	}

	created := make([]string, 0, len(req.Nodes))
	for _, payload := range req.Nodes {
		node, err := nodeMgr.CreateNode(r.Context(), payload.toConfig())
		if err != nil {
			for _, name := range created {
				_ = nodeMgr.DeleteNode(r.Context(), name)
			}
			s.respondNodeError(w, err)
			return
		}
		created = append(created, node.Name)
	}
	writeJSON(w, map[string]any{
		"message": "批量添加完成，请点击重载使配置生效",
		"created": len(created),
		"names":   created,
	})
}
