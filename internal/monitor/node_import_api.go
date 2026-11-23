package monitor

import (
	"net/http"
	"strings"

	"easy_proxies/internal/config"
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
