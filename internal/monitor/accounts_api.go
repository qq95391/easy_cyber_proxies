package monitor

import (
	"net/http"
	"strings"

	"easy_proxies/internal/accounts"
)

// handleAccounts serves the credential-free overview and the CRUD work chain.
// All mutations go through withAuth, which also rejects cross-site writes.
func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	store := accounts.Default()
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/accounts"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, map[string]any{
			"users": store.Users(),
			"pools": store.Pools(),
			"audit": store.Audit(),
		})
		return
	}
	parts := strings.Split(rest, "/")
	switch parts[0] {
	case "users":
		s.handleAccountUsers(w, r, store, parts)
	case "pools":
		s.handleAccountPools(w, r, store, parts)
	default:
		writeStatusJSON(w, http.StatusNotFound, map[string]any{"error": "未知资源"})
	}
}

func decodeAccountBody(w http.ResponseWriter, r *http.Request, target any) bool {
	if err := decodeManagementJSON(w, r, 1<<20, target); err != nil {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"error": "请求格式错误"})
		return false
	}
	return true
}

func writeAccountError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	status := http.StatusBadRequest
	if strings.Contains(err.Error(), "不存在") || strings.Contains(err.Error(), "未知") {
		status = http.StatusNotFound
	} else if strings.Contains(err.Error(), "持久化") || strings.Contains(err.Error(), "路径未知") {
		status = http.StatusServiceUnavailable
	}
	writeStatusJSON(w, status, map[string]any{"error": err.Error()})
}

func (s *Server) handleAccountUsers(w http.ResponseWriter, r *http.Request, store *accounts.Store, parts []string) {
	switch {
	case len(parts) == 1 && r.Method == http.MethodPost:
		var input accounts.UserInput
		if !decodeAccountBody(w, r, &input) {
			return
		}
		view, err := store.CreateUser(input)
		if err != nil {
			writeAccountError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "用户已创建并立即生效", "user": view})
	case len(parts) == 2 && r.Method == http.MethodPut:
		var input accounts.UserInput
		if !decodeAccountBody(w, r, &input) {
			return
		}
		view, err := store.UpdateUser(parts[1], input)
		if err != nil {
			writeAccountError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "用户已更新并立即生效", "user": view})
	case len(parts) == 2 && r.Method == http.MethodDelete:
		if err := store.DeleteUser(parts[1]); err != nil {
			writeAccountError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "用户已删除，在途连接保持到自然结束"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAccountPools(w http.ResponseWriter, r *http.Request, store *accounts.Store, parts []string) {
	switch {
	case len(parts) == 1 && r.Method == http.MethodPost:
		var input accounts.PoolInput
		if !decodeAccountBody(w, r, &input) {
			return
		}
		pool, err := store.CreatePool(input)
		if err != nil {
			writeAccountError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "分池已创建并立即生效", "pool": pool})
	case len(parts) == 2 && r.Method == http.MethodPut:
		var input accounts.PoolInput
		if !decodeAccountBody(w, r, &input) {
			return
		}
		pool, err := store.UpdatePool(parts[1], input)
		if err != nil {
			writeAccountError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "分池已更新并立即生效", "pool": pool})
	case len(parts) == 2 && r.Method == http.MethodDelete:
		if err := store.DeletePool(parts[1]); err != nil {
			writeAccountError(w, err)
			return
		}
		writeJSON(w, map[string]any{"message": "分池已删除并立即生效"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
