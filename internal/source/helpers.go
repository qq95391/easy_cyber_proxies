package source

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// getPath walks a dot-separated path. Numeric segments index arrays, which
// lets users map APIs that return positional arrays (e.g. FOFA "results").
func getPath(root any, path string) any {
	cur := root
	path = strings.TrimSpace(path)
	if path == "" {
		return cur
	}
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		switch t := cur.(type) {
		case map[string]any:
			cur = t[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(t) {
				return nil
			}
			cur = t[i]
		default:
			return nil
		}
	}
	return cur
}

// asString converts common JSON scalar types to a string.
func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func normalizeHost(v string) string {
	h := strings.TrimSpace(v)
	if h == "" {
		return ""
	}
	if idx := strings.Index(h, "://"); idx != -1 {
		h = h[idx+3:]
	}
	if idx := strings.Index(h, "/"); idx != -1 {
		h = h[:idx]
	}
	if idx := strings.LastIndex(h, "@"); idx != -1 {
		h = h[idx+1:]
	}
	h = strings.Trim(h, "[]")
	return h
}

func normalizePort(v any) int {
	s := asString(v)
	if s == "" {
		return 0
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return 0
	}
	return p
}

func allowedProtocol(p, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "http", "https", "socks", "socks5", "socks5h":
		return strings.ToLower(strings.TrimSpace(p))
	case "socks4":
		return "socks"
	default:
		if fallback != "" {
			return allowedProtocol(fallback, "")
		}
		return "http"
	}
}

func buildProxyURI(protocol, host string, port int, user, pass string) string {
	if host == "" || port < 1 {
		return ""
	}
	u := &url.URL{
		Scheme: allowedProtocol(protocol, ""),
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
	}
	if user != "" && pass != "" {
		u.User = url.UserPassword(user, pass)
	} else if user != "" {
		u.User = url.User(user)
	}
	return u.String()
}

// parseHostPort accepts "host:port", a full URI, or an entry with credentials.
func parseHostPort(entry string) (string, int, string, string, string, bool) {
	raw := strings.TrimSpace(entry)
	if raw == "" {
		return "", 0, "", "", "", false
	}
	protocol, user, pass := "", "", ""
	hostPort := raw
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			protocol = u.Scheme
			hostPort = u.Host
			if u.User != nil {
				user = u.User.Username()
				pass, _ = u.User.Password()
			}
		}
	}
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, "", "", "", false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", "", "", false
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, "", "", "", false
	}
	return host, port, protocol, user, pass, true
}

var defaultHostPortPattern = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}\s*[:,\s]\s*\d{2,5}`)

var unsafeLabelChars = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// safeLabel produces a fragment-safe, stable node label.
func safeLabel(s string) string {
	v := strings.Trim(unsafeLabelChars.ReplaceAllString(strings.TrimSpace(s), "-"), "-")
	if v == "" {
		return "node"
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

// extractTextEntries returns raw "host:port" strings from plain text.
func extractTextEntries(body []byte, pattern string) []string {
	var re *regexp.Regexp
	if strings.TrimSpace(pattern) != "" {
		compiled, err := regexp.Compile(pattern)
		if err == nil {
			re = compiled
		}
	}
	if re == nil {
		re = defaultHostPortPattern
	}
	matches := re.FindAllStringSubmatch(string(body), -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		candidate := m[0]
		if re.SubexpNames() != nil {
			host, port := "", ""
			for i, name := range re.SubexpNames() {
				if i == 0 || i >= len(m) {
					continue
				}
				switch name {
				case "host":
					host = m[i]
				case "port":
					port = m[i]
				}
			}
			if host != "" && port != "" {
				candidate = host + ":" + port
			}
		}
		candidate = strings.ReplaceAll(candidate, ",", ":")
		candidate = strings.Join(strings.Fields(candidate), "")
		out = append(out, candidate)
	}
	return out
}

// extractJSONEntries returns the entries at a user-defined JSON path.
func extractJSONEntries(body []byte, path string) []any {
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil
	}
	v := getPath(root, path)
	switch t := v.(type) {
	case []any:
		return t
	case map[string]any:
		return []any{t}
	case nil:
		return nil
	default:
		return []any{t}
	}
}

// fieldOf extracts a mapped field from a decoded response item.
func fieldOf(item any, path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return asString(getPath(item, path))
}
