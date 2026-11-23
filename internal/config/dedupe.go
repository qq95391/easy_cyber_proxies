package config

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// DedupeKey identifies a node by endpoint + protocol, so the same host:port
// exposed through different display names or credentials collapses, while the
// same port serving different protocols (e.g. socks5 and http) is preserved.
func DedupeKey(uri string) string {
	host, port, scheme := nodeEndpoint(uri)
	if host == "" {
		return strings.ToLower(strings.TrimSpace(stableNodeKey(uri)))
	}
	return host + ":" + port + "|" + scheme
}

// DedupeNodes keeps one node per DedupeKey. Priority: an encrypted protocol
// wins, then the earliest input order. Callers that already know liveness
// should use DedupeNodesWithPriority to rank usable nodes first.
func DedupeNodes(nodes []NodeConfig) ([]NodeConfig, int) {
	return DedupeNodesWithPriority(nodes, nil)
}

// DedupeNodesWithPriority is DedupeNodes with caller-supplied liveness, so the
// priority becomes usable > encrypted > earliest. usable may be nil.
func DedupeNodesWithPriority(nodes []NodeConfig, usable func(NodeConfig) bool) ([]NodeConfig, int) {
	if len(nodes) <= 1 {
		return nodes, 0
	}
	index := make(map[string]int, len(nodes))
	out := make([]NodeConfig, 0, len(nodes))
	dropped := 0
	for _, node := range nodes {
		key := DedupeKey(node.URI)
		if key == "" {
			out = append(out, node)
			continue
		}
		existing, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, node)
			continue
		}
		if nodeRank(node, usable) > nodeRank(out[existing], usable) {
			out[existing] = node
		}
		dropped++
	}
	return out, dropped
}

// nodeRank orders duplicates: usable > encrypted > plain. Ties keep the
// earliest occurrence because callers only replace on a strictly higher rank.
func nodeRank(node NodeConfig, usable func(NodeConfig) bool) int {
	rank := 0
	if usable != nil && usable(node) {
		rank += 10
	}
	if nodeEncrypted(node.URI) {
		rank += 5
	}
	return rank
}

func nodeEncrypted(uri string) bool {
	_, _, scheme := nodeEndpoint(uri)
	switch scheme {
	case "https", "vless", "vmess", "trojan", "hysteria", "hysteria2", "hy2",
		"tuic", "anytls", "ss", "shadowsocks", "ssr", "shadowsocksr":
		return true
	default:
		return false
	}
}

// nodeEndpoint extracts a normalized host, port and scheme from a proxy URI.
// It supports standard URL links plus the base64 payloads used by vmess, ss
// and ssr, falling back to the empty string when the endpoint is unknown.
func nodeEndpoint(uri string) (host, port, scheme string) {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return "", "", ""
	}
	lower := strings.ToLower(uri)
	if idx := strings.Index(lower, "://"); idx > 0 {
		scheme = lower[:idx]
	} else {
		return "", "", ""
	}

	switch scheme {
	case "vmess":
		host, port = vmessEndpoint(uri)
	case "ss":
		host, port = ssEndpoint(uri)
	case "ssr", "shadowsocksr":
		host, port = ssrEndpoint(uri)
	default:
		u, err := url.Parse(uri)
		if err != nil {
			return "", "", scheme
		}
		host, port = normalizeHost(u.Hostname()), u.Port()
	}
	if host == "" {
		return "", "", scheme
	}
	if port == "" {
		port = defaultPortForScheme(scheme)
	}
	return host, port, scheme
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(host, ".")
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks", "socks5", "socks5h", "socks4":
		return "1080"
	default:
		return "0"
	}
}

func decodeAnyBase64(payload string) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(payload); err == nil {
			return decoded, true
		}
	}
	return nil, false
}

func vmessEndpoint(uri string) (string, string) {
	payload := uri[len("vmess://"):]
	if idx := strings.Index(payload, "#"); idx != -1 {
		payload = payload[:idx]
	}
	if strings.Contains(payload, "@") {
		// URL-form vmess link.
		if u, err := url.Parse(uri); err == nil {
			return normalizeHost(u.Hostname()), u.Port()
		}
		return "", ""
	}
	decoded, ok := decodeAnyBase64(payload)
	if !ok {
		return "", ""
	}
	var fields map[string]any
	if err := json.Unmarshal(decoded, &fields); err != nil {
		return "", ""
	}
	host := normalizeHost(asText(fields["add"]))
	port := asText(fields["port"])
	if host == "" {
		return "", ""
	}
	return host, port
}

func ssEndpoint(uri string) (string, string) {
	rest := uri[len("ss://"):]
	if idx := strings.Index(rest, "#"); idx != -1 {
		rest = rest[:idx]
	}
	if idx := strings.Index(rest, "?"); idx != -1 {
		rest = rest[:idx]
	}
	if at := strings.LastIndex(rest, "@"); at != -1 {
		hostPort := rest[at+1:]
		if idx := strings.Index(hostPort, "/"); idx != -1 {
			hostPort = hostPort[:idx]
		}
		host, port := splitHostPort(hostPort)
		if host != "" {
			return host, port
		}
	}
	decoded, ok := decodeAnyBase64(strings.TrimSuffix(rest, "/"))
	if !ok {
		return "", ""
	}
	text := string(decoded)
	if at := strings.LastIndex(text, "@"); at != -1 {
		text = text[at+1:]
	}
	return splitHostPort(text)
}

func ssrEndpoint(uri string) (string, string) {
	payload := uri[len("ssr://"):]
	if idx := strings.Index(payload, "#"); idx != -1 {
		payload = payload[:idx]
	}
	decoded, ok := decodeAnyBase64(payload)
	if !ok {
		return "", ""
	}
	// host:port:protocol:method:obfs:base64(pass)/?params
	parts := strings.SplitN(string(decoded), ":", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return normalizeHost(parts[0]), parts[1]
}

func splitHostPort(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	host, port, err := splitHostPortStrict(value)
	if err != nil {
		return "", ""
	}
	return normalizeHost(host), port
}

func splitHostPortStrict(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end == -1 {
			return "", "", strconv.ErrSyntax
		}
		host := value[1:end]
		rest := strings.TrimPrefix(value[end+1:], ":")
		return host, rest, nil
	}
	idx := strings.LastIndex(value, ":")
	if idx == -1 {
		return value, "", nil
	}
	return value[:idx], value[idx+1:], nil
}

func asText(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.Itoa(int(v))
	case int:
		return strconv.Itoa(v)
	default:
		return ""
	}
}
