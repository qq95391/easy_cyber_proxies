package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseClashProxies converts a Clash `proxies:` YAML document into node
// configs. Only the proxies list is consumed; proxy-groups and rules are
// intentionally ignored.
func ParseClashProxies(data []byte) ([]NodeConfig, error) {
	var doc clashConfig
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse clash yaml: %w", err)
	}
	if len(doc.Proxies) == 0 {
		return nil, fmt.Errorf("no proxies found (expected a top-level `proxies:` list)")
	}
	out := make([]NodeConfig, 0, len(doc.Proxies))
	skipped := 0
	for _, raw := range doc.Proxies {
		var proxy clashProxy
		if err := raw.Decode(&proxy); err != nil {
			skipped++
			continue
		}
		if strings.TrimSpace(proxy.Server) == "" {
			skipped++
			continue
		}
		uri := strings.TrimSpace(convertClashProxyToURI(proxy))
		if uri == "" {
			skipped++
			continue
		}
		name := strings.TrimSpace(proxy.Name)
		if name == "" {
			name = ExtractNodeName(uri)
		}
		out = append(out, NodeConfig{Name: name, URI: uri})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no supported proxies in the document (skipped %d)", skipped)
	}
	return out, nil
}
