package source

import (
	"fmt"
	"os"
	"strings"

	"easy_proxies/internal/config"
)

// Built-in mapping platform presets. These are plain MappingProviderConfig
// templates; no platform-specific client code is copied from the reference
// project. Endpoint, auth, query parameter names, pagination and response
// field mapping follow the published API shapes verified from Deadpool v1.8
// (utils/netspace.go) and the local aiscan knowledge base.
//
// Credentials are referenced only by environment variable name. FOFA's legacy
// email field is optional and read from EmailEnv for old accounts.

// EnsureMappingPresets fills the three built-in presets when the user has not
// configured any. An explicit empty list keeps all presets disabled.
func EnsureMappingPresets(current []config.MappingPresetConfig) []config.MappingPresetConfig {
	if current == nil {
		return config.DefaultMappingPresets()
	}
	return current
}

// BuildPreset converts a built-in preset into the same provider configuration
// a custom user entry uses, so both go through one Fetch implementation.
func BuildPreset(pr config.MappingPresetConfig) (config.MappingProviderConfig, error) {
	platform := strings.ToLower(strings.TrimSpace(pr.Platform))
	encoding := strings.ToLower(strings.TrimSpace(pr.Encoding))
	if encoding == "" {
		encoding = "url"
	}
	size := pr.Size
	if size <= 0 {
		size = 100
	}
	base := config.MappingProviderConfig{
		Name:          platform,
		Enabled:       pr.Enabled,
		Query:         pr.Query,
		QueryEncoding: encoding,
		MaxResults:    size,
		Auth: config.MappingAuthConfig{
			Type:   "query",
			KeyEnv: pr.KeyEnv,
		},
		Response: config.MappingResponse{
			Format:      "json",
			Fields:      config.MappingFields{DefaultProtocol: "socks5"},
			ErrorPath:   "",
			MessagePath: "message",
		},
	}

	switch platform {
	case "fofa":
		base.Endpoint = "https://fofa.info/api/v1/search/all"
		base.Method = "GET"
		base.Auth.KeyName = "key" // FOFA is key-only on current accounts
		base.QueryParam = "qbase64"
		base.ExtraParams = map[string]string{
			"fields": "ip,port",
			"size":   fmt.Sprintf("%d", size),
		}
		if env := strings.TrimSpace(pr.EmailEnv); env != "" {
			if v := strings.TrimSpace(os.Getenv(env)); v != "" {
				base.ExtraParams["email"] = v
			}
		}
		base.Response.ResultsPath = "results"
		base.Response.Fields.Host = "0"
		base.Response.Fields.Port = "1"
		base.Response.ErrorPath = "error"
		base.Response.SuccessValue = "false"
		base.Response.MessagePath = "errmsg"

	case "quake":
		base.Endpoint = "https://quake.360.net/api/v3/search/quake_service"
		base.Method = "POST"
		base.Auth.Type = "header"
		base.Auth.KeyName = "X-QuakeToken"
		base.BodyTemplate = `{"query":{query},"latest":"True","start":{start},"size":{size},"include":["ip","port"]}`
		base.ExtraParams = map[string]string{
			"size":  fmt.Sprintf("%d", size),
			"start": "0",
		}
		base.Response.ResultsPath = "data"
		base.Response.Fields.Host = "ip"
		base.Response.Fields.Port = "port"
		base.Response.ErrorPath = "code"
		base.Response.SuccessValue = "0"

	case "hunter":
		base.Endpoint = "https://hunter.qianxin.com/openApi/search"
		base.Method = "GET"
		base.Auth.KeyName = "api-key"
		base.QueryParam = "search"
		pages := size / 100
		if pages < 1 {
			pages = 1
		}
		base.Pagination = config.PaginationConfig{
			Enabled:   true,
			Param:     "page",
			Start:     1,
			MaxPages:  pages,
			SizeParam: "page_size",
			Size:      100,
		}
		base.RequestInterval = "3s"
		base.Response.ResultsPath = "data.arr"
		base.Response.Fields.Host = "ip"
		base.Response.Fields.Port = "port"
		base.Response.ErrorPath = "code"
		base.Response.SuccessValue = "200"

	default:
		return config.MappingProviderConfig{}, fmt.Errorf("unknown mapping preset %q", pr.Platform)
	}
	return base, nil
}
