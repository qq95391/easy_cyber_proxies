package source

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"easy_proxies/internal/config"
)

func TestExtPresetsAreDisabledByDefault(t *testing.T) {
	presets := config.DefaultMappingPresets()
	if len(presets) != 3 {
		t.Fatalf("want 3 built-in presets, got %d", len(presets))
	}
	want := map[string]string{"fofa": "FOFA_KEY", "hunter": "HUNTER_API_KEY", "quake": "QUAKE_TOKEN"}
	for _, p := range presets {
		if p.Enabled {
			t.Fatalf("preset %q must be disabled by default", p.Platform)
		}
		if p.KeyEnv != want[p.Platform] {
			t.Fatalf("preset %q key_env = %q", p.Platform, p.KeyEnv)
		}
		if p.KeyEnv == "" || p.Query == "" || p.Size <= 0 {
			t.Fatalf("preset %q incomplete: %+v", p.Platform, p)
		}
	}
	if err := config.ValidateExtensionConfig(config.ExtensionConfig{
		Mapping: config.MappingSourcesConfig{Presets: presets},
	}); err != nil {
		t.Fatalf("default presets rejected: %v", err)
	}
}

func TestExtBuildPresetParameters(t *testing.T) {
	cases := []struct {
		platform string
		method   string
		keyName  string
		path     string
		authType string
	}{
		{"fofa", http.MethodGet, "key", "results", "query"},
		{"hunter", http.MethodGet, "api-key", "data.arr", "query"},
		{"quake", http.MethodPost, "X-QuakeToken", "data", "header"},
	}
	for _, tc := range cases {
		p, err := BuildPreset(config.MappingPresetConfig{
			Platform: tc.platform, Enabled: true, KeyEnv: "TEST_KEY",
			Query: "protocol=socks5", Size: 200, Encoding: "url",
		})
		if err != nil {
			t.Fatal(err)
		}
		if p.Method != tc.method || p.Auth.KeyName != tc.keyName || p.Auth.Type != tc.authType {
			t.Fatalf("%s: unexpected request setup: %+v", tc.platform, p)
		}
		if p.Response.ResultsPath != tc.path || p.Response.Fields.DefaultProtocol != "socks5" {
			t.Fatalf("%s: unexpected response mapping: %+v", tc.platform, p.Response)
		}
		if !strings.HasPrefix(p.Endpoint, "https://") {
			t.Fatalf("%s: endpoint must be https: %s", tc.platform, p.Endpoint)
		}
	}
}

func TestExtQuakeBodyTemplateIsValidJSON(t *testing.T) {
	p, _ := BuildPreset(config.MappingPresetConfig{Platform: "quake", Enabled: true, Size: 500})
	body, err := config.RenderMappingBody(p.BodyTemplate, map[string]string{
		"query": `service:socks5 AND "No authentication"`, "size": "500", "start": "0", "page": "1", "key": "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["query"] != `service:socks5 AND "No authentication"` {
		t.Fatalf("query not escaped correctly: %s", body)
	}
	if decoded["size"] != float64(500) {
		t.Fatalf("size not numeric: %s", body)
	}
}

func TestExtQueryEncodingVariants(t *testing.T) {
	q := "protocol=\"socks5\" && country=\"CN\""
	if got := encodeMappingQuery(q, ""); got != q {
		t.Fatal("plain encoding changed the query")
	}
	if got := encodeMappingQuery(q, "std"); got != base64.StdEncoding.EncodeToString([]byte(q)) {
		t.Fatal("std encoding mismatch")
	}
	if got := encodeMappingQuery(q, "url"); got != base64.URLEncoding.EncodeToString([]byte(q)) {
		t.Fatal("url encoding mismatch")
	}
}

func TestExtMappingBusinessError(t *testing.T) {
	resp := config.MappingResponse{ErrorPath: "error", SuccessValue: "false", MessagePath: "errmsg"}
	if err := checkMappingBusinessError([]byte(`{"error":false,"errmsg":""}`), resp); err != nil {
		t.Fatalf("success body rejected: %v", err)
	}
	if err := checkMappingBusinessError([]byte(`{"error":true,"errmsg":"bad key"}`), resp); err == nil || !strings.Contains(err.Error(), "bad key") {
		t.Fatalf("business error not detected: %v", err)
	}
	codeResp := config.MappingResponse{ErrorPath: "code", SuccessValue: "200"}
	if err := checkMappingBusinessError([]byte(`{"code":200,"data":{}}`), codeResp); err != nil {
		t.Fatalf("numeric code rejected: %v", err)
	}
	if err := checkMappingBusinessError([]byte(`{"code":401}`), codeResp); err == nil {
		t.Fatal("error code not detected")
	}
}

func TestExtPresetFetchFOFALikeResponse(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("qbase64")
		_, _ = w.Write([]byte(`{"error":false,"results":[["1.2.3.4","1080"],["5.6.7.8","1081"]]}`))
	}))
	defer srv.Close()

	p, _ := BuildPreset(config.MappingPresetConfig{
		Platform: "fofa", Enabled: true, KeyEnv: "TEST_KEY", Size: 10,
		Encoding: "url", Query: `protocol=="socks5"`,
	})
	p.Endpoint = srv.URL
	t.Setenv("TEST_KEY", "dummy")
	provider := &MappingProvider{cfg: p, global: config.MappingSourcesConfig{Enabled: true}, limiter: NewLimiter(0)}
	nodes, err := provider.Fetch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(nodes))
	}
	if nodes[0].DeclaredIP != "1.2.3.4" || nodes[0].Source != config.NodeSourceMapping {
		t.Fatalf("declared IP/source missing: %+v", nodes[0])
	}
	decoded, err := base64.URLEncoding.DecodeString(gotQuery)
	if err != nil || !strings.Contains(string(decoded), "socks5") {
		t.Fatalf("query not url-base64 encoded: %q", gotQuery)
	}
}

func TestExtPresetFetchQuakeLikeResponse(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-QuakeToken") != "dummy" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"data":[{"ip":"9.8.7.6","port":1080}]}`))
	}))
	defer srv.Close()

	p, _ := BuildPreset(config.MappingPresetConfig{Platform: "quake", Enabled: true, KeyEnv: "TEST_KEY", Size: 10})
	p.Endpoint = srv.URL
	t.Setenv("TEST_KEY", "dummy")
	provider := &MappingProvider{cfg: p, global: config.MappingSourcesConfig{Enabled: true}, limiter: NewLimiter(0)}
	nodes, err := provider.Fetch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].DeclaredIP != "9.8.7.6" {
		t.Fatalf("unexpected nodes: %+v", nodes)
	}
	if body["size"] != float64(10) || body["start"] != float64(0) {
		t.Fatalf("unexpected JSON body: %+v", body)
	}
	if !strings.HasPrefix(nodes[0].URI, "socks5://") {
		t.Fatalf("quake preset should produce socks5 nodes: %s", nodes[0].URI)
	}
}

func TestExtCustomProvidersStillSupported(t *testing.T) {
	global := config.MappingSourcesConfig{
		Enabled: true,
		Providers: []config.MappingProviderConfig{{
			Name: "custom", Enabled: true, Endpoint: "https://example.invalid/api",
			Method: "GET", Auth: config.MappingAuthConfig{Type: "none"},
		}},
	}
	providers := NewMappingProviders(global, nil)
	found := false
	for _, p := range providers {
		if p.Name() == "mapping:custom" {
			found = true
		}
	}
	if !found {
		t.Fatal("custom provider lost when presets are present")
	}
}

func TestExtNewMappingProvidersExpandsEnabledPresets(t *testing.T) {
	global := config.MappingSourcesConfig{
		Enabled: true,
		Presets: []config.MappingPresetConfig{{Platform: "fofa", Enabled: true, KeyEnv: "FOFA_KEY", Size: 100}},
	}
	providers := NewMappingProviders(global, nil)
	found := false
	for _, p := range providers {
		if p.Name() == "mapping:fofa" {
			found = true
		}
	}
	if !found {
		t.Fatal("enabled preset was not expanded")
	}
}
