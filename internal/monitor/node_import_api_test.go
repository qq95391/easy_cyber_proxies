package monitor

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestNodePreviewMarksDuplicates(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	body := `{"mode":"clash","yaml":"proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: x\n  - name: b\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-128-gcm\n    password: y\n"}`
	resp := proxyAPIRequest(t, s, http.MethodPost, "/api/nodes/preview", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Items []struct {
			Name      string `json:"name"`
			Duplicate bool   `json:"duplicate"`
		} `json:"items"`
		Summary struct {
			Total     int `json:"total"`
			Unique    int `json:"unique"`
			Duplicate int `json:"duplicate"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Summary.Total != 2 || payload.Summary.Unique != 1 || payload.Summary.Duplicate != 1 {
		t.Fatalf("summary wrong: %+v", payload.Summary)
	}
	if len(payload.Items) != 2 || payload.Items[0].Duplicate || !payload.Items[1].Duplicate {
		t.Fatalf("duplicate flags wrong: %+v", payload.Items)
	}
}

func TestNodeBatchDeleteDryRunMatchesNames(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	body := `{"names":["node-a","node-b"],"dry_run":true}`
	resp := proxyAPIRequest(t, s, http.MethodPost, "/api/nodes/config/batch-delete", body)
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	var payload struct {
		DryRun  bool     `json:"dry_run"`
		Count   int      `json:"count"`
		Matched []string `json:"matched"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.DryRun || payload.Count != 2 || len(payload.Matched) != 2 {
		t.Fatalf("unexpected dry-run payload: %+v", payload)
	}
}

func TestNodeBatchDeleteRejectsEmptySelection(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	resp := proxyAPIRequest(t, s, http.MethodPost, "/api/nodes/config/batch-delete", `{"names":[],"dry_run":true}`)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("empty selection must be rejected, got %d", resp.Code)
	}
}

func TestNodePreviewRejectsEmptyURLList(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	resp := proxyAPIRequest(t, s, http.MethodPost, "/api/nodes/preview", `{"mode":"urls","urls":["  "]} `)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("empty preview must be rejected, got %d", resp.Code)
	}
}
