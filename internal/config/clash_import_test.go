package config

import (
	"strings"
	"testing"
)

func TestParseClashProxiesKeepsSupportedAndSkipsUnknown(t *testing.T) {
	doc := `proxies:
  - name: ss-1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: pw
  - name: wg-1
    type: wireguard
    server: 5.6.7.8
    port: 1000
`
	nodes, err := ParseClashProxies([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("unsupported type must be skipped, got %+v", nodes)
	}
	if nodes[0].Name != "ss-1" || !strings.HasPrefix(nodes[0].URI, "ss://") {
		t.Fatalf("unexpected node: %+v", nodes[0])
	}
}

func TestParseClashProxiesRejectsDocumentWithoutProxies(t *testing.T) {
	if _, err := ParseClashProxies([]byte("rules:\n  - MATCH,DIRECT\n")); err == nil {
		t.Fatal("expected an error for a document without proxies")
	}
}
