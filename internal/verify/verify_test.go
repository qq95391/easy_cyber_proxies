package verify

import (
	"net/url"
	"strings"
	"testing"
)

func TestExtParseExitIP(t *testing.T) {
	cases := map[string]string{
		`{"origin":"1.2.3.4"}`:          "1.2.3.4",
		`{"ip":"5.6.7.8"}`:              "5.6.7.8",
		`{"origin":"9.9.9.9, 8.8.8.8"}`: "9.9.9.9",
		`"11.22.33.44"`:                 "",
		`<html>login</html>`:            "",
	}
	for input, want := range cases {
		if got := parseExitIP([]byte(input)); got != want {
			t.Fatalf("parseExitIP(%s) = %q, want %q", input, got, want)
		}
	}
}

func TestExtClassifyAnonymity(t *testing.T) {
	if got := classifyAnonymity([]byte(`{"headers":{"X-Forwarded-For":"1.2.3.4"}}`), "5.6.7.8", "9.9.9.9"); got != "transparent" {
		t.Fatalf("forwarded header should be transparent, got %q", got)
	}
	if got := classifyAnonymity([]byte(`{"headers":{"Host":"example.com"}}`), "5.6.7.8", "9.9.9.9"); got != "high" {
		t.Fatalf("clean headers should be high, got %q", got)
	}
	if got := classifyAnonymity([]byte(`{}`), "5.6.7.8", "5.6.7.8"); got != "transparent" {
		t.Fatalf("same direct/exit IP should be transparent, got %q", got)
	}
}

func TestExtScoreGrades(t *testing.T) {
	unreachable := Result{}
	if s, g := score(unreachable); s != 0 || g != "D" {
		t.Fatalf("unreachable score = %d %s", s, g)
	}
	good := Result{Reachable: true, SuccessRate: 1, LatencyMS: 100, Anonymity: "high", Handshake: "socks5", SpeedBPS: 1024}
	if s, g := score(good); s < 80 || g != "A" {
		t.Fatalf("good proxy score = %d %s", s, g)
	}
	poor := Result{Reachable: true, SuccessRate: 0.34, LatencyMS: 5000, Anonymity: "transparent"}
	if s, g := score(poor); s >= 40 || g == "A" || g == "B" {
		t.Fatalf("poor proxy score = %d %s", s, g)
	}
}

func TestExtRedactProxyURL(t *testing.T) {
	// url.User escapes the mask to %2A%2A%2A; what matters is that no
	// credential survives in API output.
	got := redactProxyURL("http://user:secret@1.2.3.4:8080")
	if strings.Contains(got, "secret") || strings.Contains(got, "user:") {
		t.Fatalf("credential leaked: %q", got)
	}
}

func TestExtBuildTransportSchemes(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:8080", "socks5://u:p@127.0.0.1:1080"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		tr, err := buildTransport(u, 0)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		tr.CloseIdleConnections()
	}
}
