package session

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPrepareReplayAllowsIdempotentMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, "http://example.com/", nil)
		if ok, _ := prepareReplay(req, false); !ok {
			t.Fatalf("%s must be replayable", method)
		}
	}
}

func TestPrepareReplayRespectsIdempotencyKey(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("payload"))
	if ok, _ := prepareReplay(req, false); ok {
		t.Fatal("POST without Idempotency-Key must not be replayed")
	}
	keyed, _ := http.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader("payload"))
	keyed.Header.Set("Idempotency-Key", "abc-123")
	if ok, _ := prepareReplay(keyed, false); !ok {
		t.Fatal("POST with Idempotency-Key must be replayable")
	}
}

func TestPrepareReplayRejectsUpgradesAndLargeBodies(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	if ok, _ := prepareReplay(req, true); ok {
		t.Fatal("protocol upgrades must never be replayed")
	}
	large, _ := http.NewRequest(http.MethodPut, "http://example.com/", strings.NewReader(strings.Repeat("x", maxReplayBody+1)))
	if ok, _ := prepareReplay(large, false); ok {
		t.Fatal("bodies over the replay limit must not be buffered")
	}
}

func TestPrepareReplayRestoresBufferedBody(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPut, "http://example.com/", strings.NewReader("original"))
	ok, body := prepareReplay(req, false)
	if !ok || string(body) != "original" {
		t.Fatalf("replay buffer wrong: ok=%v body=%q", ok, string(body))
	}
	read, err := io.ReadAll(req.Body)
	if err != nil || string(read) != "original" {
		t.Fatalf("first attempt body was consumed: %q err=%v", string(read), err)
	}
}
