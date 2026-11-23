package session

import (
	"bytes"
	"io"
	"net/http"
)

const maxReplayBody = 1 << 20

// prepareReplay decides whether a request can be safely re-sent before any
// response headers arrive, and buffers its body so a retry can reproduce it.
// It follows RFC 9110 §9.2.2: non-idempotent methods require an explicit
// Idempotency-Key, upgrades and unbounded bodies are never replayed.
func prepareReplay(req *http.Request, upgrade bool) (bool, []byte) {
	if upgrade || !isReplayableMethod(req) {
		return false, nil
	}
	if req.Body == nil || req.Body == http.NoBody || req.ContentLength == 0 {
		return true, nil
	}
	if req.ContentLength < 0 || req.ContentLength > maxReplayBody {
		return false, nil
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxReplayBody+1))
	// Always restore whatever was consumed so the first attempt is still valid.
	req.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil || len(body) > maxReplayBody {
		return false, nil
	}
	req.ContentLength = int64(len(body))
	return true, body
}

func isReplayableMethod(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	case http.MethodPost, http.MethodPatch:
		return req.Header.Get("Idempotency-Key") != ""
	default:
		return false
	}
}
