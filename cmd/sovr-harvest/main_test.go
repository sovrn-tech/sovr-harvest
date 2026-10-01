package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthz(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var last atomic.Int64
	last.Store(now.Unix())
	h := healthz(&last, 10*time.Minute, func() time.Time { return now })
	code := func() int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		return rec.Code
	}
	if c := code(); c != http.StatusOK {
		t.Fatalf("fresh: %d", c)
	}
	now = now.Add(11 * time.Minute)
	if c := code(); c != http.StatusServiceUnavailable {
		t.Fatalf("stale: %d, want 503", c)
	}
	last.Store(now.Unix())
	if c := code(); c != http.StatusOK {
		t.Fatalf("after poll: %d", c)
	}
}
