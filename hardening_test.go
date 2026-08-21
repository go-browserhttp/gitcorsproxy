// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- New: hardening defaults ------------------------------------------------

func TestNewHardeningDefaults(t *testing.T) {
	// Burst <= 0 falls back to RatePerMinute; a negative hop count clamps to 0.
	p, err := New(Config{
		AllowedOrigins:   []string{testOrigin},
		UpstreamHosts:    []string{"github.com"},
		RatePerMinute:    120,
		Burst:            0,
		TrustedProxyHops: -3,
	})
	if err != nil {
		t.Fatalf("New() err = %v", err)
	}
	if p.limiter == nil {
		t.Fatal("limiter should be built when RatePerMinute > 0")
	}
	if p.limiter.burst != 120 {
		t.Errorf("burst = %v, want fallback to RatePerMinute 120", p.limiter.burst)
	}
	if p.hops != 0 {
		t.Errorf("hops = %d, want negative clamped to 0", p.hops)
	}
	if p.limiter.maxKeys != 1<<16 {
		t.Errorf("maxKeys = %d, want default 65536", p.limiter.maxKeys)
	}
	if p.limiter.idleAfter != 10*time.Minute {
		t.Errorf("idleAfter = %v, want default 10m", p.limiter.idleAfter)
	}
}

// --- token-bucket limiter (white-box) ---------------------------------------

func TestRateLimiterBucket(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	clock := func() time.Time { return now }
	// 60/min = 1 token/sec, burst 2.
	l := newRateLimiter(60, 2, 10, time.Minute, clock)

	// Two back-to-back requests fit the burst; the third is denied.
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("req 1 should pass")
	}
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("req 2 should pass (burst)")
	}
	ok, retry := l.allow("a")
	if ok {
		t.Fatal("req 3 should be denied")
	}
	if retry <= 0 || retry > time.Second {
		t.Fatalf("retry = %v, want (0,1s]", retry)
	}

	// A different key is independent even while "a" is throttled.
	if ok, _ := l.allow("b"); !ok {
		t.Fatal("distinct key must be independent")
	}

	// After one second "a" regains exactly one token.
	now = now.Add(time.Second)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("req after 1s refill should pass")
	}
	if ok, _ := l.allow("a"); ok {
		t.Fatal("only one token should have refilled")
	}
}

func TestRateLimiterSweepEviction(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	clock := func() time.Time { return now }
	// maxKeys 2, idle 1 minute.
	l := newRateLimiter(60, 1, 2, time.Minute, clock)

	l.allow("a") // a.last = base
	now = now.Add(2 * time.Minute)
	l.allow("b") // len 1 < 2, no sweep; b.last = base+2m
	l.allow("c") // len 2 >= 2 → sweep drops idle "a"; room made, no evict
	if _, ok := bucketsHas(l, "a"); ok {
		t.Fatal("idle bucket a should have been swept")
	}
	if _, ok := bucketsHas(l, "b"); !ok {
		t.Fatal("recent bucket b should survive")
	}
	if _, ok := bucketsHas(l, "c"); !ok {
		t.Fatal("new bucket c should be present")
	}
}

func TestRateLimiterEvictOldest(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	clock := func() time.Time { return now }
	// idle window huge so the sweep frees nothing; the cap forces evictOldest.
	l := newRateLimiter(60, 1, 2, time.Hour, clock)

	l.allow("x") // x.last = base
	now = now.Add(time.Second)
	l.allow("y") // y.last = base+1s
	now = now.Add(time.Second)
	l.allow("z") // len 2 >= 2, nothing idle → evict least-recently-seen "x"
	if _, ok := bucketsHas(l, "x"); ok {
		t.Fatal("least-recently-seen x should have been evicted")
	}
	if _, ok := bucketsHas(l, "y"); !ok {
		t.Fatal("y should survive")
	}
	if _, ok := bucketsHas(l, "z"); !ok {
		t.Fatal("z should be present")
	}
}

func bucketsHas(l *rateLimiter, key string) (*bucket, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	return b, ok
}

// --- clientIP (XFF rightmost-after-hops, anti-spoof) -------------------------

func TestClientIP(t *testing.T) {
	mk := func(remote, xff string, hops int) string {
		r := httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		p := &Proxy{hops: hops}
		return p.clientIP(r)
	}
	tests := []struct {
		name   string
		remote string
		xff    string
		hops   int
		want   string
	}{
		{"hops<=0 strips port", "192.0.2.9:555", "1.1.1.1", 0, "192.0.2.9"},
		{"hops<=0 no port", "192.0.2.9", "", 0, "192.0.2.9"},
		{"hops>0 no xff → remote", "10.0.0.1:1", "", 1, "10.0.0.1"},
		{"hops>0 xff too short → remote", "10.0.0.1:1", "1.1.1.1", 2, "10.0.0.1"},
		// Caddy (1 hop) appended the real client as the rightmost entry; the
		// attacker's forged leftmost 9.9.9.9 is ignored.
		{"hops=1 rightmost is real client", "10.0.0.1:1", "9.9.9.9, 1.1.1.1", 1, "1.1.1.1"},
		// Two trusted hops: skip the rightmost (nearest trusted) entry.
		{"hops=2 second-from-right", "10.0.0.1:1", "9.9.9.9, 1.1.1.1, 7.7.7.7", 2, "1.1.1.1"},
		// The selected slot is blank → fall back to RemoteAddr.
		{"hops selects empty slot → remote", "10.0.0.1:1", "  , 1.1.1.1", 2, "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mk(tt.remote, tt.xff, tt.hops); got != tt.want {
				t.Fatalf("clientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- rate limiting through ServeHTTP ----------------------------------------

// okTransport answers every upstream round-trip 200 with a tiny git body.
func okTransport() roundTripFunc {
	return func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": {"application/x-git-upload-pack-result"}},
			Body:          io.NopCloser(strings.NewReader("0008NAK\n")),
			ContentLength: -1,
		}, nil
	}
}

func TestServeRateLimit429(t *testing.T) {
	logBuf := &bytes.Buffer{}
	p := mustProxy(t, Config{
		RatePerMinute: 60, // 1 token/sec
		Burst:         1,
		Transport:     okTransport(),
		Logger:        slog.New(slog.NewTextHandler(logBuf, nil)),
	})

	do := func(remote, xff string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		req.Header.Set("Authorization", "token "+testToken)
		p.ServeHTTP(rec, req)
		return rec
	}

	// First request from the client passes; the second (burst exhausted) 429s.
	if rec := do("203.0.113.5:9000", ""); rec.Code != http.StatusOK {
		t.Fatalf("req1 code = %d, want 200", rec.Code)
	}
	rec := do("203.0.113.5:9000", "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("req2 code = %d, want 429", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want an integer >= 1", ra)
	}

	// A DIFFERENT client IP has its own bucket.
	if rec := do("198.51.100.7:1", ""); rec.Code != http.StatusOK {
		t.Fatalf("distinct IP code = %d, want 200 (independent bucket)", rec.Code)
	}

	// The forwarded token never reaches the log, even on the 429 path.
	if strings.Contains(logBuf.String(), testToken) || strings.Contains(logBuf.String(), "Authorization") {
		t.Fatalf("token leaked into logs:\n%s", logBuf.String())
	}
}

func TestServeRateLimitXFFAntiSpoof(t *testing.T) {
	p := mustProxy(t, Config{
		RatePerMinute:    60,
		Burst:            1,
		TrustedProxyHops: 1, // behind one Caddy
		Transport:        okTransport(),
	})

	do := func(xff string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil)
		req.RemoteAddr = "10.0.0.1:5000" // Caddy
		req.Header.Set("X-Forwarded-For", xff)
		p.ServeHTTP(rec, req)
		return rec.Code
	}

	// Caddy appended real client 1.1.1.1 (rightmost); leftmost is attacker-forged.
	if code := do("9.9.9.9, 1.1.1.1"); code != http.StatusOK {
		t.Fatalf("first real-client request code = %d, want 200", code)
	}
	// Same real client, DIFFERENT forged leftmost → must hit the SAME bucket → 429.
	if code := do("8.8.8.8, 1.1.1.1"); code != http.StatusTooManyRequests {
		t.Fatalf("spoofed-leftmost repeat code = %d, want 429 (key must be rightmost)", code)
	}
	// Different real client (rightmost) → independent bucket → allowed.
	if code := do("9.9.9.9, 2.2.2.2"); code != http.StatusOK {
		t.Fatalf("distinct real client code = %d, want 200", code)
	}
}

func TestServeRateLimitHopsZeroUsesRemoteAddr(t *testing.T) {
	// hops=0: XFF is ignored entirely, the key is RemoteAddr.
	p := mustProxy(t, Config{
		RatePerMinute:    60,
		Burst:            1,
		TrustedProxyHops: 0,
		Transport:        okTransport(),
	})
	do := func(remote, xff string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-For", xff)
		p.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do("203.0.113.9:1", "1.1.1.1"); code != http.StatusOK {
		t.Fatalf("req1 code = %d, want 200", code)
	}
	// Same RemoteAddr, different XFF: XFF is ignored so the bucket is shared → 429.
	if code := do("203.0.113.9:1", "2.2.2.2"); code != http.StatusTooManyRequests {
		t.Fatalf("req2 code = %d, want 429 (hops=0 keys on RemoteAddr)", code)
	}
}

// --- response size cap ------------------------------------------------------

func bodyTransport(status int, contentLength int64, body string) roundTripFunc {
	return func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    status,
			Header:        http.Header{"Content-Type": {"application/x-git-upload-pack-result"}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: contentLength,
		}, nil
	}
}

func serveGet(t *testing.T, p *Proxy) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil)
	req.Header.Set("Authorization", "token "+testToken)
	p.ServeHTTP(rec, req)
	return rec
}

func TestServeSizeCapDeclaredTooLarge(t *testing.T) {
	logBuf := &bytes.Buffer{}
	p := mustProxy(t, Config{
		MaxResponseBytes: 10,
		Transport:        bodyTransport(http.StatusOK, 100, strings.Repeat("x", 100)),
		Logger:           slog.New(slog.NewTextHandler(logBuf, nil)),
	})
	rec := serveGet(t, p)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502 (declared length over cap)", rec.Code)
	}
	if strings.Contains(logBuf.String(), testToken) {
		t.Fatalf("token leaked into logs:\n%s", logBuf.String())
	}
}

func TestServeSizeCapUnderCapPasses(t *testing.T) {
	p := mustProxy(t, Config{
		MaxResponseBytes: 100,
		Transport:        bodyTransport(http.StatusOK, -1, "0008NAK\n"),
	})
	rec := serveGet(t, p)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "0008NAK\n" {
		t.Fatalf("body = %q, want whole body under cap", rec.Body.String())
	}
}

func TestServeSizeCapChunkedTruncated(t *testing.T) {
	logBuf := &bytes.Buffer{}
	p := mustProxy(t, Config{
		MaxResponseBytes: 4,
		// ContentLength -1 (chunked) bypasses the declared-length check, so the
		// cap must bite mid-stream.
		Transport: bodyTransport(http.StatusOK, -1, "0008NAK\n"),
		Logger:    slog.New(slog.NewTextHandler(logBuf, nil)),
	})
	rec := serveGet(t, p)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (status already committed)", rec.Code)
	}
	if rec.Body.Len() != 4 {
		t.Fatalf("relayed %d bytes, want cap of 4", rec.Body.Len())
	}
	if !strings.Contains(logBuf.String(), "response copy interrupted") {
		t.Fatalf("expected a copy-interrupted log, got:\n%s", logBuf.String())
	}
	if strings.Contains(logBuf.String(), testToken) {
		t.Fatalf("token leaked into logs:\n%s", logBuf.String())
	}
}

func TestServeSizeCapBodyReadError(t *testing.T) {
	// A read error while a cap is active exercises copyBody's io.Copy error
	// branch (distinct from the plain-copy path with no cap).
	p := mustProxy(t, Config{
		MaxResponseBytes: 100,
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": {"application/x-git-upload-pack-result"}},
				Body:          errReadCloser{},
				ContentLength: -1,
			}, nil
		}),
	})
	rec := serveGet(t, p)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

// --- per-request timeout ----------------------------------------------------

func TestServeTimeoutHappyPath(t *testing.T) {
	// A generous deadline must not disturb a fast request; this covers the
	// context.WithTimeout branch on success.
	p := mustProxy(t, Config{
		Timeout:   5 * time.Second,
		Transport: okTransport(),
	})
	rec := serveGet(t, p)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestServeTimeoutTrips(t *testing.T) {
	logBuf := &bytes.Buffer{}
	returned := make(chan struct{})
	p := mustProxy(t, Config{
		Timeout: 20 * time.Millisecond,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done() // block until the per-request deadline fires
			close(returned)
			return nil, r.Context().Err()
		}),
		Logger: slog.New(slog.NewTextHandler(logBuf, nil)),
	})
	req := httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil)
	req.Header.Set("Authorization", "token "+testToken)
	rec := httptest.NewRecorder()

	done := make(chan int, 1)
	go func() {
		p.ServeHTTP(rec, req)
		done <- rec.Code
	}()

	select {
	case code := <-done:
		if code != http.StatusBadGateway {
			t.Fatalf("code = %d, want 502 on deadline", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after the deadline (possible hang)")
	}

	// The injected transport observed cancellation and returned — no leak.
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("upstream round-trip goroutine did not unblock")
	}

	if strings.Contains(logBuf.String(), testToken) {
		t.Fatalf("token leaked into logs:\n%s", logBuf.String())
	}
}

// --- limiter is off by default (library zero value) -------------------------

func TestServeNoLimiterByDefault(t *testing.T) {
	p := mustProxy(t, Config{Transport: okTransport()})
	if p.limiter != nil {
		t.Fatal("rate limiting must be disabled when RatePerMinute is unset")
	}
	// Many rapid requests all pass with no limiter.
	for i := 0; i < 5; i++ {
		if rec := serveGet(t, p); rec.Code != http.StatusOK {
			t.Fatalf("req %d code = %d, want 200", i, rec.Code)
		}
	}
}
