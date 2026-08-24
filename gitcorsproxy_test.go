// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// --- test doubles ------------------------------------------------------------

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// redirectTransport rewrites every request onto target (scheme+host) before
// delegating to base, so the proxy's logical upstream ("github.com") reaches a
// local httptest server.
type redirectTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (t redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme = t.target.Scheme
	r.URL.Host = t.target.Host
	r.Host = t.target.Host
	return t.base.RoundTrip(r)
}

// errReadCloser is a response body whose Read always fails, to exercise the
// mid-stream copy-error branch.
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("boom read") }
func (errReadCloser) Close() error             { return nil }

// noFlushWriter is a minimal http.ResponseWriter that does NOT implement
// http.Flusher, to cover the non-flushing branch.
type noFlushWriter struct {
	hdr  http.Header
	code int
	body bytes.Buffer
}

func (n *noFlushWriter) Header() http.Header         { return n.hdr }
func (n *noFlushWriter) Write(b []byte) (int, error) { return n.body.Write(b) }
func (n *noFlushWriter) WriteHeader(c int)           { n.code = c }

// publicLookup resolves any host to a single public IP so the SSRF pre-flight
// passes without touching the network.
func publicLookup(string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("140.82.121.3")}, nil
}

const testOrigin = "https://go-tex.github.io"

// --- New --------------------------------------------------------------------

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"no origins", Config{UpstreamHosts: []string{"github.com"}}, "allowed origin"},
		{"blank origins", Config{AllowedOrigins: []string{"  ", ""}, UpstreamHosts: []string{"github.com"}}, "allowed origin"},
		{"wildcard origin", Config{AllowedOrigins: []string{"*"}, UpstreamHosts: []string{"github.com"}}, "wildcard"},
		{"no hosts", Config{AllowedOrigins: []string{testOrigin}}, "upstream host"},
		{"blank hosts", Config{AllowedOrigins: []string{testOrigin}, UpstreamHosts: []string{" ", ""}}, "upstream host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("New() err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	p, err := New(Config{AllowedOrigins: []string{testOrigin}, UpstreamHosts: []string{"GitHub.com"}})
	if err != nil {
		t.Fatalf("New() err = %v", err)
	}
	if p.scheme != "https" {
		t.Errorf("scheme = %q, want https", p.scheme)
	}
	if p.log == nil {
		t.Error("default logger not set")
	}
	if p.transport == nil {
		t.Error("default transport not set")
	}
	if p.lookupIP == nil {
		t.Error("default lookupIP not set")
	}
	if _, ok := p.hosts["github.com"]; !ok {
		t.Errorf("host allowlist not lowercased: %v", p.hosts)
	}
}

// --- SSRF guard --------------------------------------------------------------

func TestCheckRemoteIP(t *testing.T) {
	tests := []struct {
		ip     net.IP
		reject bool
	}{
		{net.ParseIP("140.82.121.3"), false},
		{net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"), false},
		{net.ParseIP("127.0.0.1"), true},
		{net.ParseIP("::1"), true},
		{net.ParseIP("10.0.0.1"), true},
		{net.ParseIP("192.168.1.1"), true},
		{net.ParseIP("169.254.0.1"), true},     // link-local unicast
		{net.ParseIP("224.0.0.1"), true},       // multicast
		{net.ParseIP("ff02::1"), true},         // link-local multicast
		{net.ParseIP("ff01::1"), true},         // interface-local multicast
		{net.ParseIP("0.0.0.0"), true},         // unspecified
		{net.ParseIP("169.254.169.254"), true}, // cloud metadata
		{net.ParseIP("fd00::1"), true},         // IPv6 ULA
		{net.IP{1, 2, 3}, false},               // degenerate length → isIPv6ULA false path
	}
	for _, tt := range tests {
		err := checkRemoteIP(tt.ip)
		if (err != nil) != tt.reject {
			t.Errorf("checkRemoteIP(%v) err=%v, wantReject=%v", tt.ip, err, tt.reject)
		}
	}
}

// --- ServeHTTP: CORS + method routing ---------------------------------------

func mustProxy(t *testing.T, cfg Config) *Proxy {
	t.Helper()
	if cfg.AllowedOrigins == nil {
		cfg.AllowedOrigins = []string{testOrigin}
	}
	if cfg.UpstreamHosts == nil {
		cfg.UpstreamHosts = []string{"github.com"}
	}
	if cfg.LookupIP == nil {
		cfg.LookupIP = publicLookup
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() err = %v", err)
	}
	return p
}

func TestServePreflight(t *testing.T) {
	p := mustProxy(t, Config{})

	// Allowed origin → 204 + echoed ACAO + the CORS header set.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "http://proxy/github.com/o/r.git/git-upload-pack", nil)
	req.Header.Set("Origin", testOrigin)
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != testOrigin {
		t.Errorf("ACAO = %q, want %q", got, testOrigin)
	}
	for h, want := range map[string]string{
		"Access-Control-Allow-Methods":  "GET,POST,OPTIONS",
		"Access-Control-Allow-Headers":  "Content-Type,Git-Protocol,Authorization",
		"Access-Control-Expose-Headers": "Content-Type,Content-Length",
	} {
		if got := rec.Header().Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}

	// Disallowed origin → 204 but NO ACAO.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodOptions, "http://proxy/github.com/o/r.git/git-upload-pack", nil)
	req.Header.Set("Origin", "https://evil.example")
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO = %q, want empty for disallowed origin", got)
	}
}

func TestServeRejects(t *testing.T) {
	p := mustProxy(t, Config{})
	tests := []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"bad method", http.MethodPut, "http://p/github.com/o/r.git/git-upload-pack", http.StatusMethodNotAllowed},
		{"not git shape", http.MethodGet, "http://p/github.com/o/r", http.StatusBadRequest},
		{"info/refs via POST", http.MethodPost, "http://p/github.com/o/r.git/info/refs?service=git-upload-pack", http.StatusMethodNotAllowed},
		{"info/refs no service", http.MethodGet, "http://p/github.com/o/r.git/info/refs", http.StatusBadRequest},
		{"info/refs bad service", http.MethodGet, "http://p/github.com/o/r.git/info/refs?service=nope", http.StatusBadRequest},
		{"upload-pack via GET", http.MethodGet, "http://p/github.com/o/r.git/git-upload-pack", http.StatusMethodNotAllowed},
		{"host not allowed", http.MethodPost, "http://p/evil.com/o/r.git/git-upload-pack", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))
			if rec.Code != tt.want {
				t.Fatalf("code = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestServeSSRFRejections(t *testing.T) {
	// Literal loopback IP host in the allowlist → checkHost via net.ParseIP.
	pLoop := mustProxy(t, Config{UpstreamHosts: []string{"127.0.0.1"}})
	rec := httptest.NewRecorder()
	pLoop.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://p/127.0.0.1/o/r.git/git-upload-pack", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("loopback literal: code = %d, want 403", rec.Code)
	}

	// Hostname that resolves into a private range → checkHost via LookupIP.
	pPriv := mustProxy(t, Config{LookupIP: func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.1.2.3")}, nil
	}})
	rec = httptest.NewRecorder()
	pPriv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("private resolve: code = %d, want 403", rec.Code)
	}

	// Resolver failure → 403.
	pErr := mustProxy(t, Config{LookupIP: func(string) ([]net.IP, error) {
		return nil, errors.New("nxdomain")
	}})
	rec = httptest.NewRecorder()
	pErr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("resolve error: code = %d, want 403", rec.Code)
	}

	// Resolver returns no addresses → 403.
	pEmpty := mustProxy(t, Config{LookupIP: func(string) ([]net.IP, error) { return nil, nil }})
	rec = httptest.NewRecorder()
	pEmpty.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty resolve: code = %d, want 403", rec.Code)
	}
}

// TestServe403LogsClientIP pins the abuse-signal contract: every 403 rejection
// path — the allowlist reject and the SSRF-guard reject — logs the trustworthy
// client IP (so a fail2ban-style banner can extract and ban the offender), and
// none of them ever writes the forwarded token or the Authorization header.
func TestServe403LogsClientIP(t *testing.T) {
	const clientIP = "203.0.113.42"

	// do drives one 403 rejection with a logger attached and the client's
	// RemoteAddr + Authorization set, returning the captured log output.
	do := func(t *testing.T, cfg Config, target string) string {
		t.Helper()
		logBuf := &bytes.Buffer{}
		cfg.Logger = slog.New(slog.NewTextHandler(logBuf, nil))
		p := mustProxy(t, cfg)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, target, nil)
		req.RemoteAddr = clientIP + ":51000"
		req.Header.Set("Authorization", "token "+testToken)
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
		return logBuf.String()
	}

	// assert checks the rejection line names host and carries client=<ip>, and
	// that neither the token nor the Authorization header leaked.
	assert := func(t *testing.T, out, wantSubstr string) {
		t.Helper()
		if !strings.Contains(out, wantSubstr) {
			t.Fatalf("log missing rejection %q:\n%s", wantSubstr, out)
		}
		if !strings.Contains(out, "client="+clientIP) {
			t.Fatalf("403 log missing client=%s:\n%s", clientIP, out)
		}
		if strings.Contains(out, testToken) || strings.Contains(out, "Authorization") {
			t.Fatalf("token/Authorization leaked into 403 log:\n%s", out)
		}
	}

	t.Run("host not allowed", func(t *testing.T) {
		out := do(t, Config{}, "http://p/evil.com/o/r.git/git-upload-pack")
		assert(t, out, "host not allowed")
	})

	t.Run("SSRF guard", func(t *testing.T) {
		out := do(t, Config{LookupIP: func(string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("10.1.2.3")}, nil
		}}, "http://p/github.com/o/r.git/git-upload-pack")
		assert(t, out, "SSRF guard")
	})
}

func TestServeHostWithPort(t *testing.T) {
	// A host carrying an explicit :port exercises checkHost's SplitHostPort
	// branch; an injected transport avoids a real dial.
	p := mustProxy(t, Config{
		UpstreamHosts: []string{"forge.example.net:3000"},
		LookupIP:      publicLookup,
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "forge.example.net:3000" {
				t.Errorf("upstream host = %q, want forge.example.net:3000", r.URL.Host)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://p/forge.example.net:3000/o/r.git/git-upload-pack", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestServeUpstreamError(t *testing.T) {
	p := mustProxy(t, Config{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code = %d, want 502", rec.Code)
	}
}

func TestServeNewRequestError(t *testing.T) {
	// A host segment carrying a percent-escape passes the allowlist + injected
	// resolver but makes the upstream URL unparseable, exercising the
	// NewRequestWithContext error path.
	p := mustProxy(t, Config{UpstreamHosts: []string{"a%20b"}, LookupIP: publicLookup})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://p/a%20b/o/r.git/info/refs?service=git-upload-pack", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rec.Code)
	}
}

func TestServeBodyCopyError(t *testing.T) {
	// Upstream responds 200 with headers but the body fails mid-stream; the
	// proxy has already committed the status, so it just logs and stops.
	p := mustProxy(t, Config{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/x-git-upload-pack-result"}},
			Body:       errReadCloser{},
		}, nil
	})})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestServeNonFlushingWriter(t *testing.T) {
	// A ResponseWriter that is not an http.Flusher must still stream cleanly.
	p := mustProxy(t, Config{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/x-git-upload-pack-result"}},
			Body:       io.NopCloser(strings.NewReader("0008NAK\n")),
		}, nil
	})})
	w := &noFlushWriter{hdr: http.Header{}}
	p.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://p/github.com/o/r.git/git-upload-pack", nil))
	if w.code != http.StatusOK {
		t.Fatalf("code = %d, want 200", w.code)
	}
	if w.body.String() != "0008NAK\n" {
		t.Fatalf("body = %q", w.body.String())
	}
}

// --- end-to-end against a fake git smart-HTTP upstream -----------------------

type fakeUpstream struct {
	mu         sync.Mutex
	gotAuth    string
	gotService string
	gotBody    []byte
}

func (f *fakeUpstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/info/refs"):
			f.mu.Lock()
			f.gotAuth = r.Header.Get("Authorization")
			f.gotService = r.URL.Query().Get("service")
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = io.WriteString(w, "001e# service=git-upload-pack\n0000")
		case strings.HasSuffix(r.URL.Path, "/git-upload-pack"):
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.gotBody = body
			f.gotAuth = r.Header.Get("Authorization")
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			_, _ = io.WriteString(w, "0008NAK\n")
		default:
			http.NotFound(w, r)
		}
	})
}

// newE2EProxy wires a proxy whose upstream host "github.com" is redirected onto
// srv, with a buffered logger so we can prove the token is never written.
func newE2EProxy(t *testing.T, srv *httptest.Server) (*Proxy, *bytes.Buffer) {
	t.Helper()
	su, _ := url.Parse(srv.URL)
	logBuf := &bytes.Buffer{}
	p, err := New(Config{
		AllowedOrigins: []string{testOrigin},
		UpstreamHosts:  []string{"github.com"},
		UpstreamScheme: "http",
		LookupIP:       publicLookup,
		Logger:         slog.New(slog.NewTextHandler(logBuf, nil)),
		Transport:      redirectTransport{base: http.DefaultTransport, target: su},
	})
	if err != nil {
		t.Fatalf("New() err = %v", err)
	}
	return p, logBuf
}

const testToken = "ghp_SUPERSECRETTOKENvalue1234567890"

func TestE2EInfoRefs(t *testing.T) {
	up := &fakeUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()
	p, logBuf := newE2EProxy(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://proxy/github.com/owner/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Authorization", "token "+testToken)
	req.Header.Set("Git-Protocol", "version=2")
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		t.Errorf("Content-Type = %q, not preserved", ct)
	}
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("Cache-Control not forwarded")
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != testOrigin {
		t.Errorf("ACAO not added on proxied response")
	}
	if rec.Header().Get("Content-Length") == "" {
		t.Errorf("Content-Length not forwarded")
	}
	if !strings.Contains(rec.Body.String(), "# service=git-upload-pack") {
		t.Errorf("body not round-tripped: %q", rec.Body.String())
	}
	up.mu.Lock()
	gotAuth, gotService := up.gotAuth, up.gotService
	up.mu.Unlock()
	if gotAuth != "token "+testToken {
		t.Errorf("upstream Authorization = %q, want forwarded token", gotAuth)
	}
	if gotService != "git-upload-pack" {
		t.Errorf("upstream service query = %q", gotService)
	}
	// The token must never appear in the logs.
	if strings.Contains(logBuf.String(), testToken) || strings.Contains(logBuf.String(), "Authorization") {
		t.Fatalf("token or Authorization leaked into logs:\n%s", logBuf.String())
	}
}

func TestE2EUploadPack(t *testing.T) {
	up := &fakeUpstream{}
	srv := httptest.NewServer(up.handler())
	defer srv.Close()
	p, logBuf := newE2EProxy(t, srv)

	wantBody := "0032want 0000000000000000000000000000000000000000\n0000"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://proxy/github.com/owner/repo.git/git-upload-pack", strings.NewReader(wantBody))
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Authorization", "token "+testToken)
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-git-upload-pack-result" {
		t.Errorf("Content-Type = %q, not preserved", ct)
	}
	up.mu.Lock()
	gotBody := string(up.gotBody)
	up.mu.Unlock()
	if gotBody != wantBody {
		t.Errorf("upstream body = %q, want %q (not streamed through)", gotBody, wantBody)
	}
	if strings.Contains(logBuf.String(), testToken) {
		t.Fatalf("token leaked into logs:\n%s", logBuf.String())
	}
}
