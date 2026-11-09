// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// swapServe replaces both serve seams and returns a restore func.
func swapServe(nonTLS, tls func(*http.Server, string, string) error) func() {
	oldNon, oldTLS := listenAndServe, listenAndServeTLS
	if nonTLS != nil {
		listenAndServe = func(s *http.Server) error { return nonTLS(s, "", "") }
	}
	if tls != nil {
		listenAndServeTLS = func(s *http.Server, c, k string) error { return tls(s, c, k) }
	}
	return func() { listenAndServe, listenAndServeTLS = oldNon, oldTLS }
}

func TestRunFlagParseError(t *testing.T) {
	if code := run([]string{"-nope"}, &bytes.Buffer{}); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

func TestRunConfigError(t *testing.T) {
	if code := run([]string{"-origins", "", "-hosts", ""}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestRunServeSuccess(t *testing.T) {
	restore := swapServe(func(*http.Server, string, string) error { return nil }, nil)
	defer restore()
	if code := run([]string{"-origins", "https://x", "-hosts", "github.com"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestRunServeClosed(t *testing.T) {
	restore := swapServe(func(*http.Server, string, string) error { return http.ErrServerClosed }, nil)
	defer restore()
	if code := run([]string{"-origins", "https://x", "-hosts", "github.com"}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestRunServeError(t *testing.T) {
	restore := swapServe(func(*http.Server, string, string) error { return errors.New("boom") }, nil)
	defer restore()
	if code := run([]string{"-origins", "https://x", "-hosts", "github.com"}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestRunTLSSuccess(t *testing.T) {
	var gotCert, gotKey string
	restore := swapServe(nil, func(_ *http.Server, c, k string) error {
		gotCert, gotKey = c, k
		return nil
	})
	defer restore()
	code := run([]string{"-origins", "https://x", "-hosts", "github.com", "-tls-cert", "c.pem", "-tls-key", "k.pem"}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if gotCert != "c.pem" || gotKey != "k.pem" {
		t.Fatalf("cert/key = %q/%q, want c.pem/k.pem", gotCert, gotKey)
	}
}

func TestRunTLSError(t *testing.T) {
	restore := swapServe(nil, func(*http.Server, string, string) error { return errors.New("tls boom") })
	defer restore()
	code := run([]string{"-origins", "https://x", "-hosts", "github.com", "-tls-cert", "c.pem", "-tls-key", "k.pem"}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

// The two tests below exercise the DEFAULT serve closures (no override) with a
// deliberately invalid listen address so the bind fails fast instead of
// blocking.
func TestRunDefaultListenClosure(t *testing.T) {
	if code := run([]string{"-listen", "bad-no-port", "-origins", "https://x", "-hosts", "github.com"}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestRunDefaultTLSClosure(t *testing.T) {
	code := run([]string{"-listen", "bad-no-port", "-origins", "https://x", "-hosts", "github.com", "-tls-cert", "/no/such/cert", "-tls-key", "/no/such/key"}, &bytes.Buffer{})
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
}

func TestRunEnvFallback(t *testing.T) {
	t.Setenv("GITCORSPROXY_ORIGINS", "https://env-origin")
	t.Setenv("GITCORSPROXY_HOSTS", "github.com")
	restore := swapServe(func(*http.Server, string, string) error { return nil }, nil)
	defer restore()
	if code := run(nil, &bytes.Buffer{}); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestRunHardeningFlags(t *testing.T) {
	restore := swapServe(func(*http.Server, string, string) error { return nil }, nil)
	defer restore()
	code := run([]string{
		"-origins", "https://x", "-hosts", "github.com",
		"-rate", "5", "-burst", "2", "-trusted-hops", "2",
		"-max-response-bytes", "1024", "-timeout", "1s",
	}, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
}

func TestResolveTrustedHops(t *testing.T) {
	tests := []struct {
		name     string
		flag     int
		tls      bool
		want     int
		wantWarn bool
	}{
		{"auto behind a proxy", autoHops, false, 1, false},
		{"auto serving TLS directly", autoHops, true, 0, false},
		{"explicit 0 behind a proxy", 0, false, 0, false},
		{"explicit 2 behind a proxy", 2, false, 2, false},
		{"explicit 0 with TLS", 0, true, 0, false},
		{"explicit 1 with TLS warns", 1, true, 1, true},
	}
	for _, tt := range tests {
		got, warn := resolveTrustedHops(tt.flag, tt.tls)
		if got != tt.want || (warn != "") != tt.wantWarn {
			t.Errorf("%s: resolveTrustedHops(%d, %v) = %d, %q", tt.name, tt.flag, tt.tls, got, warn)
		}
	}
}

// serveAndProbe runs the command with args, captures the handler it would
// serve, and sends two requests from one connection address whose
// X-Forwarded-For differs only in its rightmost entry (the one a client picks
// when nothing in front of the proxy appends it). Burst 1 means the second
// request is throttled exactly when both map to the same limiter key. It
// returns the second response's status and what the command wrote to stderr.
func serveAndProbe(t *testing.T, args []string) (int, string) {
	t.Helper()
	var h http.Handler
	capture := func(s *http.Server, _, _ string) error { h = s.Handler; return nil }
	restore := swapServe(capture, capture)
	defer restore()
	var stderr bytes.Buffer
	base := []string{"-origins", "https://x", "-hosts", "github.com", "-rate", "1", "-burst", "1"}
	if code := run(append(base, args...), &stderr); code != 0 {
		t.Fatalf("run = %d: %s", code, stderr.String())
	}
	var second int
	for _, xff := range []string{"198.51.100.1", "198.51.100.2"} {
		req := httptest.NewRequest(http.MethodGet, "http://p/not-a-git-endpoint", nil)
		req.RemoteAddr = "203.0.113.7:4444"
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		second = rec.Code
	}
	return second, stderr.String()
}

func TestSpoofedXFFWhenServingTLSDirectly(t *testing.T) {
	tlsArgs := []string{"-tls-cert", "c.pem", "-tls-key", "k.pem"}

	// Default with TLS: nothing in front, so XFF is ignored and both requests
	// share the RemoteAddr key; the second is throttled.
	code, errOut := serveAndProbe(t, tlsArgs)
	if code != http.StatusTooManyRequests {
		t.Fatalf("TLS default: second request = %d, want 429 (the forged XFF must not change the key)", code)
	}
	if !strings.Contains(errOut, "hops=0") || strings.Contains(errOut, "warning") {
		t.Fatalf("TLS default banner:\n%s", errOut)
	}

	// Default behind a proxy (no TLS): one trusted hop, the rightmost XFF entry
	// is the client, so the two requests are distinct clients.
	code, errOut = serveAndProbe(t, nil)
	if code == http.StatusTooManyRequests {
		t.Fatalf("proxy default: second request throttled, want it keyed on the XFF entry")
	}
	if !strings.Contains(errOut, "hops=1") {
		t.Fatalf("proxy default banner:\n%s", errOut)
	}

	// Explicit hops with TLS is honoured, with a warning.
	code, errOut = serveAndProbe(t, append([]string{"-trusted-hops", "1"}, tlsArgs...))
	if code == http.StatusTooManyRequests || !strings.Contains(errOut, "hops=1") || !strings.Contains(errOut, "warning") {
		t.Fatalf("explicit hops with TLS: code=%d\n%s", code, errOut)
	}
}

func TestEnvInt(t *testing.T) {
	if got := envInt("GITCORSPROXY_TEST_INT", 7); got != 7 {
		t.Fatalf("unset → %d, want default 7", got)
	}
	t.Setenv("GITCORSPROXY_TEST_INT", "42")
	if got := envInt("GITCORSPROXY_TEST_INT", 7); got != 42 {
		t.Fatalf("set valid → %d, want 42", got)
	}
	t.Setenv("GITCORSPROXY_TEST_INT", "notanint")
	if got := envInt("GITCORSPROXY_TEST_INT", 7); got != 7 {
		t.Fatalf("set invalid → %d, want default 7", got)
	}
}

func TestEnvInt64(t *testing.T) {
	if got := envInt64("GITCORSPROXY_TEST_I64", 9); got != 9 {
		t.Fatalf("unset → %d, want default 9", got)
	}
	t.Setenv("GITCORSPROXY_TEST_I64", "1073741824")
	if got := envInt64("GITCORSPROXY_TEST_I64", 9); got != 1<<30 {
		t.Fatalf("set valid → %d, want 1<<30", got)
	}
	t.Setenv("GITCORSPROXY_TEST_I64", "nope")
	if got := envInt64("GITCORSPROXY_TEST_I64", 9); got != 9 {
		t.Fatalf("set invalid → %d, want default 9", got)
	}
}

func TestEnvDuration(t *testing.T) {
	if got := envDuration("GITCORSPROXY_TEST_DUR", time.Second); got != time.Second {
		t.Fatalf("unset → %v, want default 1s", got)
	}
	t.Setenv("GITCORSPROXY_TEST_DUR", "2m30s")
	if got := envDuration("GITCORSPROXY_TEST_DUR", time.Second); got != 150*time.Second {
		t.Fatalf("set valid → %v, want 2m30s", got)
	}
	t.Setenv("GITCORSPROXY_TEST_DUR", "banana")
	if got := envDuration("GITCORSPROXY_TEST_DUR", time.Second); got != time.Second {
		t.Fatalf("set invalid → %v, want default 1s", got)
	}
}

func TestMain_Exit(t *testing.T) {
	oldArgs, oldExit := os.Args, osExit
	defer func() { os.Args, osExit = oldArgs, oldExit }()
	var got int
	osExit = func(code int) { got = code }
	os.Args = []string{"gitcorsproxy", "-nope"}
	main()
	if got != 2 {
		t.Fatalf("exit code = %d, want 2", got)
	}
}
