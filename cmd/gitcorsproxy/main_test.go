// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"errors"
	"net/http"
	"os"
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
