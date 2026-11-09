// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

// The first path segment is client-controlled and may be an authority carrying
// userinfo ("user:token@host"). RFC 3986 section 3.2.1 says nothing after the
// first colon of userinfo may be rendered in clear text. These tests pin that no
// refusal path writes it to the log, and fuzz the text that reaches the logger.

import (
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const canary = "CANARYtoken0123456789"

func TestRedactHost(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"github.com", "github.com"},
		{"GitHub.COM", "github.com"},
		{"forge.example.net:3000", "forge.example.net:3000"},
		{"user:" + canary + "@github.com", "github.com"}, // userinfo dropped
		{canary + "@github.com", "github.com"},
		{"user:" + canary + "@", redactedHost},                // no host left
		{"user:" + canary + "@evil.com:99999x", redactedHost}, // bad port
		{"user:" + canary + "@[::1]:80", redactedHost},        // not a hostname shape
		{"a%zz", redactedHost},                                // unparseable escape
		{"a%20b", redactedHost},                               // escape is not a host char
		{"under_score.example", redactedHost},
		{"-lead.example", redactedHost},
		{strings.Repeat("a", maxLoggedHost+1), redactedHost},
		{"", redactedHost},
	}
	for _, tt := range tests {
		got := redactHost(tt.in)
		if got != tt.want {
			t.Errorf("redactHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if strings.Contains(got, canary) {
			t.Errorf("redactHost(%q) leaked the credential: %q", tt.in, got)
		}
	}
}

// refusedTargets are inputs the proxy refuses (403 or 400) whose first segment
// carries a credential in one shape or another.
func refusedSegments() []string {
	return []string{
		"user:" + canary + "@evil.com",
		canary + "@github.com",
		"user:" + canary + "@github.com:443",
		"user%3A" + canary + "%40evil.com",
		"user:" + canary + "@" + strings.Repeat("a", 400) + ".com",
		"user:" + canary + "@",
		canary,
		canary + "%zz",
	}
}

func TestRefusedHostNeverReachesTheLogWithCredentials(t *testing.T) {
	for _, seg := range refusedSegments() {
		logBuf := &bytes.Buffer{}
		p := mustProxy(t, Config{Logger: slog.New(slog.NewTextHandler(logBuf, nil))})
		rec := httptest.NewRecorder()
		req := &http.Request{
			Method: http.MethodPost, Header: http.Header{}, RemoteAddr: "203.0.113.9:1",
			URL: &url.URL{Path: "/" + seg + "/o/r.git/git-upload-pack"},
		}
		p.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("segment %q was not refused", seg)
		}
		if strings.Contains(logBuf.String(), canary) {
			t.Errorf("segment %q: credential reached the log:\n%s", seg, logBuf.String())
		}
	}
}

// An allowlist entry that itself carries userinfo (an operator mistake) must
// not put it in the SSRF-guard line either.
func TestSSRFRejectLineNeverCarriesUserinfo(t *testing.T) {
	logBuf := &bytes.Buffer{}
	entry := "user:" + canary + "@internal.example"
	p := mustProxy(t, Config{
		UpstreamHosts: []string{entry},
		Logger:        slog.New(slog.NewTextHandler(logBuf, nil)),
		LookupIP:      func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.7")}, nil },
	})
	rec := httptest.NewRecorder()
	req := &http.Request{
		Method: http.MethodPost, Header: http.Header{}, RemoteAddr: "203.0.113.9:1",
		URL: &url.URL{Path: "/" + entry + "/o/r.git/git-upload-pack"},
	}
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	out := logBuf.String()
	if !strings.Contains(out, "SSRF guard") || !strings.Contains(out, "internal.example") {
		t.Fatalf("control: expected the SSRF line with the bare host:\n%s", out)
	}
	if strings.Contains(out, canary) {
		t.Fatalf("credential reached the SSRF log line:\n%s", out)
	}
}

func FuzzRedactHost(f *testing.F) {
	for _, s := range refusedSegments() {
		f.Add(s)
	}
	f.Add("github.com")
	f.Add("[::1]:80")
	f.Fuzz(func(t *testing.T, segment string) {
		got := redactHost(segment)
		if got == redactedHost {
			return
		}
		if len(got) > maxLoggedHost || !hostShape.MatchString(got) || got != strings.ToLower(got) {
			t.Fatalf("redactHost(%q) = %q: not a bounded, lowercase hostname[:port]", segment, got)
		}
		// Whatever precedes the last "@" is userinfo and must never survive.
		// ("/", "?" and "#" end the authority, so an "@" after them is not
		// userinfo; a route segment never holds a "/" anyway.)
		if i := strings.LastIndex(segment, "@"); i >= 0 && !strings.ContainsAny(segment, "/?#") && !strings.Contains(strings.ToLower(segment[i+1:]), got) {
			t.Fatalf("redactHost(%q) = %q: result is not drawn from the host after the last @", segment, got)
		}
	})
}

// FuzzRefusalLog drives the logger input end to end: a credential placed in
// userinfo before arbitrary fuzzer text must never appear in any log line, for
// every request the proxy refuses.
func FuzzRefusalLog(f *testing.F) {
	f.Add("evil.com")
	f.Add("github.com:443")
	f.Add("%zz")
	f.Add("[::1]")
	f.Fuzz(func(t *testing.T, tail string) {
		if strings.Contains(tail, canary) || strings.Contains(tail, "/") || strings.ContainsAny(tail, "\x00?#") {
			t.Skip()
		}
		seg := "user:" + canary + "@" + tail
		logBuf := &bytes.Buffer{}
		p := mustProxy(t, Config{Logger: slog.New(slog.NewTextHandler(logBuf, nil))})
		req := &http.Request{
			Method: http.MethodPost, Header: http.Header{}, RemoteAddr: "203.0.113.9:1",
			URL: &url.URL{Path: "/" + seg + "/o/r.git/git-upload-pack"},
		}
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if strings.Contains(logBuf.String(), canary) {
			t.Fatalf("segment %q: credential reached the log:\n%s", seg, logBuf.String())
		}
	})
}
