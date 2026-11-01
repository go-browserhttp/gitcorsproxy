// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

// The proxy sees every user's Authorization header, which makes it the one
// place a token could cross from one user to another. These tests pin what it
// does with that header: forward it to the request's own upstream and nowhere
// else, never write it (or a query string) to a log, never let a shared cache
// keep an authenticated answer.

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const placeholderToken = "PROXY-TOKEN-PLACEHOLDER-0123456789"

func authReq(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("Authorization", "Basic "+placeholderToken)
	return req
}

func TestAuthorizationIsNeverFollowedThroughARedirect(t *testing.T) {
	var thief atomic.Int32
	steal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		thief.Add(1)
	}))
	defer steal.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, steal.URL+"/x", http.StatusFound)
	}))
	defer up.Close()
	p, _ := newE2EProxy(t, up)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, authReq(http.MethodGet, "http://proxy/github.com/o/r.git/info/refs?service=git-upload-pack"))
	if thief.Load() != 0 {
		t.Fatalf("the redirect target received %d requests", thief.Load())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location relayed to the browser: %q", loc)
	}
}

func TestAuthenticatedResponsesAreNotCacheable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Expires", "Wed, 21 Oct 2099 07:28:00 GMT")
		w.Header().Set("Pragma", "cache")
		_, _ = io.WriteString(w, "refs")
	}))
	defer up.Close()
	p, _ := newE2EProxy(t, up)

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, authReq(http.MethodGet, "http://proxy/github.com/o/r.git/info/refs?service=git-upload-pack"))
	h := rec.Header()
	if h.Get("Cache-Control") != "private, no-store" || h.Get("Expires") != "" || h.Get("Pragma") != "" {
		t.Fatalf("authenticated response cache headers: %v", h)
	}
	if !strings.Contains(strings.Join(h.Values("Vary"), ","), "Authorization") {
		t.Fatalf("Vary must name Authorization: %v", h.Values("Vary"))
	}

	// The control: an anonymous request keeps the upstream's policy.
	anon := httptest.NewRequest(http.MethodGet, "http://proxy/github.com/o/r.git/info/refs?service=git-upload-pack", nil)
	anon.Header.Set("Origin", testOrigin)
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, anon)
	if rec2.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("anonymous Cache-Control = %q", rec2.Header().Get("Cache-Control"))
	}
}

func TestNoLogLineCarriesTheTokenOrTheQuery(t *testing.T) {
	logBuf := &bytes.Buffer{}
	p, err := New(Config{
		AllowedOrigins: []string{testOrigin},
		UpstreamHosts:  []string{"github.com"},
		LookupIP:       publicLookup,
		Logger:         slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Get", URL: r.URL.String(), Err: errors.New("connection refused")}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	// A careless client puts a credential in the query as well as the header.
	target := "http://proxy/github.com/o/r.git/info/refs?service=git-upload-pack&access_token=" + placeholderToken
	paths := []string{
		target, // upstream error path
		"http://proxy/evil.example/o/r.git/info/refs?service=git-upload-pack&access_token=" + placeholderToken, // 403 path
		"http://proxy/github.com/o/r.git/bogus?access_token=" + placeholderToken,                              // 400 path
	}
	for _, u := range paths {
		p.ServeHTTP(httptest.NewRecorder(), authReq(http.MethodGet, u))
	}
	logs := logBuf.String()
	if logs == "" {
		t.Fatal("control: the proxy should have logged something")
	}
	if strings.Contains(logs, placeholderToken) || strings.Contains(logs, "Authorization") || strings.Contains(logs, "access_token") {
		t.Fatalf("logs carry a credential:\n%s", logs)
	}
	if !strings.Contains(logs, "connection refused") {
		t.Fatalf("the upstream cause should still be logged:\n%s", logs)
	}
}

func TestUpstreamErr(t *testing.T) {
	err := &url.Error{Op: "Post", URL: "https://h/x?t=secret", Err: &url.Error{Op: "Get", URL: "https://h/y?t=secret", Err: errors.New("eof")}}
	if got := upstreamErr(err); got != "Post: Get: eof" {
		t.Fatalf("upstreamErr = %q", got)
	}
	if got := upstreamErr(errors.New("plain")); got != "plain" {
		t.Fatal(got)
	}
}

func TestAuthorizationGoesOnlyToTheRequestsUpstream(t *testing.T) {
	var seen []string
	p := mustProxy(t, Config{
		UpstreamHosts: []string{"github.com", "codeberg.org"},
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seen = append(seen, r.URL.Host+" "+r.Header.Get("Authorization"))
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
	})
	p.ServeHTTP(httptest.NewRecorder(), authReq(http.MethodGet, "http://proxy/codeberg.org/o/r.git/info/refs?service=git-upload-pack"))
	if len(seen) != 1 || seen[0] != "codeberg.org Basic "+placeholderToken {
		t.Fatalf("upstream requests = %v", seen)
	}
}
