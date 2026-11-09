// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// BenchmarkServeHTTP measures the per-request overhead of the whole handler
// (route, allowlist, SSRF pre-flight, upstream request, relay) with a stub
// transport and a discarded log, so it isolates what the proxy itself adds.
// Run with -benchmem: allocations per request are exact, times are not.
func BenchmarkServeHTTP(b *testing.B) {
	p, err := New(Config{
		AllowedOrigins: []string{testOrigin},
		UpstreamHosts:  []string{"github.com"},
		LookupIP:       publicLookup,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/x-git-upload-pack-advertisement"}},
				Body:       io.NopCloser(strings.NewReader("001e# service=git-upload-pack\n0000")),
			}, nil
		}),
	})
	if err != nil {
		b.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://proxy/github.com/owner/repo.git/info/refs?service=git-upload-pack", nil)
	req.Header.Set("Origin", testOrigin)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.ServeHTTP(httptest.NewRecorder(), req)
	}
}
