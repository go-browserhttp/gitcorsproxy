// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

// parseRoute selects the upstream host that receives the client's Authorization
// header, so it is table-tested for what it must refuse and fuzzed for what it
// accepts (FuzzRoute, corpus in testdata/fuzz/FuzzRoute).

import (
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"
)

func routeProxy(t *testing.T) *Proxy {
	t.Helper()
	return mustProxy(t, Config{UpstreamHosts: []string{"github.com", "Forge.Example.net:3000"}})
}

func TestParseRoute(t *testing.T) {
	const refs = "/github.com/o/r.git/info/refs?service=git-upload-pack"
	tests := []struct {
		name   string
		method string
		target string
		want   int
	}{
		{"info/refs upload", http.MethodGet, refs, 0},
		{"info/refs receive", http.MethodGet, "/github.com/o/r.git/info/refs?service=git-receive-pack", 0},
		{"upload-pack", http.MethodPost, "/github.com/o/r.git/git-upload-pack", 0},
		{"receive-pack", http.MethodPost, "/github.com/o/r.git/git-receive-pack", 0},
		{"subgroups", http.MethodPost, "/github.com/a/b/c/r.git/git-upload-pack", 0},
		{"host with port, any case", http.MethodPost, "/forge.example.net:3000/o/r.git/git-upload-pack", 0},
		{"encoded segment that is not a dot segment", http.MethodPost, "/github.com/o/r%2e.git/git-upload-pack", 0},
		{"not a git shape", http.MethodGet, "/github.com/o/r", http.StatusBadRequest},
		{"dot-dot", http.MethodPost, "/github.com/../admin/r.git/git-upload-pack", http.StatusBadRequest},
		{"dot-dot last", http.MethodPost, "/github.com/o/../r.git/git-upload-pack", http.StatusBadRequest},
		{"dot segment", http.MethodPost, "/github.com/o/./r.git/git-upload-pack", http.StatusBadRequest},
		{"encoded dot-dot", http.MethodPost, "/github.com/o/%2e%2e/r.git/git-upload-pack", http.StatusBadRequest},
		{"encoded slash makes dot-dot", http.MethodPost, "/github.com/o/..%2f../r.git/git-upload-pack", http.StatusBadRequest},
		{"empty segment", http.MethodPost, "/github.com/o//r.git/git-upload-pack", http.StatusBadRequest},
		{"encoded empty segment", http.MethodPost, "/github.com/o%2f%2fx/r.git/git-upload-pack", http.StatusBadRequest},
		{"backslash", http.MethodPost, "/github.com/o%5cx/r.git/git-upload-pack", http.StatusBadRequest},
		{"control character", http.MethodPost, "/github.com/o%0d%0ax/r.git/git-upload-pack", http.StatusBadRequest},
		{"delete character", http.MethodPost, "/github.com/o%7fx/r.git/git-upload-pack", http.StatusBadRequest},
		{"info/refs via POST", http.MethodPost, refs, http.StatusMethodNotAllowed},
		{"pack via GET", http.MethodGet, "/github.com/o/r.git/git-upload-pack", http.StatusMethodNotAllowed},
		{"no service", http.MethodGet, "/github.com/o/r.git/info/refs", http.StatusBadRequest},
		{"bad service", http.MethodGet, "/github.com/o/r.git/info/refs?service=nope", http.StatusBadRequest},
		{"duplicate service", http.MethodGet, refs + "&service=git-receive-pack", http.StatusBadRequest},
		{"malformed query", http.MethodGet, refs + "&x=%zz", http.StatusBadRequest},
		{"host not allowed", http.MethodPost, "/evil.com/o/r.git/git-upload-pack", http.StatusForbidden},
		{"userinfo host", http.MethodPost, "/github.com@evil.com/o/r.git/git-upload-pack", http.StatusForbidden},
	}
	p := routeProxy(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.ParseRequestURI(tt.target)
			if err != nil {
				t.Fatal(err)
			}
			rt, status, msg := p.parseRoute(tt.method, u)
			if status != tt.want {
				t.Fatalf("status = %d (%s), want %d", status, msg, tt.want)
			}
			if tt.want == 0 && rt.host == "" {
				t.Fatal("accepted route without a host")
			}
		})
	}
}

// A request target never yields an invalid escape from URL.EscapedPath, so the
// decode-failure branch is pinned here directly.
func TestCleanRepoPathRejectsABadEscape(t *testing.T) {
	if cleanRepoPath("o%zzx/r.git") {
		t.Fatal("a bad percent-escape was accepted")
	}
	if !cleanRepoPath("o/r.git") {
		t.Fatal("a plain repository path was refused")
	}
}

// FuzzRoute asserts what an accepted route guarantees, for any request target
// the net/http server could hand over (it parses the request line with
// url.ParseRequestURI).
func FuzzRoute(f *testing.F) {
	f.Add(false, "/github.com/o/r.git/info/refs?service=git-upload-pack")
	f.Add(true, "/github.com/o/r.git/git-upload-pack")
	f.Add(true, "/forge.example.net:3000/a/b/r.git/git-receive-pack")
	f.Add(true, "/github.com/../x.git/git-upload-pack")
	f.Add(true, "/github.com/%2e%2e/x.git/git-upload-pack")
	f.Add(true, "/github.com/o//r.git/git-upload-pack")
	f.Add(false, "/github.com/o/r.git/info/refs?service=git-upload-pack&service=git-receive-pack")
	f.Add(true, "/github.com@evil.com/o/r.git/git-upload-pack")
	p, err := New(Config{AllowedOrigins: []string{testOrigin}, UpstreamHosts: []string{"github.com", "forge.example.net:3000"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, post bool, target string) {
		u, err := url.ParseRequestURI(target)
		if err != nil {
			t.Skip()
		}
		method := http.MethodGet
		if post {
			method = http.MethodPost
		}
		rt, status, _ := p.parseRoute(method, u)
		if status != 0 {
			return
		}

		if _, ok := p.hosts[strings.ToLower(rt.host)]; !ok {
			t.Fatalf("%q: accepted host %q is not allowlisted", target, rt.host)
		}
		switch rt.service {
		case "info/refs":
			svc := u.Query()["service"]
			if method != http.MethodGet || len(svc) != 1 || (svc[0] != "git-upload-pack" && svc[0] != "git-receive-pack") {
				t.Fatalf("%q: bad info/refs accepted (method %s, service %q)", target, method, svc)
			}
		case "git-upload-pack", "git-receive-pack":
			if method != http.MethodPost {
				t.Fatalf("%q: %s accepted with %s", target, rt.service, method)
			}
		default:
			t.Fatalf("%q: accepted service %q is not a git endpoint", target, rt.service)
		}
		dec, err := url.PathUnescape(rt.repoPath)
		if err != nil || !strings.HasSuffix(dec, ".git") && !strings.HasSuffix(rt.repoPath, ".git") {
			t.Fatalf("%q: repository path %q is not a .git path", target, rt.repoPath)
		}
		for _, seg := range strings.Split(dec, "/") {
			if seg == "" || seg == "." || seg == ".." {
				t.Fatalf("%q: repository path %q has dot or empty segment %q", target, rt.repoPath, seg)
			}
		}

		// The URL the request is forwarded to: its host is exactly the parsed
		// host, and its path stays inside the repository.
		up, err := url.Parse(rt.upstreamURL("https", u.RawQuery))
		if err != nil {
			t.Skip() // NewRequest would refuse it with a 500; nothing is dialed
		}
		if up.Host != rt.host || up.User != nil || up.Scheme != "https" {
			t.Fatalf("%q: upstream %q: host %q user %v, want host %q and no userinfo", target, up, up.Host, up.User, rt.host)
		}
		if path.Clean(up.Path) != up.Path {
			t.Fatalf("%q: upstream path %q is not in clean form", target, up.Path)
		}
		if !strings.HasPrefix(up.EscapedPath(), "/"+rt.repoPath+"/") {
			t.Fatalf("%q: upstream path %q left the repository path %q", target, up.EscapedPath(), rt.repoPath)
		}
	})
}
