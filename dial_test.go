// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

package gitcorsproxy

// The SSRF guard resolves the upstream host and checks every address; the
// connection must then go to an address that was checked, not to whatever a
// second lookup returns (DNS rebinding, a short TTL). These tests use a
// resolver that changes its answer after the first call.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// rebindingResolver answers with first on its first call and then with later,
// and counts its calls.
type rebindingResolver struct {
	mu           sync.Mutex
	calls        int
	first, later net.IP
}

func (r *rebindingResolver) lookup(string) ([]net.IP, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == 1 {
		return []net.IP{r.first}, nil
	}
	return []net.IP{r.later}, nil
}

func (r *rebindingResolver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// dialRecorder is a rawDial that records the addresses it is asked for and
// answers with an error (or a connection to target when target is set).
type dialRecorder struct {
	mu     sync.Mutex
	addrs  []string
	target string // connect here instead, when non-empty
	fail   map[string]bool
}

func (d *dialRecorder) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	fail := d.fail[addr]
	d.mu.Unlock()
	if fail || d.target == "" {
		return nil, errors.New("dial " + addr + ": refused by test")
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func (d *dialRecorder) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

func TestRebindingBetweenCheckAndConnectDialsTheCheckedIP(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "refs")
	}))
	defer up.Close()

	res := &rebindingResolver{first: net.ParseIP("140.82.121.3"), later: net.ParseIP("10.0.0.7")}
	rec := &dialRecorder{target: up.Listener.Addr().String()}
	p := mustProxy(t, Config{UpstreamScheme: "http", LookupIP: res.lookup})
	p.rawDial = rec.dial

	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://proxy/github.com/o/r.git/info/refs?service=git-upload-pack", nil))
	if w.Code != http.StatusOK || w.Body.String() != "refs" {
		t.Fatalf("code = %d body = %q, want 200 refs", w.Code, w.Body.String())
	}
	if res.count() != 1 {
		t.Fatalf("resolver called %d times, want exactly 1 (resolve once)", res.count())
	}
	if got := rec.dialed(); len(got) != 1 || got[0] != "140.82.121.3:80" {
		t.Fatalf("dialed %v, want only the checked IP 140.82.121.3:80", got)
	}
}

func TestDialResolvingItselfRefusesAnAnswerThatChanged(t *testing.T) {
	// A connection for a name the request pre-flight did not check resolves
	// once itself; if that single answer is private, nothing is dialed.
	res := &rebindingResolver{first: net.ParseIP("10.0.0.7"), later: net.ParseIP("140.82.121.3")}
	rec := &dialRecorder{}
	p := mustProxy(t, Config{LookupIP: res.lookup})
	p.rawDial = rec.dial
	_, err := p.dialContext(context.Background(), "tcp", "github.com:443")
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("err = %v, want a private-address refusal", err)
	}
	if len(rec.dialed()) != 0 {
		t.Fatalf("dialed %v despite the refusal", rec.dialed())
	}
}

func TestDialContextRefusesNonPublicAddressesAtDialTime(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.169.254", "169.254.1.1", "::1", "fe80::1", "fd00::1", "0.0.0.0", "224.0.0.1"} {
		rec := &dialRecorder{}
		p := mustProxy(t, Config{})
		p.rawDial = rec.dial

		// Literal address as the dial target.
		if _, err := p.dialContext(context.Background(), "tcp", net.JoinHostPort(ip, "443")); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("literal %s: err = %v, want a refusal", ip, err)
		}
		// Pre-approved set carrying a bad address is still refused at dial time.
		ctx := withResolved(context.Background(), "github.com", []net.IP{net.ParseIP("140.82.121.3"), net.ParseIP(ip)})
		if _, err := p.dialContext(ctx, "tcp", "github.com:443"); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("approved set with %s: err = %v, want a refusal", ip, err)
		}
		if len(rec.dialed()) != 0 {
			t.Errorf("%s: dialed %v despite the refusal", ip, rec.dialed())
		}
	}
}

func TestDialContextErrorsAndFallback(t *testing.T) {
	rec := &dialRecorder{}
	p := mustProxy(t, Config{})
	p.rawDial = rec.dial

	if _, err := p.dialContext(context.Background(), "tcp", "no-port"); err == nil {
		t.Error("an address without a port should be an error")
	}

	pe := mustProxy(t, Config{LookupIP: func(string) ([]net.IP, error) { return nil, errors.New("nxdomain") }})
	pe.rawDial = rec.dial
	if _, err := pe.dialContext(context.Background(), "tcp", "github.com:443"); err == nil {
		t.Error("a resolver failure should be an error")
	}

	// A stash for another name is ignored: the dial resolves for its own name.
	ctx := withResolved(context.Background(), "other.example", []net.IP{net.ParseIP("10.0.0.1")})
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer up.Close()
	ok := &dialRecorder{target: up.Listener.Addr().String()}
	p.rawDial = ok.dial
	conn, err := p.dialContext(ctx, "tcp", "GitHub.com:443")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	_ = conn.Close()
	if got := ok.dialed(); len(got) != 1 || got[0] != "140.82.121.3:443" {
		t.Fatalf("dialed %v, want the resolved checked IP", got)
	}

	// The first address fails, the second connects; all failing joins the errors.
	two := withResolved(context.Background(), "github.com", []net.IP{net.ParseIP("140.82.121.3"), net.ParseIP("140.82.121.4")})
	fb := &dialRecorder{target: up.Listener.Addr().String(), fail: map[string]bool{"140.82.121.3:443": true}}
	p.rawDial = fb.dial
	conn, err = p.dialContext(two, "tcp", "github.com:443")
	if err != nil {
		t.Fatalf("fallback err = %v", err)
	}
	_ = conn.Close()
	if got := fb.dialed(); len(got) != 2 {
		t.Fatalf("dialed %v, want both addresses tried in order", got)
	}
	none := &dialRecorder{}
	p.rawDial = none.dial
	if _, err := p.dialContext(two, "tcp", "github.com:443"); err == nil || !strings.Contains(err.Error(), "140.82.121.4") {
		t.Fatalf("all failing: err = %v, want the joined errors", err)
	}
}

func TestDefaultTransportRefusesALoopbackTarget(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the loopback server must not be reached")
	}))
	defer up.Close()
	p := mustProxy(t, Config{})
	req := httptest.NewRequest(http.MethodGet, up.URL, nil)
	req.RequestURI = ""
	resp, err := p.transport.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the default transport dialed a loopback address")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("err = %v, want a loopback refusal", err)
	}
}
