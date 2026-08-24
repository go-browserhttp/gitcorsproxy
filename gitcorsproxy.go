// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

// Package gitcorsproxy is a small, sovereign reverse proxy that lets a
// browser reach git smart-HTTP remotes that do not send CORS headers.
//
// A browser-hosted git client (for example the go-tex playground's wasm
// git-worker, github.com/go-tex/go-tex.github.io playground/internal/browsergit)
// speaks the git smart-HTTP protocol over the Fetch API. GitHub and most
// ghcr-style hosts answer that protocol correctly but send no
// Access-Control-Allow-Origin, so the browser blocks the response. This proxy
// sits in front: the browser talks to it same-origin-friendly (with an
// explicit allowed-origin list), and the proxy streams the git bytes to and
// from the real upstream, adding the CORS headers the browser needs.
//
// # Route
//
// The proxy accepts exactly the git smart-HTTP endpoint shape, with the
// upstream host carried as the first path segment:
//
//	GET  /<host>/<owner>/<repo>.git/info/refs?service=git-upload-pack
//	GET  /<host>/<owner>/<repo>.git/info/refs?service=git-receive-pack
//	POST /<host>/<owner>/<repo>.git/git-upload-pack
//	POST /<host>/<owner>/<repo>.git/git-receive-pack
//
// and forwards them to https://<host>/<owner>/<repo>.git/… . The <owner>/<repo>
// portion may contain nested groups (Forgejo/GitLab subgroups). Any path that
// does not match this shape is rejected 400.
//
// # Security posture
//
//   - CORS is scoped to a CONFIGURED explicit origin list. It is never "*",
//     because the client's Authorization header (a PAT) is forwarded upstream;
//     a wildcard origin with credential-bearing requests would let any web page
//     drive the user's token.
//   - An upstream-host ALLOWLIST is the primary SSRF control: only the exact
//     hosts an operator lists (github.com, the sovereign Forgejo host, …) are
//     reachable. Everything else is 403.
//   - As defence in depth the target host is resolved and every IP is checked
//     against a private/loopback/link-local/cloud-metadata denylist (ported
//     from the loom server's checkRemoteIP), so an allowlisted host that
//     resolves into an internal range is still refused.
//   - The Authorization header is forwarded upstream but NEVER logged. Nothing
//     in this package writes a token, a header dump, or a request body to the
//     logger.
//   - Because a browser CORS proxy is publicly reachable and cannot
//     source-restrict, it defends itself against abuse/DoS: a per-client-IP
//     token-bucket rate limit (429 + Retry-After), a cap on the size of a single
//     relayed response, and a per-request timeout. The client IP is read from
//     X-Forwarded-For counting from the right by a trusted-hops count, so a
//     client-forged leftmost entry cannot spoof the limiter key. These paths
//     never log the token either. See Config for the knobs; all default to off
//     in the library (the command sets production defaults).
//
// The proxy stores nothing: it is a pure auth-passthrough. The browser holds
// the user's PAT and sends it on each request; the proxy relays it and forgets
// it.
package gitcorsproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config configures a Proxy. AllowedOrigins and UpstreamHosts are required;
// the rest have production-safe defaults.
type Config struct {
	// AllowedOrigins is the explicit list of browser origins permitted to read
	// proxied responses, e.g. []string{"https://go-tex.github.io"}. It must be
	// non-empty and must not contain "*" — see the package doc for why a
	// wildcard is refused when Authorization is forwarded.
	AllowedOrigins []string

	// UpstreamHosts is the allowlist of upstream hosts the proxy will reach,
	// matched case-insensitively against the first path segment exactly as it
	// appears in the URL (including any :port), e.g.
	// []string{"github.com", "sources.example.net"}. It must be non-empty.
	UpstreamHosts []string

	// UpstreamScheme is the scheme used to reach the upstream. It defaults to
	// "https" and should stay that way in production; tests set "http" to reach
	// a local httptest server.
	UpstreamScheme string

	// Logger receives request/decision logs. Defaults to slog.Default(). The
	// proxy never logs the Authorization header, any token, or a request body.
	Logger *slog.Logger

	// Transport performs the upstream round-trip. Defaults to an SSRF-agnostic
	// http.Transport with compression passthrough (DisableCompression) so git
	// bytes are relayed verbatim. Primarily an injection seam for tests; the
	// SSRF decision itself lives in the ServeHTTP pre-flight, not here.
	Transport http.RoundTripper

	// LookupIP resolves a host to its IPs for the SSRF pre-flight. Defaults to
	// net.LookupIP. Injectable for tests.
	LookupIP func(host string) ([]net.IP, error)

	// --- abuse / DoS hardening (a browser CORS proxy is publicly reachable
	// and cannot source-restrict, so these bound what one client can extract)
	// ---

	// RatePerMinute is the sustained request budget per client IP. When it is
	// <= 0 rate limiting is disabled (the library default); the command sets a
	// production default. On exceed the proxy answers 429 with Retry-After.
	RatePerMinute int

	// Burst is the token-bucket ceiling: the number of requests a single client
	// IP may make back-to-back before the per-minute rate throttles it. When
	// <= 0 it falls back to RatePerMinute (a one-minute burst). Ignored when
	// rate limiting is disabled.
	Burst int

	// TrustedProxyHops is the number of trusted reverse proxies (Caddy, plus any
	// trusted CDN in front of it) between the client and this process. The real
	// client IP is read as the (1+hops)-th entry from the right of the
	// [X-Forwarded-For…, RemoteAddr] chain, so a client-forged LEFTMOST
	// X-Forwarded-For entry cannot spoof the limiter key. Default 0 means "trust
	// nothing, key on RemoteAddr"; the command defaults it to 1 for the
	// behind-Caddy deployment.
	TrustedProxyHops int

	// MaxResponseBytes caps the size of a single relayed upstream response so
	// the proxy cannot be used to shift unbounded bandwidth. 0 means unlimited
	// (the library default); the command sets a production default. A response
	// whose declared Content-Length exceeds the cap is refused 502 before any
	// body is streamed; an undeclared (chunked) body is truncated at the cap.
	MaxResponseBytes int64

	// Timeout bounds the whole proxied request (upstream round-trip plus body
	// relay) via a context deadline, so a slow-loris or hung upstream cannot pin
	// resources. 0 means no deadline (the library default); the command sets a
	// production default.
	Timeout time.Duration

	// Now is the limiter's clock. Defaults to time.Now; injectable for tests.
	Now func() time.Time

	// MaxTrackedIPs bounds the number of live per-IP buckets. Defaults to 65536.
	// Injectable for tests.
	MaxTrackedIPs int

	// IdleEvictAfter is how long a per-IP bucket may go unseen before it is
	// swept. Defaults to 10 minutes. Injectable for tests.
	IdleEvictAfter time.Duration
}

// Proxy is an http.Handler implementing the CORS git smart-HTTP proxy. It is
// safe for concurrent use.
type Proxy struct {
	origins   map[string]struct{}
	hosts     map[string]struct{}
	scheme    string
	log       *slog.Logger
	transport http.RoundTripper
	lookupIP  func(host string) ([]net.IP, error)

	limiter  *rateLimiter // nil when rate limiting is disabled
	hops     int
	maxBytes int64
	timeout  time.Duration
}

// errResponseTooLarge marks a relayed body that ran past MaxResponseBytes.
var errResponseTooLarge = errors.New("gitcorsproxy: upstream response exceeds size cap")

// New validates cfg and returns a ready Proxy. It errors when the required
// allowlists are empty or when AllowedOrigins contains a wildcard.
func New(cfg Config) (*Proxy, error) {
	if len(cfg.AllowedOrigins) == 0 {
		return nil, errors.New("gitcorsproxy: at least one allowed origin is required")
	}
	if len(cfg.UpstreamHosts) == 0 {
		return nil, errors.New("gitcorsproxy: at least one upstream host is required")
	}
	origins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		o = strings.TrimSpace(o)
		if o == "*" {
			return nil, errors.New("gitcorsproxy: wildcard origin \"*\" is refused because Authorization is forwarded")
		}
		if o == "" {
			continue
		}
		origins[o] = struct{}{}
	}
	if len(origins) == 0 {
		return nil, errors.New("gitcorsproxy: at least one allowed origin is required")
	}
	hosts := make(map[string]struct{}, len(cfg.UpstreamHosts))
	for _, h := range cfg.UpstreamHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		hosts[h] = struct{}{}
	}
	if len(hosts) == 0 {
		return nil, errors.New("gitcorsproxy: at least one upstream host is required")
	}

	hops := cfg.TrustedProxyHops
	if hops < 0 {
		hops = 0
	}
	p := &Proxy{
		origins:   origins,
		hosts:     hosts,
		scheme:    cfg.UpstreamScheme,
		log:       cfg.Logger,
		transport: cfg.Transport,
		lookupIP:  cfg.LookupIP,
		hops:      hops,
		maxBytes:  cfg.MaxResponseBytes,
		timeout:   cfg.Timeout,
	}
	if p.scheme == "" {
		p.scheme = "https"
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	if p.transport == nil {
		p.transport = &http.Transport{
			Proxy:              http.ProxyFromEnvironment,
			DisableCompression: true, // relay git bytes (and Content-Encoding) verbatim
			ForceAttemptHTTP2:  true,
		}
	}
	if p.lookupIP == nil {
		p.lookupIP = net.LookupIP
	}
	if cfg.RatePerMinute > 0 {
		burst := cfg.Burst
		if burst <= 0 {
			burst = cfg.RatePerMinute
		}
		now := cfg.Now
		if now == nil {
			now = time.Now
		}
		maxKeys := cfg.MaxTrackedIPs
		if maxKeys <= 0 {
			maxKeys = 1 << 16
		}
		idle := cfg.IdleEvictAfter
		if idle <= 0 {
			idle = 10 * time.Minute
		}
		p.limiter = newRateLimiter(cfg.RatePerMinute, burst, maxKeys, idle, now)
	}
	return p, nil
}

// gitRoute matches the git smart-HTTP endpoint shape. Group 1 is the upstream
// host, group 2 is the repo path (owner/…/repo.git, subgroups allowed), group 3
// is the service endpoint.
var gitRoute = regexp.MustCompile(`^/([^/]+)/(.+\.git)/(info/refs|git-upload-pack|git-receive-pack)$`)

// gitService is the set of services the info/refs query may request.
var gitService = map[string]struct{}{
	"git-upload-pack":  {},
	"git-receive-pack": {},
}

// forwardRequestHeaders are the request headers relayed upstream. Authorization
// rides here (and is never logged).
var forwardRequestHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"Authorization",
	"Content-Encoding",
	"Content-Type",
	"Git-Protocol",
	"User-Agent",
}

// forwardResponseHeaders are the upstream response headers relayed back.
var forwardResponseHeaders = []string{
	"Cache-Control",
	"Content-Encoding",
	"Content-Type",
	"Expires",
	"Pragma",
}

// ServeHTTP routes, guards and proxies a single request.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.setCORS(w, r)

	if r.Method == http.MethodOptions {
		// A CORS preflight is cheap and must always be answerable, so it is not
		// rate limited.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Per-client-IP rate limit. Keyed on the trustworthy client IP (see
	// clientIP) so one browser cannot exhaust the shared upstream, and a
	// forged X-Forwarded-For cannot spoof another client's budget.
	if p.limiter != nil {
		key := p.clientIP(r)
		if ok, retry := p.limiter.allow(key); !ok {
			secs := int(retry.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			p.log.Warn("gitcorsproxy: rate limited", "client", key)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	m := gitRoute.FindStringSubmatch(r.URL.EscapedPath())
	if m == nil {
		http.Error(w, "not a git smart-HTTP endpoint", http.StatusBadRequest)
		return
	}
	// host is the first path segment (a plain hostname[:port]); repoPath and
	// service keep their escaped form so they forward upstream verbatim.
	host, repoPath, service := m[1], m[2], m[3]

	// Method must match the endpoint: info/refs is a GET, the pack endpoints
	// are POSTs.
	if service == "info/refs" {
		if r.Method != http.MethodGet {
			http.Error(w, "info/refs must be GET", http.StatusMethodNotAllowed)
			return
		}
		if _, ok := gitService[r.URL.Query().Get("service")]; !ok {
			http.Error(w, "info/refs requires a git service query", http.StatusBadRequest)
			return
		}
	} else if r.Method != http.MethodPost {
		http.Error(w, service+" must be POST", http.StatusMethodNotAllowed)
		return
	}

	// Allowlist: the primary SSRF control.
	if _, ok := p.hosts[strings.ToLower(host)]; !ok {
		p.log.Warn("gitcorsproxy: host not allowed", "host", host, "client", p.clientIP(r))
		http.Error(w, "upstream host not allowed", http.StatusForbidden)
		return
	}

	// Defence in depth: refuse an allowlisted host that resolves into a
	// private/loopback/link-local/metadata range.
	if err := p.checkHost(host); err != nil {
		p.log.Warn("gitcorsproxy: host rejected by SSRF guard", "host", host, "reason", err.Error(), "client", p.clientIP(r))
		http.Error(w, "upstream host rejected", http.StatusForbidden)
		return
	}

	upstreamPath := "/" + repoPath + "/" + service
	upstream := p.scheme + "://" + host + upstreamPath
	if r.URL.RawQuery != "" {
		upstream += "?" + r.URL.RawQuery
	}

	// Log the decision — method, upstream host, path, service — but never the
	// Authorization header, token or body.
	p.log.Info("gitcorsproxy: proxying", "method", r.Method, "host", host, "path", upstreamPath, "service", queryService(r, service))

	// Bound the whole proxied request so a slow/hung upstream cannot pin
	// resources. The deadline covers the round-trip AND the streamed body,
	// because the request context propagates to resp.Body reads.
	ctx := r.Context()
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, r.Method, upstream, r.Body)
	if err != nil {
		http.Error(w, "bad upstream request", http.StatusInternalServerError)
		return
	}
	req.ContentLength = r.ContentLength
	copyHeaders(req.Header, r.Header, forwardRequestHeaders)

	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		p.log.Warn("gitcorsproxy: upstream error", "host", host, "error", err.Error())
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Size cap: a response that DECLARES a length past the cap is refused before
	// any body is written, so the client sees a clean error rather than a
	// truncated stream. An undeclared (chunked) body is capped mid-stream below.
	if p.maxBytes > 0 && resp.ContentLength > p.maxBytes {
		p.log.Warn("gitcorsproxy: upstream response too large", "host", host, "declared", resp.ContentLength, "cap", p.maxBytes)
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}

	copyHeaders(w.Header(), resp.Header, forwardResponseHeaders)
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	w.WriteHeader(resp.StatusCode)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if _, err := p.copyBody(w, resp.Body); err != nil {
		// Headers and status are already on the wire, so we cannot signal the
		// failure to the client — record it (never the token) and stop.
		p.log.Warn("gitcorsproxy: response copy interrupted", "host", host, "error", err.Error())
	}
}

// copyBody relays the upstream body to w, enforcing MaxResponseBytes. With no
// cap it is a plain io.Copy. With a cap it copies at most maxBytes and then
// checks for a single trailing byte; if the upstream had more, the relay stops
// with errResponseTooLarge (the client keeps the truncated bytes already sent).
func (p *Proxy) copyBody(w io.Writer, body io.Reader) (int64, error) {
	if p.maxBytes <= 0 {
		return io.Copy(w, body)
	}
	n, err := io.Copy(w, io.LimitReader(body, p.maxBytes))
	if err != nil {
		return n, err
	}
	if extra, _ := io.CopyN(io.Discard, body, 1); extra > 0 {
		return n, errResponseTooLarge
	}
	return n, nil
}

// setCORS writes the CORS headers. Access-Control-Allow-Origin echoes the
// request Origin only when it is in the configured allowlist; otherwise it is
// omitted so the browser blocks the read. Vary: Origin keeps caches correct.
func (p *Proxy) setCORS(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type,Git-Protocol,Authorization")
	h.Set("Access-Control-Expose-Headers", "Content-Type,Content-Length")
	h.Set("Access-Control-Max-Age", "600")
	h.Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	if _, ok := p.origins[origin]; ok {
		h.Set("Access-Control-Allow-Origin", origin)
	}
}

// checkHost resolves host and rejects it if any resolved IP is in a
// non-public range. A literal IP host is checked directly.
func (p *Proxy) checkHost(host string) error {
	// Strip a :port if present so the resolver sees a bare host.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return checkRemoteIP(ip)
	}
	ips, err := p.lookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve %q: no addresses", host)
	}
	for _, ip := range ips {
		if err := checkRemoteIP(ip); err != nil {
			return err
		}
	}
	return nil
}

// checkRemoteIP rejects an IP in a private/loopback/link-local/multicast/
// unspecified/cloud-metadata/IPv6-ULA range. Ported from the loom server's
// api_git.go guard.
func checkRemoteIP(ip net.IP) error {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	// The two most specific rejections come first so each is reachable on its
	// own: the cloud-metadata address is also link-local-unicast, and an IPv6
	// ULA is also "private", so placing them after those broader checks would
	// make them dead code.
	switch {
	case ip.Equal(net.IPv4(169, 254, 169, 254)):
		return fmt.Errorf("refusing cloud metadata IP %s", ip)
	case isIPv6ULA(ip):
		return fmt.Errorf("refusing IPv6 ULA %s", ip)
	case ip.IsLoopback():
		return fmt.Errorf("refusing loopback IP %s", ip)
	case ip.IsPrivate():
		return fmt.Errorf("refusing private IP %s", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("refusing link-local IP %s", ip)
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return fmt.Errorf("refusing multicast IP %s", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("refusing unspecified IP %s", ip)
	}
	return nil
}

// isIPv6ULA matches the fc00::/7 unique-local range.
func isIPv6ULA(ip net.IP) bool {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return false
	}
	return v6[0]&0xfe == 0xfc
}

// copyHeaders copies the named headers (all their values) from src to dst.
func copyHeaders(dst, src http.Header, names []string) {
	for _, n := range names {
		for _, v := range src.Values(n) {
			dst.Add(n, v)
		}
	}
}

// queryService returns the service being negotiated for logging: the ?service
// value on an info/refs GET, or the endpoint name for a pack POST.
func queryService(r *http.Request, service string) string {
	if service == "info/refs" {
		return r.URL.Query().Get("service")
	}
	return service
}

// clientIP returns the trustworthy client IP for rate limiting.
//
// The proxy runs behind p.hops trusted reverse proxies (Caddy, plus any trusted
// CDN in front of it). Treat [X-Forwarded-For entries…, RemoteAddr] as the
// address chain, rightmost = nearest to us. RemoteAddr is the immediate trusted
// peer, and each trusted proxy appended the address IT saw. The real client is
// therefore the (1+hops)-th entry from the right of that chain: skip RemoteAddr
// and the hops-1 trusted XFF entries our proxies added, and take the next one.
//
// Crucially this counts from the RIGHT, so a client that forges a LEFTMOST
// X-Forwarded-For value cannot move the key — the forged entry sits to the left
// of the address Caddy appended and is never selected. With hops <= 0 (trust
// nothing) or when X-Forwarded-For is absent or too short, it falls back to
// RemoteAddr.
func (p *Proxy) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if h, _, err := net.SplitHostPort(remote); err == nil {
		remote = h
	}
	if p.hops <= 0 {
		return remote
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remote
	}
	parts := strings.Split(xff, ",")
	// parts[idx] is the (1+hops)-th-from-right element of [parts…, RemoteAddr].
	idx := len(parts) - p.hops
	if idx < 0 {
		return remote
	}
	if ip := strings.TrimSpace(parts[idx]); ip != "" {
		return ip
	}
	return remote
}
