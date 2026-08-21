// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

// Command gitcorsproxy runs the sovereign CORS git smart-HTTP proxy.
//
// It reads its configuration from flags, each of which falls back to an
// environment variable:
//
//	-listen              GITCORSPROXY_LISTEN              listen address                          (default ":8181")
//	-origins             GITCORSPROXY_ORIGINS             comma-separated allowed browser origins
//	-hosts               GITCORSPROXY_HOSTS               comma-separated upstream host allowlist
//	-tls-cert            GITCORSPROXY_TLS_CERT            optional TLS certificate file
//	-tls-key             GITCORSPROXY_TLS_KEY             optional TLS key file
//	-rate                GITCORSPROXY_RATE                requests per minute per client IP        (default 120)
//	-burst               GITCORSPROXY_BURST               back-to-back request burst per client IP (default 30)
//	-trusted-hops        GITCORSPROXY_TRUSTED_HOPS        trusted reverse-proxy hops for XFF       (default 1)
//	-max-response-bytes  GITCORSPROXY_MAX_RESPONSE_BYTES  cap on one relayed response, 0=unlimited (default 1073741824)
//	-timeout             GITCORSPROXY_TIMEOUT             per-request timeout, 0=none              (default 5m0s)
//
// -origins and -hosts are required. TLS is optional: in the sovereign
// deployment the proxy runs behind Caddy (which terminates Let's Encrypt TLS),
// so the two TLS flags are only for a standalone bind.
//
// # Abuse / DoS hardening
//
// The proxy is publicly reachable and cannot source-restrict (the playground
// runs in end-users' browsers), so it defends itself:
//
//   - -rate/-burst apply a per-client-IP token bucket; over budget → 429 with
//     Retry-After. The client IP is read from X-Forwarded-For counting from the
//     right by -trusted-hops (so a client-forged leftmost XFF cannot spoof the
//     key), falling back to the connection's RemoteAddr.
//   - -max-response-bytes caps a single relayed response so the proxy cannot be
//     used to shift unbounded bandwidth.
//   - -timeout bounds the whole proxied request so a slow-loris or hung upstream
//     cannot pin resources.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-browserhttp/gitcorsproxy"
)

// osExit is the process-exit seam, overridden in tests so main() is coverable.
var osExit = os.Exit

func main() { osExit(run(os.Args[1:], os.Stderr)) }

// listenAndServe and listenAndServeTLS are injection seams so run()'s serve
// branches are testable without binding a real long-lived listener.
var (
	listenAndServe    = func(srv *http.Server) error { return srv.ListenAndServe() }
	listenAndServeTLS = func(srv *http.Server, cert, key string) error {
		return srv.ListenAndServeTLS(cert, key)
	}
)

// run parses args, builds the proxy and serves. It returns a process exit code:
// 0 on a clean server shutdown, 1 on a configuration or serve error, 2 on a
// flag-parsing error.
func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("gitcorsproxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", env("GITCORSPROXY_LISTEN", ":8181"), "listen address")
	origins := fs.String("origins", env("GITCORSPROXY_ORIGINS", ""), "comma-separated allowed browser origins")
	hosts := fs.String("hosts", env("GITCORSPROXY_HOSTS", ""), "comma-separated upstream host allowlist")
	tlsCert := fs.String("tls-cert", env("GITCORSPROXY_TLS_CERT", ""), "optional TLS certificate file")
	tlsKey := fs.String("tls-key", env("GITCORSPROXY_TLS_KEY", ""), "optional TLS key file")
	rate := fs.Int("rate", envInt("GITCORSPROXY_RATE", 120), "requests per minute per client IP (0 disables)")
	burst := fs.Int("burst", envInt("GITCORSPROXY_BURST", 30), "back-to-back request burst per client IP")
	trustedHops := fs.Int("trusted-hops", envInt("GITCORSPROXY_TRUSTED_HOPS", 1), "trusted reverse-proxy hops for X-Forwarded-For")
	maxRespBytes := fs.Int64("max-response-bytes", envInt64("GITCORSPROXY_MAX_RESPONSE_BYTES", 1<<30), "cap on one relayed response in bytes (0 = unlimited)")
	timeout := fs.Duration("timeout", envDuration("GITCORSPROXY_TIMEOUT", 300*time.Second), "per-request timeout (0 = none)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	proxy, err := gitcorsproxy.New(gitcorsproxy.Config{
		AllowedOrigins:   splitList(*origins),
		UpstreamHosts:    splitList(*hosts),
		RatePerMinute:    *rate,
		Burst:            *burst,
		TrustedProxyHops: *trustedHops,
		MaxResponseBytes: *maxRespBytes,
		Timeout:          *timeout,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 15 * time.Second,
	}

	fmt.Fprintf(stderr, "gitcorsproxy: listening on %s (origins=%s hosts=%s rate=%d/min burst=%d hops=%d max-response=%d timeout=%s)\n",
		*listen, *origins, *hosts, *rate, *burst, *trustedHops, *maxRespBytes, *timeout)
	var serveErr error
	if *tlsCert != "" && *tlsKey != "" {
		serveErr = listenAndServeTLS(srv, *tlsCert, *tlsKey)
	} else {
		serveErr = listenAndServe(srv)
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		fmt.Fprintln(stderr, "gitcorsproxy:", serveErr)
		return 1
	}
	return 0
}

// env returns the value of the environment variable key, or def when unset.
func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// envInt returns key parsed as an int, or def when unset or unparseable.
func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envInt64 returns key parsed as an int64, or def when unset or unparseable.
func envInt64(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

// envDuration returns key parsed as a time.Duration, or def when unset or
// unparseable.
func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// splitList splits a comma-separated flag value into trimmed, non-empty items.
func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
