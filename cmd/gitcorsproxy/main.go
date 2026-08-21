// Copyright (c) the go-browserhttp/gitcorsproxy authors.
// SPDX-License-Identifier: BSD-3-Clause

// Command gitcorsproxy runs the sovereign CORS git smart-HTTP proxy.
//
// It reads its configuration from flags, each of which falls back to an
// environment variable:
//
//	-listen   GITCORSPROXY_LISTEN    listen address           (default ":8181")
//	-origins  GITCORSPROXY_ORIGINS   comma-separated allowed browser origins
//	-hosts    GITCORSPROXY_HOSTS     comma-separated upstream host allowlist
//	-tls-cert GITCORSPROXY_TLS_CERT  optional TLS certificate file
//	-tls-key  GITCORSPROXY_TLS_KEY   optional TLS key file
//
// -origins and -hosts are required. TLS is optional: in the sovereign
// deployment the proxy runs behind Caddy (which terminates Let's Encrypt TLS),
// so the two TLS flags are only for a standalone bind.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
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
	if err := fs.Parse(args); err != nil {
		return 2
	}

	proxy, err := gitcorsproxy.New(gitcorsproxy.Config{
		AllowedOrigins: splitList(*origins),
		UpstreamHosts:  splitList(*hosts),
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

	fmt.Fprintf(stderr, "gitcorsproxy: listening on %s (origins=%s hosts=%s)\n", *listen, *origins, *hosts)
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
