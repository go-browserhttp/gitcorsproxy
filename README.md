<p align="center"><img src="https://raw.githubusercontent.com/go-browserhttp/brand/main/social/go-browserhttp.png" alt="go-browserhttp/gitcorsproxy" width="720"></p>

# go-browserhttp / gitcorsproxy

[![CI](https://github.com/go-browserhttp/gitcorsproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/go-browserhttp/gitcorsproxy/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-browserhttp/gitcorsproxy.svg)](https://pkg.go.dev/github.com/go-browserhttp/gitcorsproxy)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

A tiny, sovereign **CORS reverse proxy for git smart-HTTP**. It lets a browser
— specifically a Go/wasm git client such as the
[go-tex playground](https://github.com/go-tex/go-tex.github.io)'s
`git-worker.wasm` — reach git remotes that answer the smart-HTTP protocol
correctly but send **no `Access-Control-Allow-Origin`** (GitHub, ghcr-style
hosts, a bare Forgejo). The proxy forwards the git bytes both ways and adds the
CORS headers the browser needs, scoped to an explicit origin list.

Pure-Go, **CGO=0**, zero dependencies (standard library only). It stores
nothing: the browser holds the user's PAT and sends it on each request; the
proxy relays it and forgets it (**auth passthrough**).

```
browser (wasm go-git) ──▶ gitcorsproxy ──▶ https://github.com/owner/repo.git/…
        Fetch + PAT          + CORS               real smart-HTTP
```

## Route

The upstream host is carried as the first path segment; the rest is the git
smart-HTTP endpoint verbatim:

```
GET  /<host>/<owner>/<repo>.git/info/refs?service=git-upload-pack
GET  /<host>/<owner>/<repo>.git/info/refs?service=git-receive-pack
POST /<host>/<owner>/<repo>.git/git-upload-pack
POST /<host>/<owner>/<repo>.git/git-receive-pack
```

is proxied to `https://<host>/<owner>/<repo>.git/…`. The `<owner>/<repo>` part
may contain nested groups (Forgejo/GitLab subgroups). Anything that does not
match this shape is rejected `400`. `info/refs` must be a `GET` with exactly
one `service` query value naming a git service; the pack endpoints must be
`POST`. The repository path is forwarded verbatim, so a path with an empty,
`.` or `..` segment (also percent-encoded, or made with `%2f`), a control
character or a backslash is rejected `400`: an upstream that cleans paths could
otherwise be steered out of the repository the allow-list was meant to reach.
The parser is fuzzed (`FuzzRoute`, corpus in `testdata/fuzz/FuzzRoute`, run in
CI): an accepted request always has an allow-listed host, one of the four git
endpoints with the right method, a clean repository path, and an upstream URL
whose host is exactly the parsed host.

This is exactly the client contract of the go-tex playground's `browsergit`
package, whose panel accepts a proxy-prefixed base URL like
`https://gitproxy.<host>/github.com/owner/repo.git`.

## CORS

- `Access-Control-Allow-Origin` echoes the request `Origin` **only** when it is
  in the configured allow-list — it is **never `*`**, because the client's
  `Authorization` (a PAT) is forwarded upstream and a wildcard origin with
  credential-bearing requests would let any web page drive the user's token.
- `Access-Control-Allow-Methods: GET,POST,OPTIONS`
- `Access-Control-Allow-Headers: Content-Type,Git-Protocol,Authorization`
- `Access-Control-Expose-Headers: Content-Type,Content-Length`
- `OPTIONS` preflight is answered `204` with the headers above.

Request bodies and response bodies are **streamed** (never fully buffered — git
packs are large). `Content-Type` (`application/x-git-*`), `Git-Protocol`,
`Authorization`, `Content-Encoding`, `Accept-Encoding` and `User-Agent` are
forwarded upstream; the relevant response headers and the upstream status code
are preserved on the way back.

## Security: SSRF guard + no token logging

- An **upstream-host allow-list** is the primary control: only the exact hosts
  an operator lists (e.g. `github.com`, the sovereign Forgejo host) are
  reachable — everything else is `403`.
- As defence in depth the target host is resolved and every IP is checked
  against a private/loopback/link-local/multicast/unspecified/cloud-metadata/
  IPv6-ULA deny-list (ported from the loom server's `checkRemoteIP`), so an
  allow-listed host that resolves into an internal range is still refused.
- **The checked address is the one dialed (no DNS rebinding).** The host is
  resolved once; the transport's `DialContext` connects to exactly the
  addresses that passed the check and re-checks them at dial time, refusing
  private, loopback, link-local, multicast, unspecified and metadata addresses.
  A second lookup that answers differently is never consulted. The URL keeps
  the name, so `Host`, SNI and certificate verification are unchanged. The
  default transport no longer honours `HTTP_PROXY`/`HTTPS_PROXY`, so the check
  sees the real target; a `Config.Transport` you supply dials for itself.
- The **`Authorization` header is never logged.** Nothing in this package
  writes a token, a header dump, a query string or a request body to the
  logger. An upstream error is logged without its URL, because a client
  controls the query string and could have put a credential in it.
- **A refused host segment is never logged raw.** The first path segment is
  client-controlled and may be `user:token@host`. The 403 lines log it only
  after parsing it as an authority (RFC 3986 section 3.2.1: no password in
  clear text), dropping the userinfo, and only if what is left is a strict
  `hostname[:port]` of bounded length; otherwise they log `<invalid-host>`.
  `FuzzRedactHost` and `FuzzRefusalLog` (corpus in `testdata/fuzz`) run in CI.
- **It reaches only that request's upstream.** The proxy uses `RoundTrip`,
  which never follows a redirect, and relays no `Location` header.
- **Authenticated answers are not cacheable.** A response to a request that
  carried `Authorization` gets `Cache-Control: private, no-store` and
  `Vary: Authorization`, whatever the upstream said, so no shared cache in front
  of the proxy can serve one person's private repository to another.

Each point has a test (`authorization_test.go`) that fails if it is broken.

> **The operator of a proxy can read every token that passes through it.**
> Using a public proxy is a decision to trust its operator. Prefer a forge's
> REST API, which needs no proxy (GitHub and GitLab answer CORS themselves; see
> [browsergit](https://github.com/go-browserhttp/browsergit)), or run your own
> proxy.

## Library

```go
proxy, err := gitcorsproxy.New(gitcorsproxy.Config{
    AllowedOrigins: []string{"https://go-tex.github.io"},
    UpstreamHosts:  []string{"github.com", "sources.example.net"},
})
if err != nil {
    log.Fatal(err)
}
log.Fatal(http.ListenAndServe(":8181", proxy))
```

`*Proxy` is an `http.Handler`, so it drops into any server or middleware chain.

## Command

```
go run ./cmd/gitcorsproxy -origins https://go-tex.github.io -hosts github.com
```

Each flag falls back to an environment variable:

| Flag                  | Env                               | Default      | Meaning                                              |
|-----------------------|-----------------------------------|--------------|------------------------------------------------------|
| `-listen`             | `GITCORSPROXY_LISTEN`             | `:8181`      | listen address                                       |
| `-origins`            | `GITCORSPROXY_ORIGINS`            | —            | comma-separated allowed origins                      |
| `-hosts`              | `GITCORSPROXY_HOSTS`              | —            | comma-separated upstream host allow-list             |
| `-tls-cert`           | `GITCORSPROXY_TLS_CERT`           | —            | optional TLS certificate file                        |
| `-tls-key`            | `GITCORSPROXY_TLS_KEY`            | —            | optional TLS key file                                |
| `-rate`               | `GITCORSPROXY_RATE`               | `120`        | requests per minute per client IP (`0` disables)     |
| `-burst`              | `GITCORSPROXY_BURST`              | `30`         | back-to-back request burst per client IP             |
| `-trusted-hops`       | `GITCORSPROXY_TRUSTED_HOPS`       | `-1` (auto)  | trusted reverse-proxy hops; auto = `1`, `0` with TLS flags (see below) |
| `-max-response-bytes` | `GITCORSPROXY_MAX_RESPONSE_BYTES` | `1073741824` | cap on one relayed response in bytes (`0` unlimited) |
| `-timeout`            | `GITCORSPROXY_TIMEOUT`            | `5m0s`       | per-request timeout (`0` = none)                     |

`-origins` and `-hosts` are required.

## Abuse / DoS hardening

A browser CORS proxy is **publicly reachable and cannot source-restrict** — the
playground runs in end-users' browsers, so the proxy cannot allow-list callers.
It therefore defends itself:

- **Per-client-IP rate limiting.** A concurrency-safe token bucket (a tiny
  internal implementation — the package keeps its **zero-dependency** posture)
  keyed on the real client IP. Over budget → `429` with a `Retry-After` header.
  Idle buckets are swept and the live set is capped, so a spray of forged IPs
  cannot grow memory without bound.
- **Trustworthy client IP.** Behind Caddy the real client is the **rightmost**
  `X-Forwarded-For` entry Caddy appended — a client-forged **leftmost** entry is
  ignored. `-trusted-hops` N reads the `(1+N)`-th entry from the right of the
  `[X-Forwarded-For…, RemoteAddr]` chain, falling back to the connection
  `RemoteAddr` when the header is absent or too short. `-trusted-hops` counts
  the reverse proxies that **append** to the header. Left on auto it is `1`
  behind Caddy, and `0` when the proxy serves TLS itself (`-tls-cert` and
  `-tls-key`): nothing in front appends the header, so every entry is the
  client's and trusting one would let a client choose the address the rate
  limiter and fail2ban key on. An explicit non-zero value with TLS served
  directly is honoured (for example a CDN that re-encrypts to the origin) but
  prints a warning at startup. Set `-trusted-hops 2` if a CDN sits in front of
  Caddy.
- **Response-size cap.** `-max-response-bytes` bounds a single relayed response
  so the proxy cannot be used to shift unbounded bandwidth. A declared
  `Content-Length` over the cap is refused `502` before any body streams; an
  undeclared (chunked) body is truncated at the cap.
- **Per-request timeout.** `-timeout` bounds the whole proxied request via a
  context deadline, so a slow-loris or hung upstream cannot pin resources.

None of these paths log the `Authorization` header or the token.

## Deployment (behind the sovereign EU Caddy)

Run the proxy behind Caddy, which terminates Let's Encrypt TLS, so the two TLS
flags stay unused in production:

```caddyfile
gitproxy.example.net {
    reverse_proxy 127.0.0.1:8181
}
```

```
gitcorsproxy \
  -listen 127.0.0.1:8181 \
  -origins https://go-tex.github.io \
  -hosts github.com
```

The go-tex playground is then configured with a proxy-prefixed remote, e.g.
`https://gitproxy.example.net/github.com/owner/repo.git`. The proxy is
**auth-passthrough**: the browser sends the user's PAT on each request; the
proxy relays it upstream and never stores it. Keep the allow-lists tight — one
or two origins, one or two upstream hosts.

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026, the
go-browserhttp/gitcorsproxy authors.
