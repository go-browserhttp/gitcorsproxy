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
match this shape is rejected `400`. `info/refs` must be a `GET` with a valid
`service` query; the pack endpoints must be `POST`.

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
- The **`Authorization` header is never logged.** Nothing in this package
  writes a token, a header dump, or a request body to the logger.

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

| Flag        | Env                     | Default   | Meaning                              |
|-------------|-------------------------|-----------|--------------------------------------|
| `-listen`   | `GITCORSPROXY_LISTEN`   | `:8181`   | listen address                       |
| `-origins`  | `GITCORSPROXY_ORIGINS`  | —         | comma-separated allowed origins      |
| `-hosts`    | `GITCORSPROXY_HOSTS`    | —         | comma-separated upstream host allow-list |
| `-tls-cert` | `GITCORSPROXY_TLS_CERT` | —         | optional TLS certificate file        |
| `-tls-key`  | `GITCORSPROXY_TLS_KEY`  | —         | optional TLS key file                |

`-origins` and `-hosts` are required.

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
