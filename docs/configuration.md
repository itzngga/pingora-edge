# Configuration

One TOML file.
[`proxy.example.toml`](https://github.com/itzngga/pingora-edge/blob/main/proxy.example.toml) has
every key with a comment, start from there. Always check a file before using it:

```bash
pingora-edge --check proxy.toml
```

`[acme]`, `[security]` and at least one `[[route]]` must be there. `[security]` can be empty.
Required keys: `acme.email`, `acme.provider`, `acme.storage`, and `name` and `hosts` on each
route. Everything else has a default.

## Top level

| Key | Default | |
|---|---|---|
| `metrics` | `true` | serve `/metrics`, `/health` and `/api/*` |
| `metrics_listen` | `127.0.0.1:9090` | restart to change |
| `on_demand_hosts` | `""` | host list file for [on-demand TLS](certificates.md#on-demand-tls) |

## `[acme]`

Needs a restart to change.

| Key | Default | |
|---|---|---|
| `email` | required | |
| `provider` | required | `letsencrypt` or `zerossl` |
| `eab_kid`, `eab_hmac` | `""` | for ZeroSSL, never printed |
| `storage` | required | certs, account and caches. Must be writable |

## `[[route]]`

| `mode` | Does | Uses |
|---|---|---|
| `proxy` (default) | forwards to an upstream | `upstream`, `upstream_h2`, `insecure_skip_verify`, `timeout_secs`, `add_headers`, `on_demand_fallback` |
| `static` | serves a directory | `static_root`, `not_found_status`, `redirects` |
| `redirect` | redirects every host | `redirect_to`, `redirect_status` |

| Key | Default | |
|---|---|---|
| `name` | required | keep it unique, it's the route's identity across reloads |
| `hosts` | required | no wildcards. `[]` on the on-demand fallback route |
| `upstream` | | `host:port`, `http://host:port` or `https://host:port`, no path |
| `upstream_h2` | auto | HTTP/2 to a TLS upstream. Auto = on for Cloudflare upstreams |
| `insecure_skip_verify` | `false` | skip the upstream cert check |
| `timeout_secs` | global | upstream read timeout for this route |
| `add_headers` | | extra headers to the upstream |
| `rate_limit` | global | `{ rps = 100, burst = 200 }` |
| `cloudflare_only` | `false` | only accept Cloudflare peers |
| `static_cert`, `static_key` | | own cert for this route. Without it the route is in the ACME bundle |
| `ignore_ssl` | `false` | use the fallback cert, no ACME. For CDN-fronted origins |
| `static_root` | | must exist at startup |
| `not_found_status` | `404` | `404` or `410` |
| `redirects` | | exact paths that `301` on a static route |
| `redirect_to` | | target host, path and query are kept |
| `redirect_status` | `301` | `301`, `302`, `307` or `308` |
| `on_demand_fallback` | `false` | serves the on-demand host list. One route max |

`www.` hosts redirect to the apex by themselves. Static files support `.br`/`.gz` siblings,
ranges and conditional requests, with a 2 s memory cache.

## `[security]`

Access and request checks:

| Key | Default | |
|---|---|---|
| `trusted_ips` | `[]` | never tracked for abuse. Loopback is always trusted |
| `trust_cloudflare` | auto | don't strike Cloudflare peers. Auto = on with `trust_upstream_real_ip` or any `cloudflare_only` |
| `cloudflare_only` | `false` | for every route |
| `maintenance_mode` | `false` | |
| `blocked_ips` | `[]` | IPs and CIDRs. `--check` rejects very wide ranges |
| `block_user_agents` | `[]` | substrings, case-insensitive |
| `block_empty_user_agent` | `false` | |
| `block_header_patterns` | `[]` | |
| `block_scanners` | `true` | known scanner paths and tools |
| `reject_invalid_content_length` | `true` | |
| `reject_header_injection` | `true` | |
| `max_request_body` | `5242880` | bytes |

Limits:

| Key | Default | |
|---|---|---|
| `default_rate_limit`, `default_burst` | `50`, `100` | per visitor per route, req/s |
| `max_inflight_per_ip` | `150` | |
| `global_rps_limit` | `3000` | whole edge, `0` = off. Over it = instant `503` |
| `fingerprint_rps`, `fingerprint_burst` | `200`, `400` | per User-Agent, `0` = off |
| `global_connection_limit` | `8000` | inside Pingora |
| `max_live_tls` | `40000` | held by the pre-filter. The default is capped to fit RAM |
| `penalty_box_ttl_secs` | `300` | |
| `penalty_box_capacity` | `100000` | |
| `keepalive_max_requests` | `100` | per HTTP/1 connection |
| `keepalive_idle_secs` | from RAM | `60` under 2 GiB, `120` under 8 GiB, else `0` (no limit) |
| `global_timeout_secs` | `60` | upstream read timeout. `0` is an error if a proxy route uses it |

Pre-filter on `:443`:

| Key | Default | |
|---|---|---|
| `conn_rate_per_ip` | `100` | per 10 s, `0` = off |
| `abuse_strikes` | `3` | strikes before a block |
| `abuse_block_secs` | `300` | |
| `tls_fp_rate` | `0` | per ClientHello fingerprint per 10 s, `0` = off |
| `tls_fp_enforce` | `false` | `false` = only count (shadow mode) |
| `max_live_direct` | `0` | cap for non-Cloudflare connections, `0` = none |
| `max_live_direct_degraded` | `0` | that cap while the on-demand backend is down |
| `drop_direct_when_backend_down` | `false` | |

HTTP/2:

| Key | Default | |
|---|---|---|
| `http2_enabled` | `true` | restart. Off is the quick fix for a rapid reset flood |
| `h2_max_concurrent_streams` | `64` | restart |
| `h2_cancel_threshold` | `200` | cancels per IP per 10 s before a block, `0` = off |
| `h2_max_streams_per_conn` | `1000` | then `429` on that connection, `0` = off |

Circuit breaker:

| Key | Default | |
|---|---|---|
| `upstream_max_fails` | `10` | failures in a row, `0` = off |
| `upstream_fail_timeout_secs` | `5` | then one probe |

Real client IP (for chained edges):

| Key | Default | |
|---|---|---|
| `real_ip_header` | `X-Real-IP` | |
| `real_ip_sig_header` | `X-Real-IP-Sig` | `<unix-ts>.<hex HMAC-SHA256>` |
| `real_ip_secret` | `""` | shared key, never logged. The old key still works for 600 s after a change |
| `real_ip_verify` | `false` | only trust a valid signature |
| `trust_upstream_real_ip` | `false` | inner edges only, never on the internet-facing one |

## `[blocklist]`

| Key | Default | |
|---|---|---|
| `enabled` | `true` | |
| `source` | `""` | URL or file, JSON or plain text |
| `token` | `""` | `Authorization: Bearer` for URLs |
| `insecure` | `false` | skip cert checks for URLs |
| `pull_secs` | `300` | |
| `dyn_source` | `""` | short-lived entries, `{"ips":[{"ip":"...","ttl":60}]}` |
| `dyn_secs` | `30` | |
| `cache` | `""` | `""` = `<acme.storage>/blocklist-cache.json`, `off` = none |
| `origin_block_header` | `""` | upstream sets it to ban the visitor (max 3600 s). Stripped before the response goes out |

## `[error_page]`

| Key | Default | |
|---|---|---|
| `enabled` | `false` | self-refreshing 503 page for browsers |
| `retry_secs` | `8` | backs off x1.5 up to 60 |

## Headers

Removed from requests before they go upstream: `X-Real-IP`, `CF-Connecting-IP`,
`True-Client-IP`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL`,
`X-Rewrite-URL` and your real-IP headers. Then the edge sets the real-IP header itself.

Added to responses unless the upstream sets them: `X-XSS-Protection`, `X-Content-Type-Options`,
`X-Frame-Options`, `Strict-Transport-Security` (`max-age=63072000; includeSubDomains; preload`),
`Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
`Cross-Origin-Resource-Policy` and `Content-Security-Policy` (`upgrade-insecure-requests`).

## Live or restart

`[[route]]` and most of `[security]` reload live. These need a restart: `[acme]`, `[blocklist]`
(except `origin_block_header`), `[error_page]`, `metrics_listen`, `on_demand_hosts`,
`http2_enabled`, `h2_max_concurrent_streams` and a few sizing keys.

Not sure? `pingora-edge --check --against LIVE NEW` tells you. More in
[Operations](operations.md#reloading-the-config).
