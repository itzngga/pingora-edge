# Abuse defence

Drop bad traffic as early and as cheaply as possible. From the outside in:

## 1. Pre-filter on `:443`

A small Tokio listener reads the TLS ClientHello before Pingora gets the connection, so dropped
clients never cost a handshake.

- non-TLS bytes (HTTP on 443) get reset, so do ClientHellos over 8 KiB and early disconnects
- 3 seconds to send a full ClientHello
- `conn_rate_per_ip`: new connections per IP per 10 s
- strikes: misbehaving IPs (like disconnecting mid-handshake) get refused for `abuse_block_secs`
  after `abuse_strikes`
- `tls_fp_rate`: limit per ClientHello fingerprint, for floods that rotate IPs but not the
  client. Starts in shadow mode, check `/api/tls-fingerprints` before you set
  `tls_fp_enforce = true`
- `max_live_tls`, with separate budgets for Cloudflare and direct traffic. While the on-demand
  backend is down, direct traffic can get a smaller cap or be refused
- a watchdog cleans up leaked connections

`trusted_ips` and Cloudflare peers (when trusted) never get strikes here. Every held connection
uses one local port to Pingora, so keep `max_live_tls` well under the kernel's port range.

## 2. HTTP/2

- `h2_max_concurrent_streams` per connection
- `h2_max_streams_per_conn`, then cheap `429`s
- `h2_cancel_threshold` counts cancels per IP and hands floods to the pre-filter to block
- `http2_enabled = false` falls back to HTTP/1.1, where rapid reset can't happen (restart)

## 3. Request checks

- scanner paths and tools, header injection, bad `Content-Length`, big bodies
- `blocked_ips`, `block_user_agents`, `block_header_patterns`, `block_empty_user_agent`
- blocklist from a file or URL, plus optional short-lived entries
- an upstream can ban the visitor it's answering with `origin_block_header`
- `cloudflare_only`, per route or for everything
- verified crawler IPs (from the lists Google, Bing, Apple, DuckDuckGo and OpenAI publish) are
  never blocked by the IP gates

## 4. Rate limits

- token bucket per route: `default_rate_limit` / `default_burst`, or `rate_limit` on the route
- `max_inflight_per_ip`
- `global_rps_limit`, past it requests get `503` right away
- `fingerprint_rps` per User-Agent, for botnets that reuse one UA on many IPs

## 5. Penalty box

IPs that trip the HTTP gates go in for `penalty_box_ttl_secs`. Repeat offenders move from HTTP
refusals to TCP-level blocks.

## 6. Circuit breaker

After `upstream_max_fails` failures in a row the route stops dialling the upstream, then sends
one probe after `upstream_fail_timeout_secs`. With `[error_page]` on, browsers get a 503 page
that refreshes itself.

## 7. Chained edges

The front edge sets `real_ip_header` and can sign it (HMAC-SHA256) with `real_ip_secret`. The
inner edge trusts it only from trusted peers (`trust_upstream_real_ip`), and with
`real_ip_verify` only when the signature is valid.

## Tips

- start with the defaults and watch `/metrics`, refusals are counted per gate
- long blocks beat attackers that rotate IPs, but home IPs get shared and reused, so a long block
  can hit a real visitor
- use shadow mode first where there is one
