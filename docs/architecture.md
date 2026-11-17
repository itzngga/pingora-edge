# Architecture

```text
                          +------------------------------+
 client --TCP--> :443 --> | pre-filter (Tokio)           | --loopback--> Pingora 127.0.0.1:4443
                          | conn-rate gate, abuse box,   |               TLS (BoringSSL), SNI certs,
                          | ClientHello checks, budgets  |               WAF, limits, routing
                          +------------------------------+                    |
                                                                              v
 client --HTTP--> :80 --> ACME HTTP-01 challenges, else 301 to https    upstreams / static roots

 127.0.0.1:9090   /metrics, /health, /api/*
 unix socket      config status, verify, reload; certificate status and warmup
```

1. The pre-filter reads the ClientHello and decides if the connection is worth it.
2. Good ones get spliced to Pingora on `127.0.0.1:4443`. The real client IP goes along through a
   table keyed by the loopback source port, so no PROXY protocol.
3. Pingora terminates TLS and picks the cert by SNI.
4. Request checks, limits, routing, then upstream or a file from disk.
5. `:80` answers ACME challenges and redirects the rest to HTTPS.

Why the pre-filter: Pingora sets up TLS state as soon as it accepts. A flood of half-open, non-TLS
or slow connections can use that up before any HTTP check runs. Reading a ClientHello first is a
lot cheaper. The cost is one loopback hop and one local port per connection.

Around it: one reload task owns the config, a unix socket for control calls, the metrics
listener, and a background job that renews on-demand certs.

## Source

| File | |
|---|---|
| [`main.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/main.rs) | boot, runtimes, Pingora server |
| [`tls_router.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/tls_router.rs) | the `:443` pre-filter |
| [`proxy.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/proxy.rs) | Pingora `ProxyHttp`: filters, routing, upstreams |
| [`h2_guard.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/h2_guard.rs) | rapid reset guard |
| [`limiter.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/limiter.rs), [`breaker.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/breaker.rs) | rate limits, penalty box, breaker |
| [`acme.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/acme.rs), [`on_demand.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/on_demand.rs) | ACME bundle, on-demand certs |
| [`static_handler.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/static_handler.rs) | static files |
| [`config.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/config.rs) | config and defaults |
| [`check.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/check.rs), [`check_rules.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/check_rules.rs) | `--check` |
| [`reload.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/reload.rs) | hot reload |
| [`shield.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/shield.rs), [`blocklist.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/blocklist.rs) | Cloudflare and crawler ranges, blocklist |
| [`metrics.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/metrics.rs), [`control.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/control.rs), [`cli.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/cli.rs) | metrics, control socket, CLI |
| [`tuning.rs`](https://github.com/itzngga/pingora-edge/blob/main/src/tuning.rs) | memory sizing |

## Tests

```bash
cargo test
```

Unit tests for the parts (parsers, limiters, breaker, budgets, config checks, static files). No
end-to-end suite, so also try changes with the [local setup](getting-started.md#try-it-locally).
