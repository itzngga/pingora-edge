# Operations

## Checking a config

Same checks the edge runs at boot and on reload. Writes nothing.

```text
pingora-edge --check [--json] [--strict] [--offline] [--workdir DIR] [--against FILE] <FILE|->
```

| Flag | |
|---|---|
| `--json` | JSON output |
| `--strict` | warnings fail too |
| `--offline` | skip checks on this machine (cert files, folders). Handy on a laptop |
| `--workdir DIR` | resolve relative paths from `DIR` |
| `--against FILE` | diff against the live config: what changes, restart or not. Needs a file |
| `-` | read from stdin |

| Code | Means |
|---|---|
| `F1xx`, `F2xx` | can't read, parse or type the file |
| `E2xx`, `E3xx` | broken: bad upstream, redirect loop, bad cert, ACME folder not writable |
| `W4xx` | allowed but suspicious: a `0` that isn't "off", unknown keys, odd hosts |
| `I5xx` | info, like `insecure_skip_verify` |
| `N6xx` | what a change will do: restart needed, route removed, bundle reissued |

Secrets (`eab_hmac`, `real_ip_secret`, `token`) are never printed.

Exit codes: `0` ok, `10` restart required, `11` warnings with `--strict`, `12` sha mismatch,
`64` usage, `65` invalid or rejected, `66` unreadable, `69` no control socket, `70` internal,
`75` timeout or not ready, `77` forbidden.

## Reloading the config

```text
pingora-edge --reload [--json] [--sock PATH] [--timeout SECS] [--expect-sha HEX64]
pingora-edge --status [--json] [--sock PATH] [--expect-sha HEX64]
```

Three ways in, same pipeline:

- SIGHUP (`systemctl reload pingora-edge`), which also rereads the on-demand list and static certs
- the edge sees the file change
- `pingora-edge --reload`, or `POST /config/reload` on the control socket

What you get:

- the file is checked first, then applied whole or not at all. A request never sees half old,
  half new
- restart-only keys come back as `restart_required` instead of half applying
- under systemd (or `PROXY_SUPERVISED=1`), a SIGHUP with restart-only changes makes the edge
  stop itself so systemd starts it again, at most once a minute
- `--expect-sha` (64 lowercase hex) applies nothing unless the file on disk has that hash, exit `12`
- every clean config is saved as `.proxy.toml.last-good` next to it (or `PROXY_LAST_GOOD`, an
  absolute path or `off`). It's only used at boot when the real file is broken

## Control socket

HTTP over a unix socket, nothing on the network. Default `/run/pingora-edge/control.sock`,
`CONTROL_SOCK` changes it. Anyone local can read, `POST` needs root or the edge's own user.

| Route | |
|---|---|
| `GET /health` | `{"status":"ok"}` |
| `GET /config/status` | generation, hashes, pending restart keys, last reload, last-good |
| `POST /config/reload` | reload now, `?expect_sha=` optional. `200`, `409`, `412`, `422`, `503` or `504` |
| `POST /config/verify` | send TOML, get the check report against the live config |
| `GET /certs/summary` | `{total, issued, cooling}` |
| `GET /certs/list` | on-demand certs, `limit`, `offset`, `q` |
| `POST /certs/warmup` | `{"domain":"..."}` orders a cert for a listed name |

```bash
curl --unix-socket /run/pingora-edge/control.sock http://localhost/config/status
```

POST bodies max 64 KiB.

## Metrics and health

On `metrics_listen` (default `127.0.0.1:9090`):

| Path | |
|---|---|
| `/metrics` | Prometheus: requests, refusals per gate, latency, pre-filter and h2 counters, reloads |
| `/health` | `200` ok, or `503` degraded |
| `/api/ssl` | on-demand cert state, paginated |
| `/api/blocklist` | source, last pull, counts |
| `/api/bandwidth` | bytes per route per day and month |
| `/api/tls-fingerprints` | top ClientHello fingerprints |

`/health` is about the edge itself (live TLS connections, watchdog, accept errors, config
state). It only says `503` after the watchdog tried to recover and couldn't, which is when a
restart makes sense.

Counters worth watching: `edge_conn_rate_drops_total`, `edge_strikes_total`,
`edge_tls_fp_shadow_total`, `edge_tls_fp_blocked_total`, `edge_h2_cancels_total`,
`edge_h2_blocked_ips_total`, `edge_breaker_short_circuits_total`, `edge_tls_live_direct`,
`edge_tls_live_cloudflare`.

## Logs

stdout, so journald picks them up. `RUST_LOG=debug` for more, default `info`. Noisy Pingora
lines (like clients closing early) are off and counted in metrics instead.

## Memory sizing

At start it reads the machine's memory (cgroup and systemd limits too) and sizes caches and
connection caps to fit. That's where the defaults of `max_live_tls` and `keepalive_idle_secs`
come from. Set them yourself to override.
