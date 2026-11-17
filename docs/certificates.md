# Certificates

| Route | Gets |
|---|---|
| no `static_cert` | the shared ACME bundle (one cert, all these hosts) |
| `static_cert` + `static_key` | that cert, picked by SNI |
| `ignore_ssl = true` | the self-signed fallback, no ACME |
| host in the on-demand list | its own cert on the first handshake |

Any other SNI gets the fallback and never triggers an order, so scanners can't make the edge
order certs for names they made up.

## ACME

HTTP-01 only. Port 80 must be reachable and the hostnames must point at the server.
Everything else on `:80` gets a `301` to HTTPS.

```toml
[acme]
email    = "admin@example.com"
provider = "letsencrypt"
storage  = "/var/lib/pingora-edge/acme"
```

- `zerossl` needs `eab_kid` and `eab_hmac`, and falls back to Let's Encrypt if it fails
- add a route with a new host and the bundle gets reissued in the background
- no DNS-01, so no wildcard certs

## Static certs

```toml
[[route]]
name        = "shop"
hosts       = ["shop.example.com"]
upstream    = "http://127.0.0.1:8082"
static_cert = "/etc/pingora-edge/certs/shop.example.com.crt"
static_key  = "/etc/pingora-edge/certs/shop.example.com.key"
```

They reload when the files change. `--check` catches a pair that won't load (`E302`) or a key
that doesn't match (`E303`).

## Behind a CDN

If the CDN terminates the real cert, set `ignore_ssl = true` on the route. Add
`cloudflare_only = true` if only the CDN should reach it.

## On-demand TLS

For when customers point their own domains at you.

1. Put one hostname per line in a file, and set `on_demand_hosts` to it.
2. Add one route with `on_demand_fallback = true`. It serves every host on the list, with the
   original `Host` header.

```toml
on_demand_hosts = "/etc/pingora-edge/on-demand-hosts.txt"

[[route]]
name               = "tenants"
hosts              = []
upstream           = "http://127.0.0.1:8090"
on_demand_fallback = true
```

- the first handshake waits up to 800 ms. If the cert isn't ready, it gets the fallback and the
  next visit gets the real one
- one order per name, even under a burst
- a failed name waits an hour before the next try
- certs renew 30 days before expiry
- the list is checked every 5 s and on SIGHUP, so no restart needed

To look at it: `GET /api/ssl` on `metrics_listen`, or `GET /certs/summary`, `GET /certs/list`
and `POST /certs/warmup` on the [control socket](operations.md#control-socket). Warmup orders a
cert for a listed name before anyone visits.
