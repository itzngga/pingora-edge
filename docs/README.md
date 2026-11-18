# pingora-edge

TLS edge proxy built on [Pingora](https://github.com/cloudflare/pingora) and BoringSSL. It
terminates HTTPS for many hostnames, gets their certificates, drops bad clients before the TLS
handshake, then proxies, serves static files or redirects.

Running in production, rough edges and all.

- [Getting started](getting-started.md): download or build, run, try it locally
- [Configuration](configuration.md): every key and its default
- [Certificates](certificates.md): ACME, static and on-demand
- [Abuse defence](abuse-defence.md): what gets dropped, and where
- [Operations](operations.md): check, reload, control socket, metrics
- [Architecture](architecture.md): how it fits together

Source and issues: [github.com/itzngga/pingora-edge](https://github.com/itzngga/pingora-edge) (MIT)
