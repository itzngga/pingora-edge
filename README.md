<h1 align="center">pingora-edge</h1>
<p align="center">tls edge proxy built on <a href="https://github.com/cloudflare/pingora">pingora</a> and boringssl</p>

<p align="center">
	<img alt="License" src="https://img.shields.io/github/license/itzngga/pingora-edge?style=flat-square">
	<img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/itzngga/pingora-edge?style=flat-square">
</p>

It sits in front of your apps on `:443`. It terminates TLS for many hostnames, gets their
certificates, drops abusive clients before the handshake, then proxies, serves files or redirects.

Running in production. Not perfect, but it holds up. Issues and PRs are welcome.

## Features

- ACME HTTP-01 (Let's Encrypt or ZeroSSL), static certs per route, on-demand certs from a host list
- pre-TLS filter on `:443`: junk and slow clients, connection rate, strikes, ClientHello fingerprint limit
- HTTP/2 rapid reset guard, rate limits, penalty box, blocklist, circuit breaker
- proxy, static and redirect routes
- `--check` config verifier, hot reload (whole file or nothing), control socket, Prometheus metrics

## Build

BoringSSL builds from source, so you need `cmake`, `clang`, Go and a C/C++ compiler.

```bash
cargo build --release
```

## Run

```bash
cp proxy.example.toml proxy.toml
```

Set `acme.email`, `acme.storage` and your routes, then:

```bash
./target/release/pingora-edge --check proxy.toml
```

```bash
sudo ./target/release/pingora-edge proxy.toml
```

To try it on your laptop first (no domain needed), see
[try it locally](docs/getting-started.md#try-it-locally).

## Limitations

- ports are fixed: `:80`, `:443`, `127.0.0.1:4443`, `127.0.0.1:8080`
- HTTP-01 only, so no wildcard certs
- one upstream per route, no load balancing
- made for Linux, macOS is fine for development
- it adds security headers to every response, including HSTS preload, so check them before using a real domain
- not audited and no end-to-end tests

## License

MIT
