<h1 align="center">pingora-edge</h1>
<p align="center">tls edge proxy built on <a href="https://github.com/cloudflare/pingora">pingora</a> and boringssl</p>

<p align="center">
	<a href="https://itzngga.github.io/pingora-edge/"><img alt="docs" src="https://img.shields.io/badge/docs-itzngga.github.io-6366f1?style=flat-square"></a>
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

## Install

Linux binaries (x86_64 and arm64, glibc 2.34+) are on the
[releases](https://github.com/itzngga/pingora-edge/releases) page.

```bash
VER=v0.6.0 ARCH=x86_64  # or aarch64
NAME=pingora-edge-$VER-$ARCH-unknown-linux-gnu
curl -LO https://github.com/itzngga/pingora-edge/releases/download/$VER/$NAME.tar.gz
curl -LO https://github.com/itzngga/pingora-edge/releases/download/$VER/$NAME.tar.gz.sha256
sha256sum -c $NAME.tar.gz.sha256
tar -xzf $NAME.tar.gz
sudo install $NAME/pingora-edge /usr/local/bin/
```

Or build it yourself. BoringSSL builds from source, so you need `cmake`, `clang`, Go and a C/C++
compiler.

```bash
cargo build --release
```

## Run

```bash
cp proxy.example.toml proxy.toml
```

Set `acme.email`, `acme.storage` and your routes, then:

```bash
pingora-edge --check proxy.toml
```

```bash
sudo pingora-edge proxy.toml
```

Built it yourself? The binary is `./target/release/pingora-edge`.

To try it on your laptop first (no domain needed), see
[try it locally](docs/getting-started.md#try-it-locally).

## Docs

https://itzngga.github.io/pingora-edge/ (same files as [`docs/`](docs/))

## Limitations

- ports are fixed: `:80`, `:443`, `127.0.0.1:4443`, `127.0.0.1:8080`
- HTTP-01 only, so no wildcard certs
- one upstream per route, no load balancing
- made for Linux, macOS is fine for development
- it adds security headers to every response, including HSTS preload, so check them before using a real domain
- not audited and no end-to-end tests

## License

MIT
