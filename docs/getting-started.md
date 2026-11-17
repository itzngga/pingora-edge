# Getting started

## Build

BoringSSL builds from source, so you need `cmake`, `clang`, Go and a C/C++ compiler.

```bash
cargo build --release
```

The binary ends up in `target/release/pingora-edge`. For a static Linux build with
`cargo zigbuild`, see the notes in
[`.cargo/config.toml`](https://github.com/itzngga/pingora-edge/blob/main/.cargo/config.toml).

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

It binds `:80` and `:443` on all addresses, plus `127.0.0.1:4443`, `127.0.0.1:8080` and
`metrics_listen` (default `127.0.0.1:9090`). On Linux you need root or `CAP_NET_BIND_SERVICE`.

For ACME, your hostnames must already point at the server and port 80 must be open.

## systemd

There's an example unit in
[`deploy/pingora-edge.service`](https://github.com/itzngga/pingora-edge/blob/main/deploy/pingora-edge.service).
It runs as its own user with `CAP_NET_BIND_SERVICE`, and `systemctl reload` sends SIGHUP.

```bash
sudo systemctl enable --now pingora-edge
```

```bash
sudo systemctl reload pingora-edge
```

## Try it locally

A self-signed cert, a small upstream, no ACME. macOS lets a normal user bind `:80` and `:443`;
on Linux run the edge with `sudo`.

1. Make a cert and a static root (git ignores these paths):

   ```bash
   mkdir -p examples/certs examples/site examples/state
   ```

   ```bash
   openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
     -keyout examples/certs/edge.key -out examples/certs/edge.crt \
     -subj "/CN=app.example.test" \
     -addext "subjectAltName=DNS:app.example.test,DNS:static.example.test,DNS:old.example.test"
   ```

   ```bash
   echo '<h1>static root</h1>' > examples/site/index.html
   ```

2. Start an upstream in another terminal:

   ```bash
   mkdir -p /tmp/upstream && echo '<h1>hello from the upstream</h1>' > /tmp/upstream/index.html
   ```

   ```bash
   python3 -m http.server 8081 --bind 127.0.0.1 --directory /tmp/upstream
   ```

3. Check and start the edge with
   [`examples/local.toml`](https://github.com/itzngga/pingora-edge/blob/main/examples/local.toml).
   The check warns about relative paths, that's fine here.

   ```bash
   ./target/release/pingora-edge --check examples/local.toml
   ```

   ```bash
   CONTROL_SOCK=examples/state/control.sock ./target/release/pingora-edge examples/local.toml
   ```

   It's ready when it logs `Pingora on 127.0.0.1:4443` (it fetches the Cloudflare and crawler IP
   lists first, so give it a few seconds).

4. Send some requests:

   ```bash
   curl -sk --resolve app.example.test:443:127.0.0.1 https://app.example.test/ -D -
   ```

   ```bash
   curl -sk --resolve static.example.test:443:127.0.0.1 https://static.example.test/
   ```

   ```bash
   curl -sk --resolve old.example.test:443:127.0.0.1 "https://old.example.test/a?b=1" -o /dev/null -w '%{http_code} %{redirect_url}\n'
   ```

   ```bash
   curl -s http://127.0.0.1:9090/health
   ```

5. Stop the upstream and ask for the app like a browser to see the 503 page:

   ```bash
   curl -sk --resolve app.example.test:443:127.0.0.1 -H 'Accept: text/html' https://app.example.test/ -D -
   ```

   After 10 failures in a row the breaker opens and the edge stops dialling the upstream.
   `curl -s http://127.0.0.1:9090/metrics | grep edge_` shows the counters.

6. Change `X-Edge-Route` in `examples/local.toml` and reload without a restart:

   ```bash
   CONTROL_SOCK=examples/state/control.sock ./target/release/pingora-edge --reload
   ```

Loopback is trusted, so the abuse gates don't apply to these tests.
