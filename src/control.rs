//! control.rs: a small control/status API served over a UNIX SOCKET (not TCP),
//! so nothing is exposed on the network and access follows file permissions
//! plus peer credentials.
//!
//! Routes (HTTP/1 over the unix socket; every POST needs uid 0 or the
//! process's own euid):
//!   GET  /health
//!   GET  /certs/summary                → {total, issued, cooling}
//!   GET  /certs/list?limit&offset&q    → {total, rows:[{domain,has_cert,days_left,cooling}]}
//!   POST /certs/warmup  {"domain":"x"} → start ACME issuance for one allowlisted SNI
//!
//! Config (reload.rs):
//!   GET  /config/status                → <name>/config-status/1
//!   POST /config/reload[?expect_sha=]  → <name>/reload/1 (200/409/412/422/503/504)
//!   POST /config/verify  <TOML body>   → <name>/check/1 against the live generation

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;
use tracing::{info, warn};

use crate::on_demand::OnDemandResolver;
use crate::reload::Reloader;

fn json(status: u16, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Existing POST bodies are tiny JSON; anything larger is refused, not buffered.
const POST_BODY_MAX: usize = 64 * 1024;

/// Ok(bytes), or Err(413) when the body is over `max`. Other read errors read as empty.
async fn capped_body(req: Request<Incoming>, max: usize) -> Result<Bytes, Response<Full<Bytes>>> {
    match Limited::new(req.into_body(), max).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            Err(json(413, r#"{"error":"body too large"}"#.to_string()))
        }
        Err(_) => Ok(Bytes::new()),
    }
}

fn query_param(uri: &hyper::Uri, key: &str) -> Option<String> {
    uri.query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let mut it = kv.splitn(2, '=');
            if it.next() == Some(key) {
                it.next().map(|v| v.to_string())
            } else {
                None
            }
        })
    })
}

async fn small_body(req: Request<Incoming>) -> Result<Bytes, Response<Full<Bytes>>> {
    capped_body(req, POST_BODY_MAX).await
}

fn forbidden() -> Response<Full<Bytes>> {
    json(
        403,
        r#"{"error":"forbidden: POST needs uid 0 or the proxy's own uid"}"#.to_string(),
    )
}

/// `trusted`: the peer is root or runs as this process's euid (peer credentials).
async fn handle(
    req: Request<Incoming>,
    ns: Arc<OnDemandResolver>,
    rl: Reloader,
    trusted: bool,
) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let uri = req.uri().clone();

    match (method, path.as_str()) {
        (Method::GET, "/health") => json(200, r#"{"status":"ok"}"#.to_string()),

        (Method::GET, "/config/status") => json(200, rl.status().await.to_string()),

        (Method::POST, "/config/reload") => {
            if !trusted {
                return forbidden();
            }
            let expect = match query_param(&uri, "expect_sha") {
                None => None,
                Some(h) => match crate::reload::parse_sha(&h) {
                    Some(s) => Some(s),
                    None => {
                        return json(
                            400,
                            r#"{"error":"expect_sha must be 64 lowercase hex characters"}"#
                                .to_string(),
                        )
                    }
                },
            };
            let (code, v) = rl.reload(expect).await;
            json(code, v.to_string())
        }

        (Method::POST, "/config/verify") => {
            if !trusted {
                return forbidden();
            }
            let body = match capped_body(req, crate::reload::VERIFY_MAX).await {
                Ok(b) => b,
                Err(r) => return r,
            };
            let (code, v) = rl.verify(body.to_vec()).await;
            json(code, v.to_string())
        }

        (Method::GET, "/certs/summary") => {
            let domains = ns.on_demand_domains();
            let total = domains.len();
            let issued = ns.issued_count();
            let cooling = domains.iter().filter(|d| ns.cert_status(d).2).count();
            json(
                200,
                format!(
                    r#"{{"total":{},"issued":{},"cooling":{}}}"#,
                    total, issued, cooling
                ),
            )
        }

        (Method::GET, "/certs/list") => {
            let mut domains = ns.on_demand_domains();
            domains.sort();
            let q = query_param(&uri, "q").unwrap_or_default().to_lowercase();
            if !q.is_empty() {
                domains.retain(|d| d.contains(&q));
            }
            let total = domains.len();
            let offset: usize = query_param(&uri, "offset")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let limit: usize = query_param(&uri, "limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100)
                .min(1000);

            let mut rows = String::from("[");
            for (i, d) in domains.iter().skip(offset).take(limit).enumerate() {
                let (has_cert, days, cooling) = ns.cert_status(d);
                if i > 0 {
                    rows.push(',');
                }
                rows.push_str(&format!(
                    r#"{{"domain":{},"has_cert":{},"days_left":{},"cooling":{}}}"#,
                    serde_json::to_string(d).unwrap_or_else(|_| "\"\"".into()),
                    has_cert,
                    days.unwrap_or(0),
                    cooling
                ));
            }
            rows.push(']');
            json(200, format!(r#"{{"total":{},"rows":{}}}"#, total, rows))
        }

        (Method::POST, "/certs/warmup") => {
            if !trusted {
                return forbidden();
            }
            let body = match small_body(req).await {
                Ok(b) => b,
                Err(r) => return r,
            };
            let domain = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| {
                    v.get("domain")
                        .and_then(|d| d.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();
            if domain.is_empty() {
                return json(400, r#"{"error":"domain required"}"#.to_string());
            }
            let ns2 = ns.clone();
            tokio::spawn(async move {
                let _ = ns2.warmup_domain(&domain).await;
            });
            json(202, r#"{"status":"queued"}"#.to_string())
        }

        _ => json(404, r#"{"error":"not found"}"#.to_string()),
    }
}

/// Serve the control API on a unix socket. Path from `CONTROL_SOCK` (caller-resolved).
pub async fn serve(sock_path: String, ns: Arc<OnDemandResolver>, rl: Reloader) {
    // A socket that still accepts belongs to a live instance (a diagnostics run must not
    // take it over); only a dead one is cleared.
    if std::os::unix::net::UnixStream::connect(&sock_path).is_ok() {
        warn!(
            "control: '{}' is served by another live instance — leaving it alone",
            sock_path
        );
        return;
    }
    let _ = std::fs::remove_file(&sock_path);
    if let Some(dir) = std::path::Path::new(&sock_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let listener = match UnixListener::bind(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            warn!("control: cannot bind unix socket '{}': {}", sock_path, e);
            return;
        }
    };
    // World-rw so a status reader under another uid can connect; every POST
    // still needs the peer credentials checked below. Tighten the directory
    // permissions if reads should be private too.
    let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o666));
    info!("Control API on unix://{}", sock_path);
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };

    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::error!("control accept failed ({}) — backing off 100ms", e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        // The socket is world-rw for reads; changing anything is not.
        let trusted = stream
            .peer_cred()
            .is_ok_and(|c| c.uid() == 0 || c.uid() == euid);
        let ns = ns.clone();
        let rl = rl.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        let (ns, rl) = (ns.clone(), rl.clone());
                        async move { Ok::<_, hyper::Error>(handle(req, ns, rl, trusted).await) }
                    }),
                )
                .await;
        });
    }
}
