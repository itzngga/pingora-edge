use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

pub static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static RATE_LIMITED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static INFLIGHT_REJECTED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static INVALID_HOST_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static UPSTREAM_UNAVAIL_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static BODY_TOO_LARGE_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static CF_BLOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static WAF_BLOCKED_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static BYTES_IN_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static BYTES_OUT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static ACTIVE_CONNECTIONS: AtomicI64 = AtomicI64::new(0);
pub static PENALTY_BOX_HITS: AtomicU64 = AtomicU64::new(0);
pub static GUILLOTINE_CUTS: AtomicU64 = AtomicU64::new(0);
pub static LOAD_SHED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// /health requests the edge answers itself: plumbing, not visitors.
pub static EDGE_PROBES_TOTAL: AtomicU64 = AtomicU64::new(0);

// ── RAII Guard to track active connections safely (Solves Counter Leaks) ─────
pub struct ActiveGuard;

impl ActiveGuard {
    pub fn new() -> Self {
        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}
// ─────────────────────────────────────────────────────────────────────────────

pub static LAT_BUCKET: [AtomicU64; 11] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
const LAT_BOUNDS_MS: [f64; 10] = [
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
];

#[inline]
pub fn observe_latency_ms(ms: f64) {
    let idx = LAT_BOUNDS_MS.iter().position(|&b| ms < b).unwrap_or(10);
    LAT_BUCKET[idx].fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn inc_requests() {
    REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_rate_limited() {
    RATE_LIMITED_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_inflight_rejected() {
    INFLIGHT_REJECTED_TOTAL.fetch_add(1, Ordering::Relaxed);
}
/// Connections refused by the :443 pre-filter's OWN live-connection ceiling.
/// Separate from upstream failures: a rising number here means raise
/// `max_live_tls`, not that Pingora is unwell.
pub static EDGE_AT_CAPACITY_TOTAL: AtomicU64 = AtomicU64::new(0);
#[inline]
pub fn inc_edge_at_capacity() {
    EDGE_AT_CAPACITY_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_invalid_host() {
    INVALID_HOST_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_upstream_unavailable() {
    UPSTREAM_UNAVAIL_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_body_too_large() {
    BODY_TOO_LARGE_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_cf_blocked() {
    CF_BLOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_waf_blocked() {
    WAF_BLOCKED_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn add_bytes_in(n: u64) {
    BYTES_IN_TOTAL.fetch_add(n, Ordering::Relaxed);
}
#[inline]
pub fn add_bytes_out(n: u64) {
    BYTES_OUT_TOTAL.fetch_add(n, Ordering::Relaxed);
}
#[inline]
pub fn inc_edge_probe() {
    EDGE_PROBES_TOTAL.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_penalty_box_hit() {
    PENALTY_BOX_HITS.fetch_add(1, Ordering::Relaxed);
}
// The [blocklist] (blocklist.rs): requests refused because the visitor was
// listed, and origin_block_header marks received from upstreams.
pub static BLOCKLIST_HITS: AtomicU64 = AtomicU64::new(0);
pub static ORIGIN_BLOCKS: AtomicU64 = AtomicU64::new(0);
#[inline]
pub fn inc_blocklist_hit() {
    BLOCKLIST_HITS.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_origin_block() {
    ORIGIN_BLOCKS.fetch_add(1, Ordering::Relaxed);
}

// Upstream real-IP headers by signature ([security].real_ip_secret): signed-valid / unsigned / bad.
pub const REAL_IP_KINDS: [&str; 3] = ["signed", "unsigned", "bad"];
pub static REAL_IP_SEEN: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
#[inline]
pub fn inc_real_ip(kind: usize) {
    REAL_IP_SEEN[kind].fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_guillotine_cut() {
    GUILLOTINE_CUTS.fetch_add(1, Ordering::Relaxed);
}
#[inline]
pub fn inc_load_shed() {
    LOAD_SHED_TOTAL.fetch_add(1, Ordering::Relaxed);
}

// 5xx answers the EDGE synthesised, by cause (proxy.rs fail_reason). An app's
// own 503 is not counted here, which is the point: the two need different fixes.
pub const EDGE_FAILURES: [&str; 4] = [
    "edge-breaker-open",
    "edge-connect-failed",
    "edge-upstream-timeout",
    "edge-upstream-error",
];
pub static EDGE_FAILURES_SEEN: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
#[inline]
pub fn inc_edge_failure(reason: &str) {
    if let Some(i) = EDGE_FAILURES.iter().position(|r| *r == reason) {
        EDGE_FAILURES_SEEN[i].fetch_add(1, Ordering::Relaxed);
    }
}

/// Snapshot of the configured routes, republished with each applied config so
/// /api/bandwidth follows the live set without threading ProxyConfig through.
static ROUTES: once_cell::sync::Lazy<arc_swap::ArcSwap<Vec<crate::config::RouteConfig>>> =
    once_cell::sync::Lazy::new(|| arc_swap::ArcSwap::from_pointee(Vec::new()));

pub fn set_routes(r: Vec<crate::config::RouteConfig>) {
    ROUTES.store(std::sync::Arc::new(r));
}

pub fn routes() -> std::sync::Arc<Vec<crate::config::RouteConfig>> {
    ROUTES.load_full()
}

/// The on-demand resolver, published so /api/ssl can report per-domain cert
/// state. Held as an Arc: the resolver is shared with the TLS accept path.
static RESOLVER: once_cell::sync::OnceCell<std::sync::Arc<crate::on_demand::OnDemandResolver>> =
    once_cell::sync::OnceCell::new();

pub fn set_resolver(r: std::sync::Arc<crate::on_demand::OnDemandResolver>) {
    let _ = RESOLVER.set(r);
}

/// GET /api/ssl?page=&limit= : cert state for the on-demand host list.
///
/// PAGINATED SERVER-SIDE ON PURPOSE. `cert_status` stats and parses a PEM per
/// domain, and the list can run to hundreds of names, so doing them all on every
/// poll would hammer the disk. Only the requested slice is touched.
fn ssl_page(query: &str) -> String {
    let param = |k: &str| -> Option<usize> {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .and_then(|v| v.parse().ok())
    };
    let limit = param("limit").unwrap_or(25).clamp(1, 100);
    let page = param("page").unwrap_or(1).max(1);

    let Some(ns) = RESOLVER.get() else {
        return r#"{"total":0,"page":1,"pages":1,"items":[],"issued":0}"#.to_string();
    };
    let mut domains = ns.on_demand_domains();
    domains.sort();

    let total = domains.len();
    let pages = total.div_ceil(limit).max(1);
    let page = page.min(pages);
    let start = (page - 1) * limit;
    let slice = domains
        .get(start..(start + limit).min(total))
        .unwrap_or(&[]);

    let items: Vec<serde_json::Value> = slice
        .iter()
        .map(|d| {
            let (has, days, cooling) = ns.cert_status(d);
            // Buckets the operator can act on, rather than a raw day count:
            // expired = serving a dead cert right now; expiring = renew window.
            let state = if !has {
                if cooling {
                    "failed"
                } else {
                    "missing"
                }
            } else if days.unwrap_or(0) <= 0 {
                "expired"
            } else if days.unwrap_or(0) <= 14 {
                "expiring"
            } else {
                "ok"
            };
            serde_json::json!({
                "domain": d, "has_cert": has, "days": days, "cooling": cooling, "state": state,
            })
        })
        .collect();

    serde_json::json!({
        "total": total, "page": page, "pages": pages, "limit": limit,
        "issued": ns.issued_count(), "items": items,
    })
    .to_string()
}

pub async fn serve(addr: String) {
    use http_body_util::Full;
    use hyper::{body::Bytes, server::conn::http1, service::service_fn, Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    // A panic here would abort the whole edge (panic = abort); serve without metrics instead.
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                "Cannot bind metrics on {}: {} — /metrics and /health are not served",
                addr,
                e
            );
            return;
        }
    };

    tracing::info!("Metrics: http://{}/metrics | http://{}/health", addr, addr);

    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::error!("metrics accept failed ({}) — backing off 100ms", e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(|req: Request<hyper::body::Incoming>| async move {
                    match req.uri().path() {
                        "/health" => {
                            let active = ACTIVE_CONNECTIONS.load(Ordering::Relaxed);
                            let total = REQUESTS_TOTAL.load(Ordering::Relaxed);

                            // A liveness check that only proves THIS service is up
                            // is worthless here: with the loopback leg out of
                            // ephemeral ports, this listener would keep answering
                            // 200 while :443 accepts nothing. So report on the EDGE.
                            //
                            // Saturated = the pre-filter is at/near its ceiling and
                            // cannot take new TLS connections. That state does not
                            // recover on its own, so a 503 lets the orchestrator
                            // restart us instead of leaving a dead edge running.
                            let live = crate::tls_router::live_splices();
                            let max  = crate::tls_router::max_live_splices();
                            // NOT raw saturation: the pre-filter's watchdog gets
                            // first refusal and usually reclaims the ports itself.
                            // This only goes false once that has demonstrably
                            // failed, so the supervisor restarts the process as a
                            // last resort instead of on every traffic spike.
                            let unhealthy = crate::tls_router::edge_unhealthy();
                            let (accept_errs, failed_reaps, tracked) =
                                crate::tls_router::watchdog_state();

                            // Config state is reported, never acted on: a health cron must not restart into a refused file.
                            let body = format!(
                                r#"{{"status":"{}","active_connections":{},"total_requests":{},"live_tls":{},"live_tls_max":{},"tracked_conns":{},"accept_err_streak":{},"failed_reaps":{},"config":{}}}"#,
                                if unhealthy { "degraded" } else { "ok" },
                                active, total, live, max, tracked, accept_errs, failed_reaps,
                                crate::reload::health_json()
                            );
                            if unhealthy {
                                tracing::error!(
                                    "/health DEGRADED — {}/{} edge connections held, \
                                     {} failed reap round(s), accept-error streak {}. \
                                     In-process recovery did not help; a restart is warranted.",
                                    live, max, failed_reaps, accept_errs
                                );
                            }
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(if unhealthy { 503 } else { 200 })
                                    .header("Content-Type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap()
                            )
                        }
                        "/api/ssl" => {
                            let q = req.uri().query().unwrap_or("").to_string();
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .header("Content-Type", "application/json")
                                    .header("Cache-Control", "no-store")
                                    .body(Full::new(Bytes::from(ssl_page(&q))))
                                    .unwrap()
                            )
                        }
                        "/api/blocklist" => {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .header("Content-Type", "application/json")
                                    .header("Cache-Control", "no-store")
                                    .body(Full::new(Bytes::from(crate::blocklist::status_json())))
                                    .unwrap()
                            )
                        }

                        "/api/tls-fingerprints" => {
                            let top: Vec<serde_json::Value> = crate::tls_router::tls_fp_top(25)
                                .into_iter()
                                .map(|(fp, over)| serde_json::json!({"fingerprint": fp, "over_threshold": over}))
                                .collect();
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .header("Content-Type", "application/json")
                                    .header("Cache-Control", "no-store")
                                    .body(Full::new(Bytes::from(serde_json::json!({"top": top}).to_string())))
                                    .unwrap()
                            )
                        }
                        "/api/bandwidth" => {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .header("Content-Type", "application/json")
                                    .header("Cache-Control", "no-store")
                                    .body(Full::new(Bytes::from(crate::bandwidth::json(&routes()))))
                                    .unwrap()
                            )
                        }
                        _ => {
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(200)
                                    .header("Content-Type", "text/plain; version=0.0.4")
                                    .body(Full::new(Bytes::from(scrape())))
                                    .unwrap()
                            )
                        }
                    }
                }))
                .await;
        });
    }
}

fn scrape() -> String {
    use std::fmt::Write;
    let mut o = String::with_capacity(2048);

    macro_rules! counter {
        ($name:expr, $help:expr, $val:expr) => {
            writeln!(o, "# HELP {} {}", $name, $help).ok();
            writeln!(o, "# TYPE {} counter", $name).ok();
            writeln!(o, "{} {}", $name, $val.load(Ordering::Relaxed)).ok();
        };
    }
    macro_rules! gauge {
        ($name:expr, $help:expr, $val:expr) => {
            writeln!(o, "# HELP {} {}", $name, $help).ok();
            writeln!(o, "# TYPE {} gauge", $name).ok();
            writeln!(o, "{} {}", $name, $val.load(Ordering::Relaxed)).ok();
        };
    }

    macro_rules! value {
        ($kind:expr, $name:expr, $help:expr, $val:expr) => {
            writeln!(o, "# HELP {} {}", $name, $help).ok();
            writeln!(o, "# TYPE {} {}", $name, $kind).ok();
            writeln!(o, "{} {}", $name, $val).ok();
        };
    }

    counter!(
        "proxy_requests_total",
        "Requests proxied successfully",
        REQUESTS_TOTAL
    );
    counter!(
        "proxy_blocklist_hits_total",
        "Requests refused by the [blocklist] (429)",
        BLOCKLIST_HITS
    );
    counter!(
        "proxy_origin_blocks_total",
        "origin_block_header marks received from upstreams",
        ORIGIN_BLOCKS
    );
    writeln!(
        o,
        "# HELP proxy_real_ip_total Upstream real-IP headers by signature"
    )
    .ok();
    writeln!(o, "# TYPE proxy_real_ip_total counter").ok();
    for (i, k) in REAL_IP_KINDS.iter().enumerate() {
        writeln!(
            o,
            r#"proxy_real_ip_total{{sig="{}"}} {}"#,
            k,
            REAL_IP_SEEN[i].load(Ordering::Relaxed)
        )
        .ok();
    }
    writeln!(
        o,
        "# HELP proxy_edge_failures_total 5xx answers synthesised by the edge, by cause"
    )
    .ok();
    writeln!(o, "# TYPE proxy_edge_failures_total counter").ok();
    for (i, k) in EDGE_FAILURES.iter().enumerate() {
        writeln!(
            o,
            r#"proxy_edge_failures_total{{reason="{}"}} {}"#,
            k,
            EDGE_FAILURES_SEEN[i].load(Ordering::Relaxed)
        )
        .ok();
    }
    counter!(
        "proxy_rate_limited_total",
        "Requests rejected by rate limiter (429)",
        RATE_LIMITED_TOTAL
    );
    counter!(
        "proxy_inflight_rejected_total",
        "Requests rejected by in-flight cap (503)",
        INFLIGHT_REJECTED_TOTAL
    );
    counter!(
        "proxy_invalid_host_total",
        "Requests with unknown Host (403)",
        INVALID_HOST_TOTAL
    );
    counter!(
        "proxy_upstream_unavailable_total",
        "Upstream failures served as 503",
        UPSTREAM_UNAVAIL_TOTAL
    );
    counter!(
        "proxy_body_too_large_total",
        "Requests exceeding body limit (413)",
        BODY_TOO_LARGE_TOTAL
    );
    counter!(
        "proxy_cf_blocked_total",
        "Requests blocked: non-CF origin (403)",
        CF_BLOCKED_TOTAL
    );
    counter!(
        "proxy_waf_blocked_total",
        "Requests blocked by WAF rules (400)",
        WAF_BLOCKED_TOTAL
    );
    counter!(
        "proxy_penalty_box_hits_total",
        "Requests rejected: IP in Penalty Box",
        PENALTY_BOX_HITS
    );
    counter!(
        "proxy_guillotine_cuts_total",
        "Connections closed: Keep-Alive Guillotine (req limit)",
        GUILLOTINE_CUTS
    );
    counter!(
        "proxy_load_shed_total",
        "Connections dropped: Global Load Shedder ceiling",
        LOAD_SHED_TOTAL
    );
    counter!(
        "proxy_bytes_in_total",
        "Total bytes received from clients",
        BYTES_IN_TOTAL
    );
    counter!(
        "proxy_bytes_out_total",
        "Bytes sent to clients (body + headers, before TLS)",
        BYTES_OUT_TOTAL
    );
    counter!(
        "proxy_edge_probes_total",
        "/health requests answered by the edge",
        EDGE_PROBES_TOTAL
    );
    counter!(
        "proxy_edge_at_capacity_total",
        "TLS connections refused at the pre-filter ceiling",
        EDGE_AT_CAPACITY_TOTAL
    );
    gauge!(
        "proxy_active_connections",
        "Currently open proxy connections",
        ACTIVE_CONNECTIONS
    );

    // :443 pre-filter (tls_router.rs)
    let (live_cf, live_direct, cf_cap) = crate::tls_router::live_split();
    value!(
        "gauge",
        "edge_tls_live_cloudflare",
        "TLS connections held for Cloudflare peers",
        live_cf
    );
    value!(
        "gauge",
        "edge_tls_live_direct",
        "TLS connections held for direct peers",
        live_direct
    );
    value!(
        "gauge",
        "edge_tls_cloudflare_cap",
        "Ceiling for Cloudflare-sourced connections",
        cf_cap
    );
    value!(
        "gauge",
        "edge_tls_direct_cap",
        "Ceiling for direct connections in force (0 = none)",
        crate::tls_router::direct_cap()
    );
    value!(
        "gauge",
        "edge_tls_live_max",
        "Overall pre-filter connection ceiling",
        crate::tls_router::max_live_splices()
    );
    value!(
        "counter",
        "edge_conn_rate_drops_total",
        "Connections refused by the per-IP connection-rate gate",
        crate::tls_router::conn_rate_drops()
    );
    value!(
        "counter",
        "edge_strikes_total",
        "Abuse strikes filed against source addresses",
        crate::tls_router::edge_strikes()
    );
    value!(
        "counter",
        "edge_backend_down_drops_total",
        "Direct connections refused while the fallback backend was down",
        crate::tls_router::backend_down_drops()
    );
    let (fp_shadow, fp_blocked) = crate::tls_router::tls_fp_stats();
    value!(
        "counter",
        "edge_tls_fp_shadow_total",
        "Connections the fingerprint gate would refuse (shadow mode)",
        fp_shadow
    );
    value!(
        "counter",
        "edge_tls_fp_blocked_total",
        "Connections refused by the fingerprint gate",
        fp_blocked
    );

    // HTTP/2 rapid-reset guard (h2_guard.rs) and circuit breaker (breaker.rs)
    let (cancels, h2_blocked, conn_flags, rejects) = crate::h2_guard::stats();
    value!(
        "counter",
        "edge_h2_cancels_total",
        "Client-cancelled requests seen",
        cancels
    );
    value!(
        "counter",
        "edge_h2_blocked_ips_total",
        "Source IPs blocked for cancel floods",
        h2_blocked
    );
    value!(
        "counter",
        "edge_h2_conn_flags_total",
        "Connections that hit the per-connection stream ceiling",
        conn_flags
    );
    value!(
        "counter",
        "edge_h2_stream_rejects_total",
        "Streams rejected cheaply on flagged connections",
        rejects
    );
    value!(
        "counter",
        "edge_breaker_short_circuits_total",
        "Requests answered by an open circuit breaker without dialling the upstream",
        crate::breaker::tripped()
    );

    writeln!(
        o,
        "# HELP proxy_request_duration_ms Request latency buckets (ms)"
    )
    .ok();
    writeln!(o, "# TYPE proxy_request_duration_ms histogram").ok();
    let mut cum: u64 = 0;
    for (i, &b) in LAT_BOUNDS_MS.iter().enumerate() {
        cum += LAT_BUCKET[i].load(Ordering::Relaxed);
        writeln!(
            o,
            r#"proxy_request_duration_ms_bucket{{le="{}"}} {}"#,
            b, cum
        )
        .ok();
    }
    cum += LAT_BUCKET[10].load(Ordering::Relaxed);
    writeln!(
        o,
        r#"proxy_request_duration_ms_bucket{{le="+Inf"}} {}"#,
        cum
    )
    .ok();
    writeln!(o, "proxy_request_duration_ms_count {}", cum).ok();

    crate::reload::scrape(&mut o);
    o
}
#[cfg(test)]
mod ssl_page_tests {
    // The query parser is hand-rolled (no query-string dep), so pin its behaviour:
    // a bad or hostile page/limit must clamp, never panic or slice out of bounds.
    #[test]
    fn ssl_pagination_params_clamp() {
        let param = |query: &str, k: &str| -> Option<usize> {
            query
                .split('&')
                .find_map(|kv| kv.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
                .and_then(|v| v.parse().ok())
        };
        assert_eq!(param("page=3&limit=50", "page"), Some(3));
        assert_eq!(param("page=3&limit=50", "limit"), Some(50));
        assert_eq!(param("", "page"), None);
        assert_eq!(param("page=abc", "page"), None, "garbage must not parse");
        assert_eq!(
            param("page=-1", "page"),
            None,
            "negative must not parse into usize"
        );
        // clamp mirrors ssl_page
        assert_eq!(
            param("limit=9999", "limit").unwrap_or(25).clamp(1, 100),
            100
        );
        assert_eq!(param("limit=0", "limit").unwrap_or(25).clamp(1, 100), 1);
        // "limit" must not be matched by the "page" lookup and vice versa
        assert_eq!(param("limit=7", "page"), None);
    }

    #[test]
    fn ssl_page_slice_never_goes_out_of_bounds() {
        // Mirrors the slice arithmetic in ssl_page for awkward totals.
        for total in [0usize, 1, 24, 25, 26, 199] {
            for req_page in [1usize, 2, 99] {
                let limit = 25usize;
                let pages = total.div_ceil(limit).max(1);
                let page = req_page.min(pages);
                let start = (page - 1) * limit;
                let end = (start + limit).min(total);
                let v: Vec<usize> = (0..total).collect();
                let slice = v.get(start..end).unwrap_or(&[]);
                assert!(slice.len() <= limit, "total={} page={}", total, req_page);
                if total > 0 && req_page == 1 {
                    assert!(!slice.is_empty(), "page 1 empty for total={}", total);
                }
            }
        }
    }
}
