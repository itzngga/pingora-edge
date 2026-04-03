use crate::static_handler;

use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::header::HeaderName;
use pingora_core::protocols::l4::socket::SocketAddr as PingoraAddr;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

use crate::{
    config::{ProxyConfig, RouteConfig, TrustedNets, SECURITY_HEADERS, STRIP_HEADERS},
    host_list::HostList,
    limiter::{
        FingerprintLimiter, GlobalGuard, GlobalLoadShedder, GlobalRpsLimiter, Guillotine,
        InflightCounter, InflightGuard, PenaltyBox, RateLimiterStore,
    },
    metrics,
    shield::{check_headers, is_cloudflare_ip},
};

use moka::sync::Cache as MokaCache;

// ── Fast-path WAF ─────────────────────────────────────────────────────────────
const POISONED_PATHS: &[&str] = &[
    ".env",
    ".git",
    "wp-config.php",
    "wp-login.php",
    "actuator",
    "phpunit",
    "phpmyadmin",
    "eval-stdin.php",
    "docker.sock",
];

// Attack-tool User-Agent strings (case-insensitive match): penalised and struck.
// These are NEVER used by real browsers or legitimate crawlers.
const SCANNER_UAS: &[&str] = &[
    "masscan",
    "nuclei",
    "zgrab",
    "siege",
    "wrk",
    "bombardier",
    "hey/",
    "apachebench/", // not "ab/": that matched Facebook's Android in-app "[FB_IAB/..."
    "vegeta",
    "slowloris",
    "nikto",
    "sqlmap",
    "nmap",
    "dirbuster",
    "gobuster",
    "wfuzz",
    "realvisitor",
];

// Generic HTTP client libraries: refused, never boxed or struck — one script
// behind a hotspot/CGNAT address must not ban every reader sharing it.
const LIBRARY_UAS: &[&str] = &[
    "go-http-client",
    "python-requests",
    "python-urllib",
    "httpx",
    "fasthttp",
    "aiohttp",
    "scrapy",
];

// ── Chained-edge real IP: <real_ip_sig_header> = "<ts>.<hex HMAC-SHA256("<real>|<ts>")>" ──
const REAL_SIG_WINDOW_SECS: u64 = 300;
const REAL_IP_SIGNED: usize = 0;
const REAL_IP_UNSIGNED: usize = 1;
const REAL_IP_BAD: usize = 2;

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn real_ip_sig(key: &ring::hmac::Key, real_ip: &str, ts: u64) -> String {
    use std::fmt::Write;
    let tag = ring::hmac::sign(key, format!("{}|{}", real_ip, ts).as_bytes());
    let mut out = format!("{}.", ts);
    for b in tag.as_ref() {
        let _ = write!(out, "{:02x}", b);
    }
    out
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// REAL_IP_SIGNED (valid MAC inside the window), REAL_IP_UNSIGNED (no header) or REAL_IP_BAD.
fn real_ip_sig_kind(key: &ring::hmac::Key, sig: Option<&[u8]>, real_ip: &str, now: u64) -> usize {
    let Some(sig) = sig else {
        return REAL_IP_UNSIGNED;
    };
    let Some((ts_raw, mac)) = std::str::from_utf8(sig)
        .ok()
        .and_then(|s| s.trim().split_once('.'))
    else {
        return REAL_IP_BAD;
    };
    let Ok(ts) = ts_raw.parse::<u64>() else {
        return REAL_IP_BAD;
    };
    if now.abs_diff(ts) > REAL_SIG_WINDOW_SECS {
        return REAL_IP_BAD;
    }
    let Some(tag) = hex32(mac) else {
        return REAL_IP_BAD;
    };
    // ring::hmac::verify compares in constant time; the raw ts is what was signed.
    match ring::hmac::verify(key, format!("{}|{}", real_ip, ts_raw).as_bytes(), &tag) {
        Ok(()) => REAL_IP_SIGNED,
        Err(_) => REAL_IP_BAD,
    }
}

// Library-UA refusals per visitor per 10s; reaching LIBRARY_STRIKE_AT strikes the
// peer once, so only a sustained flood graduates to the pre-TLS ban.
const LIBRARY_STRIKE_AT: u32 = 100;
static LIBRARY_HITS: once_cell::sync::Lazy<MokaCache<IpAddr, Arc<AtomicU32>>> =
    once_cell::sync::Lazy::new(|| {
        MokaCache::builder()
            .max_capacity(crate::tuning::TUNING.abuse_cache_entries)
            .time_to_live(Duration::from_secs(10))
            .build()
    });

// ── Per-request context ───────────────────────────────────────────────────────

pub struct Ctx {
    /// The config generation this request was admitted under, for its whole life.
    pub live: Arc<Live>,
    pub start: Instant,
    pub host: String,
    pub route: Option<Arc<RouteConfig>>,
    /// The host came from the on-demand list, not a route's `hosts`.
    pub is_on_demand: bool,
    /// Resolved once in request_filter; reused by later phases so they
    /// don't redo the REAL_IP_MAP read + CF-range check + header parse.
    pub visitor_ip: IpAddr,
    /// visitor_ip is CF's own cf-connecting-ip from a CF peer, so CF-IPCountry
    /// describes this visitor and may be passed on.
    pub cf_geo: bool,
    /// Pre-filter source port — the only stable per-CONNECTION key available,
    /// because on h2 every stream gets its own Ctx. See h2_guard.
    pub conn_port: u16,
    pub _inflight: Option<InflightGuard>,
    pub _global_guard: Option<GlobalGuard>,
    pub _active_guard: Option<metrics::ActiveGuard>,
    pub bytes_in: u64,
    pub guillotine: Guillotine,
    /// Set when the EDGE synthesised the error rather than the backend sending
    /// one. Without it an infrastructure 503 (we could not open a socket to the
    /// app) is indistinguishable in the metrics from an application 503 (the
    /// app answered 503), and those two have completely different fixes.
    pub fail_reason: &'static str,
    /// The upstream sent a response header. Whatever its status, the backend
    /// is reachable — which is all the breaker measures.
    pub upstream_answered: bool,
    pub is_crawler: bool,
    /// The upstream answered an outage status and the visitor gets the
    /// error page instead of its body (errpage.rs).
    pub dress: bool,
}

// ── Gateway ───────────────────────────────────────────────────────────────────

/// A rotated-out real_ip_secret still verifies this long, so chained edges can roll one at a time.
const REAL_IP_PREV_GRACE: Duration = Duration::from_secs(600);

/// A header name from the config, or `fallback` when it is not a valid name.
fn header_name(raw: &str, fallback: &'static str) -> HeaderName {
    HeaderName::try_from(raw.trim()).unwrap_or_else(|_| HeaderName::from_static(fallback))
}

/// One config generation as the request path reads it. Swapped whole; a request
/// pins one in new_ctx, so it never mixes two generations.
pub struct Live {
    pub generation: u64,
    pub cfg: Arc<ProxyConfig>,
    /// Lowercased host → route; shares its Arcs with fallback_route.
    pub route_map: HashMap<String, Arc<RouteConfig>>,
    /// The route with `on_demand_fallback = true`, if any.
    pub fallback_route: Option<Arc<RouteConfig>>,
    /// [security].real_ip_header / real_ip_sig_header, parsed once.
    pub real_ip_header: HeaderName,
    pub real_ip_sig_header: HeaderName,
    /// [blocklist].origin_block_header; None = off.
    pub origin_block_header: Option<HeaderName>,
    // [security].trusted_ips — exempt from the abuse gates (exact IPs + CIDRs).
    pub trusted_ips: TrustedNets,
    // [security].real_ip_secret as an HMAC key; None = no signing.
    pub real_ip_key: Option<ring::hmac::Key>,
    /// The key before the last rotation, verified until the deadline.
    pub real_ip_prev: Option<(ring::hmac::Key, Instant)>,
    // Anti-DDoS: global limit that works against residential proxies.
    pub global_rps: Arc<GlobalRpsLimiter>,
}

impl Live {
    /// `prev` is the generation being replaced: its global RPS bucket is kept when the
    /// limit is unchanged, and its key stays verifiable for 600 s after a secret rotation.
    pub fn build(cfg: Arc<ProxyConfig>, generation: u64, prev: Option<&Live>) -> Self {
        let sec = &cfg.security;
        let trusted_ips = sec.trusted_nets();
        let real_ip_key = (!sec.real_ip_secret.is_empty())
            .then(|| ring::hmac::Key::new(ring::hmac::HMAC_SHA256, sec.real_ip_secret.as_bytes()));
        if sec.real_ip_verify && real_ip_key.is_none() {
            tracing::warn!("[security] real_ip_verify is set without real_ip_secret, so an upstream real-IP header stays unverified");
        }
        let real_ip_prev = prev.and_then(|p| {
            if p.cfg.security.real_ip_secret == sec.real_ip_secret {
                return p
                    .real_ip_prev
                    .clone()
                    .filter(|(_, until)| Instant::now() < *until);
            }
            p.real_ip_key
                .clone()
                .map(|k| (k, Instant::now() + REAL_IP_PREV_GRACE))
        });

        // The on-demand fallback, resolved by config::fallback_route_index: the
        // single place that decides which route serves on-demand hosts, shared
        // with the circuit breaker and the pre-filter's backend-down shed.
        //
        // No route claiming it is not fatal: named hosts still work, and
        // on-demand hosts get a clean 421 instead of being attached to an
        // unrelated route's upstream, limits and breaker.
        let fb_idx = crate::config::fallback_route_index(&cfg.route);
        if fb_idx.is_none() && !cfg.on_demand_hosts.trim().is_empty() {
            tracing::warn!(
                "on_demand_hosts is set but no route has on_demand_fallback = true, \
                 so on-demand hosts will not be served."
            );
        }
        let routes: Vec<Arc<RouteConfig>> = cfg.route.iter().map(|r| Arc::new(r.clone())).collect();
        let fallback_route = fb_idx.and_then(|i| routes.get(i).cloned());

        let mut route_map = HashMap::new();
        for r in &routes {
            for h in &r.hosts {
                if h != "*" {
                    route_map.insert(h.to_lowercase(), Arc::clone(r));
                }
            }
        }

        let global_rps = match prev {
            Some(p) if p.cfg.security.global_rps_limit == sec.global_rps_limit => {
                Arc::clone(&p.global_rps)
            }
            _ => Arc::new(GlobalRpsLimiter::new(sec.global_rps_limit)),
        };

        let real_ip_header = header_name(&sec.real_ip_header, "x-real-ip");
        let real_ip_sig_header = header_name(&sec.real_ip_sig_header, "x-real-ip-sig");
        let origin_block_header = Some(cfg.blocklist.origin_block_header.trim())
            .filter(|h| !h.is_empty())
            .and_then(|h| HeaderName::try_from(h).ok());

        Self {
            generation,
            route_map,
            fallback_route,
            real_ip_header,
            real_ip_sig_header,
            origin_block_header,
            trusted_ips,
            real_ip_key,
            real_ip_prev,
            global_rps,
            cfg,
        }
    }
}

/// What the reloader needs from a running Gateway: the generation switch and the
/// two capacity limits it retunes in place.
pub struct GatewayHandle {
    pub live: Arc<ArcSwap<Live>>,
    pub inflight: Arc<InflightCounter>,
    pub shedder: Arc<GlobalLoadShedder>,
}

pub struct Gateway {
    live: Arc<ArcSwap<Live>>,
    hosts: HostList,
    rl: Arc<RateLimiterStore>,
    inflight: Arc<InflightCounter>,
    penalty: Arc<PenaltyBox>,
    shedder: Arc<GlobalLoadShedder>,
    dns_cache: MokaCache<String, std::net::SocketAddr>,
    // Negative cache for upstreams whose DNS just failed (e.g. a service that isn't
    // running). Short TTL: skip re-resolving + log the failure at most once per window
    // per upstream instead of on every request, so one down backend can't flood logs.
    dns_neg: MokaCache<String, ()>,
    // Per-UA buckets at the live fingerprint quota (anti-botnet).
    fingerprint: Arc<FingerprintLimiter>,
}

use hyper::body::Bytes;
use std::collections::HashMap;

// Parse a request header value as an IP (trimming whitespace). None if absent/garbled.
fn header_ip(session: &Session, name: impl http::header::AsHeaderName) -> Option<IpAddr> {
    session
        .req_header()
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
}

impl Gateway {
    /// Generation 0 from the boot config. The penalty box is sized from it for the
    /// life of the process (restart-class); everything else follows the live generation.
    pub fn new(cfg: Arc<ProxyConfig>, hosts: HostList) -> (Self, GatewayHandle) {
        let sec = &cfg.security;
        let inflight = Arc::new(InflightCounter::new(sec.max_inflight_per_ip));
        let shedder = Arc::new(GlobalLoadShedder::new(sec.global_connection_limit));
        let penalty = Arc::new(PenaltyBox::new(
            sec.penalty_box_capacity,
            sec.penalty_box_ttl_secs,
        ));
        let live = Arc::new(ArcSwap::from_pointee(Live::build(
            Arc::clone(&cfg),
            0,
            None,
        )));
        let gw = Self {
            live: Arc::clone(&live),
            inflight: Arc::clone(&inflight),
            rl: Arc::new(RateLimiterStore::new()),
            penalty,
            shedder: Arc::clone(&shedder),
            fingerprint: Arc::new(FingerprintLimiter::new()),
            hosts,
            dns_cache: MokaCache::builder()
                .max_capacity(256)
                .time_to_live(Duration::from_secs(60))
                .build(),
            dns_neg: MokaCache::builder()
                .max_capacity(256)
                .time_to_live(Duration::from_secs(10))
                .build(),
        };
        (
            gw,
            GatewayHandle {
                live,
                inflight,
                shedder,
            },
        )
    }

    fn tcp_ip(session: &Session) -> IpAddr {
        match session.client_addr() {
            Some(PingoraAddr::Inet(s)) => {
                let ip = s.ip();

                if ip.is_loopback() {
                    let port = s.port();
                    // Graceful on a poisoned lock: fall back to the loopback IP rather
                    // than `.unwrap()` panicking on EVERY request for this port. On a
                    // single edge one panic takes every site behind it down.
                    if let Ok(slot) = crate::tls_router::REAL_IP_MAP[port as usize].read() {
                        if let Some(real_ip) = *slot {
                            return real_ip;
                        }
                    }
                }

                ip
            }
            _ => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Per-connection key: the loopback source port assigned by the :443
    /// pre-filter. Returns 0 (= "no key") for any non-loopback peer, because
    /// only loopback ports are allocated by us and therefore unique; two
    /// different remote clients can trivially share an ephemeral port number,
    /// and keying shared state on that would cross-contaminate them.
    fn conn_port(session: &Session) -> u16 {
        match session.client_addr() {
            Some(PingoraAddr::Inet(s)) if s.ip().is_loopback() => s.port(),
            _ => 0,
        }
    }

    /// The visitor, and whether it came from a CF peer's cf-connecting-ip.
    fn visitor_ip(live: &Live, session: &Session) -> (IpAddr, bool) {
        let tcp = Self::tcp_ip(session);

        // Chained edge: when this instance sits behind another trusted edge
        // (front edge, then a CDN, then this one), the front already resolved
        // the real client and stamped `real_ip_header`. Trust it instead of
        // re-deriving from cf-connecting-ip, which at THIS layer names the
        // front edge or the CDN, not the client. Gated to trusted peers (CF,
        // loopback, trusted_ips) so an internet-facing client can never spoof
        // its own address.
        if live.cfg.security.trust_upstream_real_ip
            && (is_cloudflare_ip(tcp) || tcp.is_loopback() || live.trusted_ips.contains(&tcp))
        {
            if let Some(ip) = header_ip(session, &live.real_ip_header) {
                // With a secret the signature is classified; only real_ip_verify makes it decide.
                let honour = match &live.real_ip_key {
                    None => !live.cfg.security.real_ip_verify,
                    Some(key) => {
                        let h = &session.req_header().headers;
                        let real = h
                            .get(&live.real_ip_header)
                            .and_then(|v| v.to_str().ok())
                            .map_or("", str::trim);
                        let sig = h.get(&live.real_ip_sig_header).map(|v| v.as_bytes());
                        let now = unix_secs();
                        let mut kind = real_ip_sig_kind(key, sig, real, now);
                        // A peer still signing with the rotated-out key, inside its grace.
                        if kind == REAL_IP_BAD {
                            if let Some((prev, until)) = &live.real_ip_prev {
                                if Instant::now() < *until
                                    && real_ip_sig_kind(prev, sig, real, now) == REAL_IP_SIGNED
                                {
                                    kind = REAL_IP_SIGNED;
                                }
                            }
                        }
                        metrics::inc_real_ip(kind);
                        kind == REAL_IP_SIGNED || !live.cfg.security.real_ip_verify
                    }
                };
                if honour {
                    return (ip, false);
                }
            }
        }

        let cf = is_cloudflare_ip(tcp);
        if cf || tcp.is_loopback() {
            if let Some(ip) = header_ip(session, "cf-connecting-ip") {
                return (ip, cf);
            }
        }
        (tcp, false)
    }

    fn incoming_host(session: &Session) -> String {
        let req = session.req_header();
        if let Some(h) = req.headers.get("host").and_then(|v| v.to_str().ok()) {
            return h.split(':').next().unwrap_or("_").to_lowercase();
        }
        if let Some(a) = req.uri.authority() {
            return a.host().to_lowercase();
        }
        if let Some(h) = req.uri.host() {
            return h.to_lowercase();
        }
        "_".to_string()
    }

    async fn reject(session: &mut Session, status: u16) -> pingora_core::Result<bool> {
        let mut r = ResponseHeader::build(status, None)?;
        let _ = r.insert_header("Content-Length", "0");
        let _ = r.insert_header("Connection", "close");
        session.write_response_header(Box::new(r), true).await?;
        session.set_keepalive(None); // force TCP close — no reuse
        Ok(true)
    }

    /// Refuse this request only; the connection stays open for the next one.
    async fn shed(session: &mut Session, status: u16) -> pingora_core::Result<bool> {
        let mut r = ResponseHeader::build(status, None)?;
        let _ = r.insert_header("Content-Length", "0");
        let _ = r.insert_header("Retry-After", "1");
        session.write_response_header(Box::new(r), true).await?;
        Ok(true)
    }

    /// Does this rejection reason justify escalating the source to the TCP
    /// layer, where it stops getting a TLS handshake at all?
    ///
    /// The split is "did the client do something a real browser never does",
    /// NOT "did we refuse it". That distinction is the whole safety story here:
    ///
    ///   - the per-IP rate limit and inflight cap refuse the request and never reach the box.
    ///
    ///   - capacity rejections (load shed, global RPS, breaker, edge-at-cap)
    ///     never reach here at all. They are our limits, not their behaviour.
    ///
    /// What remains is unambiguous: no User-Agent, a scanner signature, a
    /// forged/absent Host, a malformed length, a direct hit on a CF-only route,
    /// or a source already penalised that came straight back.
    fn escalates_to_edge(reason: &str) -> bool {
        !matches!(reason, "blocked-dyn" | "origin-block")
    }

    async fn penalise_and_reject(
        &self,
        session: &mut Session,
        ip: IpAddr,
        reason: &'static str,
        status: u16,
    ) -> pingora_core::Result<bool> {
        self.penalty.insert(ip, reason);
        if Self::escalates_to_edge(reason) {
            // Three of these and the source stops getting a TLS handshake.
            //
            // Struck against the TCP PEER, not `ip` (the visitor). Those differ
            // behind Cloudflare: `ip` is the end user from CF-Connecting-IP,
            // while the pre-filter only ever sees, and only ever blocks on, the
            // TCP peer. Striking the visitor there would file a block that can
            // never match the traffic that caused it, and would instead land on
            // that reader the next time they opened a site on this edge
            // DIRECTLY: a real user, punished on a different site, for
            // something that happened behind a CDN.
            //
            // Using the peer makes CF traffic a no-op: CF ranges are in
            // trusted_ips, and `strike` exempts trusted addresses.
            crate::tls_router::strike_ip(Self::tcp_ip(session));
        }
        tracing::debug!("Penalised {} (reason={})", ip, reason);
        Self::reject(session, status).await
    }

    /// Reject and escalate, for gates that do not go through the penalty box.
    ///
    /// `_ip` is accepted for call-site symmetry but deliberately unused: the
    /// strike must land on the TCP peer, which is what the pre-filter blocks
    /// on. See the note in penalise_and_reject.
    async fn reject_and_strike(
        session: &mut Session,
        _ip: IpAddr,
        status: u16,
    ) -> pingora_core::Result<bool> {
        crate::tls_router::strike_ip(Self::tcp_ip(session));
        Self::reject(session, status).await
    }

    /// Redirect the entire request to `https://<target><path?query>` (path and
    /// query kept so deep links survive). Answered at the edge, the source host
    /// never reaches an upstream. Used for `mode="redirect"` routes and the
    /// www to apex fallback.
    async fn redirect_to(
        session: &mut Session,
        target: &str,
        status: u16,
    ) -> pingora_core::Result<bool> {
        let pq = session
            .req_header()
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/")
            .to_string();
        let location = format!("https://{}{}", target, pq);
        let mut r = ResponseHeader::build(status, None)?;
        let _ = r.insert_header("Location", location);
        let _ = r.insert_header("Content-Length", "0");
        // Only permanent redirects are safe to cache; temporary ones must not stick.
        if status == 301 || status == 308 {
            let _ = r.insert_header("Cache-Control", "public, max-age=86400");
        } else {
            let _ = r.insert_header("Cache-Control", "no-store");
        }
        let _ = r.insert_header("Connection", "close");
        session.write_response_header(Box::new(r), true).await?;
        session.set_keepalive(None);
        Ok(true)
    }
}

// ── ProxyHttp ────────────────────────────────────────────────────────────────

#[async_trait]
impl ProxyHttp for Gateway {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        let live = self.live.load_full();
        Ctx {
            guillotine: Guillotine::new(live.cfg.security.keepalive_max_requests),
            live,
            start: Instant::now(),
            host: String::new(),
            route: None,
            is_on_demand: false,
            visitor_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            cf_geo: false,
            conn_port: 0,
            _inflight: None,
            _global_guard: None,
            _active_guard: None,
            bytes_in: 0,
            fail_reason: "",
            upstream_answered: false,
            is_crawler: false,
            dress: false,
        }
    }

    // ── 1. request_filter ────────────────────────────────────────────────────

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool> {
        // Every config read below comes from the generation this request pinned.
        let live = Arc::clone(&ctx.live);

        ctx.start = std::time::Instant::now();
        ctx.host = String::new();
        ctx.route = None;
        ctx.is_on_demand = false;
        ctx._inflight = None;
        ctx.bytes_in = 0;
        ctx._active_guard = Some(metrics::ActiveGuard::new());

        // Pingora keeps an h1 connection as long as the client likes; at ~120 KiB
        // per idle connection a CDN's pooled connections can fill a small box.
        // Bound the idle wait — a client's own Keep-Alive timeout or close stays.
        let idle = crate::config::effective_keepalive_idle(&live.cfg.security);
        if idle > 0 && session.get_keepalive() == Some(0) {
            session.set_keepalive(Some(idle));
        }

        // Resolved before the edge's own answers below, so none of them is
        // logged against 0.0.0.0.
        let tcp_ip = Self::tcp_ip(session);
        let (visitor_ip, cf_geo) = Self::visitor_ip(&live, session);
        ctx.visitor_ip = visitor_ip;
        ctx.cf_geo = cf_geo;

        if session.req_header().uri.path() == "/health" {
            metrics::inc_edge_probe();
            let mut r = ResponseHeader::build(200, None)?;
            let _ = r.insert_header("Content-Length", "0");
            session.write_response_header(Box::new(r), true).await?;
            return Ok(true);
        }

        if live.cfg.security.maintenance_mode {
            if crate::errpage::enabled()
                && crate::errpage::wants_page(session)
                && !crate::shield::is_verified_crawler(&Self::tcp_ip(session))
            {
                let host = Self::incoming_host(session);
                crate::errpage::respond(session, &host, crate::errpage::Kind::Maintenance, "3600")
                    .await?;
                return Ok(true);
            }
            let mut r = ResponseHeader::build(503, Some(1))?;
            let _ = r.insert_header("Retry-After", "3600");
            session.write_response_header(Box::new(r), false).await?;
            let body_text = Bytes::from("Service temporarily unavailable due to maintenance.");
            session.write_response_body(Some(body_text), true).await?;
            return Ok(true);
        }

        ctx.conn_port = Self::conn_port(session);
        let sec = &live.cfg.security;

        // Trusted infrastructure skips the abuse gates. Trust is decided on the TCP
        // source IP; ADDITIONALLY, when the peer is a VERIFIED Cloudflare IP, we honour
        // the real client IP (visitor_ip = CF-Connecting-IP). CF sets that header
        // authentically, so a tool reaching us THROUGH CF (its server IP in
        // CF-Connecting-IP, with a library User-Agent the UA filter would otherwise
        // refuse) can be allowed by that IP. CF headers are never trusted when the
        // peer is not CF: a direct client could forge them.
        let is_trusted = live.trusted_ips.contains(&tcp_ip)
            || (is_cloudflare_ip(tcp_ip) && live.trusted_ips.contains(&visitor_ip));

        // robots.txt is fetched by many legitimate tools with library User-Agents.
        let verifier_path = {
            let req = session.req_header();
            (req.method == http::Method::GET || req.method == http::Method::HEAD)
                && req.uri.path() == "/robots.txt"
        };

        // ── Operator blocklists ──────────────────────────────────────────
        // BEFORE the verified-crawler branch on purpose: a common use of the
        // list is AI and SEO crawlers, and several of those ride ranges the
        // crawler verifier waves through. Trusted IPs and loopback stay
        // exempt; everything else answers 403 the moment either its IP or its
        // User-Agent is on the list.
        if !is_trusted && !tcp_ip.is_loopback() {
            if crate::shield::ip_blocked(sec, &visitor_ip)
                || crate::shield::ip_blocked(sec, &tcp_ip)
            {
                metrics::inc_waf_blocked();
                return self
                    .penalise_and_reject(session, visitor_ip, "blocked-ip", 403)
                    .await;
            }
            // The [blocklist] networks (blocklist.rs). Checked on the VISITOR
            // address, so a CDN-fronted scraper is judged by its own IP and a
            // CF edge is never the one penalised; verified crawlers are exempt
            // inside block_kind. The penalty box's escalation turns repeat
            // hits into a pre-TLS drop.
            let kind = if verifier_path {
                None
            } else {
                crate::blocklist::block_kind(&visitor_ip).or_else(|| {
                    if tcp_ip != visitor_ip && !crate::shield::is_cloudflare_ip(tcp_ip) {
                        crate::blocklist::block_kind(&tcp_ip)
                    } else {
                        None
                    }
                })
            };
            if let Some(kind) = kind {
                metrics::inc_blocklist_hit();
                // A listed network escalates to the TLS-level block like any
                // WAF hit. A short-lived entry does not: it is one IP for one
                // TTL, and if it was wrong about a person the damage must end
                // with that TTL, not turn into a handshake ban.
                let reason = if kind == "dyn" {
                    "blocked-dyn"
                } else {
                    "blocked-ip"
                };
                return self
                    .penalise_and_reject(session, visitor_ip, reason, 429)
                    .await;
            }
            let ua_hit = !sec.compiled_ua_blocks.is_empty()
                && session
                    .req_header()
                    .headers
                    .get("user-agent")
                    .is_some_and(|v| crate::shield::ua_blocked(sec, v.as_bytes()));
            if ua_hit {
                metrics::inc_waf_blocked();
                return self
                    .penalise_and_reject(session, visitor_ip, "blocked-ua", 403)
                    .await;
            }
        }

        let _ = session.req_header_mut().remove_header("X-Verified-Bot");
        let is_crawler = crate::shield::is_verified_crawler(&tcp_ip);
        ctx.is_crawler = is_crawler;

        if is_crawler {
            let _ = session
                .req_header_mut()
                .insert_header("X-Verified-Bot", "1");
        } else if !is_trusted {
            // ①a HTTP/2 per-connection ceiling — deliberately the FIRST gate.
            // A flagged connection is answered here, before the load shedder,
            // the rate limiters, the host lookup and any upstream work, which
            // is what turns an amplified request back into a few microseconds.
            // A live CF peer multiplexes many readers on one connection.
            if !crate::tls_router::trusted_cf_peer(tcp_ip)
                && crate::h2_guard::note_stream(ctx.conn_port)
            {
                return Self::reject(session, 429).await;
            }

            if ctx._global_guard.is_none() {
                match self.shedder.acquire() {
                    Some(g) => ctx._global_guard = Some(g),
                    None => {
                        metrics::inc_load_shed();
                        return Self::reject(session, 503).await;
                    }
                }
            }

            // ①b Global RPS Limiter
            if sec.global_rps_limit > 0 && !live.global_rps.check() {
                metrics::inc_load_shed();
                return Self::reject(session, 503).await;
            }

            // ② Penalty Box
            if !tcp_ip.is_loopback() && !verifier_path {
                if let Some(reason) = self.penalty.check(visitor_ip) {
                    metrics::inc_penalty_box_hit();
                    if !Self::escalates_to_edge(reason) {
                        // Short-lived entry: refuse for the box's TTL, no strike toward the handshake ban.
                        return Self::reject(session, 429).await;
                    }
                    return Self::reject_and_strike(session, visitor_ip, 429).await;
                }
            }

            let headers = &session.req_header().headers;

            // ②a Blocked User-Agent (no per-request lowercase allocation)
            if let Some(ua_val) = headers.get("user-agent") {
                let ua = ua_val.as_bytes();
                for blocked in SCANNER_UAS {
                    if crate::shield::contains_ignore_case(ua, blocked.as_bytes()) {
                        metrics::inc_waf_blocked();
                        return self
                            .penalise_and_reject(session, visitor_ip, "blocked-ua", 403)
                            .await;
                    }
                }
                for blocked in LIBRARY_UAS {
                    if !verifier_path && crate::shield::contains_ignore_case(ua, blocked.as_bytes())
                    {
                        metrics::inc_waf_blocked();
                        let hits =
                            LIBRARY_HITS.get_with(visitor_ip, || Arc::new(AtomicU32::new(0)));
                        if hits.fetch_add(1, Ordering::Relaxed) + 1 == LIBRARY_STRIKE_AT {
                            crate::tls_router::strike_ip(tcp_ip);
                        }
                        return Self::reject(session, 403).await;
                    }
                }
            }

            // ③ WAF: Fast Path Scanner Blocking
            if sec.block_scanners {
                let req_path = session.req_header().uri.path();
                let normalized_path = if req_path.contains('%') {
                    static_handler::percent_decode(req_path).to_lowercase()
                } else {
                    req_path.to_lowercase()
                };
                for poison in POISONED_PATHS {
                    if contains_anchored(&normalized_path, poison) {
                        return self
                            .penalise_and_reject(session, visitor_ip, "cve-scanner", 403)
                            .await;
                    }
                }
            }

            // ④ Cloudflare-only gate (global)
            if sec.cloudflare_only && !is_cloudflare_ip(tcp_ip) && !tcp_ip.is_loopback() {
                metrics::inc_cf_blocked();
                return self
                    .penalise_and_reject(session, visitor_ip, "non-cf-ip", 403)
                    .await;
            }

            // ⑤ WAF header scan
            let ua_present = headers.get("user-agent").is_some_and(|v| !v.is_empty());
            if let Some(reason) = check_headers(headers, ua_present, sec) {
                metrics::inc_waf_blocked();
                return self
                    .penalise_and_reject(session, visitor_ip, reason, 400)
                    .await;
            }

            // ⑥ Body size gate
            if sec.max_request_body > 0 {
                if let Some(len) = headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    if len > sec.max_request_body {
                        metrics::inc_body_too_large();
                        return Self::reject_and_strike(session, visitor_ip, 413).await;
                    }
                } else if let Some(te) = headers
                    .get("transfer-encoding")
                    .and_then(|v| v.to_str().ok())
                {
                    if te.to_lowercase().contains("chunked") {
                        metrics::inc_body_too_large();
                        return Self::reject_and_strike(session, visitor_ip, 411).await;
                    }
                }
            }
        }

        // Extraction deferred until necessary to save allocations on dropped requests
        let host = Self::incoming_host(session);

        // ─── ⑦ Route match: O(1) HashMap lookup, zero allocation ───
        // Precedence: explicit route (incl. mode="redirect"), then an on-demand
        // host, then the www to apex fallback, then 421. Redirects short-circuit
        // here, before any upstream work.
        let (route, on_demand) = if let Some(r) = live.route_map.get(&host) {
            // Config-driven redirect route: the whole request goes to its target
            // with path and query kept.
            if r.is_redirect() {
                return Self::redirect_to(session, r.redirect_target(), r.redirect_code()).await;
            }
            (Arc::clone(r), false)
        } else if self.hosts.exists(&host) {
            match &live.fallback_route {
                Some(r) => (Arc::clone(r), true),
                None => {
                    metrics::inc_invalid_host();
                    return Self::reject_and_strike(session, visitor_ip, 421).await;
                }
            }
        } else if let Some(apex) = host.strip_prefix("www.") {
            // Implicit www→apex fallback for any served apex WITHOUT an explicit
            // redirect route — so www canonicalizes to the bare apex automatically.
            if !apex.is_empty() && (live.route_map.contains_key(apex) || self.hosts.exists(apex)) {
                return Self::redirect_to(session, apex, 301).await;
            }
            metrics::inc_invalid_host();
            return Self::reject_and_strike(session, visitor_ip, 421).await;
        } else {
            metrics::inc_invalid_host();
            return Self::reject_and_strike(session, visitor_ip, 421).await;
        };

        if !is_crawler && !is_trusted {
            // ─── ⑦b Per-route CF gate ───
            if route.cloudflare_only && !is_cloudflare_ip(tcp_ip) && !tcp_ip.is_loopback() {
                metrics::inc_cf_blocked();
                return self
                    .penalise_and_reject(session, visitor_ip, "non-cf-ip", 403)
                    .await;
            }

            // ─── ⑧ Per-route rate limit ───
            let rps = route.effective_rps(sec);
            let burst = route.effective_burst(sec);
            if !tcp_ip.is_loopback() && !self.rl.check(visitor_ip, route.uid, rps, burst) {
                metrics::inc_rate_limited();
                return Self::shed(session, 429).await;
            }

            // ─── ②b Fingerprint Limiter ───
            // After ⑧: an IP adds to the shared UA bucket only what its own limit admitted.
            if sec.fingerprint_rps > 0 && !tcp_ip.is_loopback() && !verifier_path {
                let ua_hash = session
                    .req_header()
                    .headers
                    .get("user-agent")
                    .map(|v| {
                        let b = v.as_bytes();
                        let mut h: u64 = 0xcbf29ce484222325;
                        for &byte in b {
                            h = h.wrapping_mul(0x100000001b3) ^ (byte as u64);
                        }
                        h
                    })
                    .unwrap_or(0);
                if !self
                    .fingerprint
                    .check(ua_hash, sec.fingerprint_rps, sec.fingerprint_burst)
                {
                    metrics::inc_waf_blocked();
                    // Shed only: a shared UA bucket (reduced Android Chrome) says nothing about this IP.
                    return Self::shed(session, 429).await;
                }
            }

            // ─── ⑨ Per-IP inflight cap (Slowloris) ───
            if !tcp_ip.is_loopback() {
                match self.inflight.acquire(visitor_ip) {
                    Some(g) => ctx._inflight = Some(g),
                    None => {
                        metrics::inc_inflight_rejected();
                        return Self::shed(session, 503).await;
                    }
                }
            }
        }

        ctx.host = host;
        let route_for_static = Arc::clone(&route);
        ctx.route = Some(route);
        ctx.is_on_demand = on_demand;

        if route_for_static.is_static() {
            // Rapid-reset accounting for the STATIC path.
            //
            // note_cancel lives in fail_to_proxy, which pingora only calls
            // for requests that entered the PROXY path. A static route
            // answers here and returns, so it never reaches that callback —
            // every cancelled static stream was invisible to the guard.
            //
            // That matters most on an edge that only serves static roots: it
            // has no proxied routes at all, so the cancel counter would never
            // move, and the lever that hands a flooding IP to
            // tls_router::block_ip never pulled. The per-connection ceiling
            // (note_stream, above) still applied — it runs before this — but
            // that only sheds streams on the one connection. It does not stop
            // the source from opening another.
            //
            // Cost on the happy path is zero: this only runs when the write
            // itself failed, which for a static response means the socket is
            // already gone.
            let r = static_handler::serve_static(session, &route_for_static, &ctx.host, is_crawler)
                .await;
            if let Err(ref e) = r {
                use pingora_core::ErrorSource;
                // Downstream only. A header-build failure or a read error off
                // the disk is our problem, not an abusive client, and
                // charging it to the visitor's IP would block real traffic
                // over a local fault.
                if matches!(e.esource(), ErrorSource::Downstream) {
                    crate::h2_guard::note_cancel(
                        ctx.visitor_ip,
                        ctx.conn_port,
                        ctx.start.elapsed(),
                    );
                }
            }
            return r;
        }

        // Circuit breaker — answered HERE rather than in upstream_peer, and
        // that placement is the fix, not a preference.
        //
        // Rejecting from upstream_peer meant returning an upstream-sourced
        // Error, which pingora then routed through fail_to_proxy, which
        // recorded ANOTHER failure. The breaker fed itself and never closed.
        // Answering in request_filter produces no Error at all, so there is no
        // path back into the failure counter — the loop cannot exist. It also
        // skips DNS, connect and the errlog accounting entirely.
        if !crate::breaker::allow(route_for_static.id) {
            if crate::errpage::enabled() && !is_crawler && crate::errpage::wants_page(session) {
                ctx.fail_reason = "edge-breaker-open";
                crate::errpage::respond(session, &ctx.host, crate::errpage::Kind::Down, "5")
                    .await?;
                return Ok(true);
            }
            let mut r = ResponseHeader::build(503, Some(3))?;
            let _ = r.insert_header("Retry-After", "5");
            let _ = r.insert_header("Content-Length", "0");
            let _ = r.insert_header("Connection", "close");
            ctx.fail_reason = "edge-breaker-open";
            session.write_response_header(Box::new(r), true).await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let route = match ctx.route.as_ref() {
            Some(r) => r,
            None => {
                return Err(pingora_core::Error::explain(
                    pingora_core::InternalError,
                    "No route found for this request",
                ));
            }
        };
        if route.is_static() {
            tracing::error!(
                "upstream_peer reached for static route '{}' (host={}). \
                 This indicates a misconfiguration — static_handler should have \
                 short-circuited in request_filter.",
                route.name,
                ctx.host
            );
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::InternalError,
                "static route reached upstream_peer",
            ));
        }

        let (addr, tls) = route.upstream_addr();
        let sni = route.upstream_sni();

        let dns_cache = self.dns_cache.clone();
        let addr_clone = addr.clone();
        let socket_addr = match dns_cache.get(&addr) {
            Some(cached) => cached,
            None => {
                // Recently-failed upstream: fail fast without re-resolving or re-logging
                // (it was already logged when the negative entry was inserted).
                if self.dns_neg.contains_key(&addr) {
                    // into_up() matters: Error::explain hardcodes ErrorSource::Unset,
                    // which is why this printed as "Fail to proxy:  ConnectError"
                    // (note the empty source) and fell through suppress_error_log's
                    // Upstream arm to be logged in full, per request, despite the
                    // negative cache existing precisely to stop that. Failing to
                    // resolve the upstream IS an upstream error.
                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::ConnectError,
                        "upstream DNS failing (negative-cached)",
                    )
                    .into_up());
                }
                let mut addrs = tokio::net::lookup_host(&addr_clone).await.map_err(|e| {
                    // Log once per window per upstream, then suppress via the negative cache.
                    tracing::error!(
                        "DNS lookup failed for upstream {}: {} (suppressing repeats for 10s)",
                        addr_clone,
                        e
                    );
                    self.dns_neg.insert(addr_clone.clone(), ());
                    pingora_core::Error::because(
                        pingora_core::ErrorType::ConnectError,
                        "DNS resolution failed",
                        e,
                    )
                    .into_up()
                })?;
                let resolved = addrs.next().ok_or_else(|| {
                    tracing::error!(
                        "No IPs found for upstream {} (suppressing repeats for 10s)",
                        addr_clone
                    );
                    self.dns_neg.insert(addr_clone.clone(), ());
                    pingora_core::Error::explain(
                        pingora_core::ErrorType::ConnectError,
                        "No IP found",
                    )
                    .into_up()
                })?;
                dns_cache.insert(addr.clone(), resolved);
                resolved
            }
        };

        let mut peer = HttpPeer::new(socket_addr, tls, sni);
        // Per-route, falling back to [security].global_timeout_secs. Lets the
        // edge stay tight for the fast routes without 504ing a slow one.
        let timeout = Duration::from_secs(route.effective_timeout(&ctx.live.cfg.security));

        peer.options.connection_timeout = Some(Duration::from_secs(3));
        peer.options.read_timeout = Some(timeout);
        peer.options.write_timeout = Some(timeout);
        peer.options.idle_timeout = Some(Duration::from_secs(60));
        peer.options.verify_cert = tls && !route.insecure_skip_verify;
        peer.options.verify_hostname = tls && !route.insecure_skip_verify;
        // ── Upstream HTTP/2 ──────────────────────────────────────────────
        //
        // Decided from the RESOLVED UPSTREAM IP, not from response headers.
        // Cloudflare does announce itself (`server: cloudflare`, `cf-ray`), but
        // those only arrive with the first response — and ALPN is negotiated
        // during the TLS handshake, before any request is sent. Header sniffing
        // could therefore only ever fix the NEXT connection, and would need a
        // learning period plus a per-upstream cache to do it. The IP is already
        // in hand here, and `CF_RANGES` is already loaded and refreshed for the
        // `cloudflare_only` gate, so this is exact from the very first
        // connection with nothing to remember.
        //
        // Explicit config always wins; `None` means auto.
        //
        // Safe either way: ALPN is negotiated, so an upstream that does not
        // speak h2 simply picks http/1.1.
        let want_h2 = match route.upstream_h2 {
            Some(v) => v,
            None => is_cloudflare_ip(socket_addr.ip()),
        };
        if tls && want_h2 {
            peer.options.set_http_version(2, 1);
        }

        Ok(Box::new(peer))
    }

    // ── 3. upstream_request_filter ───────────────────────────────────────────

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // Invariant: request_filter sets ctx.route before Pingora reaches the upstream
        // phase. Guard it as an Option anyway — on a sole edge a single panic here
        // would abort the worker for an otherwise-fine request. A missing route still
        // strips spoofable headers + sets forwarding headers; it only skips the
        // per-route auth headers, so the upstream rejects with 403 (a clean failure).
        let route = ctx.route.as_ref();

        for h in STRIP_HEADERS {
            let _ = upstream_request.remove_header(*h);
        }
        let live = Arc::clone(&ctx.live);
        let _ = upstream_request.remove_header(&live.real_ip_header);
        let _ = upstream_request.remove_header(&live.real_ip_sig_header);
        // When the visitor address did not come from CF's own header (a chained
        // edge, or no CDN at all), CF-IPCountry describes some hop, not the visitor.
        if !ctx.cf_geo {
            let _ = upstream_request.remove_header("CF-IPCountry");
        }
        if let Some(r) = route {
            for key in r.add_headers.keys() {
                let _ = upstream_request.remove_header(key.as_str());
            }
        }

        let client_ip = ctx.visitor_ip.to_string();

        // The configured real-IP header. When it is not one of the standard
        // names, it can survive a chain where an intermediate CDN or proxy
        // rewrites X-Real-IP and X-Forwarded-For.
        let _ = upstream_request.insert_header(live.real_ip_header.clone(), client_ip.as_str());
        if let Some(key) = &live.real_ip_key {
            let sig = real_ip_sig(key, &client_ip, unix_secs());
            let _ = upstream_request.insert_header(live.real_ip_sig_header.clone(), sig.as_str());
        }
        let _ = upstream_request.insert_header("X-Forwarded-Proto", "https");
        let _ = upstream_request.insert_header("X-Forwarded-Host", ctx.host.as_str());
        let _ = upstream_request.insert_header("X-Real-IP", client_ip.as_str());
        let _ = upstream_request.insert_header("True-Client-IP", client_ip.as_str());

        let xff = match upstream_request
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            Some(existing) if !existing.is_empty() => format!("{}, {}", existing, client_ip),
            _ => client_ip.clone(),
        };
        let _ = upstream_request.insert_header("X-Forwarded-For", xff.as_str());

        if let Some(r) = route {
            for (k, v) in &r.add_headers {
                if let Ok(hname) = HeaderName::try_from(k.as_str()) {
                    let _ = upstream_request.insert_header(hname.clone(), v.as_str());
                }
            }
        }

        // On-demand hosts proxy under their own host; a named route rewrites Host
        // to the upstream vhost. If route is (defensively) missing, fall back to
        // the request host, never panic on the SNI lookup.
        let host_val = match (ctx.is_on_demand, route) {
            (false, Some(r)) => r.upstream_sni(),
            _ => ctx.host.clone(),
        };
        let _ = upstream_request.remove_header("Host");
        let _ = upstream_request.insert_header("Host", host_val.as_str());

        if let Some(len) = upstream_request
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            ctx.bytes_in = len;
        }

        Ok(())
    }

    // Only responses that actually came from the upstream reach this hook,
    // not the edge's own answers (static files, error pages).
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        ctx.upstream_answered = true;
        Ok(())
    }

    // ── 4. response_filter ───────────────────────────────────────────────────

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()> {
        // An outage status from upstream (the origin's bare 503, a CDN 52x)
        // reaches a person as the error page. Erroring here lands in
        // fail_to_proxy with nothing written yet, which is the one place the
        // page is served from; a header-only response never reaches a body
        // filter, so the body cannot be swapped in place.
        if crate::errpage::enabled()
            && crate::errpage::is_outage_status(upstream_response.status.as_u16())
            && !_ctx.is_crawler
            && crate::errpage::wants_page(_session)
        {
            _ctx.dress = true;
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::Custom("dressed"),
                "upstream outage status",
            ));
        }

        upstream_response.remove_header("Server");
        upstream_response.remove_header("X-Powered-By");

        // [blocklist].origin_block_header: the upstream decided this visitor
        // should be refused for N seconds. List the address now, box it so the
        // next request meets the penalty box, and keep the header off the wire.
        let live = Arc::clone(&_ctx.live);
        if let Some(name) = &live.origin_block_header {
            if let Some(v) = upstream_response.headers.get(name) {
                if let Some(secs) = v.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok()) {
                    let ip = _ctx.visitor_ip;
                    if secs > 0 && !ip.is_loopback() && !live.trusted_ips.contains(&ip) {
                        metrics::inc_origin_block();
                        crate::blocklist::note_origin_block(ip, secs);
                        self.penalty.insert(ip, "origin-block");
                    }
                }
                upstream_response.remove_header(name);
            }
        }

        // Added only when the upstream did not set its own value.
        for (k, v) in SECURITY_HEADERS {
            if upstream_response.headers.get(*k).is_none() {
                let _ = upstream_response.insert_header(*k, *v);
            }
        }
        let _ = upstream_response.insert_header("Via", "1.1 proxy");
        Ok(())
    }

    // ── fail_to_proxy: upstream host errors → 503 (not the default 502) ────────
    // A dead, erroring or unreachable backend returns 503 + Retry-After, which
    // clients and crawlers treat as a transient outage. Real upstream HTTP
    // statuses (e.g. the app's own 404) pass through unchanged; downstream
    // (client-side) and internal errors keep the default mapping.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora_core::Error,
        ctx: &mut Self::CTX,
    ) -> FailToProxy {
        use pingora_core::{ErrorSource, ErrorType};
        // The upstream answered; this is its status in a readable body. Not a
        // failure of the edge, so no breaker count and no fail_reason.
        if ctx.dress {
            let _ =
                crate::errpage::respond(session, &ctx.host, crate::errpage::Kind::Down, "30").await;
            return FailToProxy {
                error_code: 503,
                can_reuse_downstream: false,
            };
        }
        let code: u16 = match e.etype() {
            ErrorType::HTTPStatus(c) => *c, // upstream returned a real status — preserve it
            _ => match e.esource() {
                ErrorSource::Upstream => 503, // connect/read/write failure to backend (was 502)
                ErrorSource::Downstream => {
                    // The client went away mid-request. One of these is a
                    // visitor closing a tab; thousands per second from one
                    // source is an HTTP/2 rapid-reset flood, and every one of
                    // them already cost us a full upstream render. The guard
                    // decides which this is by rate — see h2_guard.
                    crate::h2_guard::note_cancel(
                        ctx.visitor_ip,
                        ctx.conn_port,
                        ctx.start.elapsed(),
                    );
                    match e.etype() {
                        ErrorType::WriteError
                        | ErrorType::ReadError
                        | ErrorType::ConnectionClosed => 0, // client already gone
                        _ => 400,
                    }
                }
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        // Internal/Unset is the one class nobody else reports: Downstream is
        // suppressed, Upstream is aggregated by errlog, and pingora's own
        // "Fail to proxy" line is filtered off at the subscriber. These are
        // rare by construction (a bug in our own request path), so they are
        // logged individually and in full.
        if code == 500 {
            tracing::error!(
                "internal proxy error on {}{}: {}",
                ctx.host,
                session.req_header().uri.path(),
                e
            );
        }

        if code == 503 {
            metrics::inc_upstream_unavailable();
            // Only EDGE-synthesised 503s count against the breaker. A backend
            // that answers 503 on its own (maintenance, its own load shedding)
            // is reachable and healthy from the edge's point of view — counting
            // those would let an application status code take its own route
            // offline. That arm is ErrorType::HTTPStatus, not ErrorSource::Upstream.
            if matches!(e.esource(), ErrorSource::Upstream) {
                if let Some(r) = ctx.route.as_ref() {
                    crate::breaker::record_failure(r.id);
                }
            }
            // Name the failure so the metrics separate "the edge could not
            // reach the app" from "the app replied 503". They have completely
            // different fixes: sockets/ports versus application state.
            ctx.fail_reason = match e.etype() {
                ErrorType::ConnectError
                | ErrorType::ConnectTimedout
                | ErrorType::ConnectRefused
                | ErrorType::ConnectNoRoute => "edge-connect-failed",
                ErrorType::ReadTimedout | ErrorType::WriteTimedout => "edge-upstream-timeout",
                _ => "edge-upstream-error",
            };
            if crate::errpage::enabled() && !ctx.is_crawler && crate::errpage::wants_page(session) {
                let _ =
                    crate::errpage::respond(session, &ctx.host, crate::errpage::Kind::Down, "30")
                        .await;
            } else if let Ok(mut r) = ResponseHeader::build(503, Some(3)) {
                let _ = r.insert_header("Retry-After", "30");
                let _ = r.insert_header("Content-Length", "0");
                let _ = r.insert_header("Connection", "close");
                let _ = session.write_response_header(Box::new(r), true).await;
            }
        } else if code > 0 {
            let _ = session.respond_error(code).await;
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    // ── 4b. suppress_error_log ───────────────────────────────────────────────

    /// Drop the per-request "Fail to proxy" ERROR line for downstream aborts.
    ///
    /// Logging is not free, and at this volume it stops being a rounding error.
    /// Every abandoned request emitted a ~300-byte formatted ERROR line; at
    /// ~700/s that is a quarter of a megabyte per second of formatting, and
    /// tracing's fmt layer serialises every event through ONE stdout lock,
    /// so dozens of worker threads queue behind a single mutex to report that
    /// a client hung up, and whatever collects stdout then writes each line.
    ///
    /// A client disconnecting is not an error condition on our side. It is
    /// already counted (the h2 cancel metric) and the source IPs are named by
    /// the cancel guard, so nothing observable is lost by not printing one
    /// line per occurrence.
    ///
    /// Deliberately narrow: ONLY ErrorSource::Downstream is suppressed.
    /// Upstream and internal errors — the ones that mean something is broken
    /// on our side — still log exactly as before.
    fn suppress_error_log(
        &self,
        _session: &Session,
        _ctx: &Self::CTX,
        e: &pingora_core::Error,
    ) -> bool {
        if _ctx.dress {
            return true;
        }
        match e.esource() {
            // Client hung up. Normal, already counted, nothing to say.
            pingora_core::ErrorSource::Downstream => true,
            // Backend failure. This MUST stay visible — "connection refused"
            // is the difference between a slow app and an absent one. But a
            // down backend refuses every request, so the per-request line is
            // pure repetition. Aggregate into one summary per 10s rather than
            // dropping it (see errlog).
            pingora_core::ErrorSource::Upstream => {
                crate::errlog::note_upstream(e);
                true
            }
            // Internal / Unset: rare by construction, always print.
            _ => false,
        }
    }

    // ── 5. logging ───────────────────────────────────────────────────────────

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        if ctx.guillotine.tick() {
            metrics::inc_guillotine_cut();
        }

        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        if status > 0 {
            metrics::inc_requests();
            // A real response means the backend answered. 5xx synthesised by
            // the edge never reaches here with a route + status, so this does
            // not accidentally close the breaker on our own error pages.
            //
            // An app 5xx is an answer too. Counting only < 500 left a half-open
            // probe that met the app's own 503 (its store restarting) neither
            // success nor failure, and the breaker stayed open on a reachable
            // backend.
            if status < 500 || (ctx.upstream_answered && ctx.fail_reason.is_empty()) {
                if let Some(r) = ctx.route.as_ref() {
                    crate::breaker::record_success(r.id);
                }
            }
        }

        metrics::add_bytes_in(ctx.bytes_in);

        // Bytes actually written, not Content-Length: chunked and streamed
        // responses carry none and were missing from the total.
        let out = session.body_bytes_sent() as u64
            + session.response_written().map(header_bytes).unwrap_or(0);
        metrics::add_bytes_out(out);

        let ms = ctx.start.elapsed().as_secs_f64() * 1000.0;
        metrics::observe_latency_ms(ms);

        let route = ctx
            .route
            .as_ref()
            .map(|r| r.name.as_str())
            .unwrap_or(if ctx.is_on_demand { "on-demand" } else { "-" });
        crate::bandwidth::record(route, out, ctx.bytes_in);
        if status >= 500 && !ctx.fail_reason.is_empty() {
            metrics::inc_edge_failure(ctx.fail_reason);
        }

        tracing::debug!(
            "{} {} {} {} {} {}ms",
            ctx.visitor_ip,
            ctx.host,
            session.req_header().method,
            session.req_header().uri.path(),
            status,
            ctx.start.elapsed().as_millis()
        );
    }
}

/// HTTP/1.1 size of a response header block (status line, fields, CRLFs).
fn header_bytes(r: &ResponseHeader) -> u64 {
    let fields: usize = r
        .headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4)
        .sum();
    (fields + 19) as u64
}

fn contains_anchored(haystack: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(idx) = haystack[start..].find(needle) {
        let absolute_idx = start + idx;
        let before = if absolute_idx == 0 {
            b'/'
        } else {
            haystack.as_bytes()[absolute_idx - 1]
        };
        let after_idx = absolute_idx + needle.len();
        let after = if after_idx == haystack.len() {
            b'/'
        } else {
            haystack.as_bytes()[after_idx]
        };
        if (before == b'/' || before == b'\\')
            && (after == b'/' || after == b'?' || after == b'#' || after == b'\\')
        {
            return true;
        }
        start = absolute_idx + 1;
    }
    false
}
