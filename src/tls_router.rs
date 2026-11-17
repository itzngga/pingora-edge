//! SNI-aware TLS pre-filter for port :443.
//!
//! Sits in front of Pingora on :443. Every incoming TCP connection has its
//! TLS ClientHello peeked before forwarding. Invalid traffic gets dropped
//! at this layer before Pingora's BoringSSL accept thread ever allocates
//! TLS state, eliminating the "TLS hoarding" abuse pattern where half-open
//! and non-TLS connections exhaust the accept pool.
//!
//! Defenses applied here:
//!   - 3-second hard timeout on receiving a complete ClientHello (slowloris)
//!   - Drop non-TLS traffic (HTTP-on-443 probes get instant RST)
//!   - Drop oversize ClientHello (>8 KiB is abuse, not legitimate)
//!   - Drop early-disconnect (SYN-then-close pattern)
//!
//! Architecture
//! ─────────────
//!
//!                        ┌─────────────────────────────────┐
//!   :443 (public)  ───►  │  TlsRouter (this module)        │
//!                        │  peeks TLS ClientHello, drops   │
//!                        │  abuse before Pingora sees it   │
//!                        └───────────┬─────────────────────┘
//!                                    │
//!                                    ▼
//!                          127.0.0.1:4443  (Pingora)
//!                          TLS terminated, WAF, routing
//!
//! Trade-off: Pingora sees `127.0.0.1` as the source IP for every connection.
//! Per-IP rate limiting inside Pingora is therefore disabled — but per-IP
//! limits are already enforced at the kernel level (iptables connlimit +
//! hashlimit on :443), and Pingora's global / fingerprint limiters still
//! work (they don't depend on real source IP).

use crate::config::TrustedNets;
use arc_swap::ArcSwap;
use moka::sync::Cache;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration as StdDuration;
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

// ── Abuse tracker ─────────────────────────────────────────────────────────
//
// Tracks per-source-IP "bad behavior" counts. A source that repeatedly
// disconnects mid-handshake (causing `unexpected EOF` in Pingora) gets
// temporarily refused at tls_router before its bytes ever reach Pingora.
//
// This complements the kernel-level iptables rules: those cap rate; this
// catches IPs that stay under the rate cap but always disconnect badly.

const BAD_THRESHOLD: u32 = 3; // strikes before block (default)
const BAD_TTL_SECS: u64 = 300; // memory window (default)

// Both are runtime-configurable, and the TTL is the lever that decides whether
// a rotating proxy pool can be OUTLASTED.
//
// The arithmetic: blocks accrue at some rate R, each lasting TTL, so the
// steady-state blocked set is R x TTL. Observed R is ~2.2 IPs/s, so a 300s TTL
// holds only ~660 addresses at once. An attacker rotating through a pool larger
// than that never runs out of fresh exits and the block never bites. Raise the
// TTL to 1800s and the same rate holds ~4,000; at 3600s, ~7,900 — which is the
// order of an active exit set behind ~1000 threads. Capacity is not the
// constraint: the tracker sizes to 1,000,000 entries on this host.
//
// The cost is real and worth stating: residential addresses are shared and
// recycled, so a long block can catch a genuine visitor whose ISP handed them
// an address an attacker used. That is why it is a knob and not a new constant.
static ABUSE_THRESHOLD: AtomicU32 = AtomicU32::new(BAD_THRESHOLD);
static ABUSE_TTL_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(BAD_TTL_SECS);

/// [security].trust_cloudflare (effective): a live CF peer is never struck,
/// blocked or rate-gated here — one strike would drop every visitor it fronts.
static TRUST_CF: AtomicBool = AtomicBool::new(false);

pub fn set_trust_cf(on: bool) {
    TRUST_CF.store(on, Ordering::Relaxed);
}

pub fn trusted_cf_peer(ip: IpAddr) -> bool {
    TRUST_CF.load(Ordering::Relaxed) && crate::shield::is_cloudflare_ip(ip)
}

/// A new strike threshold for a running tracker (0 keeps the current one, as at boot).
pub fn set_abuse_strikes(strikes: u32) {
    if strikes > 0 && ABUSE_THRESHOLD.swap(strikes, Ordering::Relaxed) != strikes {
        tracing::info!(":443 abuse tracker: {} strikes -> block", strikes);
    }
}

/// Set the strike threshold and block window. MUST be called before `run()`,
/// because the tracker's cache fixes its TTL at construction.
pub fn configure_abuse(strikes: u32, ttl_secs: u64) {
    if strikes > 0 {
        ABUSE_THRESHOLD.store(strikes, Ordering::Relaxed);
    }
    if ttl_secs > 0 {
        ABUSE_TTL_SECS.store(ttl_secs, Ordering::Relaxed);
    }
    tracing::info!(
        ":443 abuse tracker: {} strikes -> {}s block (steady-state capacity {} entries)",
        ABUSE_THRESHOLD.load(Ordering::Relaxed),
        ABUSE_TTL_SECS.load(Ordering::Relaxed),
        crate::tuning::TUNING.abuse_cache_entries,
    );
}

/// A spliced connection shorter than this that also moved almost no bytes never
/// completed a real TLS session. See `MIN_REAL_BYTES`.
const SHORT_CONN: StdDuration = StdDuration::from_millis(50);

/// Byte floor that proves a real TLS session happened: the server's certificate
/// chain alone is 3-5 KiB, so anything past this had a completed handshake and is
/// simply a nearby client on a fast link — not "valid bytes then instant close"
/// (a lone ClientHello tops out around 2 KiB).
///
/// Deliberately generous. The costs here are wildly asymmetric: a false negative
/// just forwards one abusive connection to Pingora, which has its own defenses; a
/// false positive blocks a real visitor's IP. Prefer letting abuse through.
const MIN_REAL_BYTES: u64 = 4096;

#[derive(Clone)]
struct AbuseTracker {
    inner: Arc<Cache<IpAddr, Arc<AtomicU32>>>,
    /// [security].trusted_ips: never strike-tracked or blocked, so a health
    /// checker stays able to observe recovery. Swapped by set_trusted.
    trusted: Arc<ArcSwap<TrustedNets>>,
}

impl AbuseTracker {
    fn new(trusted: TrustedNets) -> Self {
        Self::with_ttl(
            trusted,
            StdDuration::from_secs(ABUSE_TTL_SECS.load(Ordering::Relaxed)),
        )
    }

    fn with_ttl(trusted: TrustedNets, ttl: StdDuration) -> Self {
        Self {
            inner: Arc::new(
                Cache::builder()
                    // Capacity autosized from host RAM (tuning.rs).
                    .max_capacity(crate::tuning::TUNING.abuse_cache_entries)
                    // time_to_LIVE, not time_to_idle. With time_to_idle the block
                    // was self-perpetuating: `is_blocked` does a cache GET, and a
                    // read refreshes the idle timer, so a blocked client that kept
                    // retrying (i.e. any browser) kept its own entry alive forever.
                    // The 5-minute "memory window" never elapsed and the only way
                    // out was a process restart. TTL is absolute — the block now
                    // really does expire 5 minutes after the last strike.
                    .time_to_live(ttl.min(StdDuration::from_secs(crate::limiter::TTL_MAX_SECS)))
                    .build(),
            ),
            trusted: Arc::new(ArcSwap::from_pointee(trusted)),
        }
    }

    /// Returns true if this IP has too many recent bad-behavior strikes.
    /// Trusted IPs always return false.
    fn is_blocked(&self, ip: IpAddr) -> bool {
        if self.trusted.load().contains(&ip) || trusted_cf_peer(ip) {
            return false;
        }
        // Verified search crawlers are NEVER blocked here. Pingora already
        // exempts them (proxy.rs), but this pre-filter did not — and it sits in
        // front, so its block was the one that actually mattered.
        //
        // How that bit: an edge-generated 503 is a tiny, fast connection
        // (Content-Length: 0, ~2ms), which is exactly the strike signature
        // below. So while upstream connects were failing, Googlebot earned 3
        // strikes in seconds and was dropped at :443 for 5 minutes at a time —
        // turning a backend problem into "Google cannot reach this site at all".
        // A prefix-trie lookup is cheap enough to pay on every accept to make
        // that impossible.
        if crate::shield::is_verified_crawler(&ip) {
            return false;
        }
        let threshold = ABUSE_THRESHOLD.load(Ordering::Relaxed);
        self.inner
            .get(&ip)
            .map(|c| c.load(Ordering::Relaxed) >= threshold)
            .unwrap_or(false)
    }

    /// Add a strike. Returns the new count.
    /// Trusted IPs are silently no-op'd (returns 0) so they never accumulate.
    fn strike(&self, ip: IpAddr) -> u32 {
        // Same reasoning as is_blocked: a crawler must not accumulate strikes,
        // or a transient backend wobble evicts it for the whole TTL.
        if self.trusted.load().contains(&ip)
            || crate::shield::is_verified_crawler(&ip)
            || trusted_cf_peer(ip)
        {
            return 0;
        }
        let counter = self.inner.get_with(ip, || Arc::new(AtomicU32::new(0)));
        let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
        // Crossing into a block is the moment a real visitor starts seeing a dead
        // site, so it is not a debug-level event. Logged once per transition.
        if n == ABUSE_THRESHOLD.load(Ordering::Relaxed) {
            tracing::warn!(
                "tls pre-filter: blocking {} for {}s ({} strikes)",
                ip,
                ABUSE_TTL_SECS.load(Ordering::Relaxed),
                n
            );
        }
        n
    }
}

// ── Connection-rate gate ──────────────────────────────────────────────────
//
// nginx's `limit_conn` / `limit_req` at the connection layer, and the answer to
// a TLS handshake flood specifically.
//
// The strike heuristic below classifies a connection AFTER it has been spliced,
// by duration and byte count. That catches connections which never completed a
// handshake — but it is blind to the attack actually running here, where the
// client completes a FULL TLS handshake and then closes before sending the H2
// preface. A completed handshake ships the certificate chain (3-5 KiB), so
// `bytes < MIN_REAL_BYTES` is false and no strike is recorded. The expensive
// part — the asymmetric crypto — has already been paid at that point.
//
// The only thing that bounds handshake cost is refusing the CONNECTION, before
// any of it happens. Rate is the right axis: a real browser opens perhaps six
// to ten connections loading a page, and residential-proxy flood nodes open
// hundreds. Unlike the strike path this needs no judgement about what the
// client did afterwards — by the time we would know, the money is spent.
const CONN_RATE_WINDOW: StdDuration = StdDuration::from_secs(10);

/// Connections per IP per window. 0 disables. Set from config at boot.
static CONN_RATE_MAX: AtomicU32 = AtomicU32::new(0);

/// Connections refused by the gate since boot.
static CONN_RATE_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

static CONN_RATE: once_cell::sync::Lazy<Cache<IpAddr, Arc<AtomicU32>>> =
    once_cell::sync::Lazy::new(|| {
        Cache::builder()
            .max_capacity(crate::tuning::TUNING.abuse_cache_entries)
            // time_to_live, not idle: a lookup must not extend the window it
            // measures, or a client that keeps connecting keeps its own
            // counter alive and never gets a fresh window.
            .time_to_live(CONN_RATE_WINDOW)
            .build()
    });

pub fn configure_conn_rate(max: u32) {
    CONN_RATE_MAX.store(max, Ordering::Relaxed);
    if max > 0 {
        tracing::info!(
            ":443 conn-rate gate: max {} connections per IP per {}s",
            max,
            CONN_RATE_WINDOW.as_secs()
        );
    } else {
        tracing::warn!(":443 conn-rate gate: DISABLED (conn_rate_per_ip = 0)");
    }
}

#[derive(PartialEq)]
enum ConnRate {
    Pass,
    Refuse,
    RefuseAndStrike,
}

/// Refuse when this IP has exceeded its connection budget for the window.
///
/// Trusted IPs and verified crawlers are exempt: Cloudflare and Googlebot both
/// legitimately open far more connections than any single visitor, and a block
/// here happens before TLS, so there is no later layer to save them.
fn conn_rate_exceeded(tracker: &AbuseTracker, ip: IpAddr) -> ConnRate {
    let max = CONN_RATE_MAX.load(Ordering::Relaxed);
    if max == 0 {
        return ConnRate::Pass;
    }
    if tracker.trusted.load().contains(&ip)
        || crate::shield::is_verified_crawler(&ip)
        || trusted_cf_peer(ip)
    {
        return ConnRate::Pass;
    }
    let counter = CONN_RATE.get_with(ip, || Arc::new(AtomicU32::new(0)));
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= max {
        return ConnRate::Pass;
    }
    CONN_RATE_DROPS.fetch_add(1, Ordering::Relaxed);
    if n == max + 1 {
        tracing::debug!(
            ":443 conn-rate gate: {} exceeded {} connections in {}s — refusing before TLS",
            ip,
            max,
            CONN_RATE_WINDOW.as_secs()
        );
    }
    // At most one strike per window: every excess connection is refused, but
    // a burst of them is one event, not dozens of strikes.
    if n == max.saturating_mul(2) {
        tracing::warn!(
            ":443 conn-rate gate: {} reached {} connections in {}s — strike",
            ip,
            n,
            CONN_RATE_WINDOW.as_secs()
        );
        ConnRate::RefuseAndStrike
    } else {
        ConnRate::Refuse
    }
}

/// Connections refused by the conn-rate gate since boot.
pub fn conn_rate_drops() -> u64 {
    CONN_RATE_DROPS.load(Ordering::Relaxed)
}

/// Process-global handle on the pre-filter's abuse tracker.
///
/// The tracker is owned by `run()`, but abuse is not only visible at the TLS
/// layer: an HTTP/2 rapid-reset flood arrives as thousands of streams inside a
/// SINGLE connection, so the pre-filter — which counts connections — sees one
/// well-behaved client. Pingora is the only layer that can see those streams,
/// so it needs a way to report the source back down here, where blocking is
/// cheap (drop before TLS) instead of expensive (terminate TLS, then refuse).
static ABUSE: OnceLock<AbuseTracker> = OnceLock::new();

/// Record ONE strike against `ip` from outside the pre-filter, so an HTTP-layer
/// security gate can escalate a source down to the TCP layer.
///
/// Deliberately one strike rather than an immediate block: at BAD_THRESHOLD the
/// source has to misbehave three times before it stops getting TLS at all. Any
/// single gate hit can be a false positive, and a block here has no appeal — it
/// lands before the handshake, applies across every domain, and lasts the whole
/// window. Three strikes is the cheapest way to require corroboration.
///
/// Trusted IPs and verified crawlers are filtered inside `strike`.
pub fn strike_ip(ip: IpAddr) {
    if let Some(t) = ABUSE.get() {
        t.strike(ip);
        EDGE_STRIKES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Replace the running tracker's trusted set (a no-op before `run()` publishes it).
pub fn set_trusted(nets: TrustedNets) {
    if let Some(t) = ABUSE.get() {
        t.trusted.store(Arc::new(nets));
    }
}

/// Strikes escalated from the HTTP layer, for /metrics.
static EDGE_STRIKES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn edge_strikes() -> u64 {
    EDGE_STRIKES.load(Ordering::Relaxed)
}

/// Force `ip` into the blocked state immediately, as if it had earned every
/// strike at once. For abuse that is unambiguous on first detection, where
/// waiting out three separate windows would mean three more floods.
///
/// Trusted IPs and verified crawlers are exempt — the check lives inside
/// `strike`, so this cannot be used to block Googlebot even by mistake.
pub fn block_ip(ip: IpAddr) {
    if let Some(t) = ABUSE.get() {
        for _ in 0..BAD_THRESHOLD {
            t.strike(ip);
        }
    }
}

pub async fn run(pingora_addr: String, trusted_ips: TrustedNets) {
    let listener = TcpListener::bind("0.0.0.0:443").await.unwrap_or_else(|e| {
        tracing::error!("Cannot bind :443: {}", e);
        std::process::exit(1)
    });

    let trusted_count = trusted_ips.len();
    let tracker = AbuseTracker::new(trusted_ips);
    // Publish for `block_ip` — see ABUSE. Ignore the error: run() is called
    // once, and a second call losing the race would be a no-op either way.
    let _ = ABUSE.set(tracker.clone());

    info!(
        ":443 TLS pre-filter up — all valid TLS → {} (abuse threshold: {} strikes / {}s, {} trusted IP(s) exempt)",
        pingora_addr,
        ABUSE_THRESHOLD.load(Ordering::Relaxed),
        ABUSE_TTL_SECS.load(Ordering::Relaxed),
        trusted_count
    );

    loop {
        let (client, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // NEVER `continue` straight into the next accept(). Under fd
                // exhaustion (EMFILE/ENFILE) accept() fails immediately and
                // forever, which turned this into a silent 100%-CPU spin that
                // served nothing until the process was restarted. Back off so the
                // loop stays alive, sheds CPU, and recovers on its own once fds
                // free up — and say so out loud.
                // Track the STREAK, not just the event: one failure is noise,
                // a sustained run means the listener is wedged (EMFILE) and the
                // watchdog should escalate.
                let streak = ACCEPT_ERR_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::error!(
                    ":443 accept failed ({}) — backing off 100ms (streak {})",
                    e,
                    streak
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        ACCEPT_ERR_STREAK.store(0, Ordering::Relaxed);

        let pingora_addr = pingora_addr.clone();
        let tracker = tracker.clone();
        let peer_ip = peer.ip();

        // Registered with the watchdog so a leaked connection can be reclaimed
        // in-process instead of needing a container restart.
        let conn_id = next_conn_id();
        let jh = tokio::spawn(async move {
            let _ticket = ConnTicket(conn_id);
            // Disable Nagle's algorithm to eliminate 40ms latency spikes
            // on small TLS handshake records.
            let _ = client.set_nodelay(true);
            // Reap this client if it disappears without closing — see the
            // connection-hygiene notes above.
            arm_keepalive(&client, "client");

            // Fast-path block: if this source IP is in penalty, drop instantly.
            // Costs one cache lookup; saves all downstream work.
            if tracker.is_blocked(peer_ip) {
                debug!("Dropped {}: in abuse penalty box", peer);
                return;
            }

            // Backend-down shed. Before the ClientHello peek and before the
            // splice, so a connection with nowhere to go never costs a
            // handshake. Cheapest possible refusal: two atomic reads.
            let peer_is_cf = crate::shield::is_cloudflare_ip(peer_ip);
            if drop_because_backend_down(&tracker, peer_ip, peer_is_cf) {
                debug!("Dropped {}: fallback backend down, refusing pre-TLS", peer);
                return;
            }

            // Connection-rate gate. Sits here, before the ClientHello peek and
            // long before the splice, so a refused connection never costs a
            // TLS handshake. A strike on top means a source that keeps hammering
            // graduates into the penalty box and stops reaching even this check.
            match conn_rate_exceeded(&tracker, peer_ip) {
                ConnRate::Pass => {}
                verdict => {
                    if verdict == ConnRate::RefuseAndStrike {
                        tracker.strike(peer_ip);
                    }
                    debug!("Dropped {}: connection rate exceeded (pre-filter)", peer);
                    return;
                }
            }

            let mut buf = [0u8; 8192];
            let mut last_len = 0;

            // Hard 3-second budget for the client to deliver a complete
            // TLS ClientHello. Slowloris-style attacks (sending one byte
            // every few seconds) are rejected here without ever reaching
            // Pingora.
            let sni_result = timeout(Duration::from_secs(3), async {
                loop {
                    let n = match client.peek(&mut buf).await {
                        Ok(0) => return Err("client-disconnected"),
                        Ok(n) => n,
                        Err(_) => return Err("peek-error"),
                    };

                    match parse_tls_sni(&buf[..n]) {
                        // We only need the parser to confirm "this is a valid
                        // TLS ClientHello". The actual SNI value is no longer
                        // used for routing: Pingora's combined cert resolver
                        // (named routes plus on-demand ACME) handles every
                        // valid SNI, so there's nothing to discriminate on.
                        // Return the byte count as well: the fingerprint gate
                        // below needs the ClientHello, and re-peeking for it
                        // would be a second syscall on the accept path.
                        SniResult::Found(_) | SniResult::NoSni => return Ok(n),
                        SniResult::NotTls => return Err("not-tls-traffic"),
                        SniResult::Incomplete => {
                            if n == buf.len() {
                                return Err("client-hello-too-large");
                            }
                            if n == last_len {
                                tokio::time::sleep(Duration::from_millis(5)).await;
                            }
                            last_len = n;
                        }
                    }
                }
            })
            .await;

            // Reject everything that isn't a valid TLS ClientHello.
            // Each rejection costs a strike for the source IP.
            let hello_len = match sni_result {
                Ok(Ok(n)) => n, // valid TLS — fall through to splice
                Ok(Err("client-disconnected")) => {
                    // NOT a strike. Every mainstream browser opens speculative
                    // preconnect sockets and abandons them without a ClientHello,
                    // as do L4 health checks. Striking this meant three ordinary
                    // page loads could blocklist a real visitor's IP.
                    debug!(
                        "Dropped {}: client-disconnected (pre-filter, no strike)",
                        peer
                    );
                    return;
                }
                Ok(Err(reason)) => {
                    let strikes = tracker.strike(peer_ip);
                    debug!(
                        "Dropped {}: {} (pre-filter, strike {}/{})",
                        peer, reason, strikes, BAD_THRESHOLD
                    );
                    return;
                }
                Err(_) => {
                    let strikes = tracker.strike(peer_ip);
                    debug!(
                        "Dropped {}: slowloris timeout (pre-filter, strike {}/{})",
                        peer, strikes, BAD_THRESHOLD
                    );
                    return;
                }
            };

            // TLS fingerprint gate. Last stop before the splice, and still
            // BEFORE the handshake — the ClientHello is only peeked, so
            // refusing here costs no asymmetric crypto. Unlike every per-IP
            // check above it, this one survives exit-address rotation.
            if fp_over_threshold(&tracker, peer_ip, &buf[..hello_len.min(buf.len())]) {
                debug!("Dropped {}: TLS fingerprint over threshold", peer);
                return;
            }

            // Splice with duration tracking. A connection that completes in under
            // 50ms AND moved almost no bytes never finished a real TLS handshake —
            // the "valid bytes then immediate close" pattern behind `unexpected EOF`
            // in Pingora's logs.
            let started = std::time::Instant::now();
            // Classified once here: CF-sourced connections draw on their own
            // capped share, leaving the remainder reserved for direct traffic.
            let is_cf = peer_is_cf;
            let outcome = splice(client, &pingora_addr, peer, is_cf).await;
            let dur = started.elapsed();

            match outcome {
                // Upstream never accepted us. That is the edge's own fault, not the
                // client's — striking here was a self-amplifying outage: one Pingora
                // hiccup made EVERY connection look "short-lived", so every visitor
                // collected 3 strikes within seconds and the edge blocked the entire
                // internet until it was restarted.
                SpliceOutcome::UpstreamUnavailable => {
                    warn_upstream_down(&pingora_addr);
                }
                // Our own ceiling, not an upstream problem — and equally not the
                // client's fault, so no strike either.
                SpliceOutcome::EdgeAtCapacity => {
                    crate::metrics::inc_edge_at_capacity();
                }
                SpliceOutcome::Spliced(bytes) => {
                    if dur < SHORT_CONN && bytes < MIN_REAL_BYTES {
                        let strikes = tracker.strike(peer_ip);
                        debug!(
                            "Suspicious short-lived TLS from {}: {:?}, {}B (pre-filter, strike {}/{})",
                            peer, dur, bytes, strikes, BAD_THRESHOLD
                        );
                    }
                }
            }
        });
        // The AbortHandle only exists after spawn. If the task already finished
        // by now the entry is stale, and the watchdog's prune pass drops it — so
        // the race is harmless by construction.
        register_conn(conn_id, jh.abort_handle());
    }
}

// ── Connection hygiene ───────────────────────────────────────────────────────
//
// WHY THIS EXISTS. The :443 pre-filter sits in FRONT of Pingora, so Pingora's
// own `global_connection_limit` cannot protect it, and every spliced connection
// costs TWO fds plus one EPHEMERAL PORT for the upstream leg. Linux hands out
// ~28k ephemeral ports (32768-60999). Nothing here ever timed a connection out:
// `copy_bidirectional` runs until one side closes, and a peer that vanishes
// WITHOUT a FIN — a mobile client losing signal, a NAT entry expiring, a CF edge
// node rotating — never closes. Those sockets stayed ESTABLISHED forever because
// SO_KEEPALIVE was never enabled (only TCP_NODELAY was).
//
// One such connection every ~12 seconds exhausts the ephemeral range in about
// four days. Past that, `TcpStream::connect()` to Pingora fails, every new TLS
// connection is dropped, and Cloudflare reports an SSL error — while the process
// is alive, healthy, and logging nothing. That is the 3-5 day cycle.
//
// Two independent defences below, because either alone leaves a hole:
//   1. TCP keepalive so the KERNEL reaps dead peers (~2 min).
//   2. A hard ceiling so a future leak sheds loudly instead of silently
//      strangling the edge.

/// Idle time before the kernel starts probing a quiet peer.
const KA_IDLE_SECS: u64 = 60;
/// Gap between probes once probing starts.
const KA_INTERVAL_SECS: u64 = 10;
/// Failed probes before the connection is declared dead (~2 min total).
const KA_RETRIES: u32 = 6;

/// Enable SO_KEEPALIVE so a peer that disappears without FIN is reaped by the
/// kernel instead of holding an fd and an ephemeral port until restart.
fn arm_keepalive(stream: &tokio::net::TcpStream, what: &str) {
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(KA_IDLE_SECS))
        .with_interval(Duration::from_secs(KA_INTERVAL_SECS))
        .with_retries(KA_RETRIES);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&ka) {
        // Non-fatal: we simply lose the automatic reaper on this socket.
        tracing::debug!("could not arm keepalive on {} socket: {}", what, e);
    }
}

/// Ceiling on simultaneously spliced connections. Sized well under both the fd
/// limit and the ephemeral-port range so we shed with a loud log long before the
/// kernel starts refusing connects. With keepalive armed this should never be
/// reached; if it is, something is leaking and the log says so.
/// Set once at startup from `[security] max_live_tls`. 0 = unlimited.
static MAX_LIVE_SPLICES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(40_000);

/// Share of the ceiling Cloudflare-sourced connections may occupy. The
/// remainder is RESERVED for direct traffic and CF can never take it.
///
/// Why: CF connections are pooled and long-lived (its PoPs hold keep-alives to
/// the origin), while direct connections are short and unbuffered. Sharing one
/// budget lets CF pooling grow until the directly-served hosts, which have no
/// CDN in front and nowhere else to go, start failing TLS. Direct traffic may
/// still use the WHOLE ceiling when CF is quiet; only CF is capped.
const CF_SHARE_PCT: usize = 75;

/// Hard ceiling on direct connections, independent of the overall limit.
/// 0 = no separate cap (direct may use the whole ceiling).
///
/// Why this exists, when CF_SHARE_PCT already reserves capacity FOR direct:
/// that reservation is a floor, not a ceiling. It guarantees direct visitors
/// can always get in; it does nothing to stop them taking everything. Under a
/// residential-proxy flood, direct connections can borrow Cloudflare's idle
/// share until the whole ceiling is held by the attack while the CDN-fronted
/// routes starve.
///
/// With this set, direct traffic is bounded whatever CF is doing, so edge CPU
/// has a deterministic worst case instead of one dictated by the attacker.
static MAX_LIVE_DIRECT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Direct ceiling to use while the fallback backend is DOWN. 0 = no degraded mode.
///
/// The point: when the backend behind the direct surface is dead, every
/// connection it accepts is either attack traffic or a visitor who will get a
/// 503 anyway — but each one still costs a full TLS handshake, which is the
/// expensive part and happens before any routing exists. Holding the normal
/// budget open in that state spends real CPU to produce error pages.
///
/// So the budget follows backend health automatically: it shrinks when the
/// breaker opens and restores when the breaker closes, which happens on the
/// first successful probe after the backend returns. No config edit, no
/// restart, and nothing to remember to undo.
static MAX_LIVE_DIRECT_DEGRADED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Route id whose breaker decides "is the direct backend up" (the on-demand
/// fallback route). usize::MAX = unset, which disables degraded mode entirely.
static WATCH_ROUTE_ID: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Refuse direct connections outright while the fallback backend is down,
/// instead of terminating TLS for them and answering 503.
///
/// Shrinking the budget was the wrong SHAPE of fix: a ceiling only refuses
/// connections above it, so every connection below it still bought a full TLS
/// handshake just to be told the site is down. Refusing at accept costs two
/// atomic reads and a close — no ClientHello parse, no splice, and above all no
/// asymmetric crypto, which is the entire expense.
///
/// Self-limiting by construction: it applies only while the breaker is open, so
/// the moment the backend answers a probe, direct traffic is served normally.
static DROP_DIRECT_WHEN_DOWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Connections refused pre-TLS because the fallback backend was down.
static BACKEND_DOWN_DROPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// True when the watched route's breaker is open.
fn watched_backend_down() -> bool {
    let id = WATCH_ROUTE_ID.load(Ordering::Relaxed);
    id != usize::MAX && crate::breaker::is_open(id)
}

/// Should this connection be dropped before TLS because its backend is dead?
///
/// Cloudflare-sourced traffic is never dropped: it belongs to the CF-fronted
/// routes, which have their own upstreams and their own breakers. Trusted IPs
/// and verified crawlers are exempt too: a drop here lands before TLS, so no
/// later layer can reprieve them, and blackholing a search crawler for the
/// length of a backend outage would cost far more than the handshakes save.
fn drop_because_backend_down(tracker: &AbuseTracker, ip: IpAddr, is_cf: bool) -> bool {
    if !DROP_DIRECT_WHEN_DOWN.load(Ordering::Relaxed) || is_cf {
        return false;
    }
    if !watched_backend_down() {
        return false;
    }
    if tracker.trusted.load().contains(&ip) || crate::shield::is_verified_crawler(&ip) {
        return false;
    }
    BACKEND_DOWN_DROPS.fetch_add(1, Ordering::Relaxed);
    true
}

/// Connections refused pre-TLS because the backend was down, for /metrics.
pub fn backend_down_drops() -> u64 {
    BACKEND_DOWN_DROPS.load(Ordering::Relaxed)
}

pub fn set_drop_direct_when_down(on: bool) {
    DROP_DIRECT_WHEN_DOWN.store(on, Ordering::Relaxed);
    if on {
        tracing::info!(
            ":443 direct connections will be REFUSED pre-TLS while the fallback backend is down"
        );
    }
}

/// The direct ceiling in force RIGHT NOW, given backend health.
///
/// One relaxed load plus, at most, one more inside `is_open`. Cheap enough for
/// the accept path, which is the only place it is called.
fn effective_direct_cap() -> usize {
    let normal = MAX_LIVE_DIRECT.load(Ordering::Relaxed);
    let degraded = MAX_LIVE_DIRECT_DEGRADED.load(Ordering::Relaxed);
    if degraded == 0 {
        return normal;
    }
    if watched_backend_down() {
        return degraded;
    }
    normal
}

static LIVE_CF: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static LIVE_DIRECT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Apply the configured ceiling. Called from main before the listener starts.
pub fn set_max_live_splices(n: usize) {
    MAX_LIVE_SPLICES.store(n, Ordering::Relaxed);
}

/// Apply the direct ceiling. Called from main before the listener starts.
pub fn set_max_live_direct(n: usize) {
    MAX_LIVE_DIRECT.store(n, Ordering::Relaxed);
    if n > 0 {
        tracing::info!(":443 direct connections hard-capped at {}", n);
    }
}

/// Configure the automatic shrink and the backend-down drop. `route_id` is the
/// breaker slot of the on-demand fallback route, which signals backend health;
/// None disables both.
pub fn set_direct_degraded(degraded: usize, route_id: Option<usize>) {
    MAX_LIVE_DIRECT_DEGRADED.store(degraded, Ordering::Relaxed);
    // Cleared too, so losing the fallback route stops watching the old slot.
    WATCH_ROUTE_ID.store(route_id.unwrap_or(usize::MAX), Ordering::Relaxed);
    match (degraded, route_id) {
        (0, _) => {}
        (d, Some(id)) => {
            tracing::info!(
                ":443 direct budget auto-shrinks to {} while route slot {} (on-demand fallback) is down",
                d, id
            );
        }
        (_, None) => {
            tracing::warn!(
                ":443 max_live_direct_degraded is set but no on_demand_fallback route exists, \
                 so the automatic shrink is DISABLED (nothing to watch)"
            );
        }
    }
}

/// The ceiling in force, for /metrics.
pub fn max_live_splices() -> usize {
    MAX_LIVE_SPLICES.load(Ordering::Relaxed)
}

/// Live spliced-connection count, for /health. A number that climbs and never
/// falls back toward zero during quiet hours is the leak signature.
pub fn live_splices() -> usize {
    LIVE_CF.load(Ordering::Relaxed) + LIVE_DIRECT.load(Ordering::Relaxed)
}

/// (cloudflare, direct, cf_cap), so /metrics can show which class is consuming
/// the edge, and whether CF is at its own cap rather than the total.
pub fn live_split() -> (usize, usize, usize) {
    let max = MAX_LIVE_SPLICES.load(Ordering::Relaxed);
    (
        LIVE_CF.load(Ordering::Relaxed),
        LIVE_DIRECT.load(Ordering::Relaxed),
        max / 100 * CF_SHARE_PCT,
    )
}

/// Effective direct ceiling for /metrics: the explicit cap when set, otherwise
/// the overall ceiling (which is what actually bounds it).
pub fn direct_cap() -> usize {
    let n = effective_direct_cap();
    if n > 0 {
        n
    } else {
        MAX_LIVE_SPLICES.load(Ordering::Relaxed)
    }
}

/// Decrements on drop, including task cancellation.
struct SpliceSlot {
    cf: bool,
}

impl SpliceSlot {
    /// None when this connection's budget is exhausted. CF is bounded by its
    /// own share; direct traffic is bounded only by the overall ceiling, so the
    /// reserved remainder is always there when direct visitors need it.
    fn acquire(cf: bool) -> Option<Self> {
        let max = MAX_LIVE_SPLICES.load(Ordering::Relaxed);
        if max == 0 {
            // Unlimited: still count, so /metrics stays truthful.
            if cf {
                LIVE_CF.fetch_add(1, Ordering::Relaxed);
            } else {
                LIVE_DIRECT.fetch_add(1, Ordering::Relaxed);
            }
            return Some(SpliceSlot { cf });
        }

        let counter = if cf { &LIVE_CF } else { &LIVE_DIRECT };
        let prev = counter.fetch_add(1, Ordering::Relaxed);
        let total = LIVE_CF.load(Ordering::Relaxed) + LIVE_DIRECT.load(Ordering::Relaxed);

        // Each class hits its own cap first; both respect the overall ceiling.
        let cf_cap = max / 100 * CF_SHARE_PCT;
        let direct_cap = effective_direct_cap();
        let refused =
            total > max || (cf && prev >= cf_cap) || (!cf && direct_cap > 0 && prev >= direct_cap);
        if refused {
            counter.fetch_sub(1, Ordering::Relaxed);
            warn_splice_ceiling(total.saturating_sub(1), max, cf);
            return None;
        }
        Some(SpliceSlot { cf })
    }
}

impl Drop for SpliceSlot {
    fn drop(&mut self) {
        if self.cf {
            LIVE_CF.fetch_sub(1, Ordering::Relaxed);
        } else {
            LIVE_DIRECT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ── The pre-filter's own watchdog ────────────────────────────────────────────
//
// Docker cannot restart a thread — a failing healthcheck takes the WHOLE
// container down, Pingora included, dropping warm upstream pools and the cert
// cache to fix a problem that is usually recoverable in place. So recovery is
// tiered, and the container restart is the last tier, not the first:
//
//   1. reap  — abort the oldest connections to hand their ephemeral ports back
//   2. wedge — notice the accept loop failing persistently (EMFILE and friends)
//   3. 503   — only once reaping has run and FAILED to relieve the pressure,
//              report unhealthy and let Docker recycle us
//
// Tier 1 is what makes months of uptime plausible: a leak is reclaimed while
// traffic keeps flowing, and nobody is paged.

/// Reap only connections older than this. With keepalive armed a genuinely dead
/// peer is gone in ~2 minutes, so anything still here after 10 is either a real
/// long transfer (rare on an article edge) or leaked. Under pressure the leak is
/// far likelier, and reaping a live transfer only costs that client a retry.
// Cloudflare holds origin keep-alive connections open for many minutes, so a
// 10-minute-old connection is ordinary, not suspect. With SO_KEEPALIVE armed the
// kernel already reaps genuinely dead peers in ~2 minutes, which leaves this
// reaper responsible only for true zombies — sockets alive at the TCP layer but
// abandoned above it. An hour is conservative on purpose: reaping a live CF
// connection costs real user requests.
const REAP_MIN_AGE: Duration = Duration::from_secs(3600);
/// Start reaping at this fraction of the ceiling.
const REAP_AT_PCT: usize = 70;

/// How often the watchdog looks.
const WATCH_INTERVAL: Duration = Duration::from_secs(15);

struct ConnEntry {
    started: std::time::Instant,
    abort: tokio::task::AbortHandle,
}

static CONN_REG: once_cell::sync::Lazy<
    std::sync::Mutex<std::collections::HashMap<u64, ConnEntry>>,
> = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
static NEXT_CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Consecutive accept() failures. A listener stuck on EMFILE returns errors
/// forever; one failure is noise, a few hundred is a wedged edge.
static ACCEPT_ERR_STREAK: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Reap rounds that did not bring us back under the reap threshold.
static FAILED_REAPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Removes its registry entry on drop — including on task cancellation, which is
/// exactly how a reaped connection unwinds.
struct ConnTicket(u64);

impl Drop for ConnTicket {
    fn drop(&mut self) {
        if let Ok(mut reg) = CONN_REG.lock() {
            reg.remove(&self.0);
        }
    }
}

fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

/// Record a spawned connection so the watchdog can reach it later. Called from
/// the accept loop AFTER spawn, since the AbortHandle only exists then; if the
/// task already finished, the sweep below prunes the entry.
fn register_conn(id: u64, abort: tokio::task::AbortHandle) {
    if let Ok(mut reg) = CONN_REG.lock() {
        reg.insert(
            id,
            ConnEntry {
                started: std::time::Instant::now(),
                abort,
            },
        );
    }
}

/// True while the edge is too saturated to be considered healthy AND reaping has
/// already failed to help. Both halves matter: pressure alone is survivable, and
/// reporting unhealthy on pressure alone would restart the container during any
/// legitimate traffic spike.
pub fn edge_unhealthy() -> bool {
    let max = MAX_LIVE_SPLICES.load(Ordering::Relaxed);
    if max == 0 {
        return false;
    }
    let _ = max;
    // DELIBERATELY NOT saturation. Learned the hard way in production: a healthy
    // edge fronted by Cloudflare holds thousands of legitimate long-lived
    // keep-alive connections, so "near the ceiling" is a normal working state,
    // not a fault. Reporting unhealthy on it restarts the container — which does
    // not create capacity, drops every warm connection, and comes straight back
    // to the same number. That is a restart loop, and it is worse than the
    // saturation it was meant to fix.
    //
    // A restart only ever helps when the process itself is wedged, so that is the
    // only thing escalated here. Saturation is handled by reaping (if it is a
    // leak) and by raising `max_live_tls` (if it is real traffic) — both of which
    // keep serving while they happen.
    ACCEPT_ERR_STREAK.load(Ordering::Relaxed) >= 200
}

/// Watchdog state for the /health payload.
pub fn watchdog_state() -> (usize, usize, usize) {
    (
        ACCEPT_ERR_STREAK.load(Ordering::Relaxed),
        FAILED_REAPS.load(Ordering::Relaxed),
        CONN_REG.lock().map(|r| r.len()).unwrap_or(0),
    )
}

/// The watcher. Prunes finished entries every round (cheap, keeps the registry
/// honest) and reaps the oldest connections when the edge is under pressure.
pub fn spawn_watchdog() {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(WATCH_INTERVAL);
        loop {
            ticker.tick().await;
            watchdog_round();
        }
    });
}

/// One watchdog pass. Split out from the timer so the recovery logic can be
/// tested directly instead of through a sleeping loop.
/// Returns (reaped, pruned).
pub(crate) fn watchdog_round() -> (usize, usize) {
    let max = MAX_LIVE_SPLICES.load(Ordering::Relaxed);
    if max == 0 {
        return (0, 0);
    }
    let live = live_splices();

    // Always prune entries whose task already ended. Without this the
    // registry would slowly diverge from reality and the watchdog would
    // reason about connections that no longer exist.
    let mut pruned = 0usize;
    let mut victims: Vec<(u64, tokio::task::AbortHandle)> = Vec::new();
    let under_pressure = live * 100 >= max * REAP_AT_PCT;

    if let Ok(mut reg) = CONN_REG.lock() {
        reg.retain(|_, e| {
            if e.abort.is_finished() {
                pruned += 1;
                false
            } else {
                true
            }
        });
        if under_pressure {
            let now = std::time::Instant::now();
            for (id, e) in reg.iter() {
                if now.duration_since(e.started) >= REAP_MIN_AGE {
                    victims.push((*id, e.abort.clone()));
                }
            }
        }
    }

    if !under_pressure {
        FAILED_REAPS.store(0, Ordering::Relaxed);
        if pruned > 0 {
            tracing::debug!(":443 watchdog pruned {} finished entries", pruned);
        }
        return (0, pruned);
    }

    if victims.is_empty() {
        // Saturated but nothing is old enough to blame — this is real
        // load, not a leak. Count it so a sustained, unrecoverable state
        // eventually reaches the health endpoint.
        let n = FAILED_REAPS.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            ":443 watchdog: {}/{} held but nothing older than {}s to reap \
                     (round {}) — this looks like genuine load, not a leak",
            live,
            max,
            REAP_MIN_AGE.as_secs(),
            n
        );
        return (0, pruned);
    }

    let count = victims.len();
    for (_, abort) in &victims {
        abort.abort();
    }
    // Each aborted task drops its PortCleanupGuard, SpliceSlot and
    // ConnTicket, so the ephemeral port and the slot come back without
    // touching Pingora or any other connection.
    tracing::warn!(
        ":443 watchdog RECLAIMED {} connection(s) older than {}s ({}/{} held, {} pruned) \
                 — ports returned in-process, no restart needed",
        count,
        REAP_MIN_AGE.as_secs(),
        live,
        max,
        pruned
    );

    // Did it help? Checked next round via the live count.
    let after = live_splices();
    if after * 100 >= max * REAP_AT_PCT {
        FAILED_REAPS.fetch_add(1, Ordering::Relaxed);
    } else {
        FAILED_REAPS.store(0, Ordering::Relaxed);
    }
    (count, pruned)
}

/// Hitting the ceiling means connections are not being released. Say so at most
/// once every 10s — this is the warning the silent version never gave.
fn warn_splice_ceiling(live: usize, max: usize, cf: bool) {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) >= 10
        && LAST
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::error!(
            ":443 shedding new {} TLS connections — {} held of a {} ceiling (CF share {}%). \
             If this is real traffic, raise [security].max_live_tls; if it climbs and never \
             recedes, something is leaking.",
            if cf { "CLOUDFLARE" } else { "DIRECT" },
            live,
            max,
            CF_SHARE_PCT
        );
    }
}

pub static REAL_IP_MAP: [RwLock<Option<IpAddr>>; 65536] = [const { RwLock::new(None) }; 65536];

struct PortCleanupGuard(u16);

impl Drop for PortCleanupGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            // Same lifetime, same owner: the h2 per-connection counters are
            // keyed by this port, so they die with it. Ports recycle in
            // seconds and a stale flag would silently 429 the next client.
            crate::h2_guard::release_conn(self.0);
            if let Ok(mut slot) = crate::tls_router::REAL_IP_MAP[self.0 as usize].write() {
                *slot = None;
            }
        }
    }
}

/// What actually happened to a connection handed to `splice`.
enum SpliceOutcome {
    /// Connected to Pingora; carried this many bytes in total (both directions).
    Spliced(u64),
    /// Never reached Pingora — connect refused or timed out. The client did
    /// nothing wrong, so it must not be penalised for this.
    UpstreamUnavailable,
    /// Refused by OUR OWN live-connection ceiling, not by the upstream. Tracked
    /// separately so it is obvious that raising `max_live_tls` is the fix.
    EdgeAtCapacity,
}

/// Pingora being unreachable is an outage, not a debug detail — but it happens
/// once per connection, so log it at most once every 10 seconds.
fn warn_upstream_down(addr: &str) {
    use std::sync::atomic::AtomicU64;
    static LAST: AtomicU64 = AtomicU64::new(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) >= 10
        && LAST
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::error!(
            ":443 pre-filter cannot reach Pingora at {} — TLS connections are being dropped",
            addr
        );
    }
}

async fn splice(
    mut client: tokio::net::TcpStream,
    upstream_addr: &str,
    peer_addr: std::net::SocketAddr,
    is_cf: bool,
) -> SpliceOutcome {
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(upstream_addr),
    )
    .await
    {
        Ok(Ok(mut upstream)) => {
            let _ = upstream.set_nodelay(true);
            // The upstream leg is the one that burns an ephemeral port, so it
            // matters most that a dead one gets reaped.
            arm_keepalive(&upstream, "upstream");

            // Held for the whole splice; released on return OR cancellation.
            let _slot = match SpliceSlot::acquire(is_cf) {
                Some(s) => s,
                // Distinct from UpstreamUnavailable on purpose: reporting our own
                // ceiling as "upstream down" would report phantom upstream
                // failures and point the operator at Pingora, which is healthy.
                None => return SpliceOutcome::EdgeAtCapacity,
            };

            let mut local_port = 0;
            if let Ok(local_addr) = upstream.local_addr() {
                local_port = local_addr.port();
                if let Ok(mut slot) = crate::tls_router::REAL_IP_MAP[local_port as usize].write() {
                    *slot = Some(peer_addr.ip());
                }
            }

            // Clears the REAL_IP_MAP slot on drop, even if this task is cancelled.
            let _guard = PortCleanupGuard(local_port);

            match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                Ok((up, down)) => SpliceOutcome::Spliced(up.saturating_add(down)),
                Err(e) => {
                    tracing::debug!("splice bidirectional error {}: {}", peer_addr, e);
                    // Bytes moved before the error are unknown; report 0 so the
                    // short-connection heuristic can still catch abort patterns.
                    SpliceOutcome::Spliced(0)
                }
            }
        }
        Ok(Err(e)) => {
            tracing::debug!("splice: cannot connect to {}: {}", upstream_addr, e);
            SpliceOutcome::UpstreamUnavailable
        }
        Err(_) => {
            tracing::debug!("splice: connect to {} timed out", upstream_addr);
            SpliceOutcome::UpstreamUnavailable
        }
    }
}
// ── TLS ClientHello SNI parser ────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum SniResult<'a> {
    Found(&'a str),
    NoSni,
    Incomplete,
    NotTls,
}

// ── TLS ClientHello fingerprint (JA3-shaped) ─────────────────────────────────
//
// The one axis a residential proxy pool does NOT randomise.
//
// Rotating exits changes the source address on every connection, which is why
// every per-IP counter in this file read ~zero during the August flood:
// conn-rate 12, h2 ip blocks 0, penalty box flat. But the exits are just
// network paths — one client program is making all of those connections, and it
// emits a byte-identical ClientHello every time. Cipher list, extension list
// and their ORDER are properties of the TLS library and how it was configured,
// not of the route the packet took.
//
// So this hashes the JA3 components — client version, cipher suites, extension
// types, supported groups, EC point formats — into one u64 that stays constant
// across an entire botnet no matter how many addresses it burns.
//
// Two things to be honest about:
//
//   1. It is NOT identity. Every Chrome 120 on earth shares a fingerprint, so a
//      threshold has to sit above the aggregate traffic of the most popular
//      browser build you serve. It groups CLIENT SOFTWARE, not clients.
//   2. It is evadable in principle — a determined attacker can mimic Chrome's
//      ClientHello. It is just far more work than rotating an IP, which is the
//      entire point: it moves the cost onto them for once.
//
// Deliberately a separate pass from parse_tls_sni rather than folded into it.
// That parser returns the moment it finds SNI, so it never walks the remaining
// extensions, and it is the safety-critical gate everything else depends on.
// One extra pass over ~500 already-resident bytes is nothing next to a
// handshake, and it keeps a well-tested function untouched.
//
// GREASE (RFC 8701) values are skipped. Chrome injects random GREASE points
// into these lists specifically to stop implementations hardcoding them — leave
// them in and every Chrome connection fingerprints differently, which would
// defeat the entire mechanism.
#[inline]
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0x00ff)
}

/// FNV-1a, matching the UA fingerprint hashing in proxy.rs.
#[inline]
fn fnv(h: u64, v: u16) -> u64 {
    let mut h = h;
    for b in v.to_be_bytes() {
        h = h.wrapping_mul(0x100000001b3) ^ (b as u64);
    }
    h
}

/// Fingerprint a complete ClientHello. None when the buffer is not a
/// well-formed one — callers treat that as "no fingerprint", never as abuse,
/// because parse_tls_sni is the gate that decides validity.
fn tls_fingerprint(buf: &[u8]) -> Option<u64> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let total_len = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < total_len {
        return None;
    }

    let mut pos = 5usize;
    if pos >= total_len || buf[pos] != 0x01 {
        return None;
    }
    pos += 1 + 3; // handshake type + 3-byte length

    if pos + 2 > total_len {
        return None;
    }
    let mut h = fnv(
        0xcbf29ce484222325,
        u16::from_be_bytes([buf[pos], buf[pos + 1]]),
    );
    pos += 2;

    pos += 32; // client_random
    if pos >= total_len {
        return None;
    }
    pos += 1 + buf[pos] as usize; // session_id

    // cipher_suites
    if pos + 2 > total_len {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > total_len || !cs_len.is_multiple_of(2) {
        return None;
    }
    for c in buf[pos..pos + cs_len].as_chunks::<2>().0 {
        let v = u16::from_be_bytes(*c);
        if !is_grease(v) {
            h = fnv(h, v);
        }
    }
    pos += cs_len;

    // compression_methods
    if pos >= total_len {
        return None;
    }
    pos += 1 + buf[pos] as usize;

    // extensions
    if pos + 2 > total_len {
        return None;
    }
    let ext_end = pos + 2 + u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if ext_end > total_len {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            return None;
        }

        if !is_grease(ext_type) {
            h = fnv(h, ext_type);
        }

        // supported_groups (0x000a) and ec_point_formats (0x000b) contribute
        // their contents too — the last two JA3 fields. Both are length-
        // prefixed inside the extension body.
        match ext_type {
            0x000a if ext_len >= 2 => {
                let n = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                if n + 2 <= ext_len && n.is_multiple_of(2) {
                    for g in buf[pos + 2..pos + 2 + n].as_chunks::<2>().0 {
                        let v = u16::from_be_bytes(*g);
                        if !is_grease(v) {
                            h = fnv(h, v);
                        }
                    }
                }
            }
            0x000b if ext_len >= 1 => {
                let n = buf[pos] as usize;
                if n < ext_len {
                    for &f in &buf[pos + 1..pos + 1 + n] {
                        h = fnv(h, f as u16);
                    }
                }
            }
            _ => {}
        }
        pos += ext_len;
    }

    Some(h)
}

// ── Fingerprint rate tracking ────────────────────────────────────────────────
//
// Ships in SHADOW MODE by default (`tls_fp_enforce = false`): it counts what it
// would have refused and blocks nothing. That default is deliberate. A
// fingerprint groups client SOFTWARE, so a threshold set below the aggregate
// traffic of a popular Chrome build would refuse a slice of the real internet
// before TLS, with no appeal and no way to notice except a traffic dip. Look at
// the distribution first, then enforce.

/// Window over which per-fingerprint connections are counted.
const FP_WINDOW: StdDuration = StdDuration::from_secs(10);

/// Connections per fingerprint per window before it is over threshold.
/// 0 disables the whole mechanism, including the shadow counting.
static FP_RATE_MAX: AtomicU32 = AtomicU32::new(0);
/// false = observe only.
static FP_ENFORCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static FP_SHADOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FP_BLOCKED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Enforcement window: fingerprint -> connections this window.
static FP_RATE: once_cell::sync::Lazy<Cache<u64, Arc<AtomicU32>>> =
    once_cell::sync::Lazy::new(|| {
        Cache::builder()
            .max_capacity(crate::tuning::TUNING.abuse_cache_entries)
            .time_to_live(FP_WINDOW)
            .build()
    });

/// Observation window: fingerprint -> how many times it went over threshold.
/// Long TTL so /api/tls-fingerprints shows a stable picture of who the heavy
/// fingerprints are, which is the whole point of shadow mode.
static FP_OVER: once_cell::sync::Lazy<Cache<u64, Arc<std::sync::atomic::AtomicU64>>> =
    once_cell::sync::Lazy::new(|| {
        Cache::builder()
            .max_capacity(65_536)
            .time_to_live(StdDuration::from_secs(3600))
            .build()
    });

pub fn configure_tls_fp(rate: u32, enforce: bool) {
    FP_RATE_MAX.store(rate, Ordering::Relaxed);
    FP_ENFORCE.store(enforce, Ordering::Relaxed);
    match (rate, enforce) {
        (0, _) => tracing::warn!(":443 TLS fingerprint gate: DISABLED (tls_fp_rate = 0)"),
        (r, false) => tracing::info!(
            ":443 TLS fingerprint gate: SHADOW at {}/{}s — counting only, blocking nothing",
            r,
            FP_WINDOW.as_secs()
        ),
        (r, true) => tracing::info!(
            ":443 TLS fingerprint gate: ENFORCING at {}/{}s",
            r,
            FP_WINDOW.as_secs()
        ),
    }
}

/// Count this ClientHello against its fingerprint. Returns true only when the
/// connection should be refused — which never happens in shadow mode.
fn fp_over_threshold(tracker: &AbuseTracker, ip: IpAddr, hello: &[u8]) -> bool {
    let max = FP_RATE_MAX.load(Ordering::Relaxed);
    if max == 0 {
        return false;
    }
    // Same exemptions as everywhere else, applied BEFORE counting so a crawler
    // can never contribute to a fingerprint's rate either. Googlebot shares its
    // fingerprint with every other client on the same TLS stack.
    if tracker.trusted.load().contains(&ip)
        || crate::shield::is_verified_crawler(&ip)
        || trusted_cf_peer(ip)
    {
        return false;
    }
    let fp = match tls_fingerprint(hello) {
        Some(fp) => fp,
        // Unparseable: parse_tls_sni already accepted this connection, so it is
        // valid TLS we simply could not fingerprint. Never treat that as abuse.
        None => return false,
    };

    let counter = FP_RATE.get_with(fp, || Arc::new(AtomicU32::new(0)));
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= max {
        return false;
    }

    FP_OVER
        .get_with(fp, || Arc::new(std::sync::atomic::AtomicU64::new(0)))
        .fetch_add(1, Ordering::Relaxed);

    if !FP_ENFORCE.load(Ordering::Relaxed) {
        FP_SHADOW.fetch_add(1, Ordering::Relaxed);
        // Log the crossing once per window per fingerprint, so shadow mode is
        // readable rather than a wall.
        if n == max + 1 {
            tracing::warn!(
                ":443 TLS fingerprint {:016x} over threshold ({} in {}s) — SHADOW, not blocked",
                fp,
                n,
                FP_WINDOW.as_secs()
            );
        }
        return false;
    }
    FP_BLOCKED.fetch_add(1, Ordering::Relaxed);
    if n == max + 1 {
        tracing::warn!(
            ":443 TLS fingerprint {:016x} over threshold ({} in {}s) — refusing pre-TLS",
            fp,
            n,
            FP_WINDOW.as_secs()
        );
    }
    true
}

/// (would-have-blocked, actually blocked) since boot.
pub fn tls_fp_stats() -> (u64, u64) {
    (
        FP_SHADOW.load(Ordering::Relaxed),
        FP_BLOCKED.load(Ordering::Relaxed),
    )
}

/// Heaviest fingerprints in the last hour, as (hex fingerprint, times over
/// threshold), worst first. This is what shadow mode is FOR: before enforcing,
/// check that the top entries are the attack and not the browser your readers
/// happen to use.
pub fn tls_fp_top(n: usize) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = FP_OVER
        .iter()
        .map(|(k, c)| (format!("{:016x}", *k), c.load(Ordering::Relaxed)))
        .collect();
    v.sort_by_key(|r| std::cmp::Reverse(r.1));
    v.truncate(n);
    v
}

fn parse_tls_sni(buf: &[u8]) -> SniResult<'_> {
    // Need at least the 5-byte TLS record header
    if buf.len() < 5 {
        return SniResult::Incomplete;
    }

    // ── Record header ────────────────────────────────────────────────────
    // byte 0: content type (0x16 = Handshake)
    // bytes 1-2: legacy_record_version. Modern clients send 0x0301 here
    //   regardless of actual TLS version. Old SSLv3 clients send 0x0300.
    //   Random/garbage clients send other values.
    // bytes 3-4: record length
    if buf[0] != 0x16 {
        return SniResult::NotTls;
    }
    // Reject SSLv3 (0x0300) and anything that isn't TLS 1.0+ record layer.
    // This catches attack tools that send malformed records or pre-TLS-1.0
    // SSL versions that BoringSSL would later reject with [UNSUPPORTED_PROTOCOL].
    if buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x04 {
        return SniResult::NotTls;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;

    // Sanity bound on record_len. RFC 5246 caps it at 2^14 (16384), but
    // a ClientHello rarely exceeds 1-2 KiB. Anything > 8 KiB is abuse.
    // A record_len of 0 or 1 is malformed.
    if !(4..=8192).contains(&record_len) {
        return SniResult::NotTls;
    }

    let total_len = 5 + record_len;

    // Need the entire TLS record to safely parse it
    if buf.len() < total_len {
        return SniResult::Incomplete;
    }

    let mut pos = 5usize;

    if pos >= total_len {
        return SniResult::NotTls;
    }
    if buf[pos] != 0x01 {
        return SniResult::NotTls;
    } // Must be ClientHello
    pos += 1;

    // Skip handshake length (3 bytes)
    if pos + 3 > total_len {
        return SniResult::NotTls;
    }
    pos += 3;

    // ── ClientHello version field ───────────────────────────────────────
    // For TLS 1.2 AND TLS 1.3, this field is 0x0303 (TLS 1.2).
    // TLS 1.3 advertises its actual version via the supported_versions
    // extension, not this field. So 0x0303 is the only valid value for
    // any modern client. Reject everything else.
    if pos + 2 > total_len {
        return SniResult::NotTls;
    }
    let client_ver = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    if client_ver != 0x0303 {
        // 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0300 = SSLv3.
        // Real clients in 2026 don't speak these. BoringSSL would reject
        // anyway with [UNSUPPORTED_PROTOCOL] — we save it the work.
        return SniResult::NotTls;
    }
    pos += 2;

    // Skip client_random (32 bytes)
    if pos + 32 > total_len {
        return SniResult::NotTls;
    }
    pos += 32;

    // Skip session_id
    if pos >= total_len {
        return SniResult::NotTls;
    }
    let sid_len = buf[pos] as usize;
    if sid_len > 32 {
        return SniResult::NotTls;
    } // RFC caps session_id at 32 bytes
    pos += 1 + sid_len;

    // ── cipher_suites ────────────────────────────────────────────────────
    // Empty cipher_suites is malformed. Absurdly long is abuse.
    // RFC technically allows up to 2^16-2, but real clients send 10-50 ciphers
    // (20-100 bytes). > 1024 bytes is an attack pattern.
    if pos + 2 > total_len {
        return SniResult::NotTls;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    if !(2..=1024).contains(&cs_len) || !cs_len.is_multiple_of(2) {
        return SniResult::NotTls;
    }
    pos += 2 + cs_len;

    // Skip compression_methods
    if pos >= total_len {
        return SniResult::NotTls;
    }
    let cm_len = buf[pos] as usize;
    pos += 1 + cm_len;

    // Extensions
    if pos + 2 > total_len {
        return SniResult::NotTls;
    }
    let ext_total = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_total;
    if ext_end > total_len {
        return SniResult::NotTls;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // server_name extension
            if pos + 5 > ext_end {
                return SniResult::NoSni;
            }
            let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
            let name_start = pos + 5;
            let name_end = name_start + name_len;

            if name_end > ext_end {
                return SniResult::NoSni;
            }

            if let Ok(sni) = std::str::from_utf8(&buf[name_start..name_end]) {
                return SniResult::Found(sni);
            } else {
                return SniResult::NoSni; // Malformed UTF-8
            }
        }

        pos += ext_len;
    }

    SniResult::NoSni // No SNI extension found
}

#[cfg(test)]
mod tests {
    use super::{parse_tls_sni, AbuseTracker, SniResult, BAD_THRESHOLD};
    use crate::config::TrustedNets;
    use std::time::Duration as StdDuration;

    /// REGRESSION: a blocked client that keeps retrying must still be released when
    /// the window elapses.
    ///
    /// The tracker used `time_to_idle`, and `is_blocked()` reads the entry — under
    /// moka a read counts as an access and pushes the idle deadline out. So every
    /// retry renewed the very block that was rejecting it: any client that reached
    /// 3 strikes and kept reconnecting (i.e. a browser) stayed blocked until the
    /// process was restarted. This asserts the block really does lift while the
    /// client is polling continuously.
    #[test]
    fn block_expires_even_while_the_client_keeps_retrying() {
        let ip = "203.0.113.7".parse().unwrap();
        let ttl = StdDuration::from_millis(400);
        let tracker = AbuseTracker::with_ttl(TrustedNets::default(), ttl);

        for _ in 0..BAD_THRESHOLD {
            tracker.strike(ip);
        }
        assert!(
            tracker.is_blocked(ip),
            "should be blocked after {} strikes",
            BAD_THRESHOLD
        );

        // Hammer is_blocked() the whole time, exactly like a retrying browser.
        let deadline = std::time::Instant::now() + StdDuration::from_millis(1200);
        let mut released = false;
        while std::time::Instant::now() < deadline {
            std::thread::sleep(StdDuration::from_millis(50));
            tracker.inner.run_pending_tasks();
            if !tracker.is_blocked(ip) {
                released = true;
                break;
            }
        }
        assert!(
            released,
            "block never lifted despite the TTL elapsing — retries are refreshing it"
        );
    }

    /// Trusted IPs (the CF ranges and health checkers) must never be blocked.
    #[test]
    fn trusted_ips_are_never_blocked() {
        let sec: crate::config::SecurityConfig =
            toml::from_str(r#"trusted_ips = ["198.51.100.0/24"]"#).unwrap();
        let tracker = AbuseTracker::with_ttl(sec.trusted_nets(), StdDuration::from_secs(60));
        let ip = "198.51.100.42".parse().unwrap();
        for _ in 0..(BAD_THRESHOLD * 5) {
            assert_eq!(tracker.strike(ip), 0, "trusted IP accumulated a strike");
        }
        assert!(!tracker.is_blocked(ip));
    }

    #[test]
    fn parses_sni() {
        let hostname = b"example.com";
        let name_len = hostname.len() as u16;
        let sni_body_len = (2 + 1 + 2 + hostname.len()) as u16;
        let ext_len = 2 + 2 + sni_body_len as usize + 4;

        let mut ch: Vec<u8> = Vec::new();
        ch.push(0x16);
        ch.extend_from_slice(&[0x03, 0x01]);
        let record_len = (1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_len - 4) as u16;
        ch.extend_from_slice(&record_len.to_be_bytes());

        ch.push(0x01);
        ch.extend_from_slice(&[0x00, 0x00, 0x00]);
        ch.extend_from_slice(&[0x03, 0x03]);
        ch.extend_from_slice(&[0u8; 32]);

        ch.push(0x00);
        ch.extend_from_slice(&[0x00, 0x02]);
        ch.extend_from_slice(&[0x00, 0x2F]);
        ch.push(0x01);
        ch.push(0x00);

        let one_ext_total: u16 = 2 + 2 + sni_body_len;
        ch.extend_from_slice(&one_ext_total.to_be_bytes());
        ch.extend_from_slice(&[0x00, 0x00]);
        ch.extend_from_slice(&sni_body_len.to_be_bytes());
        ch.extend_from_slice(&(sni_body_len - 2).to_be_bytes());
        ch.push(0x00);
        ch.extend_from_slice(&name_len.to_be_bytes());
        ch.extend_from_slice(hostname);

        assert_eq!(parse_tls_sni(&ch), SniResult::Found("example.com"));
    }

    #[test]
    fn returns_incomplete_for_short_buf() {
        // 3 bytes is below the 5-byte record header minimum.
        // Use the first 3 bytes of a valid TLS record header so it isn't
        // rejected as NotTls by the version check.
        let buf = [0x16, 0x03, 0x01];
        assert_eq!(parse_tls_sni(&buf), SniResult::Incomplete);
    }

    #[test]
    fn returns_nottls_for_non_handshake() {
        let mut buf = [0u8; 100];
        buf[0] = 0x15; // alert, not handshake
        assert_eq!(parse_tls_sni(&buf), SniResult::NotTls);
    }

    #[test]
    fn returns_nottls_for_sslv3_record_version() {
        // Valid 0x16 handshake byte but SSLv3 (0x0300) record version.
        // Real attack pattern — these used to slip through and trigger
        // BoringSSL's [UNSUPPORTED_PROTOCOL] error.
        let mut buf = [0u8; 100];
        buf[0] = 0x16;
        buf[1] = 0x03;
        buf[2] = 0x00; // SSLv3 record version
        buf[3] = 0x00;
        buf[4] = 0x40; // 64-byte record
        assert_eq!(parse_tls_sni(&buf), SniResult::NotTls);
    }

    #[test]
    fn returns_nottls_for_pre_tls12_clienthello_version() {
        // Valid record header but ClientHello advertises TLS 1.0.
        // Real clients always send 0x0303 in this field (even for TLS 1.3).
        let mut ch: Vec<u8> = Vec::new();
        ch.push(0x16);
        ch.extend_from_slice(&[0x03, 0x01]); // valid record version
        ch.extend_from_slice(&[0x00, 0x2F]); // record length = 47 bytes (the exact body below)

        ch.push(0x01); // ClientHello
        ch.extend_from_slice(&[0x00, 0x00, 0x3c]); // length
        ch.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 — should be rejected
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session_id len
        ch.extend_from_slice(&[0x00, 0x02]); // cs_len = 2
        ch.extend_from_slice(&[0x00, 0x2F]); // one cipher
        ch.push(0x01);
        ch.push(0x00); // compression
        ch.extend_from_slice(&[0x00, 0x00]); // no extensions

        assert_eq!(parse_tls_sni(&ch), SniResult::NotTls);
    }

    #[test]
    fn parser_never_panics_on_garbage() {
        // Poor-man's fuzz: the ClientHello parser eats raw bytes from the open
        // internet, so it must return a SniResult for ANY input — never panic on an
        // out-of-bounds index or a bad slice. 20k deterministic pseudo-random +
        // truncated inputs, spanning below/at/above the 8 KiB record bound.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 9000) as usize;
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = (next() & 0xff) as u8;
            }
            // Half the time, forge a valid-looking record header so the fuzzer
            // reaches the deeper extension-walking code, not just the early rejects.
            if len >= 5 && next() % 2 == 0 {
                buf[0] = 0x16;
                buf[1] = 0x03;
                buf[2] = 0x01;
                let rl = (next() % 8200) as u16;
                buf[3] = (rl >> 8) as u8;
                buf[4] = (rl & 0xff) as u8;
            }
            let _ = parse_tls_sni(&buf);
        }
    }
}
/// One lock for every test that touches the shared connection budget and
/// registry statics, whichever module it lives in.
#[cfg(test)]
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
// The std lock only serialises these tests; holding it across their awaits is the point.
#[allow(clippy::await_holding_lock)]
mod watchdog_tests {
    use super::*;
    use std::sync::atomic::Ordering as O;

    // Every test here mutates the same process-wide statics, so they must not
    // overlap. (Running them in parallel is what made the first cut fail with
    // another test's connections showing up in the registry.)
    use super::TEST_SERIAL as SERIAL;

    fn reset() {
        LIVE_CF.store(0, O::Relaxed);
        LIVE_DIRECT.store(0, O::Relaxed);
        FAILED_REAPS.store(0, O::Relaxed);
        ACCEPT_ERR_STREAK.store(0, O::Relaxed);
        if let Ok(mut r) = CONN_REG.lock() {
            r.clear();
        }
        set_max_live_splices(100);
    }

    /// A task that hangs forever holding a slot — exactly a leaked splice —
    /// recorded with the age the watchdog will see.
    fn leak(age: Duration) {
        let id = next_conn_id();
        let jh = tokio::spawn(async move {
            let _slot = SpliceSlot::acquire(false); // direct class in tests
            let _t = ConnTicket(id);
            std::future::pending::<()>().await;
        });
        if let Ok(mut reg) = CONN_REG.lock() {
            reg.insert(
                id,
                ConnEntry {
                    started: std::time::Instant::now() - age,
                    abort: jh.abort_handle(),
                },
            );
        }
    }

    /// Abort every task the test leaked and wait for their slots to come
    /// back. A #[tokio::test] releases the lock before its runtime drops the
    /// remaining tasks, so without this their slot decrements would land in
    /// the NEXT test and underflow its counters.
    async fn drain() {
        let handles: Vec<tokio::task::AbortHandle> = CONN_REG
            .lock()
            .map(|r| r.values().map(|e| e.abort.clone()).collect())
            .unwrap_or_default();
        for h in &handles {
            h.abort();
        }
        for _ in 0..200 {
            if handles.iter().all(|h| h.is_finished()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        reset();
    }

    #[tokio::test]
    async fn reaps_leaked_connections_but_spares_young_ones() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for _ in 0..80 {
            leak(REAP_MIN_AGE + Duration::from_secs(60));
        } // leaked
        for _ in 0..10 {
            leak(Duration::from_secs(5));
        } // legitimate
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(live_splices(), 90, "all held before the sweep");

        let (reaped, _) = watchdog_round();
        assert_eq!(reaped, 80, "must reap exactly the old ones");

        // Aborts are asynchronous; give the runtime a moment to unwind them.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let live = live_splices();
        assert_eq!(
            live, 10,
            "young connections must survive, got {} held",
            live
        );
        drain().await;
    }

    #[tokio::test]
    async fn does_nothing_when_pressure_is_low() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for _ in 0..20 {
            leak(REAP_MIN_AGE * 10);
        } // ancient, but only 20/100
        tokio::time::sleep(Duration::from_millis(150)).await;
        let (reaped, _) = watchdog_round();
        assert_eq!(reaped, 0, "must not reap while there is plenty of headroom");
        assert_eq!(live_splices(), 20);
        drain().await;
    }

    /// A CF-fronted edge can sit near its ceiling as a NORMAL state. Restarting on that is a loop — it creates no capacity and drops
    /// every warm connection. Saturation must never escalate, at any duration.
    #[tokio::test]
    async fn saturation_never_triggers_a_restart() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        LIVE_DIRECT.store(100, O::Relaxed); // pinned AT the ceiling
        assert!(
            !edge_unhealthy(),
            "at-capacity must not be reported unhealthy"
        );
        FAILED_REAPS.store(50, O::Relaxed); // reaping has failed for ages
        assert!(
            !edge_unhealthy(),
            "sustained saturation must STILL not restart"
        );
        reset();
    }

    #[tokio::test]
    async fn genuine_load_escalates_instead_of_reaping_forever() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for _ in 0..90 {
            leak(Duration::from_secs(5));
        } // saturated, all YOUNG
        tokio::time::sleep(Duration::from_millis(150)).await;
        for _ in 0..5 {
            let (reaped, _) = watchdog_round();
            assert_eq!(reaped, 0, "nothing is old enough to reap");
        }
        // It logs and counts, but it does NOT restart the process: this is
        // real traffic, and a restart would come straight back to the same number.
        assert!(
            !edge_unhealthy(),
            "genuine load must never trigger a restart"
        );
        drain().await;
    }

    #[tokio::test]
    async fn wedged_accept_loop_is_caught_even_with_no_traffic() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert!(!edge_unhealthy());
        ACCEPT_ERR_STREAK.store(200, O::Relaxed);
        assert!(
            edge_unhealthy(),
            "a persistently failing accept() must be caught"
        );
        reset();
    }

    #[tokio::test]
    async fn finished_tasks_are_pruned() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let id = next_conn_id();
        let jh = tokio::spawn(async {});
        if let Ok(mut reg) = CONN_REG.lock() {
            reg.insert(
                id,
                ConnEntry {
                    started: std::time::Instant::now(),
                    abort: jh.abort_handle(),
                },
            );
        }
        let _ = jh.await;
        let (_, pruned) = watchdog_round();
        assert_eq!(
            pruned, 1,
            "a finished task must be pruned from the registry"
        );
        assert_eq!(CONN_REG.lock().unwrap().len(), 0);
    }
}

#[cfg(test)]
mod capacity_split_tests {
    use super::*;
    use std::sync::atomic::Ordering as O;

    use super::TEST_SERIAL as SERIAL;

    fn reset(max: usize) {
        LIVE_CF.store(0, O::Relaxed);
        LIVE_DIRECT.store(0, O::Relaxed);
        set_max_live_splices(max);
    }

    /// The whole point: a CF connection surge must never consume the slice the
    /// directly-served hosts depend on. They have no CDN to fall back to.
    #[test]
    fn cloudflare_cannot_starve_direct_traffic() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset(1000); // CF share = 750, reserved for direct = 250

        // CF floods as hard as it can.
        let cf: Vec<_> = (0..5000)
            .filter_map(|_| SpliceSlot::acquire(true))
            .collect();
        assert_eq!(cf.len(), 750, "CF must stop at its share, got {}", cf.len());
        assert_eq!(LIVE_CF.load(O::Relaxed), 750);

        // Direct traffic must still be served from the reserved remainder.
        let direct: Vec<_> = (0..5000)
            .filter_map(|_| SpliceSlot::acquire(false))
            .collect();
        assert_eq!(
            direct.len(),
            250,
            "reserved slice must be intact, got {}",
            direct.len()
        );
        assert_eq!(
            live_splices(),
            1000,
            "total must respect the overall ceiling"
        );

        drop(cf);
        drop(direct);
        assert_eq!(live_splices(), 0, "everything released");
    }

    /// The reservation is one-directional: when CF is quiet, direct traffic may
    /// use the entire ceiling rather than being pinned to its 25%.
    #[test]
    fn direct_traffic_may_use_the_whole_ceiling_when_cf_is_idle() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset(1000);
        let direct: Vec<_> = (0..5000)
            .filter_map(|_| SpliceSlot::acquire(false))
            .collect();
        assert_eq!(
            direct.len(),
            1000,
            "direct must not be capped at its reserve"
        );
        // And with the edge full, CF gets nothing — correct, the ceiling is global.
        assert!(SpliceSlot::acquire(true).is_none());
        drop(direct);
        reset(1000);
    }

    /// Ordering must not matter: CF arriving first must not be able to claim
    /// more than its share even when the edge is otherwise empty.
    #[test]
    fn cf_share_holds_regardless_of_arrival_order() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset(400); // CF share = 300, reserved = 100
        let d1: Vec<_> = (0..50).filter_map(|_| SpliceSlot::acquire(false)).collect();
        let cf: Vec<_> = (0..1000)
            .filter_map(|_| SpliceSlot::acquire(true))
            .collect();
        assert_eq!(cf.len(), 300, "CF capped at its share even arriving second");
        let d2: Vec<_> = (0..1000)
            .filter_map(|_| SpliceSlot::acquire(false))
            .collect();
        assert_eq!(
            d1.len() + d2.len(),
            100,
            "direct gets the rest of the ceiling"
        );
        drop((d1, d2, cf));
        assert_eq!(live_splices(), 0);
    }

    #[test]
    fn unlimited_ceiling_still_counts_both_classes() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset(0); // 0 = unlimited
        let a = SpliceSlot::acquire(true).expect("unlimited must never refuse");
        let b = SpliceSlot::acquire(false).expect("unlimited must never refuse");
        assert_eq!(live_split().0, 1, "cf counted");
        assert_eq!(live_split().1, 1, "direct counted");
        drop((a, b));
        assert_eq!(live_splices(), 0);
        reset(40_000);
    }
}

#[cfg(test)]
mod crawler_exemption_tests {
    use super::*;

    /// The failure this prevents: an edge-generated 503 is tiny and fast, which
    /// is the exact strike signature — so a backend wobble was enough to get
    /// Googlebot evicted from :443 entirely.
    #[test]
    fn a_verified_crawler_survives_the_strike_threshold() {
        // Seed the verified-crawler set with a range we control.
        let mut v4: iprange::IpRange<ipnet::Ipv4Net> = iprange::IpRange::new();
        v4.add("66.249.64.0/19".parse().unwrap()); // real Googlebot range
        v4.simplify();
        crate::shield::set_verified_crawlers_for_test(v4);

        let t = AbuseTracker::new(TrustedNets::default());
        let bot: IpAddr = "66.249.66.1".parse().unwrap();
        let human: IpAddr = "203.0.113.50".parse().unwrap();

        // Well past BAD_THRESHOLD.
        for _ in 0..(BAD_THRESHOLD * 5) {
            t.strike(bot);
            t.strike(human);
        }

        assert!(
            !t.is_blocked(bot),
            "Googlebot must never be blocked at the pre-filter"
        );
        assert!(
            t.is_blocked(human),
            "a normal abusive IP must still be blocked"
        );
    }

    #[test]
    fn strikes_are_not_even_recorded_for_crawlers() {
        let mut v4: iprange::IpRange<ipnet::Ipv4Net> = iprange::IpRange::new();
        v4.add("66.249.64.0/19".parse().unwrap());
        v4.simplify();
        crate::shield::set_verified_crawlers_for_test(v4);

        let t = AbuseTracker::new(TrustedNets::default());
        let bot: IpAddr = "66.249.66.9".parse().unwrap();
        assert_eq!(t.strike(bot), 0, "strike() must be a no-op for a crawler");
        assert_eq!(t.strike(bot), 0, "and stay a no-op");
    }
}
