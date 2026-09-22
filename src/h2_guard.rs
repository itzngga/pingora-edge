//! Downstream-cancel accounting — the rapid-reset (CVE-2023-44487) lever, and
//! the general "client vanishes before the response header" gate.
//!
//! Named for h2 because rapid reset is what motivated it, but it is NOT
//! protocol-specific and is deliberately active on HTTP/1.1 too. Over h1 the
//! same behaviour costs MORE per request — no multiplexing means every
//! abandoned request is its own TCP connection and TLS handshake.
//!
//! ## Why nothing else catches this
//!
//! The attack sends a request and immediately RST_STREAMs it, thousands of
//! times, over ONE connection. Every layer we already had counts connections:
//!
//!   - the `:443` pre-filter tracks per-IP connects, short-connection strikes
//!     and `max_live_tls` — all of which see a single, well-behaved client;
//!   - `max_concurrent_streams` is not a bound either, because a reset frees
//!     the slot instantly. That is precisely the attack;
//!   - the `h2` crate's own CVE mitigation, `max_pending_accept_reset_streams`
//!     (default 20), only counts streams reset BEFORE the application accepts
//!     them. Pingora accepts immediately, so these become accepted-then-
//!     cancelled streams and never enter that queue.
//!
//! Meanwhile each cancelled stream had already cost a full upstream request:
//! the backend rendered an article and threw it away. That is where the CPU
//! goes — not in the proxy, in the app behind it.
//!
//! ## Both paths report, and they report from different places
//!
//! `note_cancel` has TWO call sites, and it needs both:
//!
//!   - `fail_to_proxy`, for anything that entered the proxy path;
//!   - the static branch of `request_filter`, because a static route answers
//!     inline and returns — pingora never calls `fail_to_proxy` for it.
//!
//! Miss the second and a STATIC-ONLY host never counts a single cancel: the
//! per-IP threshold is never approached, and the lever that hands a flooding
//! source to `tls_router::block_ip` never pulls. `note_stream` still applies
//! there (it runs before the static dispatch), but a per-connection ceiling
//! only sheds streams on the one connection — it does not stop the source
//! opening another.
//!
//! On a static route the per-stream cost is lower — no upstream render — but
//! it is not free: TLS, HPACK, a spawned task, and the filter chain ahead of
//! the dispatch. The cheap gate is still worth having.
//!
//! So the only layer that can see the abuse is the one holding the H2 session,
//! and the only cheap place to act on it is the pre-filter. This module joins
//! the two: count cancels per source IP, and when one IP's rate is far past
//! anything a browser produces, hand it to `tls_router::block_ip` so its next
//! connections are dropped before TLS.
//!
//! ## The amplification, precisely
//!
//! pingora-core's H2 accept loop is:
//!
//! ```text
//! loop {
//!     let stream = accept_next_stream().await;
//!     runtime.spawn(async move { app.process_new_http(stream).await });
//! }
//! ```
//!
//! Unbounded. Every HEADERS frame spawns a task that runs the full request
//! path — new_ctx, WAF, rate limiters, host lookup, upstream dial — and a
//! client that RST_STREAMs immediately pays for none of it. `max_concurrent_
//! streams` does not throttle the loop, because a reset closes the stream and
//! frees the slot before the spawned task has even started.
//!
//! Two consequences worth stating out loud:
//!
//!   - CTX is created PER STREAM on h2, not per connection. Anything built on
//!     per-connection CTX state silently does not apply — including the
//!     `keepalive_max_requests` guillotine, which on h2 counts to one and
//!     never fires. h2 has no per-connection request cap at all.
//!   - Per-connection state therefore has to be keyed externally. The key is
//!     the pre-filter's source port: every stream on one H2 connection shares
//!     `session.client_addr()`, and the pre-filter already owns that port's
//!     lifetime (see `PortCleanupGuard`), so cleanup comes for free.
//!
//! ## Why a rate, not a flag
//!
//! Client-cancelled streams are completely normal: every time a visitor
//! navigates away mid-load, the browser RST_STREAMs the in-flight requests.
//! A single cancel means nothing. Only the RATE separates a reader closing a
//! tab from a flood, so the default threshold sits two orders of magnitude
//! above browser behaviour and the window is short enough that a busy shared
//! NAT cannot accumulate into it across a whole day.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use once_cell::sync::Lazy;

/// Sliding window over which cancels are counted. Short on purpose: the
/// entry expires outright, so a low background rate of genuine navigation-away
/// cancels can never accumulate into a block over hours.
const WINDOW: Duration = Duration::from_secs(10);

/// Only a cancel that arrives sooner than this after the request counts.
///
/// This is the guard's most important filter, and it exists because the log
/// signature of a rapid-reset flood and the log signature of an OVERLOADED
/// BACKEND are identical: both are a wall of "client closed H2". In the second
/// case the clients are real visitors giving up on a server that stopped
/// answering — and blocking them would turn an outage into a longer outage.
///
/// Time separates the two cleanly. A rapid-reset cancel is sent milliseconds
/// after the request, before any response could exist; a client that gave up
/// waiting cancels after seconds. Anything slower than this threshold is
/// therefore treated as a symptom, never as abuse.
const FAST_CANCEL: Duration = Duration::from_secs(1);

/// Cancels per IP per WINDOW before the IP is blocked. 0 disables the guard.
/// Set from config at boot.
static THRESHOLD: AtomicU32 = AtomicU32::new(0);

/// Total cancels seen, and total IPs blocked — surfaced on the dashboard so
/// an attack in progress is visible rather than inferred from a CPU graph.
static CANCELS: AtomicU64 = AtomicU64::new(0);
static BLOCKED: AtomicU64 = AtomicU64::new(0);

static COUNTS: Lazy<Cache<IpAddr, Arc<AtomicU32>>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(crate::tuning::TUNING.abuse_cache_entries)
        // time_to_live, not time_to_idle: reading a counter must not extend
        // the window it is measuring. The pre-filter's tracker learned this
        // the hard way — an idle timer refreshed by its own lookups made a
        // block self-perpetuating.
        .time_to_live(WINDOW)
        .build()
});

/// Enable the guard with `n` cancels per 10s per IP. 0 leaves it off.
pub fn configure(n: u32) {
    THRESHOLD.store(n, Ordering::Relaxed);
    if n > 0 {
        tracing::info!(
            "h2 cancel guard: blocking any IP past {} cancelled streams / {}s",
            n,
            WINDOW.as_secs()
        );
    } else {
        tracing::warn!("h2 cancel guard: DISABLED (h2_cancel_threshold = 0)");
    }
}

/// Record one client-cancelled stream from `ip` on connection `port`, where
/// `age` is how long the request had been alive when the client gave up.
///
/// Returns true when this cancel crossed the threshold — i.e. the caller just
/// triggered a block. Only true once per window per IP, so it is safe to log
/// on, unlike the cancel itself.
pub fn note_cancel(ip: IpAddr, port: u16, age: Duration) -> bool {
    CANCELS.fetch_add(1, Ordering::Relaxed);
    if age >= FAST_CANCEL {
        // Slow cancel: a client that waited, then gave up. That is a symptom
        // of our own latency, not an attack. Counted in the total so the
        // dashboard still shows the volume, but never blocked on.
        return false;
    }
    note_conn_cancel(port);

    let threshold = THRESHOLD.load(Ordering::Relaxed);

    let counter = COUNTS.get_with(ip, || Arc::new(AtomicU32::new(0)));
    let n = counter.fetch_add(1, Ordering::Relaxed) + 1;

    // Name the source, whether or not blocking is enabled. Diagnosis has to
    // work with the guard switched off: "who is doing this" is the question
    // that decides whether this is an attack, a crawler, or our own tooling,
    // and pingora's own "Fail to proxy" line does not carry the client IP.
    if n == NOISY_MARK {
        name_source(ip, n);
    }

    if threshold == 0 || n != threshold {
        // `!=` rather than `<`: the block fires on the exact crossing, so a
        // flood that keeps arriving during the same window does not re-block
        // (and re-log) on every single stream.
        return false;
    }

    // Verified crawlers and trusted IPs are filtered inside block_ip. Do not
    // pre-filter them here — the counting is harmless and the exemption
    // belongs in one place.
    crate::tls_router::block_ip(ip);
    BLOCKED.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        "h2 cancel guard: {} sent {} cancelled streams in {}s — blocking at the edge",
        ip,
        n,
        WINDOW.as_secs()
    );
    true
}

// ── Per-connection accounting ────────────────────────────────────────────────
//
// Keyed by the pre-filter's source port, which is stable for the life of one
// H2 connection and is already the key REAL_IP_MAP uses. Flat array rather
// than a map: 65536 entries of four u32s is 1 MB, allocated once, and every
// access is an index — no hashing and no lock on the hot path, which matters
// when the thing we are defending against is "too many cheap requests".

const PORTS: usize = 65536;

struct ConnSlot {
    streams: AtomicU32,
    cancels: AtomicU32,
    flagged: AtomicU32, // secs since boot (+1) the connection was flagged; 0 = never
    epoch: AtomicU32,   // coarse secs since boot (+1) the counters started; 0 = unset
}

static CONNS: Lazy<Vec<ConnSlot>> = Lazy::new(|| {
    (0..PORTS)
        .map(|_| ConnSlot {
            streams: AtomicU32::new(0),
            cancels: AtomicU32::new(0),
            flagged: AtomicU32::new(0),
            epoch: AtomicU32::new(0),
        })
        .collect()
});

/// Per-connection counters restart this often, so a long-lived browser
/// connection never adds a lifetime of normal cancels/streams into a flag.
const CONN_EPOCH_SECS: u32 = 60;

/// A flag sheds the connection's streams for this long, then lapses.
const CONN_FLAG_SECS: u32 = 10;

static BOOT: Lazy<std::time::Instant> = Lazy::new(std::time::Instant::now);

fn now_secs() -> u32 {
    BOOT.elapsed().as_secs() as u32 + 1
}

fn roll_epoch(slot: &ConnSlot, now: u32) {
    let epoch = slot.epoch.load(Ordering::Relaxed);
    // saturating: a peer that already rolled to a later `now` is not a stale window.
    if (epoch == 0 || now.saturating_sub(epoch) >= CONN_EPOCH_SECS)
        && slot
            .epoch
            .compare_exchange(epoch, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        slot.streams.store(0, Ordering::Relaxed);
        slot.cancels.store(0, Ordering::Relaxed);
    }
}

fn is_flagged(slot: &ConnSlot, now: u32) -> bool {
    let at = slot.flagged.load(Ordering::Relaxed);
    at != 0 && now.saturating_sub(at) < CONN_FLAG_SECS
}

/// Streams one connection may open before it is flagged. Generous: h2 exists
/// so a browser can pull a page and its assets down one connection, and a
/// crawler may walk many pages. This is the ceiling that h2 never had.
static MAX_STREAMS_PER_CONN: AtomicU32 = AtomicU32::new(0);

/// Fast cancels on ONE connection before it is flagged. Much tighter than the
/// per-IP threshold: a single connection cancelling this many sub-second
/// streams is not a browser under any circumstances.
const CONN_CANCEL_LIMIT: u32 = 20;

/// Configure the per-connection stream ceiling. 0 disables it.
pub fn configure_conn_limit(max_streams: u32) {
    MAX_STREAMS_PER_CONN.store(max_streams, Ordering::Relaxed);
}

/// Called once per request. Returns true when this connection has already been
/// flagged as abusive and the caller should reject cheaply — no upstream dial,
/// no backend render. That early exit is the whole point: it converts an
/// expensive amplified request back into a few microseconds.
pub fn note_stream(port: u16) -> bool {
    let max = MAX_STREAMS_PER_CONN.load(Ordering::Relaxed);
    if max == 0 || port == 0 {
        return false;
    }
    let slot = &CONNS[port as usize];
    let now = now_secs();
    roll_epoch(slot, now);
    if is_flagged(slot, now) {
        // Counted toward the next flag: one that keeps flooding re-flags the moment this lapses.
        slot.streams.fetch_add(1, Ordering::Relaxed);
        REJECTS.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    let n = slot.streams.fetch_add(1, Ordering::Relaxed) + 1;
    if n > max {
        flag(slot, port, now, "stream ceiling");
        REJECTS.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    false
}

/// Called for each fast cancel, in addition to the per-IP accounting.
fn note_conn_cancel(port: u16) {
    if MAX_STREAMS_PER_CONN.load(Ordering::Relaxed) == 0 || port == 0 {
        return;
    }
    let slot = &CONNS[port as usize];
    let now = now_secs();
    roll_epoch(slot, now);
    if slot.cancels.fetch_add(1, Ordering::Relaxed) + 1 >= CONN_CANCEL_LIMIT
        && !is_flagged(slot, now)
    {
        flag(slot, port, now, "cancel ratio");
    }
}

fn flag(slot: &ConnSlot, port: u16, now: u32, why: &str) {
    // swap: re-flags refresh the window; only a connection's first flag logs and counts.
    let prev = slot.flagged.swap(now, Ordering::Relaxed);
    // The window restarts at the flag, so the lapse after CONN_FLAG_SECS is real.
    slot.epoch.store(now, Ordering::Relaxed);
    slot.streams.store(0, Ordering::Relaxed);
    slot.cancels.store(0, Ordering::Relaxed);
    if prev == 0 {
        CONN_FLAGS.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            "h2 cancel guard: connection on port {} flagged ({}) — further streams rejected cheaply",
            port,
            why
        );
    }
}

/// Release a connection's slot. Called by the pre-filter when the connection
/// closes, alongside the REAL_IP_MAP cleanup — ports are recycled fast, and a
/// stale flag would silently break the next client to land on this port.
pub fn release_conn(port: u16) {
    if port == 0 {
        return;
    }
    let slot = &CONNS[port as usize];
    slot.streams.store(0, Ordering::Relaxed);
    slot.cancels.store(0, Ordering::Relaxed);
    slot.flagged.store(0, Ordering::Relaxed);
    slot.epoch.store(0, Ordering::Relaxed);
}

static CONN_FLAGS: AtomicU64 = AtomicU64::new(0);
static REJECTS: AtomicU64 = AtomicU64::new(0);

/// Fast cancels from one IP within a window before it is named in the log.
/// Independent of THRESHOLD so diagnosis works with blocking disabled.
const NOISY_MARK: u32 = 20;

/// Cap on how many distinct IPs get named per window. A handful of names
/// answers the question; ten thousand names IS the answer (it is distributed)
/// and printing them all would only add load during an incident.
const MAX_NAMED_PER_WINDOW: u32 = 10;

static NAMED_COUNT: AtomicU32 = AtomicU32::new(0);
static NAMED_WINDOW: AtomicU64 = AtomicU64::new(0);

fn name_source(ip: IpAddr, n: u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / WINDOW.as_secs())
        .unwrap_or(0);

    // New window: reset the name budget. Losing the race is harmless — the
    // other thread reset it to the same value.
    let prev = NAMED_WINDOW.load(Ordering::Relaxed);
    if prev != now
        && NAMED_WINDOW
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        NAMED_COUNT.store(0, Ordering::Relaxed);
    }

    let slot = NAMED_COUNT.fetch_add(1, Ordering::Relaxed);
    if slot < MAX_NAMED_PER_WINDOW {
        tracing::warn!(
            "h2 cancel guard: {} sent {} sub-second cancels in {}s (blocking {})",
            ip,
            n,
            WINDOW.as_secs(),
            if THRESHOLD.load(Ordering::Relaxed) == 0 {
                "OFF"
            } else {
                "on"
            }
        );
    } else if slot == MAX_NAMED_PER_WINDOW {
        tracing::warn!(
            "h2 cancel guard: more than {} distinct IPs cancelling this window \
             — the source is DISTRIBUTED, not a single client",
            MAX_NAMED_PER_WINDOW
        );
    }
}

/// (cancels seen, IPs blocked, connections flagged, streams cheap-rejected).
pub fn stats() -> (u64, u64, u64, u64) {
    (
        CANCELS.load(Ordering::Relaxed),
        BLOCKED.load(Ordering::Relaxed),
        CONN_FLAGS.load(Ordering::Relaxed),
        REJECTS.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    // THRESHOLD is process-global, so these tests cannot run concurrently
    // with each other. Serialise them rather than pretending otherwise.
    static SERIAL: Mutex<()> = Mutex::new(());

    const FAST: Duration = Duration::from_millis(1);
    const SLOW: Duration = Duration::from_secs(30);

    /// A flagged connection must reject cheaply, and releasing it must clear
    /// the flag — ports are recycled within seconds and the next client to
    /// land on this port is a stranger.
    #[test]
    fn connection_flag_is_set_then_released() {
        let _g = SERIAL.lock().unwrap();
        configure_conn_limit(3);
        let port = 40_000u16;
        release_conn(port);

        assert!(!note_stream(port));
        assert!(!note_stream(port));
        assert!(!note_stream(port));
        assert!(note_stream(port), "4th stream is past the ceiling of 3");
        assert!(note_stream(port), "stays flagged within the flag window");

        release_conn(port);
        assert!(!note_stream(port), "a recycled port must start clean");

        release_conn(port);
        configure_conn_limit(0);
    }

    #[test]
    fn conn_limit_of_zero_disables_the_ceiling() {
        let _g = SERIAL.lock().unwrap();
        configure_conn_limit(0);
        let port = 40_001u16;
        release_conn(port);
        for _ in 0..10_000 {
            assert!(!note_stream(port));
        }
    }

    #[test]
    fn disabled_by_default_counts_nothing() {
        let _g = SERIAL.lock().unwrap();
        THRESHOLD.store(0, Ordering::Relaxed);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        for _ in 0..1000 {
            assert!(
                !note_cancel(ip, 0, FAST),
                "guard must be inert when unconfigured"
            );
        }
    }

    #[test]
    fn fires_once_on_the_exact_crossing() {
        let _g = SERIAL.lock().unwrap();
        THRESHOLD.store(5, Ordering::Relaxed);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));

        let mut fired = 0;
        for _ in 0..20 {
            if note_cancel(ip, 0, FAST) {
                fired += 1;
            }
        }
        assert_eq!(
            fired, 1,
            "must block on the crossing only, not every cancel after"
        );
        THRESHOLD.store(0, Ordering::Relaxed);
    }

    #[test]
    fn counts_are_per_ip() {
        let _g = SERIAL.lock().unwrap();
        THRESHOLD.store(3, Ordering::Relaxed);
        let a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));
        let b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 4));

        // a reaches the threshold...
        assert!(!note_cancel(a, 0, FAST));
        assert!(!note_cancel(a, 0, FAST));
        assert!(note_cancel(a, 0, FAST), "a's third cancel crosses");

        // ...without carrying b along with it.
        assert!(!note_cancel(b, 0, FAST));
        assert!(
            !note_cancel(b, 0, FAST),
            "b has its own counter, still under"
        );
        THRESHOLD.store(0, Ordering::Relaxed);
    }

    /// The false-positive that matters: an overloaded backend makes real
    /// visitors give up, producing the same "client closed H2" wall as an
    /// attack. Blocking them would deepen the outage.
    #[test]
    fn slow_cancels_never_block_however_many() {
        let _g = SERIAL.lock().unwrap();
        THRESHOLD.store(3, Ordering::Relaxed);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        for _ in 0..500 {
            assert!(
                !note_cancel(ip, 0, SLOW),
                "a client that waited 30s and gave up is a symptom, not abuse"
            );
        }
        THRESHOLD.store(0, Ordering::Relaxed);
    }
}
