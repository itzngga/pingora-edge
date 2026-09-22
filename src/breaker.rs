//! Per-upstream circuit breaker — nginx's `max_fails` / `fail_timeout`.
//!
//! This is the defence with no equivalent anywhere else in this proxy, and the
//! one that matters most when a backend dies.
//!
//! nginx marks an upstream server DOWN after `max_fails` failures and stops
//! sending it traffic for `fail_timeout`, answering from the edge instead.
//! Pingora has no such concept: every single request attempts its own fresh
//! connect(). With a backend that is refusing connections and ~1500 req/s
//! arriving, that is 1500 failed syscalls per second, 1500 error objects,
//! 1500 trips through the error path — the edge burning CPU to discover
//! something it already knew 1499 times.
//!
//! Worse, it kicks the backend while it is down. A container trying to boot
//! is fielding a full connection storm the whole time, which is exactly when
//! it least needs one.
//!
//! ## Half-open, not just open
//!
//! A breaker that only opens and closes on a timer either never recovers or
//! stampedes on recovery — every worker discovers "the timeout elapsed" in the
//! same millisecond and the storm resumes. So after `fail_timeout` exactly ONE
//! request is let through as a probe (claimed with a compare-exchange). If it
//! succeeds the breaker closes; if it fails the window restarts. Everything
//! else keeps getting the fast 503.
//!
//! ## Keyed by route id, not address
//!
//! Route ids are small, stable integers assigned at config load, so the state
//! is a flat array indexed directly — no hashing, no allocation, no lock on a
//! path that runs on every request. `upstream_addr()` returns a fresh String
//! and would have meant allocating a key per request to look up "is it down".

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

/// Slots for route ids. Far above any realistic route count; ids at or beyond
/// this fail OPEN (traffic allowed) rather than being silently blackholed.
const SLOTS: usize = crate::route_ids::SLOTS;

struct Breaker {
    /// Consecutive upstream failures since the last success.
    fails: AtomicU32,
    /// Unix seconds when the breaker opened. 0 = closed.
    opened_at: AtomicU64,
    /// Unix seconds the half-open probe was claimed; 0 = none in flight.
    /// Only one probe gets through, and it releases the claim when it reports
    /// back. A probe that never reports — the client left first, or the app
    /// answered in a way neither success nor failure recorded — used to hold
    /// the claim forever: no second probe was ever admitted and the route
    /// answered 503 until the edge restarted. The claim now lapses after
    /// PROBE_LEASE and the next request probes instead.
    probing: AtomicU64,
}

static STATE: Lazy<Vec<Breaker>> = Lazy::new(|| {
    (0..SLOTS)
        .map(|_| Breaker {
            fails: AtomicU32::new(0),
            opened_at: AtomicU64::new(0),
            probing: AtomicU64::new(0),
        })
        .collect()
});

static MAX_FAILS: AtomicU32 = AtomicU32::new(0);
static FAIL_TIMEOUT: AtomicU64 = AtomicU64::new(0);
/// Seconds a half-open probe may stay unreported before another is admitted.
/// Longer than any upstream read, so a slow probe is not joined by a second.
static PROBE_LEASE: AtomicU64 = AtomicU64::new(30);

/// Total requests short-circuited without touching the backend.
static TRIPPED: AtomicU64 = AtomicU64::new(0);

pub fn configure(max_fails: u32, fail_timeout_secs: u64) {
    MAX_FAILS.store(max_fails, Ordering::Relaxed);
    FAIL_TIMEOUT.store(fail_timeout_secs, Ordering::Relaxed);
    PROBE_LEASE.store((fail_timeout_secs * 2).max(30), Ordering::Relaxed);
    if max_fails > 0 {
        tracing::info!(
            "upstream breaker: open after {} consecutive failures, retry after {}s",
            max_fails,
            fail_timeout_secs
        );
    } else {
        tracing::warn!("upstream breaker: DISABLED (upstream_max_fails = 0)");
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True when this request may attempt the upstream.
///
/// Fails open everywhere it is unsure: breaker disabled, unknown route id, or
/// a clock that went backwards. A bug here must never take a healthy backend
/// offline.
pub fn allow(route_id: usize) -> bool {
    if MAX_FAILS.load(Ordering::Relaxed) == 0 || route_id >= SLOTS {
        return true;
    }
    let b = &STATE[route_id];
    let opened = b.opened_at.load(Ordering::Relaxed);
    if opened == 0 {
        return true;
    }

    let t = now();
    if t.saturating_sub(opened) < FAIL_TIMEOUT.load(Ordering::Relaxed) {
        TRIPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    // Timeout elapsed — exactly one caller wins the probe, unless the current
    // claim has lapsed without a report.
    let claimed = b.probing.load(Ordering::Relaxed);
    if claimed != 0 && t.saturating_sub(claimed) < PROBE_LEASE.load(Ordering::Relaxed) {
        TRIPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if b.probing
        .compare_exchange(claimed, t.max(1), Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        return true;
    }
    TRIPPED.fetch_add(1, Ordering::Relaxed);
    false
}

/// Record an upstream failure for this route.
pub fn record_failure(route_id: usize) {
    if MAX_FAILS.load(Ordering::Relaxed) == 0 || route_id >= SLOTS {
        return;
    }
    let b = &STATE[route_id];
    // Was this failure the half-open probe? Read-and-clear, so only the probe's
    // own failure restarts the window.
    let was_probing = b.probing.swap(0, Ordering::Relaxed) != 0;

    let n = b.fails.fetch_add(1, Ordering::Relaxed) + 1;
    if n < MAX_FAILS.load(Ordering::Relaxed) {
        return;
    }

    // CRITICAL: do NOT re-stamp opened_at on every failure while already open.
    //
    // The first version did, and it latched the breaker permanently. Once open,
    // its own rejection produced an upstream-sourced 503, which fell through
    // fail_to_proxy and recorded another failure, which pushed opened_at
    // forward again — so `now - opened_at < fail_timeout` was true forever and
    // the timeout could never elapse. A route that saw one bad ten-failure
    // streak stayed 503 until the process restarted. That is what took the
    // CF-fronted routes down.
    //
    // Stamp on the closed→open transition, and again only when the half-open
    // PROBE fails (which legitimately restarts the window).
    let prev = b.opened_at.load(Ordering::Relaxed);
    if prev == 0 {
        b.opened_at.store(now(), Ordering::Relaxed);
        tracing::error!(
            "upstream breaker OPEN for route {} after {} failures — \
             serving 503 from the edge for {}s without touching the backend",
            route_id,
            n,
            FAIL_TIMEOUT.load(Ordering::Relaxed)
        );
    } else if was_probing {
        b.opened_at.store(now(), Ordering::Relaxed);
    }
}

/// Record an upstream success. Cheap on the hot path: the common case is a
/// closed breaker with zero fails, which costs one relaxed load.
pub fn record_success(route_id: usize) {
    if MAX_FAILS.load(Ordering::Relaxed) == 0 || route_id >= SLOTS {
        return;
    }
    let b = &STATE[route_id];
    if b.fails.load(Ordering::Relaxed) == 0 && b.opened_at.load(Ordering::Relaxed) == 0 {
        return;
    }
    b.fails.store(0, Ordering::Relaxed);
    b.probing.store(0, Ordering::Relaxed);
    if b.opened_at.swap(0, Ordering::Relaxed) != 0 {
        tracing::info!(
            "upstream breaker CLOSED for route {} — backend answering again",
            route_id
        );
    }
}

/// Is this route's breaker currently open? A pure read with no side effects —
/// unlike `allow`, which claims half-open probes and counts trips. Used by the
/// pre-filter to size the direct connection budget to backend health.
pub fn is_open(route_id: usize) -> bool {
    if MAX_FAILS.load(Ordering::Relaxed) == 0 || route_id >= SLOTS {
        return false;
    }
    STATE[route_id].opened_at.load(Ordering::Relaxed) != 0
}

/// Forget a slot's state: it now belongs to another route, or its route's upstream changed.
pub fn reset(route_id: usize) {
    if let Some(b) = STATE.get(route_id) {
        b.fails.store(0, Ordering::Relaxed);
        b.opened_at.store(0, Ordering::Relaxed);
        b.probing.store(0, Ordering::Relaxed);
    }
}

/// Requests short-circuited since boot.
pub fn tripped() -> u64 {
    TRIPPED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // configure() sets process-wide knobs, so the tests take turns.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset(id: usize) {
        STATE[id].fails.store(0, Ordering::Relaxed);
        STATE[id].opened_at.store(0, Ordering::Relaxed);
        STATE[id].probing.store(0, Ordering::Relaxed);
    }

    #[test]
    fn opens_after_max_fails_then_short_circuits() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        configure(3, 60);
        let id = 100;
        reset(id);

        assert!(allow(id));
        record_failure(id);
        record_failure(id);
        assert!(allow(id), "still closed below the threshold");
        record_failure(id);
        assert!(!allow(id), "third failure must open the breaker");
        assert!(!allow(id), "and stay open inside fail_timeout");

        record_success(id);
        assert!(allow(id), "a success closes it again");
        reset(id);
        configure(0, 0);
    }

    #[test]
    fn only_one_probe_is_admitted_after_the_timeout() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // fail_timeout 0 => the timeout has always elapsed, so every call is
        // in probe territory. Exactly one may pass.
        configure(1, 0);
        let id = 101;
        reset(id);

        record_failure(id); // opens
        let admitted = (0..500).filter(|_| allow(id)).count();
        assert_eq!(admitted, 1, "a recovery must not stampede the backend");
        reset(id);
        configure(0, 0);
    }

    /// Regression: the breaker must not latch. Failures arriving WHILE it is
    /// open (including ones caused by its own rejections) must not push the
    /// reopen deadline forward, or it never closes again.
    #[test]
    fn open_breaker_does_not_latch_on_further_failures() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        configure(2, 0); // fail_timeout 0 => the window has always elapsed
        let id = 102;
        reset(id);

        record_failure(id);
        record_failure(id); // opens
        let opened = STATE[id].opened_at.load(Ordering::Relaxed);

        // A pile of further failures while open, as the latch bug produced.
        for _ in 0..100 {
            record_failure(id);
        }
        assert_eq!(
            STATE[id].opened_at.load(Ordering::Relaxed),
            opened,
            "failures while open must not move the reopen deadline"
        );
        // ...and a probe is still admitted, i.e. recovery is still possible.
        assert!(allow(id), "breaker must still be able to half-open");
        reset(id);
        configure(0, 0);
    }

    #[test]
    fn unreported_probe_lapses_instead_of_latching() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        configure(1, 0);
        let id = 103;
        reset(id);

        record_failure(id); // opens
        assert!(allow(id), "first probe admitted");
        // The probe never reports back (client abort / app 5xx).
        assert!(!allow(id), "no second probe while the claim is live");
        // The lease runs out: backdate the claim rather than touching the
        // shared lease, which the other tests read concurrently.
        let lease = PROBE_LEASE.load(Ordering::Relaxed);
        STATE[id]
            .probing
            .store(now().saturating_sub(lease + 1).max(1), Ordering::Relaxed);
        assert!(allow(id), "a lapsed claim must admit the next probe");
        record_success(id);
        assert!(allow(id) && allow(id), "and a success closes the breaker");
        reset(id);
        configure(0, 0);
    }

    #[test]
    fn disabled_and_unknown_routes_fail_open() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        configure(0, 0);
        assert!(allow(7), "breaker off must never block");
        configure(1, 60);
        assert!(allow(SLOTS + 5), "an id past the table must fail open");
        configure(0, 0);
    }
}
