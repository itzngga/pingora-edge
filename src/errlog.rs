//! Aggregated logging for upstream failures.
//!
//! Upstream errors are the opposite of downstream aborts: a client hanging up
//! is normal, but "connection refused" means the backend is DOWN, and that is
//! the single most important line the edge can print. It must not be silenced.
//!
//! What makes it unusable is not the message, it is the repetition. When the
//! backend is refusing connections it refuses ALL of them, so the same line is
//! emitted per request — thousands per second, each one formatted and pushed
//! through tracing's single stdout mutex, which every worker thread then
//! queues behind. The log stops being a signal and becomes load.
//!
//! So: count them, print one line per interval. The operator learns strictly
//! more from
//!
//!     upstream unreachable: 41203 REFUSED, 12 timeout in the last 10s
//!
//! than from 41203 identical lines, and it costs one atomic increment per
//! error instead of a formatted write.
//!
//! The first error after a quiet period prints immediately — a rare, isolated
//! failure must not sit in a buffer for ten seconds — after which the interval
//! throttle applies.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use pingora_core::ErrorType;

/// Seconds between summary lines while errors keep arriving.
const INTERVAL: u64 = 10;

// Classified rather than keyed by ErrorType so the hot path stays four
// lock-free counters with no hashing and no allocation. These are the
// operationally distinct cases: refused means the process is down, timeout
// means it is alive but wedged, no-route means networking moved under us.
static REFUSED: AtomicU64 = AtomicU64::new(0);
static TIMEOUT: AtomicU64 = AtomicU64::new(0);
static NO_ROUTE: AtomicU64 = AtomicU64::new(0);
/// ConnectError — pingora's catch-all, and what our own DNS failures use
/// (resolution failed / no IP / negative-cached). Broken out because during a
/// DNS outage it is the dominant bucket and lumping it into "other" would hide
/// the cause.
static CONNECT: AtomicU64 = AtomicU64::new(0);
static OTHER: AtomicU64 = AtomicU64::new(0);

static LAST_LOG: AtomicU64 = AtomicU64::new(0);

/// Record one upstream error. The caller suppresses the per-request line
/// unconditionally; this decides when a summary is due.
pub fn note_upstream(e: &pingora_core::Error) {
    match e.etype() {
        ErrorType::ConnectRefused => &REFUSED,
        ErrorType::ConnectTimedout | ErrorType::ReadTimedout | ErrorType::WriteTimedout => &TIMEOUT,
        ErrorType::ConnectNoRoute => &NO_ROUTE,
        ErrorType::ConnectError => &CONNECT,
        _ => &OTHER,
    }
    .fetch_add(1, Ordering::Relaxed);

    maybe_flush();
}

fn maybe_flush() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let last = LAST_LOG.load(Ordering::Relaxed);
    if now.saturating_sub(last) < INTERVAL {
        return;
    }
    // Only the thread that wins the stamp prints, so a burst across all
    // workers still produces exactly one line.
    if LAST_LOG
        .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let refused = REFUSED.swap(0, Ordering::Relaxed);
    let timeout = TIMEOUT.swap(0, Ordering::Relaxed);
    let no_route = NO_ROUTE.swap(0, Ordering::Relaxed);
    let connect = CONNECT.swap(0, Ordering::Relaxed);
    let other = OTHER.swap(0, Ordering::Relaxed);
    if refused + timeout + no_route + connect + other == 0 {
        return;
    }

    // ConnectRefused is not a degraded backend, it is an absent one: nothing
    // is listening on the port. Say so, because it is the difference between
    // "the app is slow" and "the container is not running".
    if refused > 0 {
        tracing::error!(
            "upstream unreachable: {} REFUSED, {} timeout, {} no-route, {} connect/DNS, {} other \
             in the last {}s — connection refused means nothing is listening; check the backend container",
            refused, timeout, no_route, connect, other, INTERVAL
        );
    } else {
        tracing::error!(
            "upstream errors: {} timeout, {} no-route, {} connect/DNS, {} other in the last {}s",
            timeout,
            no_route,
            connect,
            other,
            INTERVAL
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        REFUSED.store(0, Ordering::Relaxed);
        TIMEOUT.store(0, Ordering::Relaxed);
        NO_ROUTE.store(0, Ordering::Relaxed);
        CONNECT.store(0, Ordering::Relaxed);
        OTHER.store(0, Ordering::Relaxed);
        LAST_LOG.store(0, Ordering::Relaxed);
    }

    /// The point of the module: N errors must not produce N log decisions.
    /// The flush that wins drains the counters; the rest of the burst
    /// accumulates for the next interval instead of printing.
    #[test]
    fn a_burst_flushes_once_and_drains() {
        reset();
        for _ in 0..10_000 {
            REFUSED.fetch_add(1, Ordering::Relaxed);
        }
        maybe_flush(); // LAST_LOG is 0, so this one is due immediately
        assert_eq!(
            REFUSED.load(Ordering::Relaxed),
            0,
            "flush must drain the counter"
        );

        // Straight away again: inside the interval, so nothing is emitted and
        // newly-arrived errors stay counted for the next one.
        REFUSED.fetch_add(5, Ordering::Relaxed);
        maybe_flush();
        assert_eq!(
            REFUSED.load(Ordering::Relaxed),
            5,
            "a second flush inside the interval must not drain"
        );
        reset();
    }
}
