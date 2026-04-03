use std::{
    net::IpAddr,
    num::NonZeroU32,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use moka::sync::Cache;

use crate::tuning::TUNING;

type Lim = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// moka panics on a TTL over 1000 years; config TTLs are clamped to 10.
pub const TTL_MAX_SECS: u64 = 315_360_000;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Nanosecond Penalty Box
// ─────────────────────────────────────────────────────────────────────────────

pub struct PenaltyBox {
    inner: Cache<IpAddr, &'static str>,
}

impl PenaltyBox {
    pub fn new(capacity: u64, ttl_secs: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(capacity)
                .time_to_live(Duration::from_secs(ttl_secs.min(TTL_MAX_SECS)))
                .build(),
        }
    }

    #[inline]
    pub fn insert(&self, ip: IpAddr, reason: &'static str) {
        self.inner.insert(ip, reason);
    }

    #[inline]
    pub fn check(&self, ip: IpAddr) -> Option<&'static str> {
        self.inner.get(&ip)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Keep-Alive Guillotine (Zero-Allocation)
// ─────────────────────────────────────────────────────────────────────────────

pub struct Guillotine {
    count: usize,
    max: usize,
}

impl Guillotine {
    pub fn new(max: usize) -> Self {
        Self { count: 0, max }
    }

    #[inline]
    pub fn tick(&mut self) -> bool {
        self.count += 1;
        self.count >= self.max
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Global Load Shedder
// ─────────────────────────────────────────────────────────────────────────────

pub struct GlobalLoadShedder {
    active: AtomicUsize,
    limit: AtomicUsize,
}

impl GlobalLoadShedder {
    pub fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            limit: AtomicUsize::new(limit),
        }
    }

    /// New limit for new requests; live guards keep counting against it.
    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    pub fn acquire(self: &Arc<Self>) -> Option<GlobalGuard> {
        let limit = self.limit.load(Ordering::Relaxed);
        if limit == 0 {
            return Some(GlobalGuard {
                shedder: Arc::clone(self),
                armed: false,
            });
        }
        let prev = self.active.fetch_add(1, Ordering::Relaxed);
        if prev >= limit {
            self.active.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(GlobalGuard {
            shedder: Arc::clone(self),
            armed: true,
        })
    }
}

pub struct GlobalGuard {
    shedder: Arc<GlobalLoadShedder>,
    armed: bool,
}

impl Drop for GlobalGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shedder.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Rate Limiter (0-allocation via IDs)
// ─────────────────────────────────────────────────────────────────────────────

/// (visitor, route uid): the uid survives reorders and reloads (route_ids.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RlKey(IpAddr, u32);

/// A bucket remembers its quota, so a route whose rps/burst changed gets a fresh one.
struct Bucket {
    rps: u32,
    burst: u32,
    lim: Lim,
}

impl Bucket {
    fn new(rps: u32, burst: u32) -> Arc<Self> {
        let quota = Quota::per_second(NonZeroU32::new(rps.max(1)).unwrap())
            .allow_burst(NonZeroU32::new(burst.max(1)).unwrap());
        Arc::new(Self {
            rps,
            burst,
            lim: RateLimiter::direct(quota),
        })
    }
}

/// The bucket under `key` at this quota: kept when it matches, replaced when it does not.
fn bucket<K>(cache: &Cache<K, Arc<Bucket>>, key: K, rps: u32, burst: u32) -> Arc<Bucket>
where
    K: std::hash::Hash + Eq + Copy + Send + Sync + 'static,
{
    let b = cache.get_with(key, || Bucket::new(rps, burst));
    if b.rps == rps && b.burst == burst {
        return b;
    }
    let fresh = Bucket::new(rps, burst);
    cache.insert(key, Arc::clone(&fresh));
    fresh
}

pub struct RateLimiterStore {
    cache: Cache<RlKey, Arc<Bucket>>,
}

impl RateLimiterStore {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(TUNING.abuse_cache_entries)
                .time_to_idle(Duration::from_secs(300))
                .build(),
        }
    }

    pub fn check(&self, ip: IpAddr, uid: u32, rps: u32, burst: u32) -> bool {
        bucket(&self.cache, RlKey(ip, uid), rps, burst)
            .lim
            .check()
            .is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Inflight Limiter
// ─────────────────────────────────────────────────────────────────────────────

pub struct InflightCounter {
    cache: Cache<IpAddr, Arc<AtomicUsize>>,
    max: AtomicUsize,
}

impl InflightCounter {
    pub fn new(max: usize) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(TUNING.abuse_cache_entries)
                .time_to_idle(Duration::from_secs(300))
                .build(),
            max: AtomicUsize::new(max),
        }
    }

    /// New per-IP cap; counters and live guards are kept.
    pub fn set_max(&self, max: usize) {
        self.max.store(max, Ordering::Relaxed);
    }

    pub fn acquire(&self, ip: IpAddr) -> Option<InflightGuard> {
        // Relaxed is enough: the cap only depends on the RMW's atomicity,
        // not on ordering against other memory.
        let counter = self.cache.get_with(ip, || Arc::new(AtomicUsize::new(0)));
        if counter.fetch_add(1, Ordering::Relaxed) >= self.max.load(Ordering::Relaxed) {
            counter.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(InflightGuard(counter))
    }
}

pub struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Global RPS Limiter (anti-residential-proxy DDoS)
//
// Per-IP rate limiting is useless against botnets using millions of unique
// residential IPs. This limiter caps TOTAL requests/sec across ALL sources.
// When the server is overwhelmed, excess requests get 503'd instantly.
// ─────────────────────────────────────────────────────────────────────────────

pub struct GlobalRpsLimiter {
    limiter: Lim,
}

impl GlobalRpsLimiter {
    pub fn new(rps: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rps.max(1)).unwrap())
            .allow_burst(NonZeroU32::new(rps.saturating_mul(2).max(1)).unwrap());
        Self {
            limiter: RateLimiter::direct(quota),
        }
    }

    /// Returns true if this request is allowed, false if global RPS exceeded.
    #[inline]
    pub fn check(&self) -> bool {
        self.limiter.check().is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Fingerprint Limiter (anti-botnet pattern detection)
//
// Residential proxy botnets reuse the same User-Agent across millions of IPs.
// This limiter rate-limits by UA hash — if 1000 different IPs share the same
// UA and collectively exceed the limit, they all get throttled.
// ─────────────────────────────────────────────────────────────────────────────

pub struct FingerprintLimiter {
    cache: Cache<u64, Arc<Bucket>>,
}

impl FingerprintLimiter {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(TUNING.abuse_cache_entries)
                .time_to_idle(Duration::from_secs(120))
                .build(),
        }
    }

    /// Check if a request with this fingerprint hash is allowed at the live quota.
    /// The fingerprint should be a hash of User-Agent (or UA + other signals).
    pub fn check(&self, fingerprint: u64, rps: u32, burst: u32) -> bool {
        bucket(&self.cache, fingerprint, rps, burst)
            .lim
            .check()
            .is_ok()
    }
}
