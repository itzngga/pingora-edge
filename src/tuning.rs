//! Host-spec autotuning. main.rs derives thread counts from the CPU count;
//! the knobs here derive from available RAM the same way, so a 1 GB VM
//! and a 16 GB box both get sane cache budgets without config changes.
//! `PROXY_BODY_CACHE_MB` overrides the body-cache budget, mirroring the
//! `TOKIO_WORKER_THREADS` override for threads.

use once_cell::sync::Lazy;

pub struct Tuning {
    pub total_ram_bytes: u64,
    /// static_handler body cache budget (bytes).
    pub body_cache_bytes: u64,
    /// Largest single body the static_handler will cache (bytes).
    pub max_cached_body: usize,
    /// static_handler resolution cache (entry count; entries are tiny).
    pub resolve_cache_entries: u64,
    /// tls_router per-IP abuse tracker capacity (entry count).
    pub abuse_cache_entries: u64,
    /// Downstream h1 keep-alive idle timeout (seconds); 0 = as long as the
    /// client likes. `[security] keepalive_idle_secs` overrides it.
    pub keepalive_idle_secs: u64,
    /// Live :443 connections the RAM carries; caps the shipped `max_live_tls`.
    pub max_live_conns: usize,
    /// Idle upstream connections Pingora keeps for reuse (one pool, every upstream).
    pub upstream_pool: usize,
    /// The memory the edge's own systemd unit lets it use, when it runs in one.
    pub unit_limit_bytes: Option<u64>,
}

pub static TUNING: Lazy<Tuning> = Lazy::new(|| {
    let mut t = Tuning::from_limits(effective_ram(), unit_limit());
    if let Some(mb) = std::env::var("PROXY_BODY_CACHE_MB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        t.body_cache_bytes = mb << 20;
        t.max_cached_body = per_entry_cap(t.body_cache_bytes);
    }
    t
});

impl Tuning {
    /// Pure sizing formulas. At 1 GiB they yield 16 MiB / 512 KiB / 2048 /
    /// ~51k — the values the static handler originally shipped with.
    fn from_ram(ram: u64) -> Self {
        let body_cache_bytes = (ram / 64).clamp(8 << 20, 256 << 20);
        let ram_mib = ram >> 20;
        Self {
            total_ram_bytes: ram,
            body_cache_bytes,
            max_cached_body: per_entry_cap(body_cache_bytes),
            resolve_cache_entries: (ram_mib * 2).clamp(512, 32_768),
            // Per-IP counter caches: abuse strikes, conn-rate, h2 cancels,
            // rate limiter, inflight, UA fingerprint, SNI attempts. SEVEN
            // caches share this number, so the real cost is 7x whatever it
            // says — worth remembering before raising it.
            //
            // Budget at ~200 B/entry (IpAddr or short String key, an
            // Arc<AtomicU32>, plus moka's entry metadata, TTL timestamps and
            // TinyLFU sketch):
            //
            //     1,000,000 ->  1.3 GB across all seven   (the old ceiling)
            //     6,553,600 ->  8.5 GB  <- what 128 GiB now gets
            //    16,000,000 -> 20.9 GB  (the new ceiling)
            //
            // The old flat 1,000,000 cap made sizing stop being proportional
            // at 20 GiB of RAM, so a 128 GiB edge held no more blocked
            // addresses than a small one. Capacity decides how large a
            // rotating proxy pool can be outlasted: the blocked set holds
            // (strike rate x block window), and once that product exceeds
            // capacity, moka starts evicting live blocks.
            //
            // The multiplier is deliberately UNCHANGED, so small hosts size
            // exactly as before — only the ceiling moved. Capacity is also a
            // limit, not a reservation: moka allocates per entry on insert, so
            // an edge that never sees these addresses never pays for them.
            abuse_cache_entries: (ram_mib * 50).clamp(10_000, 16_000_000),
            // A kept-alive TLS connection holds ~120 KiB while it idles (the
            // splice task and its two sockets, the TLS session, the h1 session):
            // measured at 1 GiB, 3,000 idle Cloudflare connections = 410 MiB
            // RSS. Pingora keeps an h1 connection open as long as the CLIENT
            // likes and Cloudflare holds idle origin connections ~15 min, so a
            // small box's RSS becomes the size of CF's pool, and past a unit's
            // MemoryHigh the kernel throttles the edge, past MemoryMax it is
            // killed. Small boxes close idle keep-alives; big ones keep them.
            keepalive_idle_secs: if ram < 2 << 30 {
                60
            } else if ram < 8 << 30 {
                120
            } else {
                0
            },
            // Half the RAM (a typical MemoryHigh) less ~128 MiB for the process and
            // its caches, at 128 KiB a connection: 1 GiB carries ~3,000.
            max_live_conns: ((ram / 2).saturating_sub(128 << 20) / (128 << 10)).clamp(1_024, 40_000)
                as usize,
            upstream_pool: ((ram_mib * 4).clamp(256, 8_192)) as usize,
            unit_limit_bytes: None,
        }
    }

    /// `from_ram`, then sized to the edge's own unit when it runs in one.
    ///
    /// A systemd unit may cap the edge well below the box's RAM (for example
    /// MemoryHigh at half of it). The RAM-only formulas read the whole box, so
    /// on a ~1 GB VM they would allow ~2,800 live connections AND an upstream
    /// pool of 3,844 idle TLS connections, which together outgrow a 480 MB
    /// unit: the kernel throttles the edge, its health probe times out, and a
    /// watchdog restarts it into the same flood. Inside a unit both come out of
    /// its limit: 60% of it (less 128 MiB for the process) for live
    /// connections, 25% for the upstream pool, at 128 KiB each. Past the cap
    /// the edge refuses new connections and keeps answering the ones it holds.
    fn from_limits(ram: u64, unit: Option<u64>) -> Self {
        let mut t = Self::from_ram(ram);
        if let Some(b) = unit.map(|u| u.min(ram)) {
            let spare = b.saturating_sub(128 << 20);
            t.max_live_conns = (spare / 5 * 3 / (128 << 10)).clamp(512, 40_000) as usize;
            t.upstream_pool = (spare / 4 / (128 << 10)).clamp(128, 8_192) as usize;
            if b < 768 << 20 && (t.keepalive_idle_secs == 0 || t.keepalive_idle_secs > 30) {
                t.keepalive_idle_secs = 30;
            }
            t.unit_limit_bytes = Some(b);
        }
        t
    }
}

fn per_entry_cap(body_cache_bytes: u64) -> usize {
    (body_cache_bytes / 32).clamp(128 << 10, 4 << 20) as usize
}

pub fn log_summary() {
    let t = &*TUNING;
    tracing::info!(
        "autotune: ram={} MiB, unit limit={} → body_cache={} MiB (≤{} KiB/entry), resolve_cache={} entries, abuse_cache={} IPs, keepalive_idle={} s, live_conns≤{}, upstream_pool={}",
        t.total_ram_bytes >> 20,
        t.unit_limit_bytes.map_or_else(|| "none".to_string(), |b| format!("{} MiB", b >> 20)),
        t.body_cache_bytes >> 20,
        t.max_cached_body >> 10,
        t.resolve_cache_entries,
        t.abuse_cache_entries,
        t.keepalive_idle_secs,
        t.max_live_conns,
        t.upstream_pool,
    );
}

/// Physical RAM, capped by the cgroup memory limit when present — inside a
/// container sysconf reports the HOST total, not what we're allowed to use.
fn effective_ram() -> u64 {
    let host = physical_ram().unwrap_or(1 << 30); // assume 1 GiB when unknown
    match cgroup_limit() {
        Some(limit) if limit < host => limit,
        _ => host,
    }
}

#[cfg(unix)]
fn physical_ram() -> Option<u64> {
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) };
    (pages > 0 && page > 0).then(|| pages as u64 * page as u64)
}

#[cfg(not(unix))]
fn physical_ram() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn cgroup_limit() -> Option<u64> {
    // cgroup v2 then v1. Unlimited shows as "max" (v2, fails parse) or an
    // absurdly large number (v1).
    for p in [
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ] {
        if let Ok(s) = std::fs::read_to_string(p) {
            if let Ok(v) = s.trim().parse::<u64>() {
                if v < (1 << 60) {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn cgroup_limit() -> Option<u64> {
    None
}

/// The limit of the systemd unit the edge runs in: its memory.high (where the
/// kernel starts throttling), else 85% of memory.max. None in the root cgroup
/// or a container's own namespace ("/"), where cgroup_limit already read it.
#[cfg(target_os = "linux")]
fn unit_limit() -> Option<u64> {
    let cg = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = cg.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    if path.is_empty() || path == "/" {
        return None;
    }
    let read = |file: &str| -> Option<u64> {
        let v = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/{file}"))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?;
        (v < (1 << 60)).then_some(v)
    };
    read("memory.high").or_else(|| read("memory.max").map(|m| m / 20 * 17))
}

#[cfg(not(target_os = "linux"))]
fn unit_limit() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_gib_matches_shipped_defaults() {
        let t = Tuning::from_ram(1 << 30);
        assert_eq!(t.body_cache_bytes, 16 << 20);
        assert_eq!(t.max_cached_body, 512 << 10);
        assert_eq!(t.resolve_cache_entries, 2_048);
        assert_eq!(t.abuse_cache_entries, 51_200);
        assert_eq!(t.keepalive_idle_secs, 60);
        assert_eq!(t.max_live_conns, 3_072);
    }

    /// A ~1 GB VM and the boxes above it: idle keep-alives close on small
    /// hosts only, and the connection ceiling never rises past the shipped
    /// 40,000.
    #[test]
    fn keepalive_and_connection_ceiling_follow_ram() {
        let small = Tuning::from_ram(957 << 20);
        assert_eq!(small.keepalive_idle_secs, 60);
        assert_eq!(small.max_live_conns, 2_804);
        assert_eq!(Tuning::from_ram(4 << 30).keepalive_idle_secs, 120);
        assert_eq!(Tuning::from_ram(4 << 30).max_live_conns, 15_360);
        let big = Tuning::from_ram(128 << 30);
        assert_eq!(
            big.keepalive_idle_secs, 0,
            "a big box keeps idle keep-alives open"
        );
        assert_eq!(big.max_live_conns, 40_000);
        assert_eq!(Tuning::from_ram(256 << 20).max_live_conns, 1_024);
    }

    /// A 961 MiB VM whose unit has MemoryHigh 480M. Live connections and the
    /// upstream pool both fit the unit, not the box; no unit leaves the RAM
    /// formulas exactly as they were.
    #[test]
    fn a_unit_limit_sizes_conns_and_pool() {
        let unit = Tuning::from_limits(961 << 20, Some(480 << 20));
        assert_eq!(unit.max_live_conns, 1_689);
        assert_eq!(unit.upstream_pool, 704);
        assert_eq!(unit.keepalive_idle_secs, 30);
        assert_eq!(unit.unit_limit_bytes, Some(480 << 20));
        // ~123 KiB per held connection, 128 KiB per pooled one, ~100 MiB of
        // process: under the 480 MiB the kernel throttles at.
        assert!(
            unit.max_live_conns as u64 * 123 + unit.upstream_pool as u64 * 128 + 100 * 1024
                < 480 * 1024
        );

        let bare = Tuning::from_ram(961 << 20);
        let none = Tuning::from_limits(961 << 20, None);
        assert_eq!(
            (
                none.max_live_conns,
                none.upstream_pool,
                none.keepalive_idle_secs
            ),
            (
                bare.max_live_conns,
                bare.upstream_pool,
                bare.keepalive_idle_secs
            )
        );
        assert_eq!(none.upstream_pool, 3_844);

        // A limit above the RAM is the RAM; a big unit keeps its longer idle.
        let big = Tuning::from_limits(4 << 30, Some(8 << 30));
        assert_eq!(big.unit_limit_bytes, Some(4 << 30));
        assert_eq!(big.keepalive_idle_secs, 120);
        assert_eq!(
            Tuning::from_limits(256 << 20, Some(200 << 20)).max_live_conns,
            512
        );
    }

    #[test]
    fn clamps_hold_at_extremes() {
        let small = Tuning::from_ram(256 << 20);
        assert_eq!(small.body_cache_bytes, 8 << 20);
        assert_eq!(small.max_cached_body, 256 << 10);
        assert_eq!(small.resolve_cache_entries, 512);
        assert_eq!(small.abuse_cache_entries, 12_800);

        let big = Tuning::from_ram(64 << 30);
        assert_eq!(big.body_cache_bytes, 256 << 20);
        assert_eq!(big.max_cached_body, 4 << 20);
        assert_eq!(big.resolve_cache_entries, 32_768);
        // Proportional now, not pinned to the old flat 1,000,000 cap.
        assert_eq!(big.abuse_cache_entries, 3_276_800);
    }

    /// A large box. Locks in what it gets, so a future tweak to the
    /// multiplier or the ceiling cannot silently shrink it.
    #[test]
    fn large_128gib_sizing() {
        let t = Tuning::from_ram(128 << 30);
        assert_eq!(t.abuse_cache_entries, 6_553_600);
        // Seven caches at ~200 B/entry — comfortably inside the 25 GB budget.
        assert!(7 * t.abuse_cache_entries * 200 < 25 * (1 << 30));
    }

    /// The ceiling still exists, and still binds somewhere absurd.
    #[test]
    fn abuse_cache_ceiling_still_holds() {
        let huge = Tuning::from_ram(1024 << 30); // 1 TiB
        assert_eq!(huge.abuse_cache_entries, 16_000_000);
    }

    #[test]
    fn detection_returns_something_sane() {
        // Any real host has more than 64 MiB.
        assert!(effective_ram() >= 64 << 20);
    }
}
