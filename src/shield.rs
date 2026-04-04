use std::{net::IpAddr, time::Duration};

use anyhow::Result;
use ipnet::{Ipv4Net, Ipv6Net};

#[allow(unused_imports)]
use tracing::{info, warn};

use crate::config::SecurityConfig;

use arc_swap::ArcSwap;
use iprange::IpRange;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub static VERIFIED_CRAWLERS_V4: Lazy<ArcSwap<IpRange<Ipv4Net>>> =
    Lazy::new(|| ArcSwap::from_pointee(IpRange::new()));
pub static VERIFIED_CRAWLERS_V6: Lazy<ArcSwap<IpRange<Ipv6Net>>> =
    Lazy::new(|| ArcSwap::from_pointee(IpRange::new()));

#[derive(Deserialize)]
struct CrawlerJson {
    prefixes: Vec<CrawlerPrefix>,
}

#[derive(Deserialize)]
struct CrawlerPrefix {
    #[serde(rename = "ipv4Prefix")]
    ipv4: Option<String>,
    #[serde(rename = "ipv6Prefix")]
    ipv6: Option<String>,
}

// Every publisher with a machine-readable list: the search engines plus
// the AI assistants' search and user-triggered fetchers. Training crawlers
// publish lists too and are deliberately not here: knowing an address is
// theirs is no reason to exempt it.
const GOOGLE_COMMON_URL: &str =
    "https://developers.google.com/static/crawling/ipranges/common-crawlers.json";
const GOOGLE_FETCHERS_URL: &str =
    "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json";
const CRAWLER_URLS: &[&str] = &[
    GOOGLE_COMMON_URL,
    "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
    GOOGLE_FETCHERS_URL,
    "https://www.bing.com/toolbox/bingbot.json",
    "https://search.developer.apple.com/applebot.json",
    "https://duckduckgo.com/duckduckbot.json",
    "https://openai.com/searchbot.json",
    "https://openai.com/chatgpt-user.json",
    "https://www.perplexity.ai/perplexitybot.json",
];

// Googlebot's long-standing pool: a floor only while Google's common list is absent.
const BAKED_CRAWLER_V4: &[&str] = &["66.249.64.0/19"];
const BAKED_CRAWLER_V6: &[&str] = &["2001:4860:4801::/48"];

const CRAWLER_ENTRY_MAX_AGE_SECS: u64 = 30 * 86400;

#[derive(Serialize, Deserialize, Clone)]
struct CrawlerEntry {
    v4: Vec<String>,
    v6: Vec<String>,
    fetched_at: u64,
}

// Last good parse per list URL. The live set is the union, so one list
// failing a cycle never drops its prefixes.
static CRAWLER_LISTS: Lazy<Mutex<HashMap<String, CrawlerEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Google's own list is in the union; until then block_kind fails open.
static GOOGLE_COMMON: AtomicBool = AtomicBool::new(false);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn init_crawler_updater(cfg: &crate::config::ProxyConfig) {
    let cache = crate::blocklist::cache_path("", &cfg.acme.storage, "crawler-ranges-cache.json");

    // 1. Start from the last good set; boot waits for a fetch only without Google's list.
    if !cache.is_empty() {
        load_crawler_cache(&cache).await;
    }
    let first = if GOOGLE_COMMON.load(Ordering::Relaxed) {
        None
    } else {
        Some(update_crawlers(&cache).await)
    };

    // 2. Retry soon while a list has never loaded, otherwise every 6 hours.
    tokio::spawn(async move {
        let mut retry_soon = match first {
            Some(r) => r,
            None => update_crawlers(&cache).await,
        };
        loop {
            let wait = if retry_soon { 600 } else { 6 * 3600 };
            tokio::time::sleep(Duration::from_secs(wait)).await;
            retry_soon = update_crawlers(&cache).await;
        }
    });
}

async fn load_crawler_cache(path: &str) {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warn!("crawler ranges: cache {} unreadable: {}", path, e);
            return;
        }
    };
    match serde_json::from_slice::<HashMap<String, CrawlerEntry>>(&bytes) {
        Ok(lists) => {
            let n = lists.len();
            CRAWLER_LISTS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(lists);
            if let Some((active, _, _)) = publish_crawlers().await {
                info!(
                    "crawler ranges: {} list(s) loaded from cache {} ({} subnets active)",
                    n, path, active
                );
            }
        }
        Err(e) => warn!("crawler ranges: cache {} did not parse: {}", path, e),
    }
}

fn parse_crawler_list(raw: &str) -> Result<CrawlerEntry> {
    let data = serde_json::from_str::<CrawlerJson>(raw)?;
    let mut entry = CrawlerEntry {
        v4: Vec::new(),
        v6: Vec::new(),
        fetched_at: unix_now(),
    };
    for p in data.prefixes {
        if let Some(v4) = p.ipv4.filter(|s| s.parse::<Ipv4Net>().is_ok()) {
            entry.v4.push(v4);
        }
        if let Some(v6) = p.ipv6.filter(|s| s.parse::<Ipv6Net>().is_ok()) {
            entry.v6.push(v6);
        }
    }
    Ok(entry)
}

/// One refresh cycle. Returns whether to retry soon: some list has no last
/// good entry, or Google's common list is not in the live set.
async fn update_crawlers(cache: &str) -> bool {
    let mut fresh = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for &url in CRAWLER_URLS {
        match fetch_url(url).await {
            Ok(raw) => match parse_crawler_list(&raw) {
                Ok(entry) if !entry.v4.is_empty() || !entry.v6.is_empty() => {
                    fresh.push((url, entry))
                }
                Ok(_) => failures.push(format!("{} (no prefixes)", url)),
                Err(e) => failures.push(format!("{} (parse: {})", url, e)),
            },
            // Logged, because a host without CA certs never loads a range, and
            // every gate that exempts verified crawlers then exempts nobody.
            Err(e) => failures.push(format!("{} ({})", url, e)),
        }
    }
    let failed = failures.len();
    if failed > 0 {
        warn!(
            "crawler ranges: {} list(s) failed, last good kept: {}",
            failed,
            failures.join("; ")
        );
    }

    let refreshed = !fresh.is_empty();
    {
        let mut lists = CRAWLER_LISTS.lock().unwrap_or_else(|e| e.into_inner());
        for (url, entry) in fresh {
            lists.insert(url.to_string(), entry);
        }
    }

    let retry_soon = || {
        let lists = CRAWLER_LISTS.lock().unwrap_or_else(|e| e.into_inner());
        CRAWLER_URLS.iter().any(|u| !lists.contains_key(*u))
            || !GOOGLE_COMMON.load(Ordering::Relaxed)
    };
    let Some((v4_count, union, pruned)) = publish_crawlers().await else {
        return retry_soon();
    };
    tracing::info!(
        "Updated verified crawlers: {} subnets active (union of {} list(s), {} URL(s) failed).",
        v4_count,
        union,
        failed
    );
    if (refreshed || pruned) && !cache.is_empty() {
        if let Err(e) = write_crawler_cache(cache).await {
            warn!("crawler ranges: cache write to {} failed: {}", cache, e);
        }
    }
    retry_soon()
}

/// Prune stale lists and swap in the union (plus the baked pool without Google's list). Returns
/// (v4 subnets active, lists in the union, whether any list was pruned).
async fn publish_crawlers() -> Option<(usize, usize, bool)> {
    let (v4_strings, v6_strings, union, pruned, has_google) = {
        let mut lists = CRAWLER_LISTS.lock().unwrap_or_else(|e| e.into_inner());
        let before = lists.len();
        let now = unix_now();
        lists.retain(|_, e| now.saturating_sub(e.fetched_at) <= CRAWLER_ENTRY_MAX_AGE_SECS);
        let v4: Vec<String> = lists.values().flat_map(|e| e.v4.iter().cloned()).collect();
        let v6: Vec<String> = lists.values().flat_map(|e| e.v6.iter().cloned()).collect();
        (
            v4,
            v6,
            lists.len(),
            lists.len() != before,
            lists.contains_key(GOOGLE_COMMON_URL),
        )
    };

    let joined = tokio::task::spawn_blocking(move || {
        let mut v4 = IpRange::<Ipv4Net>::new();
        let mut v6 = IpRange::<Ipv6Net>::new();
        let (baked4, baked6) = if has_google {
            (&[][..], &[][..])
        } else {
            (BAKED_CRAWLER_V4, BAKED_CRAWLER_V6)
        };

        for ip_str in v4_strings
            .iter()
            .map(String::as_str)
            .chain(baked4.iter().copied())
        {
            if let Ok(net) = ip_str.parse::<Ipv4Net>() {
                v4.add(net);
            }
        }
        for ip_str in v6_strings
            .iter()
            .map(String::as_str)
            .chain(baked6.iter().copied())
        {
            if let Ok(net) = ip_str.parse::<Ipv6Net>() {
                v6.add(net);
            }
        }

        v4.simplify();
        v6.simplify();

        (v4, v6)
    })
    .await;

    // Don't `.expect()` — a JoinError must not crash the boot path or silently kill
    // the updater loop. Skip this cycle and keep the current ranges.
    let (v4_range, v6_range) = match joined {
        Ok(ranges) => ranges,
        Err(e) => {
            tracing::warn!(
                "crawler range rebuild failed ({}) — keeping current ranges",
                e
            );
            return None;
        }
    };

    let v4_count = v4_range.iter().count();
    VERIFIED_CRAWLERS_V4.store(Arc::new(v4_range));
    VERIFIED_CRAWLERS_V6.store(Arc::new(v6_range));
    GOOGLE_COMMON.store(has_google, Ordering::Relaxed);
    Some((v4_count, union, pruned))
}

async fn write_crawler_cache(path: &str) -> Result<()> {
    let bytes = {
        let lists = CRAWLER_LISTS.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::to_vec(&*lists)?
    };
    let tmp = format!("{}.tmp", path);
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

/// Test-only: seed the verified-crawler set so the pre-filter's exemption can
/// be exercised without a live fetch.
#[cfg(test)]
pub fn set_verified_crawlers_for_test(v4: IpRange<Ipv4Net>) {
    VERIFIED_CRAWLERS_V4.store(Arc::new(v4));
}

/// Whether Google's own published list is in the set. The blocklist refuses
/// nobody until it is — otherwise Googlebot looks like any Google Cloud host.
pub fn verified_crawlers_loaded() -> bool {
    GOOGLE_COMMON.load(Ordering::Relaxed)
}

pub fn verified_crawler_count() -> usize {
    VERIFIED_CRAWLERS_V4.load().iter().count() + VERIFIED_CRAWLERS_V6.load().iter().count()
}

pub fn is_verified_crawler(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => VERIFIED_CRAWLERS_V4.load().contains(ipv4),
        IpAddr::V6(ipv6) => VERIFIED_CRAWLERS_V6.load().contains(ipv6),
    }
}

// Prefix tries, not a Vec scan — is_cloudflare_ip runs 2-3× per request.
//
// ArcSwap, not OnceCell: the set was previously written once at boot and never
// again. Two ways that rotted on a long-lived process — (1) a network blip during
// container start fell back to the compiled-in snapshot and stayed there forever,
// (2) when Cloudflare adds a range, `cloudflare_only` routes answer 403 "non-cf-ip"
// to that whole range until someone restarts the proxy. Refreshed every 12h now,
// same cadence as the verified-crawler list.
type CfRanges = Option<(IpRange<Ipv4Net>, IpRange<Ipv6Net>)>;
static CF_RANGES: Lazy<ArcSwap<CfRanges>> = Lazy::new(|| ArcSwap::from_pointee(None));

/// Parse the two CF list bodies into prefix tries. Returns None if they yielded
/// no usable prefixes at all (a captive portal / error page rather than a list).
fn parse_cf_ranges(v4: &str, v6: &str) -> Option<(IpRange<Ipv4Net>, IpRange<Ipv6Net>, usize)> {
    let mut r4 = IpRange::<Ipv4Net>::new();
    let mut r6 = IpRange::<Ipv6Net>::new();
    let mut count = 0usize;
    for line in v4.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Ok(net) = line.parse::<Ipv4Net>() {
            r4.add(net);
            count += 1;
        }
    }
    for line in v6.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if let Ok(net) = line.parse::<Ipv6Net>() {
            r6.add(net);
            count += 1;
        }
    }
    if count == 0 {
        return None;
    }
    r4.simplify();
    r6.simplify();
    Some((r4, r6, count))
}

pub async fn init_cloudflare_ranges() -> Result<()> {
    let mut used_snapshot = false;
    let v4 = fetch_url("https://www.cloudflare.com/ips-v4")
        .await
        .unwrap_or_else(|e| {
            warn!("CF IPv4 fetch failed ({}), using built-in snapshot", e);
            used_snapshot = true;
            CF_IPV4_SNAPSHOT.to_string()
        });
    let v6 = fetch_url("https://www.cloudflare.com/ips-v6")
        .await
        .unwrap_or_else(|e| {
            warn!("CF IPv6 fetch failed ({}), using built-in snapshot", e);
            used_snapshot = true;
            CF_IPV6_SNAPSHOT.to_string()
        });

    match parse_cf_ranges(&v4, &v6) {
        Some((r4, r6, count)) => {
            info!(
                "Loaded {} Cloudflare IP ranges{}",
                count,
                if used_snapshot { " (from built-in snapshot — will retry in 12h)" } else { "" }
            );
            CF_RANGES.store(Arc::new(Some((r4, r6))));
        }
        None => warn!("CF range load produced no usable prefixes — cloudflare_only routes will reject everything"),
    }
    Ok(())
}

/// Set once the 12-hourly updater runs: boot and a reload that newly needs ranges share one.
static CF_UPDATER: AtomicBool = AtomicBool::new(false);

/// Ranges loaded (fetch, else the compiled-in snapshot) and the updater running. For a
/// config that newly needs them; a no-op when both already hold. Needs a runtime.
pub async fn ensure_cf_ranges() {
    if CF_RANGES.load().is_none() {
        if let Err(e) = init_cloudflare_ranges().await {
            tracing::error!("CF range init failed: {} (built-in snapshot used)", e);
        }
    }
    spawn_cf_range_updater();
}

/// Re-fetch the CF ranges every 12 hours. Only swaps on a GOOD fetch, so a
/// transient failure keeps the last known-good set rather than degrading to the
/// compiled-in snapshot. Started at most once.
pub fn spawn_cf_range_updater() {
    if CF_UPDATER.swap(true, Ordering::Relaxed) {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(12 * 3600)).await;

            let (Ok(v4), Ok(v6)) = (
                fetch_url("https://www.cloudflare.com/ips-v4").await,
                fetch_url("https://www.cloudflare.com/ips-v6").await,
            ) else {
                warn!("CF range refresh failed — keeping the current set");
                continue;
            };

            match parse_cf_ranges(&v4, &v6) {
                Some((r4, r6, count)) => {
                    CF_RANGES.store(Arc::new(Some((r4, r6))));
                    info!("CF IP ranges refreshed ({} prefixes)", count);
                }
                None => {
                    warn!("CF range refresh returned no usable prefixes — keeping the current set")
                }
            }
        }
    });
}

async fn fetch_url(url: &str) -> Result<String> {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::{Bytes, Incoming};
    use hyper::{Request, Response};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()?
        .https_only()
        .enable_http1()
        .build();

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let req = Request::get(url)
        .header(
            "User-Agent",
            concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION"),
                " range-fetch"
            ),
        )
        .body(Empty::<Bytes>::new())?;

    // The body read sits inside the timeout too: a stalled body hung the updater forever.
    let bytes = tokio::time::timeout(Duration::from_secs(10), async {
        // Fix E0282: Strictly annotate the nested HTTP Response type
        let resp: Response<Incoming> = client.request(req).await?;
        if !resp.status().is_success() {
            anyhow::bail!("HTTP {}", resp.status().as_u16());
        }
        // Fix E0282: Break the method chain to help the compiler infer the Collected<Bytes> trait
        let collected = resp.into_body().collect().await?;
        Ok::<Bytes, anyhow::Error>(collected.to_bytes())
    })
    .await
    .map_err(|_| anyhow::anyhow!("CF range fetch timed out"))??;

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[inline]
pub fn is_cloudflare_ip(ip: IpAddr) -> bool {
    // Fail-closed: blocks all non-CF traffic if ranges never loaded.
    let guard = CF_RANGES.load();
    match (guard.as_ref(), ip) {
        (Some((v4, _)), IpAddr::V4(ip)) => v4.contains(&ip),
        (Some((_, v6)), IpAddr::V6(ip)) => v6.contains(&ip),
        _ => false,
    }
}

// ── Operator blocklists (AI/SEO crawler fence) ────────────────────────────────

/// True when the User-Agent matches any operator-blocked substring.
/// Patterns were lowered at config load; the scan allocates nothing.
#[inline]
pub fn ua_blocked(cfg: &SecurityConfig, ua: &[u8]) -> bool {
    cfg.compiled_ua_blocks
        .iter()
        .any(|p| contains_ignore_case(ua, p))
}

/// True when the IP falls in any operator-blocked network.
#[inline]
pub fn ip_blocked(cfg: &SecurityConfig, ip: &std::net::IpAddr) -> bool {
    cfg.blocked_ip_nets.iter().any(|n| n.contains(ip))
}

// ── Header-level WAF checks ───────────────────────────────────────────────────

pub fn check_headers(
    headers: &pingora_http::HMap,
    ua_present: bool,
    cfg: &SecurityConfig,
) -> Option<&'static str> {
    if cfg.block_empty_user_agent && !ua_present {
        return Some("missing-user-agent");
    }

    if cfg.reject_header_injection {
        for (_, v) in headers.iter() {
            let b = v.as_bytes();
            if b.contains(&b'\r') || b.contains(&b'\n') || b.contains(&0u8) {
                return Some("header-injection");
            }
        }
    }

    if cfg.reject_invalid_content_length {
        let has_cl = headers.contains_key("content-length");
        let has_te = headers
            .get("transfer-encoding")
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.trim().eq_ignore_ascii_case("identity"))
            .unwrap_or(false);
        if has_cl && has_te {
            return Some("cl-te-smuggling");
        }
    }

    // 0-ALLOCATION HEADER SCAN FIX
    if !cfg.compiled_patterns.is_empty() {
        for (k, v) in headers.iter() {
            let k_bytes = k.as_str().as_bytes();
            let v_bytes = v.as_bytes();

            for pattern in &cfg.compiled_patterns {
                if contains_ignore_case(k_bytes, pattern) || contains_ignore_case(v_bytes, pattern)
                {
                    return Some("blocked-pattern");
                }
            }
        }
    }

    None
}

/// Case-insensitive byte search; `needle` must already be lowercase.
#[inline(always)]
pub(crate) fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

const CF_IPV4_SNAPSHOT: &str = "\
173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n\
141.101.64.0/18\n108.162.192.0/18\n190.93.240.0/20\n188.114.96.0/20\n\
197.234.240.0/22\n198.41.128.0/17\n162.158.0.0/15\n104.16.0.0/13\n\
104.24.0.0/14\n172.64.0.0/13\n131.0.72.0/22";

const CF_IPV6_SNAPSHOT: &str = "\
2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n\
2405:8100::/32\n2a06:98c0::/29\n2c0f:f248::/32";
