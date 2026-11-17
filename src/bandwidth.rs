//! bandwidth.rs — bytes sent per route by UTC day and month,
//! kept across restarts in `<acme.storage>/bandwidth.json`.
//!
//! Hot path: `record()` bumps three atomics behind a by-&str lookup; a String
//! is only built the first time a route is seen. Route names come from the
//! config (plus "on-demand" and "-"), so the key set cannot be grown by traffic.
//! A flusher folds the counters into the day/month history every FLUSH_SECS;
//! a crash loses at most that much.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use moka::sync::Cache;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tracing::warn;

const FLUSH_SECS: u64 = 120;
const KEEP_DAYS: u32 = 120;
const KEEP_MONTHS: usize = 24;
const DAY: u64 = 86_400;

/// [bytes out, bytes in, requests]
type Tally = [u64; 3];

#[derive(Default)]
struct Pending {
    out: AtomicU64,
    inb: AtomicU64,
    req: AtomicU64,
}

static PENDING: Lazy<Cache<String, Arc<Pending>>> =
    Lazy::new(|| Cache::builder().max_capacity(512).build());

#[derive(Default, Serialize, Deserialize)]
struct Doc {
    /// Unix secs recording began; estimates divide by the time actually covered.
    #[serde(default)]
    since: u64,
    /// Day number (unix secs / 86400, UTC) → route → tally.
    #[serde(default)]
    days: BTreeMap<u32, BTreeMap<String, Tally>>,
    /// yyyymm (UTC) → route → tally.
    #[serde(default)]
    months: BTreeMap<u32, BTreeMap<String, Tally>>,
}

static HIST: Lazy<Mutex<Doc>> = Lazy::new(|| Mutex::new(Doc::default()));
static WRITE_FAILING: AtomicBool = AtomicBool::new(false);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hist() -> MutexGuard<'static, Doc> {
    HIST.lock().unwrap_or_else(|e| e.into_inner())
}

#[inline]
pub fn record(route: &str, out: u64, inb: u64) {
    let p = match PENDING.get(route) {
        Some(p) => p,
        None => PENDING.get_with(route.to_string(), || Arc::new(Pending::default())),
    };
    p.out.fetch_add(out, Ordering::Relaxed);
    p.inb.fetch_add(inb, Ordering::Relaxed);
    p.req.fetch_add(1, Ordering::Relaxed);
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (H. Hinnant).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 31,
    }
}

fn month_key(day: u32) -> u32 {
    let (y, m, _) = civil(i64::from(day));
    (y as u32) * 100 + m
}

fn prev_month_key(mk: u32) -> u32 {
    if mk % 100 == 1 {
        (mk / 100 - 1) * 100 + 12
    } else {
        mk - 1
    }
}

fn add(t: &mut Tally, c: Tally) {
    for (a, b) in t.iter_mut().zip(c) {
        *a = a.saturating_add(b);
    }
}

fn fold_into(doc: &mut Doc, day: u32, route: &str, c: Tally) {
    add(
        doc.days
            .entry(day)
            .or_default()
            .entry(route.to_string())
            .or_default(),
        c,
    );
    add(
        doc.months
            .entry(month_key(day))
            .or_default()
            .entry(route.to_string())
            .or_default(),
        c,
    );
}

fn prune(doc: &mut Doc, today: u32) {
    doc.days = doc.days.split_off(&today.saturating_sub(KEEP_DAYS));
    while doc.months.len() > KEEP_MONTHS {
        doc.months.pop_first();
    }
}

fn fold(doc: &mut Doc, now: u64) {
    let day = (now / DAY) as u32;
    for (k, p) in PENDING.iter() {
        let c = [
            p.out.swap(0, Ordering::Relaxed),
            p.inb.swap(0, Ordering::Relaxed),
            p.req.swap(0, Ordering::Relaxed),
        ];
        if c != [0; 3] {
            fold_into(doc, day, k.as_str(), c);
        }
    }
    if doc.since == 0 {
        doc.since = now;
    }
    prune(doc, day);
}

async fn write(path: &str, bytes: Vec<u8>) {
    let tmp = format!("{}.tmp", path);
    let res = match tokio::fs::write(&tmp, bytes).await {
        Ok(()) => tokio::fs::rename(&tmp, path).await,
        Err(e) => Err(e),
    };
    match res {
        Ok(()) => {
            WRITE_FAILING.store(false, Ordering::Relaxed);
        }
        Err(e) => {
            if !WRITE_FAILING.swap(true, Ordering::Relaxed) {
                warn!(
                    "bandwidth: could not write {}: {} (history stays in memory)",
                    path, e
                );
            }
        }
    }
}

/// Loads the saved history and folds the live counters into it every FLUSH_SECS.
pub fn spawn(storage: &str) {
    let path = crate::blocklist::cache_path("", storage, "bandwidth.json");
    tokio::spawn(async move {
        if !path.is_empty() {
            match tokio::fs::read(&path).await {
                Ok(b) => match serde_json::from_slice::<Doc>(&b) {
                    Ok(d) => *hist() = d,
                    Err(e) => warn!("bandwidth: {} unreadable, starting fresh: {}", path, e),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("bandwidth: could not read {}: {}", path, e),
            }
        }
        {
            let mut h = hist();
            if h.since == 0 {
                h.since = now_secs();
            }
        }
        let mut tick = tokio::time::interval(Duration::from_secs(FLUSH_SECS));
        tick.tick().await;
        loop {
            tick.tick().await;
            let bytes = {
                let mut h = hist();
                fold(&mut h, now_secs());
                serde_json::to_vec(&*h).ok()
            };
            if let (false, Some(b)) = (path.is_empty(), bytes) {
                write(&path, b).await;
            }
        }
    });
}

fn ymd(day: u32) -> String {
    let (y, m, d) = civil(i64::from(day));
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn ym(mk: u32) -> String {
    format!("{:04}-{:02}", mk / 100, mk % 100)
}

fn tally_json(t: Tally) -> serde_json::Value {
    serde_json::json!({ "out": t[0], "in": t[1], "req": t[2] })
}

/// GET /api/bandwidth — per route: today, 7 and 30 days, this and last month,
/// a 30-day daily series and a 30-day estimate; plus 12 months of totals.
pub fn json(routes: &[crate::config::RouteConfig]) -> String {
    let now = now_secs();
    let today = (now / DAY) as u32;
    let (y, m, dom) = civil(i64::from(today));
    let mk = month_key(today);
    let pmk = prev_month_key(mk);
    let first = today.saturating_sub(29);

    let pend: BTreeMap<String, Tally> = PENDING
        .iter()
        .map(|(k, p)| {
            (
                (*k).clone(),
                [
                    p.out.load(Ordering::Relaxed),
                    p.inb.load(Ordering::Relaxed),
                    p.req.load(Ordering::Relaxed),
                ],
            )
        })
        .collect();
    let h = hist();

    let mut keys: BTreeSet<&str> = pend.keys().map(String::as_str).collect();
    for (_, per) in h.days.range(first..=today) {
        keys.extend(per.keys().map(String::as_str));
    }
    for k in [mk, pmk] {
        if let Some(per) = h.months.get(&k) {
            keys.extend(per.keys().map(String::as_str));
        }
    }

    let since = if h.since == 0 { now } else { h.since };
    let covered = now
        .saturating_sub(since.max(now.saturating_sub(30 * DAY)))
        .max(1);
    let get = |map: Option<&BTreeMap<String, Tally>>, k: &str| -> Tally {
        map.and_then(|per| per.get(k)).copied().unwrap_or_default()
    };

    let mut total = [[0u64; 3]; 5];
    let mut total_daily = vec![0u64; 30];
    let mut rows: Vec<(u64, serde_json::Value)> = keys
        .iter()
        .map(|&k| {
            let live = pend.get(k).copied().unwrap_or_default();
            let mut sums = [[0u64; 3]; 5];
            let mut daily = vec![0u64; 30];
            for (d, per) in h.days.range(first..=today) {
                let t = get(Some(per), k);
                daily[(d - first) as usize] = t[0];
                add(&mut sums[2], t);
                if *d + 6 >= today {
                    add(&mut sums[1], t);
                }
                if *d == today {
                    add(&mut sums[0], t);
                }
            }
            daily[29] = daily[29].saturating_add(live[0]);
            add(&mut sums[0], live);
            add(&mut sums[1], live);
            add(&mut sums[2], live);
            sums[3] = get(h.months.get(&mk), k);
            add(&mut sums[3], live);
            sums[4] = get(h.months.get(&pmk), k);
            for (t, s) in total.iter_mut().zip(sums) {
                add(t, s);
            }
            for (i, v) in daily.iter().enumerate() {
                total_daily[i] = total_daily[i].saturating_add(*v);
            }
            let rc = routes.iter().find(|r| r.name == k);
            let est = (sums[2][0] as f64 * (30 * DAY) as f64 / covered as f64) as u64;
            (sums[2][0], serde_json::json!({
                "route": k,
                "upstream": rc.map(|r| r.upstream.as_str()).unwrap_or(""),
                "hosts": rc.map(|r| r.hosts.iter().take(3).cloned().collect::<Vec<_>>()).unwrap_or_default(),
                "today": tally_json(sums[0]),
                "d7": tally_json(sums[1]),
                "d30": tally_json(sums[2]),
                "month": tally_json(sums[3]),
                "prev_month": tally_json(sums[4]),
                "est30": est,
                "daily": daily,
            }))
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.0));

    let months: Vec<serde_json::Value> = h
        .months
        .iter()
        .rev()
        .take(12)
        .map(|(k, per)| {
            let mut t = [0u64; 3];
            let mut by: Vec<(&String, u64)> = per.iter().map(|(r, v)| (r, v[0])).collect();
            by.sort_by_key(|r| std::cmp::Reverse(r.1));
            for v in per.values() {
                add(&mut t, *v);
            }
            if *k == mk {
                for v in pend.values() {
                    add(&mut t, *v);
                }
            }
            serde_json::json!({
                "month": ym(*k),
                "total": tally_json(t),
                "by": by.into_iter().map(|(r, o)| serde_json::json!([r, o])).collect::<Vec<_>>(),
            })
        })
        .collect();

    serde_json::json!({
        "tz": "UTC",
        "today": ymd(today),
        "month": ym(mk),
        "prev_month": ym(pmk),
        "day_of_month": dom,
        "days_in_month": days_in_month(y, m),
        "since": since,
        "covered_secs": covered,
        "now": now,
        "first_day": ymd(first),
        "routes": rows.into_iter().map(|r| r.1).collect::<Vec<_>>(),
        "total": {
            "today": tally_json(total[0]),
            "d7": tally_json(total[1]),
            "d30": tally_json(total[2]),
            "month": tally_json(total[3]),
            "prev_month": tally_json(total[4]),
            "est30": (total[2][0] as f64 * (30 * DAY) as f64 / covered as f64) as u64,
            "daily": total_daily,
        },
        "months": months,
    })
    .to_string()
}
