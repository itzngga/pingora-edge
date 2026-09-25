//! Config at runtime: the boot loader (last-good fallback on FATAL only) and the one worker
//! that re-reads, verifies and applies the file on SIGHUP, a file change or a control call.
//! A file is applied whole or not at all; anything off the HOT table waits for a restart.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};
use tracing::{error, info, warn};

use crate::check::{self, CheckOpts, Issue, Plan, Sev};
use crate::config::{ProxyConfig, RouteConfig};
use crate::host_list::HostList;
use crate::on_demand::OnDemandResolver;
use crate::proxy::{GatewayHandle, Live};
use crate::route_ids::RouteIds;
use crate::tls_sni::{CertRegistry, Prepared};
use crate::watch_state::{self as ws, Next, Stamp, Verdict, WatchState};
use crate::BootCaptured;

/// A control reload answers 504 after this; the evaluation itself goes on.
const CONTROL_WAIT: Duration = Duration::from_secs(55);
const HUP_POLL: Duration = Duration::from_millis(250);
const SELF_RESTART_GAP: Duration = Duration::from_secs(60);
const PENDING_REMINDER: Duration = Duration::from_secs(600);
const RECHECK: Duration = Duration::from_secs(60);
/// POST /config/verify body cap.
pub const VERIFY_MAX: usize = 1 << 20;

// ── SIGHUP ────────────────────────────────────────────────────────────────────

static HUP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_hup(_: libc::c_int) {
    HUP.store(true, Ordering::Relaxed);
}

/// The first statement of main: from here a HUP is a flag the worker polls, never the default kill.
pub fn install_sighup() {
    // SAFETY: `sa` is fully initialised; the handler only stores to an atomic (async-signal-safe).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_hup as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGHUP, &sa, std::ptr::null_mut());
    }
}

fn supervised() -> bool {
    std::env::var_os("INVOCATION_ID").is_some_and(|v| !v.is_empty())
        || std::env::var("PROXY_SUPERVISED").is_ok_and(|v| v.trim() == "1")
}

// ── Status ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Source {
    #[default]
    Boot,
    Watch,
    Hup,
    Control,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Boot => "boot",
            Source::Watch => "watch",
            Source::Hup => "hup",
            Source::Control => "control",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Res {
    Applied,
    Unchanged,
    Rejected,
    RestartRequired,
    ShaMismatch,
}

const RESULTS: [Res; 5] = [
    Res::Applied,
    Res::Unchanged,
    Res::Rejected,
    Res::RestartRequired,
    Res::ShaMismatch,
];
static RELOADS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

impl Res {
    fn as_str(self) -> &'static str {
        match self {
            Res::Applied => "applied",
            Res::Unchanged => "unchanged",
            Res::Rejected => "rejected",
            Res::RestartRequired => "restart_required",
            Res::ShaMismatch => "sha_mismatch",
        }
    }

    fn http(self) -> u16 {
        match self {
            Res::Applied | Res::Unchanged => 200,
            Res::RestartRequired => 409,
            Res::ShaMismatch => 412,
            Res::Rejected => 422,
        }
    }

    fn count(self) {
        if let Some(c) = RESULTS
            .iter()
            .position(|r| *r == self)
            .and_then(|i| RELOADS.get(i))
        {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
struct Pending {
    sha: [u8; 32],
    since: DateTime<Utc>,
    keys: Vec<String>,
}

#[derive(Clone)]
struct Attempt {
    at: DateTime<Utc>,
    source: Source,
    sha: [u8; 32],
    res: Res,
    ms: u64,
    errors: usize,
    warnings: usize,
    issues: Vec<Issue>,
    restart_keys: Vec<String>,
}

/// Written only by the worker (and once by Reloader::new).
#[derive(Clone, Default)]
struct Status {
    generation: u64,
    applied_sha: [u8; 32],
    applied_at: DateTime<Utc>,
    applied_source: Source,
    applied_last_good: bool,
    boot_at: DateTime<Utc>,
    boot_last_good: bool,
    /// The configured file's fatal/error/warning issues at boot.
    boot_issues: Vec<Issue>,
    boot_error: bool,
    degraded: Vec<String>,
    pending: Option<Pending>,
    last_attempt: Option<Attempt>,
    last_rejected: Option<[u8; 32]>,
    acme_desired: usize,
    acme_uncovered: usize,
    last_success: DateTime<Utc>,
}

struct Meta {
    path: String,
    watch_secs: u64,
    last_good: Option<PathBuf>,
}

static STATUS: ArcSwapOption<Status> = ArcSwapOption::const_empty();
static META: OnceLock<Meta> = OnceLock::new();
static BINARY_SHA: OnceLock<String> = OnceLock::new();
/// (stat, sha) of the config file as last hashed: the disk side of in_sync.
static DISK: Mutex<Option<(Stamp, [u8; 32])>> = Mutex::new(None);

fn current() -> Arc<Status> {
    STATUS.load_full().unwrap_or_default()
}

fn hex(sha: [u8; 32]) -> String {
    check::hex(&sha)
}

fn short(sha: [u8; 32]) -> String {
    hex(sha).chars().take(12).collect()
}

fn ts(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn issues_json(v: &[Issue]) -> Vec<Value> {
    v.iter().map(Issue::to_json).collect()
}

fn read_capped(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(path)?
        .take((check::MAX_BYTES as u64).saturating_add(1))
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Stat (taken first, so a write during the read shows as a moved stat), bytes and their sha.
fn read_hashed(path: &Path) -> std::io::Result<(Option<Stamp>, Vec<u8>, [u8; 32])> {
    let stamp = Stamp::stat(path);
    let raw = read_capped(path)?;
    let sha = check::sha256(&raw);
    Ok((stamp, raw, sha))
}

fn note_disk(stamp: Option<Stamp>, sha: [u8; 32]) {
    if let Some(s) = stamp {
        *DISK.lock().unwrap_or_else(PoisonError::into_inner) = Some((s, sha));
    }
}

/// The file vanished or could not be read: nothing on disk is known to be in sync.
fn forget_disk() {
    *DISK.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

/// The memo only, no I/O: for the handlers on the runtime. The worker keeps it current
/// (every watcher read, every evaluation, the minute recheck).
fn disk_memo() -> Option<[u8; 32]> {
    DISK.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .map(|(_, sha)| sha)
}

/// The sha on disk now, re-hashed only when the stat moved; the lock is not held over the read.
/// Blocking: call off the runtime.
fn disk_sha() -> Option<[u8; 32]> {
    let path = Path::new(&META.get()?.path);
    let stamp = Stamp::stat(path);
    let seen = *DISK.lock().unwrap_or_else(PoisonError::into_inner);
    if let (Some(st), Some((s, sha))) = (stamp, seen) {
        if s == st {
            return Some(sha);
        }
    }
    let fresh = stamp.and_then(|st| read_capped(path).ok().map(|raw| (st, check::sha256(&raw))));
    let mut g = DISK.lock().unwrap_or_else(PoisonError::into_inner);
    // A note the worker made meanwhile came from its own read: keep it.
    if *g == seen {
        *g = fresh;
    }
    fresh.map(|(_, sha)| sha)
}

/// fallback > rejected > restart_required > degraded > ok. An unreadable disk matches either memo.
fn state_of(s: &Status, disk: Option<[u8; 32]>) -> &'static str {
    let on_disk = |sha: [u8; 32]| disk.is_none_or(|d| d == sha);
    if s.applied_last_good {
        "fallback"
    } else if s.last_rejected.is_some_and(on_disk) {
        "rejected"
    } else if s.pending.as_ref().is_some_and(|p| on_disk(p.sha)) {
        "restart_required"
    } else if !s.degraded.is_empty() || (s.applied_source == Source::Boot && s.boot_error) {
        "degraded"
    } else {
        "ok"
    }
}

/// GET /config/status (<name>/config-status/1). Reads the disk: call off the runtime.
pub fn status_json() -> Value {
    let s = current();
    let meta = META.get();
    let disk = disk_sha();
    json!({
        "schema": concat!(env!("CARGO_PKG_NAME"), "/config-status/1"),
        "version": env!("CARGO_PKG_VERSION"), "config_api": 1, "pid": std::process::id(),
        "binary_sha256": BINARY_SHA.get(),
        "path": meta.map(|m| m.path.as_str()),
        "state": state_of(&s, disk),
        "generation": s.generation,
        "applied": {
            "sha256": hex(s.applied_sha), "at": ts(&s.applied_at), "source": s.applied_source.as_str(),
            "from": if s.applied_last_good { "last_good" } else { "file" },
        },
        "disk": {"sha256": disk.map(hex), "in_sync": disk == Some(s.applied_sha)},
        "boot": {
            "at": ts(&s.boot_at), "from": if s.boot_last_good { "last_good" } else { "file" },
            "issues": issues_json(&s.boot_issues), "degraded_routes": s.degraded,
        },
        "pending_restart": s.pending.as_ref().map(|p| json!({"sha256": hex(p.sha), "since": ts(&p.since), "keys": p.keys})),
        "last_attempt": s.last_attempt.as_ref().map(|a| json!({
            "at": ts(&a.at), "source": a.source.as_str(), "sha256": hex(a.sha), "result": a.res.as_str(), "ms": a.ms,
            "errors": a.errors, "warnings": a.warnings, "issues": issues_json(&a.issues), "restart_keys": a.restart_keys,
        })),
        "acme": {
            "desired_hosts": s.acme_desired, "uncovered_hosts": s.acme_uncovered,
            "issuing": crate::acme::issuing(), "last_error": crate::acme::last_error(),
        },
        "watch": {"enabled": meta.is_some_and(|m| m.watch_secs > 0), "interval_secs": meta.map_or(0, |m| m.watch_secs)},
        "last_good": {
            "enabled": meta.is_some_and(|m| m.last_good.is_some()),
            "path": meta.and_then(|m| m.last_good.as_ref()).map(|p| p.display().to_string()),
        },
    })
}

/// The `config` object of :9090/health. Never feeds the HTTP status.
pub fn health_json() -> Value {
    let s = current();
    let disk = disk_memo();
    json!({"gen": s.generation, "state": state_of(&s, disk), "sha": short(s.applied_sha), "in_sync": disk == Some(s.applied_sha)})
}

/// proxy_config_* and proxy_acme_uncovered_hosts, appended to the /metrics scrape.
pub fn scrape(o: &mut String) {
    use std::fmt::Write;
    let s = current();
    let disk = disk_memo();
    let state = state_of(&s, disk);
    let mut g = |name: &str, help: &str, kind: &str, v: u64| {
        let _ = writeln!(
            o,
            "# HELP {} {}\n# TYPE {} {}\n{} {}",
            name, help, name, kind, name, v
        );
    };
    g(
        "proxy_config_generation",
        "Config generation in force",
        "gauge",
        s.generation,
    );
    g(
        "proxy_config_last_success_timestamp_seconds",
        "Unix time of the last applied config (boot included)",
        "gauge",
        u64::try_from(s.last_success.timestamp()).unwrap_or(0),
    );
    g(
        "proxy_config_restart_pending_keys",
        "Restart-class keys waiting in the file on disk",
        "gauge",
        s.pending.as_ref().map_or(0, |p| p.keys.len() as u64),
    );
    g(
        "proxy_config_in_sync",
        "The file on disk is the one applied",
        "gauge",
        u64::from(disk == Some(s.applied_sha)),
    );
    g(
        "proxy_config_boot_fallback",
        "Running on the last-good copy (the file is invalid)",
        "gauge",
        u64::from(s.applied_last_good),
    );
    g(
        "proxy_config_degraded_routes",
        "Static routes whose root does not resolve (503)",
        "gauge",
        s.degraded.len() as u64,
    );
    g(
        "proxy_acme_uncovered_hosts",
        "ACME hosts the bundle does not name yet",
        "gauge",
        s.acme_uncovered as u64,
    );
    let _ = writeln!(o, "# HELP proxy_config_reloads_total Config evaluations by result\n# TYPE proxy_config_reloads_total counter");
    for (r, c) in RESULTS.iter().zip(RELOADS.iter()) {
        let _ = writeln!(
            o,
            "proxy_config_reloads_total{{result=\"{}\"}} {}",
            r.as_str(),
            c.load(Ordering::Relaxed)
        );
    }
    let _ = writeln!(
        o,
        "# HELP proxy_config_state Config state (1 = current)\n# TYPE proxy_config_state gauge"
    );
    for st in ["ok", "degraded", "restart_required", "rejected", "fallback"] {
        let _ = writeln!(
            o,
            "proxy_config_state{{state=\"{}\"}} {}",
            st,
            u8::from(st == state)
        );
    }
}

// ── Last-good ─────────────────────────────────────────────────────────────────

/// PROXY_LAST_GOOD (`off` or an absolute path), else `<dir>/.<base>.last-good` if that dir takes a write.
fn last_good_path(cfg_path: &str) -> Option<PathBuf> {
    match std::env::var("PROXY_LAST_GOOD").map(|v| v.trim().to_string()) {
        Ok(v) if v == "off" => None,
        Ok(v) if Path::new(&v).is_absolute() => Some(PathBuf::from(v)),
        Ok(v) if !v.is_empty() => {
            warn!(target: "config", "config: PROXY_LAST_GOOD={:?} is not an absolute path — last-good is off", v);
            None
        }
        _ => {
            let p = Path::new(cfg_path);
            let dir = p
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let base = p.file_name()?.to_string_lossy().into_owned();
            let probe = dir.join(format!(".edge-probe.{}", std::process::id()));
            let ok = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&probe)
                .is_ok();
            let _ = std::fs::remove_file(&probe);
            ok.then(|| dir.join(format!(".{}.last-good", base)))
        }
    }
}

/// tmp + rename, 0600.
fn write_last_good(path: &Path, raw: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(d)?;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{}.tmp.{}", name, std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(raw)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Last-good writes in the order the worker queued them (boot copy, then each apply).
static LG_NEXT: AtomicU64 = AtomicU64::new(0);
/// The newest queued write that has started; held across the write, so writes never overlap.
static LG_LATEST: Mutex<u64> = Mutex::new(0);

fn save_last_good(path: Option<PathBuf>, raw: Vec<u8>) {
    let Some(p) = path else { return };
    let seq = LG_NEXT.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    tokio::task::spawn_blocking(move || store_last_good(&p, &raw, seq));
}

/// One writer at a time (they share the tmp name); a write older than one already started is dropped.
fn store_last_good(p: &Path, raw: &[u8], seq: u64) {
    let mut latest = LG_LATEST.lock().unwrap_or_else(PoisonError::into_inner);
    if *latest > seq {
        return;
    }
    *latest = seq;
    if let Err(e) = write_last_good(p, raw) {
        warn!(target: "config", "config: cannot write last-good {}: {}", p.display(), e);
    }
}

// ── Boot ──────────────────────────────────────────────────────────────────────

fn opts() -> CheckOpts {
    CheckOpts {
        host: true,
        workdir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
        strict: false,
    }
}

/// What the boot loaded, for the worker and the status.
pub struct Booted {
    raw: Vec<u8>,
    sha: [u8; 32],
    /// The configured file's stat, taken before it was read.
    stamp: Option<Stamp>,
    from_last_good: bool,
    /// From the file with no FATAL/ERROR: becomes the last-good copy.
    clean: bool,
    issues: Vec<Issue>,
    had_error: bool,
    ids: RouteIds,
    last_good: Option<PathBuf>,
    at: DateTime<Utc>,
}

/// The file through the full check. FATAL exits as it always has, unless a last-good copy
/// without FATAL exists; ERROR/WARN are logged and the edge comes up (a bad root degrades its route).
pub fn boot_load(path: &str) -> (ProxyConfig, Booted) {
    let at = Utc::now();
    let p = Path::new(path);
    let last_good = last_good_path(path);
    let stamp = Stamp::stat(p);
    let file = read_capped(p).map(|raw| {
        let rep = check::check_bytes(&raw, &opts());
        (raw, rep)
    });
    let file_issues: Vec<Issue> = match &file {
        Ok((_, rep)) => rep
            .issues
            .iter()
            .filter(|i| i.sev <= Sev::Warning)
            .cloned()
            .collect(),
        Err(e) => vec![Issue::new(
            Sev::Fatal,
            "F101",
            format!("Cannot read '{}': {}", path, e),
        )],
    };
    let fatals: Vec<&Issue> = file_issues.iter().filter(|i| i.sev == Sev::Fatal).collect();

    let (raw, rep, from_last_good) = match file {
        Ok((raw, rep)) if fatals.is_empty() => (raw, rep, false),
        _ => {
            let fallback = last_good.as_ref().filter(|lg| lg.is_file()).and_then(|lg| {
                let raw = read_capped(lg).ok()?;
                let rep = check::check_bytes(&raw, &opts());
                (!rep.issues.iter().any(|i| i.sev == Sev::Fatal)).then_some((lg, raw, rep))
            });
            match fallback {
                Some((lg, raw, rep)) => {
                    error!(target: "config", "config: booted from LAST-GOOD {} — {} is invalid:", lg.display(), path);
                    for i in &fatals {
                        error!(target: "config", "config: {}", i.line_text());
                    }
                    (raw, rep, true)
                }
                None => {
                    for i in &fatals {
                        error!("{}", i.line_text());
                    }
                    std::process::exit(1);
                }
            }
        }
    };

    for i in rep.issues.iter().filter(|i| i.sev <= Sev::Warning) {
        match i.sev {
            Sev::Error => error!(target: "config", "config: {}", i.line_text()),
            _ => warn!(target: "config", "config: {}", i.line_text()),
        }
    }
    let had_error = rep.issues.iter().any(|i| i.sev == Sev::Error);
    let Some(mut cfg) = rep.cfg else {
        error!("{}: no config after a clean parse", path);
        std::process::exit(1);
    };
    let mut ids = RouteIds::default();
    cfg.finalize(&mut ids);
    for (r, id) in cfg.route.iter().zip(cfg.route_ids()) {
        if r.is_static() && r.canonical_static_root.is_none() {
            error!(target: "config", "config: route '{}' DEGRADED (E301) — 503 until the directory exists", id);
        }
    }
    let sha = check::sha256(&raw);
    let clean = !from_last_good && !had_error;
    let booted = Booted {
        raw,
        sha,
        stamp,
        from_last_good,
        clean,
        issues: file_issues,
        had_error,
        ids,
        last_good,
        at,
    };
    (cfg, booted)
}

fn root_ok(r: &RouteConfig) -> bool {
    r.static_root
        .as_deref()
        .and_then(|p| Path::new(p).canonicalize().ok())
        .is_some_and(|p| p.is_dir())
}

/// Static routes whose root does not resolve to a directory right now (identities).
fn degraded_routes(cfg: &ProxyConfig) -> Vec<String> {
    cfg.route
        .iter()
        .zip(cfg.route_ids())
        .filter(|(r, _)| r.is_static() && !root_ok(r))
        .map(|(_, id)| id)
        .collect()
}

fn watch_secs() -> u64 {
    match std::env::var("PROXY_CONFIG_WATCH_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(0) => 0,
        Some(n) => n.clamp(1, 60),
        None => 2,
    }
}

/// sha256 of the running image (/proc/self/exe survives a replaced file on disk).
fn exe_sha() -> Option<String> {
    let p = Path::new("/proc/self/exe");
    let path = if p.exists() {
        p.to_path_buf()
    } else {
        std::env::current_exe().ok()?
    };
    let mut f = std::fs::File::open(path).ok()?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        ctx.update(buf.get(..n)?);
    }
    Some(check::hex(ctx.finish().as_ref()))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(f).await.ok()
}

fn later(now: Instant, d: Duration) -> Instant {
    now.checked_add(d).unwrap_or(now)
}

pub fn parse_sha(s: &str) -> Option<[u8; 32]> {
    if !crate::cli_args::is_hex64(s) {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        *o = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

// ── Reloader (control side) and Worker ────────────────────────────────────────

#[derive(Clone)]
struct Outcome {
    res: Res,
    sha: Option<[u8; 32]>,
    generation: u64,
    applied_sha: [u8; 32],
    ms: u64,
    changed: Vec<String>,
    restart_keys: Vec<String>,
    notices: Vec<Issue>,
    issues: Vec<Issue>,
}

impl Outcome {
    fn to_json(&self) -> Value {
        json!({
            "schema": concat!(env!("CARGO_PKG_NAME"), "/reload/1"), "result": self.res.as_str(), "generation": self.generation,
            "sha256": self.sha.map(hex), "applied_sha256": hex(self.applied_sha), "ms": self.ms,
            "source": "control", "changed": self.changed, "restart_keys": self.restart_keys,
            "notices": issues_json(&self.notices), "issues": issues_json(&self.issues), "error": null,
        })
    }
}

fn reload_stub(result: &str, ms: u64) -> Value {
    let s = current();
    json!({
        "schema": concat!(env!("CARGO_PKG_NAME"), "/reload/1"), "result": result, "generation": s.generation, "sha256": null,
        "applied_sha256": hex(s.applied_sha), "ms": ms, "source": "control", "changed": [],
        "restart_keys": [], "notices": [], "issues": [], "error": null,
    })
}

struct Req {
    expect: Option<[u8; 32]>,
    reply: oneshot::Sender<Outcome>,
}

struct Shared {
    path: String,
    boot: Arc<BootCaptured>,
    live: Arc<ArcSwap<Live>>,
    verify_gate: Semaphore,
}

/// The control socket's handle on the worker.
#[derive(Clone)]
pub struct Reloader {
    tx: mpsc::Sender<Req>,
    sh: Arc<Shared>,
}

pub struct Parts {
    pub path: String,
    pub booted: Booted,
    pub boot: Arc<BootCaptured>,
    pub gw: GatewayHandle,
    pub registry: CertRegistry,
    pub on_demand: Arc<OnDemandResolver>,
    pub hosts: HostList,
    pub acme_desired: Arc<ArcSwap<Vec<String>>>,
    pub acme_changed: Arc<Notify>,
}

pub struct Worker {
    sh: Arc<Shared>,
    rx: mpsc::Receiver<Req>,
    gw: GatewayHandle,
    registry: CertRegistry,
    on_demand: Arc<OnDemandResolver>,
    hosts: HostList,
    acme_desired: Arc<ArcSwap<Vec<String>>>,
    acme_changed: Arc<Notify>,
    ids: RouteIds,
    watch: Option<WatchState>,
    watch_every: Duration,
    next_watch: Instant,
    next_recheck: Instant,
    last_good: Option<PathBuf>,
    /// The clean boot bytes, written as last-good once the worker starts.
    boot_write: Option<Vec<u8>>,
    boot_sha: [u8; 32],
    self_restart_at: Option<Instant>,
    reminded_at: Option<Instant>,
    logged_reject: Option<[u8; 32]>,
}

impl Reloader {
    pub fn new(p: Parts) -> (Reloader, Worker) {
        let now = Instant::now();
        let secs = watch_secs();
        let b = p.booted;
        let _ = META.set(Meta {
            path: p.path.clone(),
            watch_secs: secs,
            last_good: b.last_good.clone(),
        });
        if !b.from_last_good {
            note_disk(b.stamp, b.sha);
        }
        STATUS.store(Some(Arc::new(Status {
            generation: p.gw.live.load().generation,
            applied_sha: b.sha,
            applied_at: b.at,
            applied_source: Source::Boot,
            applied_last_good: b.from_last_good,
            boot_at: b.at,
            boot_last_good: b.from_last_good,
            boot_issues: b.issues,
            boot_error: b.had_error,
            degraded: degraded_routes(&p.boot.cfg),
            acme_desired: p.acme_desired.load().len(),
            last_success: b.at,
            ..Status::default()
        })));
        let (tx, rx) = mpsc::channel(64);
        let sh = Arc::new(Shared {
            path: p.path,
            boot: p.boot,
            live: Arc::clone(&p.gw.live),
            verify_gate: Semaphore::new(1),
        });
        let every = Duration::from_secs(secs.max(1));
        let worker = Worker {
            sh: Arc::clone(&sh),
            rx,
            gw: p.gw,
            registry: p.registry,
            on_demand: p.on_demand,
            hosts: p.hosts,
            acme_desired: p.acme_desired,
            acme_changed: p.acme_changed,
            ids: b.ids,
            watch: (secs > 0).then(|| WatchState::new(every, b.stamp, b.sha, now)),
            watch_every: every,
            next_watch: later(now, every),
            next_recheck: later(now, RECHECK),
            last_good: b.last_good,
            boot_write: b.clean.then_some(b.raw),
            boot_sha: b.sha,
            self_restart_at: None,
            reminded_at: None,
            logged_reject: None,
        };
        (Reloader { tx, sh }, worker)
    }

    /// POST /config/reload: (HTTP status, <name>/reload/1).
    pub async fn reload(&self, expect: Option<[u8; 32]>) -> (u16, Value) {
        let t0 = Instant::now();
        let ms = || u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (reply, rx) = oneshot::channel();
        let wait = async {
            self.tx.send(Req { expect, reply }).await.ok()?;
            rx.await.ok()
        };
        match tokio::time::timeout(CONTROL_WAIT, wait).await {
            Ok(Some(out)) => (out.res.http(), out.to_json()),
            Ok(None) => (503, reload_stub("not_ready", ms())),
            Err(_) => (504, reload_stub("timeout", ms())),
        }
    }

    /// POST /config/verify: the body through the same check, diffed against the live generation.
    pub async fn verify(&self, body: Vec<u8>) -> (u16, Value) {
        let Ok(_permit) = self.sh.verify_gate.try_acquire() else {
            return (429, json!({"error": "busy — one verify at a time"}));
        };
        let live = self.sh.live.load_full();
        let boot = Arc::clone(&self.sh.boot);
        let against = hex(current().applied_sha);
        let job = blocking(move || {
            let o = opts();
            let mut rep = check::check_bytes(&body, &o);
            let plan = match rep.cfg.as_ref().map(|new| {
                check::plan_at(
                    &boot.cfg,
                    &live.cfg,
                    new,
                    !boot.bundle,
                    boot.static_fallback,
                )
            }) {
                Some(Ok(mut p)) => {
                    rep.issues.append(&mut p.notices);
                    Some(p)
                }
                Some(Err(e)) => {
                    rep.issues.push(Issue::new(
                        Sev::Warning,
                        "W499",
                        format!("diff against the live generation failed: {}", e),
                    ));
                    None
                }
                None => None,
            };
            check::finish(&mut rep.issues, std::str::from_utf8(&body).unwrap_or(""));
            check::check_json(&rep, "-", &o, plan.as_ref().map(|p| (against.as_str(), p)))
        });
        match job.await {
            Some(v) => (200, v),
            None => (500, json!({"error": "verify failed"})),
        }
    }

    /// GET /config/status.
    pub async fn status(&self) -> Value {
        blocking(status_json).await.unwrap_or_else(|| json!({"schema": concat!(env!("CARGO_PKG_NAME"), "/config-status/1"), "state": null}))
    }
}

/// A new generation, built off the runtime; committing it is stores only.
struct Built {
    ids: RouteIds,
    resets: Vec<usize>,
    /// W408 per route left without a breaker slot.
    unslotted: Vec<Issue>,
    prepared: Prepared,
    hosts: (HashSet<String>, HashSet<String>),
    routes: Vec<RouteConfig>,
    needs_cf: bool,
    /// Bundle mode: the ACME host list to store (None = the same set) and how many hosts are new.
    acme: Option<(Option<Vec<String>>, usize)>,
    next: Live,
}

/// finalize, the cert prepare (the one fallible step), breaker resets, derived sets and the Live.
fn build(
    mut cfg: ProxyConfig,
    mut ids: RouteIds,
    live: &Live,
    generation: u64,
    had: Option<Arc<Vec<String>>>,
) -> anyhow::Result<Built> {
    let assign = cfg.finalize(&mut ids);
    let prepared = CertRegistry::prepare(&cfg.route)?;
    let rids = cfg.route_ids();
    let lids = live.cfg.route_ids();
    let old: HashMap<&str, usize> = lids
        .iter()
        .enumerate()
        .map(|(j, id)| (id.as_str(), j))
        .collect();
    let mut resets = assign.reset;
    for (r, id) in cfg.route.iter().zip(&rids) {
        let moved = old
            .get(id.as_str())
            .and_then(|&j| live.cfg.route.get(j))
            .is_some_and(|o| o.upstream_addr() != r.upstream_addr());
        if moved {
            resets.push(r.id);
        }
    }
    let unslotted = assign
        .unslotted
        .iter()
        .map(|&j| {
            Issue::new(
                Sev::Warning,
                "W408",
                "no free breaker slot — this route is never short-circuited",
            )
            .at_route(j, &rids, None)
        })
        .collect();
    let acme = had.map(|had| {
        let want = cfg.acme_hosts();
        let have: HashSet<&str> = had.iter().map(String::as_str).collect();
        let added = want.iter().filter(|h| !have.contains(h.as_str())).count();
        let changed = added > 0 || want.len() != have.len();
        (changed.then_some(want), added)
    });
    let needs_cf = crate::config::needs_cf_ranges(&cfg);
    let hosts = crate::on_demand::route_host_sets(&cfg.route);
    let routes = cfg.route.clone();
    let next = Live::build(Arc::new(cfg), generation, Some(live));
    Ok(Built {
        ids,
        resets,
        unslotted,
        prepared,
        hosts,
        routes,
        needs_cf,
        acme,
        next,
    })
}

enum Done {
    Mismatch,
    Unchanged,
    Rejected(Vec<Issue>),
    Restart(Plan, Vec<Issue>),
    Applied {
        plan: Plan,
        issues: Vec<Issue>,
        raw: Vec<u8>,
        generation: u64,
    },
}

impl Worker {
    pub async fn run(mut self) {
        self.on_start().await;
        let mut tick = tokio::time::interval(HUP_POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The control server may never start (another live instance owns the socket).
        let mut open = true;
        loop {
            tokio::select! {
                r = self.rx.recv(), if open => match r {
                    Some(first) => self.serve(first).await,
                    None => open = false,
                },
                _ = tick.tick() => self.on_tick().await,
            }
        }
    }

    async fn on_start(&mut self) {
        if let Some(raw) = self.boot_write.take() {
            save_last_good(self.last_good.clone(), raw);
        }
        tokio::task::spawn_blocking(|| {
            if let Some(h) = exe_sha() {
                let _ = BINARY_SHA.set(h);
            }
        });
        self.recheck().await;
        if HUP.swap(false, Ordering::Relaxed) {
            self.on_hup().await;
            return;
        }
        // A file changed while boot ran (ACME issuance can take minutes), or boot fell back.
        let path = PathBuf::from(&self.sh.path);
        if let Some(Ok((stamp, raw, sha))) = blocking(move || read_hashed(&path)).await {
            note_disk(stamp, sha);
            if sha != self.boot_sha {
                self.evaluate(Source::Watch, None, Some((raw, sha))).await;
            }
        }
    }

    async fn on_tick(&mut self) {
        if HUP.swap(false, Ordering::Relaxed) {
            self.on_hup().await;
        }
        let now = Instant::now();
        if self.watch.is_some() && now >= self.next_watch {
            self.watch_step(now).await;
        }
        if now >= self.next_recheck {
            self.next_recheck = later(now, RECHECK);
            self.recheck().await;
        }
        self.remind(now);
    }

    async fn watch_step(&mut self, now: Instant) {
        let path = PathBuf::from(&self.sh.path);
        let stamp = Stamp::stat(&path);
        let Some(w) = self.watch.as_mut() else { return };
        match w.poll(stamp, now) {
            Next::Sleep(d) => self.next_watch = later(now, d),
            Next::Read => {
                self.next_watch = later(now, self.watch_every);
                let (raw, sha) = match blocking(move || read_hashed(&path)).await {
                    Some(Ok((_, r, sha))) => (r, sha),
                    _ => {
                        forget_disk();
                        if let Some(w) = self.watch.as_mut() {
                            w.read_failed();
                        }
                        return;
                    }
                };
                note_disk(stamp, sha);
                let v = match self.watch.as_mut() {
                    Some(w) => w.on_read(&raw, sha, Instant::now()),
                    None => return,
                };
                if v == Verdict::Evaluate {
                    self.evaluate(Source::Watch, None, Some((raw, sha))).await;
                }
            }
        }
    }

    async fn on_hup(&mut self) {
        info!(target: "config", "config: SIGHUP — re-reading {}", self.sh.path);
        let (hosts, registry) = (self.hosts.clone(), self.registry.clone());
        blocking(move || {
            hosts.reload();
            if let Err(e) = registry.reload() {
                warn!("CertRegistry reload failed: {}", e);
            }
        })
        .await;
        let Some(out) = self.evaluate(Source::Hup, None, None).await else {
            return;
        };
        let due = self
            .self_restart_at
            .is_none_or(|t| t.elapsed() >= SELF_RESTART_GAP);
        if out.res == Res::RestartRequired && supervised() && due {
            self.self_restart_at = Some(Instant::now());
            warn!(target: "config", "config: SIGHUP with restart-required keys ({}) — restarting via SIGTERM", out.restart_keys.join(", "));
            // SAFETY: a plain syscall on our own pid; Pingora shuts down gracefully on SIGTERM.
            unsafe {
                libc::kill(libc::getpid(), libc::SIGTERM);
            }
        }
    }

    /// Control calls queued behind an evaluation share the next one when their expect_sha agree.
    async fn serve(&mut self, first: Req) {
        let mut batch = vec![first];
        while let Ok(r) = self.rx.try_recv() {
            batch.push(r);
        }
        while let Some(key) = batch.first().map(|r| r.expect) {
            let (group, rest): (Vec<Req>, Vec<Req>) =
                batch.into_iter().partition(|r| r.expect == key);
            batch = rest;
            let out = self.evaluate(Source::Control, key, None).await;
            for r in group {
                if let Some(o) = &out {
                    let _ = r.reply.send(o.clone());
                }
            }
        }
    }

    /// Degraded static roots, the bundle's coverage and the disk memo, re-read every minute.
    async fn recheck(&mut self) {
        let cfg = Arc::clone(&self.sh.live.load().cfg);
        let storage = self.sh.boot.cfg.acme.storage.clone();
        let desired = self.acme_desired.load_full();
        let bundle = self.sh.boot.bundle;
        let n = desired.len();
        let Some((degraded, uncovered)) = blocking(move || {
            // Keeps the memo the handlers read honest when the watcher is off.
            disk_sha();
            let u = if bundle && !desired.is_empty() {
                crate::acme::CertBundle::load(&storage)
                    .map_or(desired.len(), |b| b.uncovered(&desired))
            } else {
                0
            };
            (degraded_routes(&cfg), u)
        })
        .await
        else {
            return;
        };
        let prev = current();
        for id in degraded.iter().filter(|d| !prev.degraded.contains(d)) {
            error!(target: "config", "config: route '{}' DEGRADED (E301) — 503 until the directory exists", id);
        }
        for id in prev.degraded.iter().filter(|d| !degraded.contains(d)) {
            info!(target: "config", "config: route '{}' static_root resolves again — serving", id);
        }
        if degraded != prev.degraded || uncovered != prev.acme_uncovered || n != prev.acme_desired {
            let mut s = (*prev).clone();
            s.degraded = degraded;
            s.acme_uncovered = uncovered;
            s.acme_desired = n;
            STATUS.store(Some(Arc::new(s)));
        }
    }

    fn remind(&mut self, now: Instant) {
        let s = current();
        let Some(p) = &s.pending else {
            self.reminded_at = None;
            return;
        };
        match self.reminded_at {
            Some(t) if now.saturating_duration_since(t) < PENDING_REMINDER => {}
            Some(_) => {
                warn!(target: "config", "config: RESTART REQUIRED sha {} keys {} — still serving gen {}", short(p.sha), p.keys.join(", "), s.generation);
                self.reminded_at = Some(now);
            }
            None => self.reminded_at = Some(now),
        }
    }

    fn rejected(
        &mut self,
        source: Source,
        t0: Instant,
        sha: Option<[u8; 32]>,
        issues: Vec<Issue>,
    ) -> Option<Outcome> {
        Some(self.finish(source, t0, sha, Done::Rejected(issues)))
    }

    /// Design 3.3: read, sha gate, check, plan, prepare, commit (TLS before HTTP). None only
    /// when a watcher-triggered route removal saw the file move under it (re-read next tick).
    /// Everything but the stores runs off the runtime that also serves the :443 pre-filter.
    async fn evaluate(
        &mut self,
        source: Source,
        expect: Option<[u8; 32]>,
        pre: Option<(Vec<u8>, [u8; 32])>,
    ) -> Option<Outcome> {
        let t0 = Instant::now();
        let (raw, sha) = match pre {
            Some(p) => p,
            None => {
                let path = PathBuf::from(&self.sh.path);
                match blocking(move || read_hashed(&path)).await {
                    Some(Ok((stamp, r, sha))) => {
                        note_disk(stamp, sha);
                        (r, sha)
                    }
                    Some(Err(e)) => {
                        forget_disk();
                        let i = Issue::new(
                            Sev::Fatal,
                            "F101",
                            format!("{} is unreadable: {}", self.sh.path, e),
                        );
                        return self.rejected(source, t0, None, vec![i]);
                    }
                    None => {
                        let i = Issue::new(Sev::Fatal, "F101", "the read task failed");
                        return self.rejected(source, t0, None, vec![i]);
                    }
                }
            }
        };
        if expect.is_some_and(|e| e != sha) {
            return Some(self.finish(source, t0, Some(sha), Done::Mismatch));
        }
        if sha == current().applied_sha {
            return Some(self.finish(source, t0, Some(sha), Done::Unchanged));
        }

        let live = self.sh.live.load_full();
        let boot = Arc::clone(&self.sh.boot);
        let (l, b) = (Arc::clone(&live), Arc::clone(&boot));
        let Some(checked) = blocking(move || {
            let rep = check::check_bytes(&raw, &opts());
            let ok = rep.ok();
            let mut issues: Vec<Issue> = rep
                .issues
                .iter()
                .filter(|i| i.sev <= Sev::Warning)
                .cloned()
                .collect();
            let planned = match (ok, rep.cfg) {
                (true, Some(new)) => {
                    match check::plan_at(&b.cfg, &l.cfg, &new, !b.bundle, b.static_fallback) {
                        Ok(p) => Some((new, p)),
                        Err(e) => {
                            issues.push(Issue::new(
                                Sev::Warning,
                                "W499",
                                format!("the diff could not run: {}", e),
                            ));
                            None
                        }
                    }
                }
                _ => None,
            };
            (raw, issues, planned)
        })
        .await
        else {
            let i = Issue::new(Sev::Warning, "W499", "the check task failed");
            return self.rejected(source, t0, Some(sha), vec![i]);
        };
        let (raw, mut issues, planned) = checked;
        let Some((new, plan)) = planned else {
            return self.rejected(source, t0, Some(sha), issues);
        };
        if !plan.restart_keys.is_empty() {
            return Some(self.finish(source, t0, Some(sha), Done::Restart(plan, issues)));
        }
        // A route removal may be a half-written file: it must still read the same a moment later.
        if let Some(d) = ws::removal_settle(source == Source::Watch, plan.routes_removed.len()) {
            tokio::time::sleep(d).await;
            let path = PathBuf::from(&self.sh.path);
            let again = blocking(move || read_capped(&path).map(|r| check::sha256(&r))).await;
            if !matches!(again, Some(Ok(s)) if s == sha) {
                info!(target: "config", "config: sha {} moved while a route removal settled — re-reading", short(sha));
                return None;
            }
        }

        // Prepare and build: nothing global is touched until every fallible step passed.
        let generation = live.generation.saturating_add(1);
        let (ids, l) = (self.ids.clone(), Arc::clone(&live));
        let had = boot.bundle.then(|| self.acme_desired.load_full());
        let Some(built) = blocking(move || build(new, ids, &l, generation, had)).await else {
            let i = Issue::new(Sev::Warning, "W499", "the prepare task failed");
            return self.rejected(source, t0, Some(sha), vec![i]);
        };
        let b = match built {
            Ok(b) => b,
            Err(e) => {
                issues.push(Issue::new(Sev::Error, "E302", format!("{:#}", e)).on_host());
                return self.rejected(source, t0, Some(sha), issues);
            }
        };
        if !b.unslotted.is_empty() {
            // One line however many: past 1024 routes every apply would repeat them all.
            let ids: Vec<&str> = b
                .unslotted
                .iter()
                .take(10)
                .filter_map(|i| i.route.as_deref())
                .collect();
            let more = if b.unslotted.len() > ids.len() {
                ", …"
            } else {
                ""
            };
            warn!(target: "config", "config: W408 {} route(s) without a breaker slot, never short-circuited: {}{}", b.unslotted.len(), ids.join(", "), more);
        }
        issues.extend(b.unslotted);
        if b.needs_cf {
            crate::shield::ensure_cf_ranges().await;
        }

        // Commit: stores only (the registry's behind its writer lock, which a cert reload may hold).
        self.ids = b.ids;
        for slot in &b.resets {
            crate::breaker::reset(*slot);
        }
        self.on_demand.set_route_hosts(b.hosts);
        let registry = self.registry.clone();
        let prepared = b.prepared;
        blocking(move || registry.commit(prepared)).await;
        let cfg = Arc::clone(&b.next.cfg);
        self.sh.live.store(Arc::new(b.next));
        crate::apply_setters(&cfg, Some(live.cfg.as_ref()), &self.gw);
        crate::metrics::set_routes(b.routes);
        if let Some((want, added)) = b.acme {
            if let Some(want) = want {
                self.acme_desired.store(Arc::new(want));
            }
            if added > 0 {
                self.acme_changed.notify_one();
                info!(target: "config", "config: ACME reissue for {} new host(s) queued", added);
            }
        }
        // Degraded roots and bundle coverage of the new set, on the next tick.
        self.next_recheck = Instant::now();
        Some(self.finish(
            source,
            t0,
            Some(sha),
            Done::Applied {
                plan,
                issues,
                raw,
                generation,
            },
        ))
    }

    /// Status, counters, logs and the watcher's memo for one evaluation.
    fn finish(
        &mut self,
        source: Source,
        t0: Instant,
        sha: Option<[u8; 32]>,
        done: Done,
    ) -> Outcome {
        let ms = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        let now = Utc::now();
        let key = sha.unwrap_or_else(|| check::sha256(b""));
        let mut s = (*current()).clone();
        let count = |v: &[Issue], f: fn(Sev) -> bool| v.iter().filter(|i| f(i.sev)).count();
        let (res, changed, restart_keys, notices, issues, memo) = match done {
            Done::Mismatch => {
                warn!(target: "config", "config: the file on disk (sha {}) is not the expected one — nothing applied", short(key));
                (
                    Res::ShaMismatch,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    ws::Outcome::ShaMismatch,
                )
            }
            Done::Unchanged => {
                s.pending = None;
                s.last_rejected = None;
                // The file now holds exactly what runs.
                s.applied_last_good = false;
                if source != Source::Watch {
                    info!(target: "config", "config: unchanged (gen {}, sha {}, source {})", s.generation, short(key), source.as_str());
                }
                (
                    Res::Unchanged,
                    vec![],
                    vec![],
                    vec![],
                    vec![],
                    ws::Outcome::Unchanged,
                )
            }
            Done::Rejected(issues) => {
                s.last_rejected = Some(key);
                let errs: Vec<&Issue> = issues.iter().filter(|i| i.sev <= Sev::Error).collect();
                let host_only = !errs.is_empty() && errs.iter().all(|i| i.host);
                if self.logged_reject != Some(key) {
                    self.logged_reject = Some(key);
                    error!(
                        target: "config",
                        "config: REJECTED sha {} (source {}): {} error(s), {} warning(s) — still serving gen {}",
                        short(key), source.as_str(), errs.len(), count(&issues, |v| v == Sev::Warning), s.generation
                    );
                    for i in &issues {
                        warn!(target: "config", "config: {}", i.line_text());
                    }
                }
                (
                    Res::Rejected,
                    vec![],
                    vec![],
                    vec![],
                    issues,
                    ws::Outcome::Rejected { host_only },
                )
            }
            Done::Restart(plan, issues) => {
                let same = s.pending.as_ref().filter(|p| p.sha == key).map(|p| p.since);
                if same.is_none() {
                    warn!(
                        target: "config",
                        "config: RESTART REQUIRED sha {} keys {} — still serving gen {}",
                        short(key), plan.restart_keys.join(", "), s.generation
                    );
                    self.reminded_at = Some(Instant::now());
                }
                s.pending = Some(Pending {
                    sha: key,
                    since: same.unwrap_or(now),
                    keys: plan.restart_keys.clone(),
                });
                (
                    Res::RestartRequired,
                    plan.changed,
                    plan.restart_keys,
                    plan.notices,
                    issues,
                    ws::Outcome::RestartRequired,
                )
            }
            Done::Applied {
                plan,
                issues,
                raw,
                generation,
            } => {
                s.generation = generation;
                s.applied_sha = key;
                s.applied_at = now;
                s.applied_source = source;
                s.applied_last_good = false;
                s.pending = None;
                s.last_rejected = None;
                s.last_success = now;
                s.acme_desired = self.acme_desired.load().len();
                save_last_good(self.last_good.clone(), raw);
                let whole: HashSet<&str> = plan
                    .routes_added
                    .iter()
                    .chain(&plan.routes_removed)
                    .map(String::as_str)
                    .collect();
                let touched: HashSet<&str> = plan
                    .changed
                    .iter()
                    .filter_map(|p| {
                        p.strip_prefix("route[")
                            .and_then(|r| r.split_once(']'))
                            .map(|(id, _)| id)
                    })
                    .filter(|id| !whole.contains(id))
                    .collect();
                info!(
                    target: "config",
                    "config: gen {} applied (sha {}, source {}, {} changed, routes +{} -{} ~{}) in {} ms",
                    generation, short(key), source.as_str(), plan.changed.len(), plan.routes_added.len(),
                    plan.routes_removed.len(), touched.len(), ms
                );
                (
                    Res::Applied,
                    plan.changed,
                    vec![],
                    plan.notices,
                    issues,
                    ws::Outcome::Applied,
                )
            }
        };
        s.last_attempt = Some(Attempt {
            at: now,
            source,
            sha: key,
            res,
            ms,
            errors: count(&issues, |v| v <= Sev::Error),
            warnings: count(&issues, |v| v == Sev::Warning),
            issues: issues.clone(),
            restart_keys: restart_keys.clone(),
        });
        let (generation, applied_sha) = (s.generation, s.applied_sha);
        STATUS.store(Some(Arc::new(s)));
        res.count();
        if let Some(w) = self.watch.as_mut() {
            w.note(key, memo, source == Source::Watch, Instant::now());
        }
        Outcome {
            res,
            sha,
            generation,
            applied_sha,
            ms,
            changed,
            restart_keys,
            notices,
            issues,
        }
    }
}
