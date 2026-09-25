//! When the config watcher reads the file, and whether a read is worth an evaluation (std only).
//! A write in progress is waited out (settle, newline guard); a sha already judged is not re-judged.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::Path;
use std::time::{Duration, Instant};

/// Re-sample spacing while a change settles.
pub const SETTLE: Duration = Duration::from_millis(500);
/// A file still changing after this is read anyway.
pub const SETTLE_MAX: Duration = Duration::from_secs(10);
/// A read without a trailing newline is taken once the stat held this long.
pub const NEWLINE_BYPASS: Duration = Duration::from_secs(10);
/// Full read regardless of stat (a change the stat tuple cannot see).
pub const REHASH: Duration = Duration::from_secs(300);
/// A file refused only for host reasons (a missing root, a cert not there yet) is retried this often.
pub const HOST_RETRY: Duration = Duration::from_secs(60);
/// Watcher-triggered evaluations are at least this far apart.
pub const MIN_GAP: Duration = Duration::from_secs(1);
/// A watcher plan that removes routes re-reads after this, in case it caught a torn write.
pub const REMOVAL_SETTLE: Duration = Duration::from_millis(500);

/// What identifies one version of the file on disk; ctime catches an in-place rewrite
/// that restored the old size and mtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub len: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

impl Stamp {
    pub fn of(m: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        let ns = |s: i64, n: i64| {
            i128::from(s)
                .saturating_mul(1_000_000_000)
                .saturating_add(i128::from(n))
        };
        Self {
            dev: m.dev(),
            ino: m.ino(),
            len: m.size(),
            mtime_ns: ns(m.mtime(), m.mtime_nsec()),
            ctime_ns: ns(m.ctime(), m.ctime_nsec()),
        }
    }

    /// Follows symlinks; None when the file is missing.
    pub fn stat(path: &Path) -> Option<Self> {
        std::fs::metadata(path).ok().map(|m| Self::of(&m))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    Sleep(Duration),
    Read,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing new: applied, pending a restart, or already refused.
    Skip,
    /// Looks mid-write: read again next tick.
    Wait,
    Evaluate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Unchanged,
    Rejected { host_only: bool },
    RestartRequired,
    ShaMismatch,
}

pub struct WatchState {
    interval: Duration,
    /// The stamp whose content the last completed read consumed.
    seen: Option<Stamp>,
    /// The latest sample and when it first appeared.
    cur: Option<Stamp>,
    cur_since: Instant,
    /// When `cur` first differed from `seen`.
    change_since: Option<Instant>,
    last_read: Instant,
    applied: [u8; 32],
    rejected: Option<([u8; 32], bool, Instant)>,
    pending: Option<[u8; 32]>,
    last_eval: Option<Instant>,
}

impl WatchState {
    /// `stamp` is the file's stat taken before the applied bytes were read.
    pub fn new(interval: Duration, stamp: Option<Stamp>, applied: [u8; 32], now: Instant) -> Self {
        Self {
            interval,
            seen: stamp,
            cur: stamp,
            cur_since: now,
            change_since: None,
            last_read: now,
            applied,
            rejected: None,
            pending: None,
            last_eval: None,
        }
    }

    fn observe(&mut self, stamp: Option<Stamp>, now: Instant) {
        if stamp != self.cur {
            self.cur = stamp;
            self.cur_since = now;
        }
        if self.cur == self.seen {
            self.change_since = None;
        } else if self.change_since.is_none() {
            self.change_since = Some(now);
        }
    }

    fn retry_due(&self, now: Instant) -> bool {
        self.rejected.is_some_and(|(_, host_only, at)| {
            host_only && now.saturating_duration_since(at) >= HOST_RETRY
        })
    }

    /// One stat sample: read now, or sleep this long first.
    pub fn poll(&mut self, stamp: Option<Stamp>, now: Instant) -> Next {
        self.observe(stamp, now);
        let want = match self.change_since {
            Some(since) => {
                let settled = now.saturating_duration_since(self.cur_since) >= SETTLE;
                if !settled && now.saturating_duration_since(since) < SETTLE_MAX {
                    return Next::Sleep(SETTLE);
                }
                true
            }
            None => now.saturating_duration_since(self.last_read) >= REHASH || self.retry_due(now),
        };
        if !want {
            return Next::Sleep(self.interval);
        }
        if let Some(t) = self.last_eval {
            let gap = now.saturating_duration_since(t);
            if gap < MIN_GAP {
                return Next::Sleep(MIN_GAP.saturating_sub(gap));
            }
        }
        Next::Read
    }

    /// The bytes a Read produced, and their sha.
    pub fn on_read(&mut self, raw: &[u8], sha: [u8; 32], now: Instant) -> Verdict {
        self.last_read = now;
        let torn = raw.last().is_some_and(|b| *b != b'\n');
        if torn && now.saturating_duration_since(self.cur_since) < NEWLINE_BYPASS {
            return Verdict::Wait;
        }
        self.seen = self.cur;
        self.change_since = None;
        if sha == self.applied {
            // Back to what runs: evaluated only to clear a stale pending/rejected state.
            return if self.pending.is_some() || self.rejected.is_some() {
                Verdict::Evaluate
            } else {
                Verdict::Skip
            };
        }
        if self.pending == Some(sha) {
            return Verdict::Skip;
        }
        if let Some((r, host_only, at)) = self.rejected {
            if r == sha {
                let retry = host_only && now.saturating_duration_since(at) >= HOST_RETRY;
                return if retry {
                    Verdict::Evaluate
                } else {
                    Verdict::Skip
                };
            }
        }
        Verdict::Evaluate
    }

    /// The file vanished or could not be read: wait for the next stat change.
    pub fn read_failed(&mut self) {
        self.seen = self.cur;
        self.change_since = None;
    }

    /// Any evaluation's result (every source), so the watcher never re-judges the same sha.
    pub fn note(&mut self, sha: [u8; 32], out: Outcome, from_watch: bool, now: Instant) {
        if from_watch {
            self.last_eval = Some(now);
        }
        match out {
            Outcome::Applied | Outcome::Unchanged => {
                self.applied = sha;
                self.pending = None;
                self.rejected = None;
            }
            Outcome::Rejected { host_only } => self.rejected = Some((sha, host_only, now)),
            Outcome::RestartRequired => self.pending = Some(sha),
            Outcome::ShaMismatch => {}
        }
    }
}

/// A watcher-triggered plan that removes routes waits this long and re-reads first.
pub fn removal_settle(from_watch: bool, routes_removed: usize) -> Option<Duration> {
    (from_watch && routes_removed > 0).then_some(REMOVAL_SETTLE)
}
