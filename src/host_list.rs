//! host_list.rs: the on-demand TLS allowlist.
//!
//! A plain text file, one hostname per line. Blank lines and `#` comments are
//! ignored, names are lowercased. A host in this file gets a certificate issued
//! on its first TLS handshake (on_demand.rs) and is served by the route marked
//! `on_demand_fallback = true`.
//!
//! ```text
//! # on-demand hosts
//! shop.example.com
//! blog.example.net
//! ```
//!
//! The list is a read-only snapshot. It is reloaded when the file's mtime
//! changes (a 5 s poll) and on SIGHUP. Whoever writes the file owns it.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use arc_swap::ArcSwap;
use tracing::{info, warn};

type Store = HashSet<String>;

/// Shared, cheaply cloneable handle to the on-demand allowlist.
#[derive(Clone)]
pub struct HostList {
    inner: Arc<ArcSwap<Store>>,
    file_path: Arc<PathBuf>,
}

impl HostList {
    /// Load the list from `file_path`. An empty path or a missing file gives an
    /// empty list, not an error: the writer may not have created it yet.
    pub fn load(file_path: impl AsRef<Path>) -> Self {
        let path = file_path.as_ref().to_path_buf();
        let store = read_file(&path).unwrap_or_default();
        if !path.as_os_str().is_empty() {
            info!(
                "on-demand hosts: loaded {} name(s) from '{}'",
                store.len(),
                path.display()
            );
        }
        Self {
            inner: Arc::new(ArcSwap::from_pointee(store)),
            file_path: Arc::new(path),
        }
    }

    /// Re-read the file in place. In-flight readers keep the old snapshot.
    /// Returns false if the file could not be read (the old snapshot stays), so
    /// the watcher tries again instead of latching the failure.
    pub fn reload(&self) -> bool {
        if self.file_path.as_os_str().is_empty() {
            return true;
        }
        match read_file(&self.file_path) {
            Ok(store) => {
                info!(
                    "on-demand hosts: reloaded {} name(s) from '{}'",
                    store.len(),
                    self.file_path.display()
                );
                self.inner.store(Arc::new(store));
                true
            }
            Err(e) => {
                warn!(
                    "on-demand hosts: reload failed, keeping the old list: {}",
                    e
                );
                false
            }
        }
    }

    /// Poll the file's mtime and reload on change. The interval doubles as a
    /// debounce: a burst of writes becomes at most one reload per interval.
    /// A writer that truncates in place can be caught mid-write, which is why a
    /// failed reload is retried on the next tick. Spawn inside a Tokio runtime.
    pub fn spawn_reload_watcher(&self, interval: std::time::Duration) {
        if self.file_path.as_os_str().is_empty() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            let mtime = || {
                std::fs::metadata(&*this.file_path)
                    .and_then(|m| m.modified())
                    .ok()
            };
            let mut last = mtime();
            loop {
                tokio::time::sleep(interval).await;
                let cur = mtime();
                // Commit the new stamp only once the reload worked.
                if cur != last && this.reload() {
                    last = cur;
                }
            }
        });
    }

    /// Whether `hostname` (case-insensitive) is on the list. Hot-path callers
    /// pass lowercase names, so this only allocates when they do not.
    #[inline]
    pub fn exists(&self, hostname: &str) -> bool {
        let set = self.inner.load();
        if hostname.bytes().any(|b| b.is_ascii_uppercase()) {
            set.contains(&hostname.to_lowercase())
        } else {
            set.contains(hostname)
        }
    }

    /// Snapshot of every listed name.
    pub fn all_domains(&self) -> Vec<String> {
        self.inner.load().iter().cloned().collect()
    }
}

/// Parse the file format: one name per line, `#` starts a comment.
pub fn parse(raw: &str) -> Store {
    raw.lines()
        .map(|l| {
            l.split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .filter(|l| !l.is_empty())
        .collect()
}

fn read_file(path: &Path) -> anyhow::Result<Store> {
    if path.as_os_str().is_empty() {
        return Ok(HashSet::new());
    }
    if !path.exists() {
        warn!(
            "on-demand hosts: '{}' not found, starting with an empty list",
            path.display()
        );
        return Ok(HashSet::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read '{}': {}", path.display(), e))?;
    Ok(parse(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names_comments_and_case() {
        let s = parse(
            "# header\nShop.Example.com\n\n  blog.example.net.  # trailing\n#x.example.org\n",
        );
        assert_eq!(s.len(), 2);
        assert!(s.contains("shop.example.com"));
        assert!(s.contains("blog.example.net"));
    }

    #[test]
    fn empty_path_is_an_empty_list() {
        let l = HostList::load("");
        assert!(l.all_domains().is_empty());
        assert!(!l.exists("example.com"));
        assert!(l.reload());
    }
}
