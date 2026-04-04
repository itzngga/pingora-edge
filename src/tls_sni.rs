//! SNI-aware TLS certificate selection via BoringSSL's `TlsAcceptCallbacks`.
//!
//! At the start of each TLS handshake BoringSSL pauses and calls
//! `SniCertSelector::certificate_callback`. We read the client SNI, look up
//! the right cert from a lock-free `ArcSwap<HashMap>`, then inject it into
//! the connection via `ssl_use_certificate` + `ssl_use_private_key`.

use std::{
    collections::{HashMap, HashSet},
    fs,
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use tracing::info;

#[cfg(feature = "boringssl")]
use pingora_boringssl as tls_lib;
#[cfg(feature = "openssl")]
use pingora_openssl as tls_lib;

use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use tls_lib::{pkey::PKey, ssl::NameType, x509::X509};

use crate::config::{AcmeConfig, RouteConfig};

// ── Loaded cert bundle for one route ─────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct CertEntry {
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<tls_lib::pkey::Private>,
}

// ── PEM helpers ───────────────────────────────────────────────────────────────

pub(crate) fn load_cert_entry(cert_path: &str, key_path: &str) -> Result<CertEntry> {
    let cert_pem = fs::read(cert_path).with_context(|| format!("reading cert '{}'", cert_path))?;
    let key_pem = fs::read(key_path).with_context(|| format!("reading key '{}'", key_path))?;

    let mut certs = X509::stack_from_pem(&cert_pem)
        .with_context(|| format!("parsing cert PEM '{}'", cert_path))?;

    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in '{}'",
        cert_path
    );

    let leaf = certs.remove(0);
    let chain = certs;

    let key = PKey::private_key_from_pem(&key_pem)
        .with_context(|| format!("parsing key PEM '{}'", key_path))?;

    Ok(CertEntry { leaf, chain, key })
}

/// The key is the leaf's own: otherwise every handshake on it fails.
pub(crate) fn key_matches(entry: &CertEntry) -> bool {
    entry
        .leaf
        .public_key()
        .map(|pk| pk.public_eq(&entry.key))
        .unwrap_or(false)
}

/// A static route's pair, loaded and checked: what the SNI map serves.
fn load_route_entry(route: &RouteConfig) -> Result<CertEntry> {
    let (Some(cert), Some(key)) = (route.static_cert.as_deref(), route.static_key.as_deref())
    else {
        anyhow::bail!("static_cert and static_key must both be set");
    };
    let entry = load_cert_entry(cert, key)?;
    anyhow::ensure!(
        key_matches(&entry),
        "key '{}' does not match certificate '{}'",
        key,
        cert
    );
    Ok(entry)
}

/// Static-only mode's fallback: the first static-cert route whose pair loads and matches, else
/// the first whose pair merely loads (E303: an edge that booted before the key check still boots).
pub fn static_fallback(routes: &[RouteConfig]) -> Option<usize> {
    let mut loads_only = None;
    for (i, r) in routes
        .iter()
        .enumerate()
        .filter(|(_, r)| r.uses_static_cert())
    {
        let why = match r.static_cert.as_deref().zip(r.static_key.as_deref()) {
            None => "static_cert and static_key must both be set".to_string(),
            Some((cert, key)) => match load_cert_entry(cert, key) {
                Ok(e) if key_matches(&e) => return Some(i),
                Ok(_) => {
                    loads_only = loads_only.or(Some(i));
                    format!("key '{}' does not match certificate '{}'", key, cert)
                }
                Err(e) => format!("{:#}", e),
            },
        };
        tracing::error!(
            "CertRegistry: route '{}' cannot be the static fallback: {}",
            r.name,
            why
        );
    }
    if let Some(r) = loads_only.and_then(|i| routes.get(i)) {
        tracing::error!(
            "CertRegistry: E303 no static pair matches its key — route '{}' is the fallback anyway; handshakes on it fail until its key matches",
            r.name
        );
    }
    loads_only
}

/// `proxy --check`'s view of a cert/key pair: why it cannot serve, else its SANs and days left.
pub(crate) enum PairFault {
    Unloadable(String),
    KeyMismatch,
}

pub(crate) struct PairProbe {
    pub fault: Option<PairFault>,
    pub sans: Vec<String>,
    pub days_left: Option<i64>,
}

pub(crate) fn probe_pair(cert_path: &str, key_path: &str) -> PairProbe {
    let entry = match load_cert_entry(cert_path, key_path) {
        Ok(e) => e,
        Err(e) => {
            return PairProbe {
                fault: Some(PairFault::Unloadable(format!("{:#}", e))),
                sans: Vec::new(),
                days_left: None,
            }
        }
    };
    let matches = key_matches(&entry);
    let sans = entry
        .leaf
        .subject_alt_names()
        .map(|s| {
            s.iter()
                .filter_map(|g| g.dnsname().map(str::to_ascii_lowercase))
                .collect()
        })
        .unwrap_or_default();
    let days_left = fs::read_to_string(cert_path)
        .ok()
        .map(|pem| crate::on_demand::days_until_expiry(&pem));
    PairProbe {
        fault: (!matches).then_some(PairFault::KeyMismatch),
        sans,
        days_left,
    }
}

// ── SNI callback (implements Pingora's TlsAccept) ─────────────────────────────

type CertMap = HashMap<String, CertEntry>;

struct SniCertSelector {
    map: ArcSwap<CertMap>,
    fallback: ArcSwap<CertEntry>,
    /// Pre-built set of known hostnames for fast O(1) lookup.
    known: ArcSwap<std::collections::HashSet<String>>,
}

impl SniCertSelector {
    async fn apply(&self, ssl: &mut TlsRef) {
        let map_guard = self.map.load();
        let fallback_guard = self.fallback.load();

        // Lookup without allocating: SNI is almost always lowercase already
        // (map keys are lowercased at build time).
        let entry = {
            match ssl.servername(NameType::HOST_NAME) {
                Some(s) if !s.bytes().any(|b| b.is_ascii_uppercase()) => map_guard.get(s),
                Some(s) => map_guard.get(&s.to_ascii_lowercase()),
                None => None,
            }
        }
        .unwrap_or_else(|| &**fallback_guard);

        if let Err(e) = tls_lib::ext::ssl_use_certificate(ssl, &entry.leaf) {
            tracing::error!("ssl_use_certificate failed: {}", e);
            return;
        }
        if let Err(e) = tls_lib::ext::ssl_use_private_key(ssl, &entry.key) {
            tracing::error!("ssl_use_private_key failed: {}", e);
            return;
        }
        for cert in &entry.chain {
            if let Err(e) = tls_lib::ext::ssl_add_chain_cert(ssl, cert) {
                tracing::warn!("ssl_add_chain_cert failed: {}", e);
            }
        }
    }
}

#[async_trait]
impl TlsAccept for SniCertSelector {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        self.apply(ssl).await
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Holds all loaded certificates and vends a `TlsAcceptCallbacks` for Pingora.
/// Clone is cheap — all inner state is `Arc`.
#[derive(Clone)]
pub struct CertRegistry {
    selector: Arc<SniCertSelector>,
    routes: Arc<ArcSwap<Vec<RouteConfig>>>,
    acme_cfg: Arc<AcmeConfig>,
    /// Serialises reload() and commit(): a renewal never publishes a map for a route set a commit replaced.
    writer: Arc<Mutex<()>>,
}

/// A route set whose static certs all loaded and match their keys, ready to publish.
pub struct Prepared {
    routes: Vec<RouteConfig>,
    map: CertMap,
    known: HashSet<String>,
}

impl CertRegistry {
    pub fn build(routes: &[RouteConfig], acme: &AcmeConfig) -> Result<Self> {
        let fallback = load_cert_entry(&acme.cert_path(), &acme.key_path())
            .context("loading ACME SAN bundle")?;
        info!("CertRegistry: ACME bundle loaded ({})", acme.cert_path());

        let (map, known) = build_map(routes);

        Ok(Self::assemble(routes, fallback, map, known, acme.clone()))
    }

    fn assemble(
        routes: &[RouteConfig],
        fallback: CertEntry,
        map: CertMap,
        known: HashSet<String>,
        acme: AcmeConfig,
    ) -> Self {
        Self {
            selector: Arc::new(SniCertSelector {
                map: ArcSwap::from_pointee(map),
                fallback: ArcSwap::new(Arc::new(fallback)),
                known: ArcSwap::from_pointee(known),
            }),
            routes: Arc::new(ArcSwap::from_pointee(routes.to_vec())),
            acme_cfg: Arc::new(acme),
            writer: Arc::new(Mutex::new(())),
        }
    }

    pub fn build_static_only(
        routes: &[RouteConfig],
        fallback_cert: &str,
        fallback_key: &str,
    ) -> Result<Self> {
        let fallback = load_cert_entry(fallback_cert, fallback_key)
            .with_context(|| format!("loading fallback cert '{}'", fallback_cert))?;
        info!(
            "CertRegistry: static-only mode, fallback = '{}'",
            fallback_cert
        );

        let (map, known) = build_map(routes);

        let dummy_acme = AcmeConfig {
            email: String::new(),
            provider: String::new(),
            eab_kid: String::new(),
            eab_hmac: String::new(),
            storage: String::new(),
        };

        Ok(Self::assemble(routes, fallback, map, known, dummy_acme))
    }

    /// Returns `true` if `host` (already lowercased) is a named route host.
    /// Used by the combined selector in main.rs to decide which resolver wins.
    pub fn has_host(&self, host: &str) -> bool {
        self.selector.known.load().contains(host)
    }

    /// Apply the certificate for `ssl` directly (called by combined selector).
    pub async fn tls_callbacks_inner(&self, ssl: &mut TlsRef) {
        self.selector.apply(ssl).await
    }

    /// Reload every cert from disk. ATOMIC: everything is parsed BEFORE anything is
    /// swapped, so a half-written PEM (a renewal caught mid-copy) leaves the live
    /// certs untouched instead of publishing a broken fallback and then bailing.
    ///
    /// A route that was serving its own cert and now fails to load (or to match its
    /// key) fails the whole reload, as before; one that never loaded stays on the
    /// fallback cert without blocking the other routes' renewals.
    pub fn reload(&self) -> Result<()> {
        let _w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let new_fallback = if self.acme_cfg.storage.is_empty() {
            None
        } else {
            Some(
                load_cert_entry(&self.acme_cfg.cert_path(), &self.acme_cfg.key_path())
                    .context("reloading ACME bundle")?,
            )
        };
        let cur = self.selector.map.load_full();
        let (new_map, new_known) =
            build_map_inner(&self.routes.load_full(), false, OnFail::KeepServing(&cur))?;

        if let Some(fb) = new_fallback {
            self.selector.fallback.store(Arc::new(fb));
        }
        self.selector.map.store(Arc::new(new_map));
        self.selector.known.store(Arc::new(new_known));
        info!("CertRegistry reloaded");
        Ok(())
    }

    /// Load and check every static cert of `routes` without touching what is served.
    /// Any unusable pair is an error: a new route set is published whole or not at all.
    pub fn prepare(routes: &[RouteConfig]) -> Result<Prepared> {
        let (map, known) = build_map_inner(routes, false, OnFail::Refuse)?;
        Ok(Prepared {
            routes: routes.to_vec(),
            map,
            known,
        })
    }

    /// Publish a prepared route set (stores only).
    pub fn commit(&self, p: Prepared) {
        let _w = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        self.routes.store(Arc::new(p.routes));
        self.selector.map.store(Arc::new(p.map));
        self.selector.known.store(Arc::new(p.known));
    }

    /// Every distinct file this registry serves from: each route's static cert/key
    /// pair, plus the ACME SAN bundle when one is configured. Follows the live route set.
    fn watched_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = Vec::new();
        for route in self.routes.load_full().iter() {
            if !route.uses_static_cert() {
                continue;
            }
            if let Some(c) = route.static_cert.as_deref() {
                paths.push(c.to_string());
            }
            if let Some(k) = route.static_key.as_deref() {
                paths.push(k.to_string());
            }
        }
        if !self.acme_cfg.storage.is_empty() {
            paths.push(self.acme_cfg.cert_path());
            paths.push(self.acme_cfg.key_path());
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// Hot-reload static certs when they change on disk.
    ///
    /// WHY THIS EXISTS: `reload()` used to be reachable only from the ACME renewal
    /// callback, which `main.rs` spawns only when `acme_hosts()` is non-empty. A
    /// config where EVERY named route carries a `static_cert` (the CF-fronted
    /// deployment) has no ACME hosts at all — so nothing ever called `reload()` and
    /// the certs parsed at boot were served for the entire life of the process.
    /// Renewing cert.pem on disk changed nothing until someone restarted the proxy;
    /// at expiry every CF-fronted domain started failing TLS. Polling mtime+len
    /// makes an on-disk renewal take effect on its own, whatever wrote it.
    pub fn spawn_file_watcher(&self, interval: std::time::Duration) {
        let this = self.clone();
        tokio::spawn(async move {
            // The path set is re-read every tick: a committed route set can add or drop certs.
            // Stats and PEM reads run off the runtime that also serves the :443 pre-filter.
            let sample = |reg: CertRegistry| async move {
                tokio::task::spawn_blocking(move || {
                    let routes = reg.routes.load_full();
                    let stamps: Vec<_> = reg
                        .watched_paths()
                        .into_iter()
                        .map(|p| {
                            let st = std::fs::metadata(&p)
                                .ok()
                                .map(|m| (m.modified().ok(), m.len()));
                            (p, st)
                        })
                        .collect();
                    (stamps, routes)
                })
                .await
                .ok()
            };
            // A commit loaded its certs before publishing; a renewal in between is caught by re-reading once.
            let Some((mut last, mut last_routes)) = sample(this.clone()).await else {
                return;
            };
            info!(
                "CertRegistry: watching {} cert file(s) for on-disk renewal every {:?}",
                last.len(),
                interval
            );
            loop {
                tokio::time::sleep(interval).await;
                let Some((cur, routes)) = sample(this.clone()).await else {
                    continue;
                };
                if cur == last && Arc::ptr_eq(&routes, &last_routes) {
                    continue;
                }

                let reg = this.clone();
                let res = tokio::task::spawn_blocking(move || reg.reload())
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("reload task: {}", e)));
                match res {
                    Ok(()) => {
                        // Only commit the new stamps on success — a failed reload
                        // (partial write) is retried on the next tick instead of
                        // being latched as "already handled".
                        last = cur;
                        last_routes = routes;
                        info!("CertRegistry: cert file(s) changed on disk — hot-reloaded, no restart needed");
                    }
                    Err(e) => tracing::warn!(
                        "CertRegistry: on-disk cert change failed to load — keeping previous certs, retrying: {}",
                        e
                    ),
                }
            }
        });
    }

    /// Periodic expiry audit. An edge that silently serves an expired cert is the
    /// worst failure mode there is: every visitor gets a browser interstitial while
    /// the logs stay clean. This makes it loud BEFORE it breaks.
    pub fn spawn_expiry_watchdog(&self, interval: std::time::Duration) {
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let paths: Vec<String> = this
                    .watched_paths()
                    .into_iter()
                    .filter(|p| !p.ends_with(".key"))
                    .collect();
                for p in &paths {
                    let Ok(pem) = std::fs::read_to_string(p) else {
                        tracing::error!(
                            "cert watchdog: '{}' is unreadable — TLS for its routes will fail",
                            p
                        );
                        continue;
                    };
                    let days = crate::on_demand::days_until_expiry(&pem);
                    if days <= 0 {
                        tracing::error!(
                            "cert watchdog: '{}' HAS EXPIRED ({}d) — CF-fronted domains on it are failing TLS now; renew it on disk (auto-reloads)",
                            p, days
                        );
                    } else if days <= 14 {
                        tracing::warn!("cert watchdog: '{}' expires in {} day(s)", p, days);
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
    }
}

// ── Internal loader ───────────────────────────────────────────────────────────

/// What a route whose pair does not load (or match) does to the build.
enum OnFail<'a> {
    /// Boot: its hosts get the fallback cert; the rest of the edge comes up.
    Skip,
    /// reload(): fail if it was serving its own cert (keep the live one), else stay on the fallback.
    KeepServing(&'a CertMap),
    /// prepare(): fail.
    Refuse,
}

/// Boot build: never fails; an unusable route is reported and served the fallback cert.
fn build_map(routes: &[RouteConfig]) -> (CertMap, HashSet<String>) {
    build_map_inner(routes, true, OnFail::Skip).unwrap_or_default()
}

fn build_map_inner(
    routes: &[RouteConfig],
    verbose: bool,
    on_fail: OnFail<'_>,
) -> Result<(CertMap, HashSet<String>)> {
    let mut map: CertMap = HashMap::new();
    let mut known: HashSet<String> = HashSet::new();

    for route in routes {
        // `ignore_ssl` routes have a static_cert set but are skipped on purpose —
        // don't load it (can't crash on a missing/broken file), fall back below.
        if !route.uses_static_cert() {
            continue;
        }

        let cert_path = route.static_cert.as_deref().unwrap_or("");

        let entry = match load_route_entry(route) {
            Ok(e) => e,
            Err(e) => {
                let serving = |cur: &CertMap| {
                    route
                        .hosts
                        .iter()
                        .any(|h| cur.contains_key(&h.to_lowercase()))
                };
                match on_fail {
                    OnFail::Refuse => {
                        return Err(
                            e.context(format!("loading static cert for route '{}'", route.name))
                        );
                    }
                    OnFail::KeepServing(cur) if serving(cur) => {
                        return Err(
                            e.context(format!("loading static cert for route '{}'", route.name))
                        );
                    }
                    OnFail::Skip | OnFail::KeepServing(_) => {
                        tracing::error!(
                            "CertRegistry: route '{}' static cert unusable — its hosts get the fallback cert: {:#}",
                            route.name, e
                        );
                    }
                }
                for host in route.hosts.iter().filter(|h| *h != "*") {
                    known.insert(host.to_lowercase());
                }
                continue;
            }
        };

        for host in &route.hosts {
            if host == "*" {
                continue;
            }
            let host_lc = host.to_lowercase();
            let prev = map.insert(host_lc.clone(), entry.clone());
            known.insert(host_lc.clone());
            if prev.is_some() {
                tracing::warn!(
                    "CertRegistry: host '{}' remapped — route '{}' wins",
                    host,
                    route.name
                );
            }
            if verbose {
                info!(
                    "CertRegistry: '{}' → static cert '{}' (route '{}')",
                    host, cert_path, route.name
                );
            }
        }
    }

    // Hosts that don't contribute their own cert to `map` (ACME routes + ignore_ssl
    // routes) still get registered in `known` so CertRegistry claims them and serves
    // the fallback cert — this keeps them off the on-demand ACME path.
    for route in routes {
        if route.uses_static_cert() {
            continue;
        }
        for host in &route.hosts {
            if host != "*" {
                let host_lc = host.to_lowercase();
                known.insert(host_lc.clone());
                if verbose {
                    if route.ignore_ssl {
                        info!(
                            "CertRegistry: '{}' → fallback cert, SSL ignored (route '{}')",
                            host, route.name
                        );
                    } else {
                        info!(
                            "CertRegistry: '{}' → ACME bundle (route '{}')",
                            host, route.name
                        );
                    }
                }
            }
        }
    }

    Ok((map, known))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_self_signed(dir: &std::path::Path, tag: &str, cn: &str) -> (String, String) {
        use rcgen::{
            CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
        };
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
        params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, cn);
            dn
        };
        let cert_pem = params.self_signed(&kp).unwrap().pem();
        let key_pem = kp.serialize_pem();

        let cp = dir.join(format!("{}.pem", tag));
        let kpth = dir.join(format!("{}.key", tag));
        std::fs::write(&cp, cert_pem).unwrap();
        std::fs::write(&kpth, key_pem).unwrap();
        (
            cp.to_string_lossy().into_owned(),
            kpth.to_string_lossy().into_owned(),
        )
    }

    fn route_with_cert(cert: &str, key: &str) -> RouteConfig {
        let src = format!(
            r#"
            name = "cf-route"
            hosts = ["example.test"]
            upstream = "127.0.0.1:8231"
            static_cert = "{}"
            static_key  = "{}"
            "#,
            cert.replace('\\', "\\\\"),
            key.replace('\\', "\\\\")
        );
        toml::from_str(&src).unwrap()
    }

    fn served_cn(reg: &CertRegistry, host: &str) -> String {
        let map = reg.selector.map.load();
        let entry = map.get(host).expect("host not in cert map");
        entry
            .leaf
            .subject_name()
            .entries()
            .next()
            .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// REGRESSION: renewing a static cert on disk must take effect without a restart.
    ///
    /// `reload()` was only ever called from the ACME renewal callback, which
    /// `main.rs` spawns only when `acme_hosts()` is non-empty. In the CF deployment
    /// every route carries a `static_cert`, so there are no ACME hosts and nothing
    /// called `reload()` for the entire life of the process — the boot certs were
    /// served until they expired and every CF-fronted domain then failed TLS.
    #[test]
    fn reload_picks_up_a_renewed_cert_on_disk() {
        let dir = std::env::temp_dir().join(format!("edge-certs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (cp, kp) = write_self_signed(&dir, "live", "old.example.test");
        let routes = vec![route_with_cert(&cp, &kp)];
        let reg = CertRegistry::build_static_only(&routes, &cp, &kp).unwrap();
        assert_eq!(served_cn(&reg, "example.test"), "old.example.test");

        // Renewal: same paths, new material (what certbot or acme.sh does).
        let (cp2, kp2) = write_self_signed(&dir, "renewed", "new.example.test");
        std::fs::copy(&cp2, &cp).unwrap();
        std::fs::copy(&kp2, &kp).unwrap();

        reg.reload().unwrap();
        assert_eq!(
            served_cn(&reg, "example.test"),
            "new.example.test",
            "reload() did not pick up the renewed cert"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A half-written PEM must leave the live certs untouched, and the next
    /// (complete) write must still be picked up — the watcher retries because it
    /// only commits its mtime stamps on a successful reload.
    #[test]
    fn a_partial_write_does_not_break_the_live_certs() {
        let dir = std::env::temp_dir().join(format!("edge-certs-partial-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (cp, kp) = write_self_signed(&dir, "live", "good.example.test");
        let routes = vec![route_with_cert(&cp, &kp)];
        let reg = CertRegistry::build_static_only(&routes, &cp, &kp).unwrap();

        std::fs::write(&cp, "-----BEGIN CERTIFICATE-----\ntruncated").unwrap();
        assert!(
            reg.reload().is_err(),
            "a truncated PEM should fail the reload"
        );
        assert_eq!(
            served_cn(&reg, "example.test"),
            "good.example.test",
            "a failed reload must not disturb the certs already being served"
        );

        let (cp2, kp2) = write_self_signed(&dir, "renewed", "fresh.example.test");
        std::fs::copy(&cp2, &cp).unwrap();
        std::fs::copy(&kp2, &kp).unwrap();
        reg.reload().unwrap();
        assert_eq!(served_cn(&reg, "example.test"), "fresh.example.test");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The watcher itself: change the file, change nothing else, and the registry
    /// should converge on its own.
    #[tokio::test]
    async fn file_watcher_hot_reloads_without_a_restart() {
        let dir = std::env::temp_dir().join(format!("edge-certs-watch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (cp, kp) = write_self_signed(&dir, "live", "before.example.test");
        let routes = vec![route_with_cert(&cp, &kp)];
        let reg = CertRegistry::build_static_only(&routes, &cp, &kp).unwrap();
        reg.spawn_file_watcher(std::time::Duration::from_millis(50));
        // Let the watcher task actually run and record its baseline stamps before
        // the files change underneath it — nothing has polled the reactor yet.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let (cp2, kp2) = write_self_signed(&dir, "renewed", "after.example.test");
        std::fs::copy(&cp2, &cp).unwrap();
        std::fs::copy(&kp2, &kp).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if served_cn(&reg, "example.test") == "after.example.test" {
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        panic!("file watcher never hot-reloaded the renewed cert");
    }
}
