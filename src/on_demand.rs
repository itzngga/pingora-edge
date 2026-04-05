//! on_demand.rs: per-SNI ACME certificate issuance at handshake time.
//!
//! Key behaviours:
//!
//! * SNI not on any allowlist: the self-signed fallback cert, no ACME order.
//! * SNI on the on-demand host list (host_list.rs) or an ACME route: load the
//!   cert from disk or issue it, cache it for 15 min in RAM.
//! * A first handshake waits at most 800 ms for a fresh order, then gets the
//!   fallback while the order finishes in the background.
//! * Failed issuance: 1 h cooldown.
//! * Singleflight: only one ACME order per SNI at a time.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use moka::sync::Cache;
use tracing::{info, warn};

#[cfg(feature = "boringssl")]
use pingora_boringssl as tls_lib;
#[cfg(feature = "openssl")]
use pingora_openssl as tls_lib;

use pingora_core::protocols::tls::TlsRef;
use tls_lib::{pkey::PKey, ssl::NameType, x509::X509};

use crate::{
    acme::{issue_cert, TokenStore},
    config::{AcmeConfig, RouteConfig},
    host_list::HostList,
};

// ── Constants ─────────────────────────────────────────────────────────────────

const CERT_CACHE_TTL: Duration = Duration::from_secs(15 * 60); // 15 min
const UNKNOWN_SNI_MAX_ATT: u32 = 3;
const UNKNOWN_SNI_COUNTER_TTL: Duration = Duration::from_secs(5 * 60);
const FAILURE_COOLDOWN: Duration = Duration::from_secs(60 * 60); // 1 h
const ACME_ISSUE_TIMEOUT: Duration = Duration::from_millis(800);
/// Renew once a cert has this many days left. Matches the sweeper's threshold so
/// the handshake path and the background sweep agree on what "due" means.
const RENEW_BEFORE_DAYS: i64 = 30;

// ── Cached cert entry ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct CachedCert {
    pub leaf: X509,
    pub chain: Vec<X509>,
    pub key: PKey<tls_lib::pkey::Private>,
}

// ── SNI attempt tracker ───────────────────────────────────────────────────────
//
// moka instead of Mutex<HashMap>: the old version did an O(n) retain under a
// global lock on every unknown-SNI handshake and grew unboundedly under
// random-subdomain floods. Capacity follows the host RAM (tuning.rs).

struct SniAttemptTracker {
    entries: Cache<String, Arc<AtomicU32>>,
}

impl SniAttemptTracker {
    fn new() -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(crate::tuning::TUNING.abuse_cache_entries)
                .time_to_live(UNKNOWN_SNI_COUNTER_TTL)
                .build(),
        }
    }

    fn should_attempt(&self, sni: &str) -> bool {
        let counter = self
            .entries
            .get_with(sni.to_string(), || Arc::new(AtomicU32::new(0)));
        counter.fetch_add(1, Ordering::Relaxed) < UNKNOWN_SNI_MAX_ATT
    }
}

// ── Failure cooldown map ──────────────────────────────────────────────────────

struct FailureCooldown {
    inner: Cache<String, ()>,
}

impl FailureCooldown {
    fn new() -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(FAILURE_COOLDOWN)
                .build(),
        }
    }

    fn is_cooling_down(&self, sni: &str) -> bool {
        self.inner.contains_key(sni)
    }

    fn mark(&self, sni: &str) {
        self.inner.insert(sni.to_string(), ());
    }

    fn clear(&self, sni: &str) {
        self.inner.invalidate(sni);
    }
}

// ── In-memory cert cache ──────────────────────────────────────────────────────

struct CertCache {
    inner: Cache<String, CachedCert>,
}

impl CertCache {
    fn new() -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(CERT_CACHE_TTL)
                .build(),
        }
    }

    fn get(&self, sni: &str) -> Option<CachedCert> {
        self.inner.get(sni)
    }

    fn insert(&self, sni: &str, cert: CachedCert) {
        self.inner.insert(sni.to_string(), cert);
    }

    /// Drop the RAM copy so the next handshake re-reads the (freshly renewed) file
    /// instead of serving the superseded cert for the rest of CERT_CACHE_TTL.
    fn invalidate(&self, sni: &str) {
        self.inner.invalidate(sni);
    }
}

// ── Singleflight ─────────────────────────────────────────────────────────────

struct Inflight {
    set: Mutex<std::collections::HashSet<String>>,
}

impl Inflight {
    fn new() -> Self {
        Self {
            set: Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn try_acquire(&self, sni: &str) -> bool {
        // Recover from a poisoned lock instead of reporting "already in flight"
        // forever. The old `Err(_) => false` was permanent and silent: one panic
        // anywhere near this mutex and NO domain could ever acquire the
        // singleflight slot again, so on-demand issuance stopped process-wide with
        // nothing in the log. The guarded data is a HashSet of hostnames — there is
        // no invariant a panic could have broken, so recovering is safe.
        let mut set = self.set.lock().unwrap_or_else(|e| e.into_inner());
        set.insert(sni.to_string())
    }

    fn release(&self, sni: &str) {
        let mut set = self.set.lock().unwrap_or_else(|e| e.into_inner());
        set.remove(sni);
    }
}

/// RAII release for an `Inflight` slot. Held by the spawned ACME task so the slot
/// is freed even if issuance panics — a leaked slot silently disables renewal for
/// that domain until the process restarts.
struct InflightGuard {
    inflight: Arc<Inflight>,
    sni: String,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inflight.release(&self.sni);
    }
}

// ── Fallback self-signed cert ─────────────────────────────────────────────────

fn generate_fallback_cert() -> Result<CachedCert> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, crate::acme::FALLBACK_CN);
        dn.push(DnType::OrganizationName, env!("CARGO_PKG_NAME"));
        dn
    };

    let cert_pem = params.self_signed(&key_pair)?.pem();
    let key_pem = key_pair.serialize_pem();

    parse_pem_to_cached(&cert_pem, &key_pem)
}

fn parse_pem_to_cached(cert_pem: &str, key_pem: &str) -> Result<CachedCert> {
    let mut certs = X509::stack_from_pem(cert_pem.as_bytes()).context("parse cert PEM")?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in PEM");

    let leaf = certs.remove(0);
    let chain = certs;
    let key = PKey::private_key_from_pem(key_pem.as_bytes()).context("parse key PEM")?;

    Ok(CachedCert { leaf, chain, key })
}

/// Returns the parsed cert plus how many days it has left, so the caller can decide
/// on renewal without reading the file a second time on the handshake path.
fn load_cached_from_disk(cert_path: &Path, key_path: &Path) -> Result<(CachedCert, i64)> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("read '{}'", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("read '{}'", key_path.display()))?;
    let cached = parse_pem_to_cached(&cert_pem, &key_pem)?;
    Ok((cached, days_until_expiry(&cert_pem)))
}

fn cert_path_for(storage: &str, sni: &str) -> PathBuf {
    Path::new(storage).join(format!("{}.crt", sni))
}

fn key_path_for(storage: &str, sni: &str) -> PathBuf {
    Path::new(storage).join(format!("{}.key", sni))
}

pub(crate) fn days_until_expiry(cert_pem: &str) -> i64 {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::parse_x509_certificate;

    let Ok((_, pem)) = parse_x509_pem(cert_pem.as_bytes()) else {
        return 0;
    };
    let Ok((_, cert)) = parse_x509_certificate(&pem.contents) else {
        return 0;
    };

    let expiry = cert.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();
    (expiry - now) / 86_400
}

// ── Main resolver ─────────────────────────────────────────────────────────────

pub struct OnDemandResolver {
    hosts: HostList,
    acme_cfg: Arc<AcmeConfig>,
    tokens: TokenStore,
    cache: Arc<CertCache>,
    pub fallback: CachedCert,
    sni_tracker: Arc<SniAttemptTracker>,
    cooldown: Arc<FailureCooldown>,
    inflight: Arc<Inflight>,

    /// Static allowlist half: the `hosts` of every ACME-managed route
    /// (pre-lowercased). The other half is the live on-demand host list,
    /// hot-reloaded from its file. A SNI must be in one of the two to get a
    /// cert; anything else gets the fallback cert and no ACME order. Both are
    /// bounded operator allowlists, so pointing many names at the edge and
    /// probing random subdomains cannot trigger an ACME order per name. The
    /// sni_tracker and cooldown back that up. Swapped by set_route_hosts when
    /// the route set changes.
    allowed_hosts: ArcSwap<HashSet<String>>,

    /// Hosts owned by CertRegistry (static-cert or `ignore_ssl` routes). These are
    /// claimed before this resolver is consulted, so they are never ACME-issued:
    /// a CDN may front their origin and the challenge would never complete.
    /// Kept apart from `allowed_hosts` because the renewal sweeper walks the
    /// on-demand list minus these, not the route allowlist.
    static_hosts: ArcSwap<HashSet<String>>,
}

/// (allowed_hosts, static_hosts) for a route set; see the fields.
pub(crate) fn route_host_sets(routes: &[RouteConfig]) -> (HashSet<String>, HashSet<String>) {
    // Every host across every route, lowercased. Wildcard `*` is ignored here —
    // wildcards are already rejected by config validation, so we shouldn't see
    // them, but skipping them defensively is free.
    let mut allowed_hosts: HashSet<String> = HashSet::new();
    let mut static_hosts: HashSet<String> = HashSet::new();
    for route in routes {
        // Only ACME-path route hosts belong in the issue allowlist. A route with
        // a static cert is served by CertRegistry and needs no ACME; `ignore_ssl`
        // opts out entirely. Both are excluded here, otherwise the background
        // sweeper would try to issue for a CDN-fronted host that also appears on
        // the on-demand list, and that order would only time out.
        let set = if route.has_static_cert() || route.ignore_ssl {
            &mut static_hosts
        } else {
            &mut allowed_hosts
        };
        for host in route.hosts.iter().filter(|h| *h != "*") {
            set.insert(host.to_lowercase());
        }
    }
    (allowed_hosts, static_hosts)
}

impl OnDemandResolver {
    pub fn new(
        hosts: HostList,
        acme_cfg: AcmeConfig,
        tokens: TokenStore,
        routes: &[RouteConfig],
    ) -> Result<Self> {
        let fallback = generate_fallback_cert().context("generating fallback cert")?;
        info!("on-demand TLS: fallback self-signed cert ready");

        // Build the SNI allowlist from configured routes.
        let (allowed_hosts, static_hosts) = route_host_sets(routes);
        info!(
            "on-demand TLS: route allowlist has {} host(s): {:?}",
            allowed_hosts.len(),
            allowed_hosts
        );

        let cache = Arc::new(CertCache::new());

        Ok(Self {
            hosts,
            acme_cfg: Arc::new(acme_cfg),
            tokens,
            cache,
            fallback,
            sni_tracker: Arc::new(SniAttemptTracker::new()),
            cooldown: Arc::new(FailureCooldown::new()),
            inflight: Arc::new(Inflight::new()),
            allowed_hosts: ArcSwap::from_pointee(allowed_hosts),
            static_hosts: ArcSwap::from_pointee(static_hosts),
        })
    }

    /// Follow a new route set (sets from route_host_sets): its ACME hosts join the allowlist,
    /// its static hosts are never issued.
    pub fn set_route_hosts(&self, (allowed, statics): (HashSet<String>, HashSet<String>)) {
        self.allowed_hosts.store(Arc::new(allowed));
        self.static_hosts.store(Arc::new(statics));
    }

    // ── Control API surface (read by the unix-socket control server) ──────────

    /// The live on-demand host list the resolver will issue certs for.
    pub fn on_demand_domains(&self) -> Vec<String> {
        self.hosts.all_domains()
    }

    /// Per-SNI cert state for the control API: (has_cert_on_disk, days_until_expiry, cooling_down).
    /// Disk is ground truth — a cert file means the domain can serve TLS now.
    pub fn cert_status(&self, sni: &str) -> (bool, Option<i64>, bool) {
        let sni_lc = sni.to_lowercase();
        let cooling = self.cooldown.is_cooling_down(&sni_lc);
        let cert_path = cert_path_for(&self.acme_cfg.storage, &sni_lc);
        if cert_path.exists() {
            let days = std::fs::read_to_string(&cert_path)
                .ok()
                .map(|pem| days_until_expiry(&pem));
            return (true, days, cooling);
        }
        (false, None, cooling)
    }

    /// Count of issued certs on disk (the ACME storage dir), for the summary card.
    pub fn issued_count(&self) -> usize {
        std::fs::read_dir(&self.acme_cfg.storage)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().map(|x| x == "crt").unwrap_or(false))
                    .count()
            })
            .unwrap_or(0)
    }

    pub async fn certificate_callback_inner(&self, ssl: &mut TlsRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        // Allowlist = the ACME route hosts (allowed_hosts) OR the live on-demand
        // list (an ArcSwap, so file reloads apply with no restart). Both are
        // bounded, operator-controlled allowlists, so a random-subdomain flood
        // cannot start ACME orders; the sni_tracker and cooldown are the second
        // line for anything that slips past.
        if sni.is_empty() || (!self.allowed_hosts.load().contains(&sni) && !self.hosts.exists(&sni))
        {
            if self.sni_tracker.should_attempt(&sni) {
                apply_cert_entry(ssl, &self.fallback);
                return;
            }
            return;
        }

        let entry = self.resolve(&sni).await;
        apply_cert_entry(ssl, &entry);
    }

    // ── Warmup (called by the control API) ───────────────────────────────────

    pub async fn warmup_domain(&self, sni: &str) -> Result<()> {
        let sni_lc = sni.to_lowercase();
        // Same allowlist as the TLS callback path: ACME route hosts OR the live
        // on-demand list. Without it, a control API caller could start an ACME
        // order for any name.
        if !self.allowed_hosts.load().contains(&sni_lc) && !self.hosts.exists(&sni_lc) {
            warn!(
                "on-demand TLS: warmup rejected for {:?} (not in allowlist)",
                sni
            );
            return Ok(());
        }
        let sni_owned = sni_lc;

        if !self.inflight.try_acquire(&sni_owned) {
            return Ok(());
        }

        let acme_cfg = Arc::clone(&self.acme_cfg);
        let tokens = self.tokens.clone();
        let cache = Arc::clone(&self.cache);
        let inflight = Arc::clone(&self.inflight);
        let cooldown = Arc::clone(&self.cooldown);

        tokio::spawn(async move {
            let _guard = InflightGuard {
                inflight,
                sni: sni_owned.clone(),
            };

            let _ = std::fs::create_dir_all(&acme_cfg.storage);
            match issue_cert(&acme_cfg, std::slice::from_ref(&sni_owned), &tokens).await {
                Ok(bundle) => {
                    cooldown.clear(&sni_owned);
                    let cp = cert_path_for(&acme_cfg.storage, &sni_owned);
                    let kp = key_path_for(&acme_cfg.storage, &sni_owned);
                    let _ = std::fs::write(&cp, &bundle.cert_pem);
                    let _ = std::fs::write(&kp, &bundle.key_pem);

                    if let Ok(cached) = parse_pem_to_cached(&bundle.cert_pem, &bundle.key_pem) {
                        cache.insert(&sni_owned, cached);
                        info!("on-demand TLS: warmup issued {}", sni_owned);
                    }
                }
                Err(e) => {
                    warn!("on-demand TLS: warmup failed for {}: {}", sni_owned, e);
                    cooldown.mark(&sni_owned);
                }
            }
        });

        Ok(())
    }

    // ── Background renewal sweep ─────────────────────────────────────────────

    pub fn start_background_sweeper(self: Arc<Self>) {
        // No cache-eviction task needed — moka evicts by TTL on its own.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut interval = tokio::time::interval(Duration::from_secs(6 * 3600)); // Every 6 hours

            loop {
                interval.tick().await;
                let domains = self.hosts.all_domains();
                let _ = std::fs::create_dir_all(&self.acme_cfg.storage);

                let total = domains.len();
                let mut renewed = 0usize;
                let mut failed = 0usize;

                for domain in domains {
                    // Must mirror `resolve()`, which serves a domain that is
                    // EITHER an ACME route host OR on the on-demand list.
                    //
                    // Testing `allowed_hosts` alone would skip everything when
                    // every named route carries a static cert (allowed_hosts is
                    // then empty), and on-demand certs would quietly expire.
                    //
                    // CertRegistry claims `static_hosts` before this resolver is
                    // consulted, so those are the only ones to skip.
                    if self.static_hosts.load().contains(&domain) {
                        continue;
                    }
                    if !self.allowed_hosts.load().contains(&domain) && !self.hosts.exists(&domain) {
                        continue;
                    }

                    let cp = cert_path_for(&self.acme_cfg.storage, &domain);
                    let kp = key_path_for(&self.acme_cfg.storage, &domain);

                    let mut needs_renewal = true;

                    if cp.exists() && kp.exists() {
                        if let Ok(pem) = std::fs::read_to_string(&cp) {
                            if days_until_expiry(&pem) > 30 {
                                needs_renewal = false;
                            }
                        }
                    }

                    if needs_renewal {
                        if self.cooldown.is_cooling_down(&domain) {
                            continue;
                        }
                        if !self.inflight.try_acquire(&domain) {
                            continue;
                        }

                        info!("Background ACME: issuing/renewing {}", domain);
                        let acme_cfg = Arc::clone(&self.acme_cfg);
                        let tokens = self.tokens.clone();
                        let domain_clone = domain.clone();
                        let cooldown = Arc::clone(&self.cooldown);

                        match issue_cert(&acme_cfg, std::slice::from_ref(&domain_clone), &tokens)
                            .await
                        {
                            Ok(bundle) => {
                                let _ = std::fs::write(&cp, &bundle.cert_pem);
                                let _ = std::fs::write(&kp, &bundle.key_pem);
                                cooldown.clear(&domain_clone);
                                // Drop the in-RAM copy so the next handshake picks
                                // up the fresh cert instead of serving the old one
                                // for up to CERT_CACHE_TTL.
                                self.cache.invalidate(&domain_clone);
                                renewed += 1;
                            }
                            Err(e) => {
                                warn!("Background ACME failed for {}: {}", domain_clone, e);
                                cooldown.mark(&domain_clone);
                                failed += 1;
                            }
                        }
                        self.inflight.release(&domain);

                        // Pace orders to stay inside CA rate limits on long lists.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }

                if renewed > 0 || failed > 0 {
                    info!(
                        "Background ACME sweep done: {} renewed, {} failed, {} domain(s) scanned",
                        renewed, failed, total
                    );
                }
            }
        });
    }

    /// Fire-and-forget ACME re-issue for one SNI. Deduped by `inflight` and
    /// rate-limited by `cooldown`, so calling it from the handshake path is safe.
    /// The caller has already checked the allowlist.
    fn spawn_reissue(&self, sni: String) {
        if self.cooldown.is_cooling_down(&sni) {
            return;
        }
        if !self.inflight.try_acquire(&sni) {
            return;
        }

        let acme_cfg = Arc::clone(&self.acme_cfg);
        let tokens = self.tokens.clone();
        let cache = Arc::clone(&self.cache);
        let cooldown = Arc::clone(&self.cooldown);
        let inflight = Arc::clone(&self.inflight);

        tokio::spawn(async move {
            // Released on every exit path, panic included — a leaked entry would
            // wedge this SNI's singleflight slot for the life of the process and
            // silently stop it from ever renewing again.
            let _guard = InflightGuard {
                inflight,
                sni: sni.clone(),
            };

            let _ = std::fs::create_dir_all(&acme_cfg.storage);
            match issue_cert(&acme_cfg, std::slice::from_ref(&sni), &tokens).await {
                Ok(bundle) => {
                    cooldown.clear(&sni);
                    let _ =
                        std::fs::write(cert_path_for(&acme_cfg.storage, &sni), &bundle.cert_pem);
                    let _ = std::fs::write(key_path_for(&acme_cfg.storage, &sni), &bundle.key_pem);
                    match parse_pem_to_cached(&bundle.cert_pem, &bundle.key_pem) {
                        Ok(fresh) => {
                            cache.insert(&sni, fresh);
                            info!("on-demand TLS: cert renewed: {}", sni);
                        }
                        Err(e) => warn!("on-demand TLS: parse renewed cert for {}: {}", sni, e),
                    }
                }
                Err(e) => {
                    warn!("on-demand TLS: renewal failed for {}: {}", sni, e);
                    cooldown.mark(&sni);
                }
            }
        });
    }

    // ── Core cert-selection logic ─────────────────────────────────────────────

    async fn resolve(&self, sni: &str) -> CachedCert {
        // 0. Allowlist gate, defence in depth.
        //
        // Must mirror `certificate_callback_inner` and `warmup_domain`, which
        // admit a host that is EITHER an ACME route host (allowed_hosts) OR on
        // the on-demand list. Checking allowed_hosts alone would give every
        // on-demand host the fallback and never reach the disk lookup (step 3).
        if !self.allowed_hosts.load().contains(sni) && !self.hosts.exists(sni) {
            return self.fallback.clone();
        }

        // 1. Memory Cache
        if let Some(cached) = self.cache.get(sni) {
            return cached;
        }

        // 2. Security Checks
        let known = self.hosts.exists(sni);

        if !known && !self.sni_tracker.should_attempt(sni) {
            return self.fallback.clone();
        }

        if self.cooldown.is_cooling_down(sni) {
            return self.fallback.clone();
        }

        // 3. Disk Check
        let storage = &self.acme_cfg.storage;
        let cp = cert_path_for(storage, sni);
        let kp = key_path_for(storage, sni);

        if cp.exists() && kp.exists() {
            match load_cached_from_disk(&cp, &kp) {
                Ok((cached, days)) => {
                    // Stale-while-revalidate. Serving whatever is on disk with no
                    // expiry check meant an expired cert was served forever: the
                    // handshake "succeeded" from the proxy's point of view while
                    // every browser showed NET::ERR_CERT_DATE_INVALID, and nothing
                    // was logged. Serve it (a stall here would break the handshake)
                    // and renew underneath. Singleflight + cooldown keep this to one
                    // ACME order per domain no matter the handshake rate.
                    if days <= RENEW_BEFORE_DAYS {
                        if days <= 0 {
                            warn!(
                                "on-demand TLS: {} is serving an EXPIRED cert ({}d), re-issuing now",
                                sni, days
                            );
                        } else {
                            info!(
                                "on-demand TLS: {} expires in {}d, re-issuing in background",
                                sni, days
                            );
                        }
                        self.spawn_reissue(sni.to_string());
                    }
                    self.cache.insert(sni, cached.clone());
                    return cached;
                }
                Err(e) => tracing::warn!("on-demand TLS: disk load failed for {}: {}", sni, e),
            }
        }

        // 4. On-Demand ACME Issuance
        if !self.inflight.try_acquire(sni) {
            return self.fallback.clone();
        }

        let acme_cfg = Arc::clone(&self.acme_cfg);
        let tokens = self.tokens.clone();
        let sni_owned = sni.to_string();
        let cooldown = Arc::clone(&self.cooldown);
        let cache = Arc::clone(&self.cache);
        let inflight = Arc::clone(&self.inflight);

        // Safely spawn the ACME order first so it doesn't get cancelled by the timeout
        let issue_handle = tokio::spawn(async move {
            let _guard = InflightGuard {
                inflight,
                sni: sni_owned.clone(),
            };

            let _ = std::fs::create_dir_all(&acme_cfg.storage);
            let result = issue_cert(&acme_cfg, std::slice::from_ref(&sni_owned), &tokens).await;
            match result {
                Ok(bundle) => {
                    cooldown.clear(&sni_owned);
                    let _ = std::fs::write(
                        cert_path_for(&acme_cfg.storage, &sni_owned),
                        &bundle.cert_pem,
                    );
                    let _ = std::fs::write(
                        key_path_for(&acme_cfg.storage, &sni_owned),
                        &bundle.key_pem,
                    );

                    match parse_pem_to_cached(&bundle.cert_pem, &bundle.key_pem) {
                        Ok(cached) => {
                            cache.insert(&sni_owned, cached.clone());
                            info!("on-demand TLS: cert issued: {}", sni_owned);
                            Some(cached)
                        }
                        Err(e) => {
                            warn!("on-demand TLS: parse issued cert for {}: {}", sni_owned, e);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("on-demand TLS: ACME issue failed for {}: {}", sni_owned, e);
                    cooldown.mark(&sni_owned);
                    None
                }
            }
        });

        // 5. 800ms race for the first user
        match tokio::time::timeout(ACME_ISSUE_TIMEOUT, issue_handle).await {
            Ok(Ok(Some(cached))) => cached,
            Ok(Ok(None)) => self.fallback.clone(),
            Ok(Err(e)) => {
                warn!("on-demand TLS: ACME task panicked for {}: {}", sni, e);
                self.fallback.clone()
            }
            Err(_elapsed) => {
                info!(
                    "on-demand TLS: ACME still running for {}, serving the fallback meanwhile",
                    sni
                );
                self.fallback.clone()
            }
        }
    }
}

// ── Shared cert-injection helper ─────────────────────────────────────────────

fn apply_cert_entry(ssl: &mut TlsRef, entry: &CachedCert) {
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
