use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use arc_swap::ArcSwap;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, ExternalAccountKey, Identifier, NewAccount,
    NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use tokio::sync::{Mutex, Notify};
use tracing::{info, warn};

/// Quiet period after a host-set change before the bundle is reissued.
const RENEW_DEBOUNCE: Duration = Duration::from_secs(30);

use crate::config::{AcmeConfig, CERT_RENEW_DAYS};

/// Common name of every self-signed fallback cert this edge generates. A bundle
/// carrying it is a placeholder and is renewed at once.
pub const FALLBACK_CN: &str = "pingora-edge fallback certificate";

#[derive(Clone)]
pub struct CertBundle {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertBundle {
    fn cert_path(storage: &str) -> PathBuf {
        Path::new(storage).join("bundle.crt")
    }
    fn key_path(storage: &str) -> PathBuf {
        Path::new(storage).join("bundle.key")
    }

    pub fn load(storage: &str) -> Option<Self> {
        Some(Self {
            cert_pem: std::fs::read_to_string(Self::cert_path(storage)).ok()?,
            key_pem: std::fs::read_to_string(Self::key_path(storage)).ok()?,
        })
    }

    pub fn save(&self, storage: &str) -> Result<()> {
        std::fs::create_dir_all(storage)?;
        std::fs::write(Self::cert_path(storage), &self.cert_pem)?;
        std::fs::write(Self::key_path(storage), &self.key_pem)?;
        Ok(())
    }

    pub fn days_until_expiry(&self) -> i64 {
        use x509_parser::pem::parse_x509_pem;
        use x509_parser::prelude::parse_x509_certificate;

        let Ok((_, pem)) = parse_x509_pem(self.cert_pem.as_bytes()) else {
            return 0;
        };
        let Ok((_, cert)) = parse_x509_certificate(&pem.contents) else {
            return 0;
        };

        // Force immediate background renewal if this is a temporary fallback cert
        if cert.subject().to_string().contains(FALLBACK_CN) {
            return 0;
        }

        let expiry = cert.validity().not_after.timestamp();
        let now = chrono::Utc::now().timestamp();
        (expiry - now) / 86_400
    }

    pub fn contains_all_domains(&self, hosts: &[String]) -> bool {
        use x509_parser::pem::parse_x509_pem;
        use x509_parser::prelude::parse_x509_certificate;

        let Ok((_, pem)) = parse_x509_pem(self.cert_pem.as_bytes()) else {
            return false;
        };
        let Ok((_, cert)) = parse_x509_certificate(&pem.contents) else {
            return false;
        };

        let mut cert_domains = std::collections::HashSet::new();
        if let Ok(Some(sans)) = cert.subject_alternative_name() {
            for san in &sans.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(name) = san {
                    cert_domains.insert(name.to_string());
                }
            }
        }
        hosts.iter().all(|h| cert_domains.contains(h))
    }

    /// Hosts in `hosts` the bundle's SANs do not name (all of them if it does not parse).
    pub fn uncovered(&self, hosts: &[String]) -> usize {
        use x509_parser::pem::parse_x509_pem;
        use x509_parser::prelude::parse_x509_certificate;

        let Ok((_, pem)) = parse_x509_pem(self.cert_pem.as_bytes()) else {
            return hosts.len();
        };
        let Ok((_, cert)) = parse_x509_certificate(&pem.contents) else {
            return hosts.len();
        };
        let mut sans = std::collections::HashSet::new();
        if let Ok(Some(ext)) = cert.subject_alternative_name() {
            for san in &ext.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(name) = san {
                    sans.insert(name.to_string());
                }
            }
        }
        hosts.iter().filter(|h| !sans.contains(*h)).count()
    }
}

/// The renewal loop is ordering right now (config status).
static ISSUING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Why the last issuance attempt did not leave a covering bundle; None after a good one.
static LAST_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn issuing() -> bool {
    ISSUING.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn last_error() -> Option<String> {
    LAST_ERROR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

pub fn set_last_error(e: Option<String>) {
    *LAST_ERROR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = e;
}

pub type TokenStore = Arc<Mutex<HashMap<String, String>>>;
pub fn new_token_store() -> TokenStore {
    Arc::new(Mutex::new(HashMap::new()))
}

fn account_path_for(storage: &str, provider: &str) -> PathBuf {
    match provider {
        "letsencrypt" => Path::new(storage).join("account-le.json"),
        _ => Path::new(storage).join("account.json"),
    }
}

fn decode_b64url(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for b in s.bytes() {
        let val: u32 = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a') as u32 + 26,
            b'0'..=b'9' => (b - b'0') as u32 + 52,
            b'-' => 62,
            b'_' => 63,
            _ => continue,
        };
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    out
}

async fn load_or_create_account(cfg: &AcmeConfig) -> Result<Account> {
    std::fs::create_dir_all(&cfg.storage)?;
    let path = account_path_for(&cfg.storage, &cfg.provider);

    if path.exists() {
        let raw = std::fs::read_to_string(&path)?;
        let raw = raw.trim();

        // Empty or corrupted account.json — delete and recreate
        if raw.is_empty() || !raw.starts_with('{') {
            warn!("ACME account file is empty or corrupted — deleting and creating new account");
            let _ = std::fs::remove_file(&path);
        } else {
            match serde_json::from_str::<AccountCredentials>(raw) {
                Ok(creds) => match Account::from_credentials(creds).await {
                    Ok(acct) => {
                        info!("Loaded ACME account from disk");
                        return Ok(acct);
                    }
                    Err(e) => {
                        warn!("ACME account credentials invalid: {} — recreating", e);
                        let _ = std::fs::remove_file(&path);
                    }
                },
                Err(e) => {
                    warn!(
                        "ACME account JSON parse failed: {} — deleting and recreating",
                        e
                    );
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    info!("Creating new ACME account (provider={})", cfg.provider);

    let email_link = format!("mailto:{}", cfg.email);
    let new_acct = NewAccount {
        contact: &[&email_link],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };

    let (acct, creds) = if cfg.has_eab() {
        let hmac = decode_b64url(&cfg.eab_hmac);
        let eab = ExternalAccountKey::new(cfg.eab_kid.clone(), &hmac);
        Account::create(&new_acct, cfg.directory_url(), Some(&eab)).await?
    } else {
        Account::create(&new_acct, cfg.directory_url(), None).await?
    };

    std::fs::write(&path, serde_json::to_string_pretty(&creds)?)?;
    info!("ACME account saved to {}", path.display());
    Ok(acct)
}

pub fn generate_fallback_bundle(hosts: &[String]) -> Result<CertBundle> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(hosts.to_vec())?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, FALLBACK_CN);
        dn.push(DnType::OrganizationName, env!("CARGO_PKG_NAME"));
        dn
    };

    let cert_pem = params.self_signed(&key_pair)?.pem();
    let key_pem = key_pair.serialize_pem();

    Ok(CertBundle { cert_pem, key_pem })
}

pub async fn issue_cert(
    cfg: &AcmeConfig,
    hosts: &[String],
    tokens: &TokenStore,
) -> Result<CertBundle> {
    if hosts.is_empty() {
        bail!("No concrete hostnames to issue a certificate for.");
    }

    info!(
        "Issuing SAN cert for {} domain(s): {:?}",
        hosts.len(),
        hosts
    );

    let account = load_or_create_account(cfg).await?;
    let identifiers: Vec<Identifier> = hosts.iter().map(|h| Identifier::Dns(h.clone())).collect();
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;
    let auths = order.authorizations().await?;

    for auth in &auths {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .context("No HTTP-01 challenge offered")?;

        let key_auth = order.key_authorization(challenge);
        tokens
            .lock()
            .await
            .insert(challenge.token.clone(), key_auth.as_str().to_string());
        info!("Challenge token published for {:?}", auth.identifier);
        order.set_challenge_ready(&challenge.url).await?;
    }

    // REDUCED TIMEOUT: 30 seconds instead of 120s
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let status = order.refresh().await?.status;
        info!("ACME order status: {:?}", status);
        match status {
            OrderStatus::Ready | OrderStatus::Valid => break,
            OrderStatus::Invalid => {
                bail!("ACME order invalid — check DNS and that port 80 is reachable")
            }
            OrderStatus::Pending => {}
            OrderStatus::Processing => {}
        }
        if tokio::time::Instant::now() > deadline {
            bail!("ACME order timed out after 30s waiting for Ready/Valid");
        }
    }

    tokens.lock().await.clear();

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(hosts.to_vec())?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &hosts[0]);
        dn
    };

    let csr = params.serialize_request(&key_pair)?;
    let key_pem = key_pair.serialize_pem();

    order.finalize(csr.der()).await?;

    // REDUCED TIMEOUT: 30 seconds instead of 120s
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        match order.certificate().await {
            Ok(Some(cert_pem)) => {
                let bundle = CertBundle { cert_pem, key_pem };
                bundle.save(&cfg.storage)?;
                info!("SAN certificate saved ({} domain(s))", hosts.len());
                return Ok(bundle);
            }
            Ok(None) => {
                info!("Certificate not yet available from CA, retrying…");
            }
            Err(e) => {
                warn!("Certificate download error (will retry): {}", e);
            }
        }
        if tokio::time::Instant::now() > deadline {
            bail!("Certificate download timed out after 30s — check ACME provider status");
        }
    }
}

pub async fn run_challenge_server(
    tokens: TokenStore,
    bind_notify: Option<Arc<tokio::sync::Notify>>,
    http_upstream: Option<String>,
) {
    use http_body_util::Full;
    use hyper::{body::Bytes, server::conn::http1, service::service_fn, Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let listener = {
        let mut tries = 0u32;
        loop {
            match TcpListener::bind("0.0.0.0:80").await {
                Ok(l) => break l,
                Err(e) if tries < 5 => {
                    warn!(":80 bind retry {}: {}", tries + 1, e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    tries += 1;
                }
                Err(e) => {
                    tracing::error!("Cannot bind :80: {}", e);
                    std::process::exit(1);
                }
            }
        }
    };

    info!("HTTP challenge/redirect server on :80");

    if let Some(n) = bind_notify {
        n.notify_one();
    }

    let http_upstream: Arc<Option<String>> = Arc::new(http_upstream);

    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                // Back off instead of hot-spinning. A bare `continue` here turned fd
                // exhaustion into a silent busy-loop that also stopped every ACME
                // challenge from being answered — certs then failed to issue/renew
                // with nothing in the log to say why.
                tracing::error!(":80 challenge accept failed ({}) — backing off 100ms", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let tokens = tokens.clone();
        let http_upstream = Arc::clone(&http_upstream);

        tokio::spawn(async move {
            use tokio::net::TcpStream;

            let acme_prefix = b"GET /.well-known/acme-challenge/";
            let mut buf = [0u8; 512];

            let n = match stream.peek(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(":80 peek error: {}", e);
                    return;
                }
            };

            let is_acme_request = n >= acme_prefix.len()
                && buf[..acme_prefix.len()].eq_ignore_ascii_case(acme_prefix);

            let mut is_our_acme = false;

            if is_acme_request {
                let token_start = acme_prefix.len();
                if let Some(space_idx) = buf[token_start..n]
                    .iter()
                    .position(|&b| b == b' ' || b == b'\r' || b == b'\n')
                {
                    let token_slice = &buf[token_start..token_start + space_idx];
                    if let Ok(token_str) = std::str::from_utf8(token_slice) {
                        if tokens.lock().await.contains_key(token_str) {
                            is_our_acme = true;
                        }
                    }
                }
            }

            if is_our_acme {
                // ── Serve Rust's ACME token ───────────────────────────────────
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let tokens = tokens.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let prefix = "/.well-known/acme-challenge/";
                                if let Some(token) = path.strip_prefix(prefix) {
                                    if let Some(auth) = tokens.lock().await.get(token) {
                                        return Ok::<_, hyper::Error>(
                                            Response::builder()
                                                .status(200)
                                                .header("Content-Type", "text/plain")
                                                .body(Full::new(Bytes::from(auth.clone())))
                                                .unwrap(),
                                        );
                                    }
                                }
                                Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(404)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            } else if is_acme_request && http_upstream.is_some() {
                // ── Forward Foreign ACME requests using safe bidirectional splice
                let upstream_addr = http_upstream.as_deref().unwrap();
                match TcpStream::connect(upstream_addr).await {
                    Ok(mut upstream) => {
                        let mut client = stream;
                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                        {
                            tracing::debug!(":80→{} splice error: {}", upstream_addr, e);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            ":80 cannot connect to http_upstream {}: {}",
                            upstream_addr,
                            e
                        );
                    }
                }
            } else {
                // ── EVERYONE ELSE GETS A 301 REDIRECT TO HTTPS ────────────────
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<hyper::body::Incoming>| async move {
                            if req.uri().path() == "/health" {
                                return Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(200)
                                        .header("Content-Length", "0")
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                );
                            }

                            let host = req
                                .headers()
                                .get("host")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("localhost");
                            let loc = format!(
                                "https://{}{}",
                                host,
                                req.uri()
                                    .path_and_query()
                                    .map(|p| p.as_str())
                                    .unwrap_or("/")
                            );
                            Ok::<_, hyper::Error>(
                                Response::builder()
                                    .status(301)
                                    .header("Location", loc)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            }
        });
    }
}

pub struct CertStore {
    cfg: AcmeConfig,
}

impl CertStore {
    pub fn new(cfg: AcmeConfig) -> Self {
        Self { cfg }
    }

    pub async fn ensure(&self, hosts: &[String], tokens: &TokenStore) -> Result<bool> {
        match CertBundle::load(&self.cfg.storage) {
            Some(b) if b.days_until_expiry() > CERT_RENEW_DAYS && b.contains_all_domains(hosts) => {
                info!("SAN cert valid ({} days left)", b.days_until_expiry());
                Ok(false)
            }
            Some(b) => {
                info!(
                    "SAN cert expiring soon ({} days) or domain list changed — renewing",
                    b.days_until_expiry()
                );
                match self.issue_with_fallback(hosts, tokens).await {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        warn!("ACME renewal failed (all providers): {}. Continuing with existing cert.", e);
                        Ok(false)
                    }
                }
            }
            None => {
                info!("No SAN cert on disk — requesting new certificate");
                match self.issue_with_fallback(hosts, tokens).await {
                    Ok(_) => Ok(true),
                    Err(e) => {
                        warn!("ACME issuance failed (all providers): {}. Generating fallback cert to prevent crash.", e);
                        let fallback = generate_fallback_bundle(hosts)?;
                        fallback.save(&self.cfg.storage)?;
                        Ok(false)
                    }
                }
            }
        }
    }

    /// Try primary provider, fall back to Let's Encrypt if it fails.
    async fn issue_with_fallback(
        &self,
        hosts: &[String],
        tokens: &TokenStore,
    ) -> Result<CertBundle> {
        // 1. Try primary provider
        match issue_cert(&self.cfg, hosts, tokens).await {
            Ok(bundle) => return Ok(bundle),
            Err(e) => {
                if self.cfg.is_letsencrypt() {
                    // Already LE, no fallback available
                    return Err(e);
                }
                warn!(
                    "Primary ACME provider ({}) failed: {} — falling back to Let's Encrypt",
                    self.cfg.provider, e
                );
            }
        }

        // 2. Fallback to Let's Encrypt (EC256, same email, no EAB)
        let le_cfg = self.cfg.letsencrypt_fallback();
        info!("Attempting Let's Encrypt fallback (email={})", le_cfg.email);
        issue_cert(&le_cfg, hosts, tokens).await
    }

    /// The runtime's only SAN-bundle issuer. `hosts` is the set the bundle should
    /// cover; `changed` (notify_one) wakes it after a host set change, and it issues
    /// once 30 s pass with no further change, so a burst of edits is one order.
    pub fn spawn_renewal_with_callback<F>(
        self: Arc<Self>,
        hosts: Arc<ArcSwap<Vec<String>>>,
        changed: Arc<Notify>,
        tokens: TokenStore,
        on_renewed: F,
    ) where
        F: Fn() + Send + Sync + 'static,
    {
        tokio::spawn(async move {
            loop {
                // Hourly while the bundle is a fallback, expired or short of a host; else daily.
                let covered = CertBundle::load(&self.cfg.storage).is_some_and(|b| {
                    b.days_until_expiry() > 0 && b.contains_all_domains(&hosts.load())
                });
                let sleep_time = Duration::from_secs(if covered { 24 * 3600 } else { 3600 });

                let woke = tokio::select! {
                    _ = tokio::time::sleep(sleep_time) => false,
                    _ = changed.notified() => loop {
                        tokio::select! {
                            _ = tokio::time::sleep(RENEW_DEBOUNCE) => break true,
                            _ = changed.notified() => {}
                        }
                    },
                };

                let desired = hosts.load_full();
                // No ACME host left: never order a certificate for nothing.
                if desired.is_empty() {
                    continue;
                }
                ISSUING.store(true, std::sync::atomic::Ordering::Relaxed);
                let res = self.ensure(&desired, &tokens).await;
                ISSUING.store(false, std::sync::atomic::Ordering::Relaxed);
                let short = CertBundle::load(&self.cfg.storage)
                    .map_or(desired.len(), |b| b.uncovered(&desired));
                match res {
                    Ok(renewed) => {
                        if renewed {
                            info!("Certificate renewed — triggering hot-reload");
                            on_renewed();
                        }
                        if short == 0 {
                            set_last_error(None);
                            if woke {
                                info!(target: "config", "config: ACME reissue for {} host(s) ok", desired.len());
                            }
                        } else {
                            set_last_error(Some(format!(
                                "the bundle still misses {} host(s) — see the log",
                                short
                            )));
                            if woke {
                                warn!(target: "config", "config: ACME reissue failed: {} host(s) still uncovered, retried hourly", short);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Certificate renewal check failed: {}", e);
                        if woke {
                            warn!(target: "config", "config: ACME reissue failed: {}", e);
                        }
                        set_last_error(Some(e.to_string()));
                    }
                }
            }
        });
    }
}
