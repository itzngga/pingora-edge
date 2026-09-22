//! blocklist.rs: networks refused at the edge, from a local file or a URL.
//!
//! `[blocklist].source` names the list. Two formats are accepted:
//!
//! ```text
//! JSON   {"version": "2024-06-01", "block": ["198.51.100.0/24"], "allow": ["198.51.100.7/32"]}
//! text   one IP or CIDR per line, `#` comments, a leading `!` marks an allow entry
//! ```
//!
//! `allow` entries punch holes in `block` ranges. A URL is pulled every
//! `pull_secs` with an ETag, so an unchanged list costs one 304, and the last
//! good copy is cached on disk so a restart enforces from its first second. A
//! file is re-read when its mtime changes.
//!
//! Two optional short-lived sources sit next to it:
//!
//!   * `dyn_source`, a URL answering `{"ips":[{"ip":"203.0.113.9","ttl":600}]}`
//!   * `origin_block_header`, a response header an upstream sets to ban the
//!     visitor it is answering for N seconds
//!
//! An address on any list that is not loopback, trusted, a Cloudflare edge or
//! a verified crawler gets no upstream fetch: the request is answered 429
//! through the penalty box, whose escalation stops the source at the TLS
//! handshake after a few strikes. Short-lived entries never escalate, so a
//! false positive ends with its TTL.
//!
//! Why the crawler exemption lives here: large cloud networks host both
//! search crawlers and scrapers, so a list of datacenter ranges necessarily
//! contains crawler addresses. The published crawler ranges (shield.rs) are
//! the only thing that tells them apart, so they are checked first, and the
//! list fails open until they have loaded.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwap;
use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use once_cell::sync::Lazy;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::config::{BlocklistConfig, ProxyConfig};

static BLOCK_V4: Lazy<ArcSwap<IpRange<Ipv4Net>>> =
    Lazy::new(|| ArcSwap::from_pointee(IpRange::new()));
static BLOCK_V6: Lazy<ArcSwap<IpRange<Ipv6Net>>> =
    Lazy::new(|| ArcSwap::from_pointee(IpRange::new()));
static ALLOW_V4: Lazy<ArcSwap<IpRange<Ipv4Net>>> =
    Lazy::new(|| ArcSwap::from_pointee(IpRange::new()));
static ALLOW_V6: Lazy<ArcSwap<IpRange<Ipv6Net>>> =
    Lazy::new(|| ArcSwap::from_pointee(IpRange::new()));

/// Short-lived entries (dyn_source and origin_block_header). The cache TTL is
/// only the ceiling; each entry carries its own expiry.
static DYN: Lazy<moka::sync::Cache<IpAddr, Instant>> = Lazy::new(|| {
    moka::sync::Cache::builder()
        .max_capacity(100_000)
        .time_to_live(Duration::from_secs(3600))
        .build()
});

static ETAG: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

/// What /api/blocklist shows: the settings in force, the last pull and the counts.
#[derive(Default, Clone)]
struct Status {
    enabled: bool,
    source: String,
    is_url: bool,
    token_set: bool,
    pull_secs: u64,
    dyn_source: bool,
    dyn_secs: u64,
    version: String,
    last_pull: u64, // unix, 0 = never
    last_ok: bool,
    last_error: String,
    last_dyn: u64,
    block_v4: usize,
    block_v6: usize,
    allow: usize,
    from_cache: bool, // restored from disk, no pull has confirmed it yet
    cache: String,    // "" = not persisted
}

static STATUS: Lazy<ArcSwap<Status>> = Lazy::new(|| ArcSwap::from_pointee(Status::default()));

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn status_update(f: impl FnOnce(&mut Status)) {
    let mut s = (**STATUS.load()).clone();
    f(&mut s);
    STATUS.store(Arc::new(s));
}

/// A missing or `null` list reads as empty.
fn null_list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct JsonDoc {
    #[serde(default)]
    version: String,
    #[serde(default, deserialize_with = "null_list")]
    block: Vec<String>,
    #[serde(default, deserialize_with = "null_list")]
    allow: Vec<String>,
}

#[derive(Deserialize)]
struct DynDoc {
    #[serde(default, deserialize_with = "null_list")]
    ips: Vec<DynEntry>,
}

#[derive(Deserialize)]
struct DynEntry {
    ip: String,
    ttl: i64,
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// The settings the pullers were started with, in comparable form. None when
/// the list is off. A reload that changes it needs a restart (check.rs).
pub(crate) fn target_key(cfg: &ProxyConfig) -> Option<BlocklistConfig> {
    let bl = &cfg.blocklist;
    if !bl.enabled || (bl.source.trim().is_empty() && bl.dyn_source.trim().is_empty()) {
        return None;
    }
    // Read live by the request path, so not part of what the pullers captured.
    Some(BlocklistConfig {
        origin_block_header: String::new(),
        ..bl.clone()
    })
}

/// Spawn the pull loops on the background runtime. Nothing is spawned when the
/// list is off.
pub fn spawn_updaters(cfg: &ProxyConfig) {
    let Some(bl) = target_key(cfg) else {
        info!("blocklist: off (no [blocklist].source)");
        return;
    };
    let source = bl.source.trim().to_string();
    let url = is_url(&source);
    let pull = Duration::from_secs(bl.pull_secs.max(if url { 30 } else { 5 }));
    let dyn_url = bl.dyn_source.trim().to_string();
    let dyn_every = (!dyn_url.is_empty()).then(|| Duration::from_secs(bl.dyn_secs.max(5)));
    let cache = if url {
        cache_path(&bl.cache, &cfg.acme.storage, "blocklist-cache.json")
    } else {
        String::new()
    };
    let _ = CACHE_PATH.set(cache.clone());
    {
        let (src, tok, c) = (source.clone(), !bl.token.is_empty(), cache.clone());
        let (ps, ds, has_dyn) = (
            pull.as_secs(),
            dyn_every.map_or(0, |d| d.as_secs()),
            dyn_every.is_some(),
        );
        status_update(move |s| {
            s.enabled = true;
            s.source = src;
            s.is_url = url;
            s.token_set = tok;
            s.pull_secs = ps;
            s.dyn_source = has_dyn;
            s.dyn_secs = ds;
            s.cache = c;
        });
    }
    if !source.is_empty() {
        info!(
            "blocklist: {} {} every {}s",
            if url { "pulling" } else { "reading" },
            source,
            pull.as_secs()
        );
    }

    // The last list first: a restart must not mean an unprotected edge until
    // the source answers, and the first pull then costs a 304.
    if !cache.is_empty() {
        let c = cache.clone();
        tokio::spawn(async move {
            match load_cache(&c).await {
                Ok(Some((n, v))) => info!(
                    "blocklist: restored {} networks (version {}) from {}",
                    n, v, c
                ),
                Ok(None) => {}
                Err(e) => warn!("blocklist: cache {} not usable: {}", c, e),
            }
        });
    }

    if !source.is_empty() {
        let t = Fetch {
            token: bl.token.clone(),
            insecure: bl.insecure,
        };
        tokio::spawn(async move {
            let mut last_mtime = None;
            loop {
                let res = if url {
                    pull_url(&t, &source).await
                } else {
                    read_file(&source, &mut last_mtime).await
                };
                match res {
                    Ok(()) => {
                        status_update(|s| {
                            s.last_pull = now_unix();
                            s.last_ok = true;
                            s.last_error.clear();
                            s.from_cache = false;
                        });
                        tokio::time::sleep(pull).await
                    }
                    Err(e) => {
                        warn!("blocklist: refresh failed: {}", e);
                        let msg = e.to_string();
                        status_update(move |s| {
                            s.last_pull = now_unix();
                            s.last_ok = false;
                            s.last_error = msg;
                        });
                        // Until the first list lands, try again soon.
                        let have_list = ETAG.lock().await.is_some() || last_mtime.is_some();
                        tokio::time::sleep(if have_list {
                            pull
                        } else {
                            Duration::from_secs(10)
                        })
                        .await;
                    }
                }
            }
        });
    }

    let Some(dyn_every) = dyn_every else { return };
    let t = Fetch {
        token: bl.token.clone(),
        insecure: bl.insecure,
    };
    tokio::spawn(async move {
        loop {
            match pull_dyn(&t, &dyn_url).await {
                Ok(()) => status_update(|s| s.last_dyn = now_unix()),
                Err(e) => warn!("blocklist: dyn pull failed: {}", e),
            }
            tokio::time::sleep(dyn_every).await;
        }
    });
}

async fn pull_url(t: &Fetch, url: &str) -> Result<()> {
    let etag = ETAG.lock().await.clone();
    let (status, body, new_etag) = fetch(t, url, etag.as_deref()).await?;
    if status == 304 {
        return Ok(());
    }
    if status != 200 {
        anyhow::bail!("HTTP {}", status);
    }
    apply(&body).await?;
    // An ETag-less source still counts as "a list has landed".
    *ETAG.lock().await = Some(new_etag.clone().unwrap_or_default());
    save_cache(&body, new_etag.as_deref()).await;
    Ok(())
}

async fn read_file(path: &str, last: &mut Option<std::time::SystemTime>) -> Result<()> {
    let meta = tokio::fs::metadata(path).await?;
    let mtime = meta.modified().ok();
    if last.is_some() && mtime == *last {
        return Ok(());
    }
    let body = tokio::fs::read_to_string(path).await?;
    apply(&body).await?;
    *last = mtime;
    Ok(())
}

/// One parsed list: block and allow ranges plus the raw counts.
pub(crate) struct Parsed {
    version: String,
    b4: IpRange<Ipv4Net>,
    b6: IpRange<Ipv6Net>,
    a4: IpRange<Ipv4Net>,
    a6: IpRange<Ipv6Net>,
    nb4: usize,
    nb6: usize,
    na: usize,
}

/// Parse either format. Unparseable entries are skipped.
pub(crate) fn parse(body: &str) -> Result<Parsed> {
    let (version, block, allow) = if body.trim_start().starts_with('{') {
        let doc: JsonDoc = serde_json::from_str(body)?;
        (doc.version, doc.block, doc.allow)
    } else {
        let mut block = Vec::new();
        let mut allow = Vec::new();
        for line in body.lines() {
            let l = line.split('#').next().unwrap_or("").trim();
            if let Some(a) = l.strip_prefix('!') {
                allow.push(a.trim().to_string());
            } else if !l.is_empty() {
                block.push(l.to_string());
            }
        }
        (String::new(), block, allow)
    };
    let mut p = Parsed {
        version,
        b4: IpRange::new(),
        b6: IpRange::new(),
        a4: IpRange::new(),
        a6: IpRange::new(),
        nb4: 0,
        nb6: 0,
        na: 0,
    };
    for s in &block {
        match net(s) {
            Some(Net::V4(n)) => {
                p.b4.add(n);
                p.nb4 += 1;
            }
            Some(Net::V6(n)) => {
                p.b6.add(n);
                p.nb6 += 1;
            }
            None => {}
        }
    }
    for s in &allow {
        match net(s) {
            Some(Net::V4(n)) => {
                p.a4.add(n);
                p.na += 1;
            }
            Some(Net::V6(n)) => {
                p.a6.add(n);
                p.na += 1;
            }
            None => {}
        }
    }
    p.b4.simplify();
    p.b6.simplify();
    p.a4.simplify();
    p.a6.simplify();
    Ok(p)
}

enum Net {
    V4(Ipv4Net),
    V6(Ipv6Net),
}

/// A CIDR, or a bare address as a host route.
fn net(s: &str) -> Option<Net> {
    let s = s.trim();
    if let Ok(n) = s.parse::<Ipv4Net>() {
        return Some(Net::V4(n.trunc()));
    }
    if let Ok(n) = s.parse::<Ipv6Net>() {
        return Some(Net::V6(n.trunc()));
    }
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => Ipv4Net::new(a, 32).ok().map(Net::V4),
        IpAddr::V6(a) => Ipv6Net::new(a, 128).ok().map(Net::V6),
    }
}

/// Parse a list and make it the one in force.
async fn apply(body: &str) -> Result<(usize, String)> {
    let owned = body.to_string();
    let p = tokio::task::spawn_blocking(move || parse(&owned)).await??;
    let (version, nb4, nb6, na) = (p.version.clone(), p.nb4, p.nb6, p.na);
    BLOCK_V4.store(Arc::new(p.b4));
    BLOCK_V6.store(Arc::new(p.b6));
    ALLOW_V4.store(Arc::new(p.a4));
    ALLOW_V6.store(Arc::new(p.a6));
    let v = version.clone();
    status_update(move |s| {
        s.version = v;
        s.block_v4 = nb4;
        s.block_v6 = nb6;
        s.allow = na;
    });
    info!(
        "blocklist: {} networks blocked, {} allowed{}",
        nb4 + nb6,
        na,
        if version.is_empty() {
            String::new()
        } else {
            format!(" (version {})", version)
        }
    );
    Ok((nb4 + nb6, version))
}

// ── the on-disk copy of a URL list ───────────────────────────────────────────

static CACHE_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[derive(serde::Serialize, Deserialize)]
struct CacheDoc {
    etag: Option<String>,
    body: String,
}

/// "" → `<storage>/<name>`; "off" → no persistence.
pub(crate) fn cache_path(configured: &str, storage: &str, name: &str) -> String {
    let c = configured.trim();
    if c.eq_ignore_ascii_case("off") {
        return String::new();
    }
    if !c.is_empty() {
        return c.to_string();
    }
    let st = storage.trim().trim_end_matches('/');
    if st.is_empty() {
        return String::new();
    }
    format!("{}/{}", st, name)
}

async fn save_cache(body: &str, etag: Option<&str>) {
    let Some(path) = CACHE_PATH.get().filter(|p| !p.is_empty()) else {
        return;
    };
    let doc = CacheDoc {
        etag: etag.map(str::to_string),
        body: body.to_string(),
    };
    let res: Result<()> = async {
        let tmp = format!("{}.tmp", path);
        tokio::fs::write(&tmp, serde_json::to_vec(&doc)?).await?;
        tokio::fs::rename(&tmp, path).await?;
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!("blocklist: could not write {}: {}", path, e);
    }
}

async fn load_cache(path: &str) -> Result<Option<(usize, String)>> {
    let doc: CacheDoc = match tokio::fs::read(path).await {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    // Only while nothing fresher has landed: a pull that beat us to it wins.
    let mut etag = ETAG.lock().await;
    if etag.is_some() {
        return Ok(None);
    }
    let r = apply(&doc.body).await?;
    *etag = Some(doc.etag.unwrap_or_default());
    status_update(|s| s.from_cache = true);
    Ok(Some(r))
}

/// GET /api/blocklist on the metrics listener: settings in force, last pulls, counts.
pub fn status_json() -> String {
    let s = STATUS.load();
    let now = Instant::now();
    let dyn_n = DYN.iter().filter(|(_, until)| *until > now).count();
    let load = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    serde_json::json!({
        "list": {
            "enabled": s.enabled, "source": s.source, "is_url": s.is_url, "token_set": s.token_set,
            "pull_secs": s.pull_secs, "dyn_source": s.dyn_source, "dyn_secs": s.dyn_secs,
            "version": s.version, "last_pull": s.last_pull, "last_ok": s.last_ok,
            "last_error": s.last_error, "last_dyn": s.last_dyn,
            "block_v4": s.block_v4, "block_v6": s.block_v6, "allow": s.allow, "dyn": dyn_n,
            "from_cache": s.from_cache, "cache": s.cache,
            "hits": load(&crate::metrics::BLOCKLIST_HITS),
            "origin_blocks": load(&crate::metrics::ORIGIN_BLOCKS),
        },
        "real_ip": {
            "signed": load(&crate::metrics::REAL_IP_SEEN[0]),
            "unsigned": load(&crate::metrics::REAL_IP_SEEN[1]),
            "bad": load(&crate::metrics::REAL_IP_SEEN[2]),
        },
        "crawlers": {
            "loaded": crate::shield::verified_crawlers_loaded(),
            "prefixes": crate::shield::verified_crawler_count(),
        },
        "now": now_unix(),
    })
    .to_string()
}

async fn pull_dyn(t: &Fetch, url: &str) -> Result<()> {
    let (status, body, _) = fetch(t, url, None).await?;
    if status != 200 {
        anyhow::bail!("HTTP {}", status);
    }
    let doc: DynDoc = serde_json::from_str(&body)?;
    let now = Instant::now();
    for e in doc.ips {
        if e.ttl <= 0 {
            continue;
        }
        if let Ok(ip) = e.ip.parse::<IpAddr>() {
            DYN.insert(ip, now + Duration::from_secs(e.ttl.min(3600) as u64));
        }
    }
    Ok(())
}

/// `origin_block_header` on an upstream response: list the visitor for `secs`.
pub fn note_origin_block(ip: IpAddr, secs: u64) {
    if secs == 0 {
        return;
    }
    DYN.insert(ip, Instant::now() + Duration::from_secs(secs.min(3600)));
}

/// Why an address is refused: `Some("dyn")` for a short-lived entry (one IP
/// with a TTL, so a false positive ends with that TTL and the caller must NOT
/// escalate it to the TLS-level block), `Some("list")` for a network of the
/// list (escalate freely), `None` otherwise. The caller has already excluded
/// loopback, trusted and Cloudflare addresses; verified crawlers are excluded
/// here so no call site can forget it.
pub fn block_kind(ip: &IpAddr) -> Option<&'static str> {
    if exempt(ip) {
        return None;
    }
    if let Some(until) = DYN.get(ip) {
        if until > Instant::now() {
            return Some("dyn");
        }
        DYN.invalidate(ip);
    }
    if listed(ip) {
        Some("list")
    } else {
        None
    }
}

fn exempt(ip: &IpAddr) -> bool {
    // Without the published crawler ranges nothing separates a search crawler
    // from a scraper in the same cloud network: fail open until shield.rs has them.
    if !crate::shield::verified_crawlers_loaded() || crate::shield::is_verified_crawler(ip) {
        return true;
    }
    allowed(ip)
}

fn allowed(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ALLOW_V4.load().contains(v4),
        IpAddr::V6(v6) => ALLOW_V6.load().contains(v6),
    }
}

fn listed(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => BLOCK_V4.load().contains(v4),
        IpAddr::V6(v6) => BLOCK_V6.load().contains(v6),
    }
}

/// How URL fetches authenticate and verify.
struct Fetch {
    token: String,
    insecure: bool,
}

/// Accepts any certificate, for `insecure = true`.
#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// One GET with an optional bearer token and ETag, over HTTP or HTTPS.
async fn fetch(t: &Fetch, url: &str, etag: Option<&str>) -> Result<(u16, String, Option<String>)> {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::{Bytes, Incoming};
    use hyper::{Request, Response};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let schemes = if t.insecure {
        let provider = rustls::crypto::ring::default_provider();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls)
    } else {
        hyper_rustls::HttpsConnectorBuilder::new().with_native_roots()?
    };
    let connector = schemes.https_or_http().enable_http1().build();
    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(connector);

    let mut req = Request::get(url).header(
        "User-Agent",
        concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION"),
            " blocklist"
        ),
    );
    if !t.token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", t.token));
    }
    if let Some(e) = etag.filter(|e| !e.is_empty()) {
        req = req.header("If-None-Match", e);
    }
    let req = req.body(Empty::<Bytes>::new())?;

    let resp: Response<Incoming> =
        tokio::time::timeout(Duration::from_secs(20), client.request(req))
            .await
            .map_err(|_| anyhow::anyhow!("blocklist fetch timed out"))??;
    let status = resp.status().as_u16();
    let new_etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if status == 304 {
        return Ok((status, String::new(), new_etag));
    }
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        new_etag,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_format_blocks_and_allows() {
        let p = parse(
            "# comment\n198.51.100.0/24\n203.0.113.5\n!198.51.100.7\n2001:db8::/32\nnot-an-ip\n",
        )
        .unwrap();
        assert_eq!((p.nb4, p.nb6, p.na), (2, 1, 1));
        assert!(p
            .b4
            .contains(&"198.51.100.20".parse::<std::net::Ipv4Addr>().unwrap()));
        assert!(p
            .b4
            .contains(&"203.0.113.5".parse::<std::net::Ipv4Addr>().unwrap()));
        assert!(!p
            .b4
            .contains(&"203.0.113.6".parse::<std::net::Ipv4Addr>().unwrap()));
        assert!(p
            .a4
            .contains(&"198.51.100.7".parse::<std::net::Ipv4Addr>().unwrap()));
    }

    #[test]
    fn json_format_with_null_lists() {
        let p = parse(r#"{"version":"v1","block":["192.0.2.0/24"],"allow":null}"#).unwrap();
        assert_eq!(p.version, "v1");
        assert_eq!((p.nb4, p.na), (1, 0));
    }

    #[test]
    fn cache_path_rules() {
        assert_eq!(
            cache_path("", "/var/lib/edge/", "x.json"),
            "/var/lib/edge/x.json"
        );
        assert_eq!(cache_path("off", "/var/lib/edge", "x.json"), "");
        assert_eq!(
            cache_path("/tmp/c.json", "/var/lib/edge", "x.json"),
            "/tmp/c.json"
        );
    }
}
