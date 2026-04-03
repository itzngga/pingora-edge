use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::check::{Issue, Sev};

/// Trusted sources for the abuse/CF gates: exact IPs plus CIDR ranges. Built from
/// `[security].trusted_ips`, where each entry is either a bare IP ("10.0.0.5") or a
/// CIDR ("172.18.0.0/16", for example a container subnet, so tools on the same
/// host are trusted whatever their dynamic address).
#[derive(Clone, Default)]
pub struct TrustedNets {
    exact: std::collections::HashSet<IpAddr>,
    v4: IpRange<Ipv4Net>,
    v6: IpRange<Ipv6Net>,
}

impl TrustedNets {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        if self.exact.contains(ip) {
            return true;
        }
        match ip {
            IpAddr::V4(v4) => self.v4.contains(v4),
            IpAddr::V6(v6) => self.v6.contains(v6),
        }
    }

    /// Count of configured entries (exact IPs + CIDR ranges), for logging.
    pub fn len(&self) -> usize {
        self.exact.len() + self.v4.iter().count() + self.v6.iter().count()
    }
}

/// `[blocklist]`: networks refused at the edge, from a local file or a URL
/// (blocklist.rs). Off unless `source` is set.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BlocklistConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Where the list comes from: an `http(s)://` URL or a local file path.
    /// "" = no list. Either a JSON document or plain text (see blocklist.rs).
    #[serde(default)]
    pub source: String,
    /// Sent as `Authorization: Bearer <token>` on URL fetches. "" = none.
    #[serde(default)]
    pub token: String,
    /// Skip certificate verification on URL fetches.
    #[serde(default)]
    pub insecure: bool,
    /// How often the list is re-read (ETag for URLs, mtime for files).
    #[serde(default = "default_bl_pull")]
    pub pull_secs: u64,
    /// Optional second URL with short-lived entries: `{"ips":[{"ip":..,"ttl":..}]}`.
    /// "" = off.
    #[serde(default)]
    pub dyn_source: String,
    /// Pull interval for `dyn_source`.
    #[serde(default = "default_bl_dyn")]
    pub dyn_secs: u64,
    /// Where the last fetched list is kept between restarts, so the edge
    /// enforces from its first second. "" = `<acme.storage>/blocklist-cache.json`,
    /// "off" = never persist. Files are not cached (they are already on disk).
    #[serde(default)]
    pub cache: String,
    /// Response header an upstream may set to ban the visitor for N seconds
    /// (capped at 3600). Stripped before the response leaves the edge.
    /// "" = off.
    #[serde(default)]
    pub origin_block_header: String,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            source: String::new(),
            token: String::new(),
            insecure: false,
            pull_secs: default_bl_pull(),
            dyn_source: String::new(),
            dyn_secs: default_bl_dyn(),
            cache: String::new(),
            origin_block_header: String::new(),
        }
    }
}

fn default_bl_pull() -> u64 {
    300
}
fn default_bl_dyn() -> u64 {
    30
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum RouteMode {
    #[default]
    Proxy,
    Static,
    /// Pure redirect, no upstream. Sends every matching host to `redirect_to`,
    /// keeping path and query. Useful for moving a hostname to a new one.
    Redirect,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProxyConfig {
    #[serde(default = "default_true")]
    pub metrics: bool,

    pub acme: AcmeConfig,
    pub security: SecurityConfig,
    pub route: Vec<RouteConfig>,

    /// Address of the metrics/health listener (Prometheus text at /metrics).
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: String,

    /// Networks refused at the edge, from a file or a URL (blocklist.rs).
    #[serde(default)]
    pub blocklist: BlocklistConfig,

    /// Visitor-facing 503 page (errpage.rs). Off by default.
    #[serde(default)]
    pub error_page: crate::errpage::ErrorPageConfig,

    /// Hostname allowlist for on-demand TLS (host_list.rs): one name per line.
    /// Listed hosts get a certificate on first handshake and are served by the
    /// route with `on_demand_fallback = true`. "" = off.
    #[serde(default)]
    pub on_demand_hosts: String,
}

impl ProxyConfig {
    /// The first FATAL of the check pipeline, as the old bails did. main boots via reload::boot_load.
    #[allow(dead_code)]
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw =
            std::fs::read(path).map_err(|e| anyhow::anyhow!("Cannot read '{}': {}", path, e))?;
        let mut issues = Vec::new();
        let Some(mut cfg) = crate::check::parse(&raw, &mut issues).cfg else {
            let first = issues.first().map(Issue::line_text).unwrap_or_default();
            anyhow::bail!("Config error in '{}': {}", path, first);
        };

        for i in cfg.validate_all() {
            match i.sev {
                Sev::Fatal => anyhow::bail!("Config error in '{}': {}", path, i.line_text()),
                _ => tracing::warn!("{}", i.message),
            }
        }

        // Unparseable blocked_ips entries are dropped (one typo must not refuse
        // the whole config), but loudly.
        for i in cfg.compile() {
            eprintln!("[config] {}", i.message);
        }

        cfg.finalize(&mut crate::route_ids::RouteIds::default());
        // A missing root degrades only its own route (503 + Retry-After until it appears).
        for route in cfg
            .route
            .iter()
            .filter(|r| r.is_static() && r.canonical_static_root.is_none())
        {
            tracing::error!(
                "config: route '{}' DEGRADED (E301) — static_root {:?} does not resolve; 503 until the directory exists",
                route.name, route.static_root.as_deref().unwrap_or("")
            );
        }
        Ok(cfg)
    }

    /// Route identities in file order (see check_rules::route_identities).
    pub fn route_ids(&self) -> Vec<String> {
        let names: Vec<&str> = self.route.iter().map(|r| r.name.as_str()).collect();
        crate::check_rules::route_identities(&names)
    }

    /// WAF precompilation. Returns W402 for blocked_ips entries it had to drop.
    pub fn compile(&mut self) -> Vec<Issue> {
        let mut out = Vec::new();
        self.security.compiled_patterns = self
            .security
            .block_header_patterns
            .iter()
            .map(|p| p.to_lowercase().into_bytes())
            .collect();
        self.security.compiled_ua_blocks = self
            .security
            .block_user_agents
            .iter()
            .map(|p| p.trim().to_lowercase().into_bytes())
            .filter(|p| !p.is_empty())
            .collect();
        let mut nets = Vec::with_capacity(self.security.blocked_ips.len());
        for s in &self.security.blocked_ips {
            match BlockedNet::parse(s) {
                Some(n) => nets.push(n),
                None if !s.trim().is_empty() => out.push(
                    Issue::new(
                        Sev::Warning,
                        "W402",
                        format!("ignoring unparseable blocked_ips entry: {:?}", s),
                    )
                    .at("security", Some("blocked_ips")),
                ),
                None => {}
            }
        }
        self.security.blocked_ip_nets = nets;
        out
    }

    /// Name-stable ids (a fresh table gives slot = uid = position) and canonical static
    /// roots; never fails (an unresolvable root stays None and the route is degraded).
    pub fn finalize(
        &mut self,
        ids: &mut crate::route_ids::RouteIds,
    ) -> crate::route_ids::Assignment {
        let a = ids.assign(&self.route_ids(), std::time::Instant::now());
        for (route, id) in self.route.iter_mut().zip(&a.ids) {
            route.id = id.slot;
            route.uid = id.uid;
            // Resolved once so the request path never re-resolves it; a relative root pins to the CWD.
            route.canonical_static_root = match (&route.mode, &route.static_root) {
                (RouteMode::Static, Some(root)) => std::path::Path::new(root)
                    .canonicalize()
                    .ok()
                    .filter(|p| p.is_dir()),
                _ => None,
            };
        }
        a
    }

    /// Every file-intrinsic refusal (F201-F208) plus the two mode warnings, collected.
    pub fn validate_all(&self) -> Vec<Issue> {
        let ids = self.route_ids();
        let mut out = Vec::new();
        let fatal = |code: &'static str, msg: String| Issue::new(Sev::Fatal, code, msg);

        if self.route.is_empty() {
            out.push(
                fatal("F201", "No [[route]] entries — nothing to proxy.".into())
                    .at("", Some("route")),
            );
        }

        // A duplicate host would silently shadow the earlier route in
        // Gateway's route_map (last insert wins) — refuse it up front.
        let mut host_owners: HashMap<String, &str> = HashMap::new();
        for (i, r) in self.route.iter().enumerate() {
            for h in &r.hosts {
                if let Some(prev) = host_owners.insert(h.to_lowercase(), r.name.as_str()) {
                    out.push(
                        fatal(
                            "F202",
                            format!(
                                "Host '{}' is claimed by both route '{}' and route '{}' — \
                         each host may appear in exactly one route.",
                                h, prev, r.name
                            ),
                        )
                        .at_route(i, &ids, Some("hosts")),
                    );
                }
            }
        }

        for (i, r) in self.route.iter().enumerate() {
            // Names outside the routes are served through the on-demand host list.
            if r.hosts.iter().any(|h| h == "*") {
                out.push(
                    fatal(
                        "F203",
                        format!(
                            "Route '{}': wildcard host '*' is not allowed. \
                     List extra names in the `on_demand_hosts` file and mark one \
                     proxy route with `on_demand_fallback = true` instead.",
                            r.name
                        ),
                    )
                    .at_route(i, &ids, Some("hosts")),
                );
            }

            match (&r.static_cert, &r.static_key) {
                (Some(_), None) | (None, Some(_)) => out.push(
                    fatal(
                        "F204",
                        format!(
                    "Route '{}': static_cert and static_key must both be set or both omitted.",
                    r.name
                ),
                    )
                    .at_route(
                        i,
                        &ids,
                        Some(if r.static_cert.is_some() {
                            "static_cert"
                        } else {
                            "static_key"
                        }),
                    ),
                ),
                _ => {}
            }

            for key in r.add_headers.keys() {
                let invalid = key.is_empty()
                    || key.bytes().any(|b| {
                        matches!(
                            b,
                            b'(' | b')'
                                | b'<'
                                | b'>'
                                | b'@'
                                | b','
                                | b';'
                                | b':'
                                | b'\\'
                                | b'"'
                                | b'/'
                                | b'['
                                | b']'
                                | b'?'
                                | b'='
                                | b'{'
                                | b'}'
                                | b' '
                                | b'\t'
                                | 0..=31 | 127
                        )
                    });
                if invalid {
                    out.push(
                        fatal(
                            "F205",
                            format!(
                                "Route '{}': add_headers key {:?} is not a valid HTTP header name.",
                                r.name, key
                            ),
                        )
                        .at_route(i, &ids, Some("add_headers")),
                    );
                }
            }

            match r.mode {
                RouteMode::Static => {
                    match r.static_root.as_deref() {
                        None => out.push(
                            fatal(
                                "F206",
                                format!(
                            "Route '{}': mode = \"static\" requires `static_root` to be set.",
                            r.name
                        ),
                            )
                            .at_route(i, &ids, Some("mode")),
                        ),
                        Some(root) if root.trim().is_empty() => out.push(
                            fatal(
                                "F206",
                                format!("Route '{}': `static_root` cannot be empty.", r.name),
                            )
                            .at_route(i, &ids, Some("static_root")),
                        ),
                        Some(_) => {}
                    }
                    if !r.upstream.trim().is_empty() {
                        out.push(
                            Issue::new(
                                Sev::Warning,
                                "W413",
                                format!(
                                    "Route '{}': mode = \"static\" — ignoring `upstream = {:?}`",
                                    r.name, r.upstream
                                ),
                            )
                            .at_route(i, &ids, Some("upstream")),
                        );
                    }
                }
                RouteMode::Proxy => {
                    if r.upstream.trim().is_empty() {
                        out.push(
                            fatal(
                                "F207",
                                format!(
                                    "Route '{}': mode = \"proxy\" (default) requires `upstream`.",
                                    r.name
                                ),
                            )
                            .at_route(i, &ids, None),
                        );
                    }
                    if r.static_root.is_some() {
                        out.push(
                            Issue::new(
                                Sev::Warning,
                                "W413",
                                format!(
                                    "Route '{}': mode = \"proxy\" — ignoring `static_root`",
                                    r.name
                                ),
                            )
                            .at_route(i, &ids, Some("static_root")),
                        );
                    }
                }
                RouteMode::Redirect => {
                    let target = r.redirect_to.as_deref().unwrap_or("").trim();
                    if target.is_empty() {
                        out.push(fatal("F208", format!(
                            "Route '{}': mode = \"redirect\" requires `redirect_to` (the target host).",
                            r.name
                        )).at_route(i, &ids, Some("mode")));
                    } else if target.contains('/') || target.contains(':') || target.contains(' ') {
                        out.push(fatal("F208", format!(
                            "Route '{}': redirect_to '{}' must be a bare host (no scheme, path, or port).",
                            r.name, target
                        )).at_route(i, &ids, Some("redirect_to")));
                    } else if r.hosts.iter().any(|h| h.eq_ignore_ascii_case(target)) {
                        out.push(fatal("F208", format!(
                            "Route '{}': redirect_to '{}' is also one of its own hosts — that would loop.",
                            r.name, target
                        )).at_route(i, &ids, Some("redirect_to")));
                    }
                    if let Some(code) = r.redirect_status {
                        if !matches!(code, 301 | 302 | 307 | 308) {
                            out.push(fatal("F208", format!(
                                "Route '{}': redirect_status {} invalid (use 301, 302, 307, or 308).",
                                r.name, code
                            )).at_route(i, &ids, Some("redirect_status")));
                        }
                    }
                }
            }
        }
        out
    }

    #[cfg(test)]
    fn validate(&self) -> anyhow::Result<()> {
        match self
            .validate_all()
            .into_iter()
            .find(|i| i.sev == Sev::Fatal)
        {
            Some(i) => anyhow::bail!("{}", i.message),
            None => Ok(()),
        }
    }

    pub fn acme_hosts(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.route
            .iter()
            // No static cert AND not opted out → managed by ACME. `ignore_ssl`
            // routes are excluded here so the edge never issues certs for them.
            .filter(|r| !r.has_static_cert() && !r.ignore_ssl)
            .flat_map(|r| r.hosts.iter())
            .filter(|h| *h != "*")
            .filter(|h| seen.insert(h.to_string()))
            .cloned()
            .collect()
    }
}

fn default_true() -> bool {
    true
}
fn default_not_found_status() -> u16 {
    404
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9090".to_string()
}

// ── ACME ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AcmeConfig {
    pub email: String,
    pub provider: String,
    #[serde(default)]
    pub eab_kid: String,
    #[serde(default)]
    pub eab_hmac: String,
    pub storage: String,
}

impl AcmeConfig {
    pub fn directory_url(&self) -> &'static str {
        match self.provider.as_str() {
            "letsencrypt" => "https://acme-v02.api.letsencrypt.org/directory",
            _ => "https://acme.zerossl.com/v2/DV90",
        }
    }
    pub fn has_eab(&self) -> bool {
        !self.eab_kid.is_empty() && !self.eab_hmac.is_empty()
    }
    pub fn cert_path(&self) -> String {
        format!("{}/bundle.crt", self.storage)
    }
    pub fn key_path(&self) -> String {
        format!("{}/bundle.key", self.storage)
    }
    pub fn bundle_exists(&self) -> bool {
        std::path::Path::new(&self.cert_path()).exists()
    }
    /// Returns a Let's Encrypt fallback config with same email + storage, no EAB.
    pub fn letsencrypt_fallback(&self) -> Self {
        Self {
            email: self.email.clone(),
            provider: "letsencrypt".to_string(),
            eab_kid: String::new(),
            eab_hmac: String::new(),
            storage: self.storage.clone(),
        }
    }
    pub fn is_letsencrypt(&self) -> bool {
        self.provider == "letsencrypt"
    }
}

/// One blocked network, parsed once at config load. Bare addresses are
/// host routes (/32 or /128); masks are applied at parse so `contains`
/// is two integer ops per entry.
#[derive(Debug, Clone, Copy)]
pub enum BlockedNet {
    V4 { net: u32, bits: u8 },
    V6 { net: u128, bits: u8 },
}

impl BlockedNet {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() || s.starts_with('#') {
            return None;
        }
        let (addr, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        match addr.trim().parse::<std::net::IpAddr>().ok()? {
            std::net::IpAddr::V4(v4) => {
                let bits = bits.unwrap_or(32).min(32);
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits as u32)
                };
                Some(Self::V4 {
                    net: u32::from(v4) & mask,
                    bits,
                })
            }
            std::net::IpAddr::V6(v6) => {
                let bits = bits.unwrap_or(128).min(128);
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits as u32)
                };
                Some(Self::V6 {
                    net: u128::from(v6) & mask,
                    bits,
                })
            }
        }
    }

    #[inline]
    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { net, bits }, std::net::IpAddr::V4(v4)) => {
                let mask = if *bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - *bits as u32)
                };
                (u32::from(*v4) & mask) == *net
            }
            (Self::V6 { net, bits }, std::net::IpAddr::V6(v6)) => {
                let mask = if *bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - *bits as u32)
                };
                (u128::from(*v6) & mask) == *net
            }
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    #[serde(default)]
    pub cloudflare_only: bool,
    #[serde(default)]
    pub maintenance_mode: bool,

    #[serde(default)]
    pub block_empty_user_agent: bool,
    #[serde(default = "default_true")]
    pub block_scanners: bool,
    #[serde(default = "default_timeout")]
    pub global_timeout_secs: u64,
    #[serde(default = "default_rps")]
    pub default_rate_limit: u32,
    #[serde(default = "default_burst")]
    pub default_burst: u32,
    #[serde(default = "default_inflight")]
    pub max_inflight_per_ip: usize,
    #[serde(default = "default_true")]
    pub reject_invalid_content_length: bool,
    #[serde(default = "default_true")]
    pub reject_header_injection: bool,
    #[serde(default = "default_max_body")]
    pub max_request_body: usize,
    #[serde(default)]
    pub block_header_patterns: Vec<String>,

    #[serde(skip)]
    pub compiled_patterns: Vec<Vec<u8>>,

    // ── Operator blocklists ──────────────────────────────────────────────
    // Substring matches against the User-Agent (case-insensitive) and
    // IPs/CIDRs matched against BOTH the TCP peer and the resolved visitor
    // IP. Enforced for everyone except trusted IPs and loopback, verified
    // search crawlers included: the operator's list is the operator's call.
    #[serde(default)]
    pub block_user_agents: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,

    #[serde(skip)]
    pub compiled_ua_blocks: Vec<Vec<u8>>,
    #[serde(skip)]
    pub blocked_ip_nets: Vec<BlockedNet>,

    #[serde(default = "default_penalty_ttl")]
    pub penalty_box_ttl_secs: u64,
    #[serde(default = "default_penalty_cap")]
    pub penalty_box_capacity: u64,
    #[serde(default = "default_keepalive_reqs")]
    pub keepalive_max_requests: usize,
    #[serde(default = "default_global_conn_limit")]
    pub global_connection_limit: usize,

    // Ceiling on TLS connections held simultaneously by the :443 PRE-FILTER.
    // Distinct from global_connection_limit, which Pingora applies BEHIND the
    // pre-filter and so cannot bound it. Each held connection costs one
    // ephemeral port on the loopback leg to Pingora, and Linux's default range
    // (32768-60999) is only ~28k — so this must stay well under that or the
    // kernel starts refusing connects and every new TLS handshake fails while
    // the process keeps running. 0 = unlimited (not advised).
    #[serde(default = "default_max_live_tls")]
    pub max_live_tls: usize,

    // How long a kept-alive HTTP/1 connection may sit idle between requests, in
    // seconds; 0 = as long as the client likes (Pingora's default, and a CDN
    // may then hold ~15 min of idle connections at ~120 KiB each). Unset = from
    // the box's RAM: 60 s under 2 GiB, 120 s under 8 GiB, else 0.
    #[serde(default)]
    pub keepalive_idle_secs: Option<u64>,

    // ── HTTP/2 ───────────────────────────────────────────────────────────
    // h2 is ON by default: it is what browsers and crawlers negotiate, and
    // turning it off costs real performance. It is a toggle because it is
    // also the only instant, total mitigation for a rapid-reset flood — an
    // attack that cannot exist over HTTP/1.1, where one request needs one
    // connection and the pre-filter can see it. Set false to fall back.
    #[serde(default = "default_true")]
    pub http2_enabled: bool,

    // Cap on concurrently-open H2 streams per connection. Bounds how much
    // upstream work a single connection can have in flight. NOT a defence
    // against rapid reset on its own — a reset frees the slot instantly —
    // but it is the floor under everything else.
    #[serde(default = "default_h2_streams")]
    pub h2_max_concurrent_streams: u32,

    // Client-cancelled streams per IP per 10s before the IP is blocked at
    // the TLS pre-filter. Browsers cancel constantly (every navigate-away),
    // so this must sit far above normal: the default is ~100x a busy real
    // client. 0 = disabled.
    #[serde(default = "default_h2_cancel_threshold")]
    pub h2_cancel_threshold: u32,

    // Streams one H2 connection may open before every further stream on it is
    // rejected cheaply (429, no upstream work). This is the per-connection
    // request cap that h2 never had: `keepalive_max_requests` lives in the
    // per-request CTX, and pingora creates a fresh CTX per STREAM on h2, so
    // that guillotine counts to one and never fires. 0 = disabled.
    #[serde(default = "default_h2_max_streams_per_conn")]
    pub h2_max_streams_per_conn: u32,

    // ── Upstream circuit breaker (nginx max_fails / fail_timeout) ────────
    // Consecutive upstream failures before the edge stops dialling a backend
    // and answers 503 itself. Without this, a dead backend is re-dialled once
    // per request — thousands of refused connects per second, and a boot storm
    // aimed at a container that is trying to start. 0 = disabled.
    #[serde(default = "default_upstream_max_fails")]
    pub upstream_max_fails: u32,

    // Seconds the breaker stays open before ONE probe request is allowed
    // through. Short: recovery should be quick, and only one request pays for
    // discovering the backend is still down.
    #[serde(default = "default_upstream_fail_timeout")]
    pub upstream_fail_timeout_secs: u64,

    // ── Connection-rate gate (nginx limit_conn / limit_req) ──────────────
    // Connections one IP may open per 10s before being refused at :443,
    // BEFORE the TLS handshake. This is the only bound on handshake cost: a
    // client that completes a handshake and then vanishes has already spent
    // our CPU, and no post-hoc heuristic can refund it. Cloudflare IPs and
    // verified crawlers are exempt. 0 = disabled.
    #[serde(default = "default_conn_rate_per_ip")]
    pub conn_rate_per_ip: u32,

    // Hard ceiling on concurrent direct (non-Cloudflare) TLS connections,
    // independent of max_live_tls. The CF share reservation is a FLOOR for
    // direct traffic, not a ceiling: it guarantees direct visitors can always
    // get in, and does nothing to stop them taking everything, which is what a
    // flood does. Bounds worst-case edge CPU and keeps direct traffic from
    // starving CDN-fronted routes. 0 = uncapped.
    #[serde(default = "default_max_live_direct")]
    pub max_live_direct: usize,

    // Direct ceiling while the on-demand fallback route's backend is DOWN,
    // decided by that route's circuit breaker. Shrinks automatically when the
    // breaker opens and restores on the first successful probe.
    //
    // Why bother: a dead backend does not make the attack cheaper. Connections
    // still complete a full TLS handshake — the expensive part, and it happens
    // before routing exists — and only then meet a 503. Holding the normal
    // budget open in that state spends CPU to produce error pages.
    // 0 = disabled (the ceiling never changes).
    #[serde(default = "default_max_live_direct_degraded")]
    pub max_live_direct_degraded: usize,

    // While the on-demand fallback backend is down, REFUSE direct connections
    // at :443 instead of terminating TLS for them and answering 503.
    //
    // The degraded ceiling above only refuses connections ABOVE it; the ones
    // below still pay a full handshake to be told the site is down. This
    // refuses at accept — two atomic reads, no crypto — which is the only way
    // to make a dead backend actually cheap. Cloudflare traffic, trusted IPs
    // and verified crawlers are never dropped.
    #[serde(default)]
    pub drop_direct_when_backend_down: bool,

    // ── TLS ClientHello fingerprint gate ─────────────────────────────────
    // Connections per fingerprint per 10s. A residential pool rotates the
    // source ADDRESS; it does not rotate the client SOFTWARE, and the cipher
    // list, extension list and their order are properties of the TLS library.
    // So one fingerprint covers the whole botnet however many exits it burns —
    // the only key here that survives rotation. 0 = disabled.
    #[serde(default = "default_tls_fp_rate")]
    pub tls_fp_rate: u32,

    // false = SHADOW: count what would have been refused, refuse nothing.
    // Start here. A fingerprint groups client SOFTWARE, not clients, so every
    // Chrome 120 on earth shares one — set the rate too low and you refuse a
    // slice of the real internet before TLS, with no appeal. Read
    // tls_fp_top on the dashboard first and confirm the heavy fingerprints
    // are the attack, not your readers' browser.
    #[serde(default)]
    pub tls_fp_enforce: bool,

    // ── Abuse tracker ────────────────────────────────────────────────────
    // Strikes before an IP is dropped at :443, and how long the block lasts.
    //
    // The block window is what decides whether a ROTATING proxy pool can be
    // outlasted: the blocked set holds (block rate x window) addresses, so at
    // ~2 IPs/s a 300s window holds ~600 and a pool bigger than that never runs
    // dry. Longer windows hold proportionally more.
    //
    // Trade-off: residential addresses are shared and recycled, so a long block
    // can catch a real visitor who inherited an address an attacker used.
    #[serde(default = "default_abuse_strikes")]
    pub abuse_strikes: u32,
    #[serde(default = "default_abuse_block_secs")]
    pub abuse_block_secs: u64,

    // Anti-residential-proxy DDoS: global RPS cap across ALL source IPs.
    // When total RPS exceeds this, excess requests get 503'd instantly.
    // 0 = disabled. Recommended: 2000-5000 for single-server setups.
    #[serde(default = "default_global_rps")]
    pub global_rps_limit: u32,

    // Per-UA-fingerprint rate limit. Botnets reuse the same User-Agent
    // across millions of IPs. This caps RPS per unique UA string.
    // 0 = disabled. Recommended: 100-300.
    #[serde(default = "default_fingerprint_rps")]
    pub fingerprint_rps: u32,
    #[serde(default = "default_fingerprint_burst")]
    pub fingerprint_burst: u32,

    /// Trusted infrastructure IPs (monitoring, health checkers, admin hosts)
    /// exempt from abuse tracking at both the TLS and HTTP layers, so a
    /// health checker that gets banned can still observe recovery.
    /// e.g. trusted_ips = ["203.0.113.10", "10.0.0.0/8"]
    #[serde(default)]
    pub trusted_ips: Vec<String>,

    /// Header that carries the visitor address to the upstream, and between
    /// chained edges. Always set on proxied requests (and any inbound copy is
    /// stripped first).
    #[serde(default = "default_real_ip_header")]
    pub real_ip_header: String,

    /// Header that carries the HMAC of `real_ip_header` when `real_ip_secret`
    /// is set. Format: `<unix-ts>.<hex HMAC-SHA256("<ip>|<ts>")>`.
    #[serde(default = "default_real_ip_sig_header")]
    pub real_ip_sig_header: String,

    /// Chained edges: when this instance sits BEHIND another trusted edge
    /// (front edge, then a CDN, then this one), trust an inbound
    /// `real_ip_header` from a trusted peer instead of recomputing the visitor
    /// address (which at this layer would be the front edge or the CDN). MUST
    /// stay `false` on any internet-facing instance, otherwise a client could
    /// spoof its own address. Only enable on an inner instance whose peers are
    /// all trusted (CF ranges and `trusted_ips`).
    #[serde(default)]
    pub trust_upstream_real_ip: bool,

    /// Shared secret between chained edges: signs the outbound real-IP header
    /// and checks an inbound one. "" = no signing. Never logged or shown.
    #[serde(default)]
    pub real_ip_secret: String,

    /// With real_ip_secret set, honour an upstream real-IP header only when its
    /// signature is valid; otherwise only count signed/unsigned/bad.
    #[serde(default)]
    pub real_ip_verify: bool,

    /// Exempt live Cloudflare peers from pre-TLS strikes/blocks; unset = on when
    /// trust_upstream_real_ip or any cloudflare_only (instance or route) is set.
    #[serde(default)]
    pub trust_cloudflare: Option<bool>,
}

fn default_real_ip_header() -> String {
    "X-Real-IP".to_string()
}
fn default_real_ip_sig_header() -> String {
    "X-Real-IP-Sig".to_string()
}

impl SecurityConfig {
    /// CIDR-aware form of the trusted set: entries with a `/` are parsed as CIDR
    /// ranges, everything else as an exact IP. Loopback is always trusted. Used by
    /// the HTTP abuse/CF gates and the TLS pre-filter so an internal subnet can be
    /// allowed in one line.
    pub fn trusted_nets(&self) -> TrustedNets {
        let mut nets = TrustedNets::default();
        nets.exact.insert("127.0.0.1".parse().unwrap());
        nets.exact.insert("::1".parse().unwrap());
        for raw in &self.trusted_ips {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            if s.contains('/') {
                if let Ok(net) = s.parse::<Ipv4Net>() {
                    nets.v4.add(net);
                } else if let Ok(net) = s.parse::<Ipv6Net>() {
                    nets.v6.add(net);
                } else {
                    tracing::warn!(
                        "SecurityConfig.trusted_ips: ignoring invalid CIDR {:?}",
                        raw
                    );
                }
            } else if let Ok(ip) = s.parse::<IpAddr>() {
                nets.exact.insert(ip);
            } else {
                tracing::warn!(
                    "SecurityConfig.trusted_ips: ignoring invalid entry {:?}",
                    raw
                );
            }
        }
        nets.v4.simplify();
        nets.v6.simplify();
        nets
    }
}

fn default_rps() -> u32 {
    50
}
fn default_burst() -> u32 {
    100
}
fn default_inflight() -> usize {
    150
}
fn default_timeout() -> u64 {
    60
}
fn default_max_body() -> usize {
    5 * 1024 * 1024
}
fn default_penalty_ttl() -> u64 {
    300
}
fn default_penalty_cap() -> u64 {
    100_000
}
fn default_keepalive_reqs() -> usize {
    100
}
fn default_global_conn_limit() -> usize {
    8_000
}
fn default_max_live_tls() -> usize {
    40_000
}

/// `max_live_tls` as the edge runs it: a value the file sets is taken as
/// written; the shipped default is capped to what the box's RAM carries, so a
/// 1 GB VM sheds new connections before the kernel kills the edge.
pub fn effective_max_live_tls(s: &SecurityConfig) -> usize {
    if s.max_live_tls == default_max_live_tls() {
        s.max_live_tls.min(crate::tuning::TUNING.max_live_conns)
    } else {
        s.max_live_tls
    }
}

/// The downstream keep-alive idle timeout in force (0 = no limit).
pub fn effective_keepalive_idle(s: &SecurityConfig) -> u64 {
    s.keepalive_idle_secs
        .unwrap_or(crate::tuning::TUNING.keepalive_idle_secs)
}
fn default_h2_streams() -> u32 {
    64
}
fn default_h2_cancel_threshold() -> u32 {
    200
}
fn default_h2_max_streams_per_conn() -> u32 {
    1_000
}
fn default_upstream_max_fails() -> u32 {
    10
}
fn default_upstream_fail_timeout() -> u64 {
    5
}
fn default_conn_rate_per_ip() -> u32 {
    100
}
fn default_max_live_direct() -> usize {
    0
}
fn default_max_live_direct_degraded() -> usize {
    0
}
fn default_tls_fp_rate() -> u32 {
    0
}
fn default_abuse_strikes() -> u32 {
    3
}
fn default_abuse_block_secs() -> u64 {
    300
}
fn default_global_rps() -> u32 {
    3_000
}
fn default_fingerprint_rps() -> u32 {
    200
}
fn default_fingerprint_burst() -> u32 {
    400
}

// ── Route ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RouteConfig {
    /// Breaker slot (route_ids.rs): name-stable, < 1024 or NO_SLOT.
    #[serde(skip)]
    pub id: usize,
    /// Rate-limit bucket id: name-stable and never handed to another route.
    #[serde(skip)]
    pub uid: u32,

    pub name: String,
    pub hosts: Vec<String>,

    // Required for mode = "proxy" (default); ignored for mode = "static".
    #[serde(default)]
    pub upstream: String,

    #[serde(default)]
    pub upstream_tls: bool,

    /// Offer HTTP/2 to the upstream (ALPN h2, falling back to http/1.1).
    ///
    /// Off by default because it changes the wire protocol to the origin and
    /// not every backend speaks h2. Turn it on where the upstream is a CDN or
    /// a modern server.
    ///
    /// Why it matters for CPU: pingora's default upstream ALPN is H1, and an
    /// H1 connection carries ONE request at a time. The number of live upstream
    /// connections therefore tracks CONCURRENCY, not request rate, so a burst
    /// past `upstream_keepalive_pool_size` opens new ones — and when
    /// `upstream_tls` is set, each of those is a full TLS handshake plus cert
    /// verification. On a 1 vCPU box that is the most expensive thing running.
    /// Over h2 the same burst becomes extra STREAMS on one connection.
    ///
    /// Leave unset to AUTO-DETECT: h2 is offered when the upstream resolves
    /// into a Cloudflare range (see `Gateway::upstream_peer`). Set `true` to
    /// force it on for a non-CF upstream you know speaks h2, or `false` to
    /// force it off.
    ///
    /// Only meaningful together with `upstream_tls` (ALPN is a TLS extension).
    #[serde(default)]
    pub upstream_h2: Option<bool>,

    /// Skip upstream certificate checks. Off by default; turn it on only for an
    /// upstream with a self-signed or mismatched certificate on a trusted path.
    #[serde(default)]
    pub insecure_skip_verify: bool,
    #[serde(default)]
    pub add_headers: HashMap<String, String>,
    #[serde(default)]
    pub rate_limit: Option<RouteLimitConfig>,

    #[serde(default)]
    pub cloudflare_only: bool,
    pub static_cert: Option<String>,
    pub static_key: Option<String>,

    /// Exact request paths that answer 301 instead of the not-found policy
    /// (static routes).
    ///
    /// A migration tool: when a site moves onto a static root, a few old URLs
    /// are worth keeping alive as redirects while the rest should simply be
    /// gone. The small set is named here and everything else falls through to
    /// `not_found_status`.
    ///
    /// Keys are request paths (`/2019/03/some-post/`). The trailing slash is
    /// matched either way, because links and sitemaps often disagree about it.
    #[serde(default)]
    pub redirects: HashMap<String, String>,

    /// Status for a path that resolves to nothing (static routes). 404 unless
    /// set to 410.
    ///
    /// 410 Gone tells clients and crawlers the removal is deliberate, so they
    /// stop asking sooner than they would for a 404. Only 404 and 410 are
    /// honoured; any other value falls back to 404.
    #[serde(default = "default_not_found_status")]
    pub not_found_status: u16,

    /// Opt this route out of TLS cert *management* entirely. When true the edge
    /// neither loads its `static_cert` nor ACME-issues for its hosts; they are
    /// served the shared fallback cert instead. Use for CDN-fronted origins
    /// (the CDN terminates the real cert, so the origin cert name need not
    /// match) or to keep a route with a broken cert from taking the edge down.
    #[serde(default)]
    pub ignore_ssl: bool,

    /// Route mode: "proxy" (default) or "static".
    #[serde(default)]
    pub mode: RouteMode,

    /// Directory to serve from when mode = "static". Must exist at startup.
    pub static_root: Option<String>,

    /// Upstream read timeout for THIS route, overriding
    /// [security].global_timeout_secs.
    ///
    /// Exists because one global value has to serve two incompatible needs. A
    /// tight timeout is what stops a wedged backend pinning edge workers for a
    /// minute under load — but backends are not alike, and a route that renders
    /// a PDF on demand can legitimately take far longer than one serving a
    /// cached article. Without a per-route knob the global has to be set for
    /// the SLOWEST backend, which means every fast route keeps holding workers
    /// it should have released.
    #[serde(default)]
    pub timeout_secs: Option<u64>,

    /// This route serves every hostname on the on-demand host list
    /// (`on_demand_hosts`), i.e. names that match no `hosts` entry. Those
    /// requests keep their own Host header upstream.
    ///
    /// Declared, not inferred: a flag cannot be renamed by accident, so the
    /// on-demand traffic never lands on an unrelated route's upstream, limits
    /// or breaker.
    #[serde(default)]
    pub on_demand_fallback: bool,

    /// Target host for mode = "redirect" (e.g. "example.com"). Every host in
    /// `hosts` 301s to https://<redirect_to><path?query>.
    #[serde(default)]
    pub redirect_to: Option<String>,

    /// Redirect status for mode = "redirect" (301 permanent by default; 302 if you
    /// want a temporary move). Only 301/302/307/308 are accepted.
    #[serde(default)]
    pub redirect_status: Option<u16>,

    /// Canonical form of `static_root`, resolved once at config load.
    /// None for a static route whose root did not resolve to a directory (degraded, 503).
    #[serde(skip)]
    pub canonical_static_root: Option<std::path::PathBuf>,
}
impl RouteConfig {
    #[inline]
    pub fn is_static(&self) -> bool {
        self.mode == RouteMode::Static
    }

    #[inline]
    pub fn is_redirect(&self) -> bool {
        self.mode == RouteMode::Redirect
    }

    /// The configured 301/302 target for a redirect route ("" if not a redirect).
    #[inline]
    pub fn redirect_target(&self) -> &str {
        self.redirect_to.as_deref().unwrap_or("")
    }

    /// Redirect status code (301 default; validated to 301/302/307/308 at load).
    #[inline]
    pub fn redirect_code(&self) -> u16 {
        self.redirect_status.unwrap_or(301)
    }

    #[inline]
    pub fn has_static_cert(&self) -> bool {
        self.static_cert.is_some() && self.static_key.is_some()
    }

    /// Whether this route contributes a dedicated static cert to the SNI map.
    /// `ignore_ssl` routes have `static_cert` set but are deliberately skipped:
    /// not loaded, not ACME-issued — they fall back to the shared cert.
    #[inline]
    pub fn uses_static_cert(&self) -> bool {
        self.has_static_cert() && !self.ignore_ssl
    }

    /// Returns `(connect_addr, use_tls)`.
    pub fn upstream_addr(&self) -> (String, bool) {
        let raw = self.upstream.trim_end_matches('/');

        let scheme_tls = raw.starts_with("https://");
        let tls = scheme_tls || self.upstream_tls;

        let host = raw
            .trim_start_matches("https://")
            .trim_start_matches("http://");

        let addr = if host.contains(':') {
            host.to_string()
        } else if tls {
            format!("{}:443", host)
        } else {
            format!("{}:80", host)
        };

        (addr, tls)
    }

    pub fn upstream_sni(&self) -> String {
        self.upstream
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .split(':')
            .next()
            .unwrap_or("")
            .to_string()
    }

    pub fn effective_rps(&self, sec: &SecurityConfig) -> u32 {
        self.rate_limit
            .as_ref()
            .map(|r| r.rps)
            .unwrap_or(sec.default_rate_limit)
    }
    pub fn effective_burst(&self, sec: &SecurityConfig) -> u32 {
        self.rate_limit
            .as_ref()
            .map(|r| r.burst)
            .unwrap_or(sec.default_burst)
    }
    /// Upstream read timeout for this route: its own override, else the global.
    pub fn effective_timeout(&self, sec: &SecurityConfig) -> u64 {
        self.timeout_secs.unwrap_or(sec.global_timeout_secs)
    }
}

/// Which route serves the on-demand host list, as a position in `routes` (its
/// breaker slot is that route's `id`).
///
/// One resolver so the proxy, the circuit breaker and the pre-filter's
/// backend-down shed can never disagree about which route that is. Only the
/// explicit `on_demand_fallback = true` counts. Deliberately NOT "first proxy
/// route": silently adopting an unrelated route would let an on-demand flood
/// trip the breaker of a route that has nothing to do with it.
pub fn fallback_route_index(routes: &[RouteConfig]) -> Option<usize> {
    routes.iter().position(|r| r.on_demand_fallback)
}

/// Exempt live Cloudflare peers from pre-TLS strikes: explicit, else implied by any CF gate.
pub fn effective_trust_cf(cfg: &ProxyConfig) -> bool {
    cfg.security.trust_cloudflare.unwrap_or(
        cfg.security.trust_upstream_real_ip
            || cfg.security.cloudflare_only
            || cfg.route.iter().any(|r| r.cloudflare_only),
    )
}

/// CF ranges back the cloudflare_only gates, trust_cf, and the upstream-h2 auto-detect in
/// Gateway::upstream_peer (routes left on auto with a TLS upstream); without them
/// is_cloudflare_ip answers false for everything.
pub fn needs_cf_ranges(cfg: &ProxyConfig) -> bool {
    effective_trust_cf(cfg)
        || cfg.security.cloudflare_only
        || cfg.route.iter().any(|r| r.cloudflare_only)
        || cfg
            .route
            .iter()
            .any(|r| r.upstream_h2.is_none() && !r.upstream.is_empty() && r.upstream_addr().1)
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RouteLimitConfig {
    pub rps: u32,
    pub burst: u32,
}

/// Client-supplied headers removed before every proxied request. The configured
/// `real_ip_header` and `real_ip_sig_header` are stripped as well.
pub const STRIP_HEADERS: &[&str] = &[
    "X-Real-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
];

pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("X-XSS-Protection", "1; mode=block"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload",
    ),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    (
        "Permissions-Policy",
        "geolocation=(), camera=(), microphone=()",
    ),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Content-Security-Policy", "upgrade-insecure-requests"),
];

pub const CERT_RENEW_DAYS: i64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(routes: &str) -> ProxyConfig {
        let toml = format!(
            r#"
[acme]
email    = "ops@example.com"
provider = "letsencrypt"
storage  = "/tmp"

[security]

{routes}
"#
        );
        toml::from_str(&toml).unwrap()
    }

    #[test]
    fn duplicate_hosts_rejected() {
        let cfg = parse(
            r#"
[[route]]
name     = "a"
hosts    = ["x.example.com"]
upstream = "up-a:80"

[[route]]
name     = "b"
hosts    = ["X.Example.Com"]
upstream = "up-b:80"
"#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("claimed by both"), "got: {err}");
    }

    #[test]
    fn distinct_hosts_pass() {
        let cfg = parse(
            r#"
[[route]]
name     = "a"
hosts    = ["x.example.com"]
upstream = "up-a:80"

[[route]]
name     = "b"
hosts    = ["y.example.com"]
upstream = "up-b:80"
"#,
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn static_route_requires_root() {
        let cfg = parse(
            r#"
[[route]]
name  = "s"
hosts = ["s.example.com"]
mode  = "static"
"#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("requires `static_root`"), "got: {err}");
    }

    #[test]
    fn proxy_route_requires_upstream() {
        let cfg = parse(
            r#"
[[route]]
name  = "p"
hosts = ["p.example.com"]
"#,
        );
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("requires `upstream`"), "got: {err}");
    }
}
#[cfg(test)]
mod live_config_tests {
    use super::*;

    /// A config must parse WITH the key, and an older config WITHOUT it must
    /// still parse (serde default): an edge that cannot read its own config
    /// is down.
    #[test]
    fn max_live_tls_parses_and_defaults() {
        let with_key = r#"
default_rate_limit      = 100
global_connection_limit = 1000000
max_live_tls            = 12000
"#;
        let sec: SecurityConfig = toml::from_str(with_key).expect("config with max_live_tls");
        assert_eq!(sec.max_live_tls, 12_000);

        let without_key = r#"
default_rate_limit      = 100
global_connection_limit = 1000000
"#;
        let sec: SecurityConfig = toml::from_str(without_key).expect("config without the key");
        assert_eq!(sec.max_live_tls, 40_000, "must fall back to the default");
    }
}
