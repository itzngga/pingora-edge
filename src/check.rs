//! Config verifier: one pipeline behind `pingora-edge --check`, the boot loader and the reloader.
//! FATAL is exactly what boot has always refused; every newer rule is ERROR or softer.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use serde::de::{DeserializeOwned, Visitor};
use serde_json::{json, Value};

use crate::check_rules::{self as rules, Where};
use crate::config::{
    fallback_route_index, needs_cf_ranges, AcmeConfig, BlocklistConfig, ProxyConfig, RouteConfig,
    RouteLimitConfig, RouteMode, SecurityConfig, STRIP_HEADERS,
};
use crate::limiter::TTL_MAX_SECS;
use crate::tls_sni::{probe_pair, PairFault};

pub const MAX_BYTES: usize = 16 << 20;
const SECRET_MSG: &str = "syntax/type error on a line holding a secret (value not shown)";
const BROWSER_TOKENS: &[&str] = &["mozilla", "chrome", "safari", "applewebkit", "gecko"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sev {
    Fatal,
    Error,
    Warning,
    Info,
    Notice,
}

impl Sev {
    pub fn as_str(self) -> &'static str {
        match self {
            Sev::Fatal => "fatal",
            Sev::Error => "error",
            Sev::Warning => "warning",
            Sev::Info => "info",
            Sev::Notice => "notice",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Sev::Fatal => "FATAL",
            Sev::Error => "ERROR",
            Sev::Warning => "WARN",
            Sev::Info => "INFO",
            Sev::Notice => "NOTICE",
        }
    }
}

#[derive(Clone, Debug)]
enum Loc {
    Nowhere,
    Route(usize, Option<String>),
    Section(String, Option<String>),
}

/// One finding. Messages never carry a secret value, only key paths.
#[derive(Clone, Debug)]
pub struct Issue {
    pub sev: Sev,
    pub code: &'static str,
    pub path: Option<String>,
    pub route: Option<String>,
    pub line: Option<usize>,
    pub col: Option<usize>,
    pub host: bool,
    pub message: String,
    pub hint: Option<String>,
    loc: Loc,
}

impl Issue {
    pub fn new(sev: Sev, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            sev,
            code,
            path: None,
            route: None,
            line: None,
            col: None,
            host: false,
            message: message.into(),
            hint: None,
            loc: Loc::Nowhere,
        }
    }

    /// `route[<id>]` or `route[<id>].<field>`; the field may be dotted (`rate_limit.rps`).
    pub fn at_route(mut self, idx: usize, ids: &[String], field: Option<&str>) -> Self {
        let id = ids.get(idx).cloned().unwrap_or_else(|| format!("#{}", idx));
        self.path = Some(match field {
            Some(f) => format!("route[{}].{}", id, f),
            None => format!("route[{}]", id),
        });
        self.route = Some(id);
        self.loc = Loc::Route(idx, field.map(str::to_string));
        self
    }

    /// `section.key`; an empty section is the top level.
    pub fn at(mut self, section: &str, key: Option<&str>) -> Self {
        self.path = Some(match key {
            Some(k) if section.is_empty() => k.to_string(),
            Some(k) => format!("{}.{}", section, k),
            None => section.to_string(),
        });
        self.loc = Loc::Section(section.to_string(), key.map(str::to_string));
        self
    }

    pub fn at_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn hint(mut self, h: impl Into<String>) -> Self {
        self.hint = Some(h.into());
        self
    }

    pub fn on_host(mut self) -> Self {
        self.host = true;
        self
    }

    fn pos(mut self, lc: Option<(usize, usize)>) -> Self {
        if let Some((l, c)) = lc {
            self.line = Some(l);
            self.col = Some(c);
        }
        self
    }

    /// `CODE path (line:col): message — hint`
    pub fn line_text(&self) -> String {
        let mut s = self.code.to_string();
        if let Some(p) = &self.path {
            s.push(' ');
            s.push_str(p);
        }
        if let (Some(l), Some(c)) = (self.line, self.col) {
            s.push_str(&format!(" ({}:{})", l, c));
        }
        s.push_str(": ");
        s.push_str(&self.message);
        if let Some(h) = &self.hint {
            s.push_str(" — ");
            s.push_str(h);
        }
        s
    }

    pub fn to_json(&self) -> Value {
        json!({
            "severity": self.sev.as_str(), "code": self.code, "path": self.path, "route": self.route,
            "line": self.line, "col": self.col, "host": self.host, "message": self.message, "hint": self.hint,
        })
    }
}

// ── Field harvester: the keys serde reads for a struct (serde(skip) excluded) ──

struct Harvest<'a>(&'a mut Vec<&'static str>);

#[derive(Debug)]
struct Stop;

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("harvested")
    }
}

impl std::error::Error for Stop {}

impl serde::de::Error for Stop {
    fn custom<T: std::fmt::Display>(_: T) -> Self {
        Stop
    }
}

impl<'de> serde::Deserializer<'de> for Harvest<'_> {
    type Error = Stop;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Stop> {
        Err(Stop)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Stop> {
        self.0.extend_from_slice(fields);
        Err(Stop)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
    }
}

pub fn fields_of<T: DeserializeOwned>() -> Vec<&'static str> {
    let mut v = Vec::new();
    let _ = T::deserialize(Harvest(&mut v));
    v
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

pub struct CheckOpts {
    pub host: bool,
    pub workdir: PathBuf,
    pub strict: bool,
}

#[derive(Default)]
pub struct Summary {
    pub routes: usize,
    pub hosts: usize,
    pub acme_hosts: usize,
    pub static_cert_routes: usize,
    pub fallback_route: Option<String>,
    pub proxy: usize,
    pub statics: usize,
    pub redirect: usize,
}

pub struct Report {
    pub cfg: Option<ProxyConfig>,
    pub issues: Vec<Issue>,
    pub sha256: [u8; 32],
    pub bytes: usize,
    pub summary: Summary,
}

impl Report {
    pub fn count(&self, s: Sev) -> usize {
        self.issues.iter().filter(|i| i.sev == s).count()
    }

    pub fn ok(&self) -> bool {
        self.count(Sev::Fatal) == 0 && self.count(Sev::Error) == 0
    }
}

pub fn sha256(raw: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, raw);
    let mut out = [0u8; 32];
    for (o, b) in out.iter_mut().zip(d.as_ref()) {
        *o = *b;
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub struct Parsed {
    pub table: Option<toml::Table>,
    pub cfg: Option<ProxyConfig>,
    pub ids: Vec<String>,
}

/// Steps 1-2: size, UTF-8, TOML syntax (F102), then types (F103/F104). Parse errors use
/// message() + span only — toml's Display quotes the source line, secrets included.
pub fn parse(raw: &[u8], out: &mut Vec<Issue>) -> Parsed {
    let mut p = Parsed {
        table: None,
        cfg: None,
        ids: Vec::new(),
    };
    if raw.len() > MAX_BYTES {
        out.push(Issue::new(
            Sev::Fatal,
            "F101",
            format!("the file is over {} MiB", MAX_BYTES >> 20),
        ));
        return p;
    }
    let src = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(e) => {
            out.push(Issue::new(
                Sev::Fatal,
                "F101",
                format!("not UTF-8 (invalid byte at offset {})", e.valid_up_to()),
            ));
            return p;
        }
    };
    let table = match toml::from_str::<toml::Table>(src) {
        Ok(t) => t,
        Err(e) => {
            out.push(toml_issue(src, None, &[], &e, "F102"));
            return p;
        }
    };
    let names: Vec<&str> = table
        .get("route")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|r| r.get("name").and_then(|n| n.as_str()).unwrap_or(""))
                .collect()
        })
        .unwrap_or_default();
    p.ids = rules::route_identities(&names);
    match toml::from_str::<ProxyConfig>(src) {
        Ok(c) => p.cfg = Some(c),
        Err(e) => out.push(toml_issue(src, Some(&table), &p.ids, &e, "F103")),
    }
    p.table = Some(table);
    p
}

fn secret_values(t: &toml::Table) -> Vec<String> {
    let mut v = Vec::new();
    let mut push = |x: Option<&toml::Value>| {
        if let Some(x) = x {
            v.push(match x {
                toml::Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        }
    };
    push(t.get("acme").and_then(|a| a.get("eab_kid")));
    push(t.get("acme").and_then(|a| a.get("eab_hmac")));
    push(t.get("security").and_then(|a| a.get("real_ip_secret")));
    push(t.get("blocklist").and_then(|a| a.get("token")));
    for r in t
        .get("route")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
    {
        for h in r
            .get("add_headers")
            .and_then(|h| h.as_table())
            .into_iter()
            .flat_map(|h| h.values())
        {
            push(Some(h));
        }
    }
    v
}

fn toml_issue(
    src: &str,
    table: Option<&toml::Table>,
    ids: &[String],
    e: &toml::de::Error,
    code: &'static str,
) -> Issue {
    let msg = e.message().trim().to_string();
    let span = e.span();
    let lc = span.as_ref().map(|s| rules::line_col(src, s.start));
    let key = lc
        .and_then(|(l, _)| src.lines().nth(l.saturating_sub(1)))
        .and_then(rules::line_key);
    let (section, ridx) = span
        .as_ref()
        .map(|s| rules::table_at(src, s.start))
        .unwrap_or_default();
    let secret = lc.is_some_and(|(l, _)| rules::line_holds_secret(src, l))
        || table.is_some_and(|t| {
            secret_values(t)
                .iter()
                .any(|s| s.len() >= 4 && msg.contains(s.as_str()))
        });

    let mut code = code;
    let mut message = msg.clone();
    let mut hint = None;
    if code == "F103" && msg.starts_with("unknown variant") && key.as_deref() == Some("mode") {
        let value = msg.split('`').nth(1).unwrap_or("").to_string();
        code = "F104";
        message = format!("unknown mode {:?}", value);
        let lower = value.to_ascii_lowercase();
        hint = Some(if value == "reverse" {
            "omit `mode` for a proxy route".to_string()
        } else if matches!(lower.as_str(), "proxy" | "static" | "redirect") {
            format!("use the lowercase spelling \"{}\"", lower)
        } else {
            "use proxy, static or redirect (omit `mode` for a proxy route)".to_string()
        });
    }
    let mut issue = Issue::new(
        Sev::Fatal,
        code,
        if secret {
            SECRET_MSG.to_string()
        } else {
            message
        },
    );
    if let Some(h) = hint.filter(|_| !secret) {
        issue = issue.hint(h);
    }
    let field = match (section.strip_prefix("route."), key.as_deref()) {
        (Some(sub), Some(k)) => Some(format!("{}.{}", sub, k)),
        (Some(sub), None) => Some(sub.to_string()),
        (None, k) => k.map(str::to_string),
    };
    issue = match (ridx, field) {
        (Some(i), f) => issue.at_route(i, ids, f.as_deref()),
        (None, Some(k)) => issue.at(&section, Some(k.as_str())),
        (None, None) if !section.is_empty() => issue.at(&section, None),
        (None, None) => issue,
    };
    issue.pos(lc)
}

/// The whole pipeline on one file's bytes.
pub fn check_bytes(raw: &[u8], opts: &CheckOpts) -> Report {
    let mut issues = Vec::new();
    let Parsed { table, cfg, ids } = parse(raw, &mut issues);
    if let Some(t) = &table {
        walk_unknown(t, &ids, &mut issues);
    }
    let mut summary = Summary::default();
    let mut cfg_out = None;
    if let (Some(mut cfg), Some(t)) = (cfg, table.as_ref()) {
        issues.extend(cfg.validate_all());
        issues.extend(cfg.compile());
        semantic(&cfg, t, &ids, &mut issues);
        if opts.host {
            host_checks(&cfg, &ids, &opts.workdir, &mut issues);
        }
        summary = summarize(&cfg, &ids);
        cfg_out = Some(cfg);
    }
    finish(&mut issues, std::str::from_utf8(raw).unwrap_or(""));
    Report {
        cfg: cfg_out,
        issues,
        sha256: sha256(raw),
        bytes: raw.len(),
        summary,
    }
}

/// Fill line:col from key paths, then order: severity, then file order.
pub fn finish(issues: &mut [Issue], src: &str) {
    for i in issues.iter_mut().filter(|i| i.line.is_none()) {
        let lc = match &i.loc {
            Loc::Route(n, k) => rules::locate(src, Where::Route(*n), k.as_deref()),
            Loc::Section(s, k) => rules::locate(src, Where::Section(s.as_str()), k.as_deref()),
            Loc::Nowhere => None,
        };
        if let Some((l, c)) = lc {
            i.line = Some(l);
            i.col = Some(c);
        }
    }
    issues.sort_by_key(|i| (i.sev, i.line.unwrap_or(0)));
}

// ── Unknown keys ──────────────────────────────────────────────────────────────

/// A top-level table is located by its header, anything else by its `key =` line.
fn at_key(i: Issue, section: &str, key: &str, table: bool) -> Issue {
    if table && section.is_empty() {
        i.at(key, None)
    } else {
        i.at(section, Some(key))
    }
}

fn unknown_key(section: &str, key: &str, known: &[&str], table: bool) -> Issue {
    let full = |k: &str| {
        if section.is_empty() {
            k.to_string()
        } else {
            format!("{}.{}", section, k)
        }
    };
    let hint = match (section, key) {
        ("security", "trusted_proxies") => Some("did you mean security.trusted_ips?".to_string()),
        _ => rules::closest(key, known).map(|c| format!("did you mean {}?", full(c))),
    };
    let i = at_key(
        Issue::new(Sev::Warning, "W401", "unknown key, not read"),
        section,
        key,
        table,
    );
    match hint {
        Some(h) => i.hint(h),
        None => i,
    }
}

fn section_keys(v: &toml::Value, section: &str, known: &[&str], out: &mut Vec<Issue>) {
    let Some(t) = v.as_table() else { return };
    for k in t.keys().filter(|k| !known.contains(&k.as_str())) {
        out.push(unknown_key(section, k, known, false));
    }
}

fn route_keys(v: &toml::Value, ids: &[String], out: &mut Vec<Issue>) {
    let Some(arr) = v.as_array() else { return };
    let known = fields_of::<RouteConfig>();
    let lim = fields_of::<RouteLimitConfig>();
    for (i, r) in arr.iter().enumerate() {
        let Some(t) = r.as_table() else { continue };
        for (k, v) in t {
            if k == "rate_limit" {
                for rk in v
                    .as_table()
                    .into_iter()
                    .flat_map(|rt| rt.keys())
                    .filter(|x| !lim.contains(&x.as_str()))
                {
                    let mut is = Issue::new(Sev::Warning, "W401", "unknown key, not read")
                        .at_route(i, ids, Some(&format!("rate_limit.{}", rk)));
                    if let Some(c) = rules::closest(rk, &lim) {
                        is = is.hint(format!("did you mean rate_limit.{}?", c));
                    }
                    out.push(is);
                }
                continue;
            }
            if known.contains(&k.as_str()) {
                continue;
            }
            let hint = match k.as_str() {
                "rate_limit_rps" => Some("did you mean [route.rate_limit] rps?".to_string()),
                "rate_limit_burst" => Some("did you mean [route.rate_limit] burst?".to_string()),
                _ => rules::closest(k, &known).map(|c| format!("did you mean {}?", c)),
            };
            let is =
                Issue::new(Sev::Warning, "W401", "unknown key, not read").at_route(i, ids, Some(k));
            out.push(match hint {
                Some(h) => is.hint(h),
                None => is,
            });
        }
    }
}

fn walk_unknown(t: &toml::Table, ids: &[String], out: &mut Vec<Issue>) {
    let top = fields_of::<ProxyConfig>();
    for (k, v) in t {
        match k.as_str() {
            "acme" => section_keys(v, k, &fields_of::<AcmeConfig>(), out),
            "security" => section_keys(v, k, &fields_of::<SecurityConfig>(), out),
            "blocklist" => section_keys(v, k, &fields_of::<BlocklistConfig>(), out),
            "error_page" => {
                section_keys(v, k, &fields_of::<crate::errpage::ErrorPageConfig>(), out)
            }
            "route" => route_keys(v, ids, out),
            _ if top.contains(&k.as_str()) => {}
            _ => out.push(unknown_key("", k, &top, v.is_table())),
        }
    }
}

// ── Config-only rules (E2xx / W4xx / I502) ────────────────────────────────────

fn semantic(cfg: &ProxyConfig, table: &toml::Table, ids: &[String], out: &mut Vec<Issue>) {
    let sec = &cfg.security;
    let fb_idx = fallback_route_index(&cfg.route);
    let w = |code: &'static str, msg: String| Issue::new(Sev::Warning, code, msg);
    let e = |code: &'static str, msg: String| Issue::new(Sev::Error, code, msg);
    let route_table = |i: usize| {
        table
            .get("route")
            .and_then(|v| v.as_array())
            .and_then(|a| a.get(i))
            .and_then(|v| v.as_table())
    };

    let mut fb_seen = false;
    for (i, r) in cfg.route.iter().enumerate() {
        let explicit = |k: &str| route_table(i).is_some_and(|t| t.contains_key(k));
        let mode = match r.mode {
            RouteMode::Proxy => "proxy",
            RouteMode::Static => "static",
            RouteMode::Redirect => "redirect",
        };
        let mut inert = |field: &str, on: bool| {
            if on {
                out.push(
                    w(
                        "W413",
                        format!("{} has no effect on a {} route", field, mode),
                    )
                    .at_route(i, ids, Some(field)),
                );
            }
        };
        match r.mode {
            RouteMode::Proxy => {
                inert("redirect_to", r.redirect_to.is_some());
                inert("redirect_status", r.redirect_status.is_some());
                inert("redirects", !r.redirects.is_empty());
                inert("not_found_status", explicit("not_found_status"));
            }
            RouteMode::Static => {
                inert("upstream_tls", r.upstream_tls);
                inert("upstream_h2", r.upstream_h2.is_some());
                inert("timeout_secs", r.timeout_secs.is_some());
                inert("add_headers", !r.add_headers.is_empty());
                inert("redirect_to", r.redirect_to.is_some());
                inert("redirect_status", r.redirect_status.is_some());
            }
            RouteMode::Redirect => {
                inert("upstream", !r.upstream.trim().is_empty());
                inert("upstream_tls", r.upstream_tls);
                inert("upstream_h2", r.upstream_h2.is_some());
                inert("timeout_secs", r.timeout_secs.is_some());
                inert("add_headers", !r.add_headers.is_empty());
                inert("static_root", r.static_root.is_some());
                inert("redirects", !r.redirects.is_empty());
            }
        }

        if r.mode == RouteMode::Proxy {
            if !r.upstream.trim().is_empty() {
                if let Some(p) = rules::upstream_problem(&r.upstream) {
                    out.push(e("E201", format!("malformed upstream: {}", p)).at_route(
                        i,
                        ids,
                        Some("upstream"),
                    ));
                }
            }
            if r.timeout_secs == Some(0) {
                out.push(
                    e(
                        "E208",
                        "timeout_secs = 0 — every upstream read times out at once".into(),
                    )
                    .at_route(i, ids, Some("timeout_secs")),
                );
            }
            let tls = r.upstream_addr().1;
            if r.upstream_h2 == Some(true) && !tls {
                out.push(
                    w(
                        "W413",
                        "upstream_h2 without TLS — ALPN needs upstream_tls or https://".into(),
                    )
                    .at_route(i, ids, Some("upstream_h2")),
                );
            }
            if r.upstream.trim_start().starts_with("http://") && r.upstream_tls {
                out.push(
                    w(
                        "W413",
                        "an http:// upstream with upstream_tls = true is dialled over TLS".into(),
                    )
                    .at_route(i, ids, Some("upstream_tls")),
                );
            }
            if tls && r.insecure_skip_verify {
                out.push(Issue::new(Sev::Info, "I502", "insecure_skip_verify = true: this TLS upstream's certificate is not verified").at_route(i, ids, Some("insecure_skip_verify")));
            }
        }

        if r.on_demand_fallback {
            if r.mode != RouteMode::Proxy {
                out.push(
                    e(
                        "E202",
                        format!(
                            "on_demand_fallback on a {} route — on-demand hosts need a proxy route",
                            mode
                        ),
                    )
                    .at_route(i, ids, Some("on_demand_fallback")),
                );
            } else if fb_seen {
                out.push(
                    e(
                        "E202",
                        "more than one on_demand_fallback = true — only the first is used".into(),
                    )
                    .at_route(i, ids, Some("on_demand_fallback")),
                );
            }
            fb_seen = fb_seen || r.mode == RouteMode::Proxy;
        }

        if r.ignore_ssl && r.static_cert.is_some() {
            out.push(
                w(
                    "W413",
                    "ignore_ssl with static_cert — the cert is never loaded".into(),
                )
                .at_route(i, ids, Some("ignore_ssl")),
            );
        }
        if !matches!(r.not_found_status, 404 | 410) {
            out.push(
                w(
                    "W414",
                    format!(
                        "not_found_status {} is not honoured — 404 is served",
                        r.not_found_status
                    ),
                )
                .at_route(i, ids, Some("not_found_status")),
            );
        }
        for (k, v) in &r.redirects {
            if !k.starts_with('/') || k.chars().any(|c| c.is_whitespace() || c == '?' || c == '#') {
                out.push(
                    w(
                        "W414",
                        format!("redirects key {:?} is not a plain request path", k),
                    )
                    .at_route(i, ids, Some("redirects")),
                );
            } else if v.is_empty() || v.chars().any(char::is_control) {
                out.push(
                    w(
                        "W414",
                        format!(
                            "redirect target for {:?} is empty or has control characters — ignored",
                            k
                        ),
                    )
                    .at_route(i, ids, Some("redirects")),
                );
            }
        }
        for (k, v) in &r.add_headers {
            let f = format!("add_headers.{}", k);
            if rules::has_ctl_bytes(v) {
                out.push(e("E206", "value contains a control byte — the header would be dropped (value not shown)".into()).at_route(i, ids, Some(&f)));
            }
            if k.eq_ignore_ascii_case("host") {
                out.push(
                    w(
                        "W415",
                        "Host is always rewritten by the edge — this has no effect".into(),
                    )
                    .at_route(i, ids, Some(&f)),
                );
            } else if STRIP_HEADERS.iter().any(|s| s.eq_ignore_ascii_case(k)) {
                out.push(
                    w(
                        "W415",
                        format!(
                            "{} is a forwarding header the edge strips and sets itself",
                            k
                        ),
                    )
                    .at_route(i, ids, Some(&f)),
                );
            }
        }
        if let Some(rl) = &r.rate_limit {
            if rl.rps == 0 {
                out.push(
                    w("W404", "rps = 0 means 1 request/s, not off".into()).at_route(
                        i,
                        ids,
                        Some("rate_limit.rps"),
                    ),
                );
            }
            if rl.burst == 0 {
                out.push(w("W404", "burst = 0 means 1, not off".into()).at_route(
                    i,
                    ids,
                    Some("rate_limit.burst"),
                ));
            } else if rl.burst < rl.rps {
                out.push(
                    w(
                        "W404",
                        format!("burst {} is below rps {}", rl.burst, rl.rps),
                    )
                    .at_route(i, ids, Some("rate_limit.burst")),
                );
            }
        }
        for h in r.hosts.iter().filter(|h| *h != "*") {
            if let Some(p) = rules::host_issue(h) {
                out.push(w("W412", format!("host {:?}: {}", h, p)).at_route(i, ids, Some("hosts")));
            }
        }
        if r.hosts.iter().all(|h| h.trim().is_empty()) && !r.on_demand_fallback {
            out.push(
                w(
                    "W412",
                    "no hosts and not on_demand_fallback — the route matches nothing by name"
                        .into(),
                )
                .at_route(i, ids, Some("hosts")),
            );
        }
        let name = r.name.as_str();
        if name.trim().is_empty() {
            let id = ids.get(i).cloned().unwrap_or_default();
            out.push(
                w("W412", format!("empty route name — its identity is {}", id)).at_route(
                    i,
                    ids,
                    Some("name"),
                ),
            );
        } else if cfg.route.iter().take(i).any(|o| o.name == name) {
            out.push(
                w(
                    "W412",
                    format!(
                        "duplicate route name {:?} — identities fall back to name#k",
                        name
                    ),
                )
                .at_route(i, ids, Some("name")),
            );
        }
    }

    let on_global = cfg
        .route
        .iter()
        .filter(|r| r.mode == RouteMode::Proxy && r.timeout_secs.is_none())
        .count();
    if sec.global_timeout_secs == 0 && on_global > 0 {
        out.push(e("E208", format!("global_timeout_secs = 0 — upstream reads time out at once on {} proxy route(s)", on_global)).at("security", Some("global_timeout_secs")));
    }

    let graph: Vec<(Vec<String>, Option<String>)> = cfg
        .route
        .iter()
        .map(|r| {
            let hosts = r
                .hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .collect();
            let to = r
                .is_redirect()
                .then(|| r.redirect_target().trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty());
            (hosts, to)
        })
        .collect();
    for cyc in rules::redirect_cycles(&graph) {
        let names: Vec<String> = cyc
            .iter()
            .chain(cyc.first())
            .map(|j| ids.get(*j).cloned().unwrap_or_default())
            .collect();
        if let Some(first) = cyc.first() {
            out.push(
                e("E203", format!("redirect cycle: {}", names.join(" → "))).at_route(
                    *first,
                    ids,
                    Some("redirect_to"),
                ),
            );
        }
    }

    for s in &sec.blocked_ips {
        if rules::cidr_too_broad(s) {
            out.push(
                e(
                    "E205",
                    format!(
                        "blocked_ips entry {:?} is IPv4 /8 / IPv6 /16 or wider",
                        s.trim()
                    ),
                )
                .at("security", Some("blocked_ips")),
            );
        } else if rules::cidr_clamped(s) {
            out.push(
                w(
                    "W402",
                    format!(
                        "blocked_ips entry {:?} has a prefix longer than its family and is clamped",
                        s.trim()
                    ),
                )
                .at("security", Some("blocked_ips")),
            );
        }
    }
    for raw in &sec.trusted_ips {
        let s = raw.trim();
        let ok = s.is_empty()
            || if s.contains('/') {
                s.parse::<ipnet::Ipv4Net>().is_ok() || s.parse::<ipnet::Ipv6Net>().is_ok()
            } else {
                s.parse::<std::net::IpAddr>().is_ok()
            };
        if !ok {
            out.push(
                w(
                    "W402",
                    format!("ignoring invalid trusted_ips entry {:?}", raw),
                )
                .at("security", Some("trusted_ips")),
            );
        }
    }

    if sec.max_inflight_per_ip == 0 {
        out.push(
            e(
                "E207",
                "max_inflight_per_ip = 0 refuses every request".into(),
            )
            .at("security", Some("max_inflight_per_ip")),
        );
    }
    if sec.http2_enabled && sec.h2_max_concurrent_streams == 0 {
        out.push(
            e(
                "E209",
                "http2_enabled with h2_max_concurrent_streams = 0 — no h2 stream can open".into(),
            )
            .at("security", Some("h2_max_concurrent_streams")),
        );
    }
    if sec.keepalive_max_requests == 0 {
        out.push(
            e(
                "E210",
                "keepalive_max_requests = 0 closes every connection after its first request".into(),
            )
            .at("security", Some("keepalive_max_requests")),
        );
    }
    let bl = &cfg.blocklist;
    for (key, raw) in [("source", &bl.source), ("dyn_source", &bl.dyn_source)] {
        let u = raw.trim();
        let Some(host) = u
            .strip_prefix("https://")
            .or_else(|| u.strip_prefix("http://"))
        else {
            continue;
        };
        if !bl.enabled {
            continue;
        }
        if host.is_empty() || host.starts_with('/') || u.chars().any(char::is_whitespace) {
            out.push(
                e(
                    "E211",
                    format!("blocklist.{} is not an absolute http(s) URL", key),
                )
                .at("blocklist", Some(key)),
            );
        }
    }
    if bl.enabled && !bl.dyn_source.trim().is_empty() && !bl.dyn_source.trim().starts_with("http") {
        out.push(
            e("E211", "blocklist.dyn_source must be an http(s) URL".into())
                .at("blocklist", Some("dyn_source")),
        );
    }
    let obh = bl.origin_block_header.trim();
    if !obh.is_empty() && http::header::HeaderName::try_from(obh).is_err() {
        out.push(
            e(
                "E211",
                format!("origin_block_header {:?} is not a valid header name", obh),
            )
            .at("blocklist", Some("origin_block_header")),
        );
    }
    for (key, raw) in [
        ("real_ip_header", &sec.real_ip_header),
        ("real_ip_sig_header", &sec.real_ip_sig_header),
    ] {
        if http::header::HeaderName::try_from(raw.trim()).is_err() {
            out.push(
                e(
                    "E213",
                    format!(
                        "{} {:?} is not a valid header name (the default is used)",
                        key, raw
                    ),
                )
                .at("security", Some(key)),
            );
        }
    }
    for (k, v) in [
        ("penalty_box_ttl_secs", sec.penalty_box_ttl_secs),
        ("abuse_block_secs", sec.abuse_block_secs),
    ] {
        if v > TTL_MAX_SECS {
            out.push(
                e(
                    "E212",
                    format!(
                        "{} {} is above 10 years ({}) and is clamped at boot",
                        k, v, TTL_MAX_SECS
                    ),
                )
                .at("security", Some(k)),
            );
        }
    }

    for (field, list) in [
        ("block_user_agents", &sec.block_user_agents),
        ("block_header_patterns", &sec.block_header_patterns),
    ] {
        for p in list {
            let lp = p.trim().to_lowercase();
            if lp.is_empty() {
                continue;
            }
            if lp.chars().count() < 4 {
                out.push(
                    w(
                        "W403",
                        format!(
                            "pattern {:?} is shorter than 4 characters and matches too much",
                            p
                        ),
                    )
                    .at("security", Some(field)),
                );
            } else if BROWSER_TOKENS
                .iter()
                .any(|b| lp.contains(b) || b.contains(lp.as_str()))
            {
                out.push(
                    w("W403", format!("pattern {:?} matches ordinary browsers", p))
                        .at("security", Some(field)),
                );
            }
        }
    }

    if sec.default_rate_limit == 0 {
        out.push(
            w(
                "W404",
                "default_rate_limit = 0 means 1 request/s, not off".into(),
            )
            .at("security", Some("default_rate_limit")),
        );
    }
    if sec.default_burst == 0 {
        out.push(
            w("W404", "default_burst = 0 means 1, not off".into())
                .at("security", Some("default_burst")),
        );
    } else if sec.default_burst < sec.default_rate_limit {
        out.push(
            w(
                "W404",
                format!(
                    "default_burst {} is below default_rate_limit {}",
                    sec.default_burst, sec.default_rate_limit
                ),
            )
            .at("security", Some("default_burst")),
        );
    }
    if sec.fingerprint_rps > 0 && sec.fingerprint_burst < sec.fingerprint_rps {
        out.push(
            w(
                "W404",
                format!(
                    "fingerprint_burst {} is below fingerprint_rps {}",
                    sec.fingerprint_burst, sec.fingerprint_rps
                ),
            )
            .at("security", Some("fingerprint_burst")),
        );
    }
    if u64::from(sec.global_rps_limit) > 1u64 << 31 {
        out.push(
            w(
                "W404",
                "global_rps_limit above 2^31 — its burst (2×) saturates".into(),
            )
            .at("security", Some("global_rps_limit")),
        );
    }

    let zero_notes = [
        (
            "penalty_box_ttl_secs",
            sec.penalty_box_ttl_secs == 0,
            "penalty entries expire at once",
        ),
        (
            "penalty_box_capacity",
            sec.penalty_box_capacity == 0,
            "the penalty box holds nothing",
        ),
        (
            "abuse_strikes",
            sec.abuse_strikes == 0,
            "0 is ignored — the default of 3 stays",
        ),
        (
            "abuse_block_secs",
            sec.abuse_block_secs == 0,
            "0 is ignored — the default of 300 s stays",
        ),
        (
            "upstream_fail_timeout_secs",
            sec.upstream_fail_timeout_secs == 0,
            "an open breaker re-probes immediately",
        ),
    ];
    for (k, on, why) in zero_notes {
        if on {
            out.push(w("W405", format!("{} = 0: {}", k, why)).at("security", Some(k)));
        }
    }

    if (1..50).contains(&sec.h2_cancel_threshold) {
        out.push(
            w(
                "W407",
                format!(
                    "h2_cancel_threshold {} is below 50 — ordinary browsing cancels reach it",
                    sec.h2_cancel_threshold
                ),
            )
            .at("security", Some("h2_cancel_threshold")),
        );
    }
    if sec.h2_max_streams_per_conn > 0
        && sec.h2_max_streams_per_conn < sec.h2_max_concurrent_streams
    {
        out.push(
            w(
                "W407",
                "h2_max_streams_per_conn is below h2_max_concurrent_streams".into(),
            )
            .at("security", Some("h2_max_streams_per_conn")),
        );
    }
    if sec.tls_fp_enforce && sec.tls_fp_rate == 0 {
        out.push(
            w(
                "W407",
                "tls_fp_enforce with tls_fp_rate = 0 enforces nothing".into(),
            )
            .at("security", Some("tls_fp_enforce")),
        );
    }
    if sec.max_live_direct > 0 && sec.max_live_direct_degraded > sec.max_live_direct {
        out.push(
            w(
                "W407",
                "max_live_direct_degraded is above max_live_direct".into(),
            )
            .at("security", Some("max_live_direct_degraded")),
        );
    }
    if (sec.max_live_direct_degraded > 0 || sec.drop_direct_when_backend_down) && fb_idx.is_none() {
        let k = if sec.drop_direct_when_backend_down {
            "drop_direct_when_backend_down"
        } else {
            "max_live_direct_degraded"
        };
        out.push(
            w(
                "W407",
                "no on_demand_fallback route to watch — the degraded settings never engage".into(),
            )
            .at("security", Some(k)),
        );
    }

    if cfg.route.len() > 1024 {
        out.push(
            w(
                "W408",
                format!(
                    "{} routes — only 1024 breaker slots; the rest fail open",
                    cfg.route.len()
                ),
            )
            .at("", Some("route")),
        );
    }

    let prov = cfg.acme.provider.as_str();
    if prov != "letsencrypt" && prov != "zerossl" {
        out.push(
            w("W409", format!("provider {:?} is treated as ZeroSSL", prov))
                .at("acme", Some("provider")),
        );
    }
    if prov != "letsencrypt" && !cfg.acme.has_eab() {
        out.push(w("W409", "ZeroSSL without eab_kid/eab_hmac".into()).at("acme", Some("provider")));
    }
    if cfg.acme.email.trim().is_empty() {
        out.push(w("W409", "empty email".into()).at("acme", Some("email")));
    }

    let keyed = !sec.real_ip_secret.is_empty();
    if sec.trust_upstream_real_ip && (!sec.real_ip_verify || !keyed) {
        out.push(w("W410", "trusts an upstream real-IP header without verifying its signature (set real_ip_secret and real_ip_verify)".into()).at("security", Some("trust_upstream_real_ip")));
    }
    if sec.real_ip_verify && !keyed {
        out.push(
            w(
                "W410",
                "real_ip_verify without real_ip_secret verifies nothing".into(),
            )
            .at("security", Some("real_ip_verify")),
        );
    }
    if !sec.real_ip_secret.is_empty() && sec.real_ip_secret.len() < 16 {
        out.push(
            w("W410", "real_ip_secret is shorter than 16 bytes".into())
                .at("security", Some("real_ip_secret")),
        );
    }

    if sec.maintenance_mode {
        out.push(
            w("W411", "maintenance_mode is on".into()).at("security", Some("maintenance_mode")),
        );
    }
    if !cfg.metrics {
        out.push(
            w(
                "W411",
                "metrics is off — /health is not served, so a health check probing it will fail"
                    .into(),
            )
            .at("", Some("metrics")),
        );
    }

    if !cfg.on_demand_hosts.trim().is_empty() && fb_idx.is_none() {
        out.push(w("W417", "on_demand_hosts is set but no route has on_demand_fallback = true — those hosts are not served".into()).at("", Some("on_demand_hosts")));
    }

    if bl.enabled && crate::blocklist::target_key(cfg).is_some() {
        let url = bl.source.trim().starts_with("http");
        if url && bl.pull_secs < 30 {
            out.push(
                w(
                    "W418",
                    format!(
                        "pull_secs {} is raised to 30 for a URL source",
                        bl.pull_secs
                    ),
                )
                .at("blocklist", Some("pull_secs")),
            );
        } else if !url && bl.pull_secs < 5 {
            out.push(
                w(
                    "W418",
                    format!(
                        "pull_secs {} is raised to 5 for a file source",
                        bl.pull_secs
                    ),
                )
                .at("blocklist", Some("pull_secs")),
            );
        }
        if (1..5).contains(&bl.dyn_secs) {
            out.push(
                w("W418", format!("dyn_secs {} is raised to 5", bl.dyn_secs))
                    .at("blocklist", Some("dyn_secs")),
            );
        }
    }
}

// ── Host rules (E3xx and the [host] warnings), skipped under --offline ────────

fn resolve(wd: &Path, p: &str) -> PathBuf {
    let pb = Path::new(p);
    if pb.is_absolute() {
        pb.to_path_buf()
    } else {
        wd.join(pb)
    }
}

/// The nearest existing ancestor accepts writes (access(2); nothing is created).
fn writable(p: &Path) -> bool {
    let mut cur = Some(p);
    while let Some(c) = cur {
        if c.exists() {
            let Ok(cs) = std::ffi::CString::new(c.as_os_str().as_bytes()) else {
                return false;
            };
            // SAFETY: cs is a valid NUL-terminated path for the duration of the call.
            return unsafe { libc::access(cs.as_ptr(), libc::W_OK) } == 0;
        }
        cur = c.parent();
    }
    false
}

fn san_covers(sans: &[String], host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    sans.iter().any(|s| {
        s == &h
            || s.strip_prefix("*.").is_some_and(|sfx| {
                h.strip_suffix(sfx)
                    .and_then(|l| l.strip_suffix('.'))
                    .is_some_and(|l| !l.is_empty() && !l.contains('.'))
            })
    })
}

fn port_range_width() -> Option<usize> {
    let s = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range").ok()?;
    let mut it = s.split_whitespace();
    let lo: usize = it.next()?.parse().ok()?;
    let hi: usize = it.next()?.parse().ok()?;
    Some(hi.saturating_sub(lo).saturating_add(1))
}

fn host_checks(cfg: &ProxyConfig, ids: &[String], wd: &Path, out: &mut Vec<Issue>) {
    let e = |code: &'static str, msg: String| Issue::new(Sev::Error, code, msg).on_host();
    let w = |code: &'static str, msg: String| Issue::new(Sev::Warning, code, msg).on_host();
    let rel = |p: &str| !p.trim().is_empty() && !Path::new(p).is_absolute();
    let relmsg = || {
        format!(
            "relative path — resolved against the working directory {}",
            wd.display()
        )
    };

    for (i, r) in cfg.route.iter().enumerate() {
        if r.mode != RouteMode::Static {
            continue;
        }
        let Some(root) = r.static_root.as_deref().filter(|s| !s.trim().is_empty()) else {
            continue;
        };
        let p = resolve(wd, root);
        let problem = if !p.exists() {
            Some(format!("{} does not exist", p.display()))
        } else if !p.is_dir() {
            Some(format!("{} is not a directory", p.display()))
        } else {
            p.canonicalize()
                .err()
                .map(|err| format!("{} cannot be resolved: {}", p.display(), err))
        };
        if let Some(m) = problem {
            out.push(e("E301", m).at_route(i, ids, Some("static_root")));
        }
        if rel(root) {
            out.push(w("W416", relmsg()).at_route(i, ids, Some("static_root")));
        }
    }

    let mut static_ok = false;
    for (i, r) in cfg
        .route
        .iter()
        .enumerate()
        .filter(|(_, r)| r.uses_static_cert())
    {
        let (Some(c), Some(k)) = (r.static_cert.as_deref(), r.static_key.as_deref()) else {
            continue;
        };
        for (f, v) in [("static_cert", c), ("static_key", k)] {
            if rel(v) {
                out.push(w("W416", relmsg()).at_route(i, ids, Some(f)));
            }
        }
        let probe = probe_pair(
            &resolve(wd, c).to_string_lossy(),
            &resolve(wd, k).to_string_lossy(),
        );
        match probe.fault {
            Some(PairFault::Unloadable(m)) => {
                out.push(e("E302", m).at_route(i, ids, Some("static_cert")))
            }
            Some(PairFault::KeyMismatch) => out.push(
                e(
                    "E303",
                    "static_key does not match the certificate's public key".into(),
                )
                .at_route(i, ids, Some("static_key")),
            ),
            None => {
                static_ok = true;
                let uncovered: Vec<&str> = r
                    .hosts
                    .iter()
                    .filter(|h| !h.trim().is_empty() && *h != "*" && !san_covers(&probe.sans, h))
                    .map(String::as_str)
                    .collect();
                if !uncovered.is_empty() {
                    out.push(
                        w(
                            "W416",
                            format!("the certificate does not cover {}", uncovered.join(", ")),
                        )
                        .at_route(i, ids, Some("static_cert")),
                    );
                }
                match probe.days_left {
                    Some(d) if d <= 0 => {
                        out.push(w("W416", "the certificate has expired".into()).at_route(
                            i,
                            ids,
                            Some("static_cert"),
                        ))
                    }
                    Some(d) if d < 30 => out.push(
                        w("W416", format!("the certificate expires in {} day(s)", d)).at_route(
                            i,
                            ids,
                            Some("static_cert"),
                        ),
                    ),
                    _ => {}
                }
            }
        }
    }

    let acme_hosts = cfg.acme_hosts();
    let storage = cfg.acme.storage.trim();
    if rel(storage) {
        out.push(w("W416", relmsg()).at("acme", Some("storage")));
    }
    let bundle = (!storage.is_empty()).then(|| {
        (
            resolve(wd, &cfg.acme.cert_path()),
            resolve(wd, &cfg.acme.key_path()),
        )
    });
    let bundle_exists = bundle.as_ref().is_some_and(|(c, _)| c.exists());
    if let (true, Some((c, k))) = (bundle_exists, &bundle) {
        match probe_pair(&c.to_string_lossy(), &k.to_string_lossy()).fault {
            Some(PairFault::Unloadable(m)) => out.push(
                e("E306", format!("the ACME bundle does not load: {}", m))
                    .at("acme", Some("storage")),
            ),
            Some(PairFault::KeyMismatch) => out.push(
                e(
                    "E306",
                    "the ACME bundle's key does not match its certificate".into(),
                )
                .at("acme", Some("storage")),
            ),
            None => {}
        }
    }
    if !acme_hosts.is_empty() {
        if storage.is_empty() {
            out.push(
                e(
                    "E304",
                    format!(
                        "acme.storage is empty while {} host(s) need ACME certificates",
                        acme_hosts.len()
                    ),
                )
                .at("acme", Some("storage")),
            );
        } else if !writable(&resolve(wd, storage)) {
            out.push(
                e(
                    "E304",
                    format!(
                        "{} is not writable (nor its nearest existing parent)",
                        resolve(wd, storage).display()
                    ),
                )
                .at("acme", Some("storage")),
            );
        }
        if !bundle_exists {
            out.push(
                Issue::new(
                    Sev::Info,
                    "I503",
                    format!(
                        "no ACME bundle yet — {} host(s) are issued at boot",
                        acme_hosts.len()
                    ),
                )
                .on_host()
                .at("acme", Some("storage")),
            );
        }
    }
    if !bundle_exists && acme_hosts.is_empty() && !static_ok {
        out.push(e("E305", "no certificate source: no ACME bundle, no loadable static_cert route and no ACME hosts".into()).at("acme", Some("storage")));
    }

    let sec = &cfg.security;
    if sec.max_live_tls == 0 {
        out.push(w("W406", "max_live_tls = 0 leaves the :443 pre-filter unbounded (ephemeral ports can run out)".into()).at("security", Some("max_live_tls")));
    } else if let Some(width) = port_range_width().filter(|n| sec.max_live_tls >= *n) {
        out.push(w("W406", format!("max_live_tls {} is not below the ephemeral port range ({}) — loopback connects fail first", sec.max_live_tls, width)).at("security", Some("max_live_tls")));
    }

    let od = cfg.on_demand_hosts.trim();
    if !od.is_empty() {
        if rel(od) {
            out.push(w("W416", relmsg()).at("", Some("on_demand_hosts")));
        }
        let p = resolve(wd, od);
        match std::fs::read_to_string(&p) {
            Err(_) if !p.exists() => {
                out.push(
                    w(
                        "W417",
                        format!(
                            "{} not found — the on-demand list starts empty",
                            p.display()
                        ),
                    )
                    .at("", Some("on_demand_hosts")),
                );
            }
            Err(err) => out.push(
                w("W417", format!("{} is unreadable: {}", p.display(), err))
                    .at("", Some("on_demand_hosts")),
            ),
            Ok(s) => {
                for h in crate::host_list::parse(&s) {
                    if let Some(problem) = rules::host_issue(&h) {
                        out.push(
                            w(
                                "W417",
                                format!("{}: host {:?}: {}", p.display(), h, problem),
                            )
                            .at("", Some("on_demand_hosts")),
                        );
                    }
                }
            }
        }
    }

    let bl = &cfg.blocklist;
    let src = bl.source.trim();
    if bl.enabled && !src.is_empty() && !src.starts_with("http") {
        if rel(src) {
            out.push(w("W416", relmsg()).at("blocklist", Some("source")));
        }
        let p = resolve(wd, src);
        if !p.is_file() {
            out.push(
                w(
                    "W418",
                    format!(
                        "{} is not a readable file — no list is enforced until it appears",
                        p.display()
                    ),
                )
                .at("blocklist", Some("source")),
            );
        }
    }

    if cfg.error_page.enabled && !(3..=60).contains(&cfg.error_page.retry_secs) {
        out.push(
            w(
                "W420",
                format!(
                    "retry_secs {} is clamped to 3..60",
                    cfg.error_page.retry_secs
                ),
            )
            .at("error_page", Some("retry_secs")),
        );
    }
    let v = &cfg.blocklist.cache;
    if v.trim() != "off" && rel(v) {
        out.push(w("W416", relmsg()).at("blocklist", Some("cache")));
    }
}

fn summarize(cfg: &ProxyConfig, ids: &[String]) -> Summary {
    let n = |m: RouteMode| cfg.route.iter().filter(|r| r.mode == m).count();
    Summary {
        routes: cfg.route.len(),
        hosts: cfg
            .route
            .iter()
            .flat_map(|r| r.hosts.iter())
            .filter(|h| !h.trim().is_empty())
            .count(),
        acme_hosts: cfg.acme_hosts().len(),
        static_cert_routes: cfg.route.iter().filter(|r| r.uses_static_cert()).count(),
        fallback_route: fallback_route_index(&cfg.route).and_then(|i| ids.get(i).cloned()),
        proxy: n(RouteMode::Proxy),
        statics: n(RouteMode::Static),
        redirect: n(RouteMode::Redirect),
    }
}

// ── Diff and plan (the reloader's verdict; --against uses the same) ──────────

/// Security keys a running edge can take without a restart; anything unlisted restarts.
const HOT_SECURITY: &[&str] = &[
    "cloudflare_only",
    "maintenance_mode",
    "block_empty_user_agent",
    "block_scanners",
    "global_timeout_secs",
    "reject_invalid_content_length",
    "reject_header_injection",
    "max_request_body",
    "block_header_patterns",
    "block_user_agents",
    "blocked_ips",
    "keepalive_max_requests",
    "trust_upstream_real_ip",
    "real_ip_verify",
    "real_ip_secret",
    "real_ip_header",
    "real_ip_sig_header",
    "default_rate_limit",
    "default_burst",
    "fingerprint_rps",
    "fingerprint_burst",
    "trusted_ips",
    "trust_cloudflare",
    "max_inflight_per_ip",
    "global_connection_limit",
    "global_rps_limit",
    "upstream_max_fails",
    "upstream_fail_timeout_secs",
    "h2_cancel_threshold",
    "h2_max_streams_per_conn",
    "conn_rate_per_ip",
    "max_live_tls",
    "max_live_direct",
    "max_live_direct_degraded",
    "keepalive_idle_secs",
    "drop_direct_when_backend_down",
    "tls_fp_rate",
    "tls_fp_enforce",
    "abuse_strikes",
];

pub fn is_hot(path: &str) -> bool {
    path.starts_with("route[")
        || path == "blocklist.origin_block_header"
        || path
            .strip_prefix("security.")
            .is_some_and(|k| HOT_SECURITY.contains(&k))
}

pub struct Plan {
    pub verdict: &'static str,
    pub changed: Vec<String>,
    pub restart_keys: Vec<String>,
    pub routes_added: Vec<String>,
    pub routes_removed: Vec<String>,
    pub acme_hosts_added: usize,
    pub notices: Vec<Issue>,
}

fn walk_diff(path: String, a: Option<&Value>, b: Option<&Value>, out: &mut Vec<String>) {
    match (a, b) {
        (Some(Value::Object(x)), Some(Value::Object(y)))
            if !path.ends_with(".add_headers") && !path.ends_with(".redirects") =>
        {
            let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                walk_diff(format!("{}.{}", path, k), x.get(k), y.get(k), out);
            }
        }
        _ if a != b => out.push(path),
        _ => {}
    }
}

fn to_object(c: &ProxyConfig) -> Result<serde_json::Map<String, Value>, String> {
    match serde_json::to_value(c) {
        Ok(Value::Object(m)) => Ok(m),
        Ok(_) => Err("the config did not serialise to an object".into()),
        Err(e) => Err(e.to_string()),
    }
}

fn route_values(c: &ProxyConfig) -> Result<Vec<(String, Value)>, String> {
    c.route
        .iter()
        .zip(c.route_ids())
        .map(|(r, id)| {
            serde_json::to_value(r)
                .map(|v| (id, v))
                .map_err(|e| e.to_string())
        })
        .collect()
}

/// Changed key paths a → b; routes are matched by identity, so a reorder is no change.
pub fn diff_paths(a: &ProxyConfig, b: &ProxyConfig) -> Result<Vec<String>, String> {
    let (va, vb) = (to_object(a)?, to_object(b)?);
    let mut out = Vec::new();
    let keys: BTreeSet<&String> = va
        .keys()
        .chain(vb.keys())
        .filter(|k| k.as_str() != "route")
        .collect();
    for k in keys {
        walk_diff(k.clone(), va.get(k), vb.get(k), &mut out);
    }
    let (ra, rb) = (route_values(a)?, route_values(b)?);
    let old: HashMap<&str, &Value> = ra.iter().map(|(id, v)| (id.as_str(), v)).collect();
    let new_ids: HashSet<&str> = rb.iter().map(|(id, _)| id.as_str()).collect();
    for (id, v) in &rb {
        match old.get(id.as_str()) {
            None => out.push(format!("route[{}]", id)),
            Some(o) => walk_diff(format!("route[{}]", id), Some(*o), Some(v), &mut out),
        }
    }
    for (id, _) in ra.iter().filter(|(id, _)| !new_ids.contains(id.as_str())) {
        out.push(format!("route[{}]", id));
    }
    Ok(out)
}

/// Static-only registry: no ACME hosts and no bundle on disk (no host view = assume none).
pub fn boot_static_only(cfg: &ProxyConfig, wd: Option<&Path>) -> bool {
    if !cfg.acme_hosts().is_empty() {
        return false;
    }
    match wd {
        Some(wd) if !cfg.acme.storage.trim().is_empty() => {
            !resolve(wd, &cfg.acme.cert_path()).exists()
        }
        _ => true,
    }
}

/// restart_keys = boot → new outside the HOT table plus derived boot captures;
/// changed = live → new. Any restart key means nothing is applied.
pub fn plan(
    boot: &ProxyConfig,
    live: &ProxyConfig,
    new: &ProxyConfig,
    static_only: bool,
) -> Result<Plan, String> {
    let fallback = if static_only {
        boot.route.iter().position(RouteConfig::uses_static_cert)
    } else {
        None
    };
    plan_at(boot, live, new, static_only, fallback)
}

/// plan() with the static-only fallback route known (its position in `boot`), as a running edge knows it.
pub fn plan_at(
    boot: &ProxyConfig,
    live: &ProxyConfig,
    new: &ProxyConfig,
    static_only: bool,
    fallback: Option<usize>,
) -> Result<Plan, String> {
    let changed = diff_paths(live, new)?;
    let mut restart: Vec<String> = diff_paths(boot, new)?
        .into_iter()
        .filter(|p| !is_hot(p))
        .collect();
    if crate::blocklist::target_key(boot) != crate::blocklist::target_key(new) {
        restart.push("blocklist.target".into());
    }
    let (bids, lids, nids) = (boot.route_ids(), live.route_ids(), new.route_ids());
    // Identities are unique per config, so a map finds a route without scanning (O(n) per plan).
    let nidx: HashMap<&str, usize> = nids
        .iter()
        .enumerate()
        .map(|(j, n)| (n.as_str(), j))
        .collect();
    let lidx: HashMap<&str, usize> = lids
        .iter()
        .enumerate()
        .map(|(j, n)| (n.as_str(), j))
        .collect();
    let new_route = |id: &str| nidx.get(id).and_then(|&j| new.route.get(j).map(|r| (j, r)));
    let live_route = |id: &str| lidx.get(id).and_then(|&j| live.route.get(j));
    if static_only {
        if let Some(fb) = fallback {
            let kept = boot
                .route
                .get(fb)
                .zip(bids.get(fb).and_then(|id| new_route(id.as_str())))
                .is_some_and(|(b, (_, n))| {
                    n.uses_static_cert()
                        && n.static_cert == b.static_cert
                        && n.static_key == b.static_key
                });
            if !kept {
                restart.push("tls.static_fallback".into());
            }
        }
        let had: HashSet<String> = boot
            .acme_hosts()
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        if new
            .acme_hosts()
            .iter()
            .any(|h| !had.contains(&h.to_ascii_lowercase()))
        {
            restart.push("acme.hosts".into());
        }
    }
    let mut seen = HashSet::new();
    restart.retain(|k| seen.insert(k.clone()));

    let routes_added: Vec<String> = nids
        .iter()
        .filter(|n| !lidx.contains_key(n.as_str()))
        .cloned()
        .collect();
    let routes_removed: Vec<String> = lids
        .iter()
        .filter(|l| !nidx.contains_key(l.as_str()))
        .cloned()
        .collect();
    let live_acme: HashSet<String> = live
        .acme_hosts()
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    let acme_hosts_added = new
        .acme_hosts()
        .iter()
        .filter(|h| !live_acme.contains(&h.to_ascii_lowercase()))
        .count();

    let note = |code: &'static str, msg: String| Issue::new(Sev::Notice, code, msg);
    let mut notices = Vec::new();
    for k in &restart {
        notices.push(
            note(
                "N601",
                "restart-class key changed — takes effect on the next restart".into(),
            )
            .at_path(k.clone()),
        );
    }
    // Host → the first removed route (in removal order) that served it.
    let mut removed_by_host: HashMap<String, usize> = HashMap::new();
    for (k, old) in routes_removed.iter().enumerate() {
        for h in live_route(old.as_str())
            .into_iter()
            .flat_map(|o| o.hosts.iter())
        {
            removed_by_host.entry(h.to_ascii_lowercase()).or_insert(k);
        }
    }
    for id in &routes_added {
        let Some((j, r)) = new_route(id.as_str()) else {
            continue;
        };
        let from = r
            .hosts
            .iter()
            .filter_map(|h| removed_by_host.get(&h.to_ascii_lowercase()).copied())
            .min()
            .and_then(|k| routes_removed.get(k));
        if let Some(old) = from {
            notices.push(
                note(
                    "N602",
                    format!(
                        "re-keyed from route[{}] — its breaker and rate state start fresh",
                        old
                    ),
                )
                .at_route(j, &nids, None),
            );
        }
    }
    for (j, (id, r)) in nids.iter().zip(&new.route).enumerate() {
        let Some(o) = live_route(id.as_str()) else {
            continue;
        };
        if r.mode == RouteMode::Proxy
            && o.mode == RouteMode::Proxy
            && r.upstream_addr() != o.upstream_addr()
        {
            notices.push(
                note(
                    "N603",
                    "upstream changed — its breaker slot is reset".into(),
                )
                .at_route(j, &nids, Some("upstream")),
            );
        }
    }
    if acme_hosts_added > 0 && !static_only {
        notices.push(
            note(
                "N604",
                format!(
                    "{} ACME host(s) added — the bundle is reissued in the background",
                    acme_hosts_added
                ),
            )
            .at_path("acme.hosts"),
        );
    }
    if live.security.real_ip_secret != new.security.real_ip_secret
        && !live.security.real_ip_secret.is_empty()
    {
        notices.push(
            note(
                "N605",
                "real_ip_secret rotated — the previous key is accepted for 600 s".into(),
            )
            .at("security", Some("real_ip_secret")),
        );
    }
    if !routes_removed.is_empty() {
        notices.push(
            note(
                "N606",
                format!("route(s) removed: {}", routes_removed.join(", ")),
            )
            .at_path("route"),
        );
    }
    if needs_cf_ranges(new) && !needs_cf_ranges(live) {
        notices.push(
            note(
                "N607",
                "Cloudflare ranges newly needed — loaded before the apply".into(),
            )
            .at("security", None),
        );
    }

    let verdict = if !restart.is_empty() {
        "restart_required"
    } else if !changed.is_empty() {
        "hot"
    } else {
        "unchanged"
    };
    Ok(Plan {
        verdict,
        changed,
        restart_keys: restart,
        routes_added,
        routes_removed,
        acme_hosts_added,
        notices,
    })
}

// ── JSON (<name>/check/1) ──────────────────────────────────────────────────

pub fn check_json(
    rep: &Report,
    input: &str,
    opts: &CheckOpts,
    diff: Option<(&str, &Plan)>,
) -> Value {
    let s = &rep.summary;
    json!({
        "schema": concat!(env!("CARGO_PKG_NAME"), "/check/1"),
        "binary": {"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION"), "config_api": 1},
        "input": {"path": input, "bytes": rep.bytes, "sha256": hex(&rep.sha256)},
        "mode": {"host_checks": opts.host, "strict": opts.strict, "workdir": opts.workdir.display().to_string()},
        "result": if rep.ok() { "ok" } else { "invalid" },
        "counts": {
            "fatal": rep.count(Sev::Fatal), "error": rep.count(Sev::Error), "warning": rep.count(Sev::Warning),
            "info": rep.count(Sev::Info), "notice": rep.count(Sev::Notice),
        },
        "issues": rep.issues.iter().map(Issue::to_json).collect::<Vec<_>>(),
        "summary": {
            "routes": s.routes, "hosts": s.hosts, "acme_hosts": s.acme_hosts,
            "static_cert_routes": s.static_cert_routes, "fallback_route": s.fallback_route,
            "modes": {"proxy": s.proxy, "static": s.statics, "redirect": s.redirect},
        },
        "diff": match diff {
            None => Value::Null,
            Some((sha, p)) => json!({
                "against_sha256": sha, "verdict": p.verdict, "changed": p.changed,
                "restart_keys": p.restart_keys, "routes_added": p.routes_added,
                "routes_removed": p.routes_removed, "acme_hosts_added": p.acme_hosts_added,
            }),
        },
    })
}
