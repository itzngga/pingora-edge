//! errpage.rs: what a PERSON sees while the site behind this edge is down.
//!
//! Status and Retry-After stay what they were; only the body changes, and only
//! for a browser asking for a document (GET + Accept: text/html, never a
//! verified crawler, an asset or an XHR). The page says what is happening and
//! probes the URL with HEAD on a jittered backoff, reloading once it answers.
//! Rendered once per (host, kind) and kept gzipped.
//!
//! Off unless `[error_page].enabled`.

use hyper::body::Bytes;
use moka::sync::Cache;
use once_cell::sync::OnceCell;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ErrorPageConfig {
    #[serde(default)]
    pub enabled: bool,
    /// First automatic retry, seconds. Backs off x1.5 up to 60.
    #[serde(default = "default_retry_secs")]
    pub retry_secs: u32,
}

fn default_retry_secs() -> u32 {
    8
}

impl Default for ErrorPageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retry_secs: default_retry_secs(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Down,
    Maintenance,
}

struct State {
    first: u32,
    cache: Cache<(String, Kind), (Bytes, Bytes)>, // plain, gzip
}

static STATE: OnceCell<State> = OnceCell::new();

pub fn configure(cfg: &ErrorPageConfig) {
    if !cfg.enabled {
        return;
    }
    let _ = STATE.set(State {
        first: cfg.retry_secs.clamp(3, 60),
        cache: Cache::builder().max_capacity(4096).build(),
    });
    tracing::info!("error page: on (visitor-facing 503 body)");
}

pub fn enabled() -> bool {
    STATE.get().is_some()
}

/// The upstream statuses that mean "the site is not there right now":
/// gateway errors and Cloudflare's origin-unreachable family.
pub fn is_outage_status(code: u16) -> bool {
    matches!(code, 502 | 503 | 504 | 520..=527 | 530)
}

pub fn wants_page(session: &Session) -> bool {
    let req = session.req_header();
    if req.method != http::Method::GET {
        return false;
    }
    let h = &req.headers;
    if let Some(d) = h.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
        if d != "document" {
            return false;
        }
    }
    h.get("accept")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"))
}

/// Writes the whole response. Err only when the write itself failed.
pub async fn respond(
    session: &mut Session,
    host: &str,
    kind: Kind,
    retry_after: &str,
) -> pingora_core::Result<()> {
    let (plain, gz) = page(host, kind);
    let gzip = !gz.is_empty()
        && session
            .req_header()
            .headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("gzip"));
    let body = if gzip { gz } else { plain };
    let mut r = ResponseHeader::build(503, Some(8))?;
    r.insert_header("Content-Type", "text/html; charset=utf-8")?;
    if gzip {
        r.insert_header("Content-Encoding", "gzip")?;
    }
    r.insert_header("Vary", "Accept-Encoding")?;
    r.insert_header("Content-Length", body.len().to_string())?;
    r.insert_header("Retry-After", retry_after)?;
    r.insert_header("Cache-Control", "no-store")?;
    r.insert_header("Connection", "close")?;
    session.write_response_header(Box::new(r), false).await?;
    session.write_response_body(Some(body), true).await?;
    session.set_keepalive(None);
    Ok(())
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(
        Vec::with_capacity(data.len() / 2),
        flate2::Compression::best(),
    );
    if e.write_all(data).is_err() {
        return Vec::new();
    }
    e.finish().unwrap_or_default()
}

fn page(host: &str, kind: Kind) -> (Bytes, Bytes) {
    let first = STATE.get().map_or(default_retry_secs(), |s| s.first);
    let key = (host.to_string(), kind);
    if let Some(s) = STATE.get() {
        if let Some(b) = s.cache.get(&key) {
            return b;
        }
    }
    let html = render(host, kind, first);
    let gz = Bytes::from(gzip(html.as_bytes()));
    let b = (Bytes::from(html), gz);
    if let Some(s) = STATE.get() {
        s.cache.insert(key, b.clone());
    }
    b
}

/// Only characters that can appear in a hostname survive into the page.
fn clean_host(host: &str) -> String {
    host.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .take(80)
        .collect()
}

const CSS: &str = "\
:root{color-scheme:light dark;--bg:#f7f7f5;--fg:#1d1d1b;--muted:#5f5f5a;--card:#fff;--line:#e2e2dd;--accent:#2f6fde}\
@media(prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ececea;--muted:#a3a39e;--card:#1e1e1c;--line:#34342f;--accent:#7aa5f5}}\
*{box-sizing:border-box}\
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);\
font:16px/1.6 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;padding:24px 16px}\
main{max-width:560px;width:100%;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:32px}\
h1{font-size:1.5rem;line-height:1.25;margin:0 0 12px}\
p{margin:0 0 16px;color:var(--muted)}\
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:24px}\
button{font:inherit;padding:8px 16px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}\
button:disabled{opacity:.55;cursor:default}\
.bar{height:4px;background:var(--line);border-radius:2px;overflow:hidden;margin-top:24px}\
.bar>i{display:block;height:100%;width:100%;background:var(--accent);transition:width 1s linear}\
small{color:var(--muted)}";

fn render(host: &str, kind: Kind, first: u32) -> String {
    let host = clean_host(host);
    let (title, lead) = match kind {
        Kind::Down => (
            "This site is temporarily unavailable",
            format!("The server behind {} is not answering right now. That is usually a restart or a short outage, and it clears up on its own.", host),
        ),
        Kind::Maintenance => (
            "Down for maintenance",
            format!("{} is undergoing planned maintenance and will be back shortly.", host),
        ),
    };
    let js = format!(
        "(function(){{var d={first},n=0,t=0,left=0,tot=1,max=40,busy=0,D=document,g=function(i){{return D.getElementById(i)}},\
         eL=g('left'),eM=g('msg'),eB=g('retry'),eP=g('bar');\
         function show(m){{eM.textContent=m}}\
         function paint(){{eP.style.width=(left/tot*100)+'%';show('Checking again in '+left+' s')}}\
         function arm(){{tot=left=Math.max(3,Math.round(d*(.8+Math.random()*.4)));clearInterval(t);paint();\
         t=setInterval(function(){{if(D.hidden)return;left--;if(left<=0)probe();else paint()}},1000)}}\
         function probe(){{if(busy)return;busy=1;clearInterval(t);n++;eB.disabled=true;eP.style.width='0%';show('Checking\\u2026');\
         fetch(location.href,{{method:'HEAD',cache:'no-store',credentials:'same-origin'}}).then(function(r){{\
         if(r.status<500&&r.status!=429){{show('Back online, reloading\\u2026');location.reload()}}else again()}}).catch(again)}}\
         function again(){{busy=0;eB.disabled=false;if(n>=max){{show('Paused. Use the button to check again.');return}}d=Math.min(d*1.5,60);arm()}}\
         eB.onclick=function(){{if(n>=max)n=max-1;probe()}};\
         D.addEventListener('visibilitychange',function(){{if(!D.hidden&&!busy&&left<=0&&n<max)probe()}});\
         addEventListener('online',function(){{if(!busy&&n<max)probe()}});\
         arm()}})();",
        first = first
    );
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\"><title>{title}</title>\
         <noscript><meta http-equiv=\"refresh\" content=\"30\"></noscript><style>{css}</style></head>\
         <body><main><h1>{title}</h1><p>{lead}</p>\
         <p>This page checks again by itself and reloads when the site answers.</p>\
         <div class=\"bar\"><i id=\"bar\"></i></div>\
         <div class=\"row\"><button id=\"retry\" type=\"button\">Check now</button>\
         <small id=\"msg\" aria-live=\"polite\"></small><span id=\"left\" hidden></span></div>\
         <p><small>503 Service Unavailable</small></p></main><script>{js}</script></body></html>",
        title = title, lead = lead, css = CSS, js = js
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_sanitised() {
        assert_eq!(clean_host("shop<b>.example.com"), "shopb.example.com");
        assert_eq!(clean_host("a\"b.example.com"), "ab.example.com");
    }

    #[test]
    fn page_names_the_host_and_retries() {
        let html = render("shop.example.com", Kind::Down, 8);
        assert!(html.contains("shop.example.com"));
        assert!(html.contains("var d=8"));
        let m = render("shop.example.com", Kind::Maintenance, 8);
        assert!(m.contains("maintenance"));
    }

    #[test]
    fn outage_statuses() {
        assert!(is_outage_status(502));
        assert!(is_outage_status(522));
        assert!(!is_outage_status(500));
        assert!(!is_outage_status(404));
    }
}
