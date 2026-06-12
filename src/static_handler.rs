// Static file serving for Pingora. Called from request_filter; writes the
// response directly and returns Ok(true) so the upstream phase is skipped.
//
// Path resolution: `/foo/bar.html` -> `<root>/foo/bar.html`
//                   `/foo/`          -> `<root>/foo/index.html`
//                   `/foo`           -> `<root>/foo` then `<root>/foo.html`;
//                                       if only `<root>/foo/index.html`
//                                       exists, 301 to `/foo/`.
// `..`, NUL, and dot-leading segments are refused on both the raw and the
// percent-decoded path; the root is canonicalized once at config load and
// each resolved file is verified to stay inside it (symlink escapes).
//
// HTML/XML/JSON get Cache-Control: no-cache (fast republish); other assets
// get a 1-year immutable lifetime. All responses carry Last-Modified for
// 304s and the same SECURITY_HEADERS the proxied path gets.
//
// Caching: resolution outcomes (incl. NotFound) and file bodies are held in
// two in-memory caches with a 2s TTL, so hot requests and 304 revalidations
// cost zero syscalls. 2s bounds the staleness after an in-place republish.
//
// Custom 404: `<root>/404.html` when present.
//
// Byte ranges: single-range only, and only for content worth seeking
// (video, audio, PDF, zip). Multi-range falls back to a full 200 — no
// client needs multipart/byteranges, and generating it is a MIME body
// nobody reads. Never offered on a compressed variant: a slice of a .br
// stream is not what the client asked for.
//
// Not implemented: directory listings, on-the-fly compression
// (precompressed .br/.gz siblings only).

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use moka::sync::Cache;
use once_cell::sync::Lazy;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use tokio::fs;

use crate::config::{RouteConfig, SECURITY_HEADERS};
use crate::tuning::TUNING;

// Cache budgets come from tuning.rs, autosized from host RAM (on a 1 GiB
// VM: 16 MiB of bodies, 512 KiB/body, 2k resolution entries).
const CACHE_TTL_SECS: u64 = 2;

static RESOLVE_CACHE: Lazy<Cache<String, Arc<Resolved>>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(TUNING.resolve_cache_entries)
        .time_to_live(Duration::from_secs(CACHE_TTL_SECS))
        .build()
});

static BODY_CACHE: Lazy<Cache<PathBuf, Bytes>> = Lazy::new(|| {
    Cache::builder()
        .max_capacity(TUNING.body_cache_bytes)
        .weigher(|_k: &PathBuf, v: &Bytes| v.len().try_into().unwrap_or(u32::MAX))
        .time_to_live(Duration::from_secs(CACHE_TTL_SECS))
        .build()
});

// ── Encoding negotiation ─────────────────────────────────────────────────────
//
// Precompressed siblings only (`index.html.br` / `.gz` next to `index.html`).
// Preference: br > gzip > plain. A compressed sibling older than the plain
// file is ignored — publisher updated the original and forgot to recompress.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Gzip,
    Brotli,
}

impl Encoding {
    fn header_value(self) -> &'static str {
        match self {
            Encoding::Gzip => "gzip",
            Encoding::Brotli => "br",
        }
    }
}

/// One on-disk file that can satisfy a request; stat data and the
/// Last-Modified string are captured at probe time and cached with it.
struct Variant {
    path: PathBuf, // canonical
    len: u64,
    mtime: Option<SystemTime>,
    last_modified: Option<Arc<str>>,
}

/// Result of resolving a request path against a static root.
///
/// `Found` holds the plain file and/or its precompressed siblings — at
/// least one is Some by construction. `content_type` comes from the BASE
/// path so it stays correct regardless of which variant is served.
// Held behind an Arc in the resolve cache, so the variant size gap costs nothing.
#[allow(clippy::large_enum_variant)]
enum Resolved {
    Found {
        plain: Option<Variant>,
        brotli: Option<Variant>,
        gzip: Option<Variant>,
        content_type: &'static str,
    },
    /// Slashless URL resolved to a directory index — 301 to the
    /// trailing-slash form so relative links in the HTML resolve correctly.
    Redirect,
    /// Path was syntactically rejected (traversal, NUL, hidden segment).
    Rejected,
    NotFound,
}

/// Serve a static file for the given route. Ok(true) = response written;
/// Ok(false) = continue normal proxy flow (escape hatch, shouldn't happen).
/// `host` and `crawler` only pick the 503 body when the root does not resolve.
pub async fn serve_static(
    session: &mut Session,
    route: &RouteConfig,
    host: &str,
    crawler: bool,
) -> pingora_core::Result<bool> {
    // The static root is re-canonicalized PER REQUEST, not once at config
    // load. The configured root ends in a `current` symlink that every
    // publish atomically swaps to a fresh release directory; the load-time
    // canonicalize resolved THROUGH the symlink and pinned this route to
    // whichever release was live when the proxy started. From then on the
    // edge silently served that stale release across publishes, until the
    // pusher's retention (keep two) deleted the pinned directory — at
    // which point every path on the site answered 404 until a restart.
    // Canonicalizing here follows the symlink as it is NOW; the load-time
    // value remains as config validation and the fallback for a disk
    // error mid-swap. The dentry cache makes the per-request resolve
    // microseconds, and the resolve cache keys on the canonical root, so
    // a swap simply starts a fresh cache generation.
    let canon_fresh: Option<PathBuf> = match route.static_root.as_deref() {
        Some(raw) => fs::canonicalize(raw).await.ok(),
        None => None,
    };
    // Degraded at load (E301): serve again only once the root is really a directory.
    let canon_fresh = match canon_fresh {
        Some(p) if route.canonical_static_root.is_none() => match fs::metadata(&p).await {
            Ok(m) if m.is_dir() => Some(p),
            _ => None,
        },
        other => other,
    };
    let Some(canon_root) = canon_fresh
        .as_deref()
        .or(route.canonical_static_root.as_deref())
    else {
        return unavailable(session, host, crawler).await;
    };

    let method = session.req_header().method.as_str();
    let is_head = method == "HEAD";
    if method != "GET" && !is_head {
        return write_simple(session, 405, "Method Not Allowed\n", "text/plain").await;
    }

    let req_path = session.req_header().uri.path();

    // Owned copies — serve_found needs &mut Session alongside these.
    let ims = session
        .req_header()
        .headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let accept_encoding = session
        .req_header()
        .headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let range = session
        .req_header()
        .headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let resolved = resolve_path(canon_root, req_path).await;
    match &*resolved {
        Resolved::Redirect => {
            // Location uses the RAW request path (cannot contain CR/LF).
            let location = match session.req_header().uri.query() {
                Some(q) => format!("{}/?{}", req_path, q),
                None => format!("{}/", req_path),
            };
            let mut r = ResponseHeader::build(301, None)?;
            let _ = r.insert_header("Location", location);
            let _ = r.insert_header("Content-Length", "0");
            apply_security_headers(&mut r);
            session.write_response_header(Box::new(r), true).await?;
            Ok(true)
        }
        Resolved::Rejected => {
            // Suspicious paths get a plain 404 — don't reveal anything.
            write_simple(session, 404, "Not Found\n", "text/plain").await
        }
        Resolved::NotFound => {
            // A retired URL that still carries external links redirects rather
            // than dying. Checked HERE, after resolution, so the map can never
            // shadow a file that actually exists.
            if let Some(target) = lookup_redirect(&route.redirects, req_path) {
                let mut r = ResponseHeader::build(301, None)?;
                let _ = r.insert_header("Location", target.clone());
                let _ = r.insert_header("Content-Length", "0");
                let _ = r.insert_header("Cache-Control", "no-store");
                apply_security_headers(&mut r);
                session.write_response_header(Box::new(r), true).await?;
                return Ok(true);
            }
            // Only 404 and 410 are honoured — see RouteConfig::not_found_status.
            let status = if route.not_found_status == 410 {
                410
            } else {
                404
            };
            let custom = resolve_path(canon_root, "/404.html").await;
            if matches!(&*custom, Resolved::Found { .. }) {
                return serve_found(
                    session,
                    &custom,
                    status,
                    is_head,
                    ims.as_deref(),
                    accept_encoding.as_deref(),
                    range.as_deref(),
                )
                .await;
            }
            if status == 410 {
                return write_simple(session, 410, "Gone\n", "text/plain").await;
            }
            write_simple(session, 404, "Not Found\n", "text/plain").await
        }
        Resolved::Found { .. } => {
            serve_found(
                session,
                &resolved,
                200,
                is_head,
                ims.as_deref(),
                accept_encoding.as_deref(),
                range.as_deref(),
            )
            .await
        }
    }
}

/// Serve the best variant for the client, in order: non-stale `.br` if
/// accepted, non-stale `.gz` if accepted, plain, else decompress a
/// compressed variant on the fly.
async fn serve_found(
    session: &mut Session,
    found: &Resolved,
    status: u16,
    is_head: bool,
    ims: Option<&str>,
    accept_encoding: Option<&str>,
    range: Option<&str>,
) -> pingora_core::Result<bool> {
    let Resolved::Found {
        plain,
        brotli,
        gzip,
        content_type: ct,
    } = found
    else {
        unreachable!("serve_found called with non-Found variant");
    };

    let (gz_ok, br_ok) = parse_accept_encoding(accept_encoding);

    // A byte range is only meaningful over the IDENTITY bytes: serving a
    // slice of a .br file would hand the client fragments of a compressed
    // stream it cannot decode. So a ranged request for seekable content
    // takes the plain variant and ignores the compressed siblings.
    if status == 200 && range.is_some() && range_supported(ct) {
        if let Some(v) = plain.as_ref() {
            return send_file_ranged(session, v, ct, is_head, ims, range).await;
        }
    }

    let plain_mtime = plain.as_ref().and_then(|v| v.mtime);
    let brotli = brotli.as_ref().filter(|v| !is_stale(plain_mtime, v.mtime));
    let gzip = gzip.as_ref().filter(|v| !is_stale(plain_mtime, v.mtime));

    if br_ok {
        if let Some(v) = brotli {
            return send_file(session, v, ct, Some(Encoding::Brotli), is_head, ims, status).await;
        }
    }
    if gz_ok {
        if let Some(v) = gzip {
            return send_file(session, v, ct, Some(Encoding::Gzip), is_head, ims, status).await;
        }
    }
    if let Some(v) = plain {
        return send_file(session, v, ct, None, is_head, ims, status).await;
    }
    // Compressed-only deployment and the client doesn't accept the encoding
    // we have on disk — decompress and send plain bytes.
    if let Some(v) = brotli {
        return send_decompressed(session, v, ct, Encoding::Brotli, is_head, ims, status).await;
    }
    if let Some(v) = gzip {
        return send_decompressed(session, v, ct, Encoding::Gzip, is_head, ims, status).await;
    }
    tracing::error!(target: "static", "serve_found: Resolved::Found with no variants — bug");
    write_simple(session, 500, "Internal Server Error\n", "text/plain").await
}

/// True if compressed sibling is older than plain — i.e. plain was updated
/// and the precompressed sibling wasn't regenerated.
fn is_stale(plain_mtime: Option<SystemTime>, comp_mtime: Option<SystemTime>) -> bool {
    match (plain_mtime, comp_mtime) {
        (Some(p), Some(c)) => p > c,
        _ => false,
    }
}

/// Probe `base` and its precompressed siblings. None when nothing matches.
/// No hidden-segment policy here — `base` includes the root prefix, which
/// may itself contain dot-directories; resolve_path checks the request part.
async fn lookup_with_siblings(canon_root: &Path, base: &Path) -> Option<Resolved> {
    let mut content_type = content_type_for(base);

    let plain = stat_variant(canon_root, base).await;

    // Last resort for an extensionless file the path rule did not name:
    // read the first bytes and look. Bounded work — clean URLs resolve to
    // index.html, so genuinely extensionless FILES are rare, and this only
    // runs when the extension and the path both told us nothing. Cached
    // with the rest of the resolution, so it is once per file per TTL.
    if content_type == "application/octet-stream" && base.extension().is_none() {
        if let Some(v) = plain.as_ref() {
            if let Some(sniffed) = sniff_head(&v.path).await {
                content_type = sniffed;
            }
        }
    }
    // Already-compressed formats never have precompressed siblings — skip
    // the extra stats. (A compressed-only `img.png.br` won't resolve.)
    let (brotli, gzip) = if skip_compressed_siblings(content_type) {
        (None, None)
    } else {
        (
            stat_variant(canon_root, &with_suffix(base, ".br")).await,
            stat_variant(canon_root, &with_suffix(base, ".gz")).await,
        )
    };

    if plain.is_none() && brotli.is_none() && gzip.is_none() {
        return None;
    }

    Some(Resolved::Found {
        plain,
        brotli,
        gzip,
        content_type,
    })
}

/// Read the first bytes of a file and sniff a content type from them.
/// Any read error just leaves the caller with its default.
async fn sniff_head(path: &Path) -> Option<&'static str> {
    use tokio::io::AsyncReadExt;
    let mut f = fs::File::open(path).await.ok()?;
    let mut buf = [0u8; 256];
    let n = f.read(&mut buf).await.ok()?;
    sniff_content_type(&buf[..n])
}

/// Content types nobody precompresses — their on-disk format is already
/// compressed (svg is the compressible exception among images).
fn skip_compressed_siblings(ct: &str) -> bool {
    (ct.starts_with("image/") && ct != "image/svg+xml")
        || ct.starts_with("video/")
        || ct.starts_with("audio/")
        || ct.starts_with("font/")
        || ct == "application/zip"
        || ct == "application/pdf"
}

/// Stat a path into a Variant if it's a regular file that resolves to
/// inside `canon_root` (symlink escapes are treated as not-existing).
async fn stat_variant(canon_root: &Path, path: &Path) -> Option<Variant> {
    let meta = fs::metadata(path).await.ok()?;
    if !meta.is_file() {
        return None;
    }
    let canon = fs::canonicalize(path).await.ok()?;
    if !canon.starts_with(canon_root) {
        return None; // symlink escape
    }
    let mtime = meta.modified().ok();
    Some(Variant {
        path: canon,
        len: meta.len(),
        mtime,
        last_modified: mtime.map(|t| Arc::from(http_date(t))),
    })
}

fn with_suffix(base: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = base.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Parse Accept-Encoding into (gzip_ok, brotli_ok). `q=0` counts as
/// refusal, `*` enables both, unknown encodings are ignored.
fn parse_accept_encoding(header: Option<&str>) -> (bool, bool) {
    let header = match header {
        Some(h) => h,
        None => return (false, false),
    };
    let mut gz = false;
    let mut br = false;

    for token in header.split(',') {
        let token = token.trim();
        let mut parts = token.split(';');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let rejected = parts.any(|p| {
            let p = p.trim().to_ascii_lowercase();
            matches!(p.as_str(), "q=0" | "q=0.0" | "q=0.00" | "q=0.000")
        });
        if rejected {
            continue;
        }
        match name.as_str() {
            "br" => br = true,
            "gzip" => gz = true,
            "*" => {
                br = true;
                gz = true;
            }
            _ => {}
        }
    }
    (gz, br)
}

/// Resolve a request path against the canonical static root: probe each
/// candidate for plain + `.br` + `.gz` and return the first hit. Outcomes
/// (including NotFound, so probe floods stay cheap) are cached for
/// CACHE_TTL_SECS; Rejected is computed without syscalls and not cached.
async fn resolve_path(canon_root: &Path, req_path: &str) -> Arc<Resolved> {
    if req_path.contains('\0') || req_path.split('/').any(|seg| seg == "..") {
        return Arc::new(Resolved::Rejected);
    }

    let decoded = percent_decode(req_path);
    // Re-checked after decoding so `%2e%2e` / `%00` can't slip past the
    // raw check above.
    if has_forbidden_segment(&decoded) {
        return Arc::new(Resolved::Rejected);
    }

    // NUL can't appear in `decoded` (rejected above), so it's a safe separator.
    let key = format!("{}\0{}", canon_root.display(), decoded);
    if let Some(hit) = RESOLVE_CACHE.get(&key) {
        return hit;
    }

    let rel = decoded.trim_start_matches('/');
    // The bool marks the directory-index candidate for a slashless URL,
    // which must 301 instead of serving.
    let mut candidates: Vec<(PathBuf, bool)> = Vec::with_capacity(3);

    if rel.is_empty() {
        candidates.push((canon_root.join("index.html"), false));
    } else if rel.ends_with('/') {
        candidates.push((canon_root.join(rel).join("index.html"), false));
    } else {
        let direct = canon_root.join(rel);
        candidates.push((direct.clone(), false));
        if Path::new(rel).extension().is_none() {
            let mut with_html = canon_root.join(rel).into_os_string();
            with_html.push(".html");
            candidates.push((PathBuf::from(with_html), false));
            candidates.push((direct.join("index.html"), true));
        }
    }

    let mut outcome = Resolved::NotFound;
    for (cand, is_dir_index) in candidates {
        if let Some(found) = lookup_with_siblings(canon_root, &cand).await {
            outcome = if is_dir_index {
                Resolved::Redirect
            } else {
                found
            };
            break;
        }
    }

    let outcome = Arc::new(outcome);
    RESOLVE_CACHE.insert(key, Arc::clone(&outcome));
    outcome
}

/// NUL or any dot-leading segment (`..`, `.git`, `.env`); bare `.` is allowed.
fn has_forbidden_segment(decoded: &str) -> bool {
    decoded.contains('\0')
        || decoded
            .split('/')
            .any(|seg| seg.starts_with('.') && seg != ".")
}

async fn send_file(
    session: &mut Session,
    v: &Variant,
    ct: &str,
    encoding: Option<Encoding>,
    is_head: bool,
    ims: Option<&str>,
    status: u16,
) -> pingora_core::Result<bool> {
    // IMS is matched by string equality against the Last-Modified of the
    // variant we'd actually serve; Vary makes that correct for caches.
    if status == 200 {
        if let (Some(lm), Some(ims)) = (v.last_modified.as_deref(), ims) {
            if lm == ims.trim() {
                return write_304(session, lm, ct).await;
            }
        }
    }

    if is_head {
        let r = full_headers(
            status,
            ct,
            Some(v.len),
            v.last_modified.as_deref(),
            encoding,
        )?;
        session.write_response_header(Box::new(r), true).await?;
        return Ok(true);
    }

    let body = match body_bytes(&v.path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(target: "static", "read {} failed: {}", v.path.display(), e);
            return write_simple(session, 500, "Internal Server Error\n", "text/plain").await;
        }
    };

    // Content-Length from the bytes being sent, not the earlier stat — an
    // in-place republish between the two would desync HTTP/1 framing.
    let r = full_headers(
        status,
        ct,
        Some(body.len() as u64),
        v.last_modified.as_deref(),
        encoding,
    )?;
    if body.is_empty() {
        session.write_response_header(Box::new(r), true).await?;
    } else {
        session.write_response_header(Box::new(r), false).await?;
        session.write_response_body(Some(body), true).await?;
    }
    Ok(true)
}

/// Serve a byte range of the identity file: 206 with Content-Range, or 416
/// when the range cannot be satisfied.
///
/// Without range support a static root is fine for HTML and wrong for PDF
/// and media: a viewer that asks for the last 1 KB to read a trailer gets
/// the whole file, and one that refuses to proceed without 206 gets nothing.
async fn send_file_ranged(
    session: &mut Session,
    v: &Variant,
    ct: &str,
    is_head: bool,
    ims: Option<&str>,
    range: Option<&str>,
) -> pingora_core::Result<bool> {
    if let (Some(lm), Some(ims)) = (v.last_modified.as_deref(), ims) {
        if lm == ims.trim() {
            return write_304(session, lm, ct).await;
        }
    }

    let body = match body_bytes(&v.path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(target: "static", "read {} failed: {}", v.path.display(), e);
            return write_simple(session, 500, "Internal Server Error\n", "text/plain").await;
        }
    };
    let len = body.len() as u64;

    // Length from the bytes in hand, not the earlier stat — a republish
    // between stat and read would otherwise desync the Content-Range.
    let parsed = range.and_then(|h| parse_range(h, len));
    let Some((start, end)) = parsed else {
        // A single-range request we could not satisfy (start past EOF) is a
        // 416, so the client stops asking. Anything we merely do not serve —
        // multi-range, a unit other than bytes — falls back to a full 200,
        // which is always a legal answer to a Range request.
        let single_byte_range = range
            .map(|h| h.trim().starts_with("bytes=") && !h.contains(','))
            .unwrap_or(false);
        if single_byte_range {
            let mut r = ResponseHeader::build(416, None)?;
            let _ = r.insert_header("Content-Range", format!("bytes */{}", len));
            let _ = r.insert_header("Content-Length", "0");
            let _ = r.insert_header("Accept-Ranges", "bytes");
            apply_security_headers(&mut r);
            session.write_response_header(Box::new(r), true).await?;
            return Ok(true);
        }
        let mut r = full_headers(200, ct, Some(len), v.last_modified.as_deref(), None)?;
        let _ = r.insert_header("Accept-Ranges", "bytes");
        if is_head || body.is_empty() {
            session.write_response_header(Box::new(r), true).await?;
        } else {
            session.write_response_header(Box::new(r), false).await?;
            session.write_response_body(Some(body), true).await?;
        }
        return Ok(true);
    };

    let slice = body.slice(start as usize..=end as usize);
    let mut r = full_headers(
        206,
        ct,
        Some(slice.len() as u64),
        v.last_modified.as_deref(),
        None,
    )?;
    let _ = r.insert_header("Content-Range", format!("bytes {}-{}/{}", start, end, len));
    let _ = r.insert_header("Accept-Ranges", "bytes");
    if is_head {
        session.write_response_header(Box::new(r), true).await?;
    } else {
        session.write_response_header(Box::new(r), false).await?;
        session.write_response_body(Some(slice), true).await?;
    }
    Ok(true)
}

/// Whole file as Bytes, via the body cache. Oversized bodies are served
/// but not cached. Whole-file-in-memory is fine — articles are KB-scale;
/// revisit if that changes.
async fn body_bytes(path: &Path) -> std::io::Result<Bytes> {
    if let Some(b) = BODY_CACHE.get(path) {
        return Ok(b);
    }
    let b = Bytes::from(fs::read(path).await?);
    if b.len() <= TUNING.max_cached_body {
        BODY_CACHE.insert(path.to_path_buf(), b.clone());
    }
    Ok(b)
}

/// Decompress a compressed-only file on the fly and send plain bytes —
/// for clients that don't accept the encoding we have on disk.
async fn send_decompressed(
    session: &mut Session,
    v: &Variant,
    ct: &str,
    encoding: Encoding,
    is_head: bool,
    ims: Option<&str>,
    status: u16,
) -> pingora_core::Result<bool> {
    // Last-Modified uses the compressed file's mtime; Vary keeps caches
    // from mixing this with the compressed response.
    if status == 200 {
        if let (Some(lm), Some(ims)) = (v.last_modified.as_deref(), ims) {
            if lm == ims.trim() {
                return write_304(session, lm, ct).await;
            }
        }
    }

    if is_head {
        // Plain length is unknowable without decompressing; omit
        // Content-Length (legal for HEAD) instead.
        let r = full_headers(status, ct, None, v.last_modified.as_deref(), None)?;
        session.write_response_header(Box::new(r), true).await?;
        return Ok(true);
    }

    let compressed = match body_bytes(&v.path).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(target: "static", "read {} failed: {}", v.path.display(), e);
            return write_simple(session, 500, "Internal Server Error\n", "text/plain").await;
        }
    };

    // flate2/brotli decoders are sync — keep them off the async workers.
    let plain = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        match encoding {
            Encoding::Gzip => {
                let mut dec = flate2::read::GzDecoder::new(compressed.as_ref());
                let mut out = Vec::with_capacity(compressed.len() * 4);
                dec.read_to_end(&mut out)?;
                Ok(out)
            }
            Encoding::Brotli => {
                let mut dec = brotli::Decompressor::new(compressed.as_ref(), 4096);
                let mut out = Vec::with_capacity(compressed.len() * 4);
                dec.read_to_end(&mut out)?;
                Ok(out)
            }
        }
    })
    .await;

    let plain = match plain {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::warn!(target: "static", "decompress {} ({}) failed: {}",
                v.path.display(), encoding.header_value(), e);
            return write_simple(session, 500, "Internal Server Error\n", "text/plain").await;
        }
        Err(e) => {
            tracing::error!(target: "static", "decompress task panicked: {}", e);
            return write_simple(session, 500, "Internal Server Error\n", "text/plain").await;
        }
    };

    // No Content-Encoding — we're sending plain bytes.
    let r = full_headers(
        status,
        ct,
        Some(plain.len() as u64),
        v.last_modified.as_deref(),
        None,
    )?;
    session.write_response_header(Box::new(r), false).await?;
    session
        .write_response_body(Some(plain.into()), true)
        .await?;
    Ok(true)
}

/// 304 carries only cache-update headers (RFC 7232 §4.1) — no Content-Encoding.
async fn write_304(session: &mut Session, lm: &str, ct: &str) -> pingora_core::Result<bool> {
    let mut r = ResponseHeader::build(304, None)?;
    // The stored type, unchanged, so logs and caches see what was revalidated.
    let _ = r.insert_header("Content-Type", ct);
    let _ = r.insert_header("Last-Modified", lm);
    let _ = r.insert_header("Cache-Control", cache_control_for(ct));
    let _ = r.insert_header("Vary", "Accept-Encoding");
    apply_security_headers(&mut r);
    session.write_response_header(Box::new(r), true).await?;
    Ok(true)
}

/// Shared header set for file responses. `content_length: None` omits the
/// header (HEAD on compressed-only files, where the plain size is unknown).
fn full_headers(
    status: u16,
    ct: &str,
    content_length: Option<u64>,
    last_modified: Option<&str>,
    encoding: Option<Encoding>,
) -> pingora_core::Result<ResponseHeader> {
    let mut r = ResponseHeader::build(status, None)?;
    let _ = r.insert_header("Content-Type", ct);
    if let Some(len) = content_length {
        let _ = r.insert_header("Content-Length", len.to_string());
    }
    let _ = r.insert_header("Cache-Control", cache_control_for(ct));
    // Vary keeps intermediaries from merging compressed and plain responses.
    let _ = r.insert_header("Vary", "Accept-Encoding");
    if let Some(enc) = encoding {
        let _ = r.insert_header("Content-Encoding", enc.header_value());
    }
    if let Some(lm) = last_modified {
        let _ = r.insert_header("Last-Modified", lm);
    }
    // Only on identity responses: a range over a Content-Encoding'd body
    // would be a slice of the compressed stream, which is not what the
    // client asked for.
    if encoding.is_none() && range_supported(ct) {
        let _ = r.insert_header("Accept-Ranges", "bytes");
    }
    apply_security_headers(&mut r);
    Ok(r)
}

/// Parse a single-range `Range: bytes=` header against a known length.
///
/// Returns Some((start, end_inclusive)) for a satisfiable single range,
/// None when the header is absent or not a form we serve.
///
/// Deliberately single-range only. Multipart/byteranges means generating a
/// MIME body with per-part headers, and no real client needs it — PDF
/// viewers and media players ask for one span at a time. A multi-range
/// request falls through to a normal 200, which is a legal response to any
/// Range request and better than refusing.
fn parse_range(header: &str, len: u64) -> Option<(u64, u64)> {
    let spec = header.trim().strip_prefix("bytes=")?.trim();
    if spec.contains(',') || len == 0 {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());

    let (start, end) = if a.is_empty() {
        // "-N" — the final N bytes.
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return None;
        }
        (len.saturating_sub(n), len - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        let end = if b.is_empty() {
            len - 1
        } else {
            b.parse().ok()?
        };
        (start, end.min(len - 1))
    };

    if start > end || start >= len {
        return None;
    }
    Some((start, end))
}

/// True for content worth advertising byte ranges on: the seekable stuff.
/// HTML and feeds are read start to finish, and claiming range support on
/// them only invites clients to make more requests for the same bytes.
fn range_supported(ct: &str) -> bool {
    ct.starts_with("video/")
        || ct.starts_with("audio/")
        || ct == "application/pdf"
        || ct == "application/zip"
}

/// Same SECURITY_HEADERS the proxied path gets — response_filter never runs
/// for responses written in request_filter.
fn apply_security_headers(r: &mut ResponseHeader) {
    for (k, v) in SECURITY_HEADERS {
        if r.headers.get(*k).is_none() {
            let _ = r.insert_header(*k, *v);
        }
    }
}

/// Look up `path` in a route's redirect map, tolerating the trailing slash.
///
/// One entry matches both `/foo` and `/foo/`. Old URLs are written both ways
/// in the wild — a link in an article body and the same URL in a sitemap
/// routinely disagree — and making the operator list each twice is how half
/// of them end up missed.
///
/// A target that is empty or carries control characters is IGNORED. Such a
/// value would be rejected by the header writer, and the request would then
/// answer 301 with no Location — a redirect loop for the client and a dead
/// end for a crawler, which is strictly worse than the 404 it replaced.
fn lookup_redirect<'a>(map: &'a HashMap<String, String>, path: &str) -> Option<&'a String> {
    if map.is_empty() {
        return None;
    }
    let hit = match map.get(path) {
        Some(v) => Some(v),
        None => match path.strip_suffix('/') {
            // "/" strips to "" — never a useful key, and looking it up would
            // let a stray empty entry hijack the homepage.
            Some(stripped) if !stripped.is_empty() => map.get(stripped),
            Some(_) => None,
            None => map.get(&format!("{path}/")),
        },
    }?;
    if hit.is_empty() || hit.chars().any(char::is_control) {
        return None;
    }
    Some(hit)
}

/// No site to serve from (the root is missing): a retryable 503, never a 404 that
/// clients and crawlers would treat as the content being gone.
async fn unavailable(
    session: &mut Session,
    host: &str,
    crawler: bool,
) -> pingora_core::Result<bool> {
    if crate::errpage::enabled() && !crawler && crate::errpage::wants_page(session) {
        crate::errpage::respond(session, host, crate::errpage::Kind::Down, "30").await?;
        return Ok(true);
    }
    let mut r = ResponseHeader::build(503, None)?;
    let _ = r.insert_header("Retry-After", "30");
    let _ = r.insert_header("Content-Length", "0");
    let _ = r.insert_header("Cache-Control", "no-store");
    apply_security_headers(&mut r);
    session.write_response_header(Box::new(r), true).await?;
    Ok(true)
}

async fn write_simple(
    session: &mut Session,
    status: u16,
    body: &'static str,
    ct: &'static str,
) -> pingora_core::Result<bool> {
    let mut r = ResponseHeader::build(status, None)?;
    let _ = r.insert_header("Content-Type", ct);
    let _ = r.insert_header("Content-Length", body.len().to_string());
    let _ = r.insert_header("Cache-Control", "no-store");
    if status == 405 {
        let _ = r.insert_header("Allow", "GET, HEAD");
    }
    apply_security_headers(&mut r);
    session.write_response_header(Box::new(r), false).await?;
    session
        .write_response_body(Some(Bytes::from_static(body.as_bytes())), true)
        .await?;
    Ok(true)
}

// ── MIME / cache helpers ─────────────────────────────────────────────────────

fn content_type_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "zip" => "application/zip",
        // Extensionless files are clean URLs, not downloads. Static site
        // generators often write a feed to a path like `rss/news` with no
        // suffix, and without this it would come back as
        // application/octet-stream, which every browser treats as "save to
        // disk". Sitemaps are fine only because they end in .xml.
        "" => feed_type_for(path).unwrap_or("application/octet-stream"),
        _ => "application/octet-stream",
    }
}

/// Content type for a well-known extensionless feed path.
///
/// Matched on the LAST TWO segments so it keys off the request shape
/// (`/rss/news`, `/feed`, `/atom`) rather than on where the site root
/// happens to live on disk.
fn feed_type_for(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    if name == "rss" || name == "feed" || name == "atom" || parent == "rss" || parent == "feed" {
        return Some("application/rss+xml; charset=utf-8");
    }
    None
}

/// Content type sniffed from the first bytes of an extensionless file.
///
/// The path rule above covers the feed the generator writes today; this is
/// the general case, so a future extensionless XML or HTML file does not
/// silently become a download. Only consulted when the extension told us
/// nothing — a file WITH an extension is always trusted.
fn sniff_content_type(head: &[u8]) -> Option<&'static str> {
    let start = head
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(head.len());
    let body = &head[start..];
    let lower: Vec<u8> = body
        .iter()
        .take(64)
        .map(|b| b.to_ascii_lowercase())
        .collect();

    if lower.starts_with(b"<?xml") || lower.starts_with(b"<rss") || lower.starts_with(b"<feed") {
        return Some("application/rss+xml; charset=utf-8");
    }
    if lower.starts_with(b"<!doctype html") || lower.starts_with(b"<html") {
        return Some("text/html; charset=utf-8");
    }
    None
}

fn cache_control_for(content_type: &str) -> &'static str {
    if content_type.starts_with("text/html")
        || content_type.starts_with("application/xml")
        || content_type.starts_with("application/rss+xml")
        || content_type.starts_with("application/json")
    {
        // Revalidate every request so republished content appears quickly.
        "no-cache"
    } else {
        // Assets are assumed content-addressed (?v=<hash> or renamed).
        "public, max-age=31536000, immutable"
    }
}

/// RFC7231 IMF-fixdate, e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
fn http_date(t: SystemTime) -> String {
    let dur = match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };
    let secs = dur.as_secs();
    format_imf_fixdate(secs as i64)
}

fn format_imf_fixdate(unix_secs: i64) -> String {
    let mut secs = unix_secs;
    let days = secs.div_euclid(86_400);
    secs = secs.rem_euclid(86_400);
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;

    let (y, mo, d) = civil_from_days(days);
    let wd_idx = (((days % 7) + 4).rem_euclid(7)) as usize; // 1970-01-01 was Thu (4)
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WD[wd_idx],
        d,
        MO[(mo as usize) - 1],
        y,
        h,
        m,
        s
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (y, m, d).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Percent-decoder for URI paths; invalid `%XX` sequences pass through.
/// Shared with the WAF path scanner in proxy.rs.
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip_to_known_values() {
        // 0 = 1970-01-01 00:00:00 UTC, Thursday
        assert_eq!(format_imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // 2024-05-15 12:34:56 UTC = Wednesday
        // (cross-checked against `date -u -d @1715776496`)
        assert_eq!(
            format_imf_fixdate(1_715_776_496),
            "Wed, 15 May 2024 12:34:56 GMT"
        );
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("/foo%20bar"), "/foo bar");
        assert_eq!(percent_decode("/foo%2Fbar"), "/foo/bar");
        // Invalid sequence: pass through
        assert_eq!(percent_decode("/foo%2"), "/foo%2");
        assert_eq!(percent_decode("/foo%zz"), "/foo%zz");
    }

    #[test]
    fn content_type_lookup() {
        assert_eq!(
            content_type_for(Path::new("a.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Path::new("/x/y/z.HTML")),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Path::new("unknown")),
            "application/octet-stream"
        );

        // The generator writes its feed to <root>/rss/news with no suffix.
        // Served as octet-stream it downloads instead of rendering.
        assert_eq!(
            content_type_for(Path::new("/var/www/site/rss/news")),
            "application/rss+xml; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Path::new("/var/www/site/feed")),
            "application/rss+xml; charset=utf-8"
        );
        // A feed must revalidate, like the sitemap — not sit in a cache
        // for a year as an immutable asset.
        assert_eq!(
            cache_control_for("application/rss+xml; charset=utf-8"),
            "no-cache"
        );

        // General fallback for anything extensionless the path rule misses.
        assert_eq!(
            sniff_content_type(b"<?xml version=\"1.0\"?><rss>"),
            Some("application/rss+xml; charset=utf-8")
        );
        assert_eq!(
            sniff_content_type(b"\n  <!DOCTYPE html><html>"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(sniff_content_type(b"\x00\x01binary"), None);

        // Byte ranges — PDF viewers and media players seek with these.
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_range("bytes=500-", 1000), Some((500, 999)));
        assert_eq!(parse_range("bytes=-100", 1000), Some((900, 999)));
        // End past EOF clamps rather than failing.
        assert_eq!(parse_range("bytes=990-5000", 1000), Some((990, 999)));
        // Start past EOF is unsatisfiable → caller answers 416.
        assert_eq!(parse_range("bytes=1000-", 1000), None);
        // Multi-range and non-byte units fall back to a full 200.
        assert_eq!(parse_range("bytes=0-10,20-30", 1000), None);
        assert_eq!(parse_range("items=0-10", 1000), None);
        assert_eq!(parse_range("bytes=0-0", 0), None);

        // Advertised only where seeking is real.
        assert!(range_supported("application/pdf"));
        assert!(range_supported("video/mp4"));
        assert!(!range_supported("text/html; charset=utf-8"));
        assert!(!range_supported("application/rss+xml; charset=utf-8"));
    }

    #[test]
    fn cache_for_html_no_cache() {
        assert_eq!(cache_control_for("text/html; charset=utf-8"), "no-cache");
        assert_eq!(
            cache_control_for("image/png"),
            "public, max-age=31536000, immutable"
        );
    }

    #[test]
    fn parse_accept_encoding_basic() {
        assert_eq!(parse_accept_encoding(Some("gzip, br")), (true, true));
        assert_eq!(parse_accept_encoding(Some("br, gzip")), (true, true));
        assert_eq!(parse_accept_encoding(Some("br")), (false, true));
        assert_eq!(parse_accept_encoding(Some("gzip")), (true, false));
    }

    #[test]
    fn parse_accept_encoding_q_zero_refusal() {
        assert_eq!(parse_accept_encoding(Some("br;q=0, gzip")), (true, false));
        assert_eq!(
            parse_accept_encoding(Some("br;q=0, gzip;q=0")),
            (false, false)
        );
        assert_eq!(parse_accept_encoding(Some("br;q=0.0, gzip")), (true, false));
        // Non-zero q is accepted (no weighting)
        assert_eq!(
            parse_accept_encoding(Some("br;q=0.1, gzip;q=1.0")),
            (true, true)
        );
    }

    #[test]
    fn parse_accept_encoding_edge_cases() {
        assert_eq!(parse_accept_encoding(Some("*")), (true, true));
        assert_eq!(parse_accept_encoding(Some("zstd, deflate")), (false, false));
        assert_eq!(parse_accept_encoding(Some("identity")), (false, false));
        assert_eq!(parse_accept_encoding(None), (false, false));
        assert_eq!(parse_accept_encoding(Some("")), (false, false));
        // Case-insensitive
        assert_eq!(parse_accept_encoding(Some("GZIP")), (true, false));
        assert_eq!(parse_accept_encoding(Some("Br, GZip")), (true, true));
    }

    #[test]
    fn encoding_header_values() {
        assert_eq!(Encoding::Gzip.header_value(), "gzip");
        assert_eq!(Encoding::Brotli.header_value(), "br");
    }

    #[test]
    fn forbidden_segments() {
        // Decoded traversal (raw `..` is caught earlier; this is the
        // %2e%2e-after-decode backstop) and hidden files.
        assert!(has_forbidden_segment("/../etc/passwd"));
        assert!(has_forbidden_segment("/a/../b"));
        assert!(has_forbidden_segment("/.git/config"));
        assert!(has_forbidden_segment("/a/.env"));
        assert!(has_forbidden_segment("/a\0b"));
        // Legitimate paths.
        assert!(!has_forbidden_segment("/a/b.html"));
        assert!(!has_forbidden_segment("/./a"));
        assert!(!has_forbidden_segment("/v1.2/docs"));
        assert!(!has_forbidden_segment(""));
    }

    #[test]
    fn sibling_probe_skips() {
        assert!(skip_compressed_siblings("image/png"));
        assert!(skip_compressed_siblings("font/woff2"));
        assert!(skip_compressed_siblings("video/mp4"));
        assert!(!skip_compressed_siblings("image/svg+xml"));
        assert!(!skip_compressed_siblings("text/html; charset=utf-8"));
        assert!(!skip_compressed_siblings(
            "application/javascript; charset=utf-8"
        ));
        assert!(!skip_compressed_siblings("application/octet-stream"));
    }

    #[tokio::test]
    async fn resolve_path_end_to_end() {
        // Real-filesystem checks: dot-directory in the ROOT must not break
        // serving, dir-index without slash must redirect, traversal and
        // hidden requests must be rejected.
        let root = std::env::temp_dir().join(format!(".static-test-{}", std::process::id()));
        let docs = root.join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(root.join("index.html"), "home").unwrap();
        std::fs::write(docs.join("index.html"), "docs").unwrap();
        let canon_root = root.canonicalize().unwrap();

        assert!(matches!(
            &*resolve_path(&canon_root, "/").await,
            Resolved::Found { .. }
        ));
        assert!(matches!(
            &*resolve_path(&canon_root, "/docs/").await,
            Resolved::Found { .. }
        ));
        assert!(matches!(
            &*resolve_path(&canon_root, "/docs").await,
            Resolved::Redirect
        ));
        assert!(matches!(
            &*resolve_path(&canon_root, "/%2e%2e/secret").await,
            Resolved::Rejected
        ));
        assert!(matches!(
            &*resolve_path(&canon_root, "/.git/config").await,
            Resolved::Rejected
        ));
        assert!(matches!(
            &*resolve_path(&canon_root, "/missing").await,
            Resolved::NotFound
        ));
        // Second resolve comes from the cache and must agree.
        assert!(matches!(
            &*resolve_path(&canon_root, "/").await,
            Resolved::Found { .. }
        ));

        std::fs::remove_dir_all(&root).unwrap();
    }

    // Run with: cargo test --release bench_static_core -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn bench_static_core() {
        fn report(name: &str, d: std::time::Duration, n: u32) {
            println!(
                "{name:>22}: {:>7} ns/op  ({:>9.0} ops/s)",
                d.as_nanos() / n as u128,
                n as f64 / d.as_secs_f64()
            );
        }

        let root = std::env::temp_dir().join(format!("static-bench-{}", std::process::id()));
        let docs = root.join("docs");
        std::fs::create_dir_all(&docs).unwrap();
        let body = vec![b'x'; 30 * 1024];
        std::fs::write(root.join("index.html"), &body).unwrap();
        std::fs::write(docs.join("page.html"), &body).unwrap();
        let canon_root = root.canonicalize().unwrap();
        let n = 20_000u32;

        // Steady state: resolve + body both served from cache.
        let t = std::time::Instant::now();
        for _ in 0..n {
            let r = resolve_path(&canon_root, "/docs/page.html").await;
            let Resolved::Found { plain: Some(v), .. } = &*r else {
                panic!()
            };
            assert_eq!(body_bytes(&v.path).await.unwrap().len(), 30 * 1024);
        }
        report("cached hit + body", t.elapsed(), n);

        // Unique paths defeat the cache: full probe each time.
        let t = std::time::Instant::now();
        for i in 0..n {
            let r = resolve_path(&canon_root, &format!("/nope-{i}")).await;
            assert!(matches!(&*r, Resolved::NotFound));
        }
        report("uncached miss", t.elapsed(), n);

        let cached = Bytes::from(body.clone());
        let t = std::time::Instant::now();
        for _ in 0..n {
            assert_eq!(cached.clone().len(), 30 * 1024);
        }
        report("memory baseline", t.elapsed(), n);

        let now = SystemTime::now();
        let t = std::time::Instant::now();
        for _ in 0..n {
            let _ = http_date(now);
        }
        report("http_date", t.elapsed(), n);

        std::fs::remove_dir_all(&root).unwrap();
    }
}
