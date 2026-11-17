//! Pure helpers behind the config verifier (std only, so a rustc harness can test them).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};

/// Keys whose values are never printed anywhere (add_headers values are handled by table).
pub const SECRET_KEYS: &[&str] = &["eab_kid", "eab_hmac", "real_ip_secret", "token", "secret"];

/// Name-stable route identity: `name`, `name#k` (1-based) when names repeat, `#i` when empty.
pub fn route_identities(names: &[&str]) -> Vec<String> {
    // Counted once: every plan and reload calls this per config, on thousands of routes.
    let mut total: HashMap<&str, usize> = HashMap::with_capacity(names.len());
    for n in names {
        *total.entry(*n).or_insert(0) += 1;
    }
    let mut seen: HashMap<&str, usize> = HashMap::new();
    names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            if n.trim().is_empty() {
                return format!("#{}", i);
            }
            if total.get(n).copied() == Some(1) {
                return (*n).to_string();
            }
            let k = seen.entry(*n).or_insert(0);
            *k += 1;
            format!("{}#{}", n, k)
        })
        .collect()
}

/// Why a proxy `upstream` would not dial what it says (None = fine).
pub fn upstream_problem(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return Some("empty upstream".into());
    }
    if raw.chars().any(char::is_whitespace) {
        return Some("whitespace in the upstream".into());
    }
    let s = raw.trim_end_matches('/');
    let rest = match s.split_once("://") {
        Some((scheme, rest)) if scheme == "http" || scheme == "https" => rest,
        Some((scheme, _)) => return Some(format!("scheme '{}' is not http or https", scheme)),
        None => s,
    };
    if let Some(c) = rest.chars().find(|c| matches!(c, '/' | '?' | '#')) {
        return Some(format!(
            "'{}' after the host: paths, queries and fragments are not supported",
            c
        ));
    }
    let (host, port) = if let Some(after) = rest.strip_prefix('[') {
        let Some((addr, tail)) = after.split_once(']') else {
            return Some("unterminated [ in an IPv6 upstream".into());
        };
        if addr.parse::<Ipv6Addr>().is_err() {
            return Some(format!("'{}' is not an IPv6 address", addr));
        }
        match tail.strip_prefix(':') {
            Some(p) => (addr, Some(p)),
            None if tail.is_empty() => {
                return Some("an IPv6 upstream needs an explicit port ([addr]:port)".into())
            }
            None => return Some(format!("unexpected '{}' after the IPv6 address", tail)),
        }
    } else {
        match rest.matches(':').count() {
            0 => (rest, None),
            1 => match rest.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            },
            _ => return Some("unbracketed IPv6 address — write [addr]:port".into()),
        }
    };
    if host.is_empty() {
        return Some("no host".into());
    }
    if let Some(p) = port {
        match p.parse::<u32>() {
            Ok(n) if (1..=65535).contains(&n) => {}
            _ => return Some(format!("port '{}' is outside 1..65535", p)),
        }
    }
    None
}

/// Host hygiene (W412); `*` alone is a fatal elsewhere.
pub fn host_issue(h: &str) -> Option<&'static str> {
    if h.trim().is_empty() {
        return Some("empty host");
    }
    if h.chars().any(char::is_whitespace) {
        return Some("whitespace in the host");
    }
    if h.contains("://") {
        return Some("a scheme in the host");
    }
    if h.starts_with("*.") {
        return Some("wildcards are not matched (exact names only)");
    }
    if h.ends_with('.') {
        return Some("trailing dot");
    }
    if h.contains(':') {
        return Some("a port in the host");
    }
    if h.bytes().any(|b| b.is_ascii_uppercase()) {
        return Some("uppercase (hosts match lowercased)");
    }
    None
}

/// `addr/bits` → (is_v4, bits); None for a bare address or garbage.
pub fn cidr_bits(s: &str) -> Option<(bool, u8)> {
    let (a, b) = s.trim().split_once('/')?;
    let ip: IpAddr = a.trim().parse().ok()?;
    let bits: u8 = b.trim().parse().ok()?;
    Some((ip.is_ipv4(), bits))
}

/// IPv4 /8 or wider, IPv6 /16 or wider (E205).
pub fn cidr_too_broad(s: &str) -> bool {
    match cidr_bits(s) {
        Some((true, b)) => b <= 8,
        Some((false, b)) => b <= 16,
        None => false,
    }
}

/// A prefix longer than the family allows, which the parser clamps.
pub fn cidr_clamped(s: &str) -> bool {
    match cidr_bits(s) {
        Some((true, b)) => b > 32,
        Some((false, b)) => b > 128,
        None => false,
    }
}

/// A header value byte that the upstream request would refuse (TAB is fine).
pub fn has_ctl_bytes(v: &str) -> bool {
    v.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// Redirect cycles of length ≥ 2. Each entry is (lowercased hosts, lowercased redirect_to
/// for a redirect route else None); a cycle is returned once, as route indices.
pub fn redirect_cycles(routes: &[(Vec<String>, Option<String>)]) -> Vec<Vec<usize>> {
    let next = |i: usize| -> Option<usize> {
        let target = routes.get(i)?.1.as_ref()?;
        routes
            .iter()
            .enumerate()
            .find(|(j, (hosts, t))| *j != i && t.is_some() && hosts.iter().any(|h| h == target))
            .map(|(j, _)| j)
    };
    let mut state = vec![0u8; routes.len()]; // 0 new, 1 on the current walk, 2 done
    let mut cycles = Vec::new();
    for start in 0..routes.len() {
        if state.get(start).copied() != Some(0) {
            continue;
        }
        let mut walk: Vec<usize> = Vec::new();
        let mut cur = Some(start);
        while let Some(i) = cur {
            match state.get(i).copied() {
                Some(0) => {
                    if let Some(s) = state.get_mut(i) {
                        *s = 1;
                    }
                    walk.push(i);
                    cur = next(i);
                }
                Some(1) => {
                    if let Some(pos) = walk.iter().position(|&w| w == i) {
                        let cyc: Vec<usize> = walk.iter().skip(pos).copied().collect();
                        if cyc.len() >= 2 {
                            cycles.push(cyc);
                        }
                    }
                    break;
                }
                _ => break,
            }
        }
        for w in walk {
            if let Some(s) = state.get_mut(w) {
                *s = 2;
            }
        }
    }
    cycles
}

/// Levenshtein distance, for "did you mean" hints.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = Vec::with_capacity(b.len().saturating_add(1));
        cur.push(i.saturating_add(1));
        for (j, cb) in b.iter().enumerate() {
            let sub = prev
                .get(j)
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(usize::from(ca != *cb));
            let del = prev
                .get(j.saturating_add(1))
                .copied()
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            let ins = cur.last().copied().unwrap_or(usize::MAX).saturating_add(1);
            cur.push(sub.min(del).min(ins));
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

/// The closest candidate within distance 2, if any.
pub fn closest<'a>(key: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (edit_distance(key, c), *c))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// 1-based (line, column) of a byte offset.
pub fn line_col(src: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, c) in src.char_indices() {
        if i >= offset {
            break;
        }
        if c == '\n' {
            line = line.saturating_add(1);
            col = 1;
        } else {
            col = col.saturating_add(1);
        }
    }
    (line, col)
}

/// `[name]` → (false, "name"), `[[name]]` → (true, "name"); spaces around dots dropped.
pub fn header(line: &str) -> Option<(bool, String)> {
    let t = line.trim();
    let (array, inner) = if let Some(r) = t.strip_prefix("[[") {
        (true, r.split_once("]]")?.0)
    } else {
        let r = t.strip_prefix('[')?;
        (false, r.split_once(']')?.0)
    };
    let name: Vec<&str> = inner
        .split('.')
        .map(|s| s.trim().trim_matches('"'))
        .collect();
    Some((array, name.join(".")))
}

/// The bare key a line assigns (`key = …`, `"key" = …`, `a.b = …`), if any.
pub fn line_key(line: &str) -> Option<String> {
    let t = line.trim_start();
    if t.starts_with('[') || t.starts_with('#') {
        return None;
    }
    let (k, _) = t.split_once('=')?;
    let segs: Vec<&str> = k
        .split('.')
        .map(|s| s.trim().trim_matches('"').trim_matches('\''))
        .collect();
    if segs
        .iter()
        .any(|s| s.is_empty() || s.chars().any(char::is_whitespace))
    {
        return None;
    }
    Some(segs.join("."))
}

fn key_col(line: &str) -> usize {
    line.len()
        .saturating_sub(line.trim_start().len())
        .saturating_add(1)
}

/// Where a key lives. `Route(n)` is the n-th `[[route]]` (0-based); `Section("")` is the
/// top level. A dotted key inside a route (`rate_limit.rps`) is looked up in its
/// `[route.rate_limit]` sub-table; dotted or inline forms give None.
pub enum Where<'a> {
    Route(usize),
    Section(&'a str),
}

pub fn locate(src: &str, at: Where<'_>, key: Option<&str>) -> Option<(usize, usize)> {
    let lines: Vec<&str> = src.lines().collect();
    let find_key = |from: usize, k: &str| -> Option<(usize, usize)> {
        for (i, l) in lines.iter().enumerate().skip(from) {
            if header(l).is_some() {
                return None;
            }
            if line_key(l).as_deref() == Some(k) {
                return Some((i.saturating_add(1), key_col(l)));
            }
        }
        None
    };
    match at {
        Where::Route(n) => {
            let hdr = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| matches!(header(l), Some((true, ref h)) if h == "route"))
                .nth(n)
                .map(|(i, _)| i)?;
            let Some(k) = key else {
                return Some((hdr.saturating_add(1), 1));
            };
            match k.split_once('.') {
                None => find_key(hdr.saturating_add(1), k),
                Some((sub, leaf)) => {
                    let want = format!("route.{}", sub);
                    for (i, l) in lines.iter().enumerate().skip(hdr.saturating_add(1)) {
                        match header(l) {
                            Some((false, h)) if h == want => {
                                return find_key(i.saturating_add(1), leaf)
                            }
                            Some((_, h)) if h == "route" || !h.starts_with("route.") => {
                                return None
                            }
                            _ => {}
                        }
                    }
                    None
                }
            }
        }
        Where::Section("") => key.and_then(|k| find_key(0, k)),
        Where::Section(name) => {
            let hdr = lines
                .iter()
                .position(|l| matches!(header(l), Some((false, ref h)) if h == name))?;
            match key {
                None => Some((hdr.saturating_add(1), 1)),
                Some(k) => find_key(hdr.saturating_add(1), k),
            }
        }
    }
}

/// The table governing a byte offset: (header name, index of the [[route]] it sits in).
pub fn table_at(src: &str, offset: usize) -> (String, Option<usize>) {
    let mut name = String::new();
    let mut routes = 0usize;
    let mut pos = 0usize;
    for l in src.split_inclusive('\n') {
        if pos > offset {
            break;
        }
        if let Some((array, h)) = header(l) {
            if array && h == "route" {
                routes = routes.saturating_add(1);
            }
            name = h;
        }
        pos = pos.saturating_add(l.len());
    }
    let ridx = (name == "route" || name.starts_with("route.")).then(|| routes.saturating_sub(1));
    (name, ridx)
}

/// True when a 1-based line assigns a secret, sits in an add_headers table, or names one.
pub fn line_holds_secret(src: &str, line: usize) -> bool {
    let lines: Vec<&str> = src.lines().collect();
    let Some(text) = lines.get(line.saturating_sub(1)) else {
        return false;
    };
    let first: String = text
        .trim_start()
        .split(|c: char| c == '=' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .to_string();
    let segs: Vec<&str> = first
        .split('.')
        .map(|s| s.trim_matches('"').trim_matches('\''))
        .collect();
    if segs.contains(&"add_headers") || segs.last().is_some_and(|s| SECRET_KEYS.contains(s)) {
        return true;
    }
    let governing = lines
        .iter()
        .take(line)
        .rev()
        .find_map(|l| header(l))
        .map(|(_, h)| h)
        .unwrap_or_default();
    governing.ends_with("add_headers")
}
