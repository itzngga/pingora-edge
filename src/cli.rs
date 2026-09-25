//! `pingora-edge --version|--help|--check|--reload|--status`. Runs before rustls and tracing are
//! set up, writes nothing, and never exits 1 (exit 1 is the old-binary fingerprint).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::check::{self, CheckOpts, Issue, Plan, Report, Sev};
use crate::cli_args::{self as args, CheckArgs, ClientArgs, Cmd};

const DEFAULT_SOCK: &str = "/run/pingora-edge/control.sock";
const EXITS: &str = "\
exit: 0 ok · 10 restart required · 11 warnings (--strict) · 12 sha mismatch · 64 usage
      65 invalid / rejected · 66 unreadable · 69 no config API · 70 internal
      75 timeout / not ready · 77 forbidden
";

// Write errors (a closed pipe) are ignored: println! would panic, and panic = abort.
fn out(s: &str) {
    let _ = std::io::stdout().lock().write_all(s.as_bytes());
}

fn err(s: &str) {
    let _ = std::io::stderr().lock().write_all(s.as_bytes());
}

fn json_line(v: &Value) -> String {
    format!(
        "{}\n",
        serde_json::to_string(v).unwrap_or_else(|_| "{}".into())
    )
}

fn plural(n: usize, word: &str) -> String {
    format!("{} {}{}", n, word, if n == 1 { "" } else { "s" })
}

fn short(sha: &str) -> String {
    sha.chars().take(12).collect()
}

pub fn run(argv: &[String]) -> i32 {
    match args::parse(argv) {
        Err(m) => {
            err(&format!(
                "{}: {}\n{}",
                env!("CARGO_PKG_NAME"),
                m,
                args::USAGE
            ));
            args::EX_USAGE
        }
        Ok(Cmd::Version) => {
            out(&format!(
                "{} {} config-api=1\n",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ));
            args::EX_OK
        }
        Ok(Cmd::Help) => {
            out(&format!("{}{}", args::USAGE, EXITS));
            args::EX_OK
        }
        Ok(Cmd::Check(a)) => run_check(&a),
        Ok(Cmd::Reload(a)) => run_reload(&a),
        Ok(Cmd::Status(a)) => run_status(&a),
    }
}

// ── --check ───────────────────────────────────────────────────────────────────

fn read_input(path: &str) -> std::io::Result<Vec<u8>> {
    let cap = (check::MAX_BYTES as u64).saturating_add(1);
    let mut buf = Vec::new();
    if path == "-" {
        std::io::stdin().lock().take(cap).read_to_end(&mut buf)?;
    } else {
        std::fs::File::open(path)?.take(cap).read_to_end(&mut buf)?;
    }
    Ok(buf)
}

fn run_check(a: &CheckArgs) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let workdir = match &a.workdir {
        Some(d) => cwd.join(d),
        None => cwd,
    };
    let opts = CheckOpts {
        host: !a.offline,
        workdir,
        strict: a.strict,
    };

    let (raw, mut rep, unreadable) = match read_input(&a.input) {
        Ok(raw) => {
            let rep = check::check_bytes(&raw, &opts);
            (raw, rep, false)
        }
        Err(e) => {
            let issue = Issue::new(
                Sev::Fatal,
                "F101",
                format!("{} is unreadable: {}", a.input, e),
            );
            let rep = Report {
                cfg: None,
                issues: vec![issue],
                sha256: check::sha256(b""),
                bytes: 0,
                summary: Default::default(),
            };
            (Vec::new(), rep, true)
        }
    };

    let mut diff: Option<(String, Plan)> = None;
    if let Some(base) = &a.against {
        let w499 = |m: String| Issue::new(Sev::Warning, "W499", m);
        match read_input(base) {
            Err(e) => rep.issues.push(w499(format!(
                "baseline {} is unreadable ({}) — no diff",
                base, e
            ))),
            Ok(braw) => {
                let old = check::parse(&braw, &mut Vec::new()).cfg;
                match (old, rep.cfg.as_ref()) {
                    (None, _) => rep
                        .issues
                        .push(w499(format!("baseline {} does not parse — no diff", base))),
                    (Some(_), None) => {}
                    (Some(old), Some(new)) => {
                        let static_only = check::boot_static_only(
                            &old,
                            (!a.offline).then_some(opts.workdir.as_path()),
                        );
                        match check::plan(&old, &old, new, static_only) {
                            Ok(mut p) => {
                                rep.issues.append(&mut p.notices);
                                diff = Some((check::hex(&check::sha256(&braw)), p));
                            }
                            Err(e) => rep
                                .issues
                                .push(w499(format!("diff against {} failed: {}", base, e))),
                        }
                    }
                }
            }
        }
        check::finish(&mut rep.issues, std::str::from_utf8(&raw).unwrap_or(""));
    }

    let diff_ref = diff.as_ref().map(|(s, p)| (s.as_str(), p));
    let text = human_check(&rep, &a.input, &opts, a.against.as_deref(), diff_ref);
    if a.json {
        out(&json_line(&check::check_json(
            &rep, &a.input, &opts, diff_ref,
        )));
        err(&text);
    } else {
        out(&text);
    }
    let bad = rep.count(Sev::Fatal).saturating_add(rep.count(Sev::Error));
    // W499 (a step that could not run) never changes the exit code, --strict included.
    let warnings = rep
        .issues
        .iter()
        .filter(|i| i.sev == Sev::Warning && i.code != "W499")
        .count();
    args::check_exit(bad, warnings, a.strict, unreadable)
}

fn human_check(
    rep: &Report,
    input: &str,
    opts: &CheckOpts,
    against: Option<&str>,
    diff: Option<(&str, &Plan)>,
) -> String {
    let mut s = format!(
        "{} {} — {} (sha256 {}…, {}, {}, host checks {}, workdir {})\n",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        input,
        short(&check::hex(&rep.sha256)),
        plural(rep.summary.routes, "route"),
        plural(rep.summary.hosts, "host"),
        if opts.host { "on" } else { "off" },
        opts.workdir.display()
    );
    for i in &rep.issues {
        s.push_str(&format!("{:<5} {}\n", i.sev.label(), i.line_text()));
    }
    if let Some(base) = against {
        match diff {
            Some((_, p)) => {
                let hot = p.changed.iter().filter(|c| check::is_hot(c)).count();
                let keys = if p.restart_keys.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", p.restart_keys.join(", "))
                };
                s.push_str(&format!(
                    "changes vs {}: hot {}, restart {}{}\n",
                    base,
                    hot,
                    p.restart_keys.len(),
                    keys
                ));
            }
            None => s.push_str(&format!("changes vs {}: unavailable\n", base)),
        }
    }
    s.push_str(&format!(
        "{} — {} fatal, {}, {}\n",
        if rep.ok() { "OK" } else { "INVALID" },
        rep.count(Sev::Fatal),
        plural(rep.count(Sev::Error), "error"),
        plural(rep.count(Sev::Warning), "warning")
    ));
    s
}

// ── --reload / --status: HTTP/1.1 over the control socket ─────────────────────

struct Fail {
    code: i32,
    msg: String,
}

fn sock_path(a: &ClientArgs) -> String {
    a.sock
        .clone()
        .or_else(|| std::env::var("CONTROL_SOCK").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| DEFAULT_SOCK.to_string())
}

fn call(sock: &str, method: &str, target: &str, timeout: Duration) -> Result<(u16, Vec<u8>), Fail> {
    let io = |e: std::io::Error, what: &str| Fail {
        code: args::io_exit(e.kind()),
        msg: format!("{} {}: {}", what, sock, e),
    };
    let mut s = std::os::unix::net::UnixStream::connect(sock).map_err(|e| io(e, "connect"))?;
    s.set_read_timeout(Some(timeout))
        .map_err(|e| io(e, "socket"))?;
    s.set_write_timeout(Some(timeout))
        .map_err(|e| io(e, "socket"))?;
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: edge\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        method, target
    );
    s.write_all(req.as_bytes()).map_err(|e| io(e, "write"))?;
    let mut buf = Vec::new();
    Read::by_ref(&mut s)
        .take(4 << 20)
        .read_to_end(&mut buf)
        .map_err(|e| io(e, "read"))?;
    parse_response(&buf).ok_or_else(|| Fail {
        code: args::EX_SOFTWARE,
        msg: "malformed HTTP response".into(),
    })
}

fn parse_response(buf: &[u8]) -> Option<(u16, Vec<u8>)> {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(buf.get(..split)?).ok()?;
    let body = buf.get(split.checked_add(4)?..)?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let (mut chunked, mut len) = (false, None);
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        } else if k == "content-length" {
            len = v.parse::<usize>().ok();
        }
    }
    let body = if chunked {
        dechunk(body)?
    } else {
        match len {
            Some(n) => body.get(..n)?.to_vec(),
            None => body.to_vec(),
        }
    };
    Some((status, body))
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let nl = b.windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(b.get(..nl)?).ok()?;
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        b = b.get(nl.checked_add(2)?..)?;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size.checked_add(2)?..)?;
    }
}

fn doc(body: &[u8], schema: &str) -> Option<Value> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .filter(|v| v.get("schema").and_then(Value::as_str) == Some(schema))
}

fn issue_lines(v: &Value, key: &str) -> String {
    let mut s = String::new();
    for i in v.get(key).and_then(Value::as_array).into_iter().flatten() {
        let f = |k: &str| i.get(k).and_then(Value::as_str).unwrap_or("-").to_string();
        s.push_str(&format!(
            "  {} {}: {}\n",
            f("code"),
            f("path"),
            f("message")
        ));
    }
    s
}

fn strs(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn reload_stub(result: &str, error: &str, t0: Instant) -> Value {
    json!({
        "schema": concat!(env!("CARGO_PKG_NAME"), "/reload/1"), "result": result, "generation": 0, "sha256": null,
        "applied_sha256": null, "ms": u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        "source": "control", "changed": [], "restart_keys": [], "notices": [], "issues": [], "error": error,
    })
}

fn human_reload(v: &Value) -> String {
    let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let gen = v.get("generation").and_then(Value::as_u64).unwrap_or(0);
    let ms = v.get("ms").and_then(Value::as_u64).unwrap_or(0);
    let mut o = match s("result").as_str() {
        "applied" => format!(
            "config: gen {} applied (sha {}, {} changed) in {} ms\n",
            gen,
            short(&s("sha256")),
            strs(v, "changed").len(),
            ms
        ),
        "unchanged" => format!(
            "config: unchanged (gen {}, sha {})\n",
            gen,
            short(&s("sha256"))
        ),
        "restart_required" => format!(
            "config: RESTART REQUIRED — keys {} (still serving gen {})\n",
            strs(v, "restart_keys").join(", "),
            gen
        ),
        "rejected" => format!(
            "config: REJECTED sha {} — still serving gen {}\n",
            short(&s("sha256")),
            gen
        ),
        "sha_mismatch" => format!(
            "config: the file on disk (sha {}) is not the expected one — nothing applied\n",
            short(&s("sha256"))
        ),
        other => match s("error") {
            e if e.is_empty() => format!("config: {}\n", other),
            e => format!("config: {} — {}\n", other, e),
        },
    };
    o.push_str(&issue_lines(v, "issues"));
    o
}

fn run_reload(a: &ClientArgs) -> i32 {
    let sock = sock_path(a);
    let target = match &a.expect_sha {
        Some(h) => format!("/config/reload?expect_sha={}", h),
        None => "/config/reload".to_string(),
    };
    let t0 = Instant::now();
    let (code, v, note) = match call(&sock, "POST", &target, Duration::from_secs(a.timeout)) {
        Err(f) => {
            let result = if f.code == args::EX_TEMPFAIL {
                "timeout"
            } else {
                "unavailable"
            };
            (
                f.code,
                reload_stub(result, &f.msg, t0),
                format!("config: reload {} — {}\n", result, f.msg),
            )
        }
        Ok((status, body)) => match doc(&body, concat!(env!("CARGO_PKG_NAME"), "/reload/1")) {
            Some(v) => {
                let code = args::reload_exit(status, v.get("result").and_then(Value::as_str));
                let text = human_reload(&v);
                (code, v, text)
            }
            None => {
                let why = format!(
                    "HTTP {} from {} without a reload document (no config API?)",
                    status, sock
                );
                (
                    args::reload_exit(status, None),
                    reload_stub("unavailable", &why, t0),
                    format!("config: {}\n", why),
                )
            }
        },
    };
    if a.json {
        out(&json_line(&v));
        err(&note);
    } else {
        out(&note);
    }
    code
}

fn human_status(v: &Value) -> String {
    let s = |p: &str| {
        v.pointer(p)
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_string()
    };
    let n = |p: &str| v.pointer(p).and_then(Value::as_u64).unwrap_or(0);
    let mut o = format!(
        "{} {} (pid {}) — state {}, gen {}\n",
        env!("CARGO_PKG_NAME"),
        s("/version"),
        n("/pid"),
        s("/state"),
        n("/generation")
    );
    o.push_str(&format!(
        "applied: sha {} ({}, from {}) at {}\n",
        short(&s("/applied/sha256")),
        s("/applied/source"),
        s("/applied/from"),
        s("/applied/at")
    ));
    let in_sync = v
        .pointer("/disk/in_sync")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    o.push_str(&if in_sync {
        "disk: in sync\n".to_string()
    } else {
        format!(
            "disk: sha {} differs from the applied file\n",
            short(&s("/disk/sha256"))
        )
    });
    if let Some(p) = v.get("pending_restart").filter(|p| !p.is_null()) {
        o.push_str(&format!(
            "pending restart since {}: {}\n",
            s("/pending_restart/since"),
            strs(p, "keys").join(", ")
        ));
    }
    if let Some(la) = v.get("last_attempt").filter(|p| !p.is_null()) {
        o.push_str(&format!(
            "last attempt: {} ({}) — {}, {}\n",
            s("/last_attempt/result"),
            s("/last_attempt/source"),
            plural(n("/last_attempt/errors") as usize, "error"),
            plural(n("/last_attempt/warnings") as usize, "warning")
        ));
        o.push_str(&issue_lines(la, "issues"));
    }
    o
}

fn run_status(a: &ClientArgs) -> i32 {
    let sock = sock_path(a);
    let stub = |e: &str| json!({"schema": concat!(env!("CARGO_PKG_NAME"), "/config-status/1"), "state": null, "error": e});
    let (code, v, note) = match call(
        &sock,
        "GET",
        "/config/status",
        Duration::from_secs(a.timeout),
    ) {
        Err(f) => (
            f.code,
            stub(&f.msg),
            format!("config: status unavailable — {}\n", f.msg),
        ),
        Ok((status, body)) => match (
            status,
            doc(&body, concat!(env!("CARGO_PKG_NAME"), "/config-status/1")),
        ) {
            (200, Some(v)) => {
                let applied = v.pointer("/applied/sha256").and_then(Value::as_str);
                let matches = a.expect_sha.as_deref().map(|h| applied == Some(h));
                let mut text = human_status(&v);
                if matches == Some(false) {
                    text.push_str("applied sha differs from --expect-sha\n");
                }
                (args::status_exit(200, matches), v, text)
            }
            (200, None) => (
                args::EX_SOFTWARE,
                stub("malformed status document"),
                "config: malformed status document\n".to_string(),
            ),
            (s, _) => {
                let why = format!("HTTP {} from {} (no config API?)", s, sock);
                (
                    args::status_exit(s, None),
                    stub(&why),
                    format!("config: {}\n", why),
                )
            }
        },
    };
    if a.json {
        out(&json_line(&v));
        err(&note);
    } else {
        out(&note);
    }
    code
}
