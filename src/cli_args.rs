//! `pingora-edge --<mode>` argv grammar and exit codes (std only). The CLI never
//! exits 1: a binary without the CLI would treat `--check` as a config path and
//! exit 1 with "Cannot read '--", so scripts can tell the two apart.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub const EX_OK: i32 = 0;
pub const EX_RESTART: i32 = 10;
pub const EX_WARN: i32 = 11;
pub const EX_SHA: i32 = 12;
pub const EX_USAGE: i32 = 64;
pub const EX_INVALID: i32 = 65;
pub const EX_NOINPUT: i32 = 66;
pub const EX_UNAVAILABLE: i32 = 69;
pub const EX_SOFTWARE: i32 = 70;
pub const EX_TEMPFAIL: i32 = 75;
pub const EX_NOPERM: i32 = 77;

pub const USAGE: &str = "\
usage:
  pingora-edge <FILE>        serve (default FILE: proxy.toml)
  pingora-edge --version
  pingora-edge --help
  pingora-edge --check  [--json] [--strict] [--offline] [--workdir DIR] [--against FILE] <FILE|->
  pingora-edge --reload [--json] [--sock PATH] [--timeout SECS] [--expect-sha HEX64]
  pingora-edge --status [--json] [--sock PATH] [--expect-sha HEX64]
";

#[derive(Debug, PartialEq, Eq)]
pub struct CheckArgs {
    pub json: bool,
    pub strict: bool,
    pub offline: bool,
    pub workdir: Option<String>,
    pub against: Option<String>,
    pub input: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClientArgs {
    pub json: bool,
    pub sock: Option<String>,
    pub timeout: u64,
    pub expect_sha: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Version,
    Help,
    Check(CheckArgs),
    Reload(ClientArgs),
    Status(ClientArgs),
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse argv without argv[0]. Err = usage error (exit 64); a typo is never a path.
pub fn parse(args: &[String]) -> Result<Cmd, String> {
    let Some((mode, rest)) = args.split_first() else {
        return Err("no mode flag".into());
    };
    match mode.as_str() {
        "--version" | "--help" if !rest.is_empty() => Err(format!("{} takes no arguments", mode)),
        "--version" => Ok(Cmd::Version),
        "--help" => Ok(Cmd::Help),
        "--check" => parse_check(rest).map(Cmd::Check),
        "--reload" => parse_client(rest, true).map(Cmd::Reload),
        "--status" => parse_client(rest, false).map(Cmd::Status),
        other => Err(format!("unknown mode '{}'", other)),
    }
}

fn take_value<'a>(it: &mut std::slice::Iter<'a, String>, flag: &str) -> Result<&'a String, String> {
    match it.next() {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{} needs a value", flag)),
    }
}

fn set_once<T>(slot: &mut Option<T>, v: T, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{} given twice", flag));
    }
    *slot = Some(v);
    Ok(())
}

fn set_flag(slot: &mut bool, flag: &str) -> Result<(), String> {
    if *slot {
        return Err(format!("{} given twice", flag));
    }
    *slot = true;
    Ok(())
}

fn parse_check(rest: &[String]) -> Result<CheckArgs, String> {
    let (mut json, mut strict, mut offline) = (false, false, false);
    let (mut workdir, mut against, mut input) = (None, None, None::<String>);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if input.is_some() {
            return Err(format!(
                "'{}' after the input operand (the operand is last)",
                a
            ));
        }
        match a.as_str() {
            "--json" => set_flag(&mut json, a)?,
            "--strict" => set_flag(&mut strict, a)?,
            "--offline" => set_flag(&mut offline, a)?,
            "--workdir" => set_once(&mut workdir, take_value(&mut it, a)?.clone(), a)?,
            "--against" => {
                let v = take_value(&mut it, a)?;
                if v == "-" {
                    return Err("--against needs a file, not stdin".into());
                }
                set_once(&mut against, v.clone(), a)?
            }
            "-" => input = Some(a.clone()),
            s if s.starts_with('-') => return Err(format!("unknown flag '{}' for --check", s)),
            "" => return Err("empty input operand".into()),
            _ => input = Some(a.clone()),
        }
    }
    let Some(input) = input else {
        return Err("--check needs a <FILE|-> operand".into());
    };
    Ok(CheckArgs {
        json,
        strict,
        offline,
        workdir,
        against,
        input,
    })
}

fn parse_client(rest: &[String], reload: bool) -> Result<ClientArgs, String> {
    let mode = if reload { "--reload" } else { "--status" };
    let mut json = false;
    let (mut sock, mut timeout, mut expect_sha) = (None, None::<u64>, None);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => set_flag(&mut json, a)?,
            "--sock" => set_once(&mut sock, take_value(&mut it, a)?.clone(), a)?,
            "--timeout" if reload => {
                let v = take_value(&mut it, a)?;
                match v.parse::<u64>() {
                    Ok(n) if (1..=3600).contains(&n) => set_once(&mut timeout, n, a)?,
                    _ => return Err(format!("--timeout '{}' is not 1..3600 seconds", v)),
                }
            }
            "--expect-sha" => {
                let v = take_value(&mut it, a)?;
                if !is_hex64(v) {
                    return Err("--expect-sha needs 64 lowercase hex characters".into());
                }
                set_once(&mut expect_sha, v.clone(), a)?
            }
            s => return Err(format!("unexpected '{}' for {}", s, mode)),
        }
    }
    Ok(ClientArgs {
        json,
        sock,
        timeout: timeout.unwrap_or(if reload { 60 } else { 10 }),
        expect_sha,
    })
}

/// --check: unreadable 66, fatal/error 65, warnings under --strict 11.
pub fn check_exit(fatal_or_error: usize, warnings: usize, strict: bool, unreadable: bool) -> i32 {
    if unreadable {
        EX_NOINPUT
    } else if fatal_or_error > 0 {
        EX_INVALID
    } else if strict && warnings > 0 {
        EX_WARN
    } else {
        EX_OK
    }
}

/// --reload: HTTP status (+ `result` of a 200) → exit code.
pub fn reload_exit(status: u16, result: Option<&str>) -> i32 {
    match status {
        200 => match result {
            Some("applied") | Some("unchanged") => EX_OK,
            _ => EX_SOFTWARE,
        },
        409 => EX_RESTART,
        412 => EX_SHA,
        422 => EX_INVALID,
        503 | 504 => EX_TEMPFAIL,
        403 => EX_NOPERM,
        404 => EX_UNAVAILABLE,
        _ => EX_SOFTWARE,
    }
}

/// --status: a 200 is ok; with --expect-sha the applied sha must match.
pub fn status_exit(status: u16, sha_matches: Option<bool>) -> i32 {
    match status {
        200 => match sha_matches {
            Some(false) => EX_SHA,
            _ => EX_OK,
        },
        404 => EX_UNAVAILABLE,
        503 | 504 => EX_TEMPFAIL,
        403 => EX_NOPERM,
        _ => EX_SOFTWARE,
    }
}

/// Socket-level failures: no API (missing socket / refused) vs timeout vs anything else.
pub fn io_exit(kind: std::io::ErrorKind) -> i32 {
    use std::io::ErrorKind::*;
    match kind {
        NotFound | ConnectionRefused => EX_UNAVAILABLE,
        TimedOut | WouldBlock => EX_TEMPFAIL,
        _ => EX_SOFTWARE,
    }
}
