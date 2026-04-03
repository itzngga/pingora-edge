//! pingora-edge: a TLS-terminating edge proxy on Pingora and BoringSSL.
//!
//! `pingora-edge --check|--reload|--status|--version` is the CLI (cli.rs);
//! `pingora-edge <FILE>` serves.
//!
//! Boot sequence:
//!  0. SIGHUP becomes a flag for the reloader (first statement; never the default kill)
//!  1. Verify the config file (check.rs); a FATAL file boots the last-good copy or exits
//!  2. Fetch Cloudflare IP ranges (if anything needs them)
//!  3. Load the on-demand host list from `on_demand_hosts`
//!  4. Start the :80 ACME challenge server and WAIT for it to bind
//!  5. Issue / renew the ACME bundle for named routes (static-cert routes skip this)
//!  6. Build the cert resolver:
//!       - routes with static_cert      → CertRegistry (SNI map, hot-reloadable)
//!       - routes without static_cert   → CertRegistry fallback (ACME bundle)
//!       - every other SNI              → OnDemandResolver (per-host ACME, allowlisted)
//!  7. Start Pingora on 127.0.0.1:4443 behind the :443 TLS pre-filter
//!  8. Background: metrics, ACME renewal, control socket, and the config reloader
//!     (SIGHUP / file watch / POST /config/reload → verify → hot apply or restart_required;
//!     SIGHUP also reloads the host list and the static certs)

// serde_json's json! expands nested invocations as part of the outer one, so a
// large literal with nested objects accumulates depth across the whole thing.
// Raising the limit means the next field added to a status document does not
// fail the build for a reason that has nothing to do with the field.
#![recursion_limit = "256"]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod acme;
mod bandwidth;
mod blocklist;
mod breaker;
mod check;
mod check_rules;
mod cli;
mod cli_args;
mod config;
mod control;
mod errlog;
mod errpage;
mod h2_guard;
mod host_list;
mod limiter;
mod metrics;
mod on_demand;
mod proxy;
mod reload;
mod route_ids;
mod shield;
mod static_handler;
mod tls_router;
mod tls_sni;
mod tuning;
mod watch_state;

use std::sync::Arc;

use arc_swap::ArcSwap;
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::protocols::http::v2::server::H2Options;
use pingora_core::server::Server;
use pingora_proxy::http_proxy_service;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

use crate::{
    acme::{new_token_store, run_challenge_server, CertBundle, CertStore},
    config::ProxyConfig,
    host_list::HostList,
    on_demand::OnDemandResolver,
    proxy::Gateway,
    shield::init_cloudflare_ranges,
    tls_sni::CertRegistry,
};

use pingora_core::listeners::TlsAcceptCallbacks;

// ── Combined TLS Acceptor ───────────────────────────────────────────────────
fn combined_tls_callbacks(
    registry: tls_sni::CertRegistry,
    on_demand: Arc<OnDemandResolver>,
) -> TlsAcceptCallbacks {
    use async_trait::async_trait;
    use pingora_core::listeners::TlsAccept;
    use pingora_core::protocols::tls::TlsRef;

    #[cfg(feature = "boringssl")]
    use pingora_boringssl as tls_lib;
    #[cfg(feature = "openssl")]
    use pingora_openssl as tls_lib;

    use tls_lib::ssl::NameType;

    struct Combined {
        registry: tls_sni::CertRegistry,
        on_demand: Arc<OnDemandResolver>,
    }

    #[async_trait]
    impl TlsAccept for Combined {
        async fn certificate_callback(&self, ssl: &mut TlsRef) {
            // No allocation for the common already-lowercase SNI.
            let is_named = match ssl.servername(NameType::HOST_NAME) {
                Some(s) if !s.bytes().any(|b| b.is_ascii_uppercase()) => self.registry.has_host(s),
                Some(s) => self.registry.has_host(&s.to_ascii_lowercase()),
                None => false,
            };

            if is_named {
                self.registry.tls_callbacks_inner(ssl).await;
            } else {
                self.on_demand.certificate_callback_inner(ssl).await;
            }
        }
    }

    Box::new(Combined {
        registry,
        on_demand,
    })
}

fn main() {
    reload::install_sighup();

    // `proxy --flag …` is the CLI: dispatched before any global setup, never a config path.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|a| a.to_string_lossy().starts_with('-'))
    {
        let argv: Vec<String> = std::env::args_os()
            .skip(1)
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        std::process::exit(cli::run(&argv));
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive("pingora_core::services::listening=off".parse().unwrap())
        // Benign, high-volume: emitted whenever a client/upstream closes a connection
        // early (scanners, aborted image loads). Keep real errors, drop the WARN spam.
        .add_directive("pingora_proxy::proxy_h1=error".parse().unwrap())
        // pingora_proxy's own per-request error logging is off entirely. We
        // now own every class it reported:
        //
        //   downstream aborts  → suppress_error_log, counted in /metrics
        //   upstream failures  → errlog, one aggregated line per 10s
        //   internal errors    → logged in full by fail_to_proxy
        //
        // The one thing this turns off that no hook could reach: the bare
        // "Fail to proxy:" line from handle_new_request, emitted when a client
        // disconnects before finishing its request header. That fires before a
        // CTX exists, so suppress_error_log is never consulted — a subscriber
        // directive is the only lever. It is also pure client garbage: no host,
        // no path, no context, thousands per second under a flood.
        .add_directive("pingora_proxy=off".parse().unwrap())
        // "H2 handshake error ... connection closed before reading preface" —
        // one ERROR per abandoned connection, thousands per second under a
        // handshake flood, formatted and pushed through the same global stdout
        // mutex every worker shares. It is emitted deep inside pingora-core's
        // accept loop with no hook to intercept, so a subscriber directive is
        // the only lever. Nothing is lost: these connections are counted by the
        // conn-rate gate and the abuse tracker, which also name the source IP —
        // which this line never did.
        .add_directive("pingora_core::apps=off".parse().unwrap());

    fmt().with_env_filter(filter).init();

    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "proxy.toml".to_string());

    // The boot config: immutable, and the only source for everything built once below.
    let (cfg, booted) = reload::boot_load(&cfg_path);
    let cfg = Arc::new(cfg);

    info!("Config loaded from '{}'", cfg_path);
    info!("{} route(s) configured", cfg.route.len());

    errpage::configure(&cfg.error_page);

    let host_list = HostList::load(&cfg.on_demand_hosts);

    let acme_hosts = cfg.acme_hosts();

    for r in cfg.route.iter() {
        let (addr, tls) = r.upstream_addr();
        let sni = r.upstream_sni();
        if r.ignore_ssl {
            info!(
                "Route '{}' → {} (tls={}, sni={}) | SSL ignored → fallback cert (hosts: {:?})",
                r.name, addr, tls, sni, r.hosts
            );
        } else if r.has_static_cert() {
            info!(
                "Route '{}' → {} (tls={}, sni={}) | static cert '{}' (hosts: {:?})",
                r.name,
                addr,
                tls,
                sni,
                r.static_cert.as_deref().unwrap_or("?"),
                r.hosts
            );
        } else {
            info!(
                "Route '{}' → {} (tls={}, sni={}) | ACME cert (hosts: {:?})",
                r.name, addr, tls, sni, r.hosts
            );
        }
    }

    if acme_hosts.is_empty() {
        info!("All routes use static certs — ACME will not issue certificates.");
    } else {
        info!(
            "ACME will manage {} hostname(s): {:?}",
            acme_hosts.len(),
            acme_hosts
        );
    }

    info!(":80 non-ACME traffic → 301 HTTPS redirect");
    info!(":443 public → tls_router pre-filter → Pingora (127.0.0.1:4443)");

    tuning::log_summary();

    let physical = num_cpus::get_physical().max(1);
    let logical = num_cpus::get().max(1);
    let pingora = logical.min(physical * 2);
    let bg = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(logical)
        .max(2);

    // Whether anything needs CF ranges — decides both the boot fetch and the
    // 12-hourly refresh below (see config::needs_cf_ranges).
    let need_cf_ranges = config::needs_cf_ranges(&cfg);

    // ── Bootstrap runtime ─────────────────────────────────────────────────────
    let (cert_store, tokens) = {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(bg)
            .enable_all()
            .build()
            .expect("bootstrap runtime");

        rt.block_on(async {
            let tokens = new_token_store();
            let cert_store = Arc::new(CertStore::new(cfg.acme.clone()));

            if need_cf_ranges {
                if let Err(e) = init_cloudflare_ranges().await {
                    tracing::error!("CF range init failed: {} (built-in snapshot used)", e);
                }
            }

            let bound = Arc::new(tokio::sync::Notify::new());
            let bound_tx = bound.clone();
            let t = tokens.clone();

            let pingora_internal_http = Some("127.0.0.1:8080".to_string());

            tokio::spawn(async move {
                run_challenge_server(t, Some(bound_tx), pingora_internal_http).await;
            });

            tokio::select! {
                _ = bound.notified() => info!(":80 challenge server ready — proceeding to ACME"),
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    tracing::error!("Port :80 did not bind within 10s — cannot issue ACME certs.");
                    std::process::exit(1);
                }
            }

            if !acme_hosts.is_empty() {
                if let Err(e) = cert_store.ensure(&acme_hosts, &tokens).await {
                    // A bundle that still loads keeps the edge serving; the renewal loop retries hourly.
                    if CertBundle::load(&cfg.acme.storage).is_none() {
                        tracing::error!("Certificate error: {}", e);
                        std::process::exit(1);
                    }
                    tracing::error!("Certificate error: {} — serving the existing bundle, renewal retries hourly", e);
                    acme::set_last_error(Some(e.to_string()));
                }
            }

            (cert_store, tokens)
        })
    };

    // The on-demand resolver. Built here, outside any runtime: it spawns
    // nothing until start_background_sweeper below. Its SNI allowlist is the
    // ACME route hosts plus the live on-demand list; any other SNI gets the
    // self-signed fallback and no ACME order.
    let on_demand = Arc::new(
        OnDemandResolver::new(
            host_list.clone(),
            cfg.acme.clone(),
            tokens.clone(),
            &cfg.route,
        )
        .unwrap_or_else(|e| {
            tracing::error!("on-demand resolver setup failed: {}", e);
            std::process::exit(1);
        }),
    );

    // Registry mode is fixed for the process: the ACME bundle, else the first static route
    // whose pair loads and matches (else merely loads). A route whose own pair does not is
    // served the fallback.
    let bundle = cfg.acme.bundle_exists();
    let static_fallback = if bundle {
        None
    } else {
        tls_sni::static_fallback(&cfg.route)
    };
    let boot = Arc::new(BootCaptured {
        cfg: Arc::clone(&cfg),
        bundle,
        static_fallback,
    });

    let registry = if boot.bundle {
        CertRegistry::build(&boot.cfg.route, &boot.cfg.acme).unwrap_or_else(|e| {
            tracing::error!("CertRegistry build failed: {}", e);
            std::process::exit(1);
        })
    } else {
        match boot.static_fallback.and_then(|i| boot.cfg.route.get(i)) {
            Some(first) => CertRegistry::build_static_only(
                &boot.cfg.route,
                first.static_cert.as_deref().unwrap_or(""),
                first.static_key.as_deref().unwrap_or(""),
            )
            .unwrap_or_else(|e| {
                tracing::error!("CertRegistry (static-only) build failed: {}", e);
                std::process::exit(1);
            }),
            None if boot.cfg.route.iter().any(|r| r.uses_static_cert()) => {
                tracing::error!("No ACME bundle found and no static_cert route whose cert loads.");
                std::process::exit(1);
            }
            None => {
                tracing::error!("No ACME bundle found and no static_cert route configured.");
                std::process::exit(1);
            }
        }
    };

    // Pingora always binds internally — the TLS pre-filter (tls_router)
    // owns the public :443 port and forwards valid TLS handshakes here.
    // This isolates Pingora's BoringSSL accept thread from abusive
    // half-open / non-TLS connections that previously caused TLS hoarding.
    let pingora_bind = "127.0.0.1:4443".to_string();

    // Built before the bg thread: the hot knobs are set from its handle before any
    // listener starts, and a later generation is published through the same handle.
    let (gateway, gw) = Gateway::new(Arc::clone(&boot.cfg), host_list.clone());
    apply_setters(&boot.cfg, None, &gw);

    // What the bundle must cover; a host-set change nudges the renewal loop.
    let acme_desired = Arc::new(ArcSwap::from_pointee(acme_hosts.clone()));
    let acme_changed = Arc::new(tokio::sync::Notify::new());

    let (reloader, reload_worker) = reload::Reloader::new(reload::Parts {
        path: cfg_path.clone(),
        booted,
        boot: Arc::clone(&boot),
        gw,
        registry: registry.clone(),
        on_demand: Arc::clone(&on_demand),
        hosts: host_list.clone(),
        acme_desired: Arc::clone(&acme_desired),
        acme_changed: Arc::clone(&acme_changed),
    });

    // ── Background runtime ────────────────────────────────────────────────────
    {
        let bg_boot = Arc::clone(&boot);
        let bg_store = Arc::clone(&cert_store);
        let bg_tokens = tokens.clone();
        let bg_registry = registry.clone();

        let bg_sweeper = Arc::clone(&on_demand);
        let bg_hosts = host_list.clone();

        std::thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(bg)
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let bg_cfg = &bg_boot.cfg;

                    // Clone for the control server before the sweeper consumes bg_sweeper.
                    let bg_ctl = Arc::clone(&bg_sweeper);

                    // The renewal sweep needs a live reactor, so it starts here.
                    bg_sweeper.start_background_sweeper();

                    // On-demand host list: poll the file's mtime and reload on
                    // change. 5 s is also the debounce.
                    bg_hosts.spawn_reload_watcher(std::time::Duration::from_secs(5));

                    if bg_cfg.metrics {
                        metrics::set_routes(bg_cfg.route.clone());
                        metrics::set_resolver(Arc::clone(&bg_ctl));
                        bandwidth::spawn(&bg_cfg.acme.storage);
                        tokio::spawn(metrics::serve(bg_cfg.metrics_listen.clone()));
                    }

                    // Control API over a unix socket: config status/verify/reload,
                    // cert status and warmup. Path from CONTROL_SOCK.
                    let ctl_sock = std::env::var("CONTROL_SOCK")
                        .unwrap_or_else(|_| "/run/pingora-edge/control.sock".to_string());
                    tokio::spawn(control::serve(ctl_sock, bg_ctl, reloader));
                    // After the control server: the one worker that verifies and applies config changes.
                    tokio::spawn(reload_worker.run());

                    tokio::spawn(run_challenge_server(
                        bg_tokens.clone(),
                        None,
                        Some("127.0.0.1:8080".to_string()),
                    ));

                    // TLS pre-filter on :443 — drops slowloris, non-TLS,
                    // and oversize ClientHello before Pingora's accept thread
                    // ever allocates BoringSSL state for them. Forwards every
                    // valid TLS handshake to Pingora at 127.0.0.1:4443.
                    //
                    // The trusted IP set ([security].trusted_ips) is exempt
                    // from the per-IP abuse tracker, intended for health
                    // checkers that would otherwise accumulate strikes during
                    // transient degraded states.
                    let trusted = bg_cfg.security.trusted_nets();
                    // BEFORE run(): the tracker's cache fixes its TTL when it
                    // is constructed inside run(), so configuring afterwards
                    // would silently leave the default window in force. The
                    // live splice/fingerprint knobs were set by apply_setters.
                    tls_router::configure_abuse(
                        bg_cfg.security.abuse_strikes,
                        bg_cfg.security.abuse_block_secs,
                    );
                    // The pre-filter's own supervisor: reclaims leaked
                    // connections in-process so a container restart stays the
                    // last resort rather than the first response.
                    tls_router::spawn_watchdog();
                    tokio::spawn(tls_router::run("127.0.0.1:4443".to_string(), trusted));

                    // Pick up static-cert renewals written by anything else (certbot,
                    // acme.sh, a plain `cp`). This runs UNCONDITIONALLY: the ACME
                    // renewal callback below is the only other caller of reload(),
                    // and it is never spawned when every route has a static cert,
                    // so without this the boot certs would be served until expiry.
                    bg_registry.spawn_file_watcher(std::time::Duration::from_secs(60));
                    // Keep the CF prefix set current: a boot-time fetch failure would
                    // otherwise pin the compiled-in snapshot for the life of the
                    // process, and new CF ranges would 403 until a restart.
                    if need_cf_ranges {
                        shield::spawn_cf_range_updater();
                    }
                    // [blocklist] file or URL (blocklist.rs).
                    blocklist::spawn_updaters(bg_cfg);
                    // Make a cert that is about to expire (or already has) loud.
                    bg_registry.spawn_expiry_watchdog(std::time::Duration::from_secs(6 * 3600));

                    // Bundle mode always renews, even with no ACME host yet: hosts
                    // can arrive later, and this loop is the only issuer.
                    if bg_boot.bundle {
                        let cb_registry = bg_registry.clone();
                        bg_store.spawn_renewal_with_callback(
                            acme_desired,
                            acme_changed,
                            bg_tokens,
                            move || {
                                // PEM reads behind the registry's writer lock: off the runtime.
                                let reg = cb_registry.clone();
                                tokio::task::spawn_blocking(move || match reg.reload() {
                                    Err(e) => tracing::warn!("CertRegistry reload failed: {}", e),
                                    Ok(()) => {
                                        tracing::info!("Certificates hot-reloaded successfully.")
                                    }
                                });
                            },
                        );
                    }
                    std::future::pending::<()>().await
                });
        });
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        crate::shield::init_crawler_updater(&cfg).await;
    });

    // ── Pingora server ────────────────────────────────────────────────────────
    let sc = pingora_core::server::configuration::ServerConf {
        threads: pingora,
        // Pingora defaults this to 128 for the WHOLE server, and the pool is
        // shared across every upstream. With H1 upstreams (one request per
        // connection) a concurrency burst past the cap does not queue — it opens
        // new connections, and on a TLS upstream each one is a fresh handshake.
        // Sizing it off RAM keeps a 1 GB VM modest while letting a big edge
        // actually hold its working set. Each idle entry is a socket plus its TLS
        // session, so this is a ceiling, not a reservation.
        // Inside a systemd unit it comes out of the unit's limit (tuning.rs).
        upstream_keepalive_pool_size: tuning::TUNING.upstream_pool,
        // A SIGTERM stop takes ≤4 s, inside a unit's TimeoutStopSec=5: 2 s grace for in-flight
        // requests after the listeners close, then each runtime gets ≤1 s to exit and Pingora
        // sleeps that 1 s again regardless (unset, the grace alone is 5 minutes).
        grace_period_seconds: Some(2),
        graceful_shutdown_timeout_seconds: Some(1),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, sc);
    server.bootstrap();

    {
        let mut svc = http_proxy_service(&server.configuration, gateway);

        let mut tls = TlsSettings::with_callbacks(combined_tls_callbacks(registry, on_demand))
            .unwrap_or_else(|e| {
                tracing::error!("TLS setup: {}", e);
                std::process::exit(1)
            });

        // ALPN. Advertising h2 is what lets a client open many streams on one
        // connection — the good case (multiplexing) and the bad case (rapid
        // reset) are the same mechanism. When h2 is off clients negotiate
        // HTTP/1.1, where one request costs one connection and every
        // per-connection defence at :443 applies again.
        if boot.cfg.security.http2_enabled {
            tls.enable_h2();

            // Bound per-connection stream concurrency. This does not stop a
            // reset flood by itself (see h2_guard) but it caps how much
            // upstream work one connection can hold open at once.
            if let Some(proxy) = svc.app_logic_mut() {
                let mut opts = H2Options::new();
                opts.max_concurrent_streams(boot.cfg.security.h2_max_concurrent_streams)
                    // Streams reset before we accept them sit in the accept
                    // queue holding memory. h2 defaults this to 20; keep it
                    // tight rather than inheriting whatever a future default
                    // becomes.
                    .max_pending_accept_reset_streams(32)
                    .max_header_list_size(16 * 1024);
                proxy.h2_options = Some(opts);
            }
        } else {
            tracing::warn!("HTTP/2 DISABLED by config — clients will negotiate HTTP/1.1 only");
        }

        svc.add_tls_with_settings(&pingora_bind, None, tls);
        svc.add_tcp("127.0.0.1:8080");

        server.add_service(svc);
    }

    info!(
        "Pingora on 127.0.0.1:4443 | TLS pre-filter on :443 | HTTP on :80 ({} workers)",
        pingora
    );
    server.run_forever();
}

/// What the boot-only consumers were built from: error page, on-demand host
/// path, ACME copies, the metrics listener, ALPN/H2, penalty box, abuse TTL and
/// the blocklist pullers. A later generation that would change any of it needs
/// a restart.
pub(crate) struct BootCaptured {
    pub cfg: Arc<ProxyConfig>,
    /// The registry falls back to the ACME bundle (else to a static route's cert).
    pub bundle: bool,
    /// Static-only mode: the position of the route whose cert is the fallback.
    pub static_fallback: Option<usize>,
}

/// Push the hot knobs into their runtime homes. `old` is the generation being
/// replaced (None at boot); only knobs that changed are re-set, so an apply does
/// not re-log the lot.
pub(crate) fn apply_setters(
    cfg: &ProxyConfig,
    old: Option<&ProxyConfig>,
    gw: &proxy::GatewayHandle,
) {
    let s = &cfg.security;
    let o = old.map(|c| &c.security);
    macro_rules! changed {
        ($($f:ident),+) => { o.is_none_or(|o| $(o.$f != s.$f)||+) };
    }

    let trust_cf = config::effective_trust_cf(cfg);
    if old.is_none_or(|o| config::effective_trust_cf(o) != trust_cf) {
        tls_router::set_trust_cf(trust_cf);
    }
    if changed!(tls_fp_rate, tls_fp_enforce) {
        tls_router::configure_tls_fp(s.tls_fp_rate, s.tls_fp_enforce);
    }

    // Bounds the pre-filter's own live connections: Pingora's global_connection_limit
    // sits BEHIND that listener, so without it nothing caps the edge.
    if changed!(max_live_tls) {
        tls_router::set_max_live_splices(config::effective_max_live_tls(s));
    }
    // The cancel guard is configured REGARDLESS of ALPN: gating it behind
    // http2_enabled once meant turning h2 off to stop a flood also switched off
    // the thing that measures it, and a vanishing h1 client costs MORE per
    // request (a fresh TCP connection and TLS handshake each time).
    if changed!(conn_rate_per_ip) {
        tls_router::configure_conn_rate(s.conn_rate_per_ip);
    }
    if changed!(max_live_direct) {
        tls_router::set_max_live_direct(s.max_live_direct);
    }
    if changed!(drop_direct_when_backend_down) {
        tls_router::set_drop_direct_when_down(s.drop_direct_when_backend_down);
    }
    // Watched through the on-demand fallback route's breaker slot; None (no
    // such route, or no slot) disables the automatic shrink rather than
    // watching an arbitrary route.
    let fb_slot = |c: &ProxyConfig| {
        config::fallback_route_index(&c.route)
            .and_then(|i| c.route.get(i))
            .map(|r| r.id)
            .filter(|&id| id != route_ids::NO_SLOT)
    };
    if changed!(max_live_direct_degraded) || old.is_some_and(|o| fb_slot(o) != fb_slot(cfg)) {
        tls_router::set_direct_degraded(s.max_live_direct_degraded, fb_slot(cfg));
    }
    if changed!(upstream_max_fails, upstream_fail_timeout_secs) {
        breaker::configure(s.upstream_max_fails, s.upstream_fail_timeout_secs);
    }
    if changed!(h2_cancel_threshold) {
        h2_guard::configure(s.h2_cancel_threshold);
    }
    if changed!(h2_max_streams_per_conn) {
        h2_guard::configure_conn_limit(s.h2_max_streams_per_conn);
    }
    if changed!(max_inflight_per_ip) {
        gw.inflight.set_max(s.max_inflight_per_ip);
    }
    if changed!(global_connection_limit) {
        gw.shedder.set_limit(s.global_connection_limit);
    }
    // At boot these belong to the pre-filter itself: configure_abuse and run(trusted).
    if let Some(o) = o {
        if o.abuse_strikes != s.abuse_strikes {
            tls_router::set_abuse_strikes(s.abuse_strikes);
        }
        if o.trusted_ips != s.trusted_ips {
            tls_router::set_trusted(s.trusted_nets());
        }
    }
}
