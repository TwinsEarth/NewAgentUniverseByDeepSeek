//! `nau-daemon` — run a node.
//!
//! Usage:
//! ```text
//! nau-daemon [--api-port 4002] [--api-addr 127.0.0.1:4002] [--data-dir nau-data]
//!            [--ephemeral] [--min-stake 100] [--min-reputation-bps 0]
//! ```

use std::sync::{Arc, Mutex};

use nau_core::domain::Money;
use nau_node::api;
use nau_node::{arg_value, expand_home, has_flag, Node, NodeConfig};
use tokio::signal;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        println!("{HELP}");
        return std::process::ExitCode::SUCCESS;
    }
    if has_flag(&args, "--version") || has_flag(&args, "-V") {
        println!("nau-daemon {}", nau_core::VERSION);
        return std::process::ExitCode::SUCCESS;
    }

    let mut config = NodeConfig::default();
    if let Some(addr) = arg_value(&args, "--api-addr") {
        config.api_addr = addr;
    }
    if let Some(port) = arg_value(&args, "--api-port") {
        config.api_addr = format!("127.0.0.1:{port}");
    }
    if let Some(dir) = arg_value(&args, "--data-dir") {
        config.data_dir = expand_home(&dir);
    }
    if let Some(stake) = arg_value(&args, "--min-stake") {
        match Money::parse(&stake) {
            Ok(m) => config.market.min_stake = m,
            Err(e) => {
                eprintln!("error: --min-stake: {e}");
                return std::process::ExitCode::from(2);
            }
        }
    }
    if let Some(bps) = arg_value(&args, "--min-reputation-bps") {
        match bps.parse::<u32>() {
            Ok(v) if v <= 10_000 => config.market.min_reputation_bps = v,
            _ => {
                eprintln!("error: --min-reputation-bps must be 0..=10000");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let ephemeral = has_flag(&args, "--ephemeral");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let node = if ephemeral {
        match Node::ephemeral(config.clone()) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("error: {e}");
                return std::process::ExitCode::from(1);
            }
        }
    } else {
        match Node::open(config.clone(), now) {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "error: cannot open data dir {}: {e}",
                    config.data_dir.display()
                );
                return std::process::ExitCode::from(1);
            }
        }
    };

    let snapshot = node.snapshot();
    tracing::info!(
        version = %snapshot.version,
        protocol = %snapshot.protocol,
        upstream = %snapshot.upstream,
        data_dir = %if ephemeral { "<ephemeral>".to_string() } else { config.data_dir.display().to_string() },
        "NewAgentUniverseByDeepSeek starting"
    );
    tracing::info!(
        agents = snapshot.stats.agents,
        tasks = snapshot.stats.tasks,
        escrowed_minor = snapshot.stats.escrowed_minor,
        "restored state"
    );

    let addr = config.api_addr.clone();
    let shared = Arc::new(Mutex::new(node));

    // Persist periodically so a hard kill loses at most one interval of work.
    let persister = Arc::clone(&shared);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            // `mut` because `persist` must record how much of the journal it has
            // already written; a non-mutating persist re-appended all of it.
            let mut guard = match persister.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if let Err(e) = guard.persist() {
                tracing::error!(error = %e, "periodic persist failed");
            }
        }
    });

    let shutdown = async {
        // Ctrl-C, or SIGTERM on unix.
        #[cfg(unix)]
        {
            // A signal handler that cannot be installed is a degraded shutdown
            // path, not a reason to abort the process: report it and fall back to
            // Ctrl-C. (This was the last `expect` in production code; the
            // no-panics gate treats an unverifiable "cannot happen" as a defect.)
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut term) => {
                    tokio::select! {
                        _ = signal::ctrl_c() => {}
                        _ = term.recv() => {}
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "cannot install a SIGTERM handler; shut down with Ctrl-C only"
                    );
                    let _ = signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = signal::ctrl_c().await;
        }
    };

    // A clone of the same `Arc`: `serve` takes ownership, and the stop below has to reach the
    // **same** node -- a second `Node` would be a second set of plugins to stop.
    let result = api::serve(shared.clone(), &addr, shutdown).await;

    if let Err(e) = result {
        eprintln!("error: cannot bind {addr}: {e}");
        return std::process::ExitCode::from(1);
    }

    // Stop the plugins, dependents first, and say what happened.
    //
    // # What this replaced
    //
    // Nothing. The daemon has had a shutdown path since it gained a signal handler and until
    // now that path did nothing to the plugins: seventeen of them ran, the process exited, and
    // whether any of them had state to flush was nobody's business. `SystemPluginHost::shutdown`
    // was called only from tests, and `HotPlug::stop_plan` had no caller anywhere.
    //
    // Failures are printed rather than swallowed. A plugin that will not stop is a fact an
    // operator needs, and the process is ending either way -- so the only thing reporting buys
    // is the operator's knowledge, which is exactly what was missing.
    {
        let mut node = match shared.lock() {
            Ok(node) => node,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let outcomes = node.plugins_mut().shutdown(now);
        let failed: Vec<(String, String)> = outcomes
            .iter()
            .filter_map(|(name, outcome)| {
                outcome
                    .as_ref()
                    .err()
                    .map(|why| (name.clone(), why.clone()))
            })
            .collect();
        eprintln!(
            "stopped {} plugin(s); {} could not be stopped",
            outcomes.len(),
            failed.len()
        );
        for (name, why) in failed {
            eprintln!("  {name}: {why}");
        }
    }

    std::process::ExitCode::SUCCESS
}

const HELP: &str = "\
nau-daemon — NewAgentUniverseByDeepSeek node

USAGE:
    nau-daemon [OPTIONS]

OPTIONS:
    --api-addr <ADDR>            bind address (default 127.0.0.1:4002)
    --api-port <PORT>            shorthand for --api-addr 127.0.0.1:<PORT>
    --data-dir <DIR>             state directory (default nau-data; leading ~ is expanded)
    --ephemeral                  keep everything in memory, persist nothing
    --min-stake <AMOUNT>         minimum stake to register an agent (default 100)
    --min-reputation-bps <N>     reputation floor to bid, 0..=10000 (default 0)
    --version                    print version and exit
    -h, --help                   print this help

ENDPOINTS:
    GET  /health /version /stats /conservation /audit /leaderboard
    GET  /agents [?skill= | ?q=]      POST /agents
    GET  /agents/{did}
    GET  /tasks | /tasks/{id}         POST /tasks
    POST /tasks/{id}/bids | /match | /start | /results | /verify | /settle
    GET  /accounts/{account}/balance  POST /accounts/{account}/deposit
    GET  /disputes | /disputes/{id}   POST /disputes | /disputes/{id}/arbitrate

Amounts are EXACT: send {\"amount\":\"12.5\"} as a decimal string, or
{\"amount_minor\":12500000}. Floating-point amounts are refused.
";
