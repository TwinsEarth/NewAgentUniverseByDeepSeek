//! `nau-p2p-daemon` — the market node, plus a real libp2p swarm.
//!
//! This is `nau-daemon` with a network underneath it. It runs the same market, the
//! same durable store and the same authenticated HTTP API, and additionally joins
//! a libp2p room where it publishes its registered agents and accepts peers'
//! agents after verifying their signatures.
//!
//! Usage:
//! ```text
//! nau-p2p-daemon [--api-port 4002] [--data-dir nau-data] [--ephemeral]
//!                [--listen /ip4/0.0.0.0/tcp/4001] [--room room-...]
//!                [--seed <64 hex>] [--bootstrap <multiaddr>]...
//!                [--register-self] [--agent-name <name>] [--deposit 1000]
//!                [--min-stake 100]
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nau_core::{AgentCard, Identity, Money, Skill, Verifiable};
use nau_ledger::AccountId;
use nau_node::api;
use nau_node::p2p::{self, Directory, P2pOptions};
use nau_node::{arg_value, expand_home, has_flag, Node, NodeConfig};
use tokio::signal;

/// Every value following `name`; the flag may repeat.
fn repeated(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
                i += 1;
            }
        }
        i += 1;
    }
    out
}

fn fresh_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    seed
}

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
        println!("nau-p2p-daemon {}", nau_core::VERSION);
        return std::process::ExitCode::SUCCESS;
    }

    // ---------------------------------------------------------------- config
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

    let seed: [u8; 32] = match arg_value(&args, "--seed") {
        Some(text) => match hex::decode(text.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
        {
            Some(seed) => seed,
            None => {
                eprintln!("error: --seed must be 64 hex characters (32 bytes)");
                return std::process::ExitCode::from(2);
            }
        },
        None => fresh_seed(),
    };

    let listen =
        arg_value(&args, "--listen").unwrap_or_else(|| "/ip4/0.0.0.0/tcp/4001".to_string());
    let room = arg_value(&args, "--room").unwrap_or_else(|| "room-0000000000000001".to_string());
    let bootstrap = repeated(&args, "--bootstrap");
    let ephemeral = has_flag(&args, "--ephemeral");
    let register_self = has_flag(&args, "--register-self");
    let agent_name = arg_value(&args, "--agent-name").unwrap_or_else(|| "p2p-agent".to_string());
    let deposit = arg_value(&args, "--deposit").unwrap_or_else(|| "1000".to_string());

    let now = p2p::unix_now();

    // ------------------------------------------------------------------ node
    let mut node = if ephemeral {
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

    // The `did:nau:` and the libp2p `PeerId` come from one seed, so a peer can
    // bind the card it receives to the peer it received it from.
    let identity = Identity::from_seed(&seed);
    let local_did = identity.did().to_string();

    if register_self {
        if let Err(e) = register_own_agent(&mut node, &identity, &agent_name, &deposit, now) {
            eprintln!("error: --register-self: {e}");
            return std::process::ExitCode::from(1);
        }
        if let Err(e) = node.persist() {
            eprintln!("error: cannot persist: {e}");
            return std::process::ExitCode::from(1);
        }
    }

    let snapshot = node.snapshot();
    tracing::info!(
        version = %snapshot.version,
        protocol = %snapshot.protocol,
        local_did = %local_did,
        agents = snapshot.stats.agents,
        "nau-p2p-daemon starting"
    );

    // ------------------------------------------------------------------ swarm
    let options = P2pOptions {
        listen: listen.clone(),
        room: room.clone(),
        seed,
        bootstrap,
    };
    let swarm = match p2p::start_swarm(&options).await {
        Ok(swarm) => swarm,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    let directory: Directory = node.directory().clone();
    directory.set_local(swarm.peer_id().to_string(), local_did.clone());
    tracing::info!(
        peer_id = %swarm.peer_id(),
        listen = %listen,
        room = %room,
        "libp2p swarm is up"
    );

    // ---------------------------------------------------------------- serving
    let addr = config.api_addr.clone();
    let shared = Arc::new(Mutex::new(node));

    tokio::spawn(p2p::publish_loop(
        Arc::clone(&swarm),
        directory.clone(),
        Arc::clone(&shared),
        room.clone(),
        Duration::from_secs(2),
    ));
    tokio::spawn(p2p::receive_loop(
        Arc::clone(&swarm),
        directory.clone(),
        local_did.clone(),
    ));

    // Persist periodically so a hard kill loses at most one interval of work.
    let persister = Arc::clone(&shared);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
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
        #[cfg(unix)]
        {
            // This used to be `.expect("install SIGTERM handler")`, which panicked the
            // whole daemon at startup if the signal could not be installed — the exact
            // "cannot happen" claim the no-panics gate refuses, and the opposite of
            // what a signal handler is for. A node that cannot take SIGTERM should
            // still serve and still stop on SIGINT; it should say so, not die.
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
                        "cannot install a SIGTERM handler; this node will stop on SIGINT only"
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

    let result = api::serve(shared, &addr, shutdown).await;
    if let Err(e) = result {
        eprintln!("error: cannot bind {addr}: {e}");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

/// Deposit for, sign and register this node's own agent card.
///
/// The card is signed by the node's own key, so a peer that receives it over P2P
/// can verify it against the same key that fingerprints the `did:nau:`.
fn register_own_agent(
    node: &mut Node,
    identity: &Identity,
    name: &str,
    deposit: &str,
    now: u64,
) -> Result<(), String> {
    let account = AccountId::parse(identity.did().as_str()).map_err(|e| e.to_string())?;
    let stake = node.market().config().min_stake;

    {
        let market = node.market_mut();
        // `deposit` is an open faucet on this ledger; it is not a transfer from
        // anywhere, so registering an agent is funded explicitly and visibly.
        market
            .deposit(
                &account,
                Money::parse(deposit).map_err(|e| e.to_string())?,
                now,
            )
            .map_err(|e| e.to_string())?;

        let mut card = AgentCard::draft(
            identity,
            name,
            vec![Skill::new("text-generation", 1)],
            stake,
            now,
            1,
        );
        card.sign(identity).map_err(|e| e.to_string())?;
        market
            .register_agent(card, now)
            .map_err(|e| e.to_string())?;
    }

    tracing::info!(did = %identity.did(), name = %name, "registered this node's own agent");
    Ok(())
}

const HELP: &str = "\
nau-p2p-daemon — NewAgentUniverseByDeepSeek node with a real libp2p swarm

USAGE:
    nau-p2p-daemon [OPTIONS]

MARKET / HTTP (same as nau-daemon):
    --api-addr <ADDR>            bind address (default 127.0.0.1:4002)
    --api-port <PORT>            shorthand for --api-addr 127.0.0.1:<PORT>
    --data-dir <DIR>             state directory (default nau-data)
    --ephemeral                  keep everything in memory, persist nothing
    --min-stake <AMOUNT>         minimum stake to register an agent (default 100)

P2P:
    --listen <MULTIADDR>         swarm listen address (default /ip4/0.0.0.0/tcp/4001)
    --room <NAME>                GossipSub room; nodes must share it to see each other
    --seed <64 HEX>              identity seed for both did:nau: and PeerId
    --bootstrap <MULTIADDR>      peer to dial; may be repeated
    --register-self              register this node's own (signed) agent card
    --agent-name <NAME>          name for --register-self (default p2p-agent)
    --deposit <AMOUNT>           faucet deposit funding that registration (default 1000)

    --version                    print version and exit
    -h, --help                   print this help

WHAT REPLICATES:
    Registered agent cards are gossiped to the room. A card is admitted only if its
    Ed25519 signature verifies against the key that fingerprints its own DID.
    Balances and settlement do NOT replicate: moving funds between nodes is a
    consensus problem this build does not claim to have solved.

ENDPOINTS (market, as nau-daemon):
    GET  /health /version /stats /conservation /audit /leaderboard
    GET  /agents [?skill= | ?q=]      POST /agents
    GET  /tasks | /tasks/{id}         POST /tasks
    POST /tasks/{id}/bids | /match | /start | /results | /verify | /settle
    GET  /accounts/{account}/balance  POST /accounts/{account}/deposit
    GET  /disputes | /disputes/{id}   POST /disputes | /disputes/{id}/arbitrate

ENDPOINTS (new, read-only):
    GET  /p2p/peers              peers seen, frame counters, local identity
    GET  /p2p/agents             agent cards verified from peers

Mutating routes require `Authorization: Bearer <token>` and NAU_API_TOKENS set;
the default is to refuse every write.
";
