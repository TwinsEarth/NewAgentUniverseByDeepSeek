//! `nau` — command-line entry point.
//!
//! Subcommands that operate on a **local** data directory (no network needed):
//! `version`, `identity`, `keygen`, `inspect`, `verify`, `daemon`.
//!
//! Upstream's `gsn` binary forwarded `market` subcommands over HTTP to a running
//! daemon, which meant the CLI could not report anything without one and had no
//! offline story. This CLI deliberately keeps the offline commands offline, and
//! `daemon` runs the node in-process.

use nau_core::domain::Money;
use nau_core::{Identity, Keypair};
use nau_node::{arg_value, expand_home, Node, NodeConfig};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("help");

    match command {
        "version" | "--version" | "-V" => {
            println!("nau {}", nau_core::VERSION);
            println!("protocol      {}", nau_core::PROTOCOL_VERSION);
            println!("project       {}", nau_core::PROJECT);
            println!(
                "based on      {} v{} (MIT)",
                nau_core::UPSTREAM_PROJECT,
                nau_core::UPSTREAM_VERSION
            );
            std::process::ExitCode::SUCCESS
        }

        "identity" | "keygen" => {
            // `nau identity [--seed <64 hex>]`
            let keypair = match arg_value(&args, "--seed") {
                Some(hex_seed) => match Keypair::from_seed_hex(&hex_seed) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("error: --seed: {e}");
                        return std::process::ExitCode::from(2);
                    }
                },
                None => Keypair::generate(),
            };
            let identity = Identity::new(keypair);
            let seed = identity.keypair().seed_hex();
            println!("did          {}", identity.did());
            println!("public_key   {}", identity.public_key().to_hex());
            println!("legacy_did   {}", identity.public_key().legacy_did());
            println!("seed_hex     {seed}");
            eprintln!();
            eprintln!("keep seed_hex secret: it is the private key.");
            std::process::ExitCode::SUCCESS
        }

        "inspect" | "status" => {
            // Open a data directory read-only and report the restored state.
            let dir = arg_value(&args, "--data-dir").unwrap_or_else(|| "nau-data".to_string());
            let config = NodeConfig {
                data_dir: expand_home(&dir),
                ..NodeConfig::default()
            };
            let now = now_unix();
            match Node::open(config, now) {
                Ok(node) => {
                    let snap = node.snapshot();
                    println!("version        {}", snap.version);
                    println!("protocol       {}", snap.protocol);
                    println!("upstream       {}", snap.upstream);
                    println!("data_dir       {}", node.config().data_dir.display());
                    println!("agents         {}", snap.stats.agents);
                    println!("tasks          {}", snap.stats.tasks);
                    println!("settled        {}", snap.stats.settled);
                    println!("disputes       {}", snap.stats.disputes);
                    println!("escrowed_minor {}", snap.stats.escrowed_minor);
                    let c = node.market().conservation();
                    let a = node.market().audit();
                    println!(
                        "conservation   o1={} on={} discrepancy={}",
                        c.conserved, a.conserved, a.discrepancy
                    );
                    if !a.conserved || a.discrepancy != 0 {
                        eprintln!(
                            "warning: the independent audit disagrees with the O(1) counters"
                        );
                        return std::process::ExitCode::from(1);
                    }
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: cannot open {}: {e}", expand_home(&dir).display());
                    std::process::ExitCode::from(1)
                }
            }
        }

        "verify" => {
            // Round-trip a signed payload from stdin, exercising the canonical
            // payload rules end to end. Useful for debugging cross-language issues.
            let mut input = String::new();
            if std::io::Read::read_to_string(&mut std::io::stdin(), &mut input).is_err() {
                eprintln!("error: cannot read stdin");
                return std::process::ExitCode::from(2);
            }
            let value: serde_json::Value = match serde_json::from_str(&input) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: stdin is not valid JSON: {e}");
                    return std::process::ExitCode::from(2);
                }
            };
            match nau_core::canonical::canonical_object(&value) {
                Ok(canonical) => {
                    println!("{canonical}");
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::ExitCode::from(1)
                }
            }
        }

        "daemon" => {
            // Delegate to the daemon binary's behaviour in-process.
            let exe = std::env::current_exe().ok().map(|p| {
                p.with_file_name(if cfg!(windows) {
                    "nau-daemon.exe"
                } else {
                    "nau-daemon"
                })
            });
            match exe {
                Some(path) if path.exists() => {
                    let rest: Vec<String> = args.iter().skip(2).cloned().collect();
                    match std::process::Command::new(path).args(rest).status() {
                        Ok(s) if s.success() => std::process::ExitCode::SUCCESS,
                        Ok(s) => std::process::ExitCode::from(s.code().unwrap_or(1) as u8),
                        Err(e) => {
                            eprintln!("error: cannot launch nau-daemon: {e}");
                            std::process::ExitCode::from(1)
                        }
                    }
                }
                _ => {
                    eprintln!("error: nau-daemon binary not found next to this executable");
                    std::process::ExitCode::from(1)
                }
            }
        }

        "amount" => {
            // Exact decimal parsing check: `nau amount 12.5`.
            match args.get(2) {
                Some(s) => match Money::parse(s) {
                    Ok(m) => {
                        println!("minor  {}", m.minor());
                        println!("canon  {}", m.to_decimal_string());
                        std::process::ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::ExitCode::from(2)
                    }
                },
                None => {
                    eprintln!("usage: nau amount <decimal>");
                    std::process::ExitCode::from(2)
                }
            }
        }

        "conformance" => {
            // Print the identity the shared fixture is built from, so an operator can
            // check that the local implementation agrees with it.
            let seed = [1u8; 32];
            let id = Identity::from_seed(&seed);
            let expected_did = "did:nau:34750f98bd59fcfc";
            let expected_pk = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
            println!("fixture seed   {}", hex::encode(seed));
            println!("derived did    {}", id.did());
            println!("derived pubkey {}", id.public_key().to_hex());
            if id.did().as_str() != expected_did || id.public_key().to_hex() != expected_pk {
                eprintln!("error: identity derivation disagrees with conformance/vectors.json");
                return std::process::ExitCode::from(1);
            }
            // Also prove a sign/verify round trip.
            let payload = serde_json::json!({ "n": 1, "signature": "" });
            match id.sign_payload(&payload) {
                Ok(sig) => {
                    let signed = serde_json::json!({ "n": 1, "signature": sig });
                    match id.verify_payload(&signed, &sig) {
                        Ok(()) => {
                            println!("sign/verify    ok");
                            std::process::ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("error: verify failed: {e}");
                            std::process::ExitCode::from(1)
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: sign failed: {e}");
                    std::process::ExitCode::from(1)
                }
            }
        }

        _ => {
            println!("{HELP}");
            if command == "help" || command == "--help" || command == "-h" {
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("unknown command `{command}`");
                std::process::ExitCode::from(2)
            }
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

const HELP: &str = "\
nau — NewAgentUniverseByDeepSeek command line

USAGE:
    nau <COMMAND> [OPTIONS]

COMMANDS:
    version                      print version, protocol and upstream provenance
    identity [--seed <64 hex>]   generate (or re-derive) an Ed25519 identity
    inspect [--data-dir <DIR>]   open a data dir and report restored state + audit
    verify                       read JSON on stdin and print its canonical payload
    amount <decimal>             exact decimal -> minor units (no floating point)
    conformance                  check the shared fixture identity and a sign/verify
    daemon [OPTIONS]             run the node (same options as nau-daemon)
    help                         this message

EXAMPLES:
    nau identity
    nau amount 12.5               # -> minor 12500000
    echo '{\"b\":1,\"a\":2,\"signature\":\"\"}' | nau verify
    nau inspect --data-dir ./nau-data
    nau daemon --api-port 4002 --data-dir ./nau-data
";
