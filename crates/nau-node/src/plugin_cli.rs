//! `nau plugin …` — the plugin external interface.
//!
//! # Why the matrix is generated rather than printed from a table
//!
//! `nau plugin tiers` prints the `(capability, tier)` matrix by **calling
//! [`Capability::decision`] for every pair**. Nothing here restates a policy, so this
//! command cannot describe a system different from the one that enforces it — which is
//! the failure this whole project is a reaction to. The same is true of
//! `nau plugin runtimes`, which asks each backend what it enforces instead of quoting
//! the architecture document.
//!
//! # What `verify` does and does not do
//!
//! It runs the **whole load pipeline** — parse, blacklist, the four signature checks,
//! the tier ceiling, the runtime's boundary requirement, the dependency check, the
//! lifecycle transitions — and prints every stage's outcome or the refusal.
//!
//! It does **not execute the plugin**. The process runtime's `start` validates and
//! reports the limits it will hand to the sandbox; the actual launch belongs to the
//! daemon, which owns the data directory and the executor. A command that claimed to
//! have run a plugin when it had only verified it would be exactly the kind of
//! overstatement the gates exist to prevent, so the output says which it did.

use std::path::Path;

use nau_plugin::arbiter::{Arbiter, LoadRequest};
use nau_plugin::blacklist::Blacklist;
use nau_plugin::bus::{Bus, BusLimits};
use nau_plugin::capability::{Capability, Grant};
use nau_plugin::manifest::TrustStore;
use nau_plugin::registry::Registry;
use nau_plugin::runtime::{NativeRuntime, ProcessRuntime, WasmRuntime};
use nau_plugin::tier::Tier;

/// Run a `nau plugin …` subcommand. `args` excludes the `plugin` word itself.
#[must_use]
pub fn run(args: &[String]) -> std::process::ExitCode {
    let Some(command) = args.first().map(String::as_str) else {
        return usage();
    };
    match command {
        "tiers" => tiers(),
        "runtimes" => runtimes(),
        "verify" => verify(&args[1..]),
        // The third-party registration and review flow: submit, scan, advance through
        // the stages, and certify with a scope. The scan runs the same checks the load
        // pipeline runs, so "passes review" means "can be loaded".
        "review" => crate::plugin_review::run(&args[1..]),
        "blacklist" => blacklist(&args[1..]),
        "system" => system(&args[1..]),
        // The command that actually **executes** a plugin. Until it existed, `ProcessPluginHost`
        // was constructed only by its own tests: the T1/T2/T3 tiers could be loaded, reviewed
        // and certified, and nothing an operator has ever ran one.
        "run" => run_plugin(&args[1..]),
        "help" | "--help" | "-h" => usage(),
        other => {
            eprintln!("error: `{other}` is not a plugin subcommand");
            usage();
            // A usage error is not a successful invocation. Exiting 0 here would let a
            // typo inside a script pass unnoticed, which is the class of quiet failure
            // this project keeps finding.
            std::process::ExitCode::from(2)
        }
    }
}

/// Print the usage summary.
fn usage() -> std::process::ExitCode {
    println!("nau plugin — the plugin kernel's external interface");
    println!();
    println!("  tiers                 the (capability, tier) matrix, generated from the code");
    println!("  runtimes              what each isolation backend enforces, and what it does not");
    println!("  verify <dir> [flags]  run the whole load pipeline over a plugin directory");
    println!("  run <dir> [flags]     the same pipeline, then START the plugin and call one op");
    println!("                        --op <name> --payload <json>");
    println!("  blacklist [<file>]    show a signed blacklist, verifying every entry");
    println!("  system                boot the compiled-in T0 plugins and call them");
    println!("  review <op>           the third-party registration and review flow");
    println!();
    println!("blacklist operations (the stored list the load pipeline consults):");
    println!("  add     --dir <d> --entry <signed.json> --vendor <hex>");
    println!("  list    --dir <d>");
    println!("  check   --dir <d> --name <plugin> [--digest <hex>]");
    println!("  appeal  --dir <d> --name <plugin> --from <stage> --to <stage>");
    println!("  unblock --dir <d> --name <plugin> [--digest <hex>]");
    println!("With no operation word the legacy `blacklist <file>` report form is used.");
    println!();
    println!("review operations (a scan runs the real load pipeline, so it passes only");
    println!("what the arbiter would load):");
    println!("  open    --dir <d> --manifest <path> --publisher <did> [--at <ts>]");
    println!("  scan    --dir <d> --manifest <path> [--vendor <hex>]");
    println!("  advance --dir <d> --to <stage> --because <text> [--at <ts>]");
    println!("  show    --dir <d>");
    println!("  certify --dir <d> --scope <cap,cap> --vendor-key <hex> [--at <ts>]");
    println!();
    println!("verify flags:");
    println!("  --trust <hex>         trust a publisher key (repeatable; default trusts nobody)");
    println!("  --vendor <hex>        trust a vendor key that may counter-sign (repeatable)");
    println!("  --blacklist <file>    run with the stored quarantine; without it the list is");
    println!("                        empty, and verify says so rather than implying a check");
    println!();
    println!("A directory holds `plugin.json` plus the entry artefact it names.");
    std::process::ExitCode::SUCCESS
}

/// All the values a flag was given, in order.
fn all_values(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        // `--trust=x` and `--trust x` are both accepted; a CLI that only takes one
        // form is a CLI that surprises half its callers.
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            out.push(v.to_string());
        } else if a == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        }
    }
    out
}

/// The first positional argument, skipping flags and their values.
fn positional(args: &[String]) -> Option<String> {
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") {
            // A flag that takes a separate value consumes the next argument.
            skip = !a.contains('=');
            continue;
        }
        return Some(a.clone());
    }
    None
}

/// `nau plugin tiers`
fn tiers() -> std::process::ExitCode {
    println!("tier x capability — every cell is `Capability::decision`, not a table in a document");
    println!();
    print!("{:<32}", "capability");
    for tier in Tier::LOADABLE {
        print!("{:<18}", tier_label(tier));
    }
    println!("{:>10}", "T3?");
    println!("{}", "-".repeat(32 + 18 * Tier::LOADABLE.len() + 10));

    for cap in Capability::ALL {
        print!("{:<32}", cap.as_str());
        for tier in Tier::LOADABLE {
            let cell = match cap.decision(tier) {
                Grant::Always => "always".to_string(),
                Grant::RequiresApproval(a) => format!("needs {}", a.label()),
                Grant::Refused { .. } => "REFUSED".to_string(),
            };
            print!("{cell:<18}");
        }
        // The column that matters most, stated per row rather than summarised.
        let third_party = matches!(cap.decision(Tier::ThirdParty), Grant::Refused { .. });
        println!("{:>10}", if third_party { "refused" } else { "held" });
    }

    println!();
    println!("A quarantined plugin holds nothing, including the basic set.");
    println!("`kernel:*` has no approval path: no authority exists that can grant it below the system tier.");
    std::process::ExitCode::SUCCESS
}

/// `nau plugin runtimes`
fn runtimes() -> std::process::ExitCode {
    let backends: [(&str, Box<dyn nau_plugin::runtime::PluginRuntime>); 3] = [
        ("native", Box::new(NativeRuntime::new())),
        ("process", Box::new(ProcessRuntime::new())),
        ("wasm", Box::new(WasmRuntime::new())),
    ];

    println!("isolation backends — each answers for itself what it can enforce");
    println!();
    for (name, backend) in &backends {
        let caps = backend.declares();
        println!(
            "{name}  ({})  available: {}",
            caps.kind.label(),
            caps.kind.is_available()
        );
        let mut enforced: Vec<&str> = caps.enforced.iter().map(|b| b.label()).collect();
        enforced.sort_unstable();
        if enforced.is_empty() {
            println!("    enforces:  nothing");
        } else {
            println!("    enforces:  {}", enforced.join(", "));
        }
        let mut unenforced = caps.unenforced();
        unenforced.sort_by_key(|(b, _)| b.label());
        for (boundary, why) in unenforced {
            println!("    NOT {}: {why}", boundary.label());
        }
        println!();
    }

    println!("A plugin must either have each boundary enforced or waive it in its manifest");
    println!("with a written reason. An unwaived boundary is a typed refusal, not a downgrade.");
    std::process::ExitCode::SUCCESS
}

/// `nau plugin verify <dir>`
fn verify(args: &[String]) -> std::process::ExitCode {
    load_plugin(args, None)
}

/// Run one op on a plugin, through the whole load pipeline first.
fn run_plugin(args: &[String]) -> std::process::ExitCode {
    let Some(op) = all_values(args, "--op").first().cloned() else {
        eprintln!("error: `plugin run` needs `--op <name>` ? the op to call");
        return usage();
    };
    let payload = all_values(args, "--payload")
        .first()
        .cloned()
        .unwrap_or_else(|| "{}".to_string());
    load_plugin(args, Some((&op, &payload)))
}

/// Start a plugin the pipeline accepted, call one op on it, and print the answer.
///
/// # Why this command had to exist
///
/// `verify` runs every check that can refuse a plugin and then says, in as many words, that
/// the plugin was **not executed**. That was accurate for the whole build: `ProcessPluginHost`
/// ? the only thing that can start a process plugin ? was constructed **only by its own tests**,
/// so the T1/T2/T3 tiers were loadable, reviewable, certifiable and **never run by anything an
/// operator has**. A whole set of tiers that can pass every gate and still not run is the
/// "written but not wired" shape at the largest scale in this repository.
fn execute_loaded(
    loaded: &nau_plugin::Loaded,
    manifest_json: &str,
    entry: &std::path::Path,
    op: &str,
    payload_text: &str,
    now: u64,
    registry: &nau_plugin::registry::Registry,
) -> std::process::ExitCode {
    if loaded.runtime != nau_plugin::runtime::RuntimeKind::Process {
        eprintln!(
            "refused  runtime_not_process  `{}` loads on {}, and this command starts the process \
             runtime only; a native plugin runs in this address space and is not started here",
            loaded.id,
            loaded.runtime.label()
        );
        return std::process::ExitCode::from(1);
    }
    // The manifest's own limits, not a fixture's: the pipeline validated this object, and a
    // second source of limits would be a second answer to "how much may this plugin use".
    let limits = serde_json::from_str::<serde_json::Value>(manifest_json)
        .ok()
        .and_then(|v| serde_json::from_value::<nau_plugin::Limits>(v.get("limits")?.clone()).ok());
    let Some(limits) = limits else {
        eprintln!("error: the manifest has no usable `limits` object");
        return std::process::ExitCode::from(2);
    };
    let spec = nau_plugin::runtime::StartSpec {
        plugin: loaded.id.clone(),
        tier: loaded.tier,
        entry: entry.to_path_buf(),
        limits,
        waivers: crate::plugin_process::required_waivers(),
    };
    // A scratch sandbox per invocation, under the OS temp directory. The host creates the
    // plugin's own directory inside it and the sandbox manager sweeps it on the next open, so
    // a run that dies still leaves the root cleanable rather than leaving the plugin's data in
    // the operator's working tree.
    let root = std::env::temp_dir().join(format!("nau-plugin-run-{}", std::process::id()));
    let host = match crate::plugin_process::ProcessPluginHost::open(&root, now) {
        Ok(host) => host,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let plugin = match host.start(&nau_plugin::runtime::ProcessRuntime::new(), &spec) {
        Ok(plugin) => plugin,
        Err(e) => {
            eprintln!("refused  start_refused  {e}");
            return std::process::ExitCode::from(1);
        }
    };
    // A payload that is not JSON is passed as a JSON string rather than refused: the plugin
    // owns its payload's shape, and this command is not a second parser for it.
    let payload: serde_json::Value = serde_json::from_str(payload_text)
        .unwrap_or_else(|_| serde_json::Value::String(payload_text.to_string()));
    let request = serde_json::json!({
        "abi": nau_plugins::frame::abi_version(),
        "id": "nau plugin run",
        "op": op,
        "payload": payload,
    });
    let Ok(bytes) = serde_json::to_vec(&request) else {
        eprintln!("error: the request could not be encoded");
        return std::process::ExitCode::from(2);
    };
    println!("EXECUTING  {}  op={op}", loaded.id);
    match host.call(&plugin, &bytes) {
        Ok(frame) => match nau_plugins::frame::decode_response(&frame) {
            Ok(response) => {
                println!("  ok:      {}", response.ok);
                if let Some(code) = &response.code {
                    println!("  code:    {code}");
                }
                if let Some(message) = &response.message {
                    println!("  message: {message}");
                }
                match &response.payload {
                    Some(payload) => println!(
                        "  payload: {}",
                        serde_json::to_string(payload).unwrap_or_else(|_| "<unencodable>".into())
                    ),
                    None => println!("  payload: (none)"),
                }
                // **B2: the plugin declares, the host delivers.**
                //
                // A process plugin is a child that answers one frame and exits: it holds no
                // token, no bus handle and no session key, so it cannot put anything on PMB and
                // cannot forge a source. What it can do is name what it wants sent, and the host
                // — which holds the token the pipeline minted — presents that token and lets the
                // bus decide. Every check still runs; none is skipped and none is re-implemented
                // here, because the host is the only delivery point.
                let declared = &response.outbox;
                if !declared.is_empty() {
                    match registry
                        .get(loaded.id.as_str())
                        .map(|e| e.verified.token.clone())
                    {
                        Some(token) => match Bus::new(BusLimits::default()) {
                            Ok(mut bus) => {
                                let outcomes = crate::plugin_process::deliver_declared(
                                    &mut bus,
                                    registry,
                                    &token,
                                    &loaded.id,
                                    declared,
                                    now * 1_000,
                                );
                                println!("  declared {} message(s):", outcomes.len());
                                for outcome in &outcomes {
                                    match &outcome.outcome {
                                        Ok(recipients) => println!(
                                            "    [{}] -> {}: delivered to {}",
                                            outcome.index,
                                            outcome.target,
                                            if recipients.is_empty() {
                                                "nobody (no subscriber)".to_string()
                                            } else {
                                                recipients.join(", ")
                                            }
                                        ),
                                        Err(refusal) => println!(
                                            "    [{}] -> {}: refused by the bus: {refusal}",
                                            outcome.index, outcome.target
                                        ),
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("  error: the bus limits are not usable: {e}");
                            }
                        },
                        // Not an error to be swallowed: a plugin with no token cannot send, and
                        // saying so is the difference between "it said nothing" and "nothing
                        // could carry what it said".
                        None => eprintln!(
                            "  declared {} message(s), but `{}` is not in the registry, so it has \
                             no token and nothing could be delivered on its behalf",
                            declared.len(),
                            loaded.id
                        ),
                    }
                }
                let _ = host.stop(&plugin);
                if response.ok {
                    std::process::ExitCode::SUCCESS
                } else {
                    std::process::ExitCode::from(1)
                }
            }
            Err(e) => {
                let _ = host.stop(&plugin);
                eprintln!("refused  frame_unreadable  {e}");
                std::process::ExitCode::from(2)
            }
        },
        Err(e) => {
            let _ = host.stop(&plugin);
            eprintln!("refused  call_refused  {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Verify a plugin, and optionally **execute** it.
///
/// `execute` is `Some((op, payload))` for `nau plugin run` and `None` for `nau plugin
/// verify`. The two share this body rather than each having a prologue, because two
/// trust-and-arbiter setups that agree today are two that disagree after the next edit ? and
/// here the disagreement would be between what an operator verified and what they ran.
fn load_plugin(args: &[String], execute: Option<(&str, &str)>) -> std::process::ExitCode {
    let Some(dir) = positional(args) else {
        eprintln!("error: `plugin verify` needs a directory");
        return usage();
    };
    let dir = crate::expand_home(&dir);

    let manifest_path = dir.join("plugin.json");
    let Ok(manifest_json) = std::fs::read_to_string(&manifest_path) else {
        eprintln!("error: cannot read {}", manifest_path.display());
        return std::process::ExitCode::from(2);
    };

    // The entry path comes out of the manifest, so it is untrusted input: it was
    // validated as a single path component by `Manifest::validate`, and the join here
    // relies on that. Reading the file before the pipeline runs is deliberate -- the
    // module digest check needs the bytes -- but nothing is executed.
    let entry_name = match serde_json::from_str::<serde_json::Value>(&manifest_json)
        .ok()
        .and_then(|v| v.get("plugin")?.get("entry")?.as_str().map(str::to_string))
    {
        Some(name) => name,
        None => {
            eprintln!("error: the manifest has no `plugin.entry`");
            return std::process::ExitCode::from(2);
        }
    };
    let entry_path = dir.join(&entry_name);
    let Ok(module) = std::fs::read(&entry_path) else {
        eprintln!(
            "error: cannot read the entry artefact {}",
            entry_path.display()
        );
        return std::process::ExitCode::from(2);
    };
    let entry = std::fs::canonicalize(&entry_path).unwrap_or(entry_path.clone());

    // Fail-closed: an unconfigured invocation trusts nobody, so a third-party plugin
    // is refused until the operator names a key. That is the same posture the daemon
    // takes, and doing it differently here would make `verify` a way to talk yourself
    // into a load the daemon would refuse.
    let mut trust = TrustStore::deny_all();
    for key in all_values(args, "--vendor") {
        if let Err(e) = trust.trust_vendor_key(&key) {
            eprintln!("error: --vendor {key}: {e}");
            return std::process::ExitCode::from(2);
        }
    }
    for key in all_values(args, "--trust") {
        if let Err(e) = trust.trust_third_party_key(&key) {
            eprintln!("error: --trust {key}: {e}");
            return std::process::ExitCode::from(2);
        }
    }

    // The blacklist the load pipeline will consult, loaded through the **same** function
    // every `nau plugin blacklist` operation calls.
    //
    // This used to be `Blacklist::new()` unconditionally, which meant the list an operator
    // had just maintained with `nau plugin blacklist add` was not the list `verify` ran
    // with: a plugin could be condemned and still verify clean. That is the boundary-
    // documented-but-not-consulted shape this project keeps finding -- a check that exists,
    // reports, and is not in the path it claims to be in.
    //
    // Passing the same loader rather than a second one matters for the same reason: entries
    // are signed, so loading means re-verifying, and two loaders that agree today are two
    // loaders that disagree after the next edit. `plugin_review::scan` reaches the same
    // function, and a test pins that all three callers refuse an identical file identically.
    let blacklist = match all_values(args, "--blacklist").first() {
        Some(path) => {
            let path = crate::expand_home(path);
            match crate::plugin_blacklist::load_verified(&path, &trust) {
                Ok((_entries, list)) => list,
                Err(refusal) => {
                    eprintln!(
                        "refused  {}  {}",
                        crate::plugin_blacklist::Refusal::code(&refusal),
                        crate::plugin_blacklist::Refusal::detail(&refusal)
                    );
                    return std::process::ExitCode::from(1);
                }
            }
        }
        // No flag: the list is empty, and that is stated rather than left to be inferred.
        // An empty blacklist and an unconsulted one look identical in a clean verdict.
        None => {
            println!("no --blacklist given: the load pipeline runs with an empty quarantine");
            Blacklist::new()
        }
    };

    // The shipped adapters, deliberately. A host that refuses every plugin not built for
    // its own ABI has not become extensible, it has become incompatible -- and V3.2.1's
    // compatibility promise is exactly that a 2.x plugin still loads here. The trace below
    // says which adapter carried it.
    let arbiter = Arbiter::new(trust, blacklist)
        .with_runtime(Box::new(NativeRuntime::new()))
        .with_runtime(Box::new(ProcessRuntime::new()))
        .with_runtime(Box::new(WasmRuntime::new()))
        .with_adapters(nau_plugin::hot::AdapterRegistry::with_shipped_adapters());

    // The certification a review issued, if the operator has one to hand.
    //
    // Without this flag the arbiter has no certification and a **certified** plugin is
    // refused `certification_missing` -- which is the tier's requirement, not an oversight.
    // The flag is what makes the granted scope reachable by the process that enforces it:
    // `nau plugin review certify` writes the artefact, and this reads it back through the
    // same projection, so there is one definition of the file's shape rather than two.
    let arbiter = match all_values(args, "--certification").first() {
        Some(path) => {
            let path = crate::expand_home(path);
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) => {
                    eprintln!("error: cannot read {}: {e}", path.display());
                    return std::process::ExitCode::from(2);
                }
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("error: {} is not JSON: {e}", path.display());
                    return std::process::ExitCode::from(2);
                }
            };
            match crate::plugin_review::certification_from_json(&value) {
                Ok(certification) => arbiter.with_certification(certification),
                Err(why) => {
                    eprintln!("refused  certification_refused  {why}");
                    return std::process::ExitCode::from(1);
                }
            }
        }
        None => arbiter,
    };
    let mut registry = Registry::new();
    let Ok(mut bus) = Bus::new(BusLimits::default()) else {
        eprintln!("error: the bus limits are not usable");
        return std::process::ExitCode::from(2);
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Copies rather than moves: `run` needs the manifest's own limits and the entry path
    // after the pipeline has accepted the plugin, and a second read of the same files would be
    // a second answer about what was verified.
    let request = LoadRequest::new(manifest_json.clone(), module, entry.clone());

    println!("verify {}", dir.display());
    // Ask the arbiter what it actually holds, rather than the local `trust` that was
    // moved into it: the number printed is then the trust store in force.
    println!(
        "  trust store: {} key(s) — an unconfigured run trusts nobody",
        arbiter.trust().len()
    );
    println!();
    match arbiter.load(&mut registry, &mut bus, &request, now) {
        Ok(loaded) => {
            for step in &loaded.trace {
                println!("  ok    {:<10} {}", step.step, step.outcome);
            }
            println!();
            println!(
                "ACCEPTED  {}  tier={} runtime={}",
                loaded.id,
                loaded.tier,
                loaded.runtime.label()
            );
            let mut caps: Vec<&str> = loaded.granted.iter().map(|c| c.as_str()).collect();
            caps.sort_unstable();
            println!(
                "  holds: {}",
                if caps.is_empty() {
                    "nothing".into()
                } else {
                    caps.join(", ")
                }
            );
            match &loaded.compat {
                nau_plugin::hot::Compat::Direct => println!("  abi:   this host's own"),
                nau_plugin::hot::Compat::Adapted { adapter, from } => println!(
                    "  abi:   {from} translated by `{adapter}` — hot compatibility, and the \
                     translation is named rather than inferred"
                ),
            }
            println!();
            match execute {
                None => {
                    println!(
                        "Note: this ran every check that can refuse a plugin. The plugin was NOT \
                         executed. `nau plugin run` is the command that executes one."
                    );
                    std::process::ExitCode::SUCCESS
                }
                // The registry goes along because B2 needs it twice: it holds the token the
                // plugin's declaration must be delivered under, and it is the membership the bus
                // asks "is this sender running?". A second registry built here would answer both
                // questions about a different set of plugins.
                Some((op, payload_text)) => execute_loaded(
                    &loaded,
                    &manifest_json,
                    &entry,
                    op,
                    payload_text,
                    now,
                    &registry,
                ),
            }
        }
        Err(failure) => {
            for step in &failure.trace {
                let mark = if step.passed { "ok   " } else { "FAIL " };
                println!("  {mark} {:<10} {}", step.step, step.outcome);
            }
            println!();
            println!("REFUSED  {}", failure.refusal.code());
            println!("  {}", failure.detail);
            println!();
            println!(
                "The refusal is the answer, not an error in this tool: a plugin that asks for a"
            );
            println!(
                "boundary this build cannot enforce, or a capability its tier may not hold, is"
            );
            println!("refused by name rather than run with less isolation than it declared.");
            std::process::ExitCode::from(1)
        }
    }
}

/// `nau plugin blacklist [<file>]`
fn blacklist(args: &[String]) -> std::process::ExitCode {
    // Management first, report second. `add`, `list`, `check`, `appeal` and `unblock` drive
    // the real `Blacklist` — the same one the arbiter consults — while the legacy form takes
    // a file of signed entries and reports on it. Routing on the operation word rather than
    // on the presence of a flag keeps the old invocation working unchanged.
    if args
        .first()
        .is_some_and(|word| crate::plugin_blacklist::is_operation(word))
    {
        return crate::plugin_blacklist::run(args);
    }
    let Some(file) = positional(args) else {
        println!("nau plugin blacklist <file>");
        println!();
        println!(
            "Entries must be signed by a trusted vendor key; pass --vendor <hex> to trust one."
        );
        println!("An unsigned or self-signed entry is refused, because a blacklist anyone can");
        println!("append to is a way to ban a competitor.");
        println!();
        println!("To manage a stored list instead:");
        println!("  nau plugin blacklist add --dir <d> --entry <signed.json> --trust <hex>");
        println!("  nau plugin blacklist list --dir <d>");
        println!("  nau plugin blacklist check --dir <d> --name <plugin> [--digest <hex>]");
        println!("  nau plugin blacklist appeal --dir <d> --name <plugin> --from <s> --to <s>");
        println!("  nau plugin blacklist unblock --dir <d> --name <plugin>");
        return std::process::ExitCode::SUCCESS;
    };
    let path = crate::expand_home(&file);
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!("error: cannot read {}", path.display());
        return std::process::ExitCode::from(2);
    };
    let mut trust = TrustStore::deny_all();
    for key in all_values(args, "--vendor") {
        if let Err(e) = trust.trust_vendor_key(&key) {
            eprintln!("error: --vendor {key}: {e}");
            return std::process::ExitCode::from(2);
        }
    }
    if trust.is_empty() {
        eprintln!("error: no --vendor key given, so every entry would be refused as untrusted");
        eprintln!("       that is the fail-closed default, not a bug");
        return std::process::ExitCode::from(2);
    }

    let entries: Vec<nau_plugin::blacklist::BlacklistEntry> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let mut list = Blacklist::new();
    let mut refused = 0usize;
    for entry in entries {
        match list.add(entry, &trust) {
            Ok(()) => {}
            Err(e) => {
                refused += 1;
                eprintln!("refused: {e}");
            }
        }
    }
    println!("{} accepted, {refused} refused", list.len());
    for name in list.names() {
        if let Some(e) = list.entry(name) {
            println!(
                "  {name}  {}  since {}  evidence {}",
                e.reason.label(),
                e.blacklisted_at,
                e.evidence_cid
            );
            match &e.module_sha256 {
                Some(d) => println!(
                    "      pinned to {d} — a different build is not condemned by this entry"
                ),
                None => println!("      all builds of this name"),
            }
        }
    }
    if refused > 0 {
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

/// A label wide enough for the table.
fn tier_label(tier: Tier) -> String {
    format!("{} ({})", tier.label(), tier)
}

/// `nau plugin system` — boot the compiled-in T0 plugins and call them.
///
/// This is the one command that *runs* something rather than verifying it, and it says
/// so in its output. The plugins it runs are the four compiled into this binary; no
/// downloaded code is executed, and the manifests are signed in memory with a key
/// generated for this invocation.
fn system(args: &[String]) -> std::process::ExitCode {
    let storage = match all_values(args, "--data-dir").first() {
        Some(dir) => crate::expand_home(dir),
        None => std::env::temp_dir().join(format!("nau-system-plugins-{}", std::process::id())),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // A fresh, empty ledger -- and correct here, unlike in the daemon: this command has no
    // market, so there is no second set of books for `sys.ledger` to disagree with. The
    // parameter exists so that a host which *does* have books has to say which ones.
    let books = std::sync::Arc::new(std::sync::Mutex::new(nau_ledger::Ledger::new()));
    let mut boot = match crate::plugin_host::boot_system_plugins(&storage, now, books) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {e}");
            return std::process::ExitCode::from(1);
        }
    };

    println!("system plugins (compiled into this binary, running in-process)");
    println!("  storage      {}", storage.display());
    println!(
        "  vendor key   {}…  (ephemeral: generated for this run, never written)",
        &boot.vendor_key_hex[..16]
    );
    println!();

    let declarations = nau_plugins::host::standard_declarations();
    for (name, capabilities) in &declarations {
        let state = boot
            .state(name)
            .map_or_else(|| "unregistered".to_string(), |s| s.label().to_string());
        let mut caps: Vec<&str> = capabilities.iter().map(|c| c.as_str()).collect();
        caps.sort_unstable();
        println!("  {name}");
        println!("      state  {state}");
        println!("      holds  {}", caps.join(", "));
    }
    println!();

    // Call two of them for real. A command that only listed registrations would not
    // distinguish "wired" from "wired and working".
    match boot.call(
        "com.twinsearth.sys.policy",
        "plugin:message:send",
        serde_json::json!({ "op": "matrix" }),
        now,
    ) {
        Ok(answer) => {
            let rows = answer
                .as_object()
                .map(|o| o.len())
                .or_else(|| answer.as_array().map(Vec::len))
                .unwrap_or(0);
            println!("  policy.matrix      answered ({rows} entr(ies))");
        }
        Err(e) => println!("  policy.matrix      REFUSED: {e}"),
    }

    // The capabilities asked for here are deliberately wrong: `kernel:policy:write` is
    // the identity plugin's *neighbour's* capability. The refusal is the point -- it is
    // produced by the token, so it holds regardless of what the plugin itself thinks.
    match boot.call(
        "com.twinsearth.sys.identity",
        "kernel:policy:write",
        serde_json::json!({ "op": "verify" }),
        now,
    ) {
        Ok(_) => {
            println!("  identity.overreach  ACCEPTED — this must never happen");
            return std::process::ExitCode::from(1);
        }
        Err(e) => println!("  identity.overreach  refused: {e}"),
    }

    let logs: usize = boot.names.iter().map(|n| boot.logs(n).len()).sum();
    println!();
    println!("  {logs} log line(s) across {} plugin(s)", boot.len());
    println!();
    println!("Note: these are the plugins compiled into this binary. No downloaded code ran.");
    std::process::ExitCode::SUCCESS
}

/// Whether a path looks like a plugin directory.
#[must_use]
pub fn looks_like_plugin_dir(dir: &Path) -> bool {
    dir.join("plugin.json").is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_flag_forms_are_accepted() {
        let args: Vec<String> = ["--trust=aa", "--trust", "bb", "dir"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(all_values(&args, "--trust"), vec!["aa", "bb"]);
    }

    #[test]
    fn a_flag_without_a_value_does_not_panic() {
        let args: Vec<String> = ["--trust"].iter().map(|s| (*s).to_string()).collect();
        assert!(all_values(&args, "--trust").is_empty());
    }

    #[test]
    fn positional_skips_flags_and_their_values() {
        let args: Vec<String> = ["--trust", "aa", "mydir", "--vendor=bb"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(positional(&args).as_deref(), Some("mydir"));

        let args: Vec<String> = ["mydir", "--trust", "aa"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(positional(&args).as_deref(), Some("mydir"));
    }

    #[test]
    fn no_positional_is_not_an_error() {
        let args: Vec<String> = ["--trust=aa"].iter().map(|s| (*s).to_string()).collect();
        assert!(positional(&args).is_none());
    }

    #[test]
    fn the_matrix_command_covers_every_pair() {
        // The command prints `Capability::ALL x Tier::LOADABLE`; if a variant is added
        // the print loop grows with it, which is the point of generating rather than
        // tabulating.
        //
        // This count is a deliberate tripwire rather than a fact about the CLI: adding a
        // capability must make someone look here and confirm the table test in
        // `nau-plugin` was updated too. It fired when `crypto:channel` was added, and
        // again for A-03's `sandbox:create` / `sandbox:configure`, which is exactly what
        // it is for.
        assert_eq!(Capability::ALL.len(), 19);
        assert_eq!(Tier::LOADABLE.len(), 4);
        assert_eq!(Tier::ALL.len(), 5);
    }

    #[test]
    fn a_directory_without_a_manifest_is_not_a_plugin_directory() {
        let dir = std::env::temp_dir().join("nau-plugin-cli-no-manifest");
        assert!(!looks_like_plugin_dir(&dir));
    }
}
