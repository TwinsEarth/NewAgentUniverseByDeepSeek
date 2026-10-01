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
        "blacklist" => blacklist(&args[1..]),
        "system" => system(&args[1..]),
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
    println!("  blacklist [<file>]    show a signed blacklist, verifying every entry");
    println!("  system                boot the compiled-in T0 plugins and call them");
    println!();
    println!("verify flags:");
    println!("  --trust <hex>         trust a publisher key (repeatable; default trusts nobody)");
    println!("  --vendor <hex>        trust a vendor key that may counter-sign (repeatable)");
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

    let arbiter = Arbiter::new(trust, Blacklist::new())
        .with_runtime(Box::new(NativeRuntime::new()))
        .with_runtime(Box::new(ProcessRuntime::new()))
        .with_runtime(Box::new(WasmRuntime::new()));
    let mut registry = Registry::new();
    let Ok(mut bus) = Bus::new(BusLimits::default()) else {
        eprintln!("error: the bus limits are not usable");
        return std::process::ExitCode::from(2);
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let request = LoadRequest::new(manifest_json, module, entry);

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
            println!();
            println!(
                "Note: this ran every check that can refuse a plugin. The plugin was NOT executed."
            );
            std::process::ExitCode::SUCCESS
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
    let Some(file) = positional(args) else {
        println!("nau plugin blacklist <file>");
        println!();
        println!(
            "Entries must be signed by a trusted vendor key; pass --vendor <hex> to trust one."
        );
        println!("An unsigned or self-signed entry is refused, because a blacklist anyone can");
        println!("append to is a way to ban a competitor.");
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

    let mut boot = match crate::plugin_host::boot_system_plugins(&storage, now) {
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
        assert_eq!(Capability::ALL.len(), 16);
        assert_eq!(Tier::LOADABLE.len(), 4);
        assert_eq!(Tier::ALL.len(), 5);
    }

    #[test]
    fn a_directory_without_a_manifest_is_not_a_plugin_directory() {
        let dir = std::env::temp_dir().join("nau-plugin-cli-no-manifest");
        assert!(!looks_like_plugin_dir(&dir));
    }
}
