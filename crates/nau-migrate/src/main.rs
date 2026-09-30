//! `nau-migrate` — command-line entry point.
//!
//! Argument parsing mirrors `crates/nau-node/src/bin/nau.rs`: a plain
//! `Vec<String>`, `--flag value` or `--flag=value`, and no CLI framework. `clap` is
//! not a dependency of this workspace, and adding one to a migration tool whose
//! premise is a small, auditable dependency tree would be the wrong trade.
//!
//! * `stdout` carries the machine-readable JSON (the plan, or the report).
//! * `stderr` carries the human summary, the findings and the dry-run notice.
//!
//! `apply` is a **dry run unless `--yes` is passed**: without it the plan is applied
//! to an in-memory store, through exactly the same code path, and nothing is
//! written to disk.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;
use std::process::ExitCode;

use nau_migrate::{apply, plan_from_dir, MigrationPlan, MigrationReport, Severity};
use nau_store::{FileStore, MemoryStore};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str).unwrap_or("help") {
        "plan" => command_plan(&args),
        "apply" => command_apply(&args),
        "version" | "--version" | "-V" => {
            print_version();
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command `{other}`");
            eprintln!();
            println!("{HELP}");
            ExitCode::from(2)
        }
    }
}

/// `nau-migrate plan --from <dir> [--strict]`
fn command_plan(args: &[String]) -> ExitCode {
    let Some(from) = arg_value(args, "--from") else {
        return usage("plan requires --from <dir>");
    };
    let plan = match plan_from_dir(Path::new(&from)) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    match serde_json::to_string_pretty(&plan) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("error: the plan could not be serialized: {error}");
            return ExitCode::from(1);
        }
    }
    summarize_plan(&plan, &from);
    finish(&plan, has_flag(args, "--strict"))
}

/// `nau-migrate apply --from <dir> --store <dir> [--yes] [--strict]`
fn command_apply(args: &[String]) -> ExitCode {
    let Some(from) = arg_value(args, "--from") else {
        return usage("apply requires --from <dir>");
    };
    let Some(store_path) = arg_value(args, "--store") else {
        return usage("apply requires --store <dir>");
    };
    let plan = match plan_from_dir(Path::new(&from)) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    summarize_plan(&plan, &from);

    let write = has_flag(args, "--yes");
    let report = if write {
        let mut store = match FileStore::open(&store_path) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("error: cannot open the store at `{store_path}`: {error}");
                return ExitCode::from(1);
            }
        };
        match apply(&plan, &mut store) {
            Ok(report) => report,
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::from(1);
            }
        }
    } else {
        eprintln!(
            "dry run: --yes was not given, so the plan was applied to an in-memory store \
             instead. Nothing was written to `{store_path}`."
        );
        let mut store = MemoryStore::new();
        match apply(&plan, &mut store) {
            Ok(report) => report,
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::from(1);
            }
        }
    };

    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("error: the report could not be serialized: {error}");
            return ExitCode::from(1);
        }
    }
    summarize_report(&report, write);
    finish(&plan, has_flag(args, "--strict"))
}

/// Exit `1` when `--strict` was asked for and something was refused.
fn finish(plan: &MigrationPlan, strict: bool) -> ExitCode {
    let rejected = plan.rejections().count();
    if strict && rejected > 0 {
        eprintln!("strict: {rejected} record(s) were refused; exiting non-zero");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// The human half of `plan`, on stderr so that stdout stays machine-readable.
fn summarize_plan(plan: &MigrationPlan, from: &str) {
    let summary = match plan.summary() {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("error: {error}");
            return;
        }
    };
    eprintln!("source            {from}");
    eprintln!("cards             {}", summary.cards);
    eprintln!("tasks             {}", summary.tasks);
    eprintln!("ledger entries    {}", summary.ledger_entries);
    eprintln!("accounts          {}", summary.accounts);
    eprintln!(
        "moved (exact)     {} NAU ({} minor units)",
        summary.moved.to_decimal_string(),
        summary.moved.minor()
    );
    eprintln!(
        "net movement      {} NAU ({}{} minor units)",
        summary.net.to_decimal_string(),
        if summary.net.is_negative() { "" } else { "+" },
        summary.net.minor()
    );
    eprintln!(
        "findings          {} rejection(s), {} warning(s), {} note(s)",
        summary.rejections, summary.warnings, summary.notes
    );
    print_findings(plan);
}

/// The report, in human form.
fn summarize_report(report: &MigrationReport, wrote: bool) {
    eprintln!(
        "{} cards, {} tasks, {} ledger entries",
        report.cards_imported, report.tasks_imported, report.ledger_entries_imported
    );
    eprintln!(
        "planned           {} cards, {} tasks, {} ledger entries",
        report.cards_planned, report.tasks_planned, report.ledger_entries_planned
    );
    eprintln!(
        "rejected          {} ({} at apply time)",
        report.rejected, report.rejected_at_apply
    );
    eprintln!(
        "findings          {} warning(s), {} note(s)",
        report.warnings, report.notes
    );
    eprintln!(
        "migrated total    {} NAU ({} minor units)",
        report.migrated_total.to_decimal_string(),
        report.migrated_total.minor()
    );
    eprintln!(
        "migrated net      {} NAU ({} minor units)",
        report.migrated_net.to_decimal_string(),
        report.migrated_net.minor()
    );
    eprintln!(
        "conserved exactly {} (net is zero and the re-derived balances sum to it)",
        report.conserved
    );
    if !report.accounts.is_empty() {
        eprintln!("accounts:");
        for balance in &report.accounts {
            eprintln!(
                "  {:<48} {:>18} NAU",
                balance.account,
                balance.derived.to_decimal_string()
            );
        }
    }
    if !wrote {
        eprintln!("nothing was written: this was a dry run (pass --yes to write)");
    }
}

/// Every finding, worst first, so a long migration is still readable in a terminal.
fn print_findings(plan: &MigrationPlan) {
    let mut findings: Vec<&nau_migrate::Warning> = plan.warnings.iter().collect();
    findings.sort_by_key(|warning| std::cmp::Reverse(warning.severity));
    if findings.is_empty() {
        return;
    }
    eprintln!("findings:");
    for warning in findings {
        let marker = match warning.severity {
            Severity::Rejection => "REJECTED",
            Severity::Warning => "warning ",
            Severity::Info => "note    ",
        };
        match &warning.source {
            Some(source) => eprintln!("  {marker} {} [{source}] {}", warning.code, warning.detail),
            None => eprintln!("  {marker} {} {}", warning.code, warning.detail),
        }
    }
}

/// The value of `--name <value>` or `--name=<value>`.
fn arg_value(args: &[String], name: &str) -> Option<String> {
    for (index, arg) in args.iter().enumerate() {
        if arg == name {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

/// True when a bare flag is present.
fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn usage(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    eprintln!();
    eprintln!("{HELP}");
    ExitCode::from(2)
}

fn print_version() {
    println!("nau-migrate   {}", nau_core::VERSION);
    println!("protocol      {}", nau_core::PROTOCOL_VERSION);
    println!(
        "migrates      {} v{} (MIT) JSON/JSONL artifacts",
        nau_core::UPSTREAM_PROJECT,
        nau_core::UPSTREAM_VERSION
    );
    println!("reads         AgentCard JSON, TaskRecord JSON, ledger JSONL (no database reader)");
    println!("converts      decimal text -> Money(i64) minor units, exactly or not at all");
}

const HELP: &str = "\
nau-migrate — migrate upstream agent-universe v2.5.6 historical data

USAGE:
    nau-migrate <COMMAND> [OPTIONS]

COMMANDS:
    plan  --from <DIR> [--strict]
        Read, verify and convert <DIR>, print the plan as JSON on stdout and a
        human summary on stderr. Writes nothing.
    apply --from <DIR> --store <DIR> [--yes] [--strict]
        Apply the plan. Without --yes this is a DRY RUN: the plan is applied to an
        in-memory store through the same code path and nothing is written. With
        --yes the state is written to the store directory (created if needed).
    version | --version | -V
        Print versions and provenance.
    help | --help | -h
        This message.

OPTIONS:
    --from <DIR>     the source tree (see the crate documentation for its layout)
    --store <DIR>    the destination store directory
    --yes            actually write (apply only)
    --strict         exit 1 when any record was refused

SOURCE TREE:
    agents.json | agents/*.json     agent cards (signature over canonical JSON)
    tasks.json  | tasks/*.json      task records
    ledger.jsonl                    one settlement/transfer entry per line
    keys.json                       {\"<did>\": \"<public key hex>\"}   (optional)
    balances.json                   {\"<account>\": <claimed balance>} (optional)

EXIT CODES:
    0  success
    1  error, or --strict with refusals
    2  usage error

EXAMPLES:
    nau-migrate plan  --from ./upstream-export
    nau-migrate plan  --from ./upstream-export --strict
    nau-migrate apply --from ./upstream-export --store ./nau-data
    nau-migrate apply --from ./upstream-export --store ./nau-data --yes
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_found_in_both_spellings() {
        let args: Vec<String> = ["nau-migrate", "plan", "--from", "dir", "--strict=true"]
            .iter()
            .map(|value| (*value).to_string())
            .collect();
        assert_eq!(arg_value(&args, "--from").as_deref(), Some("dir"));
        assert_eq!(arg_value(&args, "--store"), None);
        assert!(has_flag(&args, "--strict=true"));
        assert!(!has_flag(&args, "--strict"));

        let args: Vec<String> = ["nau-migrate", "plan", "--from=dir", "--strict"]
            .iter()
            .map(|value| (*value).to_string())
            .collect();
        assert_eq!(arg_value(&args, "--from").as_deref(), Some("dir"));
        assert!(has_flag(&args, "--strict"));
    }
}
