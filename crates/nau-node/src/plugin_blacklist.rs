//! `nau plugin blacklist …` — the maintainable half of the quarantine.
//!
//! # Why this module exists
//!
//! [`nau_plugin::blacklist`] is already a complete model: entries carry a signature, a
//! reason that distinguishes "this build" (`module_sha256`) from "every build", and an
//! appeal state machine whose terminal stages are `lifted` and `denied`. `Blacklist::add`
//! verifies an entry against a [`TrustStore`]. Nothing drove any of it and nothing
//! persisted it: `nau plugin blacklist <file>` printed a report of somebody else's file,
//! and the compiled-in `sys.blacklist` plugin's `add` is a typed refusal. A blacklist
//! nobody can maintain is a list that goes stale — and the arbiter's load path reads its
//! refusal from this list, so a stale list is worse than none.
//!
//! This module is the driver. It keeps the entries this host accepted in
//! `<dir>/blacklist.json`, the appeal transitions in `<dir>/appeals.json`, and the
//! removals in `<dir>/unblocked.json`.
//!
//! `nau plugin review scan` consults the same file through [`load_verified`], the same
//! function every operation here calls, so the quarantine a review decides against is the
//! quarantine this driver maintains rather than a second list that agrees until it does
//! not.
//!
//! # Integrity is the signature, not the file mode
//!
//! `blacklist.json` holds **signed** entries, and every read runs each entry back through
//! [`Blacklist::add`] with the trust store built from the command line. Nothing is
//! reported — not even a listing — before it verifies. So:
//!
//! * a missing file, or an empty one, is an empty blacklist, because that is what "nothing
//!   is condemned" looks like;
//! * a corrupt file is a typed refusal (`corrupt-blacklist`), never a panic;
//! * a hand-edited entry (a reason escalated from `policy_violation` to `malware`, a
//!   digest re-pointed, a signature pasted from elsewhere) is a typed refusal that **names
//!   the entry that failed** — it can never be read as policy;
//! * an entry whose signer key was not named on the command line is refused rather than
//!   listed, which is the same fail-closed posture as `nau plugin verify`.
//!
//! That is the whole reason the entries are signed: file permissions protect the file,
//! and the signature protects the *decision*, whoever can write the file.
//!
//! # `--trust` here means a vendor key
//!
//! `Blacklist::add` accepts an entry only when
//! `TrustStore::is_trusted_vendor_key` answers true, and `TrustStore::trust_third_party_key`
//! does **not** populate that set — a third-party key can publish plugins, but it cannot
//! condemn one. The task brief assumed a trust store could be built from a key named by
//! `--trust`; it can, but only as a vendor key. So `--vendor <hex>` is the unambiguous
//! spelling and `--trust <hex>` is accepted as an alias for it, with a note on stderr,
//! because silently registering a third-party key would leave every entry refused while
//! looking as if the key had been trusted.
//!
//! # Unblocking is conditional, and the refusal quotes the predicates
//!
//! `unblock` removes an entry only when the appeal on file has reached a terminal stage
//! **and** the entry permits the removal, and the two predicates decide it:
//!
//! * `requires_review_on_republish()` is false for exactly one reason — a revoked publisher
//!   key — because that reason is about the publisher, not the code. For every other reason
//!   the code itself was condemned, so the module's own path back is *a new build that
//!   passes review*, and the pinned entry is the evidence for the condemnation. This driver
//!   does not invent a second policy: it quotes the predicate in the refusal.
//! * `condemns_every_build()` says whether the entry pins one artefact or covers the name.
//!   It is reported, not judged.
//!
//! A refusal also names the step that is still outstanding (the next appeal edge, or the
//! re-published build), so a maintainer is told what to do instead of only that they may
//! not.
//!
//! # What is *not* signed
//!
//! The appeal log and the removal log are local operational records, not signed
//! statements, and this module does not pretend otherwise: an operator with write access
//! can type a `lifted` record. What that cannot do is forge or alter a blacklist *entry*,
//! and the removal log keeps the removed entry verbatim so that lifting a condemnation
//! keeps the evidence for it.
//!
//! # The appeal log is a record, not a lock
//!
//! `appeal` takes the current stage from the command line (`--from`) because that is the
//! shape of the operation the kernel models: [`AppealOutcome::advance`] judges the *edge*
//! it is given, and it stays the only judge of legality here. A caller who names a
//! `--from` the log does not agree with is therefore not refused — teaching the kernel
//! about history is not this driver's business, and a second state machine here would be
//! exactly the disagreeing source of truth the kernel's own comment warns about. What the
//! driver does instead is print the disagreement, so the log says what actually advanced
//! and a mismatch is visible rather than smoothed over.
//!
//! # Exit codes
//!
//! `0` success; `1` typed refusal (printed to stdout — a refusal is the answer, so it goes
//! where the answer goes); `2` a usage error (a missing flag or an unknown stage name,
//! printed to stderr). An illegal appeal transition is reported **as the value
//! [`AppealOutcome`] returned**: `AppealOutcome::advance` is total and never returns `Err`,
//! because "your appeal was refused" is an ordinary answer, and a driver that rewrote it
//! into an error would be a second, disagreeing source of truth about it.

use std::path::Path;

use nau_plugin::blacklist::{AppealOutcome, AppealStage, Blacklist, BlacklistEntry};
use nau_plugin::manifest::TrustStore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The file the maintained blacklist lives in, inside the directory given to `--dir`.
///
/// It is a bare JSON array of [`BlacklistEntry`] — the same shape
/// `nau plugin blacklist <file>` already reads — so a file this command maintains can be
/// handed straight to the older report form without conversion.
const BLACKLIST_FILE: &str = "blacklist.json";

/// The append-only log of appeal transitions, inside the directory given to `--dir`.
const APPEALS_FILE: &str = "appeals.json";

/// The append-only log of removals, inside the directory given to `--dir`.
///
/// Each record keeps the signed entry verbatim, so the one operation that does remove an
/// entry does not erase the evidence that justified it.
const UNBLOCKED_FILE: &str = "unblocked.json";

/// Every operation this module implements, in the order the usage text lists them.
pub const OPERATIONS: [&str; 5] = ["add", "list", "check", "appeal", "unblock"];

/// Whether `word` names a blacklist management operation.
///
/// A host dispatcher can use this to route to [`run`] before falling back to the legacy
/// `nau plugin blacklist <file>` report form, without restating the operation list in a
/// second place.
#[must_use]
pub fn is_operation(word: &str) -> bool {
    OPERATIONS.contains(&word)
}

/// Run one `nau plugin blacklist …` management operation.
///
/// `args` are the words **after** `blacklist`, so `args[0]` is the operation and the rest
/// are its flags. With no operation at all it prints the usage summary, like
/// `nau plugin blacklist` always did.
#[must_use]
pub fn run(args: &[String]) -> std::process::ExitCode {
    let Some(operation) = args.first().map(String::as_str) else {
        return usage();
    };
    match operation {
        "add" => add(&args[1..]),
        "list" => list(&args[1..]),
        "check" => check(&args[1..]),
        "appeal" => appeal(&args[1..]),
        "unblock" => unblock(&args[1..]),
        "help" | "--help" | "-h" => usage(),
        other => {
            eprintln!("error: `{other}` is not a blacklist operation");
            usage();
            // A usage error is not a successful invocation: a typo in a script must not
            // leave a maintainer thinking the list was updated.
            exit_usage()
        }
    }
}

/// Print what the management operations are and which flags each takes.
fn usage() -> std::process::ExitCode {
    println!("nau plugin blacklist — maintain the quarantine");
    println!();
    println!("  add     --dir <d> --entry <signed-entry.json> [--vendor <hex>]…");
    println!("          verify one signed entry, then store it in <d>/blacklist.json");
    println!("  list    --dir <d> [--vendor <hex>]…");
    println!("          re-verify every stored entry and print it");
    println!("  check   --dir <d> --name <n> [--digest <hex>] [--vendor <hex>]…");
    println!("          is this name/artefact condemned? prints the kernel's own refusal");
    println!("  appeal  --dir <d> --name <n> --from <stage> --to <stage> [--reason <text>]");
    println!("          advance the appeal machine, recording the transition");
    println!("  unblock --dir <d> --name <n> [--digest <hex>] [--vendor <hex>]… [--reason <text>]");
    println!("          lift a condemnation, when the appeal is terminal and the entry permits it");
    println!();
    println!("Entries are signed by a trusted vendor key: --vendor <hex> trusts one, and --trust");
    println!("is accepted as an alias because `Blacklist::add` verifies against the vendor set.");
    println!("With no key given, every entry is refused — that is the fail-closed default.");
    println!();
    println!("Appeal stages: appealed, under_review, grey_list, lifted, denied (lifted/denied are final).");
    println!("A missing file is an empty blacklist; a file that does not parse or does not verify");
    println!("is a typed refusal that names the entry, never a list that is quietly trusted.");
    std::process::ExitCode::SUCCESS
}

/// `nau plugin blacklist add --dir <d> --entry <signed-entry.json> [--vendor <hex>]…`
///
/// Deserialises one [`BlacklistEntry`], puts it through [`Blacklist::add`] — signature,
/// signer trust, digest shape, non-zero issue time — and writes `<dir>/blacklist.json`
/// only after that succeeded. Nothing is written for a refused entry, and the existing file
/// is re-verified first, so an append cannot launder a list that was edited by hand.
#[must_use]
pub fn add(args: &[String]) -> std::process::ExitCode {
    let (Some(dir), Some(entry_file)) = (one_value(args, "--dir"), one_value(args, "--entry"))
    else {
        return missing(&["--dir", "--entry"]);
    };
    let dir = crate::expand_home(&dir);
    let entry_path = crate::expand_home(&entry_file);
    let trust = match trust_store(args) {
        Ok(trust) => trust,
        Err(refusal) => return refuse(&refusal),
    };
    if trust.is_empty() {
        return refuse(&Refusal::new(
            "no-trusted-key",
            "no --vendor (or --trust) key was given, so the entry's signature could not be \
             verified against anything: the fail-closed default trusts nobody",
        ));
    }

    let text = match std::fs::read_to_string(&entry_path) {
        Ok(text) => text,
        Err(e) => {
            return refuse(&Refusal::new(
                "unusable-entry",
                format!(
                    "cannot read the signed entry {}: {e}. Nothing was written",
                    entry_path.display()
                ),
            ));
        }
    };
    let entry: BlacklistEntry = match serde_json::from_str(&text) {
        Ok(entry) => entry,
        Err(e) => {
            return refuse(&Refusal::new(
                "unusable-entry",
                format!(
                    "{} is not a signed blacklist entry: {e}. Nothing was written",
                    entry_path.display()
                ),
            ));
        }
    };

    let path = dir.join(BLACKLIST_FILE);
    let (_, mut list) = match load_verified(&path, &trust) {
        Ok(loaded) => loaded,
        Err(refusal) => return refuse(&refusal),
    };
    let name = entry.plugin_name.clone();
    let replaced = list.entry(&name).is_some();
    if let Err(e) = list.add(entry.clone(), &trust) {
        return refuse(&Refusal::new(
            "entry-refused",
            format!("the entry for `{name}` was refused and nothing was written: {e}"),
        ));
    }
    let entries = canonical(&list);
    if let Err(refusal) = write_json(&path, &entries) {
        return refuse(&refusal);
    }

    println!("added `{name}` to {}", path.display());
    if replaced {
        println!("  replaced the previous entry for `{name}`");
    }
    describe_entry(&entry, "  ");
    println!("  {} entr(ies) now in the file", entries.len());
    std::process::ExitCode::SUCCESS
}

/// `nau plugin blacklist list --dir <d> [--vendor <hex>]…`
///
/// Re-verifies every stored entry before printing anything. A file that was edited by hand
/// is therefore reported as the named refusal it is, rather than listed as if it were
/// policy this host had accepted.
#[must_use]
pub fn list(args: &[String]) -> std::process::ExitCode {
    let Some(dir) = one_value(args, "--dir") else {
        return missing(&["--dir"]);
    };
    let dir = crate::expand_home(&dir);
    let trust = match trust_store(args) {
        Ok(trust) => trust,
        Err(refusal) => return refuse(&refusal),
    };
    let path = dir.join(BLACKLIST_FILE);
    let (entries, _) = match load_verified(&path, &trust) {
        Ok(loaded) => loaded,
        Err(refusal) => return refuse(&refusal),
    };
    if entries.is_empty() {
        println!("the blacklist is empty ({})", path.display());
        println!("  a missing file is an empty blacklist, not an error: nothing is condemned");
        return std::process::ExitCode::SUCCESS;
    }

    println!("{} entr(ies) in {}", entries.len(), path.display());
    println!(
        "  every entry verified against the {} trusted key(s) given on the command line",
        trust.len()
    );
    for entry in &entries {
        println!();
        println!("  {}", entry.plugin_name);
        describe_entry(entry, "      ");
    }
    std::process::ExitCode::SUCCESS
}

/// `nau plugin blacklist check --dir <d> --name <n> [--digest <hex>] [--vendor <hex>]…`
///
/// Prints the matching entry and then [`Blacklist::require_allowed`]'s own refusal
/// sentence, verbatim, because that sentence is what the load path would produce. Exit `1`
/// when the artefact is condemned — the refusal is the answer — and `0` when it is not.
#[must_use]
pub fn check(args: &[String]) -> std::process::ExitCode {
    let (Some(dir), Some(name)) = (one_value(args, "--dir"), one_value(args, "--name")) else {
        return missing(&["--dir", "--name"]);
    };
    let dir = crate::expand_home(&dir);
    let digest = one_value(args, "--digest");
    let trust = match trust_store(args) {
        Ok(trust) => trust,
        Err(refusal) => return refuse(&refusal),
    };
    let path = dir.join(BLACKLIST_FILE);
    let (_, blacklist) = match load_verified(&path, &trust) {
        Ok(loaded) => loaded,
        Err(refusal) => return refuse(&refusal),
    };

    match blacklist.check(&name, digest.as_deref()) {
        Some(entry) => {
            match digest.as_deref() {
                Some(d) => println!("condemned: `{name}` at digest {d} is on the blacklist"),
                None => println!(
                    "condemned: `{name}` is on the blacklist with an entry that condemns every build"
                ),
            }
            describe_entry(entry, "  ");
            println!();
            // The kernel's own words. Paraphrasing them here would create a second,
            // disagreeing account of why a load is refused.
            match blacklist.require_allowed(&name, digest.as_deref()) {
                Err(refusal) => println!("refused  {refusal}"),
                Ok(()) => println!(
                    "refused  <the list answered `check` and `require_allowed` differently>"
                ),
            }
            exit_refused()
        }
        None => {
            match blacklist.entry(&name) {
                Some(entry) => {
                    println!("not condemned: an entry for `{name}` exists but does not apply");
                    describe_entry(entry, "  ");
                    match (&entry.module_sha256, digest.as_deref()) {
                        (Some(pinned), Some(d)) => println!(
                            "  the entry pins {pinned}; the digest asked about is {d}, and \
                             `Blacklist::check` condemns only an exact match — a different \
                             build is deliberately not condemned by this entry"
                        ),
                        (Some(pinned), None) => println!(
                            "  the entry pins {pinned} and no --digest was given, so the entry \
                             cannot be shown to apply"
                        ),
                        (None, _) => println!(
                            "  the entry condemns every build, so this branch should be \
                             unreachable: `check` and `entry` answered differently"
                        ),
                    }
                }
                None => println!("not condemned: no entry names `{name}`"),
            }
            println!("  allowed by the blacklist stage of the load pipeline");
            std::process::ExitCode::SUCCESS
        }
    }
}

/// `nau plugin blacklist appeal --dir <d> --name <n> --from <stage> --to <stage> [--reason <text>]`
///
/// Calls [`AppealOutcome::advance`] and records the transition in `<dir>/appeals.json`
/// (the stage moved to, the time, and the reason). An illegal move is reported as the
/// [`AppealOutcome::Refused`] value the kernel returned, with nothing written: an appeal
/// record is a record of a state change, and a refused move changed nothing.
#[must_use]
pub fn appeal(args: &[String]) -> std::process::ExitCode {
    let (Some(dir), Some(name), Some(from_raw), Some(to_raw)) = (
        one_value(args, "--dir"),
        one_value(args, "--name"),
        one_value(args, "--from"),
        one_value(args, "--to"),
    ) else {
        return missing(&["--dir", "--name", "--from", "--to"]);
    };
    let from = match parse_stage(&from_raw) {
        Some(stage) => stage,
        None => return bad_stage("--from", &from_raw),
    };
    let to = match parse_stage(&to_raw) {
        Some(stage) => stage,
        None => return bad_stage("--to", &to_raw),
    };
    let dir = crate::expand_home(&dir);
    let path = dir.join(APPEALS_FILE);
    let reason = one_value(args, "--reason");

    match advance_appeal(&path, &name, from, to, reason, now_seconds()) {
        Ok(AppealReport::Recorded(record)) => {
            println!(
                "appeal for `{name}` advanced: {} -> {}",
                record.from_stage.label(),
                record.stage.label()
            );
            println!("  recorded in {} at {}", path.display(), record.at);
            println!("  reason    {}", record.reason);
            println!(
                "  note      this records the appeal only. The entry is still on the blacklist;"
            );
            println!(
                "            `unblock` removes it, and only when the entry permits the removal."
            );
            std::process::ExitCode::SUCCESS
        }
        Ok(AppealReport::Refused(why)) => {
            // Verbatim, and just a value: `advance` is total and never returns `Err`.
            println!("appeal refused: {why}");
            println!(
                "  that is the `AppealOutcome::Refused` value `AppealOutcome::advance` returned,"
            );
            println!("  not an error in this tool — a refused appeal is an ordinary answer");
            println!("  legal from `{}`: {}", from.label(), legal_next(from));
            println!("  nothing was written to {}", path.display());
            exit_refused()
        }
        Err(refusal) => refuse(&refusal),
    }
}

/// `nau plugin blacklist unblock --dir <d> --name <n> [--digest <hex>] [--vendor <hex>]… [--reason <text>]`
///
/// The one operation that removes an entry. It refuses unless the appeal on file reached a
/// terminal stage that lifted the condemnation **and** the entry's own
/// `requires_review_on_republish()` permits it; the refusal names the predicate's value and
/// the step that is still outstanding. A removal is written to `<dir>/unblocked.json`
/// *before* the blacklist is rewritten, with the removed entry kept verbatim, so an
/// interrupted removal leaves evidence rather than a silent deletion.
#[must_use]
pub fn unblock(args: &[String]) -> std::process::ExitCode {
    let (Some(dir), Some(name)) = (one_value(args, "--dir"), one_value(args, "--name")) else {
        return missing(&["--dir", "--name"]);
    };
    let dir = crate::expand_home(&dir);
    let digest = one_value(args, "--digest");
    let trust = match trust_store(args) {
        Ok(trust) => trust,
        Err(refusal) => return refuse(&refusal),
    };
    let path = dir.join(BLACKLIST_FILE);
    let (entries, blacklist) = match load_verified(&path, &trust) {
        Ok(loaded) => loaded,
        Err(refusal) => return refuse(&refusal),
    };

    let Some(entry) = blacklist.entry(&name) else {
        return refuse(&Refusal::new(
            "not-condemned",
            format!(
                "`{name}` is not on the blacklist ({} holds {} entr(ies)), so there is no \
                 condemnation to lift",
                path.display(),
                entries.len()
            ),
        ));
    };
    if let Some(d) = digest.as_deref() {
        match entry.module_sha256.as_deref() {
            Some(pinned) if pinned != d => {
                return refuse(&Refusal::new(
                    "digest-mismatch",
                    format!(
                        "the entry for `{name}` pins digest {pinned}, not {d}; an unblock names \
                         the exact artefact it lifts"
                    ),
                ));
            }
            Some(_) => {}
            None => println!(
                "note: the entry for `{name}` condemns every build, so --digest {d} does not \
                 narrow it"
            ),
        }
    }

    let appeals_path = dir.join(APPEALS_FILE);
    let records = match read_records::<AppealRecord>(&appeals_path, "appeal") {
        Ok(records) => records,
        Err(refusal) => return refuse(&refusal),
    };
    let stage = latest_stage(&records, &name);
    let (granting_stage, basis) = match unblock_basis(entry, stage) {
        Ok(allowed) => allowed,
        Err(detail) => return refuse(&Refusal::new("unblock-refused", detail)),
    };

    let reason = one_value(args, "--reason").unwrap_or_else(|| "operator unblock".to_string());
    let log_path = dir.join(UNBLOCKED_FILE);
    let mut log = match read_records::<UnblockRecord>(&log_path, "removal") {
        Ok(log) => log,
        Err(refusal) => return refuse(&refusal),
    };
    let record = UnblockRecord {
        plugin_name: name.clone(),
        removed_at: now_seconds(),
        appeal_stage: granting_stage,
        reason,
        basis: basis.clone(),
        entry: entry.clone(),
    };
    log.push(record);
    // Evidence first: if the blacklist rewrite below fails, the log says a removal was
    // attempted and keeps the signed entry, rather than the entry vanishing unrecorded.
    if let Err(refusal) = write_json(&log_path, &log) {
        return refuse(&refusal);
    }
    let remaining: Vec<BlacklistEntry> = entries
        .iter()
        .filter(|candidate| candidate.plugin_name != name)
        .cloned()
        .collect();
    if let Err(refusal) = write_json(&path, &remaining) {
        return refuse(&refusal);
    }

    println!("unblocked `{name}`: removed from {}", path.display());
    println!("  appeal    reached `{}`", granting_stage.label());
    println!("  basis     {basis}");
    println!(
        "  evidence  the signed entry was preserved in {} ({} record(s))",
        log_path.display(),
        log.len()
    );
    println!("  {} entr(ies) remain in the blacklist", remaining.len());
    std::process::ExitCode::SUCCESS
}

/// The answer to an appeal request.
///
/// [`AppealOutcome`] is a *value* in the kernel, not an error, and this type keeps that
/// shape instead of flattening it into one more error path. The string inside
/// [`AppealReport::Refused`] is the kernel's own.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AppealReport {
    /// The kernel advanced the appeal, and the transition is on disk.
    Recorded(AppealRecord),
    /// The kernel refused the move; the string is `AppealOutcome::Refused`'s, verbatim.
    Refused(String),
}

/// One recorded appeal transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AppealRecord {
    /// The plugin the appeal is about.
    plugin_name: String,
    /// The stage the appeal was at before the transition.
    from_stage: AppealStage,
    /// The stage the appeal moved to.
    stage: AppealStage,
    /// When, in Unix seconds.
    at: u64,
    /// Why, as written by the operator (or the edge itself when none was given).
    reason: String,
}

/// One recorded removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnblockRecord {
    /// The plugin the lifted entry named.
    plugin_name: String,
    /// When the entry was removed, in Unix seconds.
    removed_at: u64,
    /// The appeal stage that granted the removal.
    appeal_stage: AppealStage,
    /// Why the removal was asked for, as written by the operator.
    reason: String,
    /// Which predicate values permitted it, quoted from the entry.
    basis: String,
    /// The signed entry, verbatim, so the evidence survives the removal.
    entry: BlacklistEntry,
}

/// A typed refusal: a stable code plus the sentence a person needs.
///
/// `pub(crate)` because this is the one refusal shape a blacklist load can produce, and
/// the review driver runs the same load: if it carried its own error type, the same file
/// could be reported two different ways by two drivers.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    /// A stable machine-readable code, e.g. `corrupt-blacklist`.
    code: &'static str,
    /// What happened, in this tool's own words.
    detail: String,
}

impl Refusal {
    /// Build a refusal.
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// The stable machine-readable code, for a caller that has to name the refusal.
    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    /// The sentence a person needs, for a caller that has to report the refusal.
    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

/// Advance an appeal and, only when the kernel allows it, append the transition.
///
/// The outer `Err` is a broken log or an unwritable file — this tool's own failure. The
/// inner value is the kernel's answer, carried through unchanged.
fn advance_appeal(
    path: &Path,
    name: &str,
    from: AppealStage,
    to: AppealStage,
    reason: Option<String>,
    now: u64,
) -> Result<AppealReport, Refusal> {
    match AppealOutcome::advance(from, to) {
        AppealOutcome::Refused(why) => Ok(AppealReport::Refused(why)),
        AppealOutcome::Advanced(stage) => {
            let mut records = read_records::<AppealRecord>(path, "appeal")?;
            // The kernel judged the edge; the log records what advanced. When the log's
            // last stage for this name disagrees with the `--from` the caller asserted,
            // say so rather than either refusing (a second, invented state machine) or
            // hiding it (a log that quietly disagrees with its own records).
            if let Some(recorded) = latest_stage(&records, name) {
                if recorded != from {
                    println!(
                        "note: the appeal log's last recorded stage for `{name}` is `{}`, but \
                         --from said `{}`; the kernel judges the edge you name, and this log \
                         is the record of what advanced",
                        recorded.label(),
                        from.label()
                    );
                }
            }
            let record = AppealRecord {
                plugin_name: name.to_string(),
                from_stage: from,
                stage,
                at: now,
                reason: reason.unwrap_or_else(|| format!("{} -> {}", from.label(), stage.label())),
            };
            records.push(record.clone());
            write_json(path, &records)?;
            Ok(AppealReport::Recorded(record))
        }
    }
}

/// Whether an entry may be removed, quoting the kernel's predicates.
///
/// Returns the granting stage and the basis sentence on success. On refusal the string
/// names the predicate's value and the outstanding step. The two predicates are the whole
/// policy; no rule is added here that the kernel does not state.
fn unblock_basis(
    entry: &BlacklistEntry,
    stage: Option<AppealStage>,
) -> Result<(AppealStage, String), String> {
    let review = entry.reason.requires_review_on_republish();
    let every = entry.condemns_every_build();
    let Some(stage) = stage else {
        return Err(format!(
            "no appeal is on file for `{}`: the outstanding step is the first appeal \
             transition, `appealed` -> `under_review`, then `grey_list`, then `lifted`. An \
             unblock requires a terminal appeal that lifted the condemnation, and nothing on \
             file is not `lifted`. Record it with `nau plugin blacklist appeal --dir <d> \
             --name {} --from appealed --to under_review`",
            entry.plugin_name, entry.plugin_name
        ));
    };
    if !stage.is_final() {
        return Err(format!(
            "the appeal for `{}` is at `{}`, which is not terminal (the terminal stages are \
             `lifted` and `denied`). The outstanding step is the next appeal edge from `{}`: \
             {}. A recorded appeal is not a removal — `unblock` removes, and only from the \
             stage that lifted the condemnation",
            entry.plugin_name,
            stage.label(),
            stage.label(),
            legal_next(stage)
        ));
    }
    if stage == AppealStage::Denied {
        return Err(format!(
            "the appeal for `{}` ended `denied`, which is terminal but does not lift the \
             condemnation. The outstanding step is a new build that passes review, not a \
             state change",
            entry.plugin_name
        ));
    }
    if review {
        return Err(format!(
            "the appeal for `{}` reached `lifted`, but the entry still does not permit the \
             removal: `requires_review_on_republish()` for reason `{}` is true, so the reason \
             condemns the code rather than the publisher, and new code must be reviewed \
             rather than auto-accepted (`condemns_every_build()` is {}). The outstanding step \
             is a new build that passes review: the entry is evidence, and once a build with \
             a new digest exists, this entry does not condemn it — the kernel's path back is \
             a new build, not a deletion",
            entry.plugin_name,
            entry.reason.label(),
            yes_no(every)
        ));
    }
    Ok((
        stage,
        format!(
            "reason `{}` is the one reason whose `requires_review_on_republish()` is false (a \
             revoked key is about the publisher, not the code), so the entry permits the \
             removal; `condemns_every_build()` is {} and is reported rather than judged",
            entry.reason.label(),
            yes_no(every)
        ),
    ))
}

/// Build the [`TrustStore`] this invocation verifies entries against.
///
/// Only `--vendor` populates the set [`Blacklist::add`] consults. `--trust` is accepted
/// because this command's brief named it, and it is registered as a *vendor* key with a
/// note on stderr — registering it as a third-party key would leave every entry refused
/// while looking as though the key had been trusted.
fn trust_store(args: &[String]) -> Result<TrustStore, Refusal> {
    let mut trust = TrustStore::deny_all();
    for key in all_values(args, "--vendor") {
        if let Err(e) = trust.trust_vendor_key(&key) {
            return Err(Refusal::new(
                "bad-trust-key",
                format!("--vendor {key}: {e}"),
            ));
        }
    }
    let aliased = all_values(args, "--trust");
    if !aliased.is_empty() {
        eprintln!(
            "note: --trust is registered as a vendor key here, because `Blacklist::add` \
             verifies an entry against `TrustStore::is_trusted_vendor_key`, which \
             `trust_third_party_key` does not populate; --vendor says the same thing plainly"
        );
    }
    for key in aliased {
        if let Err(e) = trust.trust_vendor_key(&key) {
            return Err(Refusal::new("bad-trust-key", format!("--trust {key}: {e}")));
        }
    }
    Ok(trust)
}

/// Read the stored blacklist and re-verify every entry against `trust`.
///
/// A missing or empty file is an empty blacklist. Any entry that does not verify is a
/// typed refusal naming it; the verified list and its canonical entry vector are returned
/// together so a caller writes back only what verified.
///
/// `pub(crate)` on purpose: `nau plugin review scan` consults the same quarantine, and it
/// has to reach the *same* verdict this driver does. A second loader would agree today and
/// disagree after the next edit, with nothing to notice it — so there is one loader, and
/// both drivers call it.
pub(crate) fn load_verified(
    path: &Path,
    trust: &TrustStore,
) -> Result<(Vec<BlacklistEntry>, Blacklist), Refusal> {
    let raw = read_blacklist_file(path)?;
    if raw.is_empty() {
        return Ok((Vec::new(), Blacklist::new()));
    }
    if trust.is_empty() {
        return Err(Refusal::new(
            "no-trusted-key",
            format!(
                "{} holds {} entr(ies) and no trusted vendor key was given, so none of them \
                 can be verified. Pass --vendor <hex> (or --trust <hex>); the fail-closed \
                 default trusts nobody, which is a posture and not a bug. An unverified \
                 blacklist is not an empty one",
                path.display(),
                raw.len()
            ),
        ));
    }
    let mut blacklist = Blacklist::new();
    for (index, entry) in raw.iter().enumerate() {
        blacklist.add(entry.clone(), trust).map_err(|e| {
            Refusal::new(
                "entry-refused",
                format!(
                    "{} entry #{} (`{}`) was refused: {e}",
                    path.display(),
                    index + 1,
                    entry.plugin_name
                ),
            )
        })?;
    }
    Ok((canonical(&blacklist), blacklist))
}

/// Read the entries as stored, before any of them is trusted.
fn read_blacklist_file(path: &Path) -> Result<Vec<BlacklistEntry>, Refusal> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(Refusal::new(
                "unreadable-blacklist",
                format!("cannot read {}: {e}", path.display()),
            ));
        }
    };
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<BlacklistEntry>>(&text).map_err(|e| {
        Refusal::new(
            "corrupt-blacklist",
            format!(
                "{} is not a JSON array of signed entries: {e}",
                path.display()
            ),
        )
    })
}

/// Read an append-only JSON log, or an empty log when the file is absent.
fn read_records<T: DeserializeOwned>(path: &Path, what: &str) -> Result<Vec<T>, Refusal> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(Refusal::new(
                "unreadable-log",
                format!("cannot read {}: {e}", path.display()),
            ));
        }
    };
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<T>>(&text).map_err(|e| {
        Refusal::new(
            "corrupt-log",
            format!("{} is not a valid {what} log: {e}", path.display()),
        )
    })
}

/// The entries of a verified list, in name order.
///
/// The kernel keys entries by plugin name, so this is also the deduplication step: what is
/// written back is exactly what [`Blacklist::add`] accepted.
fn canonical(blacklist: &Blacklist) -> Vec<BlacklistEntry> {
    let mut out = Vec::with_capacity(blacklist.len());
    for name in blacklist.names() {
        if let Some(entry) = blacklist.entry(name) {
            out.push(entry.clone());
        }
    }
    out
}

/// Serialise `value` to `path` through a temporary file.
///
/// An interrupted write must not leave a half-written blacklist that the next read would
/// refuse as corrupt: the rename replaces the file or changes nothing.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Refusal> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Refusal::new(
                    "write-failed",
                    format!("cannot create {}: {e}", parent.display()),
                )
            })?;
        }
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| {
        Refusal::new(
            "write-failed",
            format!("cannot encode {}: {e}", path.display()),
        )
    })?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, format!("{text}\n")).map_err(|e| {
        Refusal::new(
            "write-failed",
            format!("cannot write {}: {e}", temporary.display()),
        )
    })?;
    std::fs::rename(&temporary, path).map_err(|e| {
        let _ = std::fs::remove_file(&temporary);
        Refusal::new(
            "write-failed",
            format!("cannot replace {}: {e}", path.display()),
        )
    })
}

/// The last recorded stage for `name`, because the log is append-ordered.
fn latest_stage(records: &[AppealRecord], name: &str) -> Option<AppealStage> {
    records
        .iter()
        .rev()
        .find(|record| record.plugin_name == name)
        .map(|record| record.stage)
}

/// Print one entry's reason, scope, issue time and signer, indented.
fn describe_entry(entry: &BlacklistEntry, indent: &str) {
    println!(
        "{indent}reason    {}  (requires_review_on_republish: {})",
        entry.reason.label(),
        yes_no(entry.reason.requires_review_on_republish())
    );
    println!(
        "{indent}scope     {}  (condemns_every_build: {})",
        match &entry.module_sha256 {
            Some(digest) => format!(
                "pins {digest} — a different build is deliberately not condemned by this entry"
            ),
            None => format!("every build of `{}`", entry.plugin_name),
        },
        yes_no(entry.condemns_every_build())
    );
    println!(
        "{indent}issued    {}  evidence {}",
        entry.blacklisted_at, entry.evidence_cid
    );
    println!("{indent}signer    {}", entry.signer_key);
}

/// `yes`/`no` for a predicate, so a report shows the value rather than an adjective.
fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Parse an appeal stage from its stable label.
fn parse_stage(word: &str) -> Option<AppealStage> {
    AppealStage::ALL
        .into_iter()
        .find(|stage| stage.label() == word)
}

/// The legal next stages from `stage`, as labels, for a refusal that says what is possible.
fn legal_next(stage: AppealStage) -> String {
    let next = stage.next_stages();
    if next.is_empty() {
        "nothing — this stage is final".to_string()
    } else {
        next.iter()
            .map(|stage| stage.label())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Every value given to `--flag`, in order, accepting `--flag v` and `--flag=v`.
fn all_values(args: &[String], flag: &str) -> Vec<String> {
    let prefix = format!("{flag}=");
    let mut out = Vec::new();
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix(&prefix) {
            out.push(value.to_string());
        } else if arg == flag {
            if let Some(value) = args.get(index + 1) {
                out.push(value.clone());
            }
        }
    }
    out
}

/// The first value given to `--flag`, if any.
fn one_value(args: &[String], flag: &str) -> Option<String> {
    all_values(args, flag).into_iter().next()
}

/// The current time in Unix seconds, or `0` if the clock is before the epoch.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Report a typed refusal where an answer goes, and give the refusal exit code.
fn refuse(refusal: &Refusal) -> std::process::ExitCode {
    println!("refused  {}", refusal.code);
    for line in refusal.detail.lines() {
        println!("  {line}");
    }
    exit_refused()
}

/// A usage error: one or more required flags are absent.
fn missing(flags: &[&str]) -> std::process::ExitCode {
    eprintln!("error: missing required flag(s): {}", flags.join(", "));
    eprintln!("  run `nau plugin blacklist help` for each operation's flags");
    exit_usage()
}

/// A usage error: a stage name is not one of [`AppealStage`]'s labels.
fn bad_stage(flag: &str, value: &str) -> std::process::ExitCode {
    let known: Vec<&str> = AppealStage::ALL.iter().map(|stage| stage.label()).collect();
    eprintln!("error: {flag} `{value}` is not an appeal stage");
    eprintln!("  stages: {}", known.join(", "));
    exit_usage()
}

/// Exit code for a typed refusal: the operation ran and refused, with a reason.
fn exit_refused() -> std::process::ExitCode {
    std::process::ExitCode::from(1)
}

/// Exit code for a usage error: a flag or a stage name was wrong.
fn exit_usage() -> std::process::ExitCode {
    std::process::ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::path::PathBuf;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NOW: u64 = 1_750_000_000;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nau-blk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    /// Lower-case hex, so the tests do not depend on a second crate to encode bytes.
    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn vendor() -> (SigningKey, TrustStore) {
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_vendor_key(&to_hex(key.verifying_key().as_bytes()))
            .expect("trust");
        (key, trust)
    }

    fn signed(
        name: &str,
        digest: Option<&str>,
        reason: nau_plugin::blacklist::BlacklistReason,
        key: &SigningKey,
    ) -> BlacklistEntry {
        let mut entry = BlacklistEntry {
            plugin_name: name.to_string(),
            module_sha256: digest.map(str::to_string),
            reason,
            blacklisted_at: NOW,
            evidence_cid: "bafyevidence".to_string(),
            signer_key: to_hex(key.verifying_key().as_bytes()),
            signature: String::new(),
        };
        let signature = key.sign(&entry.signing_bytes());
        entry.signature = to_hex(&signature.to_bytes());
        entry
    }

    fn write_entry_file(dir: &Path, entry: &BlacklistEntry) -> PathBuf {
        let path = dir.join("entry.json");
        std::fs::write(&path, serde_json::to_string(entry).expect("encode entry"))
            .expect("write entry");
        path
    }

    fn trust_keys(key: &SigningKey) -> String {
        to_hex(key.verifying_key().as_bytes())
    }

    #[test]
    fn a_signed_entry_round_trips_through_add_and_list() {
        let dir = scratch("round-trip");
        let (key, _) = vendor();
        let key_hex = trust_keys(&key);
        let entry = signed(
            "io.example.bad",
            Some(DIGEST_A),
            nau_plugin::blacklist::BlacklistReason::Malware,
            &key,
        );
        let entry_file = write_entry_file(&dir, &entry);

        let code = add(&args(&[
            "--dir",
            dir.to_str().expect("utf8"),
            "--entry",
            entry_file.to_str().expect("utf8"),
            "--vendor",
            &key_hex,
        ]));
        assert_eq!(code, std::process::ExitCode::SUCCESS);

        let stored = std::fs::read_to_string(dir.join(BLACKLIST_FILE)).expect("stored file");
        let parsed: Vec<BlacklistEntry> = serde_json::from_str(&stored).expect("parse stored");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].plugin_name, "io.example.bad");
        assert_eq!(parsed[0].module_sha256.as_deref(), Some(DIGEST_A));

        // The stored file is the same array shape the legacy report form reads.
        let code = list(&args(&[
            "--dir",
            dir.to_str().expect("utf8"),
            "--vendor",
            &key_hex,
        ]));
        assert_eq!(code, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn add_refuses_an_entry_signed_by_an_untrusted_key_and_writes_nothing() {
        let dir = scratch("untrusted");
        let (_, trust) = vendor();
        assert!(trust.is_trusted_vendor_key(&trust_keys(&SigningKey::from_bytes(&[42u8; 32]))));
        let rogue = SigningKey::from_bytes(&[7u8; 32]);
        let entry = signed(
            "io.example.rival",
            None,
            nau_plugin::blacklist::BlacklistReason::Malware,
            &rogue,
        );
        let entry_file = write_entry_file(&dir, &entry);

        let code = add(&args(&[
            "--dir",
            dir.to_str().expect("utf8"),
            "--entry",
            entry_file.to_str().expect("utf8"),
            "--vendor",
            &trust_keys(&SigningKey::from_bytes(&[42u8; 32])),
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
        assert!(
            !dir.join(BLACKLIST_FILE).exists(),
            "a refused entry must not be persisted"
        );
    }

    #[test]
    fn add_refuses_a_tampered_field_and_writes_nothing() {
        let dir = scratch("tampered-add");
        let (key, _) = vendor();
        let key_hex = trust_keys(&key);
        let mut entry = signed(
            "io.example.bad",
            Some(DIGEST_A),
            nau_plugin::blacklist::BlacklistReason::PolicyViolation,
            &key,
        );
        // Escalate the reason after signing: the classic forgery the signature stops.
        entry.reason = nau_plugin::blacklist::BlacklistReason::Malware;
        let entry_file = write_entry_file(&dir, &entry);

        let code = add(&args(&[
            "--dir",
            dir.to_str().expect("utf8"),
            "--entry",
            entry_file.to_str().expect("utf8"),
            "--vendor",
            &key_hex,
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
        assert!(!dir.join(BLACKLIST_FILE).exists());
    }

    #[test]
    fn a_hand_edited_blacklist_is_refused_and_names_the_entry() {
        let dir = scratch("hand-edited");
        let (key, trust) = vendor();
        let entry = signed(
            "io.example.bad",
            Some(DIGEST_A),
            nau_plugin::blacklist::BlacklistReason::Malware,
            &key,
        );
        let path = dir.join(BLACKLIST_FILE);
        let mut edited = entry.clone();
        edited.evidence_cid = "bafyforged".to_string();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&vec![edited]).expect("encode"),
        )
        .expect("write");

        let refusal = load_verified(&path, &trust).expect_err("must refuse");
        assert_eq!(refusal.code, "entry-refused");
        assert!(
            refusal.detail.contains("io.example.bad"),
            "the refusal must name the entry: {}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("does not verify"),
            "the refusal must name the cause: {}",
            refusal.detail
        );

        let code = list(&args(&[
            "--dir",
            dir.to_str().expect("utf8"),
            "--vendor",
            &trust_keys(&key),
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn add_re_verifies_the_existing_file_before_appending() {
        let dir = scratch("append-onto-dirty");
        let (key, _) = vendor();
        let key_hex = trust_keys(&key);
        let good = signed(
            "io.example.good",
            Some(DIGEST_B),
            nau_plugin::blacklist::BlacklistReason::CommunityReport,
            &key,
        );
        let mut dirty = signed(
            "io.example.bad",
            Some(DIGEST_A),
            nau_plugin::blacklist::BlacklistReason::Malware,
            &key,
        );
        dirty.blacklisted_at = 1; // edited after signing
        let path = dir.join(BLACKLIST_FILE);
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&vec![dirty]).expect("encode"),
        )
        .expect("write dirty list");

        let entry_file = write_entry_file(&dir, &good);
        let code = add(&args(&[
            "--dir",
            dir.to_str().expect("utf8"),
            "--entry",
            entry_file.to_str().expect("utf8"),
            "--vendor",
            &key_hex,
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
        let after = std::fs::read_to_string(&path).expect("file still there");
        assert!(
            !after.contains("io.example.good"),
            "nothing may be appended onto an unverified file"
        );
    }

    #[test]
    fn a_corrupt_file_is_a_typed_refusal_not_a_panic() {
        let dir = scratch("corrupt");
        let (_, trust) = vendor();
        let path = dir.join(BLACKLIST_FILE);
        std::fs::write(&path, "{ this is not json").expect("write");

        let refusal = load_verified(&path, &trust).expect_err("must refuse");
        assert_eq!(refusal.code, "corrupt-blacklist");

        // A well-formed array of the wrong shape is refused too, rather than skipped.
        std::fs::write(&path, "[{\"plugin_name\":\"x\"}]").expect("write");
        let refusal = load_verified(&path, &trust).expect_err("must refuse");
        assert_eq!(refusal.code, "corrupt-blacklist");
    }

    #[test]
    fn a_missing_file_is_an_empty_blacklist() {
        let dir = scratch("missing");
        let path = dir.join(BLACKLIST_FILE);
        let (entries, blacklist) =
            load_verified(&path, &TrustStore::deny_all()).expect("missing is empty");
        assert!(entries.is_empty());
        assert!(blacklist.is_empty());

        let code = list(&args(&["--dir", dir.to_str().expect("utf8")]));
        assert_eq!(code, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn entries_that_cannot_be_verified_are_refused_rather_than_listed() {
        let dir = scratch("no-key");
        let (key, _) = vendor();
        let entry = signed(
            "io.example.bad",
            Some(DIGEST_A),
            nau_plugin::blacklist::BlacklistReason::Malware,
            &key,
        );
        let path = dir.join(BLACKLIST_FILE);
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&vec![entry]).expect("encode"),
        )
        .expect("write");

        let refusal = load_verified(&path, &TrustStore::deny_all()).expect_err("must refuse");
        assert_eq!(refusal.code, "no-trusted-key");

        let code = list(&args(&["--dir", dir.to_str().expect("utf8")]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn an_illegal_appeal_edge_is_carried_as_the_kernel_value() {
        let dir = scratch("illegal-edge");
        let path = dir.join(APPEALS_FILE);
        let report = advance_appeal(
            &path,
            "io.example.bad",
            AppealStage::Appealed,
            AppealStage::Lifted,
            None,
            NOW,
        )
        .expect("a broken log is not the expected answer");

        assert_eq!(
            report,
            AppealReport::Refused("appealed -> lifted is not an appeal edge".to_string())
        );
        assert!(!path.exists(), "a refused appeal changed nothing");

        let code = appeal(&args(&[
            "--dir",
            dir.to_str().expect("utf8"),
            "--name",
            "io.example.bad",
            "--from",
            "appealed",
            "--to",
            "lifted",
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
        assert!(!path.exists());
    }

    #[test]
    fn a_legal_appeal_is_recorded_with_its_stage_time_and_reason() {
        let dir = scratch("appeal-log");
        let dir_arg = dir.to_str().expect("utf8").to_string();
        let code = appeal(&args(&[
            "--dir",
            &dir_arg,
            "--name",
            "io.example.bad",
            "--from",
            "appealed",
            "--to",
            "under_review",
            "--reason",
            "publisher asked for a review",
        ]));
        assert_eq!(code, std::process::ExitCode::SUCCESS);

        let text = std::fs::read_to_string(dir.join(APPEALS_FILE)).expect("log written");
        let records: Vec<AppealRecord> = serde_json::from_str(&text).expect("parse log");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].plugin_name, "io.example.bad");
        assert_eq!(records[0].from_stage, AppealStage::Appealed);
        assert_eq!(records[0].stage, AppealStage::UnderReview);
        assert_eq!(records[0].reason, "publisher asked for a review");
        assert!(records[0].at >= NOW, "the record carries a real time");

        // Skipping a stage is refused and appends nothing.
        let code = appeal(&args(&[
            "--dir",
            &dir_arg,
            "--name",
            "io.example.bad",
            "--from",
            "appealed",
            "--to",
            "lifted",
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
        let records: Vec<AppealRecord> =
            serde_json::from_str(&std::fs::read_to_string(dir.join(APPEALS_FILE)).expect("log"))
                .expect("parse log");
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn an_appeal_from_a_stage_the_log_disagrees_with_is_recorded_not_refused() {
        // `--from` is the caller's assertion about the current stage and the kernel judges
        // the edge it is given; the driver prints the disagreement and keeps the record of
        // what actually advanced instead of inventing a second state machine.
        let dir = scratch("appeal-mismatch");
        let dir_arg = dir.to_str().expect("utf8").to_string();
        assert_eq!(
            appeal(&args(&[
                "--dir",
                &dir_arg,
                "--name",
                "io.example.bad",
                "--from",
                "appealed",
                "--to",
                "under_review",
            ])),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            appeal(&args(&[
                "--dir",
                &dir_arg,
                "--name",
                "io.example.bad",
                "--from",
                "grey_list",
                "--to",
                "lifted",
            ])),
            std::process::ExitCode::SUCCESS,
            "the kernel's edge is legal, so the driver does not overrule it"
        );
        let records: Vec<AppealRecord> =
            serde_json::from_str(&std::fs::read_to_string(dir.join(APPEALS_FILE)).expect("log"))
                .expect("parse log");
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].from_stage, AppealStage::GreyList);
        assert_eq!(records[1].stage, AppealStage::Lifted);
        assert_eq!(
            latest_stage(&records, "io.example.bad"),
            Some(AppealStage::Lifted)
        );
    }

    #[test]
    fn unblock_needs_a_terminal_lifted_appeal() {
        use nau_plugin::blacklist::BlacklistReason;
        let (key, _) = vendor();
        let revoked = signed(
            "io.example.revoked",
            None,
            BlacklistReason::KeyRevoked,
            &key,
        );
        let malware = signed(
            "io.example.bad",
            Some(DIGEST_A),
            BlacklistReason::Malware,
            &key,
        );

        let Err(no_appeal) = unblock_basis(&revoked, None) else {
            panic!("no appeal must not permit an unblock");
        };
        assert!(no_appeal.contains("no appeal is on file"), "{no_appeal}");

        let Err(outstanding) = unblock_basis(&revoked, Some(AppealStage::UnderReview)) else {
            panic!("a non-terminal appeal must not permit an unblock");
        };
        assert!(outstanding.contains("not terminal"), "{outstanding}");
        assert!(outstanding.contains("grey_list"), "{outstanding}");

        let Err(denied) = unblock_basis(&revoked, Some(AppealStage::Denied)) else {
            panic!("a denied appeal must not permit an unblock");
        };
        assert!(denied.contains("denied"), "{denied}");

        let Ok((stage, basis)) = unblock_basis(&revoked, Some(AppealStage::Lifted)) else {
            panic!("a lifted appeal on a key revocation permits the removal");
        };
        assert_eq!(stage, AppealStage::Lifted);
        assert!(
            basis.contains("requires_review_on_republish()` is false"),
            "{basis}"
        );
        assert!(basis.contains("condemns_every_build()` is yes"), "{basis}");

        let Err(needs_review) = unblock_basis(&malware, Some(AppealStage::Lifted)) else {
            panic!("a reason that requires re-review must not permit the removal");
        };
        assert!(
            needs_review.contains("requires_review_on_republish()` for reason `malware` is true"),
            "{needs_review}"
        );
        assert!(
            needs_review.contains("condemns_every_build()` is no"),
            "{needs_review}"
        );
        assert!(needs_review.contains("new build"), "{needs_review}");
    }

    #[test]
    fn unblock_removes_a_revoked_key_entry_and_keeps_the_evidence() {
        use nau_plugin::blacklist::BlacklistReason;
        let dir = scratch("unblock");
        let dir_arg = dir.to_str().expect("utf8").to_string();
        let (key, _) = vendor();
        let key_hex = trust_keys(&key);
        let entry = signed(
            "io.example.revoked",
            None,
            BlacklistReason::KeyRevoked,
            &key,
        );
        let entry_file = write_entry_file(&dir, &entry);
        assert_eq!(
            add(&args(&[
                "--dir",
                &dir_arg,
                "--entry",
                entry_file.to_str().expect("utf8"),
                "--vendor",
                &key_hex,
            ])),
            std::process::ExitCode::SUCCESS
        );

        // Walk the appeal machine to its granting terminal stage, one edge at a time.
        for (from, to) in [
            ("appealed", "under_review"),
            ("under_review", "grey_list"),
            ("grey_list", "lifted"),
        ] {
            assert_eq!(
                appeal(&args(&[
                    "--dir",
                    &dir_arg,
                    "--name",
                    "io.example.revoked",
                    "--from",
                    from,
                    "--to",
                    to,
                ])),
                std::process::ExitCode::SUCCESS
            );
        }

        let code = unblock(&args(&[
            "--dir",
            &dir_arg,
            "--name",
            "io.example.revoked",
            "--vendor",
            &key_hex,
            "--reason",
            "the publisher key was restored",
        ]));
        assert_eq!(code, std::process::ExitCode::SUCCESS);

        let remaining: Vec<BlacklistEntry> = serde_json::from_str(
            &std::fs::read_to_string(dir.join(BLACKLIST_FILE)).expect("list file"),
        )
        .expect("parse list");
        assert!(
            remaining.is_empty(),
            "the entry is gone from the active list"
        );

        // The removal log keeps the signed entry and the basis, so the evidence survives.
        let log: Vec<UnblockRecord> = serde_json::from_str(
            &std::fs::read_to_string(dir.join(UNBLOCKED_FILE)).expect("log file"),
        )
        .expect("parse log");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].entry.signature, entry.signature);
        assert_eq!(log[0].appeal_stage, AppealStage::Lifted);
        assert_eq!(log[0].reason, "the publisher key was restored");

        // A second unblock has nothing to lift.
        let code = unblock(&args(&[
            "--dir",
            &dir_arg,
            "--name",
            "io.example.revoked",
            "--vendor",
            &key_hex,
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn unblock_refuses_an_entry_whose_reason_requires_review() {
        use nau_plugin::blacklist::BlacklistReason;
        let dir = scratch("unblock-refused");
        let dir_arg = dir.to_str().expect("utf8").to_string();
        let (key, _) = vendor();
        let key_hex = trust_keys(&key);
        let entry = signed(
            "io.example.bad",
            Some(DIGEST_A),
            BlacklistReason::Malware,
            &key,
        );
        let entry_file = write_entry_file(&dir, &entry);
        assert_eq!(
            add(&args(&[
                "--dir",
                &dir_arg,
                "--entry",
                entry_file.to_str().expect("utf8"),
                "--vendor",
                &key_hex,
            ])),
            std::process::ExitCode::SUCCESS
        );
        for (from, to) in [
            ("appealed", "under_review"),
            ("under_review", "grey_list"),
            ("grey_list", "lifted"),
        ] {
            assert_eq!(
                appeal(&args(&[
                    "--dir",
                    &dir_arg,
                    "--name",
                    "io.example.bad",
                    "--from",
                    from,
                    "--to",
                    to,
                ])),
                std::process::ExitCode::SUCCESS
            );
        }

        let code = unblock(&args(&[
            "--dir",
            &dir_arg,
            "--name",
            "io.example.bad",
            "--vendor",
            &key_hex,
        ]));
        assert_ne!(code, std::process::ExitCode::SUCCESS);
        let kept: Vec<BlacklistEntry> = serde_json::from_str(
            &std::fs::read_to_string(dir.join(BLACKLIST_FILE)).expect("list file"),
        )
        .expect("parse list");
        assert_eq!(kept.len(), 1, "the entry is the evidence and must stay");
        assert!(!dir.join(UNBLOCKED_FILE).exists());
    }

    #[test]
    fn check_reports_the_kernel_refusal_and_a_pinned_entry_does_not_match_another_digest() {
        let dir = scratch("check");
        let dir_arg = dir.to_str().expect("utf8").to_string();
        let (key, _) = vendor();
        let key_hex = trust_keys(&key);
        let entry = signed(
            "io.example.bad",
            Some(DIGEST_A),
            nau_plugin::blacklist::BlacklistReason::Malware,
            &key,
        );
        let entry_file = write_entry_file(&dir, &entry);
        assert_eq!(
            add(&args(&[
                "--dir",
                &dir_arg,
                "--entry",
                entry_file.to_str().expect("utf8"),
                "--vendor",
                &key_hex,
            ])),
            std::process::ExitCode::SUCCESS
        );

        assert_ne!(
            check(&args(&[
                "--dir",
                &dir_arg,
                "--name",
                "io.example.bad",
                "--digest",
                DIGEST_A,
                "--vendor",
                &key_hex,
            ])),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            check(&args(&[
                "--dir",
                &dir_arg,
                "--name",
                "io.example.bad",
                "--digest",
                DIGEST_B,
                "--vendor",
                &key_hex,
            ])),
            std::process::ExitCode::SUCCESS,
            "a pinned entry does not condemn a different build"
        );
        assert_eq!(
            check(&args(&[
                "--dir",
                &dir_arg,
                "--name",
                "io.example.other",
                "--vendor",
                &key_hex,
            ])),
            std::process::ExitCode::SUCCESS
        );
    }

    #[test]
    fn unknown_flags_and_stages_are_usage_errors() {
        let dir = scratch("usage");
        let dir_arg = dir.to_str().expect("utf8").to_string();
        assert_eq!(
            appeal(&args(&[
                "--dir", &dir_arg, "--name", "x", "--from", "appealed", "--to", "greylist",
            ])),
            std::process::ExitCode::from(2)
        );
        assert_eq!(
            appeal(&args(&["--dir", &dir_arg, "--name", "x"])),
            std::process::ExitCode::from(2)
        );
        assert_eq!(run(&args(&["nonsense"])), std::process::ExitCode::from(2));
        assert!(is_operation("unblock"));
        assert!(!is_operation("nonsense"));
    }
}
