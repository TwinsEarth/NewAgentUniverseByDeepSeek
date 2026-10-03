//! `nau plugin review …` — driving the third-party registration and review process.
//!
//! # Why this module exists
//!
//! `nau_plugin::certify` *models* the process: a six-stage state machine, a scan report
//! with findings, and a certification whose scope is the control. Nothing drove it.
//! `nau plugin` exposed `tiers`, `runtimes`, `verify`, `blacklist` and `system`, and the
//! review machine was reachable only from Rust — which makes it a data structure, not a
//! process, and makes `docs/PLUGIN-MIGRATION.md` correct when it records it that way.
//! This module is the driver.
//!
//! # "Passes review" has to mean "can be loaded"
//!
//! Scanning does not invent a friendlier set of checks. It runs the per-capability
//! decisions the tier matrix makes, the manifest validation, the signature and module
//! digest checks — and then it runs **the load pipeline itself**: the same
//! [`Arbiter`], with the same runtimes and the same shipped ABI adapters that
//! `nau plugin verify` uses, over the same manifest document, module bytes and entry
//! path. A review that approved a plugin the arbiter then refused would be worse than no
//! review, because it would be a review people trust. Each pipeline stage is recorded as
//! its own check, so a blocker names the stage that produced it.
//!
//! The one check a review cannot decide is the operator's trust store: a third-party
//! manifest is refused at load until the operator lists its publisher key. The scan
//! therefore runs the pipeline with the manifest's declared publisher key trusted —
//! which is exactly the admission decision the review is making — and records that
//! assumption as a `Note` naming the key that has to be added. Nothing in `nau-plugin`
//! binds the DID in `plugin.publisher` to the key in `signature.publisher_key`; that
//! binding is established out of band, and the scan says so rather than implying it was
//! checked.
//!
//! # The quarantine is consulted, and an absent file is not a skipped check
//!
//! A real host's load pipeline refuses a **blacklisted** plugin before it verifies
//! anything, so a scan that ran against an empty list would approve a plugin the load
//! pipeline refuses — the same failure this module exists to prevent, one stage earlier.
//! So the scan loads `<dir>/blacklist.json` (the file `nau plugin blacklist` maintains)
//! through `plugin_blacklist::load_verified`, the *same* function every blacklist
//! operation calls: every stored entry goes back through the kernel's own
//! `Blacklist::add` — signatures and all, because the entries are signed and a hand-edited
//! file has to be a typed refusal that names the entry rather than a list that is quietly
//! trusted — and the verified list is handed to the arbiter, which then runs the blacklist
//! stage of the load with its own refusal text. Nothing here composes a blacklist verdict,
//! and nothing here is a second loader: two loaders that agree today are two loaders that
//! disagree after the next edit, with nothing to notice it.
//!
//! The report always says which file was consulted and how many entries it held, with the
//! absent case spelled out. "No entries" and "not consulted" look identical in a report,
//! and that ambiguity is the defect this section exists to close.
//!
//! `--vendor <hex>` is how those entries are verified, because `Blacklist::add` accepts an
//! entry only from a **vendor** key. `--trust` is deliberately not accepted for this: in
//! `nau plugin verify` it names a third-party *publisher* key, and one flag carrying two
//! different trust sets in one command is how a key ends up trusted for something its
//! holder was never trusted to do.
//!
//! # The journal is an event log, and the state machine stays the authority
//!
//! `<dir>/review-journal.json` holds the event sequence, never a serialised [`Review`].
//! Every command replays the whole log through `Review`'s and `Certification`'s own
//! methods and then appends one event. A journal a human has edited into an illegal
//! history — a skipped stage, a scan after a decision, a second certification — is
//! therefore refused *by the machine*, in an error naming the event that is illegal,
//! rather than accepted because a snapshot happened to deserialise. A malformed journal
//! is the same kind of typed refusal, not a panic.
//!
//! Three rules are this driver's rather than the kernel's, and they are applied
//! identically when an event is written and when one is replayed:
//!
//! * a scan is only recorded while a decision is still possible;
//! * a review cannot leave `auto_scanned` without a scan — the kernel lets that edge
//!   through, and a review that advanced past its own checks would be a rubber stamp;
//! * a review issues at most one certification, and only over a blocker-free scan.
//!
//! # What this cannot do from a CLI process
//!
//! [`load`](nau_plugin::arbiter::Arbiter::load) is run to the point where a runtime has
//! been started; no plugin code is executed, exactly as `nau plugin verify` says of
//! itself. The daemon that owns a data directory and an executor is still the only thing
//! that runs a plugin.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nau_plugin::arbiter::{Arbiter, LoadRequest};
use nau_plugin::blacklist::{Blacklist, BlacklistEntry};
use nau_plugin::bus::{Bus, BusLimits};
use nau_plugin::capability::{Approval, Capability, Grant};
use nau_plugin::certify::{Certification, Finding, Review, ReviewStage, ScanReport};
use nau_plugin::hot::AdapterRegistry;
use nau_plugin::manifest::{Manifest, TrustStore};
use nau_plugin::registry::Registry;
use nau_plugin::runtime::{NativeRuntime, ProcessRuntime, WasmRuntime};
use nau_plugin::tier::Tier;
use serde::{Deserialize, Serialize};

/// The review's journal file, inside the review directory.
const JOURNAL_FILE: &str = "review-journal.json";

/// The journal format this build writes and reads.
///
/// A version rather than an implicit format: a journal is durable state that outlives
/// the process that wrote it, so a reader has to be able to say "this is not mine"
/// instead of guessing.
const JOURNAL_VERSION: u32 = 1;

/// The maintained blacklist, inside the review directory.
///
/// The same file `nau plugin blacklist --dir <d> …` writes, so the quarantine the scan
/// consults is the quarantine the host maintains, not a second list.
const BLACKLIST_FILE: &str = "blacklist.json";

/// Run a `plugin review …` subcommand. `args` excludes the `plugin review` words.
#[must_use]
pub fn run(args: &[String]) -> ExitCode {
    let Some(command) = args.first().map(String::as_str) else {
        return usage();
    };
    match command {
        "open" => finish(open(&args[1..])),
        "scan" => finish(scan(&args[1..])),
        "advance" => finish(advance(&args[1..])),
        "show" => finish(show(&args[1..])),
        "certify" => finish(certify(&args[1..])),
        "help" | "--help" | "-h" => usage(),
        other => {
            eprintln!("error: `{other}` is not a `plugin review` subcommand");
            usage();
            // Usage errors exit 2, the same as the rest of `nau plugin`: a typo inside a
            // script must not read as a successful invocation.
            ExitCode::from(2)
        }
    }
}

/// Turn a command's outcome into an exit code and a readable refusal.
fn finish(result: Result<(), Refusal>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(refusal) => {
            refusal.report();
            refusal.exit_code()
        }
    }
}

/// Print the usage summary.
fn usage() -> ExitCode {
    println!("nau plugin review — the third-party registration and review process");
    println!();
    println!("  open    --dir <d> --manifest <path> --publisher <did> [--at <ts>]");
    println!("  scan    --dir <d> --manifest <path> [--vendor <hex>]…");
    println!("  advance --dir <d> --to <stage> --because <text> [--at <ts>]");
    println!("  show    --dir <d>");
    println!("  certify --dir <d> --scope <cap,cap> --vendor-key <hex> [--at <ts>]");
    println!();
    println!("`scan` consults <d>/blacklist.json, re-verifying every stored entry against the");
    println!("vendor keys given with --vendor; a missing file is an empty blacklist, and the");
    println!("report says which file was consulted either way.");
    println!();
    println!("The review is a replayable event log at <d>/review-journal.json. Every command");
    println!("replays it through the kernel's own state machine and appends one event, so a");
    println!("journal a human edited into an illegal history is refused by that machine, by name.");
    println!();
    println!("stages: {}", stage_list());
    println!();
    println!("`scan` runs the same checks the load pipeline runs, the arbiter included, so");
    println!("\"no blocker\" means the plugin is loadable rather than merely reviewed.");
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a `plugin review` command stopped.
///
/// A refusal is an answer, not a crash: each variant carries the one clause a person
/// needs in order to change something and try again.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// The invocation was malformed: a missing flag, an unknown stage, a bad key.
    Usage(String),
    /// The journal is absent, unreadable, malformed, or records a history the kernel's
    /// state machine refuses.
    Journal(String),
    /// The kernel refused the operation.
    Kernel(String),
    /// The filesystem refused.
    Io(String),
    /// The maintained blacklist is unreadable, corrupt, unverifiable, or holds entries
    /// nobody on the command line is trusted to have signed.
    ///
    /// The code and the detail are `plugin_blacklist`'s own, carried through unchanged, so
    /// that this driver and the quarantine driver report one file the same way.
    Blacklist {
        /// The shared loader's stable machine-readable code (`corrupt-blacklist`,
        /// `entry-refused`, `no-trusted-key`, …).
        code: &'static str,
        /// The shared loader's sentence, including the entry number when one was refused.
        detail: String,
    },
    /// The automatic scan reported a blocker, so the submission does not pass.
    Blocked(String),
}

impl Refusal {
    /// A stable machine-readable kind.
    fn kind(&self) -> &'static str {
        match self {
            Refusal::Usage(_) => "usage",
            Refusal::Journal(_) => "journal_refused",
            Refusal::Kernel(_) => "kernel_refused",
            Refusal::Io(_) => "io_refused",
            // The blacklist loader's own code, so `nau plugin review scan` and
            // `nau plugin blacklist check` name the same refusal the same way.
            Refusal::Blacklist { code, .. } => code,
            Refusal::Blocked(_) => "scan_blocked",
        }
    }

    /// The one-clause explanation.
    fn detail(&self) -> &str {
        match self {
            Refusal::Usage(d)
            | Refusal::Journal(d)
            | Refusal::Kernel(d)
            | Refusal::Io(d)
            | Refusal::Blocked(d) => d,
            Refusal::Blacklist { detail, .. } => detail,
        }
    }

    /// Print it in the shape the other `nau` refusals use.
    fn report(&self) {
        eprintln!("REFUSED  {}", self.kind());
        eprintln!("  {}", self.detail());
    }

    /// `2` for a malformed invocation, `1` for a refusal that is an answer.
    fn exit_code(&self) -> ExitCode {
        match self {
            Refusal::Usage(_) => ExitCode::from(2),
            _ => ExitCode::from(1),
        }
    }
}

// ---------------------------------------------------------------------------
// The journal: an append-only event log, replayed through the kernel
// ---------------------------------------------------------------------------

/// The journal document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    /// The format version; a mismatch is a typed refusal, not a best-effort read.
    version: u32,
    /// The events, oldest first. The first is always `submitted`.
    events: Vec<JournalEvent>,
}

/// One event in a review's history.
///
/// Deliberately *not* a serialised [`Review`]: replaying events through the kernel's own
/// methods is what makes a hand-edited history fail to load instead of loading
/// successfully with a stage nobody transitioned to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JournalEvent {
    /// A publisher submitted a manifest. Always the first event.
    Submitted {
        /// The plugin name, as the manifest signed it.
        plugin: String,
        /// The publisher's DID.
        publisher: String,
        /// When the submission was accepted.
        at: u64,
        /// The manifest digest at submission time, so drift after `open` is visible.
        /// `#[serde(default)]` only so a hand-kept journal without it still replays; the
        /// scan records a `Note` when it is absent rather than pretending it matched.
        #[serde(default)]
        manifest_digest: String,
    },
    /// An automatic scan, with every check it ran.
    Scanned {
        /// The report, recomputed from scratch at scan time and never edited after.
        report: ScanReport,
    },
    /// One legal transition, with the reason it was taken.
    Advanced {
        /// The stage moved to.
        to: ReviewStage,
        /// Why, in the operator's words.
        because: String,
        /// When.
        at: u64,
    },
    /// A certification issued from a review that reached `certified`.
    Certified {
        /// The capability scope the review approved, as wire names.
        scope: Vec<String>,
        /// The vendor key the certification is attributed to.
        vendor_key: String,
        /// When.
        at: u64,
    },
}

impl JournalEvent {
    /// A stable label, for naming the event in a refusal.
    fn kind(&self) -> &'static str {
        match self {
            JournalEvent::Submitted { .. } => "submitted",
            JournalEvent::Scanned { .. } => "scanned",
            JournalEvent::Advanced { .. } => "advanced",
            JournalEvent::Certified { .. } => "certified",
        }
    }
}

/// Kernel state rebuilt by replaying a journal.
#[derive(Debug)]
struct Replayed {
    /// The review, rebuilt through [`Review`]'s own methods.
    review: Review,
    /// The certification the journal records, if any.
    certification: Option<Certification>,
}

/// The journal path inside a review directory.
fn journal_path(dir: &Path) -> PathBuf {
    dir.join(JOURNAL_FILE)
}

/// Read and parse a journal.
///
/// Every failure here — missing file, invalid JSON, unknown version — is a typed
/// refusal. A journal is durable state a human can edit, so none of these may be a
/// panic and none may be silently tolerated.
fn read_journal(dir: &Path) -> Result<Journal, Refusal> {
    let path = journal_path(dir);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Refusal::Journal(format!("cannot read {}: {e}", path.display())))?;
    let journal: Journal = serde_json::from_str(&text).map_err(|e| {
        Refusal::Journal(format!("{} is not a review journal: {e}", path.display()))
    })?;
    if journal.version != JOURNAL_VERSION {
        return Err(Refusal::Journal(format!(
            "{} records journal version {}, and this build reads version {JOURNAL_VERSION}",
            path.display(),
            journal.version
        )));
    }
    Ok(journal)
}

/// Write a journal, creating the review directory if it is missing.
fn write_journal(dir: &Path, journal: &Journal) -> Result<(), Refusal> {
    std::fs::create_dir_all(dir)
        .map_err(|e| Refusal::Io(format!("cannot create {}: {e}", dir.display())))?;
    let text = serde_json::to_string_pretty(journal)
        .map_err(|e| Refusal::Journal(format!("cannot serialise the journal: {e}")))?;
    let path = journal_path(dir);
    std::fs::write(&path, text)
        .map_err(|e| Refusal::Io(format!("cannot write {}: {e}", path.display())))
}

/// Replay a journal into kernel state.
///
/// The kernel decides every event: `Review::open`, `record_scan`, `advance` and
/// `Certification::issue` all refuse an illegal history themselves, and their errors are
/// wrapped so the refusal names the event that is illegal. The three process rules the
/// kernel does not have are checked here, and the same checks run when an event is
/// written, so nothing can be written that will not replay.
fn replay(journal: &Journal) -> Result<Replayed, Refusal> {
    let mut events = journal.events.iter().enumerate();
    let Some((_, first)) = events.next() else {
        return Err(Refusal::Journal(
            "the journal records no events; a review opens with `open`".into(),
        ));
    };
    let JournalEvent::Submitted {
        plugin,
        publisher,
        at,
        ..
    } = first
    else {
        return Err(Refusal::Journal(format!(
            "submitted[0]: the first event must be `submitted`, not `{}`",
            first.kind()
        )));
    };
    let mut review = Review::open(plugin, publisher, *at)
        .map_err(|e| Refusal::Journal(format!("submitted[0]: {e}")))?;
    let mut certification: Option<Certification> = None;

    for (index, event) in events {
        match event {
            JournalEvent::Submitted { .. } => {
                return Err(Refusal::Journal(format!(
                    "submitted[{index}]: a review opens exactly once; a second submission is a \
                     second review, not another event"
                )));
            }
            JournalEvent::Scanned { report } => {
                let stage = review.stage();
                if stage != ReviewStage::Submitted && stage != ReviewStage::AutoScanned {
                    return Err(Refusal::Journal(format!(
                        "scanned[{index}]: a scan at {stage} could not change the decision, so it \
                         is refused"
                    )));
                }
                review
                    .record_scan(report.clone())
                    .map_err(|e| Refusal::Journal(format!("scanned[{index}]: {e}")))?;
            }
            JournalEvent::Advanced { to, because, at } => {
                if review.stage() == ReviewStage::AutoScanned
                    && *to != ReviewStage::Rejected
                    && review.scan().checks.is_empty()
                {
                    return Err(Refusal::Journal(format!(
                        "advanced[{index}]: the review left auto_scanned with no scan recorded; the \
                         checks that decide loading have to run before a human reads the code"
                    )));
                }
                review
                    .advance(*to, because, *at)
                    .map_err(|e| Refusal::Journal(format!("advanced[{index}]: {e}")))?;
            }
            JournalEvent::Certified {
                scope,
                vendor_key,
                at,
            } => {
                if certification.is_some() {
                    return Err(Refusal::Journal(format!(
                        "certified[{index}]: the review already issued a certification; a second one \
                         would be a second grant of authority"
                    )));
                }
                if review.scan().has_blocker() {
                    return Err(Refusal::Journal(format!(
                        "certified[{index}]: the recorded scan reports a blocker, so nothing may be \
                         certified from it"
                    )));
                }
                let caps = parse_scope(scope)
                    .map_err(|e| Refusal::Journal(format!("certified[{index}]: {e}")))?;
                // The tier comes from the name, which is the one rule the whole kernel uses
                // to classify a plugin. Hardcoding `Tier::ThirdParty` here made the flow
                // unable to issue the certification a `com.twinsearth.certified.*` name
                // *requires*: the arbiter refuses a certified plugin that no certification
                // covers, and a T3-scoped certification cannot carry a capability the T3
                // ceiling refuses -- so the tier that exists to be certified had no way to
                // be certified by anything shipped.
                let tier = named_tier(&review.plugin)
                    .map_err(|e| Refusal::Journal(format!("certified[{index}]: {e}")))?;
                let issued = Certification::issue(&review, &caps, tier, vendor_key, *at)
                    .map_err(|e| Refusal::Journal(format!("certified[{index}]: {e}")))?;
                certification = Some(issued);
            }
        }
    }

    Ok(Replayed {
        review,
        certification,
    })
}

/// The manifest digest recorded when the review was opened, if any.
fn recorded_digest(journal: &Journal) -> Option<&str> {
    journal.events.iter().find_map(|event| match event {
        JournalEvent::Submitted {
            manifest_digest, ..
        } if !manifest_digest.is_empty() => Some(manifest_digest.as_str()),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Argument handling
// ---------------------------------------------------------------------------

/// The first value given for `flag`, accepting `--flag value` and `--flag=value`.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_string());
        }
        if a == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Every value given for a repeatable `flag`, in order.
fn all_values(args: &[String], flag: &str) -> Vec<String> {
    let prefix = format!("{flag}=");
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if let Some(v) = a.strip_prefix(&prefix) {
            out.push(v.to_string());
        } else if a == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
        }
    }
    out
}

/// A required flag value, or a usage refusal naming the flag.
fn required(args: &[String], flag: &str) -> Result<String, Refusal> {
    flag_value(args, flag).ok_or_else(|| Refusal::Usage(format!("`{flag}` is required")))
}

/// The review directory, expanded the same way every other `nau` path argument is.
fn review_dir(args: &[String]) -> Result<PathBuf, Refusal> {
    let raw = required(args, "--dir")?;
    if raw.trim().is_empty() {
        // `--dir=` would otherwise silently mean the current directory, and a review
        // written into whatever directory the shell happened to be in is exactly the
        // record nobody can find again.
        return Err(Refusal::Usage(
            "`--dir` must name a review directory, not the empty string".into(),
        ));
    }
    Ok(crate::expand_home(&raw))
}

/// An optional `--at`, defaulting to now.
fn timestamp(args: &[String]) -> Result<u64, Refusal> {
    match flag_value(args, "--at") {
        None => Ok(now_seconds()),
        Some(raw) => raw.trim().parse::<u64>().map_err(|_| {
            Refusal::Usage(format!("--at `{raw}` is not a Unix timestamp in seconds"))
        }),
    }
}

/// The current Unix time, or the epoch if the clock is before it.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read a manifest document from a path, expanding a leading `~`.
fn read_manifest(path: &str) -> Result<(PathBuf, String), Refusal> {
    let path = crate::expand_home(path);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Refusal::Io(format!("cannot read {}: {e}", path.display())))?;
    Ok((path, text))
}

/// Parse a stage name: the canonical label, case-insensitive, `-` or `_` accepted.
fn parse_stage(raw: &str) -> Option<ReviewStage> {
    let wanted = raw.trim().to_ascii_lowercase().replace('-', "_");
    ReviewStage::ALL.into_iter().find(|s| s.label() == wanted)
}

/// Every stage label, for a usage message.
fn stage_list() -> String {
    ReviewStage::ALL
        .iter()
        .map(|s| s.label())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The legal next stages of `stage`, for a "what now" line.
fn next_stages(stage: ReviewStage) -> String {
    let next: Vec<&str> = stage.next_stages().iter().map(|s| s.label()).collect();
    if next.is_empty() {
        "none (terminal)".to_string()
    } else {
        next.join(", ")
    }
}

/// Parse a comma-separated capability scope.
fn parse_scope_list(value: &str) -> Result<Vec<Capability>, String> {
    let names: Vec<String> = value
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    parse_scope(&names)
}

/// Parse a list of capability wire names.
fn parse_scope(names: &[String]) -> Result<Vec<Capability>, String> {
    if names.is_empty() {
        return Err("a certification scope must name at least one capability".into());
    }
    let mut out = Vec::new();
    for name in names {
        out.push(Capability::parse(name).map_err(|e| e.to_string())?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// open
// ---------------------------------------------------------------------------

/// `nau plugin review open --dir <d> --manifest <path> --publisher <did> [--at <ts>]`
fn open(args: &[String]) -> Result<(), Refusal> {
    let dir = review_dir(args)?;
    let publisher = required(args, "--publisher")?;
    let at = timestamp(args)?;
    let (manifest_path, manifest_json) = read_manifest(&required(args, "--manifest")?)?;

    let path = journal_path(&dir);
    if path.exists() {
        return Err(Refusal::Journal(format!(
            "{} already holds a review; a refused submission is resubmitted in a new directory, \
             not appended to the record of the refusal",
            path.display()
        )));
    }

    let manifest = Manifest::parse(&manifest_json)
        .map_err(|e| Refusal::Kernel(format!("{}: {e}", manifest_path.display())))?;
    if manifest.plugin.publisher != publisher {
        return Err(Refusal::Usage(format!(
            "--publisher `{publisher}` is not the manifest's publisher `{}`; a review has to name \
             the DID of the document under review",
            manifest.plugin.publisher
        )));
    }

    let digest = manifest.digest_hex().unwrap_or_default();
    let journal = Journal {
        version: JOURNAL_VERSION,
        events: vec![JournalEvent::Submitted {
            plugin: manifest.plugin.name.clone(),
            publisher: publisher.clone(),
            at,
            manifest_digest: digest.clone(),
        }],
    };
    write_journal(&dir, &journal)?;

    let tier = Tier::from_name(&manifest.plugin.name)
        .map(|t| t.to_string())
        .unwrap_or_else(|_| "unclassified".to_string());
    println!("opened review {}", manifest.plugin.name);
    println!("  journal     {}", path.display());
    println!("  publisher   {publisher}");
    println!("  tier        {tier}");
    println!(
        "  manifest    {} sha256 {}",
        manifest_path.display(),
        short(&digest)
    );
    println!("  submitted   at {at}");
    println!("  stage       {}", ReviewStage::Submitted);
    println!();
    println!(
        "next: scan --dir {} --manifest {}",
        dir.display(),
        manifest_path.display()
    );
    println!("the scan has to run before the review can leave auto_scanned.");
    Ok(())
}

// ---------------------------------------------------------------------------
// the quarantine
// ---------------------------------------------------------------------------

/// What the scan consulted for the quarantine, and what it found.
///
/// A `Blacklist` is not `Clone`, so the verified list is owned here and moved into the
/// arbiter; the path and the counts stay behind so the report can say what was consulted
/// even after the list has been handed over.
struct BlacklistConsult {
    /// The file this host's quarantine lives in.
    path: PathBuf,
    /// Whether the file exists. An absent file is an empty blacklist, not a skipped check.
    present: bool,
    /// How many entries survived verification, which is the list the pipeline ran with.
    entries: usize,
    /// How many vendor keys were trusted for verification.
    keys: usize,
    /// The verified list, ready for the arbiter.
    list: Blacklist,
}

impl BlacklistConsult {
    /// The check row this consult contributes.
    ///
    /// Reported even when the list is empty, and the absent case is spelled out: "no
    /// entries" and "not consulted" look identical in a report, and a scan that quietly
    /// skipped the quarantine would approve a plugin the load pipeline refuses.
    fn describe(&self) -> (Finding, String) {
        if self.entries == 0 {
            let how = if self.present {
                "present and empty"
            } else {
                "absent, which is the established semantics of an empty blacklist rather than a \
                 skipped check"
            };
            (
                Finding::Note,
                format!(
                    "consulted {}: {how}; 0 entr(ies), so nothing is condemned",
                    self.path.display()
                ),
            )
        } else {
            (
                Finding::Clean,
                format!(
                    "consulted {}: {} entr(ies) re-verified against {} trusted vendor key(s); this \
                     is the list the load pipeline ran with",
                    self.path.display(),
                    self.entries,
                    self.keys
                ),
            )
        }
    }
}

/// Consult the maintained blacklist through the one shared loader.
///
/// `<dir>/blacklist.json` is the file `nau plugin blacklist` maintains, and this calls
/// [`crate::plugin_blacklist::load_verified`] — the same function that driver's `add`,
/// `list`, `check` and `unblock` call — so the review cannot develop its own idea of what
/// a valid quarantine is. A missing or empty file is an empty blacklist, which is this
/// host's established semantics for "nothing is condemned"; anything else has to verify,
/// and the loader's refusal is carried through with its own code, its own words and its
/// own entry number.
///
/// # Errors
///
/// [`Refusal::Usage`] for a `--vendor` value that is not a key, and the shared loader's own
/// refusal otherwise.
fn consult_blacklist(dir: &Path, vendor_keys: &[String]) -> Result<BlacklistConsult, Refusal> {
    let path = dir.join(BLACKLIST_FILE);

    // The fail-closed default: `Blacklist::add` accepts an entry only from a trusted
    // vendor key, and no key means no entry can be verified. `--trust` is deliberately not
    // accepted here — in `nau plugin verify` it names a third-party publisher key, and one
    // flag carrying two trust sets in one command is how a key ends up trusted for
    // something its holder was never trusted to do.
    let mut trust = TrustStore::deny_all();
    for key in vendor_keys {
        trust
            .trust_vendor_key(key)
            .map_err(|e| Refusal::Usage(format!("--vendor {key}: {e}")))?;
    }

    let present = path.is_file();
    let (_, list) = crate::plugin_blacklist::load_verified(&path, &trust).map_err(|refusal| {
        // Carried through unchanged: the code, the sentence and the entry number are the
        // shared loader's, so the two drivers cannot describe one file two ways.
        Refusal::Blacklist {
            code: refusal.code(),
            detail: refusal.detail().to_string(),
        }
    })?;

    Ok(BlacklistConsult {
        path,
        present,
        entries: list.len(),
        keys: trust.len(),
        list,
    })
}

/// One clause describing a stored entry that names the plugin under review.
///
/// Descriptive only, and deliberately not a verdict: whether the entry *applies* (a pinned
/// entry condemns one artefact, not every build) is decided by the kernel's blacklist
/// stage, which runs below.
fn describe_blacklist_entry(entry: &BlacklistEntry) -> String {
    format!(
        "an entry names this plugin: reason {}, scope {}, issued {}, evidence {}; whether it \
         applies to this build is decided by the kernel's blacklist stage below, and a pinned \
         entry condemns only the exact artefact it names",
        entry.reason.label(),
        match &entry.module_sha256 {
            Some(digest) => format!("pins {digest}"),
            None => "every build".to_string(),
        },
        entry.blacklisted_at,
        entry.evidence_cid
    )
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/// `nau plugin review scan --dir <d> --manifest <path> [--vendor <hex>]…`
fn scan(args: &[String]) -> Result<(), Refusal> {
    let dir = review_dir(args)?;
    let (manifest_path, manifest_json) = read_manifest(&required(args, "--manifest")?)?;
    let mut journal = read_journal(&dir)?;
    let mut replayed = replay(&journal)?;

    let stage = replayed.review.stage();
    if stage != ReviewStage::Submitted && stage != ReviewStage::AutoScanned {
        return Err(Refusal::Kernel(format!(
            "the review is at {stage}, and a scan recorded now could not change the decision; the \
             kernel refuses that, and this driver refuses it before touching the journal"
        )));
    }

    // The quarantine this host has accepted. A typed refusal here leaves the journal
    // untouched: a blacklist that does not verify is state the operator has to fix, not a
    // finding about the submission.
    let vendor_keys = all_values(args, "--vendor");
    let consult = consult_blacklist(&dir, &vendor_keys)?;

    let report = build_report(
        recorded_digest(&journal),
        &manifest_path,
        &manifest_json,
        consult,
        now_seconds(),
        &vendor_keys,
    );
    let blockers = report.blockers().len();

    // The report is recorded even when it blocks: a refused submission's findings are
    // part of the record, and the kernel's own gate is what stops the pipeline walking
    // past them.
    replayed
        .review
        .record_scan(report.clone())
        .map_err(|e| Refusal::Kernel(e.to_string()))?;
    journal.events.push(JournalEvent::Scanned {
        report: report.clone(),
    });
    write_journal(&dir, &journal)?;

    println!("scanned {}", replayed.review.plugin);
    println!("  review      {} (stage {stage})", dir.display());
    println!("  manifest    {}", manifest_path.display());
    println!();
    print_report(&report);
    println!();
    println!("The load pipeline above was run as far as starting a runtime. No plugin code ran.");
    println!();
    if blockers == 0 {
        println!("VERDICT  no blocker: the checks that decide loading passed");
        println!(
            "  next: advance --dir {} --to auto_scanned --because <why>",
            dir.display()
        );
        Ok(())
    } else {
        println!(
            "VERDICT  {blockers} blocker(s): this submission does not pass the checks that decide \
             loading"
        );
        println!(
            "  the scan is recorded; advance --dir {} --to rejected --because <why> is the honest \
             next step",
            dir.display()
        );
        Err(Refusal::Blocked(format!(
            "{blockers} blocker(s); the scan report above names each one"
        )))
    }
}

/// Run every check that decides whether this submission can be loaded.
///
/// The order is the order an operator needs: what the document says, what its tier
/// permits, whether it is authentic, and finally whether the load pipeline accepts it.
/// Nothing here restates a policy — every verdict comes from `nau-plugin`.
fn build_report(
    recorded: Option<&str>,
    manifest_path: &Path,
    manifest_json: &str,
    consult: BlacklistConsult,
    now: u64,
    vendor_keys: &[String],
) -> ScanReport {
    let mut report = ScanReport::default();

    // First, because it is the one check that is an input rather than a property of the
    // document, and because "which list did this decide against" has to be in the record.
    let (finding, detail) = consult.describe();
    report.push("blacklist", finding, &detail);

    let manifest = match Manifest::parse(manifest_json) {
        Ok(m) => m,
        Err(e) => {
            report.push("manifest-parse", Finding::Blocker, &e.to_string());
            report.push(
                "tier-classification",
                Finding::Note,
                "not run: the manifest did not parse",
            );
            report.push(
                "manifest-verify",
                Finding::Note,
                "not run: the manifest did not parse",
            );
            report.push(
                "load-pipeline",
                Finding::Note,
                "not run: the manifest did not parse",
            );
            return report;
        }
    };
    report.push(
        "manifest-parse",
        Finding::Clean,
        &format!("{} {}", manifest.plugin.name, manifest.plugin.version),
    );

    // The tier rule: the tier the name classifies as, which is the tier the certification
    // will be scoped at. See `named_tier` for why this is derived rather than fixed.
    let tier = match named_tier(&manifest.plugin.name) {
        Ok(tier) => {
            report.push(
                "tier-classification",
                Finding::Clean,
                &format!("classifies as {tier}: a tier this registration flow reviews"),
            );
            tier
        }
        Err(e) => {
            // Nothing below this point would mean anything: the capability rows are decided
            // at that tier, and the certification would be scoped at it. The report carries
            // the blocker, and the scan's contract is "a blocker is a refusal", so the
            // outcome is the same as continuing with a tier the name does not have.
            report.push("tier-classification", Finding::Blocker, &e);
            return report;
        }
    };

    match manifest.validate() {
        Ok(tier) => report.push(
            "manifest-validate",
            Finding::Clean,
            &format!("internally consistent; tier {tier}"),
        ),
        Err(e) => report.push("manifest-validate", Finding::Blocker, &e.to_string()),
    }

    // Drift: the manifest has to be the document the review was opened over.
    match (recorded, manifest.digest_hex()) {
        (Some(recorded), Ok(current)) if recorded == current => report.push(
            "manifest-digest",
            Finding::Clean,
            &format!("matches the digest recorded at open ({})", short(&current)),
        ),
        (Some(recorded), Ok(current)) => report.push(
            "manifest-digest",
            Finding::Blocker,
            &format!(
                "the manifest hashes to {} but the review was opened over {}; the document changed \
                 after the review began, so this is a different submission",
                short(&current),
                short(recorded)
            ),
        ),
        (Some(_), Err(e)) => report.push(
            "manifest-digest",
            Finding::Blocker,
            &format!("cannot recompute the manifest digest: {e}"),
        ),
        (None, Ok(current)) => report.push(
            "manifest-digest",
            Finding::Note,
            &format!(
                "the journal records no digest, so drift since open could not be checked; this \
                 document hashes to {}",
                short(&current)
            ),
        ),
        (None, Err(e)) => report.push(
            "manifest-digest",
            Finding::Note,
            &format!("the journal records no digest, and this one cannot be recomputed: {e}"),
        ),
    }

    // The tier matrix, per capability, at the tier the name classifies as -- the same tier
    // the certification will be scoped at.
    match manifest.requested_capabilities() {
        Ok(caps) if caps.is_empty() => report.push(
            "capabilities",
            Finding::Note,
            "the manifest requests no capability, so the token will grant nothing",
        ),
        Ok(caps) => {
            for cap in caps {
                let name = format!("capability:{}", cap.as_str());
                match cap.decision(tier) {
                    Grant::Always => report.push(
                        &name,
                        Finding::Clean,
                        &format!("held by the {tier} tier by construction"),
                    ),
                    Grant::RequiresApproval(authority) => report.push(
                        &name,
                        // Not a blocker, and this is the whole reason a review exists: the
                        // tier holds this capability **conditional on an approval**, and the
                        // certification this review issues is where that approval comes from
                        // (`Arbiter::with_certification` derives the approvals from the
                        // scope). Recording it as a blocker made the flow unable to certify
                        // anything the certified tier exists to be certified for: it refused
                        // capabilities the tier permits, on the grounds that nobody had
                        // approved them yet, while being the only place an approval could be
                        // granted.
                        Finding::Clean,
                        &format!(
                            "held by the {tier} tier with the {}'s approval, which the \
                             certification scope below is where this review grants",
                            authority.label()
                        ),
                    ),
                    Grant::Refused { reason } => report.push(
                        &name,
                        Finding::Blocker,
                        &format!(
                            "refused at {tier}: {reason}; no approval can grant it, so the load \
                             pipeline would refuse this manifest"
                        ),
                    ),
                }
            }
        }
        Err(e) => report.push("capabilities", Finding::Blocker, &e.to_string()),
    }

    // The publisher key and the module. A third-party manifest needs no
    // counter-signature; what it needs is the operator trusting this key, which is the
    // admission decision this review is making on the operator's behalf — recorded as a
    // Note, not silently assumed away.
    let publisher_key = manifest.signature.publisher_key.clone();
    let mut trust = TrustStore::deny_all();
    if let Err(e) = trust.trust_third_party_key(&publisher_key) {
        report.push(
            "publisher-key",
            Finding::Blocker,
            &format!("`{publisher_key}` is not a usable Ed25519 public key: {e}"),
        );
    }
    // The vendor keys, in the same store. A `com.twinsearth.certified.*` name **requires a
    // vendor counter-signature**, so a scan that trusted only the publisher could never pass
    // one: the tier's own defining requirement was the thing the scan reported as a blocker.
    // `--vendor` already means exactly one thing in this command -- trust this vendor key --
    // and a counter-signature is what a vendor key is for. (`--trust` stays out, because
    // there it names a third-party publisher key, and one flag carrying two trust sets is how
    // a key ends up trusted for something its holder was never trusted to do.)
    let mut vendor_key_bad = false;
    for key in vendor_keys {
        if let Err(e) = trust.trust_vendor_key(key) {
            report.push(
                "vendor-key",
                Finding::Blocker,
                &format!("`{key}` is not a usable Ed25519 vendor key: {e}"),
            );
            vendor_key_bad = true;
        }
    }
    if vendor_key_bad {
        return report;
    }

    let entry_path = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&manifest.plugin.entry);
    match std::fs::read(&entry_path) {
        Ok(module) => {
            // `Manifest::verify` is the kernel's whole authenticity path -- the
            // recomputed digest, the publisher signature, the module hash, the
            // counter-signature rule for the tier, and the capability token that can
            // only be minted if every requested capability resolves. One call, one
            // verdict, no second implementation.
            // `verify_with_approvals`, not `verify`: the approved capabilities are the ones the
            // certification this review issues will carry, and asking the manifest to resolve its
            // capabilities without them answers a question about a host that has no review.
            let approvals = prospective_approvals(&manifest, tier);
            let approval_pairs: Vec<(Capability, Approval)> = approvals.clone();
            match manifest.verify_with_approvals(&module, &trust, now, &approval_pairs) {
                Ok(verified) => report.push(
                    "manifest-verify",
                    Finding::Clean,
                    &format!(
                        "digest, publisher signature, module digest and capability resolution all \
                         verify; tier {} id {}",
                        verified.tier, verified.id
                    ),
                ),
                Err(e) => report.push("manifest-verify", Finding::Blocker, &format!("{e}")),
            }
            report.push(
                "operator-trust",
                Finding::Note,
                &format!(
                    "the scan ran the pipeline with publisher key {} trusted, because admitting this \
                     key is the decision the review makes; the load pipeline refuses this manifest \
                     until the operator adds that key. The binding from DID `{}` to that key is not \
                     checked here, or anywhere in the kernel, and has to be established out of band.",
                    short(&publisher_key),
                    manifest.plugin.publisher
                ),
            );
            // A stored entry that names this plugin is worth telling the reviewer about,
            // as a Note: the kernel's blacklist stage below decides whether it applies.
            if let Some(stored) = consult.list.entry(&manifest.plugin.name) {
                report.push(
                    "blacklist-entry",
                    Finding::Note,
                    &describe_blacklist_entry(stored),
                );
            }
            run_load_pipeline(
                LoadInputs {
                    manifest_json,
                    module,
                    entry: &entry_path,
                    trust,
                    blacklist: consult.list,
                    // The approvals the certification this review would issue will carry.
                    // Without them the integrated verdict answers "would this load with no
                    // review at all?", which is not the question a review asks: a capability
                    // the tier permits *conditional on the committee's approval* is refused by
                    // the load path precisely because the approval is what the review grants.
                    certification: ProspectiveCertification::new(
                        &manifest.plugin.name,
                        prospective_scope(&manifest, tier),
                    ),
                    now,
                },
                &mut report,
            );
        }
        Err(e) => {
            report.push(
                "module-artefact",
                Finding::Blocker,
                &format!(
                    "cannot read the entry artefact {}: {e}",
                    entry_path.display()
                ),
            );
            report.push(
                "manifest-verify",
                Finding::Note,
                "not run: the entry artefact could not be read",
            );
            report.push(
                "load-pipeline",
                Finding::Note,
                "not run: the entry artefact could not be read",
            );
        }
    }

    report
}

/// Run the host's real load pipeline and record each stage as a check.
///
/// This is the check that makes the whole command mean something: it is the arbiter, the
/// same runtimes, the same shipped ABI adapters and the same **quarantine** that
/// `nau plugin verify` uses, so a submission that gets past this gets past a load. Running
/// it does not execute the plugin — `ProcessRuntime::start` validates the spec and returns
/// a handle, and the exec belongs to the host that owns the sandbox.
/// What a scan hands the load pipeline: the artefact, and the host state it loads against.
///
/// Grouped rather than passed as eight positional arguments, because they are two things --
/// a submission and a host -- and a signature that lists them flat makes it easy to hand a
/// different submission's trust store to this one's artefact.
struct LoadInputs<'a> {
    /// The manifest document, as the submission wrote it.
    manifest_json: &'a str,
    /// The entry artefact's bytes.
    module: Vec<u8>,
    /// Where the entry artefact is.
    entry: &'a Path,
    /// Who this host trusts.
    trust: TrustStore,
    /// The quarantine this host has accepted.
    blacklist: Blacklist,
    /// The certification this review *would* issue, for the integrated verdict.
    certification: crate::plugin_review::ProspectiveCertification,
    /// The load time.
    now: u64,
}

fn run_load_pipeline(inputs: LoadInputs<'_>, report: &mut ScanReport) {
    let LoadInputs {
        manifest_json,
        module,
        entry,
        trust,
        blacklist,
        certification,
        now,
    } = inputs;
    let mut arbiter = Arbiter::new(trust, blacklist)
        .with_runtime(Box::new(NativeRuntime::new()))
        .with_runtime(Box::new(ProcessRuntime::new()))
        .with_runtime(Box::new(WasmRuntime::new()))
        .with_adapters(AdapterRegistry::with_shipped_adapters());
    // The scope this review would grant, applied to the same pipeline a load runs.
    // `with_certification` derives the approvals from that scope, so this one call supplies
    // both halves of what the load path needs: the approvals, so the token may include the
    // gated capabilities, and the scope, so nothing wider slips through.
    if let Some(certification) = certification.into_certification() {
        arbiter = arbiter.with_certification(certification);
    }
    let mut registry = Registry::new();
    let Ok(mut bus) = Bus::new(BusLimits::default()) else {
        report.push(
            "load-pipeline",
            Finding::Blocker,
            "the plugin bus limits are not usable, so the load pipeline could not be run",
        );
        return;
    };

    let request = LoadRequest::new(manifest_json, module, entry.to_path_buf());
    match arbiter.load(&mut registry, &mut bus, &request, now) {
        Ok(loaded) => {
            for step in &loaded.trace {
                report.push(
                    &format!("load:{}", step.step),
                    Finding::Clean,
                    &step.outcome,
                );
            }
            report.push(
                "load-pipeline",
                Finding::Clean,
                &format!(
                    "ACCEPTED by the whole pipeline: tier {} on the {} runtime, holding {}",
                    loaded.tier,
                    loaded.runtime.label(),
                    caps_or_nothing(&loaded.granted)
                ),
            );
        }
        Err(failure) => {
            for step in &failure.trace {
                let finding = if step.passed {
                    Finding::Clean
                } else {
                    Finding::Blocker
                };
                report.push(&format!("load:{}", step.step), finding, &step.outcome);
            }
            // The failing stage's own row above carries the outcome verbatim; this row is
            // the pipeline's verdict, so it names the stage and the refusal kind once.
            let stage = failure
                .trace
                .iter()
                .rev()
                .find(|s| !s.passed)
                .map_or("?", |s| s.step);
            report.push(
                "load-pipeline",
                Finding::Blocker,
                &format!(
                    "REFUSED by the load pipeline at `{stage}` ({}): {}",
                    failure.refusal.code(),
                    failure.detail
                ),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// advance
// ---------------------------------------------------------------------------

/// `nau plugin review advance --dir <d> --to <stage> --because <text> [--at <ts>]`
fn advance(args: &[String]) -> Result<(), Refusal> {
    let dir = review_dir(args)?;
    let to_raw = required(args, "--to")?;
    let to = parse_stage(&to_raw).ok_or_else(|| {
        Refusal::Usage(format!(
            "--to `{to_raw}` is not a review stage; the stages are {}",
            stage_list()
        ))
    })?;
    let because = required(args, "--because")?;
    let at = timestamp(args)?;

    let mut journal = read_journal(&dir)?;
    let mut replayed = replay(&journal)?;
    let from = replayed.review.stage();

    if from == ReviewStage::AutoScanned
        && to != ReviewStage::Rejected
        && replayed.review.scan().checks.is_empty()
    {
        return Err(Refusal::Kernel(
            "the review is at auto_scanned with no scan recorded; run `scan` before a human reads \
             the code, so the pipeline cannot walk past checks that never ran"
                .into(),
        ));
    }

    replayed
        .review
        .advance(to, &because, at)
        .map_err(|e| Refusal::Kernel(e.to_string()))?;
    journal.events.push(JournalEvent::Advanced {
        to,
        because: because.clone(),
        at,
    });
    write_journal(&dir, &journal)?;

    println!("advanced {} : {from} -> {to}", replayed.review.plugin);
    println!("  review      {}", dir.display());
    println!("  because     {because}");
    println!("  at          {at}");
    println!();
    if to == ReviewStage::Certified {
        println!("The review is certified, but nothing is granted yet: a certification is a");
        println!("scope, and it is issued as its own deliberate step.");
        println!(
            "  next: certify --dir {} --scope <cap,cap> --vendor-key <hex>",
            dir.display()
        );
    } else if to == ReviewStage::Rejected {
        println!("{to} is terminal: a resubmission is a new review, not another transition.");
    } else {
        println!("  next legal  {}", next_stages(to));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// show
// ---------------------------------------------------------------------------

/// `nau plugin review show --dir <d>`
fn show(args: &[String]) -> Result<(), Refusal> {
    let dir = review_dir(args)?;
    let journal = read_journal(&dir)?;
    let replayed = replay(&journal)?;
    let review = &replayed.review;

    println!("review  {}", review.plugin);
    println!("  dir         {}", dir.display());
    println!("  publisher   {}", review.publisher);
    println!("  stage       {}", review.stage());
    println!("  next legal  {}", next_stages(review.stage()));
    println!();
    println!("history ({} entries, oldest first)", review.history().len());
    for (stage, because, at) in review.history() {
        println!("  {at:>12}  {stage:<13} {because}");
    }
    println!();
    if review.scan().checks.is_empty() {
        println!("checks      none recorded: the automatic scan has not run");
        println!(
            "  next: scan --dir {} --manifest <plugin.json>",
            dir.display()
        );
    } else {
        println!("checks ({} recorded)", review.scan().checks.len());
        print_report(review.scan());
    }
    println!();
    match &replayed.certification {
        Some(certification) => {
            println!("certification");
            println!("  scope       {}", scope_list(&certification.scope));
            println!("  vendor key  {}", short(&certification.vendor_key));
            println!("  certified   at {}", certification.certified_at);
            println!(
                "  the loader enforces this scope with `Certification::require_within_scope`: a \
                 manifest"
            );
            println!(
                "  asking for anything outside it is refused at load even if every signature is valid."
            );
        }
        None => println!("certification  none issued"),
    }
    println!();
    println!(
        "conclusion  {}",
        conclusion(review, replayed.certification.is_some())
    );
    Ok(())
}

/// One line saying what the record currently supports.
fn conclusion(review: &Review, certified: bool) -> String {
    let blockers = review.scan().blockers().len();
    if certified {
        "certified: the certification scope above is what the loader enforces".to_string()
    } else if blockers > 0 {
        format!(
            "{blockers} blocker(s) in the scan: this submission does not pass the checks that decide \
             loading"
        )
    } else if review.scan().checks.is_empty() {
        "no conclusion: the automatic scan has not run".to_string()
    } else {
        "no blocker: the checks that decide loading passed".to_string()
    }
}

// ---------------------------------------------------------------------------
// certify
// ---------------------------------------------------------------------------

/// `nau plugin review certify --dir <d> --scope <cap,cap> --vendor-key <hex> [--at <ts>]`
/// The standalone artefact a loader is handed.
///
/// # Why a file next to the journal, and not only the journal
///
/// The journal is the human record of a review; a certification is a **thing a loader
/// consumes**. `nau plugin verify --certification <file>` takes this file, and the arbiter
/// enforces its scope at load. Writing it at `certify` time is what makes the granted scope
/// reachable by the process that has to enforce it — the journal alone would leave the
/// enforcement with no way to receive it from the command line, which is the same
/// "written but not wired" defect one level up.
const CERTIFICATION_FILE: &str = "certification.json";

/// Project a [`Certification`] into the artefact's JSON.
///
/// Faithful: every field comes from the struct, and the scope is written as capability
/// strings rather than as an index into anything.
fn certification_to_json(certification: &Certification) -> serde_json::Value {
    serde_json::json!({
        "plugin": certification.plugin,
        "scope": certification.scope.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "vendor_key": certification.vendor_key,
        "certified_at": certification.certified_at,
        "stage_history": certification
            .stage_history
            .iter()
            .map(|(stage, because, at)| serde_json::json!({
                "stage": stage.label(),
                "because": because,
                "at": at,
            }))
            .collect::<Vec<_>>(),
    })
}

/// Rebuild a [`Certification`] from the artefact's JSON.
///
/// # Errors
///
/// A sentence naming the field that was wrong. Nothing is guessed: an unknown capability,
/// an unknown stage label, a missing field or a timestamp of zero is a refusal rather than
/// a default, because a certification with invented contents is a grant nobody made.
///
/// The scope must be non-empty for the same reason
/// [`Certification::issue`](nau_plugin::certify::Certification::issue) refuses one: a
/// certification for nothing certifies nothing and cannot be told apart from a mistake.
pub(crate) fn certification_from_json(value: &serde_json::Value) -> Result<Certification, String> {
    let plugin = value
        .get("plugin")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "the certification names no plugin".to_string())?
        .to_string();

    let scope_raw = value
        .get("scope")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "the certification has no `scope` array".to_string())?;
    let mut scope = std::collections::BTreeSet::new();
    for entry in scope_raw {
        let name = entry
            .as_str()
            .ok_or_else(|| "a scope entry is not a capability name".to_string())?;
        let capability = Capability::parse(name)
            .map_err(|e| format!("`{name}` in the scope is not a capability: {e}"))?;
        scope.insert(capability);
    }
    if scope.is_empty() {
        return Err("the certification scope is empty, which certifies nothing".to_string());
    }

    let vendor_key = value
        .get("vendor_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "the certification has no `vendor_key`".to_string())?
        .to_string();
    // The key is attribution, but an attribution to something that is not a key is not an
    // attribution. `TrustStore`'s own setter is the validator the rest of the system uses.
    let mut probe = TrustStore::deny_all();
    probe
        .trust_vendor_key(&vendor_key)
        .map_err(|e| format!("`vendor_key` is not an Ed25519 key: {e}"))?;

    let certified_at = value
        .get("certified_at")
        .and_then(serde_json::Value::as_u64)
        .filter(|at| *at != 0)
        .ok_or_else(|| "the certification carries no timestamp".to_string())?;

    let mut stage_history = Vec::new();
    for entry in value
        .get("stage_history")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let label = entry
            .get("stage")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "a history entry has no stage".to_string())?;
        let stage = ReviewStage::ALL
            .into_iter()
            .find(|s| s.label() == label)
            .ok_or_else(|| format!("`{label}` is not a review stage"))?;
        let because = entry
            .get("because")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        let at = entry
            .get("at")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        stage_history.push((stage, because, at));
    }
    if stage_history.is_empty() {
        return Err(
            "the certification carries no review history, so it records no review".to_string(),
        );
    }

    Ok(Certification {
        plugin,
        scope,
        vendor_key,
        certified_at,
        stage_history,
    })
}

/// The approvals the certification this review would issue will carry.
///
/// One derivation, used both to describe the capability rows and to run the integrated load
/// pipeline: a capability the tier holds `RequiresApproval` is held **conditional on the
/// authority's approval**, and the certification scope is where that approval comes from
/// (`Arbiter::with_certification` derives the same list from the scope it is handed).
/// Running the pipeline without them would answer "would this load with no review at all?",
/// which is not what a scan is for.
fn prospective_approvals(manifest: &Manifest, tier: Tier) -> Vec<(Capability, Approval)> {
    let Ok(caps) = manifest.requested_capabilities() else {
        return Vec::new();
    };
    caps.into_iter()
        .filter_map(|cap| match cap.decision(tier) {
            Grant::RequiresApproval(authority) => Some((cap, authority)),
            Grant::Always | Grant::Refused { .. } => None,
        })
        .collect()
}

/// The certification this review **would** issue, for the scan's integrated verdict.
///
/// # What this is, and what it is not
///
/// It is not a certification. `certify` produces the real one *after* a blocker-free scan,
/// and the arbiter enforces it then. This is the scope the review is about to grant, used to
/// answer the only question a scan can honestly ask about a not-yet-certified submission:
/// **"would this load once certified at the scope I intend?"**
///
/// Without it the integrated verdict answered a different question -- "would this load on a
/// host with no review at all?" -- and refused every `com.twinsearth.certified.*` submission
/// at the `certification` stage, which is the tier that exists to be certified.
///
/// The attribution fields are left empty on purpose: the load path reads `plugin` and `scope`
/// and derives the approvals from the scope, so inventing a vendor key or a timestamp here
/// would put values into a record nobody signed. `certify` is where those become real.
pub(crate) struct ProspectiveCertification {
    plugin: String,
    scope: Vec<Capability>,
}

impl ProspectiveCertification {
    /// Build it from the capabilities the review would grant.
    #[must_use]
    fn new(plugin: &str, scope: Vec<Capability>) -> Self {
        Self {
            plugin: plugin.to_string(),
            scope,
        }
    }

    /// The certification to hand the arbiter, if there is a scope to hand.
    ///
    /// `None` when the scope is empty: an empty certification certifies nothing, and handing
    /// the arbiter one would either be refused or -- worse -- mean something no review
    /// decided.
    fn into_certification(self) -> Option<Certification> {
        if self.scope.is_empty() {
            return None;
        }
        Some(Certification {
            plugin: self.plugin,
            scope: self.scope.into_iter().collect(),
            vendor_key: String::new(),
            certified_at: 0,
            stage_history: Vec::new(),
        })
    }
}

/// The scope this review would grant: every requested capability the tier does not refuse
/// outright.
///
/// `Grant::Refused` is excluded because no review can grant it, and the scan already records
/// that as a blocker; everything else is what the certification would cover.
fn prospective_scope(manifest: &Manifest, tier: Tier) -> Vec<Capability> {
    let Ok(caps) = manifest.requested_capabilities() else {
        return Vec::new();
    };
    caps.into_iter()
        .filter(|cap| !matches!(cap.decision(tier), Grant::Refused { .. }))
        .collect()
}

/// The tier this flow reviews, derived from the plugin's own name.
///
/// # Why one rule instead of a hardcoded tier
///
/// A certification has to be scoped at the ceiling the plugin will **actually load at**, or
/// it cannot cover what the review approved. This flow used to hardcode
/// `Tier::ThirdParty` in the scan's rules, in the per-capability decisions and in
/// `Certification::issue` — and the consequence was that a `com.twinsearth.certified.*`
/// name could not be certified at all: the arbiter refuses a certified plugin that no
/// certification covers, while the only shipped producer of certifications issued them at
/// the T3 ceiling, which refuses outright every capability a T2 plugin exists to be
/// certified for. The tier that exists to be certified had no way to be certified by
/// anything shipped.
///
/// The kernel classifies a plugin by its name everywhere else; this is the same rule, so a
/// name cannot mean one tier to the loader and another to the review.
///
/// # Errors
///
/// A sentence naming the tier when the name classifies as one this flow does not register
/// (the system tier is in-process and the official tier is vendor-published, neither of
/// which is submitted for review), or the kernel's own error when the name does not
/// classify at all.
fn named_tier(name: &str) -> Result<Tier, String> {
    match Tier::from_name(name) {
        Ok(Tier::ThirdParty) => Ok(Tier::ThirdParty),
        Ok(Tier::Certified) => Ok(Tier::Certified),
        Ok(other) => Err(format!(
            "`{name}` classifies as {other}, which this flow does not register: it reviews \
             third-party and certified names, because a certification issued from it is scoped \
             at the tier the name classifies as"
        )),
        Err(e) => Err(e.to_string()),
    }
}

fn certify(args: &[String]) -> Result<(), Refusal> {
    let dir = review_dir(args)?;
    let scope_raw = required(args, "--scope")?;
    let vendor_key = required(args, "--vendor-key")?;
    let at = timestamp(args)?;

    // The certification attributes the grant to this key, so a key that is not a real
    // Ed25519 public key would attribute it to nobody.
    let mut key_probe = TrustStore::deny_all();
    key_probe
        .trust_vendor_key(&vendor_key)
        .map_err(|e| Refusal::Usage(format!("--vendor-key: {e}")))?;
    let scope =
        parse_scope_list(&scope_raw).map_err(|e| Refusal::Usage(format!("--scope: {e}")))?;

    let mut journal = read_journal(&dir)?;
    let replayed = replay(&journal)?;
    if replayed.certification.is_some() {
        return Err(Refusal::Kernel(format!(
            "{} already issued a certification; a second one would be a second grant of authority",
            replayed.review.plugin
        )));
    }
    if replayed.review.scan().has_blocker() {
        return Err(Refusal::Kernel(
            "the recorded scan reports a blocker, so nothing may be certified from this review"
                .into(),
        ));
    }

    // Scoped at the tier the reviewed name classifies as, so a scope the plugin could hold
    // but the wrong ceiling refuses cannot be the reason a certification fails.
    let tier = named_tier(&replayed.review.plugin).map_err(Refusal::Kernel)?;
    let certification = Certification::issue(&replayed.review, &scope, tier, &vendor_key, at)
        .map_err(|e| Refusal::Kernel(e.to_string()))?;

    journal.events.push(JournalEvent::Certified {
        scope: certification
            .scope
            .iter()
            .map(|c| c.as_str().to_string())
            .collect(),
        vendor_key: vendor_key.clone(),
        at,
    });
    write_journal(&dir, &journal)?;

    // And the artefact a loader is handed. Written after the journal, so a failure here
    // leaves the review recorded and the operator able to retry -- rather than a
    // certification on disk that the journal has no memory of, which replay would then
    // refuse and which would be a grant nothing can be asked about.
    let artifact = dir.join(CERTIFICATION_FILE);
    let encoded = serde_json::to_string_pretty(&certification_to_json(&certification))
        .map_err(|e| Refusal::Kernel(format!("the certification cannot be serialised: {e}")))?;
    std::fs::write(&artifact, encoded)
        .map_err(|e| Refusal::Kernel(format!("cannot write {}: {e}", artifact.display())))?;

    println!("certified {}", certification.plugin);
    println!("  review      {}", dir.display());
    println!("  scope       {}", scope_list(&certification.scope));
    println!(
        "  vendor key  {}  (attribution only: a `Certification` carries no signature of its own)",
        short(&vendor_key)
    );
    println!("  certified   at {at}");
    println!(
        "  history     {} transition(s) carried into the certification",
        certification.stage_history.len()
    );
    println!();
    println!(
        "The scope above is what a loader enforces: `nau plugin verify --certification {}`",
        artifact.display()
    );
    println!("hands the arbiter this certification, and `Certification::require_within_scope`");
    println!("refuses a manifest asking for anything outside it, whatever signatures it carries.");
    println!("Loading it still needs the operator to trust the publisher key in the manifest.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

/// Print a scan report, one check per line.
fn print_report(report: &ScanReport) {
    for check in &report.checks {
        println!(
            "  {:<8} {:<32} {}",
            check.finding.label(),
            check.check,
            check.detail
        );
    }
    let clean = report
        .checks
        .iter()
        .filter(|c| c.finding == Finding::Clean)
        .count();
    let notes = report
        .checks
        .iter()
        .filter(|c| c.finding == Finding::Note)
        .count();
    println!(
        "  {} clean, {notes} note(s), {} blocker(s)",
        clean,
        report.blockers().len()
    );
}

/// The first twelve characters of a value, for a message.
///
/// Character-wise rather than by byte: a hand-edited journal can put anything in a key
/// field, and slicing a string by byte offset is a panic waiting for a non-ASCII byte.
fn short(value: &str) -> String {
    value.chars().take(12).collect()
}

/// A comma-separated capability set.
fn scope_list(scope: &BTreeSet<Capability>) -> String {
    if scope.is_empty() {
        return "nothing".to_string();
    }
    scope
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A comma-separated capability slice, or `nothing`.
fn caps_or_nothing(caps: &[Capability]) -> String {
    if caps.is_empty() {
        return "nothing".to_string();
    }
    caps.iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use ed25519_dalek::{Signer, SigningKey};
    use nau_plugin::manifest::{CapabilitySection, Limits, PluginSection, SignatureSection};
    // `declares()` is a `PluginRuntime` method, and the waiver fixture below derives its
    // keys from the runtime's own declaration instead of a hand-written list.
    use nau_plugin::runtime::PluginRuntime;
    use sha2::Digest;

    const NOW: u64 = 1_750_000_000;
    const PUBLISHER_DID: &str = "did:nau:0011223344556677";

    fn keypair(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn module() -> Vec<u8> {
        b"#!/bin/sh\nexit 0\n".to_vec()
    }

    fn limits() -> Limits {
        Limits {
            memory_bytes: 64 * 1024 * 1024,
            cpu_ms: 5_000,
            disk_bytes: 8 * 1024 * 1024,
            max_processes: 2,
            max_output_bytes: 32 * 1024,
        }
    }

    /// Every boundary the process runtime cannot enforce, waived with a reason.
    ///
    /// Derived from the runtime rather than listed literally. This function used to hold a
    /// copy of the arbiter's five keys, with a comment saying it was "the set the arbiter's
    /// own tests use" -- so A-02's four new boundaries made both copies incomplete at once,
    /// and five review-pipeline tests failed while the pipeline itself was correct.
    fn waivers() -> Vec<(&'static str, &'static str)> {
        ProcessRuntime::new()
            .declares()
            .unenforced()
            .into_iter()
            .map(|(boundary, _why)| {
                (
                    boundary.waiver_key(),
                    "test: accepted for this fixture, the boundary is not under test here",
                )
            })
            .collect()
    }

    /// A signed third-party manifest whose module digest covers [`module`].
    fn manifest(name: &str, caps: &[&str], waivers: &[(&str, &str)]) -> Manifest {
        let publisher = keypair(7);
        let mut m = Manifest {
            plugin: PluginSection {
                name: name.to_string(),
                version: "1.4.0".into(),
                abi: format!("{}.{}", nau_plugin::ABI_MAJOR, nau_plugin::ABI_MINOR),
                entry: "plugin.bin".into(),
                publisher: PUBLISHER_DID.into(),
                module_sha256: hex::encode(sha2::Sha256::digest(module())),
            },
            capabilities: CapabilitySection {
                grant: caps.iter().map(|s| (*s).to_string()).collect(),
            },
            limits: limits(),
            waivers: waivers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect::<BTreeMap<String, String>>(),
            dependencies: Vec::new(),
            signature: SignatureSection {
                publisher_key: hex::encode(publisher.verifying_key().to_bytes()),
                manifest_digest: String::new(),
                sig: String::new(),
                counter_sig: None,
                counter_key: None,
            },
        };
        m.signature.manifest_digest = m.digest_hex().expect("digest");
        let digest = m.signature.manifest_digest.clone();
        m.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
        m
    }

    /// A throwaway root directory for one test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nau-review-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Write a submission directory and return `(submission, review_dir, manifest_path)`.
    fn submission(tag: &str, m: &Manifest) -> (PathBuf, PathBuf, String) {
        let root = scratch(tag);
        let sub = root.join("submission");
        let review = root.join("review");
        std::fs::create_dir_all(&sub).expect("submission dir");
        std::fs::write(
            sub.join("plugin.json"),
            serde_json::to_string_pretty(m).expect("json"),
        )
        .expect("write manifest");
        std::fs::write(sub.join("plugin.bin"), module()).expect("write module");
        let manifest_path = sub.join("plugin.json").display().to_string();
        (sub, review, manifest_path)
    }

    fn args(pairs: &[&str]) -> Vec<String> {
        pairs.iter().map(|s| (*s).to_string()).collect()
    }

    /// A signed blacklist entry from `vendor`, pinning `digest` when one is given.
    fn blacklist_entry(name: &str, digest: Option<&str>, vendor: &SigningKey) -> BlacklistEntry {
        use nau_plugin::blacklist::BlacklistReason;
        let mut entry = BlacklistEntry {
            plugin_name: name.to_string(),
            module_sha256: digest.map(str::to_string),
            reason: BlacklistReason::Malware,
            blacklisted_at: NOW,
            evidence_cid: "bafyevidence".to_string(),
            signer_key: hex::encode(vendor.verifying_key().to_bytes()),
            signature: String::new(),
        };
        entry.signature = hex::encode(vendor.sign(&entry.signing_bytes()).to_bytes());
        entry
    }

    /// Write `<review>/blacklist.json` holding `entries`.
    fn write_blacklist(review: &Path, entries: &[BlacklistEntry]) {
        std::fs::write(
            review.join(BLACKLIST_FILE),
            serde_json::to_string_pretty(entries).expect("encode blacklist"),
        )
        .expect("write blacklist");
    }

    /// The recorded scan's checks, as `"<check> <finding> <detail>"` rows.
    fn recorded_rows(review: &Path) -> Vec<String> {
        replay(&read_journal(review).expect("journal"))
            .expect("replays")
            .review
            .scan()
            .checks
            .iter()
            .map(|c| format!("{} {} {}", c.check, c.finding.label(), c.detail))
            .collect()
    }

    fn vendor_key_hex() -> String {
        hex::encode(keypair(9).verifying_key().to_bytes())
    }

    /// Drive a review from `open` to `certified`.
    fn drive_to_certified(m: &Manifest, tag: &str) -> (PathBuf, String) {
        let (_sub, review, manifest_path) = submission(tag, m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
            "--at",
            "1750000000",
        ]))
        .expect("opens");
        scan(&args(&["--dir", &dir, "--manifest", &manifest_path])).expect("scans clean");
        for stage in ["auto_scanned", "manual_review", "grey_run", "certified"] {
            advance(&args(&[
                "--dir",
                &dir,
                "--to",
                stage,
                "--because",
                "reviewed",
                "--at",
                "1750000001",
            ]))
            .expect("a legal edge");
        }
        (review, manifest_path)
    }

    #[test]
    fn the_five_commands_drive_a_submission_to_a_certification() {
        let m = manifest(
            "io.example.analytics",
            &["plugin:message:send", "plugin:storage:own"],
            &waivers(),
        );
        let (review, _manifest_path) = drive_to_certified(&m, "e2e");
        let dir = review.display().to_string();

        certify(&args(&[
            "--dir",
            &dir,
            "--scope",
            "plugin:message:send,plugin:storage:own",
            "--vendor-key",
            &vendor_key_hex(),
            "--at",
            "1750000002",
        ]))
        .expect("certifies");
        show(&args(&["--dir", &dir])).expect("shows");

        let journal = read_journal(&review).expect("journal");
        assert_eq!(
            journal.events.len(),
            7,
            "submitted, scanned, 4 advances, certified"
        );
        let replayed = replay(&journal).expect("replays");
        assert_eq!(replayed.review.stage(), ReviewStage::Certified);
        let certification = replayed.certification.expect("a certification");
        assert_eq!(certification.scope.len(), 2);
        assert_eq!(certification.plugin, "io.example.analytics");
        assert_eq!(certification.stage_history.len(), 5);

        // The raw journal is an event log, not a serialised `Review`: a reader can see
        // the report it recorded without trusting a snapshot.
        let text = std::fs::read_to_string(journal_path(&review)).expect("read");
        assert!(text.contains("\"kind\": \"scanned\""), "{text}");
        assert!(text.contains("load-pipeline"), "{text}");
        assert!(!text.contains("stage\": \"certified\""), "{text}");
        // The record says which blacklist was decided against, and that there was none:
        // "consulted and empty" must not read the same as "not consulted".
        assert!(text.contains("\"check\": \"blacklist\""), "{text}");
        assert!(text.contains("absent"), "{text}");
    }

    #[test]
    fn the_scan_runs_the_load_pipeline_so_a_missing_waiver_is_a_blocker() {
        // The headline property: the scan does not invent a friendlier check set. A
        // plugin whose boundaries the process runtime cannot enforce is refused by the
        // real pipeline, and the blocker names that stage.
        let m = manifest("io.example.analytics", &["plugin:message:send"], &[]);
        let (_sub, review, manifest_path) = submission("pipeline", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");

        let err = scan(&args(&["--dir", &dir, "--manifest", &manifest_path]))
            .expect_err("an unwaived boundary cannot load");
        assert!(matches!(err, Refusal::Blocked(_)));

        let journal = read_journal(&review).expect("journal");
        let replayed = replay(&journal).expect("replays");
        let rows: Vec<String> = replayed
            .review
            .scan()
            .checks
            .iter()
            .map(|c| format!("{} {} {}", c.check, c.finding.label(), c.detail))
            .collect();
        assert!(
            rows.iter().any(|r| r.starts_with("load:runtime blocker")),
            "{rows:#?}"
        );
        assert!(
            rows.iter().any(|r| r.contains("load-pipeline blocker")),
            "{rows:#?}"
        );
        assert!(
            rows.iter().any(|r| r.contains("network_deny")),
            "the refusal must name the boundary: {rows:#?}"
        );
    }

    #[test]
    fn a_sensitive_capability_is_a_blocker_and_the_advance_gate_stops_the_pipeline() {
        let m = manifest("io.example.analytics", &["net:dht:read"], &waivers());
        let (_sub, review, manifest_path) = submission("capability", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        scan(&args(&["--dir", &dir, "--manifest", &manifest_path]))
            .expect_err("net:dht:read is refused at T3");
        advance(&args(&[
            "--dir",
            &dir,
            "--to",
            "auto_scanned",
            "--because",
            "scan done",
        ]))
        .expect("the scan stage is reachable");
        let err = advance(&args(&[
            "--dir",
            &dir,
            "--to",
            "manual_review",
            "--because",
            "queue it",
        ]))
        .expect_err("the kernel must refuse to walk past its own blocker");
        assert!(err.detail().contains("blocker"), "{}", err.detail());
        assert!(err.detail().contains("net:dht:read"), "{}", err.detail());
    }

    #[test]
    fn the_scan_consults_the_maintained_blacklist_and_a_condemned_plugin_is_a_blocker() {
        // The defect this test exists for: a scan that ran against an empty list would
        // approve a plugin the load pipeline refuses, and it would be a review people
        // trust. The quarantine is an input to the scan, not a detail of it.
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (_sub, review, manifest_path) = submission("blk-condemned", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        let vendor = keypair(42);
        let vendor_hex = hex::encode(vendor.verifying_key().to_bytes());
        write_blacklist(
            &review,
            &[blacklist_entry("io.example.analytics", None, &vendor)],
        );

        let err = scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            &vendor_hex,
        ]))
        .expect_err("a condemned plugin must not pass a scan");
        assert!(matches!(err, Refusal::Blocked(_)));

        let rows = recorded_rows(&review);
        // The quarantine was consulted, and it is reported as consulted.
        assert!(
            rows.iter().any(|r| r.starts_with("blacklist clean")
                && r.contains("blacklist.json")
                && r.contains("1 entr(ies)")),
            "{rows:#?}"
        );
        // The verdict is the kernel's, produced by the load pipeline's own blacklist
        // stage: nothing here composes a blacklist refusal.
        let condemned: Vec<&String> = rows
            .iter()
            .filter(|r| r.starts_with("load:blacklist blocker"))
            .collect();
        assert_eq!(condemned.len(), 1, "{rows:#?}");
        assert!(condemned[0].contains("is blacklisted for"), "{rows:#?}");
        assert!(condemned[0].contains("malware"), "{rows:#?}");
        assert!(
            rows.iter().any(|r| r.starts_with("blacklist-entry note")
                && r.contains("an entry names this plugin")),
            "{rows:#?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.starts_with("load-pipeline blocker") && r.contains("blacklist")),
            "{rows:#?}"
        );
    }

    #[test]
    fn a_pinned_entry_for_another_build_does_not_condemn_the_submission() {
        // The kernel's path back from a condemnation is a new build, and `Blacklist::check`
        // expresses exactly that: an entry pinned to another artefact does not apply.
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (_sub, review, manifest_path) = submission("blk-pinned", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        let vendor = keypair(42);
        let vendor_hex = hex::encode(vendor.verifying_key().to_bytes());
        write_blacklist(
            &review,
            &[blacklist_entry(
                "io.example.analytics",
                Some(&"bb".repeat(32)),
                &vendor,
            )],
        );

        scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            &vendor_hex,
        ]))
        .expect("a different build is deliberately not condemned");

        let rows = recorded_rows(&review);
        assert!(
            rows.iter().any(|r| r.starts_with("blacklist clean")),
            "{rows:#?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.starts_with("blacklist-entry note") && r.contains("pins")),
            "{rows:#?}"
        );
        assert!(
            rows.iter().any(|r| r.starts_with("load-pipeline clean")),
            "{rows:#?}"
        );
    }

    #[test]
    fn a_corrupt_or_tampered_blacklist_is_a_typed_refusal_that_names_the_entry() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (_sub, review, manifest_path) = submission("blk-tampered", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        let vendor = keypair(42);
        let vendor_hex = hex::encode(vendor.verifying_key().to_bytes());

        // A hand-edited entry: the evidence was changed after signing, so the signature
        // no longer covers it. It must be a refusal that names the entry, never a list
        // that is quietly treated as empty.
        let mut edited = blacklist_entry("io.example.analytics", None, &vendor);
        edited.evidence_cid = "bafyforged".to_string();
        write_blacklist(&review, &[edited]);
        let err = scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            &vendor_hex,
        ]))
        .expect_err("a tampered entry must not be ignored");
        // The shared loader's own code and entry number, verbatim.
        assert_eq!(err.kind(), "entry-refused");
        assert!(err.detail().contains("entry #1"), "{}", err.detail());
        assert!(
            err.detail().contains("io.example.analytics"),
            "{}",
            err.detail()
        );
        assert!(err.detail().contains("does not verify"), "{}", err.detail());

        // Not a JSON array of entries at all.
        std::fs::write(review.join(BLACKLIST_FILE), "{ not json").expect("write");
        let err = scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            &vendor_hex,
        ]))
        .expect_err("a corrupt file is a refusal");
        assert_eq!(err.kind(), "corrupt-blacklist");
        assert!(
            err.detail().contains("is not a JSON array"),
            "{}",
            err.detail()
        );

        // Nothing was journaled: a blacklist this host cannot verify is not a finding
        // about the submission, and it must not become a recorded scan.
        assert_eq!(
            read_journal(&review).expect("journal").events.len(),
            1,
            "a refused blacklist must not be recorded as a scan"
        );
    }

    #[test]
    fn blacklist_entries_without_a_trusted_vendor_key_are_refused_not_treated_as_empty() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (_sub, review, manifest_path) = submission("blk-nokey", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        let vendor = keypair(42);
        write_blacklist(
            &review,
            &[blacklist_entry("io.example.analytics", None, &vendor)],
        );

        // Fail-closed: an entry nobody on the command line is trusted to have signed
        // cannot be verified, and an unverified list is not an empty one.
        let err = scan(&args(&["--dir", &dir, "--manifest", &manifest_path]))
            .expect_err("unverifiable entries must not be ignored");
        assert_eq!(err.kind(), "no-trusted-key");
        assert!(
            err.detail().contains("no trusted vendor key was given"),
            "{}",
            err.detail()
        );
        assert!(
            err.detail()
                .contains("unverified blacklist is not an empty one"),
            "{}",
            err.detail()
        );

        // A key that is not a key is a usage error, like every other flag value.
        let err = scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            "not-a-key",
        ]))
        .expect_err("a malformed vendor key is a usage error");
        assert_eq!(err.kind(), "usage");

        assert_eq!(read_journal(&review).expect("journal").events.len(), 1);
    }

    #[test]
    fn the_two_drivers_refuse_the_same_blacklist_identically() {
        // The property the duplication threatened: both drivers run the same
        // `plugin_blacklist::load_verified`, so one file has to produce one verdict. Two
        // loaders that agree today are two loaders that disagree after the next edit, and
        // nothing would notice.
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (_sub, review, manifest_path) = submission("blk-shared", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        let vendor = keypair(42);
        let vendor_hex = hex::encode(vendor.verifying_key().to_bytes());
        let mut trust = TrustStore::deny_all();
        trust.trust_vendor_key(&vendor_hex).expect("trust");
        let path = review.join(BLACKLIST_FILE);

        // A hand-edited entry: signed by a trusted vendor, changed after signing.
        let mut edited = blacklist_entry("io.example.analytics", None, &vendor);
        edited.evidence_cid = "bafyforged".to_string();
        write_blacklist(&review, &[edited]);

        // Ground truth: the shared loader's own verdict, which both callers run.
        let shared = crate::plugin_blacklist::load_verified(&path, &trust).expect_err("refused");
        assert_eq!(shared.code(), "entry-refused");
        assert!(shared.detail().contains("entry #1"), "{}", shared.detail());

        // Through the review driver: the same code, the same entry number.
        let from_review = scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            &vendor_hex,
        ]))
        .expect_err("the review driver refuses it");
        assert_eq!(from_review.kind(), shared.code());
        assert!(
            from_review.detail().contains("entry #1"),
            "{}",
            from_review.detail()
        );

        // Through the blacklist driver's own entry point. `check` is CLI-shaped — it
        // prints and returns an exit code — so what is asserted here is that it refuses;
        // the code equality above is asserted against the shared loader that call runs.
        let via_check = crate::plugin_blacklist::check(&args(&[
            "--dir",
            &dir,
            "--name",
            "io.example.analytics",
            "--vendor",
            &vendor_hex,
        ]));
        assert_eq!(via_check, ExitCode::from(1));

        // And the same for a file that is not a JSON array at all: `corrupt-blacklist` is
        // the shared loader's code, not something the review driver invented.
        std::fs::write(&path, "{ not json").expect("write");
        let shared = crate::plugin_blacklist::load_verified(&path, &trust).expect_err("refused");
        assert_eq!(shared.code(), "corrupt-blacklist");
        let from_review = scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            &vendor_hex,
        ]))
        .expect_err("the review driver refuses it");
        assert_eq!(from_review.kind(), shared.code());
        let via_check = crate::plugin_blacklist::check(&args(&[
            "--dir",
            &dir,
            "--name",
            "io.example.analytics",
            "--vendor",
            &vendor_hex,
        ]));
        assert_eq!(via_check, ExitCode::from(1));
    }

    #[test]
    fn a_review_cannot_leave_auto_scanned_without_a_scan() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (_sub, review, manifest_path) = submission("noscan", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        advance(&args(&[
            "--dir",
            &dir,
            "--to",
            "auto_scanned",
            "--because",
            "looking",
        ]))
        .expect("legal");
        let err = advance(&args(&[
            "--dir",
            &dir,
            "--to",
            "manual_review",
            "--because",
            "queue it",
        ]))
        .expect_err("a review with no scan must not advance");
        assert!(
            err.detail().contains("no scan recorded"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_hand_edited_journal_is_refused_by_the_machine_and_the_event_is_named() {
        let journal = Journal {
            version: JOURNAL_VERSION,
            events: vec![
                JournalEvent::Submitted {
                    plugin: "io.example.a".into(),
                    publisher: PUBLISHER_DID.into(),
                    at: NOW,
                    manifest_digest: String::new(),
                },
                JournalEvent::Advanced {
                    to: ReviewStage::Certified,
                    because: "looks fine".into(),
                    at: NOW,
                },
            ],
        };
        let err = replay(&journal).expect_err("a skipped stage is not a history");
        assert!(err.detail().contains("advanced[1]"), "{}", err.detail());
        assert!(
            err.detail().contains("not a review edge"),
            "{}",
            err.detail()
        );

        // A journal that leaves auto_scanned with no scan is refused for that reason.
        let journal = Journal {
            version: JOURNAL_VERSION,
            events: vec![
                JournalEvent::Submitted {
                    plugin: "io.example.a".into(),
                    publisher: PUBLISHER_DID.into(),
                    at: NOW,
                    manifest_digest: String::new(),
                },
                JournalEvent::Advanced {
                    to: ReviewStage::AutoScanned,
                    because: "scan stage".into(),
                    at: NOW,
                },
                JournalEvent::Advanced {
                    to: ReviewStage::ManualReview,
                    because: "queue it".into(),
                    at: NOW,
                },
            ],
        };
        let err = replay(&journal).expect_err("no scan, no advance");
        assert!(err.detail().contains("advanced[2]"), "{}", err.detail());
        assert!(
            err.detail().contains("no scan recorded"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_blocker_in_a_replayed_scan_stops_certification() {
        let mut report = ScanReport::default();
        report.push("anything", Finding::Blocker, "a blocker");
        let journal = Journal {
            version: JOURNAL_VERSION,
            events: vec![
                JournalEvent::Submitted {
                    plugin: "io.example.a".into(),
                    publisher: PUBLISHER_DID.into(),
                    at: NOW,
                    manifest_digest: String::new(),
                },
                JournalEvent::Scanned { report },
                JournalEvent::Advanced {
                    to: ReviewStage::Rejected,
                    because: "blocker unfixed".into(),
                    at: NOW,
                },
            ],
        };
        // Rejection is reachable with a blocker -- that is what a blocker should lead to.
        let replayed = replay(&journal).expect("rejects legally");
        assert_eq!(replayed.review.stage(), ReviewStage::Rejected);

        // And the same blocker cannot be certified over.
        let journal = Journal {
            version: JOURNAL_VERSION,
            events: vec![
                JournalEvent::Submitted {
                    plugin: "io.example.a".into(),
                    publisher: PUBLISHER_DID.into(),
                    at: NOW,
                    manifest_digest: String::new(),
                },
                JournalEvent::Certified {
                    scope: vec!["plugin:message:send".into()],
                    vendor_key: vendor_key_hex(),
                    at: NOW,
                },
            ],
        };
        let err = replay(&journal).expect_err("not certified");
        assert!(
            err.detail().contains("cannot be certified"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_second_certification_is_refused_by_replay() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (review, _) = drive_to_certified(&m, "twice");
        let dir = review.display().to_string();
        certify(&args(&[
            "--dir",
            &dir,
            "--scope",
            "plugin:message:send",
            "--vendor-key",
            &vendor_key_hex(),
            "--at",
            "1750000002",
        ]))
        .expect("certifies");

        let err = certify(&args(&[
            "--dir",
            &dir,
            "--scope",
            "plugin:message:send",
            "--vendor-key",
            &vendor_key_hex(),
            "--at",
            "1750000003",
        ]))
        .expect_err("one grant, not two");
        assert!(err.detail().contains("already issued"), "{}", err.detail());

        // The same rule applies when the journal itself is edited to hold two grants.
        let mut journal = read_journal(&review).expect("journal");
        journal.events.push(JournalEvent::Certified {
            scope: vec!["plugin:message:send".into()],
            vendor_key: vendor_key_hex(),
            at: NOW,
        });
        let err = replay(&journal).expect_err("refused");
        assert!(err.detail().contains("already issued"), "{}", err.detail());
    }

    #[test]
    fn a_scope_the_tier_cannot_hold_is_refused_at_certification() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (review, _) = drive_to_certified(&m, "scope");
        let err = certify(&args(&[
            "--dir",
            &review.display().to_string(),
            "--scope",
            "economy:settle",
            "--vendor-key",
            &vendor_key_hex(),
            "--at",
            "1750000002",
        ]))
        .expect_err("T3 may never hold economy:settle");
        assert!(err.detail().contains("economy:settle"), "{}", err.detail());
        assert!(err.detail().contains("3rd"), "{}", err.detail());

        // An empty scope and a key that is not a key are usage refusals.
        let err = certify(&args(&[
            "--dir",
            &review.display().to_string(),
            "--scope",
            " , ",
            "--vendor-key",
            &vendor_key_hex(),
        ]))
        .expect_err("an empty scope certifies nothing");
        assert_eq!(err.kind(), "usage");
        assert!(
            err.detail().contains("at least one capability"),
            "{}",
            err.detail()
        );

        let err = certify(&args(&[
            "--dir",
            &review.display().to_string(),
            "--scope",
            "plugin:message:send",
            "--vendor-key",
            "not-a-key",
        ]))
        .expect_err("a certification needs a real key to attribute it to");
        assert_eq!(err.kind(), "usage");

        // Nothing was written: the review still has no certification.
        let replayed = replay(&read_journal(&review).expect("journal")).expect("replays");
        assert!(replayed.certification.is_none());
    }

    #[test]
    fn a_malformed_journal_is_a_typed_refusal_not_a_panic() {
        let dir = scratch("malformed");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(journal_path(&dir), "{ not a journal").expect("write");
        let err = read_journal(&dir).expect_err("must be refused");
        assert!(
            err.detail().contains("is not a review journal"),
            "{}",
            err.detail()
        );

        let dir_string = dir.display().to_string();
        let err = show(&args(&["--dir", &dir_string])).expect_err("refused");
        assert_eq!(err.kind(), "journal_refused");

        // An unknown format version is refused too, rather than best-effort parsed.
        std::fs::write(
            journal_path(&dir),
            serde_json::json!({ "version": 99, "events": [] }).to_string(),
        )
        .expect("write");
        let err = read_journal(&dir).expect_err("refused");
        assert!(err.detail().contains("version 99"), "{}", err.detail());

        // An unknown key is refused rather than ignored, the posture every manifest in
        // this project takes: a typo'd key must not read as a rule that is in force.
        std::fs::write(
            journal_path(&dir),
            serde_json::json!({
                "version": JOURNAL_VERSION,
                "events": [{
                    "kind": "submitted",
                    "plugin": "io.example.a",
                    "publisher": PUBLISHER_DID,
                    "at": NOW,
                    "manifest_digest": "",
                    "surprise": 1
                }]
            })
            .to_string(),
        )
        .expect("write");
        let err = read_journal(&dir).expect_err("an unknown key must be refused");
        assert!(err.detail().contains("surprise"), "{}", err.detail());
    }

    #[test]
    fn open_refuses_a_second_review_and_a_publisher_that_is_not_the_manifests() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (_sub, review, manifest_path) = submission("openrefuse", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        let err = open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect_err("a directory holds one review");
        assert!(
            err.detail().contains("already holds a review"),
            "{}",
            err.detail()
        );

        let other = review.join("other");
        let err = open(&args(&[
            "--dir",
            &other.display().to_string(),
            "--manifest",
            &manifest_path,
            "--publisher",
            "did:nau:ffffffffffffffff",
        ]))
        .expect_err("the review must name the manifest's publisher");
        assert_eq!(err.kind(), "usage");
        assert!(
            err.detail().contains("not the manifest's publisher"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_manifest_that_drifted_after_open_is_a_blocker() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (sub, review, manifest_path) = submission("drift", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");

        // The publisher edits the document after the review was opened: the reviewed
        // document is no longer the submitted one.
        let mut edited = m.clone();
        edited.capabilities.grant = vec!["plugin:storage:own".into()];
        edited.signature.manifest_digest = edited.digest_hex().expect("digest");
        let digest = edited.signature.manifest_digest.clone();
        let publisher = keypair(7);
        edited.signature.sig = hex::encode(publisher.sign(digest.as_bytes()).to_bytes());
        std::fs::write(
            sub.join("plugin.json"),
            serde_json::to_string_pretty(&edited).expect("json"),
        )
        .expect("write");

        scan(&args(&["--dir", &dir, "--manifest", &manifest_path]))
            .expect_err("the document changed");
        let replayed = replay(&read_journal(&review).expect("journal")).expect("replays");
        let rows: Vec<String> = replayed
            .review
            .scan()
            .checks
            .iter()
            .map(|c| format!("{} {}", c.check, c.detail))
            .collect();
        assert!(
            rows.iter()
                .any(|r| r.starts_with("manifest-digest") && r.contains("changed")),
            "{rows:#?}"
        );
    }

    #[test]
    fn a_certified_submission_asking_for_an_approval_gated_capability_can_be_reviewed_and_certified(
    ) {
        // The arc a `com.twinsearth.certified.*` plugin has to be able to walk, and could not.
        //
        // Three separate things blocked it, each one a check refusing something it existed to
        // permit:
        //
        // 1. The flow hardcoded `Tier::ThirdParty` for the capability decision, so a
        //    capability the **certified** tier holds with the committee's approval was
        //    reported as `Grant::Refused` at T3 and blocked.
        // 2. The row for `Grant::RequiresApproval` was itself a **Blocker** -- so the flow
        //    refused a capability conditional on an approval while being the only place that
        //    approval could be granted.
        // 3. The load trust held only the **publisher** key, so the vendor counter-signature
        //    the certified tier *requires* could never verify, and the scan blocked on the
        //    tier's own defining requirement.
        //
        // All three at once meant the certified tier could not be reached by the tool that
        // exists to reach it. This test walks the whole arc and asserts the endpoint.
        let vendor = keypair(9);
        let name = "com.twinsearth.certified.analytics";
        let mut m = manifest(
            name,
            // `net:dht:read` is `RequiresApproval(CertificationCommittee)` at the certified
            // tier and `Refused` at the third-party tier, which is what makes it the right
            // probe: it is the capability the certified tier exists to be certified for.
            &["plugin:message:send", "net:dht:read"],
            &waivers(),
        );
        let digest = m.signature.manifest_digest.clone();
        m.signature.counter_sig = Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
        m.signature.counter_key = Some(hex::encode(vendor.verifying_key().to_bytes()));

        let (_sub, review, manifest_path) = submission("t2arc", &m);
        let dir = review.display().to_string();
        let vendor_hex = hex::encode(vendor.verifying_key().to_bytes());
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");

        // Recorded rather than asserted here, so a failure can print the rows.
        let scan_result = scan(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--vendor",
            &vendor_hex,
        ]));

        // The scan must have recorded the capability row as **held with approval**, not as a
        // blocker: that row is the review's subject matter, not its obstacle.
        let replayed = replay(&read_journal(&review).expect("journal")).expect("replays");
        let rows: Vec<String> = replayed
            .review
            .scan()
            .checks
            .iter()
            .map(|c| format!("{} [{}] {}", c.check, c.finding.label(), c.detail))
            .collect();
        assert!(
            scan_result.is_ok(),
            "a certified submission asking for an approval-gated capability must be scannable \
             ({scan_result:?}): {rows:#?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.starts_with("capability:net:dht:read [clean]")
                    && r.contains("certification-committee")),
            "the approval-gated capability must be recorded as held with approval: {rows:#?}"
        );
        assert!(
            !replayed.review.scan().has_blocker(),
            "the scan must be blocker-free for a certifiable submission: {rows:#?}"
        );

        // And the review can be certified with that capability in scope, which is where the
        // approval is granted.
        for (to, because) in [
            ("auto_scanned", "scanned"),
            ("manual_review", "read"),
            ("grey_run", "trialled"),
        ] {
            advance(&args(&["--dir", &dir, "--to", to, "--because", because]))
                .unwrap_or_else(|e| panic!("advancing to {to}: {e:?}"));
        }
        advance(&args(&[
            "--dir",
            &dir,
            "--to",
            "certified",
            "--because",
            "approved",
        ]))
        .expect("certified");

        certify(&args(&[
            "--dir",
            &dir,
            "--scope",
            "plugin:message:send,net:dht:read",
            "--vendor-key",
            &vendor_hex,
        ]))
        .expect("the scope includes the capability the tier holds with approval");

        let replayed = replay(&read_journal(&review).expect("journal")).expect("replays");
        let certification = replayed.certification.expect("a certification");
        assert!(
            certification.scope.contains(&Capability::DhtRead),
            "the certification must cover the approval-gated capability: {:?}",
            certification.scope
        );

        // And the artefact a loader is handed exists, which is what makes the granted scope
        // reachable by the process that has to enforce it.
        assert!(
            review.join("certification.json").is_file(),
            "certify must write the artefact a loader is handed"
        );
    }

    #[test]
    fn a_name_that_is_not_third_party_is_a_blocker() {
        // The official tier, not the certified one. The certified tier became reviewable
        // when `certify` stopped hardcoding T3: a `com.twinsearth.certified.*` name is
        // exactly what a passed review produces, so using it here would have asserted that
        // the flow refuses what it exists to register. The official tier is
        // vendor-published and is not submitted for review.
        let m = manifest(
            "com.twinsearth.official.analytics",
            &["plugin:message:send"],
            &waivers(),
        );
        // The manifest is valid and signed, but it classifies as the certified tier,
        // which this registration flow does not review.
        let (_sub, review, manifest_path) = submission("tier", &m);
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        scan(&args(&["--dir", &dir, "--manifest", &manifest_path]))
            .expect_err("not a third-party name");
        let replayed = replay(&read_journal(&review).expect("journal")).expect("replays");
        let rows: Vec<String> = replayed
            .review
            .scan()
            .checks
            .iter()
            .map(|c| format!("{} {}", c.check, c.detail))
            .collect();
        assert!(
            rows.iter()
                .any(|r| r.starts_with("tier-classification") && r.contains("does not register")),
            "the blocker must say the flow does not register this tier: {rows:#?}"
        );
    }

    #[test]
    fn an_unreadable_entry_artefact_is_a_blocker_and_the_scan_is_still_recorded() {
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (sub, review, manifest_path) = submission("noentry", &m);
        std::fs::remove_file(sub.join("plugin.bin")).expect("remove");
        let dir = review.display().to_string();
        open(&args(&[
            "--dir",
            &dir,
            "--manifest",
            &manifest_path,
            "--publisher",
            PUBLISHER_DID,
        ]))
        .expect("opens");
        scan(&args(&["--dir", &dir, "--manifest", &manifest_path]))
            .expect_err("no artefact, no load");
        let replayed = replay(&read_journal(&review).expect("journal")).expect("replays");
        assert!(replayed.review.scan().has_blocker());
        assert!(!replayed.review.scan().checks.is_empty());
    }

    #[test]
    fn a_scan_after_the_decision_is_refused_without_touching_the_journal() {
        let mut report = ScanReport::default();
        report.push("anything", Finding::Clean, "fine");
        let dir = scratch("latescan");
        std::fs::create_dir_all(&dir).expect("dir");
        let m = manifest("io.example.analytics", &["plugin:message:send"], &waivers());
        let (sub, _review, manifest_path) = submission("latescan-sub", &m);
        let _ = sub;
        let journal = Journal {
            version: JOURNAL_VERSION,
            events: vec![
                JournalEvent::Submitted {
                    plugin: "io.example.analytics".into(),
                    publisher: PUBLISHER_DID.into(),
                    at: NOW,
                    manifest_digest: m.digest_hex().expect("digest"),
                },
                JournalEvent::Scanned { report },
                JournalEvent::Advanced {
                    to: ReviewStage::AutoScanned,
                    because: "scan done".into(),
                    at: NOW,
                },
                JournalEvent::Advanced {
                    to: ReviewStage::ManualReview,
                    because: "queue it".into(),
                    at: NOW,
                },
            ],
        };
        write_journal(&dir, &journal).expect("write");
        let err = scan(&args(&[
            "--dir",
            &dir.display().to_string(),
            "--manifest",
            &manifest_path,
        ]))
        .expect_err("a scan at manual_review cannot change the decision");
        assert!(
            err.detail().contains("could not change the decision"),
            "{}",
            err.detail()
        );
        let after = read_journal(&dir).expect("journal");
        assert_eq!(after.events.len(), 4, "the journal must be untouched");
    }
}
