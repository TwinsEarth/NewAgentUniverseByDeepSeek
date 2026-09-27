//! The `nau-migrate` binary: what it writes, what it refuses, and its exit codes.
//!
//! These tests deliberately do not capture the child's output (`Stdio::null()`
//! rather than a pipe): the assertions are about the *effect* — files created or
//! not created — and about the exit status, which needs no pipe to observe. The
//! human summaries and the JSON on stdout are covered by `plan` and `apply` being
//! driven through the library in `end_to_end.rs`.
//!
//! The fixture tree is authored to model the audited upstream v2.5.6 format; see
//! `tests/common/mod.rs`.

mod common;

use std::process::{Command, Stdio};

use common::build_upstream_tree;
use nau_store::{FileStore, Store};

/// Run the binary and return its exit code.
fn run(args: &[&str]) -> i32 {
    let status = Command::new(env!("CARGO_BIN_EXE_nau-migrate"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the nau-migrate binary runs");
    status.code().unwrap_or(-1)
}

#[test]
fn the_dry_run_writes_nothing_and_yes_writes_everything() {
    let tree = build_upstream_tree("cli");
    let root = tree.root().display().to_string();
    let store_dir = tree.scratch.path("store");
    let store_arg = store_dir.display().to_string();

    assert_eq!(run(&["plan", "--from", &root]), 0);
    assert_eq!(
        run(&["plan", "--from", &root, "--strict"]),
        1,
        "--strict must fail when records were refused"
    );

    assert_eq!(
        run(&["apply", "--from", &root, "--store", &store_arg]),
        0,
        "the default is a dry run, which must succeed"
    );
    assert!(
        !store_dir.exists(),
        "a dry run must not create the store directory"
    );

    assert_eq!(
        run(&["apply", "--from", &root, "--store", &store_arg, "--yes"]),
        0
    );
    assert!(store_dir.exists(), "--yes must write");

    let store = FileStore::open(&store_dir).expect("open the store the CLI wrote");
    assert_eq!(store.load_agents().expect("agents").len(), 3);
    assert_eq!(store.load_tasks().expect("tasks").len(), 1);
    assert_eq!(store.load_ledger().expect("ledger").len(), 7);
    assert!(store
        .get_meta("nau-migrate.source-digest")
        .expect("meta")
        .is_some());

    assert_ne!(
        run(&["apply", "--from", &root, "--store", &store_arg, "--yes"]),
        0,
        "applying the same plan twice must be refused, not duplicated"
    );
    assert_eq!(
        store.load_ledger().expect("ledger").len(),
        7,
        "the append-only journal was not written a second time"
    );
}

#[test]
fn usage_errors_exit_two_and_missing_sources_exit_one() {
    let tree = build_upstream_tree("cli-usage");
    let root = tree.root().display().to_string();

    assert_eq!(run(&["apply", "--from", &root]), 2, "--store is required");
    assert_eq!(run(&["plan"]), 2, "--from is required");
    assert_eq!(run(&["teleport"]), 2, "unknown commands are usage errors");
    assert_eq!(
        run(&[
            "apply",
            "--from",
            tree.scratch.path("nope").to_str().expect("utf-8"),
            "--store",
            tree.scratch.path("store").to_str().expect("utf-8"),
        ]),
        1,
        "a source tree that does not exist is a real error"
    );
    assert_eq!(run(&["version"]), 0);
    assert_eq!(run(&["--version"]), 0);
    assert_eq!(run(&["help"]), 0);
    assert_eq!(run(&["--help"]), 0);
}
