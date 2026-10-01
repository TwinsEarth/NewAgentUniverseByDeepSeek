//! # nau-migrate — migrating upstream `agent-universe` v2.5.6 historical data
//!
//! Upstream `agent-universe` v2.5.6 and this project share an identity layer:
//! upstream's Ed25519 signatures verify byte-for-byte under this project's
//! canonical form, and [`nau_core::Did`] parses upstream's legacy `did:aip:`
//! prefix (`ATTRIBUTION.md` §3). What they do **not** share is storage and ledger
//! semantics — upstream recorded money as `f64` and checked conservation with a
//! `0.001` tolerance, this project uses exact integer minor units. This crate is
//! the migration between the two: it reads upstream-shaped artifacts, verifies
//! them, converts the money exactly, and refuses anything it cannot migrate
//! honestly.
//!
//! Version 1.1.0 and earlier said "no migration script exists". That statement was
//! true of those versions; this crate is the script.
//!
//! ## What upstream actually produced, and what this crate reads
//!
//! The artifacts below are the ones the audit of v2.5.6 found to be the canonical
//! records (`docs/GAP-ANALYSIS.md` §2, §4, §6). This crate reads:
//!
//! | Artifact | Read as | Notes |
//! |---|---|---|
//! | **AgentCard JSON** | `<root>/agents.json` (array) or `<root>/agents/*.json` (one object per file) | `did`/`agent_id`, `name`, `capabilities`/`skills`, `endpoint`, `price_per_task`/`price`, `stake`, `signature`; the signature covers the canonical JSON **minus** every `signature` key |
//! | **TaskRecord JSON** | `<root>/tasks.json` or `<root>/tasks/*.json` | `task_id`, `requester`, optional `executor`, `reward`/`budget`, `status`, `signature`, plus the six documented `TaskSpec` fields (`goal`/`context`/`done`/`todo`/`trace`/`owner`) |
//! | **Ledger JSONL** | `<root>/ledger.jsonl`, one object per line | amounts as decimal **strings or JSON numbers** (upstream used `f64`), `from`/`payer`, `to`/`payee`, `reason`, `task_id`, `ts` |
//! | `DID → public key` | `<root>/keys.json`, optional | upstream transported keys out of band and so must a migration: a DID is only a fingerprint |
//! | claimed balances | `<root>/balances.json`, optional | checked against the journal, never trusted |
//!
//! **That directory layout is this tool's reading convention over upstream-shaped
//! objects.** It is not a claim about upstream's own directory layout, and the
//! fields are looked up by every name the audit records for them.
//!
//! ### Not supported: any database
//!
//! Upstream v2.5.6 **did** ship a SQLite store (`rusqlite`, bundled) with four
//! tables — `agents`, `tasks`, `kv_meta`, `relays`
//! (`docs/GAP-ANALYSIS.md` §6.1, citing `storage/persist.rs:64,73,82,88`). The
//! reason this tool reads JSON/JSONL instead of that database is **not** that the
//! database did not exist: it is that nothing ever read it back
//! (`load_agents`/`load_tasks`/`upsert_task` had zero call sites, so the README's
//! "persisted to SQLite and restored on restart" was false as a claim about
//! behaviour), it had **no ledger or balance table of any kind** (`ATTRIBUTION.md`
//! §2.3: "账本从未持久化"), and the values it held were `f64`. Migrating the JSON
//! artifacts therefore migrates the only data that ever had semantic force, and it
//! migrates it exactly rather than through a float round-trip. Reading the SQLite
//! `agents`/`tasks` tables is possible in principle and is deliberately out of
//! scope; the schema is documented in `docs/GAP-ANALYSIS.md` §6.1. [`Finding::DatabaseIgnored`]
//! is reported when a database file is found, so the omission is visible rather
//! than silent.
//!
//! Also out of scope, for the same reason (no table, no file, nothing to read):
//! bids, disputes, reputation, memory, relay registries, and every in-memory map
//! that upstream never persisted.
//!
//! ## Honesty about the fixtures and about what was verified
//!
//! The fixtures in this crate's `tests/` are **authored to model the audited
//! upstream format**. They were **not** captured from a live upstream instance, and
//! no real upstream user data was migrated while building or testing this crate.
//! The one piece of genuine upstream data involved is stated where it appears: the
//! `upstream-v2.5.6-compat` payload in `conformance/vectors.json` is upstream's own
//! pinned cross-language test vector (public key, DID, canonical payload and
//! signature verbatim from `gsn-core/tests/cross_lang_signature.rs:11-14`), and the
//! tests reuse it as a real upstream-signed card.
//!
//! See "Limits" at the bottom of this page for exactly what the tests establish.
//!
//! ## Money: exact, or refused
//!
//! Upstream amounts arrive as decimal text (`"12.5"`, `0.1`, `1e-3`). They are
//! converted to `Money(i64)` minor units (six decimals) **from the bytes on disk**,
//! never through `f64`: this crate contains no float arithmetic at all, and
//! [`rawjson`] recovers the literal text of a field before [`amount`] parses the
//! digits. A value that needs a seventh decimal place (`0.0000001`, `1e-7`) is
//! refused with a [`MigrateError::AmountNotExact`] naming the file and the field —
//! never rounded. Exponent notation, signs and trailing zeros are all understood.
//!
//! The "no float arithmetic" property is checked with
//! `cargo clippy -p nau-migrate --all-targets -- -W clippy::float_arithmetic`,
//! which reports no finding under `crates/nau-migrate/` (the lint is a clippy
//! `restriction` lint and is off by default, so it has to be requested; the one
//! finding it reports anywhere in the graph is `nau-core`'s `ReputationScore::ratio`,
//! a reputation ratio that is not money and predates this crate).
//!
//! ## Signatures: verified against this project's canonical form
//!
//! A card or task is accepted only after its legacy signature verifies over *this*
//! project's canonical payload (every `signature` key dropped at every depth, keys
//! sorted by code point, no whitespace) with a key that really fingerprints the
//! claimed DID. Where upstream's payload cannot be reproduced that way — a float in
//! the signed payload is the common case, because upstream admitted floats — the
//! record is rejected with the reason named ([`Finding::LegacyFloatInSignedPayload`]).
//!
//! ## Every difference is reported
//!
//! Nothing is coerced silently. Each finding carries a stable [`Finding`] code, a
//! [`Severity`] and the source file:
//!
//! | Difference | How it is reported |
//! |---|---|
//! | `did:aip:` prefix | kept verbatim (this project parses both prefixes) and noted as legacy |
//! | upstream `f64` balances with a `0.001` tolerance | the journal is re-derived exactly; a claim that does not reconcile becomes a [`Finding::BalanceDiscrepancy`] with the exact difference, and the derived value wins |
//! | upstream status with no counterpart | rejected, with the upstream status named ([`Finding::UnsupportedStatus`]) |
//! | duplicate registration | later record wins, earlier one reported (upstream overwrote the map entry *and* deposited the stake twice, GAP §2.6) |
//! | missing fields the target requires | rejected with the field and the reason |
//! | defaults that had to be chosen | listed per record ([`Finding::DefaultsFilled`]) |
//! | the imported card/task cannot carry the legacy signature | stored unsigned, with [`Finding::TargetNotWireValid`], and the verified legacy signature preserved in the plan |
//!
//! ## Two stages, and a CLI
//!
//! ```text
//! nau-migrate plan  --from <dir> [--strict]           # JSON plan on stdout, summary on stderr; writes nothing
//! nau-migrate apply --from <dir> --store <dir> [--yes] [--strict]
//! nau-migrate version
//! ```
//!
//! `apply` is a **dry run by default**: without `--yes` it applies the plan to an
//! in-memory store (the same code path) and prints the report, writing nothing to
//! disk. Programme: [`plan_from_dir()`] then [`apply()`].
//!
//! ## Limits
//!
//! * The conversion is verified against authored fixtures and against upstream's
//!   own conformance vector — not against a live v2.5.6 instance, and not against
//!   any SQLite artifact.
//! * `apply` re-checks the evidence the plan carries (signature over the recorded
//!   payload, amount over the recorded verbatim text). That proves the plan was not
//!   altered after it was produced; it does not re-read the source tree, which may
//!   be gone.
//! * The migrated ledger is appended to the store; nothing re-derives market state
//!   (escrow, disputes) from it, because upstream never persisted that state.
//! * A migrated card or task is stored **unsigned**, because a migration has no
//!   private key. It must be re-signed by its owner before it is served.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
// Floating-point money is *the* defect this crate migrates away from, so this
// crate contains no float arithmetic at all: every amount is an exact `i64` count
// of minor units. That is checked, not asserted, with
//     cargo clippy -p nau-migrate --all-targets -- -W clippy::float_arithmetic
// which reports no finding under `crates/nau-migrate/`. (It does report exactly one
// finding elsewhere in the graph: `nau-core`'s `ReputationScore::ratio`, a
// reputation ratio that is not money and predates this crate.) The lint is a clippy
// `restriction` lint and is off by default, so it has to be requested; a crate-level
// `#![deny(clippy::float_arithmetic)]` attribute did not take effect on the
// toolchain this crate was built with and was removed rather than left in place as
// decoration.

pub mod amount;
pub mod apply;
pub mod error;
pub mod field;
pub mod ledger;
pub mod legacy;
pub mod plan;
pub mod rawjson;
pub mod warning;

pub use amount::{amount_from_decimal, parse_decimal_exact, AmountDefect};
pub use apply::{apply, MigrationReport, IMPORTED_KEY};
pub use error::{MigrateError, Result};
pub use ledger::{AccountBalance, LedgerKind, PlannedEntry};
pub use legacy::{keys_from_json, verify_legacy_record, KeyRegistry, RecordSource, VerifiedLegacy};
pub use plan::{
    map_status, plan_from_dir, state_name, MigrationPlan, PlanSummary, PlannedAgent, PlannedTask,
    AGENTS_AGGREGATE, AGENTS_SUBDIR, BALANCES_FILE, KEYS_FILE, LEDGER_FILE, SCHEMA_KEY,
    SCHEMA_VALUE, SOURCE_DIGEST_KEY, TASKS_AGGREGATE, TASKS_SUBDIR,
};
pub use rawjson::{root_slices, top_level_scalar, RawScalar, ScanError};
pub use warning::{Defect, Finding, Severity, Warning};

#[cfg(test)]
mod tests {
    /// The crate-level claim that matters most: there is no float arithmetic here.
    ///
    /// The statement below is the human-readable half. The mechanical half is a
    /// command, documented on the crate: `cargo clippy -p nau-migrate --all-targets
    /// -- -W clippy::float_arithmetic` reports no finding under
    /// `crates/nau-migrate/`, because every amount in this crate is an exact integer
    /// count of minor units and there is not one floating-point operation to find.
    #[test]
    fn the_money_path_never_needs_a_float() {
        for (literal, minor) in [
            ("0.1", 100_000_i64),
            ("0.2", 200_000),
            ("0.3", 300_000),
            ("1e-3", 1_000),
            ("12.5", 12_500_000),
            ("100.0", 100_000_000),
        ] {
            assert_eq!(
                crate::parse_decimal_exact(literal).expect("exact").minor(),
                minor
            );
        }
    }
}
