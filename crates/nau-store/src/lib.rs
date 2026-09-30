//! # nau-store — durable persistence that is actually read back
//!
//! This crate replaces upstream `agent-universe` v2.5.6
//! `gsn-core/src/storage/persist.rs`. It is the *port* through which market
//! state survives a restart: agent cards, tasks, ledger entries and small
//! key/value metadata.
//!
//! ## Upstream defects this crate fixes
//!
//! | # | Upstream defect | Fix here |
//! |---|---|---|
//! | 1 | **Write-only storage.** `upsert_agent` was called on registration but `load_agents`/`load_tasks` had zero call sites and `upsert_task` was never called at all, so market state vanished on restart while the README claimed "真实落盘并在重启后恢复". | [`Store::load_agents`] / [`Store::load_tasks`] exist and a reopen round-trip is proven in `tests/store_contract.rs`. |
//! | 2 | **The ledger was never persisted.** There was no balances/entries table at all. | [`Store::append_ledger`] / [`Store::load_ledger`] with an append-only `ledger.jsonl`. |
//! | 3 | **Persistence diverged from validated state.** The stored row was rebuilt from the raw request body: `skills` was flattened with `join(",")`, `reputation` was hardcoded to `0.0`, `created_at` was regenerated. | The exact validated [`AgentCard`]/[`Task`] is stored as canonical JSON, so `load` returns byte-identical field values; asserted in tests. |
//! | 4 | **`.lock().unwrap()` on 18 sites**, so one panicking request poisoned every later storage call. | Every lock acquisition goes through [`sync`](crate) helpers that recover from poisoning; no public method panics. |
//!
//! ## Design
//!
//! * **Append-only JSONL.** `agents.jsonl`, `tasks.jsonl` and `ledger.jsonl`
//!   each receive one canonical JSON object per line, written with a single
//!   `write` call on a file opened in append mode and followed by `sync_data`.
//!   A record is never modified in place, so a crash can only damage the tail.
//! * **Torn-write tolerance.** A line that is not valid JSON (or carries a
//!   different schema marker) is skipped with a `tracing::warn!` instead of
//!   failing the whole load — which is what a crash mid-append leaves behind.
//! * **Explicit caps.** A single record may not exceed
//!   [`MAX_RECORD_BYTES`](jsonl::MAX_RECORD_BYTES), and a load refuses to
//!   materialise more than [`FileStore::DEFAULT_MAX_RECORDS`] records per file
//!   so that a runaway log is compacted rather than silently eating the heap.
//! * **`meta.json`** is small and is *atomically replaced* (temp file, fsync,
//!   rename) rather than appended.
//!
//! ## Example
//!
//! ```no_run
//! use nau_store::{FileStore, Store};
//!
//! # fn main() -> nau_core::Result<()> {
//! let store = FileStore::open("data/node-1")?;
//! store.set_meta("schema", "1")?;
//! store.flush()?;
//! let reopened = FileStore::open("data/node-1")?;
//! assert_eq!(reopened.get_meta("schema")?.as_deref(), Some("1"));
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod file;
pub mod journal;
pub mod jsonl;
pub mod memory;
pub mod store;
mod sync;

pub use file::FileStore;
pub use journal::{
    JournalAnchor, JournalBreak, JournalBreakKind, LinkedRecord, LoadedJournal, LEDGER_ANCHOR_KEY,
    LINKED_SCHEMA_VERSION,
};
pub use jsonl::{Record, MAX_RECORD_BYTES, SCHEMA_VERSION};
pub use memory::MemoryStore;
pub use store::Store;
