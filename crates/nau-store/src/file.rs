//! Crash-safe, append-only, file-backed [`Store`].
//!
//! Layout of the directory given to [`FileStore::open`]:
//!
//! ```text
//! <dir>/agents.jsonl   append-only, one record per saved card (last-write-wins by DID)
//! <dir>/tasks.jsonl    append-only, one record per saved task (last-write-wins by id)
//! <dir>/ledger.jsonl   append-only, one record per ledger entry (never deduped)
//! <dir>/meta.json      small key/value object, atomically replaced
//! ```
//!
//! Durability rules:
//!
//! * an append writes the whole line with one `write` call and then `sync_data`s
//!   it, so a crash can only damage the tail;
//! * [`FileStore::compact`] and [`Store::set_meta`] write a temp file, fsync it,
//!   and `rename` it over the target (atomic on the same filesystem), so a crash
//!   leaves either the old or the new file, never a half-written one;
//! * a torn tail is skipped on load with a warning (see [`crate::jsonl`]).
//!
//! Upstream v2.5.6 analogous code (`gsn-core/src/storage/persist.rs`) had none of
//! this: `upsert_agent` was the only method with a call site, the loaded rows
//! were rebuilt from the raw request body instead of the validated object, and a
//! single poisoned mutex made every later call panic.

use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use nau_core::{AgentCard, NauError, Result, Task};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::jsonl;
use crate::store::Store;
use crate::sync;

/// File name of the agent card log.
pub const AGENTS_FILE: &str = "agents.jsonl";
/// File name of the task log.
pub const TASKS_FILE: &str = "tasks.jsonl";
/// File name of the ledger log.
pub const LEDGER_FILE: &str = "ledger.jsonl";
/// File name of the atomically-replaced metadata object.
pub const META_FILE: &str = "meta.json";

/// A [`Store`] backed by a directory of append-only JSONL files.
///
/// All operations are file-system operations taken under a single
/// poison-recovering `RwLock<()>`: readers share, mutators (append, compact,
/// meta write) exclude. The lock exists to keep concurrent appends from
/// interleaving *within* a line and to keep a compaction from removing a file
/// while another thread reads it — it never guards domain state, because the
/// files are the state.
#[derive(Debug)]
pub struct FileStore {
    dir: PathBuf,
    max_records: usize,
    lock: RwLock<()>,
}

impl FileStore {
    /// Largest number of records a single file may contain before a load
    /// refuses to materialise it.
    ///
    /// An explicit cap: the log grows by design, so a caller that never compacts
    /// must be told to, rather than have the certificate-sized heap allocated
    /// and then die.
    pub const DEFAULT_MAX_RECORDS: usize = 1_000_000;

    /// Open (creating it if missing) the store directory `dir`.
    ///
    /// Any pre-existing files are read on demand; nothing is loaded eagerly, so
    /// opening is cheap and cannot fail on a corrupt tail.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_capped(dir, Self::DEFAULT_MAX_RECORDS)
    }

    /// [`FileStore::open`] with an explicit per-file record cap.
    ///
    /// Mostly useful in tests and on memory-constrained nodes.
    pub fn open_capped(dir: impl AsRef<Path>, max_records: usize) -> Result<Self> {
        if max_records == 0 {
            return Err(NauError::Validation(
                "max_records must be at least 1 (a store that can hold nothing cannot load anything)"
                    .into(),
            ));
        }
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        tracing::debug!(dir = %dir.display(), "opened file store");
        Ok(Self {
            dir,
            max_records,
            lock: RwLock::new(()),
        })
    }

    /// The directory this store owns.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The per-file record cap this store enforces on load.
    pub fn max_records(&self) -> usize {
        self.max_records
    }

    /// Path of one of the store's files.
    pub fn path_of(&self, file_name: &str) -> PathBuf {
        self.dir.join(file_name)
    }

    /// Atomically rewrite every log with one line per *current* record.
    ///
    /// Equivalent to log rotation: the visible state before and after is
    /// identical (asserted in tests), but superseded records and torn tails are
    /// gone. Crash-safe: each file is written to `<name>.tmp`, fsynced, and then
    /// renamed over the original.
    pub fn compact(&self) -> Result<()> {
        let _guard = sync::write(&self.lock);

        let agents = self.agents_index()?;
        write_atomic(&self.path_of(AGENTS_FILE), |writer| {
            for (key, card) in &agents {
                write_record(writer, Some(key), &serde_json::to_value(card)?)?;
            }
            Ok(())
        })?;

        let tasks = self.tasks_index()?;
        write_atomic(&self.path_of(TASKS_FILE), |writer| {
            for (key, task) in &tasks {
                write_record(writer, Some(key), &serde_json::to_value(task)?)?;
            }
            Ok(())
        })?;

        let ledger = jsonl::read_records(&self.path_of(LEDGER_FILE), self.max_records)?;
        write_atomic(&self.path_of(LEDGER_FILE), |writer| {
            for record in &ledger {
                write_record(writer, None, &record.payload)?;
            }
            Ok(())
        })?;

        tracing::debug!(dir = %self.dir.display(), "compacted file store");
        Ok(())
    }

    /// Agent cards by DID, newest content last-write-wins. Caller must hold the lock.
    fn agents_index(&self) -> Result<BTreeMap<String, AgentCard>> {
        load_indexed(
            &self.path_of(AGENTS_FILE),
            self.max_records,
            |card: &AgentCard| card.owner.to_string(),
        )
    }

    /// Tasks by id, newest content last-write-wins. Caller must hold the lock.
    fn tasks_index(&self) -> Result<BTreeMap<String, Task>> {
        load_indexed(
            &self.path_of(TASKS_FILE),
            self.max_records,
            |task: &Task| task.id.to_string(),
        )
    }

    /// The metadata object, or an empty map when the file is absent.
    fn meta_map(&self) -> Result<serde_json::Map<String, Value>> {
        let path = self.path_of(META_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(serde_json::Map::new())
            }
            Err(err) => return Err(NauError::Io(err)),
        };
        if bytes.is_empty() {
            return Ok(serde_json::Map::new());
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        match value {
            Value::Object(map) => Ok(map),
            other => Err(NauError::Validation(format!(
                "`{}` must hold a JSON object, found `{other}`",
                path.display()
            ))),
        }
    }
}

impl Store for FileStore {
    fn save_agent(&self, card: &AgentCard) -> Result<()> {
        // upstream v2.5.6 fix: the *validated* card is stored, as canonical
        // JSON, instead of a lossy row rebuilt from the raw request body
        // (`skills.join(",")`, hardcoded `reputation: 0.0`, regenerated
        // `created_at`). What is loaded therefore equals what was saved.
        let payload = serde_json::to_value(card)?;
        let line = jsonl::encode_record(Some(card.owner.as_str()), &payload)?;
        let _guard = sync::write(&self.lock);
        jsonl::append_line(&self.path_of(AGENTS_FILE), &line)
    }

    fn load_agents(&self) -> Result<Vec<AgentCard>> {
        // upstream v2.5.6 fix: this method had zero call sites upstream, so
        // market state was silently lost on restart.
        let _guard = sync::read(&self.lock);
        Ok(self.agents_index()?.into_values().collect())
    }

    fn save_task(&self, task: &Task) -> Result<()> {
        // upstream v2.5.6 fix: `upsert_task` was never called at all.
        let payload = serde_json::to_value(task)?;
        let line = jsonl::encode_record(Some(task.id.as_str()), &payload)?;
        let _guard = sync::write(&self.lock);
        jsonl::append_line(&self.path_of(TASKS_FILE), &line)
    }

    fn load_tasks(&self) -> Result<Vec<Task>> {
        // upstream v2.5.6 fix: `load_tasks` had zero call sites upstream.
        let _guard = sync::read(&self.lock);
        Ok(self.tasks_index()?.into_values().collect())
    }

    fn append_ledger(&self, entry: &Value) -> Result<()> {
        // upstream v2.5.6 fix: the ledger was not persisted at all upstream —
        // there was no balances/entries table, so every balance was lost on
        // restart. Each entry is one durable append.
        let line = jsonl::encode_record(None, entry)?;
        let _guard = sync::write(&self.lock);
        jsonl::append_line(&self.path_of(LEDGER_FILE), &line)
    }

    fn load_ledger(&self) -> Result<Vec<Value>> {
        let _guard = sync::read(&self.lock);
        Ok(
            jsonl::read_records(&self.path_of(LEDGER_FILE), self.max_records)?
                .into_iter()
                .map(|record| record.payload)
                .collect(),
        )
    }

    fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let _guard = sync::read(&self.lock);
        Ok(self
            .meta_map()?
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_string))
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        if key.trim().is_empty() {
            return Err(NauError::Validation("meta key must not be empty".into()));
        }
        let _guard = sync::write(&self.lock);
        let mut map = self.meta_map()?;
        map.insert(key.to_string(), Value::String(value.to_string()));
        let bytes = jsonl::canonical_json_bytes(&Value::Object(map))?;
        write_bytes_atomic(&self.path_of(META_FILE), &bytes)
    }

    fn flush(&self) -> Result<()> {
        let _guard = sync::read(&self.lock);
        // Appends are already synced one by one; this is the belt-and-braces
        // barrier a caller uses before reporting "committed".
        for name in [AGENTS_FILE, TASKS_FILE, LEDGER_FILE, META_FILE] {
            let path = self.path_of(name);
            match std::fs::OpenOptions::new().write(true).open(&path) {
                Ok(file) => file.sync_all()?,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(NauError::Io(err)),
            }
        }
        Ok(())
    }
}

/// Read an indexed log and fold it into a last-write-wins map.
///
/// A record whose envelope is unreadable was already skipped by
/// [`jsonl::read_records`]. A record whose envelope *is* readable but whose
/// payload does not deserialize is genuine corruption of a complete record, so
/// it is an error rather than a silent skip: dropping a persisted agent card
/// looks exactly like "the agent never registered".
fn load_indexed<T, F>(path: &Path, max_records: usize, key_of: F) -> Result<BTreeMap<String, T>>
where
    T: DeserializeOwned,
    F: Fn(&T) -> String,
{
    let records = jsonl::read_records(path, max_records)?;
    let mut index: BTreeMap<String, T> = BTreeMap::new();
    for record in records {
        let stored_id = record.id.clone();
        let value: T = serde_json::from_value(record.payload).map_err(|err| {
            NauError::Validation(format!(
                "`{}` holds a well-formed record whose payload is not a valid {}: {err}",
                path.display(),
                std::any::type_name::<T>()
            ))
        })?;
        let key = key_of(&value);
        if let Some(stored_id) = stored_id {
            if stored_id != key {
                tracing::warn!(
                    path = %path.display(),
                    stored_id = %stored_id,
                    payload_id = %key,
                    "record id disagrees with its payload; trusting the payload"
                );
            }
        }
        // Last-write-wins: later records for the same key supersede earlier ones.
        index.insert(key, value);
    }
    Ok(index)
}

/// Write one encoded record plus a newline.
fn write_record(
    writer: &mut BufWriter<&std::fs::File>,
    id: Option<&str>,
    payload: &Value,
) -> Result<()> {
    let line = jsonl::encode_record(id, payload)?;
    writer.write_all(&line)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Write `path` atomically: temp file, fsync, rename.
fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    write_atomic(path, |writer| {
        writer.write_all(bytes)?;
        Ok(())
    })
}

/// Run `write_body` against a temp file next to `path`, fsync it, then rename.
fn write_atomic<F>(path: &Path, write_body: F) -> Result<()>
where
    F: FnOnce(&mut BufWriter<&std::fs::File>) -> Result<()>,
{
    let temp = temp_path(path);
    {
        let file = std::fs::File::create(&temp)?;
        {
            let mut writer = BufWriter::new(&file);
            write_body(&mut writer)?;
            writer.flush()?;
        }
        file.sync_all()?;
    }
    // `std::fs::rename` replaces an existing destination on both Unix and
    // Windows (MOVEFILE_REPLACE_EXISTING), so the swap is atomic here.
    std::fs::rename(&temp, path)?;
    Ok(())
}

/// The temp file used by [`write_atomic`] for `path`.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "store".to_string());
    name.push_str(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;

    fn scratch(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nau-store-unit-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ))
    }

    #[test]
    fn open_creates_the_directory_and_refuses_a_zero_cap() {
        let dir = scratch("open");
        assert!(!dir.exists());
        let store = FileStore::open(&dir).expect("open creates the dir");
        assert!(dir.is_dir());
        assert_eq!(store.dir(), dir.as_path());
        assert_eq!(store.max_records(), FileStore::DEFAULT_MAX_RECORDS);
        assert!(FileStore::open_capped(&dir, 0).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn metadata_is_atomically_replaced_and_survives_in_place() {
        let dir = scratch("meta");
        let store = FileStore::open(&dir).expect("open");
        store.set_meta("a", "1").expect("set");
        store.set_meta("b", "2").expect("set");
        store.set_meta("a", "3").expect("replace");
        let text = std::fs::read_to_string(store.path_of(META_FILE)).expect("read meta");
        assert_eq!(text, r#"{"a":"3","b":"2"}"#, "canonical, sorted, replaced");
        assert_eq!(store.get_meta("a").expect("get").as_deref(), Some("3"));
        assert_eq!(store.get_meta("nope").expect("get"), None);
        assert!(
            !temp_path(&store.path_of(META_FILE)).exists(),
            "temp cleaned up"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_object_meta_file_is_reported_rather_than_ignored() {
        let dir = scratch("bad-meta");
        let store = FileStore::open(&dir).expect("open");
        std::fs::write(store.path_of(META_FILE), b"[1,2,3]").expect("write");
        assert!(store.get_meta("a").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_memory_and_file_stores_reject_the_same_empty_meta_key() {
        let memory = MemoryStore::new();
        let dir = scratch("empty-key");
        let file = FileStore::open(&dir).expect("open");
        assert!(memory.set_meta("", "x").is_err());
        assert!(file.set_meta("", "x").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
