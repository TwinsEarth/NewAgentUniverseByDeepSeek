//! A durable, replayable trail of what surveillance observed.
//!
//! # Why it is on disk rather than in memory
//!
//! C-04's second criterion is that the audit record **lands on disk and can be replayed**. A trail
//! held in a `Vec` satisfies neither: it disappears with the process, and a surveillance body whose
//! observations vanish at the first restart is one whose findings can be neither appealed nor
//! audited — which is the whole difference between a record and a log line.
//!
//! # The write discipline is the storage plugin's, borrowed rather than reinvented
//!
//! One JSON object per line, appended, each followed by `sync_data`. Not `flush`: `flush` writes to
//! the kernel, `sync_data` waits for the disk, and a body that reports a clean stop and then loses
//! its last observation is worse than one that reports the failure.
//!
//! # Replay re-derives decisions, it does not re-read bytes
//!
//! [`Trail::replay`] turns the records into one line each, and two trails with the same
//! observations replay to the same lines. That is the property an audit trail is for: a reader who
//! was not there can reconstruct **what was compared and what came of it**, without the code that
//! decided it.
//!
//! # What is deliberately not recorded
//!
//! The record names the **dimension that was exceeded and both numbers**. It does not record a
//! verdict, because the verdict is [`Quota::check`](nau_core::domain::Quota::check)'s and a second
//! copy here would be a second rule that can disagree with the first. What is stored is what was
//! compared; a replay recomputes the same answer from the same inputs, which is also how a reader
//! can check the record rather than trust it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use nau_plugin::{PluginError, Result};
use serde::{Deserialize, Serialize};

/// A refusal from the trail.
///
/// `PluginError::Runtime`, matching what [`crate::payload::protocol`] constructs: a trail that
/// cannot be read or written is a failure of this component at runtime, and inventing a variant
/// would put a second vocabulary for the same thing into the error type.
fn refusal(what: impl std::fmt::Display) -> PluginError {
    PluginError::Runtime(what.to_string())
}

/// One comparison surveillance made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaObservation {
    /// When it was made. Zero is refused: an audit record that cannot say when is not one.
    pub at: u64,
    /// What was being measured.
    pub subject: String,
    /// The dimension that was exceeded, or `None` when the request fitted.
    ///
    /// `Option` rather than an empty string, so "fitted" and "exceeded nothing" cannot be confused
    /// by a reader who is skimming.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exceeded: Option<String>,
    /// What the quota allowed, in the dimension that was exceeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<u64>,
    /// What was asked for, in the dimension that was exceeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<u64>,
}

impl QuotaObservation {
    /// Whether the request fitted.
    #[must_use]
    pub fn fitted(&self) -> bool {
        self.exceeded.is_none()
    }

    /// One line, as a replay produces it.
    #[must_use]
    pub fn line(&self) -> String {
        match (&self.exceeded, self.allowed, self.asked) {
            (Some(dimension), Some(allowed), Some(asked)) => format!(
                "[{}] {} exceeded {dimension}: {asked} asked, {allowed} allowed",
                self.at, self.subject
            ),
            _ => format!("[{}] {} fitted", self.at, self.subject),
        }
    }
}

/// The trail.
#[derive(Debug)]
pub struct Trail {
    path: PathBuf,
    records: Vec<QuotaObservation>,
}

impl Trail {
    /// Open a trail at `path`, reading what is already there.
    ///
    /// A missing file is an empty trail rather than an error: the first run of a node has no
    /// history, and refusing to start because nobody has misbehaved yet would invert the point.
    ///
    /// # Errors
    ///
    /// A refusal when the file exists but a line is not a record, or when it cannot be read. A
    /// trail that silently skipped a line it could not parse would be one whose replay disagrees
    /// with what happened, which is worse than one that refuses to open.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut records = Vec::new();
        if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(|e| {
                refusal(format!("cannot read the trail at {}: {e}", path.display()))
            })?;
            for (n, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let record: QuotaObservation = serde_json::from_str(line).map_err(|e| {
                    refusal(format!(
                        "line {} of {} is not a quota observation: {e}",
                        n + 1,
                        path.display()
                    ))
                })?;
                records.push(record);
            }
        }
        Ok(Self { path, records })
    }

    /// The path this trail is written to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The records, oldest first.
    #[must_use]
    pub fn records(&self) -> &[QuotaObservation] {
        &self.records
    }

    /// How many observations have been recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether nothing has been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// How many of them did not fit.
    #[must_use]
    pub fn exceeded(&self) -> usize {
        self.records.iter().filter(|r| !r.fitted()).count()
    }

    /// Append one observation and wait for the disk.
    ///
    /// # Errors
    ///
    /// A refusal when `at` is zero, or when the write fails. The record is **not** added to memory
    /// unless the disk took it: a trail that reported an observation it did not persist would be
    /// one whose replay and whose file disagree, and the file is the one that survives.
    pub fn append(&mut self, observation: QuotaObservation) -> Result<()> {
        if observation.at == 0 {
            return Err(refusal(
                "a trailing observation must carry a non-zero timestamp; an audit record that \
                 cannot say when is not one",
            ));
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| refusal(format!("cannot create {}: {e}", parent.display())))?;
        }
        let line = serde_json::to_string(&observation)
            .map_err(|e| refusal(format!("cannot serialise a quota observation: {e}")))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| refusal(format!("cannot open {}: {e}", self.path.display())))?;
        writeln!(file, "{line}")
            .map_err(|e| refusal(format!("cannot write to {}: {e}", self.path.display())))?;
        // `sync_data`, not `flush`: see the module documentation.
        file.sync_data()
            .map_err(|e| refusal(format!("cannot sync {}: {e}", self.path.display())))?;
        self.records.push(observation);
        Ok(())
    }

    /// One line per observation, oldest first.
    #[must_use]
    pub fn replay(&self) -> Vec<String> {
        self.records.iter().map(QuotaObservation::line).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nau-trail-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("trail.jsonl")
    }

    fn fitted(at: u64) -> QuotaObservation {
        QuotaObservation {
            at,
            subject: "sb-1".to_string(),
            exceeded: None,
            allowed: None,
            asked: None,
        }
    }

    fn exceeded(at: u64) -> QuotaObservation {
        QuotaObservation {
            at,
            subject: "sb-1".to_string(),
            exceeded: Some("memory_bytes".to_string()),
            allowed: Some(1024),
            asked: Some(2048),
        }
    }

    #[test]
    fn a_missing_file_is_an_empty_trail_rather_than_an_error() {
        // The first run of a node has no history, and refusing to start because nobody has
        // misbehaved yet would invert the point.
        let trail = Trail::open(scratch("empty")).expect("opens");
        assert!(trail.is_empty());
        assert!(trail.replay().is_empty());
        assert_eq!(trail.exceeded(), 0);
    }

    #[test]
    fn an_observation_survives_reopening() {
        // C-04's "lands on disk": the trail is read back by a **new** `Trail`, so nothing is being
        // served from the first one's memory.
        let path = scratch("durable");
        {
            let mut trail = Trail::open(&path).expect("opens");
            trail.append(fitted(10)).expect("append");
            trail.append(exceeded(11)).expect("append");
            assert_eq!(trail.len(), 2);
        }
        let reopened = Trail::open(&path).expect("reopens");
        assert_eq!(
            reopened.len(),
            2,
            "the records must come back from the file"
        );
        assert_eq!(reopened.exceeded(), 1);
        assert_eq!(reopened.records()[1], exceeded(11));
    }

    #[test]
    fn a_replay_re_derives_the_decisions_from_the_file_alone() {
        // The property an audit trail is for: a reader who was not there reconstructs what was
        // compared. The replay below runs on a trail built only from the bytes on disk.
        let path = scratch("replay");
        {
            let mut trail = Trail::open(&path).expect("opens");
            trail.append(fitted(10)).expect("append");
            trail.append(exceeded(11)).expect("append");
        }
        let reopened = Trail::open(&path).expect("reopens");
        let lines = reopened.replay();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("fitted"), "got: {}", lines[0]);
        assert!(
            lines[1].contains("exceeded memory_bytes"),
            "got: {}",
            lines[1]
        );
        assert!(
            lines[1].contains("2048 asked, 1024 allowed"),
            "got: {}",
            lines[1]
        );
    }

    #[test]
    fn a_zero_timestamp_is_refused_and_nothing_is_written() {
        let path = scratch("zero");
        let mut trail = Trail::open(&path).expect("opens");
        let err = trail.append(fitted(0)).expect_err("must refuse");
        assert!(
            format!("{err}").contains("non-zero timestamp"),
            "got: {err}"
        );
        assert!(trail.is_empty(), "a refused observation must not be filed");
        assert!(!path.exists(), "and must not reach the disk either");
    }

    #[test]
    fn a_line_that_is_not_a_record_refuses_to_open_rather_than_being_skipped() {
        // A trail that skipped a line it could not parse would be one whose replay disagrees with
        // what happened. Refusing is the only answer that keeps the file and the replay together.
        let path = scratch("corrupt");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, "{\"at\":10,\"subject\":\"sb\"}\nnot json at all\n").expect("write");
        let err = Trail::open(&path).expect_err("must refuse");
        let text = format!("{err}");
        assert!(
            text.contains("line 2"),
            "the refusal must name the line, got: {text}"
        );
    }

    #[test]
    fn an_empty_line_is_tolerated_because_a_trailing_newline_is_normal() {
        let path = scratch("blank");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, "{\"at\":10,\"subject\":\"sb\"}\n\n").expect("write");
        let trail = Trail::open(&path).expect("opens");
        assert_eq!(trail.len(), 1);
    }

    #[test]
    fn the_line_classifies_fitted_and_exceeded_exactly_one_way() {
        let ok = fitted(1);
        let bad = exceeded(1);
        assert!(ok.fitted() && !bad.fitted());
        assert!(!ok.line().contains("exceeded"));
        assert!(bad.line().contains("exceeded"));
    }
}
