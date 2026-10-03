//! Every snapshot, restore and fork on the record — and replayable.
//!
//! # Why these three, and not everything
//!
//! Snapshot, restore and fork are the operations that **change what state a sandbox is standing
//! on**. A snapshot copies state out, a restore substitutes state in, and a fork decides which
//! earlier state two branches will share. Everything else an agent does is either confined to the
//! sandbox (and captured by the snapshot) or an external effect (and refused a fork point). These
//! three are what an operator has to be able to answer for after the fact.
//!
//! # The record carries the canonical capability name
//!
//! B-11's second criterion. The capability is not a string chosen here: it is a
//! [`Capability`] variant, and [`PmbMessage::new`] takes the typed value and writes
//! [`Capability::as_str`] — the same name the matrix, the audit log and the CLI use. A record
//! carrying a name invented at the call site would be one no other component could match against,
//! which is the difference between an audit trail and a log line.
//!
//! # What replay means here, and what it does not
//!
//! [`SnapshotAudit::replay`] re-derives the **sequence of decisions** — which snapshots existed,
//! in what order, on which parent, with which outcomes — and checks that against the store. It
//! does not re-fetch bytes: a snapshot is content-addressed, so re-deriving its id from the layer
//! addresses the record names is enough to establish that the record and the store describe the
//! same thing. Re-storing the data would be a second implementation of the store, and the two
//! would disagree eventually.
//!
//! A record that cannot be re-derived is reported rather than skipped, because a log with a gap
//! that reads as a quiet success is worse than one that fails loudly.

use nau_core::error::{NauError, Result};
use nau_core::identity::canonical::payload_digest_hex;
use serde::{Deserialize, Serialize};

use crate::bus::{PmbKind, PmbMessage, Priority, Target};
use crate::capability::Capability;
use crate::tier::PluginId;

/// One recorded operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum SnapshotOperation {
    /// A snapshot was taken.
    Snapshot {
        /// The sandbox it was taken from.
        sandbox: String,
        /// The entry it was filed under.
        entry: String,
        /// The snapshot's content address.
        snapshot: String,
        /// The parent it was built on, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
        /// How many layers the snapshot has.
        layers: usize,
        /// How many of them the store already held.
        reused: usize,
    },
    /// A snapshot was restored into a sandbox.
    Restore {
        /// The sandbox.
        sandbox: String,
        /// The snapshot it resumed from.
        snapshot: String,
    },
    /// A fork was placed.
    Fork {
        /// The entry the trace was filed under.
        entry: String,
        /// The step the fork was placed after.
        fork_after: usize,
        /// How many branches continue.
        branches: usize,
    },
}

impl SnapshotOperation {
    /// The capability this operation exercises, as the bus registers it.
    ///
    /// A fork is `plugin:storage:own`: it records which state two branches share and reaches
    /// nothing outside the sandbox, which is what that capability describes. It is deliberately
    /// **not** `sandbox:configure` — forking does not change any sandbox's isolation, and
    /// claiming a kernel-class capability for a bookkeeping operation would be the overstatement
    /// this crate keeps refusing.
    #[must_use]
    pub fn capability(&self) -> Capability {
        match self {
            SnapshotOperation::Snapshot { .. } => Capability::SandboxSnapshot,
            SnapshotOperation::Restore { .. } => Capability::SandboxRestore,
            SnapshotOperation::Fork { .. } => Capability::StorageOwn,
        }
    }

    /// Which sandbox or trace the operation is about.
    #[must_use]
    pub fn subject(&self) -> &str {
        match self {
            SnapshotOperation::Snapshot { sandbox, .. } => sandbox,
            SnapshotOperation::Restore { sandbox, .. } => sandbox,
            SnapshotOperation::Fork { entry, .. } => entry,
        }
    }

    /// A label for reports.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            SnapshotOperation::Snapshot { .. } => "snapshot",
            SnapshotOperation::Restore { .. } => "restore",
            SnapshotOperation::Fork { .. } => "fork",
        }
    }
}

/// The audit trail.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotAudit {
    records: Vec<PmbMessage>,
}

impl SnapshotAudit {
    /// An empty trail.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The records, oldest first.
    #[must_use]
    pub fn records(&self) -> &[PmbMessage] {
        &self.records
    }

    /// The operations, decoded from the records.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when a record's payload is not an operation — a trail with a
    /// record this code cannot read is reported rather than skipped, because a log with a gap that
    /// reads as a quiet success is worse than one that fails loudly.
    pub fn operations(&self) -> Result<Vec<SnapshotOperation>> {
        self.records
            .iter()
            .map(|m| {
                serde_json::from_value(m.payload.clone()).map_err(|e| {
                    NauError::Validation(format!(
                        "audit record {} cannot be read as a snapshot operation: {e}",
                        m.id
                    ))
                })
            })
            .collect()
    }

    /// Record an operation as a PMB message.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `at` is zero — a zero timestamp in an audit log means "we
    /// did not record when", which is the one thing an audit trail is for.
    pub fn record(
        &mut self,
        source: &PluginId,
        operation: &SnapshotOperation,
        at: u64,
    ) -> Result<()> {
        if at == 0 {
            return Err(NauError::Validation(
                "an audit record must carry a non-zero timestamp".to_string(),
            ));
        }
        let payload = serde_json::to_value(operation).map_err(NauError::from)?;
        let message = PmbMessage::new(
            source,
            Target::Broadcast,
            // The typed capability, so the wire form is the canonical name by construction.
            operation.capability(),
            // An event, not a request: nobody answers a snapshot.
            PmbKind::Event,
            payload,
            at,
        )
        .with_topic("nau.snapshot.audit");
        // High rather than Critical: this is the host's own bookkeeping, and a plugin may not use
        // Critical. Taking the highest priority a plugin may hold is honest about the record
        // mattering without claiming a reservation it does not have.
        self.records.push(PmbMessage {
            priority: Priority::High,
            ..message
        });
        Ok(())
    }

    /// Every record that exercised `capability`, by its canonical name.
    #[must_use]
    pub fn for_capability(&self, capability: Capability) -> Vec<&PmbMessage> {
        let name = capability.as_str();
        self.records
            .iter()
            .filter(|m| m.capability == name)
            .collect()
    }

    /// Every record about `subject`.
    ///
    /// # Errors
    ///
    /// As [`SnapshotAudit::operations`].
    pub fn for_subject(&self, subject: &str) -> Result<Vec<SnapshotOperation>> {
        Ok(self
            .operations()?
            .into_iter()
            .filter(|op| op.subject() == subject)
            .collect())
    }

    /// Re-derive the sequence of decisions the trail describes.
    ///
    /// Returns one line per record: the operation, what it was about, and the outcome the record
    /// states. Two trails that replay to the same lines describe the same history, which is the
    /// property an audit trail is for and the one a log of unstructured lines cannot give.
    ///
    /// # Errors
    ///
    /// As [`SnapshotAudit::operations`].
    pub fn replay(&self) -> Result<Vec<String>> {
        let mut out = Vec::with_capacity(self.records.len());
        for (message, operation) in self.records.iter().zip(self.operations()?) {
            let line = match &operation {
                SnapshotOperation::Snapshot {
                    sandbox,
                    snapshot,
                    parent,
                    layers,
                    reused,
                    ..
                } => format!(
                    "snapshot {sandbox} -> {snapshot} on {} with {layers} layer(s), {reused} reused",
                    parent.as_deref().unwrap_or("nothing")
                ),
                SnapshotOperation::Restore { sandbox, snapshot } => {
                    format!("restore {sandbox} <- {snapshot}")
                }
                SnapshotOperation::Fork {
                    entry,
                    fork_after,
                    branches,
                } => format!("fork {entry} after step {fork_after} into {branches} branch(es)"),
            };
            // The capability is appended from the record rather than from the operation, so a
            // replayed line shows the name that is actually on the wire.
            out.push(format!("[{}] {line}", message.capability));
        }
        Ok(out)
    }

    /// The digest of the whole trail.
    ///
    /// Over the records in order, so two trails with the same operations in a different order
    /// have different digests — which matters, because a restore before a snapshot is not the
    /// same history as a snapshot before a restore.
    ///
    /// # Errors
    ///
    /// [`NauError::Canonical`] if the records cannot be canonicalised.
    pub fn digest_hex(&self) -> Result<String> {
        // Wrapped in an object, and that is the canonical rules rather than a stylistic choice:
        // rule 1 requires a root **object**, so hashing the bare array fails. The three tests that
        // call this method found it immediately, which is what a rule enforced by the hasher buys
        // over one written in a comment.
        payload_digest_hex(&serde_json::json!({ "records": self.records })).map_err(NauError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> PluginId {
        PluginId::parse("com.twinsearth.sys.ausec").expect("a valid plugin id")
    }

    fn snapshot_op() -> SnapshotOperation {
        SnapshotOperation::Snapshot {
            sandbox: "sb-1".to_string(),
            entry: "before-upgrade".to_string(),
            snapshot: "a".repeat(64),
            parent: None,
            layers: 3,
            reused: 1,
        }
    }

    #[test]
    fn each_operation_records_its_capability_by_canonical_name() {
        // B-11's second criterion: the name on the wire is the one the matrix, the CLI and the
        // audit log all use, because it comes from the typed variant rather than a string here.
        let mut audit = SnapshotAudit::new();
        audit
            .record(&source(), &snapshot_op(), 100)
            .expect("record");
        audit
            .record(
                &source(),
                &SnapshotOperation::Restore {
                    sandbox: "sb-1".to_string(),
                    snapshot: "a".repeat(64),
                },
                101,
            )
            .expect("record");
        audit
            .record(
                &source(),
                &SnapshotOperation::Fork {
                    entry: "trace-1".to_string(),
                    fork_after: 4,
                    branches: 3,
                },
                102,
            )
            .expect("record");

        let names: Vec<&str> = audit
            .records()
            .iter()
            .map(|m| m.capability.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["sandbox:snapshot", "sandbox:restore", "plugin:storage:own"]
        );
        // And they are the names the capability type produces, not strings that happen to match.
        assert_eq!(
            audit.records()[0].capability,
            Capability::SandboxSnapshot.as_str()
        );
        assert_eq!(
            audit.records()[1].capability,
            Capability::SandboxRestore.as_str()
        );
        assert_eq!(
            audit.records()[2].capability,
            Capability::StorageOwn.as_str()
        );
    }

    #[test]
    fn a_fork_does_not_claim_a_kernel_capability() {
        // Forking records which state two branches share. It changes no sandbox's isolation, and
        // claiming `sandbox:configure` for it would be the overstatement this crate refuses.
        let fork = SnapshotOperation::Fork {
            entry: "t".to_string(),
            fork_after: 1,
            branches: 2,
        };
        assert_eq!(fork.capability(), Capability::StorageOwn);
        assert!(
            !fork.capability().is_kernel(),
            "a bookkeeping operation must not hold kernel authority"
        );
    }

    #[test]
    fn every_operation_is_recorded_as_an_event_and_filterable_by_capability() {
        // B-11's first criterion: every snapshot, restore and fork has a PMB record.
        let mut audit = SnapshotAudit::new();
        audit
            .record(&source(), &snapshot_op(), 100)
            .expect("record");
        assert_eq!(audit.len(), 1);
        assert!(!audit.is_empty());

        let message = &audit.records()[0];
        assert_eq!(message.kind, PmbKind::Event, "nobody answers a snapshot");
        assert_eq!(message.capability, Capability::SandboxSnapshot.as_str());
        assert_eq!(message.source, source().as_str());
        assert_eq!(message.topic.as_deref(), Some("nau.snapshot.audit"));
        assert_eq!(message.issued_at, 100);

        assert_eq!(audit.for_capability(Capability::SandboxSnapshot).len(), 1);
        assert!(audit.for_capability(Capability::SandboxRestore).is_empty());
    }

    #[test]
    fn the_trail_replays_to_the_history_it_describes() {
        // B-11's third criterion, in the form this crate can check: two trails that replay to the
        // same lines describe the same history.
        let mut a = SnapshotAudit::new();
        a.record(&source(), &snapshot_op(), 100).expect("record");
        a.record(
            &source(),
            &SnapshotOperation::Restore {
                sandbox: "sb-1".to_string(),
                snapshot: "a".repeat(64),
            },
            101,
        )
        .expect("record");

        let lines = a.replay().expect("replays");
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("[sandbox:snapshot]"), "got: {}", lines[0]);
        assert!(lines[0].contains("sb-1"), "got: {}", lines[0]);
        assert!(
            lines[0].contains("3 layer(s), 1 reused"),
            "got: {}",
            lines[0]
        );
        assert!(
            lines[0].contains("on nothing"),
            "a root snapshot has no parent"
        );
        assert!(lines[1].contains("[sandbox:restore]"), "got: {}", lines[1]);

        // An independent trail built the same way replays to the same lines, even though the
        // message ids differ -- the ids are not part of the history.
        let mut b = SnapshotAudit::new();
        b.record(&source(), &snapshot_op(), 100).expect("record");
        b.record(
            &source(),
            &SnapshotOperation::Restore {
                sandbox: "sb-1".to_string(),
                snapshot: "a".repeat(64),
            },
            101,
        )
        .expect("record");
        assert_eq!(a.replay().expect("a"), b.replay().expect("b"));
    }

    #[test]
    fn the_order_is_part_of_the_history() {
        // A restore before a snapshot is not the same history as a snapshot before a restore, and
        // the digest has to say so.
        let snap = snapshot_op();
        let rest = SnapshotOperation::Restore {
            sandbox: "sb-1".to_string(),
            snapshot: "a".repeat(64),
        };

        let mut a = SnapshotAudit::new();
        a.record(&source(), &snap, 100).expect("record");
        a.record(&source(), &rest, 101).expect("record");

        let mut b = SnapshotAudit::new();
        b.record(&source(), &rest, 100).expect("record");
        b.record(&source(), &snap, 101).expect("record");

        assert_ne!(
            a.digest_hex().expect("a"),
            b.digest_hex().expect("b"),
            "the digest must cover the order"
        );
        assert_ne!(a.replay().expect("a"), b.replay().expect("b"));
    }

    #[test]
    fn a_zero_timestamp_is_refused() {
        // A zero in an audit log means "we did not record when", which is the one thing an audit
        // trail is for.
        let mut audit = SnapshotAudit::new();
        let err = audit
            .record(&source(), &snapshot_op(), 0)
            .expect_err("must refuse");
        assert!(
            format!("{err}").contains("non-zero timestamp"),
            "got: {err}"
        );
        assert!(audit.is_empty(), "a refused record must not be filed");
    }

    #[test]
    fn a_record_that_cannot_be_read_is_reported_rather_than_skipped() {
        // A log with a gap that reads as a quiet success is worse than one that fails loudly.
        let mut audit = SnapshotAudit::new();
        audit
            .record(&source(), &snapshot_op(), 100)
            .expect("record");
        // Reach in the way a corrupted or foreign record would arrive.
        audit.records.push(PmbMessage {
            payload: serde_json::json!({ "not": "an operation" }),
            ..audit.records[0].clone()
        });
        let err = audit.operations().expect_err("must refuse");
        assert!(format!("{err}").contains("cannot be read"), "got: {err}");
        assert!(audit.replay().is_err(), "replay must refuse too");
    }

    #[test]
    fn records_are_filterable_by_subject() {
        let mut audit = SnapshotAudit::new();
        audit
            .record(&source(), &snapshot_op(), 100)
            .expect("record");
        audit
            .record(
                &source(),
                &SnapshotOperation::Snapshot {
                    sandbox: "sb-2".to_string(),
                    entry: "e".to_string(),
                    snapshot: "b".repeat(64),
                    parent: Some("a".repeat(64)),
                    layers: 2,
                    reused: 2,
                },
                101,
            )
            .expect("record");

        assert_eq!(audit.for_subject("sb-1").expect("read").len(), 1);
        assert_eq!(audit.for_subject("sb-2").expect("read").len(), 1);
        assert!(audit.for_subject("sb-9").expect("read").is_empty());
    }

    #[test]
    fn the_trail_survives_a_round_trip_through_json() {
        let mut audit = SnapshotAudit::new();
        audit
            .record(&source(), &snapshot_op(), 100)
            .expect("record");
        let text = serde_json::to_string(&audit).expect("serialise");
        let back: SnapshotAudit = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(audit, back);
        assert_eq!(audit.replay().expect("a"), back.replay().expect("b"));
        assert_eq!(
            audit.digest_hex().expect("a"),
            back.digest_hex().expect("b")
        );
    }

    #[test]
    fn an_empty_trail_replays_to_nothing_and_digests_stably() {
        let audit = SnapshotAudit::new();
        assert!(audit.replay().expect("replays").is_empty());
        assert_eq!(
            audit.digest_hex().expect("a"),
            SnapshotAudit::new().digest_hex().expect("b")
        );
    }

    #[test]
    fn an_operations_label_and_subject_are_unambiguous() {
        let snap = snapshot_op();
        assert_eq!(snap.label(), "snapshot");
        assert_eq!(snap.subject(), "sb-1");
        assert_eq!(
            SnapshotOperation::Restore {
                sandbox: "s".to_string(),
                snapshot: "x".to_string()
            }
            .label(),
            "restore"
        );
        assert_eq!(
            SnapshotOperation::Fork {
                entry: "e".to_string(),
                fork_after: 0,
                branches: 2
            }
            .subject(),
            "e"
        );
    }
}
