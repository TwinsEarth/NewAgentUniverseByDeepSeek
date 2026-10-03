//! What a component guarantees about concurrent change, and the evidence for it.
//!
//! # Why a declaration rather than an assumption
//!
//! "Consistent" is not a property a system has; it is a property a **reader** has, for a
//! **question**, across a **window**. A component that is snapshot-consistent for one question is
//! eventually consistent for another, and the failure mode of leaving it unsaid is that two people
//! assume different models and both are surprised.
//!
//! So a component declares its model, the declaration carries **why**, and — the part that makes
//! this more than documentation — a test exercises the claim. B-09's acceptance criteria are
//! exactly these three: the model is written down, the implementation matches it, and where it
//! does not, the gap is **named as a known boundary** rather than left to be discovered.
//!
//! # The two models here, stated precisely
//!
//! [`ConsistencyModel::SnapshotPoint`] — a value named at one instant is fully determined at that
//! instant, and every later read of that name returns the same thing. Content addressing is the
//! usual mechanism: the name is the content, so there is nothing to converge.
//!
//! [`ConsistencyModel::Eventual`] — reads may differ while changes propagate, and the component
//! **converges** when they stop. The obligation that comes with this model is saying **what
//! converges**; "eventually consistent" with no convergence target is a promise to be consistent
//! about something nobody named.
//!
//! # The known boundary this release declares
//!
//! [`ChunkReader`](https://docs.rs/nau-image)'s read path is snapshot-point consistent: every chunk
//! is verified against the digest the manifest names, so a source cannot substitute one version's
//! chunk for another's — content addressing makes that a verification failure rather than a
//! silent mixed result.
//!
//! Its **metrics** are not. `metrics()` reads counters that concurrent reads are writing, without a
//! transaction across them, so a snapshot of the counters can show a `chunks_fetched` that belongs
//! to a moment between two `cache_hits`. Each number is a real observation of a real moment; the
//! **combination** is not one. That is declared here, as
//! [`KNOWN_BOUNDARIES`], rather than left for someone to reason about from the code.

use serde::{Deserialize, Serialize};

/// What a component guarantees about concurrent change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyModel {
    /// A value named at one instant is fully determined at that instant.
    ///
    /// Every later read of the name returns the same thing, because the name **is** the content.
    /// There is no window to reason about and nothing to converge.
    SnapshotPoint,
    /// Reads may differ while changes propagate, and the component converges when they stop.
    ///
    /// A declaration of this model owes a statement of **what converges** — see
    /// [`ConsistencyClaim::converges_to`].
    Eventual,
}

impl ConsistencyModel {
    /// A label for reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ConsistencyModel::SnapshotPoint => "snapshot-point",
            ConsistencyModel::Eventual => "eventual",
        }
    }

    /// Whether a reader may assume two reads of one name agree.
    #[must_use]
    pub fn permits_stable_rereads(self) -> bool {
        matches!(self, ConsistencyModel::SnapshotPoint)
    }
}

/// One component's declaration, with the reason and the convergence target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsistencyClaim {
    /// The component, as a reader would name it.
    pub component: &'static str,
    /// The question the model is about. A model is always for a question, never for a component
    /// as a whole — which is why this field exists rather than being folded into `component`.
    pub question: &'static str,
    /// The model.
    pub model: ConsistencyModel,
    /// Why the component has this model. Not decoration: a claim whose reason is not written down
    /// is one nobody can check.
    pub because: &'static str,
    /// For [`ConsistencyModel::Eventual`], what the reads converge **to**. Empty for
    /// [`ConsistencyModel::SnapshotPoint`], which has nothing to converge.
    pub converges_to: &'static str,
}

impl ConsistencyClaim {
    /// A snapshot-point claim.
    #[must_use]
    pub const fn snapshot_point(
        component: &'static str,
        question: &'static str,
        because: &'static str,
    ) -> Self {
        Self {
            component,
            question,
            model: ConsistencyModel::SnapshotPoint,
            because,
            converges_to: "",
        }
    }

    /// An eventual claim, which must say what it converges to.
    #[must_use]
    pub const fn eventual(
        component: &'static str,
        question: &'static str,
        because: &'static str,
        converges_to: &'static str,
    ) -> Self {
        Self {
            component,
            question,
            model: ConsistencyModel::Eventual,
            because,
            converges_to,
        }
    }

    /// Whether this claim is complete: a reason, and a convergence target for an eventual model.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        if self.because.trim().is_empty() {
            return false;
        }
        match self.model {
            ConsistencyModel::SnapshotPoint => true,
            ConsistencyModel::Eventual => !self.converges_to.trim().is_empty(),
        }
    }
}

/// The claims this workspace makes, one per component-and-question.
///
/// Every entry is exercised by a test in the crate that owns the component; a claim nothing
/// checks would be documentation with extra steps.
pub const CLAIMS: [ConsistencyClaim; 5] = [
    ConsistencyClaim::snapshot_point(
        "ImageManifest",
        "does a manifest read now still describe the same image later?",
        "a manifest is a value: its chunk list and content address are fixed when it is built, and \
         nothing in this workspace mutates one in place",
    ),
    ConsistencyClaim::snapshot_point(
        "ChunkReader::read",
        "can one read assemble bytes from two different versions of a source?",
        "every chunk is hashed and compared against the digest the manifest names, so a source \
         that has moved on serves a verification failure rather than a mixed result -- content \
         addressing is what makes the question decidable",
    ),
    ConsistencyClaim::snapshot_point(
        "SnapshotStore layers",
        "is a layer named once the same layer later?",
        "layers are keyed by the hash of their bytes; `verify` recomputes a snapshot's id from its \
         layer addresses, so a changed list is caught rather than read",
    ),
    ConsistencyClaim::eventual(
        "ChunkReader::metrics",
        "do the counters describe one moment?",
        "the counters are shared mutable state written by concurrent reads and read without a \
         transaction across them, so a snapshot can combine numbers from adjacent moments",
        "each counter is exact for the moment it was read; the totals agree with the reads once \
         the reads stop, and no counter is ever wrong about a fetch that happened",
    ),
    ConsistencyClaim::eventual(
        "SeedingRatio",
        "does a peer's ratio describe the network now?",
        "a ratio is computed from what one peer has served and fetched, and other peers are \
         serving and fetching concurrently",
        "the ratio is exact for the peer that computed it; it converges as the peer's exchanges \
         finish, and it is undefined -- not zero -- before the peer has fetched anything",
    ),
];

/// Places the implementation does **not** meet the model a reader might assume.
///
/// Declared rather than left to be discovered. B-09 asks for exactly this: an inconsistency named
/// is a documented boundary; the same inconsistency found by a user is a defect report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownBoundary {
    /// The component.
    pub component: &'static str,
    /// What a reader might reasonably assume.
    pub looks_like: &'static str,
    /// What is actually true.
    pub actually: &'static str,
    /// What a caller must do instead.
    pub workaround: &'static str,
}

/// The boundaries this workspace declares.
pub const KNOWN_BOUNDARIES: [KnownBoundary; 2] = [
    KnownBoundary {
        component: "ChunkReader::metrics",
        looks_like: "one consistent observation of the reader's counters",
        actually:
            "each counter is a separate atomic read, so a `Metrics` value can combine numbers \
             from two adjacent moments -- `chunks_fetched` and `cache_hits` may not describe the \
             same instant",
        workaround: "read metrics after the reads have stopped when the combination matters; for \
             per-read accounting use the `ReadReport` the read itself returns, which is one \
             value from one moment",
    },
    KnownBoundary {
        component: "SeedingRatio",
        looks_like: "0% means the peer is not seeding",
        actually:
            "a peer that has fetched nothing has no ratio at all; `percent()` returns `None`, \
             which is neither 0% nor infinite, and rendering it as either is a claim about a peer \
             nobody has exchanged with",
        workaround:
            "match on the `Option` and report 'no ratio yet' rather than substituting a number; \
             `is_seeding()` is false for the undefined case by design",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_claim_is_complete() {
        // A claim with no reason is one nobody can check, and an eventual claim with no
        // convergence target is a promise to be consistent about something nobody named.
        for claim in CLAIMS {
            assert!(
                claim.is_complete(),
                "{} / {} is incomplete: because={:?} converges_to={:?}",
                claim.component,
                claim.question,
                claim.because,
                claim.converges_to
            );
        }
    }

    #[test]
    fn a_snapshot_point_claim_carries_no_convergence_target() {
        // Not an oversight when empty: there is nothing to converge, and filling it in would
        // suggest a window that does not exist.
        for claim in CLAIMS {
            if claim.model == ConsistencyModel::SnapshotPoint {
                assert!(
                    claim.converges_to.is_empty(),
                    "{} is snapshot-point and should not name a convergence target",
                    claim.component
                );
                assert!(claim.model.permits_stable_rereads());
            } else {
                assert!(
                    !claim.converges_to.trim().is_empty(),
                    "{} is eventual and must say what it converges to",
                    claim.component
                );
                assert!(!claim.model.permits_stable_rereads());
            }
        }
    }

    #[test]
    fn every_boundary_says_what_a_caller_should_do_instead() {
        // A boundary with no workaround is a complaint. The point of declaring it is that a
        // caller can act on it.
        for boundary in KNOWN_BOUNDARIES {
            assert!(!boundary.component.trim().is_empty());
            assert!(!boundary.looks_like.trim().is_empty());
            assert!(!boundary.actually.trim().is_empty());
            assert!(
                !boundary.workaround.trim().is_empty(),
                "{} declares a boundary with no workaround",
                boundary.component
            );
        }
    }

    #[test]
    fn the_models_are_labelled_uniquely_and_classify_exactly_one_way() {
        let models = [ConsistencyModel::SnapshotPoint, ConsistencyModel::Eventual];
        let mut labels: Vec<&str> = models.iter().map(|m| m.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count);

        assert!(ConsistencyModel::SnapshotPoint.permits_stable_rereads());
        assert!(!ConsistencyModel::Eventual.permits_stable_rereads());
    }

    #[test]
    fn the_claims_name_distinct_questions() {
        // A model is for a question, and two claims about the same component with the same
        // question would be two answers to one thing -- which is how a declaration starts to
        // contradict itself.
        let mut keys: Vec<(&str, &str)> =
            CLAIMS.iter().map(|c| (c.component, c.question)).collect();
        keys.sort_unstable();
        let count = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), count);
    }

    #[test]
    fn an_incomplete_claim_is_recognised_as_incomplete() {
        // The check above would pass vacuously if `is_complete` always returned true.
        let no_reason = ConsistencyClaim {
            component: "x",
            question: "y",
            model: ConsistencyModel::SnapshotPoint,
            because: "  ",
            converges_to: "",
        };
        assert!(!no_reason.is_complete());

        let no_target = ConsistencyClaim {
            component: "x",
            question: "y",
            model: ConsistencyModel::Eventual,
            because: "it drifts",
            converges_to: "",
        };
        assert!(!no_target.is_complete());
    }
}
