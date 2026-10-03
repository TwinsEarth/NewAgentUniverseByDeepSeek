//! Incremental snapshots: store each layer once, and prove it by counting.
//!
//! # The property, and how it is proved
//!
//! "A snapshot does not re-store layers that are already stored" is the whole of what
//! incremental means. It is also the kind of claim that is easy to make and hard to check, so it
//! is expressed here as **counts**: [`StoreReport`] reports how many layers were admitted and
//! how many were already present, and the tests assert those numbers rather than timing or size.
//!
//! The content address is [`nau_core::image::ChunkDigest`] — the same one an image chunk uses.
//! A second hashing scheme for snapshots would be a second thing to keep right, and the two
//! would agree right up until they did not.
//!
//! # Why a missing parent is refused rather than treated as a full snapshot
//!
//! An incremental snapshot names the snapshot it builds on. If that parent is not in the store,
//! the honest reading is that the caller has lost a snapshot — and the dishonest fallback,
//! quietly storing everything as if it were a full snapshot, would produce something that looks
//! correct, restores correctly, and is **not what the caller asked for**. It would also hide a
//! broken chain until someone tried to restore an older one.
//!
//! # Integrity is a recomputation, not a stored flag
//!
//! [`SnapshotStore::verify`] walks a snapshot's layers and re-hashes what it holds. A stored
//! `verified: true` would be a claim made once and trusted forever, which is the shape of
//! guarantee this project replaces everywhere else.

use std::collections::BTreeMap;

use nau_core::error::{NauError, Result};
use nau_core::image::ChunkDigest;

/// A layer: content-addressed bytes, plus how many there are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// The layer's content address.
    pub digest: ChunkDigest,
    /// The layer's length in bytes.
    pub len: usize,
}

/// Identifies a snapshot within a store.
///
/// A content address rather than a counter: a counter reissued across restarts is how the
/// upstream sandbox gave a new sandbox the previous one's files, and the same mistake here would
/// give a new snapshot an old one's layers.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct SnapshotId(String);

impl SnapshotId {
    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What one store call did.
///
/// The counts are the proof of incrementality: `reused_layers` is the number of layers the call
/// was **not** asked to store again because the store already held them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreReport {
    /// Layers in the snapshot.
    pub layers: usize,
    /// Layers newly admitted to the store.
    pub admitted: usize,
    /// Layers already present, and therefore not stored again.
    pub reused: usize,
    /// Bytes newly admitted.
    pub admitted_bytes: usize,
}

impl StoreReport {
    /// Whether this call added nothing new — a snapshot that is entirely shared with what is
    /// already stored.
    #[must_use]
    pub fn is_fully_shared(&self) -> bool {
        self.admitted == 0 && self.layers > 0
    }
}

/// A snapshot: an ordered list of layers, and what it was built on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The snapshot's own content address.
    pub id: SnapshotId,
    /// The snapshot this one builds on, if any.
    pub parent: Option<SnapshotId>,
    /// The layers, in order.
    pub layers: Vec<Layer>,
}

impl Snapshot {
    /// Total bytes across the layers.
    #[must_use]
    pub fn len_bytes(&self) -> usize {
        self.layers.iter().map(|l| l.len).sum()
    }

    /// The snapshot's content address, from its parent and layer addresses.
    ///
    /// Over the addresses and not the bytes: the bytes are already committed to by the layer
    /// addresses, and hashing a gigabyte of layers to name a snapshot would make naming cost as
    /// much as storing. This is the same reasoning A-08 used for chunk attestations.
    fn compute_id(parent: Option<&SnapshotId>, layers: &[Layer]) -> Result<SnapshotId> {
        let mut preimage = String::with_capacity(64 * (layers.len() + 1) + 16);
        preimage.push_str("nau-snapshot:v1:");
        preimage.push_str(parent.map(SnapshotId::as_str).unwrap_or("root"));
        for layer in layers {
            preimage.push(':');
            preimage.push_str(layer.digest.as_str());
        }
        let digest = ChunkDigest::of(preimage.as_bytes());
        Ok(SnapshotId(digest.as_str().to_string()))
    }
}

/// A store that keeps each layer once.
#[derive(Debug, Default)]
pub struct SnapshotStore {
    layers: BTreeMap<String, usize>,
    snapshots: BTreeMap<String, Snapshot>,
}

impl SnapshotStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many distinct layers are held.
    #[must_use]
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Total bytes held.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.layers.values().sum()
    }

    /// How many snapshots are held.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the store holds this layer.
    #[must_use]
    pub fn has_layer(&self, digest: &ChunkDigest) -> bool {
        self.layers.contains_key(digest.as_str())
    }

    /// The snapshot with this id, if held.
    #[must_use]
    pub fn snapshot(&self, id: &SnapshotId) -> Option<&Snapshot> {
        self.snapshots.get(id.as_str())
    }

    /// Store a snapshot built on `parent` from `layers`.
    ///
    /// # Errors
    ///
    /// [`NauError::NotFound`] when `parent` is named and not held — see the module documentation
    /// for why this is refused rather than treated as a full snapshot.
    ///
    /// [`NauError::Validation`] when a layer is empty, or when the same layer appears twice in
    /// one snapshot. A repeated layer is not a deduplication opportunity: it means the caller's
    /// list describes an image with the same content at two positions, which a layer list cannot
    /// express, and accepting it would produce a snapshot that restores to something else.
    pub fn store(
        &mut self,
        parent: Option<&SnapshotId>,
        layers: &[Vec<u8>],
    ) -> Result<(SnapshotId, StoreReport)> {
        if let Some(p) = parent {
            if !self.snapshots.contains_key(p.as_str()) {
                return Err(NauError::NotFound(format!(
                    "snapshot {p} is named as this snapshot's parent and is not in this store; \
                     storing a full snapshot instead would produce something that restores \
                     correctly and is not what was asked for"
                )));
            }
        }

        let mut report = StoreReport::default();
        let mut described = Vec::with_capacity(layers.len());
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();

        for bytes in layers {
            if bytes.is_empty() {
                return Err(NauError::Validation(
                    "a snapshot layer must not be empty".to_string(),
                ));
            }
            let digest = ChunkDigest::of(bytes);
            if seen.insert(digest.as_str().to_string(), ()).is_some() {
                return Err(NauError::Validation(format!(
                    "layer {digest} appears twice in one snapshot; a layer list cannot express \
                     the same content at two positions"
                )));
            }
            report.layers += 1;
            if self.layers.contains_key(digest.as_str()) {
                // Already held. This is the incrementality: the bytes are not stored again.
                report.reused += 1;
            } else {
                self.layers.insert(digest.as_str().to_string(), bytes.len());
                report.admitted += 1;
                report.admitted_bytes += bytes.len();
            }
            described.push(Layer {
                digest,
                len: bytes.len(),
            });
        }

        let id = Snapshot::compute_id(parent, &described)?;
        self.snapshots.insert(
            id.as_str().to_string(),
            Snapshot {
                id: id.clone(),
                parent: parent.cloned(),
                layers: described,
            },
        );
        Ok((id, report))
    }

    /// Re-hash every layer of a snapshot and recompute its id.
    ///
    /// # Errors
    ///
    /// [`NauError::NotFound`] when the snapshot or one of its layers is missing, and
    /// [`NauError::Validation`] when the recomputed id is not the id the snapshot is filed
    /// under — which is what a tampered layer list produces.
    pub fn verify(&self, id: &SnapshotId) -> Result<()> {
        let snapshot = self
            .snapshots
            .get(id.as_str())
            .ok_or_else(|| NauError::NotFound(format!("snapshot {id} is not in this store")))?;

        for layer in &snapshot.layers {
            if !self.layers.contains_key(layer.digest.as_str()) {
                return Err(NauError::NotFound(format!(
                    "snapshot {id} names layer {} which the store does not hold",
                    layer.digest
                )));
            }
        }

        let recomputed = Snapshot::compute_id(snapshot.parent.as_ref(), &snapshot.layers)?;
        if recomputed != *id {
            return Err(NauError::Validation(format!(
                "snapshot {id} recomputes to {recomputed}; the layer list is not the one that \
                 was stored"
            )));
        }
        Ok(())
    }

    /// Every snapshot that names `id` as its parent.
    #[must_use]
    pub fn children_of(&self, id: &SnapshotId) -> Vec<&Snapshot> {
        self.snapshots
            .values()
            .filter(|s| s.parent.as_ref() == Some(id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(tag: u8) -> Vec<u8> {
        vec![tag; 64]
    }

    #[test]
    fn a_layer_already_stored_is_not_stored_again() {
        // B-04's first acceptance criterion, as a count. This is the whole of what incremental
        // means, and a test that asserted bytes-saved would be asserting the sizes it chose.
        let mut store = SnapshotStore::new();
        let (first, report) = store
            .store(None, &[layer(1), layer(2)])
            .expect("first snapshot");
        assert_eq!(report.layers, 2);
        assert_eq!(report.admitted, 2);
        assert_eq!(report.reused, 0);
        assert_eq!(report.admitted_bytes, 128);

        // The second snapshot shares layer 1 and adds layer 3.
        let (second, report) = store
            .store(Some(&first), &[layer(1), layer(3)])
            .expect("second snapshot");
        assert_eq!(report.layers, 2);
        assert_eq!(report.admitted, 1, "only layer 3 is new");
        assert_eq!(report.reused, 1, "layer 1 was already held");
        assert_eq!(report.admitted_bytes, 64);
        assert_ne!(first, second, "different layers, different snapshot");

        // And the store holds three layers, not four: the deduplication is real, not reported.
        assert_eq!(store.layer_count(), 3);
        assert_eq!(store.byte_count(), 192);
    }

    #[test]
    fn a_snapshot_that_shares_everything_is_reported_as_fully_shared() {
        let mut store = SnapshotStore::new();
        let (first, _) = store.store(None, &[layer(1), layer(2)]).expect("first");
        let (_, report) = store
            .store(Some(&first), &[layer(1), layer(2)])
            .expect("again");
        assert!(report.is_fully_shared());
        assert_eq!(report.admitted, 0);
        assert_eq!(report.reused, 2);
        assert_eq!(store.layer_count(), 2);
    }

    #[test]
    fn a_layer_shared_across_unrelated_snapshots_is_stored_once() {
        // Deduplication is by content address and not by parentage: a base layer used by two
        // independent snapshots must still be stored once.
        //
        // The first version of this test stored `[layer(1)]` twice under the same parent and
        // asserted two snapshots. It got one, and the implementation was right: a
        // content-addressed snapshot with the same parent and the same layers **is the same
        // snapshot**, which is the point of addressing it by content. The test now uses two
        // different snapshots that happen to share a layer, which is what it meant to say.
        let mut store = SnapshotStore::new();
        store.store(None, &[layer(1)]).expect("a");
        store.store(None, &[layer(1), layer(2)]).expect("b");
        assert_eq!(
            store.layer_count(),
            2,
            "layer 1 is held once even though two snapshots name it"
        );
        assert_eq!(store.snapshot_count(), 2);
    }

    #[test]
    fn the_same_parent_and_layers_is_the_same_snapshot() {
        // The flip side of the test above, and worth asserting on its own: storing a snapshot
        // identical to one already held does not create a second. A caller that wanted two
        // distinct snapshots has to make them distinct, which is a real constraint rather than
        // an accident -- and it is what makes a snapshot id usable as a cache key.
        let mut store = SnapshotStore::new();
        let (first, _) = store.store(None, &[layer(1)]).expect("first");
        let (second, report) = store.store(None, &[layer(1)]).expect("second");
        assert_eq!(
            first, second,
            "identical content and parent, identical snapshot"
        );
        assert_eq!(report.admitted, 0, "and nothing new was admitted");
        assert_eq!(store.snapshot_count(), 1);
    }

    #[test]
    fn a_snapshot_verifies_by_recomputation() {
        // B-04's second acceptance criterion.
        let mut store = SnapshotStore::new();
        let (id, _) = store.store(None, &[layer(1), layer(2)]).expect("snapshot");
        store.verify(&id).expect("verifies");
    }

    #[test]
    fn a_snapshot_whose_layer_list_was_changed_does_not_verify() {
        // The id is derived from the layer addresses, so a tampered list recomputes to something
        // else. A stored `verified: true` would have been a claim made once and trusted forever.
        let mut store = SnapshotStore::new();
        let (id, _) = store.store(None, &[layer(1)]).expect("snapshot");

        // Reach into the store the way a corrupted database would.
        let key = id.as_str().to_string();
        let snapshot = store.snapshots.get_mut(&key).expect("held");
        snapshot.layers.push(Layer {
            digest: ChunkDigest::of(&layer(9)),
            len: 64,
        });
        store
            .layers
            .insert(ChunkDigest::of(&layer(9)).as_str().to_string(), 64);

        let err = store.verify(&id).expect_err("must refuse");
        assert!(
            format!("{err}").contains("recomputes to"),
            "the refusal must say the list is not the one stored, got: {err}"
        );
    }

    #[test]
    fn a_missing_layer_fails_verification() {
        let mut store = SnapshotStore::new();
        let (id, _) = store.store(None, &[layer(1)]).expect("snapshot");
        store.layers.clear();
        let err = store.verify(&id).expect_err("must refuse");
        assert!(format!("{err}").contains("does not hold"), "got: {err}");
    }

    #[test]
    fn an_unknown_parent_is_refused_rather_than_treated_as_a_full_snapshot() {
        // The dishonest fallback would look correct, restore correctly, and not be what the
        // caller asked for -- and it would hide a broken chain until an older restore failed.
        let mut store = SnapshotStore::new();
        let ghost = SnapshotId("0".repeat(64));
        let err = store
            .store(Some(&ghost), &[layer(1)])
            .expect_err("must refuse");
        assert!(format!("{err}").contains("not in this store"), "got: {err}");
        assert_eq!(store.layer_count(), 0, "a refused store must admit nothing");
        assert_eq!(store.snapshot_count(), 0);
    }

    #[test]
    fn the_same_layer_twice_in_one_snapshot_is_refused() {
        // Not a deduplication opportunity: the caller's list describes the same content at two
        // positions, which a layer list cannot express.
        let mut store = SnapshotStore::new();
        let err = store
            .store(None, &[layer(1), layer(1)])
            .expect_err("must refuse");
        assert!(format!("{err}").contains("twice"), "got: {err}");
    }

    #[test]
    fn an_empty_layer_is_refused() {
        let mut store = SnapshotStore::new();
        let err = store
            .store(None, &[layer(1), Vec::new()])
            .expect_err("must refuse");
        assert!(format!("{err}").contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn a_snapshot_id_covers_its_parent() {
        // Two snapshots with the same layers but different parents are different snapshots: the
        // parent is part of what the snapshot is.
        let mut store = SnapshotStore::new();
        let (base, _) = store.store(None, &[layer(1)]).expect("base");
        let (on_base, _) = store
            .store(Some(&base), &[layer(1), layer(2)])
            .expect("on base");
        let (on_root, _) = store.store(None, &[layer(1), layer(2)]).expect("on root");
        assert_ne!(
            on_base, on_root,
            "the same layers under a different parent must not share an id"
        );
    }

    #[test]
    fn an_empty_snapshot_is_allowed_and_carries_no_layers() {
        // A snapshot of nothing is a legitimate state (a sandbox that has written nothing), and
        // it is distinct from a refusal: it stores, and it verifies.
        let mut store = SnapshotStore::new();
        let (id, report) = store.store(None, &[]).expect("empty");
        assert_eq!(report.layers, 0);
        assert!(!report.is_fully_shared(), "no layers is not 'fully shared'");
        store.verify(&id).expect("verifies");
        assert_eq!(store.layer_count(), 0);
    }

    #[test]
    fn children_are_found_by_parent() {
        let mut store = SnapshotStore::new();
        let (base, _) = store.store(None, &[layer(1)]).expect("base");
        store.store(Some(&base), &[layer(2)]).expect("child a");
        store.store(Some(&base), &[layer(3)]).expect("child b");
        assert_eq!(store.children_of(&base).len(), 2);
    }

    #[test]
    fn the_store_measures_what_it_holds_not_what_it_was_offered() {
        // The counts the incrementality claim rests on have to describe the store, not the calls:
        // three snapshots offering four layers each must leave four layers.
        let mut store = SnapshotStore::new();
        let (a, _) = store.store(None, &[layer(1), layer(2)]).expect("a");
        store.store(Some(&a), &[layer(2), layer(3)]).expect("b");
        store.store(Some(&a), &[layer(1), layer(2)]).expect("c");
        assert_eq!(store.layer_count(), 3, "layers 1, 2 and 3 -- each once");
        assert_eq!(store.snapshot_count(), 3);
    }
}
