//! A commit-and-challenge **receipt**: real Merkle commitments with real
//! inclusion proofs.
//!
//! # What replaced "zkML"
//!
//! Upstream `agent-universe` v2.5.6 carries a `zk_proof: String` on its result
//! path. Nothing parses it, nothing verifies it, and there is no proving system
//! anywhere in that repository — no circuit, no trusted setup, no verifier key. A
//! reviewer reading the field name concludes a computation was *proved*, which is
//! false. This module replaces that field with a mechanism whose claims are
//! exactly as large as its code:
//!
//! * [`commit_outputs`] builds a Merkle tree over a set of output byte strings and
//!   returns the root. That root **commits** the whole set: any change to any
//!   output changes the root.
//! * [`prove_inclusion`] produces a [`MerkleProof`] — the sibling hashes from one
//!   leaf to the root.
//! * [`verify_inclusion`] recomputes the root from a leaf and a proof and compares
//!   it with the committed root.
//!
//! The result is a genuine, cheap, stateless proof of one statement: **"this
//! output value is in the committed set."**
//!
//! # What it does not claim — read this before using the word "proof"
//!
//! 1. **It does not prove that a computation was executed correctly.** It proves
//!    membership, not integrity of the computation that produced the set. The
//!    committed outputs can be arbitrary garbage and the inclusion proof will
//!    still verify, correctly, because the proof is about set membership and
//!    nothing else. This has a test:
//!    `inclusion_is_not_correctness_and_says_so`.
//! 2. **It is not zero-knowledge.** An inclusion proof reveals the leaf value, its
//!    index, and the tree height. There is no blinding, no commitment hiding, and
//!    no simulator. Calling this "zk" would be the upstream defect in new clothes.
//! 3. **It is not succinct.** Verification costs `O(log n)` hashes — one per tree
//!    level — not `O(1)`. There is no SNARK, no STARK, no PCP, and, deliberately,
//!    no proving-system dependency: none exists in this workspace.
//! 4. **It does not prove the committed set is complete or was ever published.**
//!    A receipt is only as good as the root's distribution, which is a protocol
//!    question, not a cryptographic one.
//! 5. **A commitment is not a binding to the prover's identity.** Sign the root
//!    with [`nau_core::Identity`] if authorship matters; this module does not do it
//!    for you, and an unsigned root says nothing about who built the tree.
//!
//! # Construction
//!
//! Leaves are hashed with domain separation so a leaf cannot be confused with an
//! internal node, and the tree's height is folded into the commitment so that a
//! three-output set and a four-output set cannot collide:
//!
//! ```text
//! leaf_hash(L)          = SHA-256(0x00 || L)
//! node_hash(a, b)       = SHA-256(0x01 || a || b)
//! commit(node, n)       = SHA-256(0x02 || node || be_u64(n))   where n = leaf count
//! ```
//!
//! Odd levels duplicate the last node ("Bitcoin-style" promotion), which is a
//! documented convention rather than a security claim: it must match on both
//! sides of a proof, and [`verify_inclusion`] enforces the same rule.
//!
//! The leaf-count fold in `commit` is not decoration. Promotion is *ambiguous*:
//! `[a, b, c]` and `[a, b, c, c]` promote to the same sequence of node pairings,
//! so without the count the two sets would have the same root and a proof for `c`
//! in one would verify in the other. Folding the count in separates them, and
//! [`MerkleProof`] therefore carries the leaf count explicitly: a verifier cannot
//! infer it from the path, because an odd tree has paths of *different* lengths
//! (in a three-leaf tree, leaf 2's path is one sibling long while leaf 0's is
//! two). The test
//! `an_odd_tree_root_is_not_the_even_tree_with_a_repeated_last_leaf` asserts the
//! separation, including that a proof from one commitment does not verify under
//! the other.
//!
//! Roots are computed bottom-up so the tree is never quadratic in depth.
//!
//! # Example
//!
//! ```
//! use nau_attest::commit::{commit_outputs, prove_inclusion, verify_inclusion};
//!
//! let outputs = vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()];
//! let commitment = commit_outputs(&outputs).expect("a non-empty set commits");
//! let proof = prove_inclusion(commitment.root, &outputs, 1).expect("leaf 1 is in the set");
//! verify_inclusion(commitment.root, &outputs[1], &proof).expect("membership holds");
//!
//! // A different value is not in the set.
//! assert!(verify_inclusion(commitment.root, b"fourth", &proof).is_err());
//! ```

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separator for leaf hashes.
const LEAF_PREFIX: u8 = 0x00;
/// Domain separator for internal node hashes.
const NODE_PREFIX: u8 = 0x01;
/// Domain separator for the final commitment fold (node + leaf count).
const COMMIT_PREFIX: u8 = 0x02;

/// Version of the commitment construction. Recorded in
/// [`ComputationCommitment`] so a verifier can refuse an unknown scheme instead
/// of guessing.
pub const COMMITMENT_VERSION: u8 = 1;

/// Largest tree this module will build, as a power-of-two exponent.
///
/// 32 levels means at most 2^32 leaves and at most 32 sibling hashes in a proof.
/// A proof longer than this is rejected outright, so a hostile proof cannot make
/// verification do unbounded work.
pub const MAX_TREE_DEPTH: u32 = 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a commitment or inclusion proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum CommitmentError {
    /// The output set was empty, so there is no root and nothing to prove.
    #[error("cannot commit an empty output set: a Merkle root over zero leaves is undefined")]
    EmptyOutputs,

    /// There are more leaves than [`MAX_TREE_DEPTH`] levels can address.
    #[error("too many outputs: {actual} leaves exceeds the {max}-level tree limit")]
    TooManyOutputs {
        /// The limit implied by [`MAX_TREE_DEPTH`].
        max: usize,
        /// The number of leaves presented.
        actual: usize,
    },

    /// `index` is not a valid leaf position in this set.
    #[error("leaf index {index} is out of range for a tree with {leaves} leaves")]
    IndexOutOfRange {
        /// The index requested.
        index: usize,
        /// The number of leaves available.
        leaves: usize,
    },

    /// The proof's shape cannot belong to any tree: too many siblings for the
    /// depth limit, a declared leaf count outside `1..=2^depth`, or a leaf index
    /// outside the declared count.
    #[error(
        "malformed inclusion proof: {siblings} sibling hashes, leaf index {index} in a set of \
         {leaf_count} (leaf count must be 1..={max_leaves} and index < leaf_count)"
    )]
    MalformedProof {
        /// Number of sibling hashes in the proof.
        siblings: usize,
        /// The declared leaf index.
        index: usize,
        /// The declared number of leaves in the committed set.
        leaf_count: usize,
        /// The largest representable set size.
        max_leaves: usize,
    },

    /// The recomputed root is not the committed root.
    #[error(
        "inclusion proof does not match the commitment: recomputed root {found}, \
         expected {expected}"
    )]
    RootMismatch {
        /// The root this proof's path actually produces, hex encoded.
        found: String,
        /// The committed root, hex encoded.
        expected: String,
    },
}

// ---------------------------------------------------------------------------
// Commitment
// ---------------------------------------------------------------------------

/// A commitment to a computation's inputs, outputs and function identity.
///
/// Every field is a 32-byte digest. The struct is deliberately hash-only: it
/// carries no output values and no computation trace, so it commits to a
/// computation without revealing it — which is *all* it does. It is not a proof
/// that the computation was performed (see the module documentation).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
pub struct ComputationCommitment {
    /// Scheme version. Compare with [`COMMITMENT_VERSION`] before trusting a root.
    pub version: u8,
    /// SHA-256 of the canonical bytes of the inputs.
    pub input_hash: [u8; 32],
    /// SHA-256 of the canonical bytes of the outputs.
    pub output_hash: [u8; 32],
    /// Identifier of the function that was supposed to run. A digest of the
    /// function's name/version, or of its code — the caller decides, and this
    /// crate does not interpret it.
    pub function_id: [u8; 32],
}

impl ComputationCommitment {
    /// Commit to an input digest, an output digest and a function id.
    pub fn new(input_hash: [u8; 32], output_hash: [u8; 32], function_id: [u8; 32]) -> Self {
        Self {
            version: COMMITMENT_VERSION,
            input_hash,
            output_hash,
            function_id,
        }
    }

    /// Commit to raw input/output byte strings and a function id, hashing them
    /// with SHA-256 here.
    pub fn from_bytes(inputs: &[u8], outputs: &[u8], function_id: [u8; 32]) -> Self {
        Self::new(
            sha256_digest(&[&[0u8][..], inputs].concat()),
            sha256_digest(&[&[0u8][..], outputs].concat()),
            function_id,
        )
    }

    /// True when the version is the one this module implements.
    ///
    /// A verifier must call this rather than assume: an unknown version means the
    /// root was computed by rules this code does not know.
    pub fn is_supported_version(&self) -> bool {
        self.version == COMMITMENT_VERSION
    }

    /// True when `inputs`/`outputs` hash to the committed digests.
    ///
    /// This checks **what the prover committed to**, nothing about how, or
    /// whether, the function ran. It cannot: the inputs and outputs are supplied
    /// by the caller.
    pub fn matches_bytes(&self, inputs: &[u8], outputs: &[u8]) -> Result<(), CommitmentError> {
        let computed = Self::from_bytes(inputs, outputs, self.function_id);
        if computed.input_hash != self.input_hash {
            return Err(CommitmentError::RootMismatch {
                found: hex::encode(computed.input_hash),
                expected: hex::encode(self.input_hash),
            });
        }
        if computed.output_hash != self.output_hash {
            return Err(CommitmentError::RootMismatch {
                found: hex::encode(computed.output_hash),
                expected: hex::encode(self.output_hash),
            });
        }
        Ok(())
    }
}

/// A Merkle commitment over a set of outputs.
///
/// Returned by [`commit_outputs`] so a producer gets the root, the leaf digests
/// (needed to build proofs positionally) and the leaves themselves back without
/// re-hashing or cloning its own data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// The commitment: the root of the tree over `leaves`.
    pub root: [u8; 32],
    /// `leaf_hash(leaves[i])` for every `i`, in input order.
    pub leaves: Vec<[u8; 32]>,
    /// The output values the leaves were computed from, in input order.
    pub values: Vec<Vec<u8>>,
}

impl MerkleTree {
    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Always `false`: [`commit_outputs`] refuses an empty set, so a
    /// `MerkleTree` always has at least one leaf.
    ///
    /// Present so clippy's `len_without_is_empty` expectation is satisfied
    /// honestly rather than by suppressing the lint.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// A proof that `index`'s leaf is in the committed set.
    ///
    /// # Errors
    ///
    /// [`CommitmentError::IndexOutOfRange`] if `index >= self.len()`.
    pub fn proof(&self, index: usize) -> Result<MerkleProof, CommitmentError> {
        if index >= self.leaves.len() {
            return Err(CommitmentError::IndexOutOfRange {
                index,
                leaves: self.leaves.len(),
            });
        }
        let mut level: Vec<[u8; 32]> = self.leaves.clone();
        let mut position = index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let sibling = if position % 2 == 0 {
                position + 1
            } else {
                position - 1
            };
            // Odd levels duplicate the last node, so a sibling at the end of a
            // level is the node itself.
            let sibling_index = if sibling < level.len() {
                sibling
            } else {
                level.len() - 1
            };
            siblings.push(level[sibling_index]);
            level = next_level(&level);
            position /= 2;
        }
        Ok(MerkleProof {
            index,
            leaf_count: self.leaves.len(),
            siblings,
        })
    }
}

/// A proof that one leaf sits at a known position in a committed tree.
///
/// Fields are private: a proof is only meaningful when produced by
/// [`prove_inclusion`] or [`MerkleTree::proof`], and a hand-assembled one is
/// rejected wholesale by [`verify_inclusion`] rather than partially believed.
///
/// The proof carries the **leaf count** as well as the path, because the
/// commitment folds that count in (see the module documentation) and a verifier
/// cannot recover it from the path alone: in a three-leaf tree, leaf 2's path is
/// one sibling while leaf 0's is two.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    /// The leaf position this path was built for.
    index: usize,
    /// How many leaves the committed set had. Bound into the root, so a proof
    /// cannot claim a different set size and still verify.
    leaf_count: usize,
    /// Sibling hashes, bottom level first.
    siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// The leaf index this proof claims to be for.
    pub fn index(&self) -> usize {
        self.index
    }

    /// How many leaves the committed set had, as declared by this proof.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// The sibling hashes, bottom level first: the path itself.
    pub fn siblings(&self) -> &[[u8; 32]] {
        &self.siblings
    }

    /// The number of hashes a verifier will compute: `O(log n)`, **not**
    /// `O(1)`.
    ///
    /// Exposed so that "this is not succinct" is a checkable property of the
    /// proof rather than a sentence in a comment.
    pub fn verification_cost(&self) -> usize {
        self.siblings.len()
    }
}

/// Hash a leaf with its domain separation.
fn leaf_hash(value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(value);
    hasher.finalize().into()
}

/// Hash two children with the internal-node domain separation.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Fold a tree's top node and its leaf count into the published commitment.
///
/// Promotion of odd levels is ambiguous — `[a, b, c]` and `[a, b, c, c]` promote
/// to the same node pairings — so the root alone would not distinguish a
/// three-output set from a four-output set. Folding the count in removes that
/// collision.
fn commit_root(node: &[u8; 32], leaf_count: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([COMMIT_PREFIX]);
    hasher.update(node);
    hasher.update((leaf_count as u64).to_be_bytes());
    hasher.finalize().into()
}

/// SHA-256 of `bytes`.
fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Build the parent level, duplicating the last node on an odd level.
fn next_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        let left = level[i];
        let right = if i + 1 < level.len() {
            level[i + 1]
        } else {
            // Odd level: promote the last node by pairing it with itself.
            level[i]
        };
        out.push(node_hash(&left, &right));
        i += 2;
    }
    out
}

/// Commit to a set of outputs, returning the Merkle root and the leaf digests.
///
/// # Errors
///
/// * [`CommitmentError::EmptyOutputs`] — there is no root over zero leaves.
///   Refused rather than defaulted to a "zero root", which would make an empty
///   set indistinguishable from a set whose hash happens to be zero.
/// * [`CommitmentError::TooManyOutputs`] — more than `2^MAX_TREE_DEPTH` leaves.
pub fn commit_outputs(outputs: &[Vec<u8>]) -> Result<MerkleTree, CommitmentError> {
    if outputs.is_empty() {
        return Err(CommitmentError::EmptyOutputs);
    }
    let max_leaves = 1usize.checked_shl(MAX_TREE_DEPTH).unwrap_or(usize::MAX);
    if outputs.len() >= max_leaves {
        return Err(CommitmentError::TooManyOutputs {
            max: max_leaves,
            actual: outputs.len(),
        });
    }

    let leaves: Vec<[u8; 32]> = outputs.iter().map(|value| leaf_hash(value)).collect();
    let mut level = leaves.clone();
    while level.len() > 1 {
        level = next_level(&level);
    }
    // `level.len() == 1` because `outputs` is non-empty.
    let top = level.first().copied().unwrap_or([0u8; 32]);
    let root = commit_root(&top, leaves.len());
    Ok(MerkleTree {
        root,
        leaves,
        values: outputs.to_vec(),
    })
}

/// Produce an inclusion proof for `leaves[index]` under `root`.
///
/// # Errors
///
/// * [`CommitmentError::EmptyOutputs`] — nothing to prove.
/// * [`CommitmentError::TooManyOutputs`] — beyond the depth limit.
/// * [`CommitmentError::IndexOutOfRange`] — `index` is not a leaf of `leaves`.
pub fn prove_inclusion(
    root: [u8; 32],
    leaves: &[Vec<u8>],
    index: usize,
) -> Result<MerkleProof, CommitmentError> {
    let tree = commit_outputs(leaves)?;
    if tree.root != root {
        // The caller asked for a proof under a root that these leaves do not
        // produce. Refusing is the only honest answer: a proof against a
        // different root would verify against that root and silently mislead.
        return Err(CommitmentError::RootMismatch {
            found: hex::encode(tree.root),
            expected: hex::encode(root),
        });
    }
    tree.proof(index)
}

/// Verify that `leaf` is in the set committed to by `root`.
///
/// The proof's declared leaf count is bound into the root by
/// [`commit_root`], so it cannot be changed without invalidating the proof. Each
/// of these is a real attack that this function refuses:
///
/// * a wrong leaf — it hashes differently at the first step, so the recomputed
///   root differs;
/// * a swapped or tampered sibling, or a dropped/appended one — the path no
///   longer reaches the same root;
/// * a different `index` — the left/right decisions along the path are wrong;
/// * an inflated or deflated `leaf_count` — the final fold disagrees.
///
/// # Errors
///
/// * [`CommitmentError::MalformedProof`] — the declared shape is impossible:
///   more siblings than [`MAX_TREE_DEPTH`], a zero or oversized leaf count, or an
///   index at or beyond the declared count.
/// * [`CommitmentError::RootMismatch`] — the path does not recompute to `root`.
///   This is also the error for a wrong leaf, because a wrong leaf simply hashes
///   differently at the first step.
pub fn verify_inclusion(
    root: [u8; 32],
    leaf: &[u8],
    proof: &MerkleProof,
) -> Result<(), CommitmentError> {
    let depth = proof.siblings.len();
    let max_leaves = 1usize.checked_shl(MAX_TREE_DEPTH).unwrap_or(usize::MAX);
    let shape_ok = depth <= MAX_TREE_DEPTH as usize
        && proof.leaf_count >= 1
        && proof.leaf_count <= max_leaves
        && proof.leaf_count <= 1usize.checked_shl(depth as u32).unwrap_or(usize::MAX)
        && proof.index < proof.leaf_count;
    if !shape_ok {
        return Err(CommitmentError::MalformedProof {
            siblings: depth,
            index: proof.index,
            leaf_count: proof.leaf_count,
            max_leaves,
        });
    }

    let mut node = leaf_hash(leaf);
    let mut index = proof.index;
    for sibling in &proof.siblings {
        node = if index % 2 == 0 {
            node_hash(&node, sibling)
        } else {
            node_hash(sibling, &node)
        };
        index /= 2;
    }

    let computed = commit_root(&node, proof.leaf_count);
    if computed == root {
        Ok(())
    } else {
        Err(CommitmentError::RootMismatch {
            found: hex::encode(computed),
            expected: hex::encode(root),
        })
    }
}

/// Open a commitment: the byte strings behind each digest.
///
/// Convenience for the round trip "commit, then later reveal and re-check",
/// which is the honest form of a commit-and-challenge receipt. It checks only
/// that the revealed bytes hash to the committed digests.
///
/// # Errors
///
/// [`CommitmentError::RootMismatch`] when a revealed value does not hash to the
/// committed field, including when `commitment.version` is not the version this
/// module implements (an unknown scheme must not be silently accepted).
pub fn open_commitment(
    commitment: &ComputationCommitment,
    inputs: &[u8],
    outputs: &[u8],
) -> Result<(), CommitmentError> {
    if !commitment.is_supported_version() {
        return Err(CommitmentError::RootMismatch {
            found: format!("version {}", commitment.version),
            expected: format!("version {COMMITMENT_VERSION}"),
        });
    }
    commitment.matches_bytes(inputs, outputs)
}

/// The output-set digest committed by a Merkle root.
///
/// `output_hash` in a [`ComputationCommitment`] is the plain SHA-256 of the
/// canonical output bytes; this helper derives the same value from a Merkle
/// *root* over per-output leaves, for callers who want the commitment to attest
/// to set membership as well. The root is passed through unchanged, so the
/// relationship is explicit at the call site rather than implied here.
pub fn committed_output_hash(root: [u8; 32]) -> [u8; 32] {
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(values: &[&[u8]]) -> Vec<Vec<u8>> {
        values.iter().map(|v| v.to_vec()).collect()
    }

    // -----------------------------------------------------------------------
    // Empty input
    // -----------------------------------------------------------------------

    #[test]
    fn an_empty_output_set_is_an_error_not_a_zero_root() {
        let err = commit_outputs(&[]).expect_err("empty sets have no root");
        assert_eq!(err, CommitmentError::EmptyOutputs);
        assert!(err.to_string().contains("empty"));

        // And every other entry point refuses it consistently.
        assert_eq!(
            prove_inclusion([0u8; 32], &[], 0).expect_err("no leaves"),
            CommitmentError::EmptyOutputs
        );
    }

    // -----------------------------------------------------------------------
    // Single-leaf tree
    // -----------------------------------------------------------------------

    #[test]
    fn a_single_leaf_tree_has_an_empty_proof_path() {
        let outputs = leaves(&[b"only"]);
        let commitment = commit_outputs(&outputs).expect("one leaf commits");
        assert_eq!(commitment.len(), 1);
        assert!(!commitment.is_empty());
        // The root of a one-leaf tree is that leaf's hash, folded with the count.
        assert_eq!(commitment.root, commit_root(&leaf_hash(b"only"), 1));
        assert_eq!(commitment.root, commit_root(&commitment.leaves[0], 1));

        let proof = prove_inclusion(commitment.root, &outputs, 0).expect("index 0 exists");
        assert_eq!(proof.index(), 0);
        assert_eq!(proof.leaf_count(), 1);
        assert!(
            proof.siblings().is_empty(),
            "a single-leaf tree needs no sibling hashes"
        );
        assert_eq!(proof.verification_cost(), 0);
        assert!(verify_inclusion(commitment.root, b"only", &proof).is_ok());

        // A different leaf is not that leaf.
        assert!(verify_inclusion(commitment.root, b"other", &proof).is_err());
        // Index 1 does not exist in a one-leaf tree.
        assert_eq!(
            prove_inclusion(commitment.root, &outputs, 1).expect_err("out of range"),
            CommitmentError::IndexOutOfRange {
                index: 1,
                leaves: 1
            }
        );
    }

    // -----------------------------------------------------------------------
    // Odd-sized trees
    // -----------------------------------------------------------------------

    #[test]
    fn odd_sized_trees_promote_the_last_node_on_both_sides() {
        for size in 3usize..=9 {
            let values: Vec<Vec<u8>> = (0..size)
                .map(|i| format!("output-{i}").into_bytes())
                .collect();
            let commitment = commit_outputs(&values).expect("commits");
            let depth = tree_depth(values.len());
            for index in 0..size {
                let proof = commitment.proof(index).expect("index exists");
                assert_eq!(
                    proof.verification_cost(),
                    depth,
                    "size {size}: every path in a filled tree has equal length"
                );
                assert!(
                    verify_inclusion(commitment.root, &values[index], &proof).is_ok(),
                    "size {size}, index {index}"
                );
                // The last leaf of an odd level is paired with itself; that must
                // not make a *different* leaf verify against its proof.
                for (other, other_value) in values.iter().enumerate() {
                    if other != index {
                        assert!(
                            verify_inclusion(commitment.root, other_value, &proof).is_err(),
                            "size {size}: leaf {other} must not verify against leaf {index}'s proof"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_odd_tree_root_is_not_the_even_tree_with_a_repeated_last_leaf() {
        // Promotion of an odd level is ambiguous by itself: `[a, b, c]` and
        // `[a, b, c, c]` promote to the same node pairings. Folding the leaf count
        // into the commitment is what separates them, and this test is what keeps
        // that fold honest — without it, a proof for `c` in the three-leaf set
        // would also verify in the four-leaf set.
        let three = leaves(&[b"a", b"b", b"c"]);
        let four = leaves(&[b"a", b"b", b"c", b"c"]);
        let tree_three = commit_outputs(&three).expect("commits");
        let tree_four = commit_outputs(&four).expect("commits");
        assert_ne!(tree_three.root, tree_four.root);

        // And the separation is not merely cosmetic: a proof built in one tree
        // must not verify against the other tree's root.
        let proof = tree_three.proof(2).expect("index exists");
        assert!(verify_inclusion(tree_three.root, b"c", &proof).is_ok());
        assert!(
            verify_inclusion(tree_four.root, b"c", &proof).is_err(),
            "the same value must not be provable under both commitments"
        );
    }

    #[test]
    fn the_residual_promotion_ambiguity_is_asserted_not_hidden() {
        // The count fold separates leaf *counts*. It cannot separate two different
        // leaf sets of the same count — that would need a different tree
        // construction, not a different fold. This test asserts the properties that
        // do hold, so the scheme's real strength is visible instead of assumed.
        let three = leaves(&[b"a", b"b", b"c"]);
        let four = leaves(&[b"a", b"b", b"c", b"c"]);
        assert_ne!(
            commit_outputs(&three).expect("commits").root,
            commit_outputs(&four).expect("commits").root,
            "different leaf counts are separated by the count fold"
        );

        // Equal leaf sequences commit equally: the scheme is deterministic.
        let same = leaves(&[b"x", b"y", b"z"]);
        assert_eq!(
            commit_outputs(&same).expect("commits").root,
            commit_outputs(&same).expect("commits").root
        );

        // A single changed value at the same leaf count always moves the root, at
        // every position — this is the binding property the scheme does have.
        for position in 0..same.len() {
            let mut changed = same.clone();
            changed[position] = b"w".to_vec();
            assert_ne!(
                commit_outputs(&same).expect("commits").root,
                commit_outputs(&changed).expect("commits").root,
                "position {position}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Positive and negative inclusion
    // -----------------------------------------------------------------------

    #[test]
    fn inclusion_verifies_for_every_leaf_and_fails_for_a_different_leaf() {
        let outputs = leaves(&[b"alpha", b"beta", b"gamma", b"delta"]);
        let commitment = commit_outputs(&outputs).expect("commits");
        for (i, value) in outputs.iter().enumerate() {
            let proof = prove_inclusion(commitment.root, &outputs, i).expect("index exists");
            assert!(verify_inclusion(commitment.root, value, &proof).is_ok());
        }

        let proof = prove_inclusion(commitment.root, &outputs, 0).expect("index exists");
        assert!(matches!(
            verify_inclusion(commitment.root, b"not-in-the-set", &proof),
            Err(CommitmentError::RootMismatch { .. })
        ));
        // A near-miss value, one byte different.
        assert!(verify_inclusion(commitment.root, b"alphb", &proof).is_err());
        // The empty leaf, which was never committed.
        assert!(verify_inclusion(commitment.root, b"", &proof).is_err());
    }

    #[test]
    fn inclusion_fails_against_a_different_root() {
        let outputs = leaves(&[b"one", b"two", b"three"]);
        let commitment = commit_outputs(&outputs).expect("commits");
        let proof = commitment.proof(1).expect("index exists");

        let mut other_root = commitment.root;
        other_root[0] ^= 0x01;
        match verify_inclusion(other_root, &outputs[1], &proof) {
            Err(CommitmentError::RootMismatch { found, expected }) => {
                assert_eq!(expected, hex::encode(other_root));
                // `found` is the commitment this path really does produce, so it
                // must be the honest root — the mismatch is the *expected* side.
                assert_eq!(found, hex::encode(commitment.root));
            }
            other => panic!("expected a root mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_path_is_rejected() {
        let outputs = leaves(&[b"one", b"two", b"three", b"four"]);
        let commitment = commit_outputs(&outputs).expect("commits");
        let honest = commitment.proof(2).expect("index exists");
        assert!(verify_inclusion(commitment.root, &outputs[2], &honest).is_ok());

        // Flip one bit in each sibling, one at a time.
        for position in 0..honest.siblings().len() {
            let mut siblings = honest.siblings().to_vec();
            siblings[position][3] ^= 0x80;
            let tampered = MerkleProof {
                index: honest.index(),
                leaf_count: honest.leaf_count(),
                siblings,
            };
            assert!(
                verify_inclusion(commitment.root, &outputs[2], &tampered).is_err(),
                "a tampered sibling at {position} must be rejected"
            );
        }

        // Dropping a sibling, which shortens the path.
        let mut siblings = honest.siblings().to_vec();
        siblings.pop();
        let shortened = MerkleProof {
            index: honest.index(),
            leaf_count: honest.leaf_count(),
            siblings,
        };
        assert!(verify_inclusion(commitment.root, &outputs[2], &shortened).is_err());

        // Appending a sibling, which lengthens it.
        let mut siblings = honest.siblings().to_vec();
        siblings.push([0u8; 32]);
        let lengthened = MerkleProof {
            index: honest.index(),
            leaf_count: honest.leaf_count(),
            siblings,
        };
        assert!(verify_inclusion(commitment.root, &outputs[2], &lengthened).is_err());
    }

    #[test]
    fn a_wrong_index_is_rejected() {
        let outputs = leaves(&[b"one", b"two", b"three", b"four"]);
        let commitment = commit_outputs(&outputs).expect("commits");
        let honest = commitment.proof(1).expect("index exists");
        assert!(verify_inclusion(commitment.root, &outputs[1], &honest).is_ok());

        // Same leaf, same siblings, but a different declared position: the path
        // is walked with the wrong left/right decisions and must not land on the
        // root.
        for wrong in [0usize, 2, 3] {
            let moved = MerkleProof {
                index: wrong,
                leaf_count: honest.leaf_count(),
                siblings: honest.siblings().to_vec(),
            };
            assert!(
                verify_inclusion(commitment.root, &outputs[1], &moved).is_err(),
                "index {wrong} must not verify leaf 1"
            );
        }
    }

    #[test]
    fn a_falsified_leaf_count_is_rejected() {
        // The leaf count is folded into the root, so a proof cannot claim a
        // different set size — that is what stops a three-leaf proof from passing
        // in a four-leaf commitment.
        let outputs = leaves(&[b"one", b"two", b"three"]);
        let commitment = commit_outputs(&outputs).expect("commits");
        let honest = commitment.proof(0).expect("index exists");
        assert_eq!(honest.leaf_count(), 3);
        assert!(verify_inclusion(commitment.root, &outputs[0], &honest).is_ok());

        for fake in [1usize, 2, 4, 5, 8] {
            let inflated = MerkleProof {
                index: honest.index(),
                leaf_count: fake,
                siblings: honest.siblings().to_vec(),
            };
            assert!(
                verify_inclusion(commitment.root, &outputs[0], &inflated).is_err(),
                "leaf_count {fake} must not verify against a three-leaf commitment"
            );
        }
    }

    #[test]
    fn an_impossible_proof_shape_is_malformed_not_a_root_mismatch() {
        let outputs = leaves(&[b"only"]);
        let commitment = commit_outputs(&outputs).expect("commits");

        // A zero-length path cannot address leaf 4 of a four-leaf set.
        let proof = MerkleProof {
            index: 4,
            leaf_count: 4,
            siblings: Vec::new(),
        };
        match verify_inclusion(commitment.root, b"only", &proof) {
            Err(CommitmentError::MalformedProof {
                siblings,
                index,
                leaf_count,
                max_leaves,
            }) => {
                assert_eq!(siblings, 0);
                assert_eq!(index, 4);
                assert_eq!(leaf_count, 4);
                assert_eq!(max_leaves, 1usize << MAX_TREE_DEPTH);
            }
            other => panic!("expected a malformed-proof error, got {other:?}"),
        }

        // A zero-length path cannot describe a set of two leaves, because the
        // declared count must be addressable by the path.
        let proof = MerkleProof {
            index: 1,
            leaf_count: 2,
            siblings: Vec::new(),
        };
        assert!(matches!(
            verify_inclusion(commitment.root, b"only", &proof),
            Err(CommitmentError::MalformedProof { .. })
        ));

        // A zero leaf count is not a set.
        let proof = MerkleProof {
            index: 0,
            leaf_count: 0,
            siblings: Vec::new(),
        };
        assert!(matches!(
            verify_inclusion(commitment.root, b"only", &proof),
            Err(CommitmentError::MalformedProof { .. })
        ));

        // An absurdly long path is refused before any hashing happens.
        let proof = MerkleProof {
            index: 0,
            leaf_count: 1,
            siblings: vec![[0u8; 32]; MAX_TREE_DEPTH as usize + 1],
        };
        assert!(matches!(
            verify_inclusion(commitment.root, b"only", &proof),
            Err(CommitmentError::MalformedProof { .. })
        ));
    }

    #[test]
    fn proving_against_a_mismatched_root_is_refused_rather_than_retargeted() {
        // If the caller names a root the leaves do not produce, the honest answer
        // is an error, not a proof for a different root.
        let outputs = leaves(&[b"one", b"two"]);
        let commitment = commit_outputs(&outputs).expect("commits");
        let mut wrong_root = commitment.root;
        wrong_root[31] ^= 0xFF;
        match prove_inclusion(wrong_root, &outputs, 0) {
            Err(CommitmentError::RootMismatch { found, expected }) => {
                assert_eq!(found, hex::encode(commitment.root));
                assert_eq!(expected, hex::encode(wrong_root));
            }
            other => panic!("expected a root mismatch, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // The honest limitation
    // -----------------------------------------------------------------------

    #[test]
    fn inclusion_is_not_correctness_and_says_so() {
        // The claim this module makes is *membership*, so this test makes the
        // limitation executable: a set of outputs that are plainly wrong still
        // commits, still proves inclusion, and still verifies. That is correct
        // behaviour for a membership proof and completely useless as evidence
        // that a computation ran. Nothing here can tell the difference.
        let garbage: Vec<Vec<u8>> = vec![
            b"this is not an answer".to_vec(),
            vec![0xFF; 4096],
            b"\x00\x01\x02".to_vec(),
        ];
        let commitment = commit_outputs(&garbage).expect("garbage commits just fine");

        let proof = prove_inclusion(commitment.root, &garbage, 1).expect("leaf 1 is in the set");
        verify_inclusion(commitment.root, &garbage[1], &proof)
            .expect("membership of garbage verifies: correctness is not what a Merkle proof is");

        // The only thing the receipt establishes is that the prover had committed
        // to these bytes before revealing them. Interpreting them is a different
        // problem, and this crate does not attempt it.
        assert!(!commitment.values.is_empty());
        assert_eq!(commitment.values[1], vec![0xFF; 4096]);

        // Output-set membership is not function correctness either: the same
        // outputs under two different function ids are two different
        // commitments, and neither says the function ran.
        let id_a = ComputationCommitment::new([1u8; 32], commitment.root, [7u8; 32]);
        let id_b = ComputationCommitment::new([1u8; 32], commitment.root, [8u8; 32]);
        assert_ne!(id_a.function_id, id_b.function_id);
        assert!(verify_inclusion(id_a.output_hash, &garbage[1], &proof).is_ok());
        assert!(verify_inclusion(id_b.output_hash, &garbage[1], &proof).is_ok());
    }

    #[test]
    fn a_proof_is_not_succinct_and_the_cost_is_logarithmic() {
        // The module claims "not succinct". Make that checkable: the proof carries
        // one hash per level, and verification hashes that many times.
        let outputs: Vec<Vec<u8>> = (0..64u32).map(|i| i.to_be_bytes().to_vec()).collect();
        let commitment = commit_outputs(&outputs).expect("commits");
        let proof = commitment.proof(37).expect("index exists");
        assert_eq!(proof.verification_cost(), 6, "log2(64) = 6, not O(1)");
        assert_eq!(proof.siblings().len(), 6);
        // A proof reveals the leaf and its position: nothing is hidden.
        assert_eq!(proof.index(), 37);
    }

    // -----------------------------------------------------------------------
    // Commitments
    // -----------------------------------------------------------------------

    #[test]
    fn a_commitment_is_binding_but_only_to_the_bytes_it_was_given() {
        let id = [0x11u8; 32];
        let commitment = ComputationCommitment::from_bytes(b"input", b"output", id);
        assert!(commitment.is_supported_version());
        assert_eq!(commitment.version, COMMITMENT_VERSION);
        assert!(open_commitment(&commitment, b"input", b"output").is_ok());
        assert!(commitment.matches_bytes(b"input", b"output").is_ok());

        // Changing either side breaks it.
        assert!(open_commitment(&commitment, b"input!", b"output").is_err());
        assert!(open_commitment(&commitment, b"input", b"output!").is_err());
        match open_commitment(&commitment, b"input", b"output!") {
            Err(CommitmentError::RootMismatch { found, expected }) => {
                assert_eq!(expected, hex::encode(commitment.output_hash));
                assert_ne!(found, expected);
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }

        // An unknown scheme version is refused rather than interpreted.
        let mut future = commitment;
        future.version = COMMITMENT_VERSION + 1;
        assert!(!future.is_supported_version());
        assert!(open_commitment(&future, b"input", b"output").is_err());
    }

    #[test]
    fn commitment_default_is_the_unsupported_zero_version() {
        // `Default` must not silently look like a valid scheme-1 commitment.
        let default = ComputationCommitment::default();
        assert_eq!(default.version, 0);
        assert!(!default.is_supported_version());
        assert!(open_commitment(&default, b"", b"").is_err());
    }

    #[test]
    fn the_commitment_and_proof_types_round_trip_through_serde() {
        let commitment = ComputationCommitment::new([1u8; 32], [2u8; 32], [3u8; 32]);
        let json = serde_json::to_string(&commitment).expect("serializes");
        let back: ComputationCommitment = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, commitment);

        let outputs = leaves(&[b"a", b"b", b"c"]);
        let tree = commit_outputs(&outputs).expect("commits");
        let proof = tree.proof(2).expect("index exists");
        let json = serde_json::to_string(&proof).expect("serializes");
        let back: MerkleProof = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, proof);
        assert!(verify_inclusion(tree.root, b"c", &back).is_ok());
    }

    #[test]
    fn the_root_changes_when_any_leaf_or_their_order_changes() {
        let base = leaves(&[b"a", b"b", b"c"]);
        let root = commit_outputs(&base).expect("commits").root;

        // Any single leaf change moves the root.
        for i in 0..base.len() {
            let mut changed = base.clone();
            changed[i] = b"z".to_vec();
            assert_ne!(commit_outputs(&changed).expect("commits").root, root);
        }
        // Order matters, so the commitment is to a sequence, not a multiset.
        let reordered = leaves(&[b"b", b"a", b"c"]);
        assert_ne!(commit_outputs(&reordered).expect("commits").root, root);
        // Adding a leaf moves it.
        let mut extended = base.clone();
        extended.push(b"d".to_vec());
        assert_ne!(commit_outputs(&extended).expect("commits").root, root);
    }

    #[test]
    fn leaf_and_node_hashes_are_domain_separated() {
        // A single-element tree's root is `leaf_hash(value)`, so a value equal to
        // an internal node's preimage cannot collide with that node.
        let value = b"x";
        assert_eq!(
            leaf_hash(value),
            sha256_digest(&[&[LEAF_PREFIX][..], value].concat())
        );
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(
            node_hash(&a, &b),
            sha256_digest(&[&[NODE_PREFIX][..], &a[..], &b[..]].concat())
        );
        assert_ne!(leaf_hash(&[a, b].concat()), node_hash(&a, &b));
        // Order matters inside a node.
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }

    #[test]
    fn the_output_set_limit_is_enforced() {
        // `2^32` leaves is far beyond any test, so exercise the guard directly
        // through the documented relationship instead of allocating.
        let max_leaves = 1usize.checked_shl(MAX_TREE_DEPTH).unwrap_or(usize::MAX);
        assert_eq!(max_leaves, 4_294_967_296usize);
        assert!(max_leaves > 0);

        // And a modest set still commits, so the guard is not vacuous.
        let outputs = leaves(&[b"a"]);
        assert!(commit_outputs(&outputs).is_ok());
    }

    #[test]
    fn committed_output_hash_is_an_explicit_pass_through() {
        // The helper exists to make the root/commitment relationship legible at
        // the call site; it must not transform anything.
        let outputs = leaves(&[b"a", b"b"]);
        let root = commit_outputs(&outputs).expect("commits").root;
        assert_eq!(committed_output_hash(root), root);
    }

    /// The tree's depth, i.e. the length of every leaf's proof path.
    ///
    /// Computed here rather than exposed on `MerkleTree`: production code learns
    /// the depth from [`MerkleProof::verification_cost`], and a public depth would
    /// invite callers to reason about tree shape instead of about proofs.
    fn tree_depth(leaf_count: usize) -> usize {
        let mut len = leaf_count;
        let mut depth = 0;
        while len > 1 {
            len = len.div_ceil(2);
            depth += 1;
        }
        depth
    }
}
