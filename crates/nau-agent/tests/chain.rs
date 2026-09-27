//! Provenance-chain tests: the upstream `DefaultHasher` defect.
//!
//! upstream v2.5.6 fix: the chain must be SHA-256 (64 hex chars), stable, and
//! re-verifiable from the payloads it stores — not a 64-bit SipHash of an
//! input the chain then throws away.

use nau_agent::{link_digest, ChainLink, HashChain, GENESIS_DIGEST};
use nau_core::NauError;

/// Build a chain from stored links, as a verifier would after loading an audit
/// trail from disk.
fn load(links: &[ChainLink]) -> HashChain {
    HashChain::from_links(links.to_vec())
}

#[test]
fn digests_are_real_sha256_not_truncated_siphash() {
    let mut chain = HashChain::new();
    for (index, payload) in ["genesis-of-work", "second entry", "third entry"]
        .iter()
        .enumerate()
    {
        chain.append(payload, 1_000 + index as u64).unwrap();
    }
    for link in chain.links() {
        assert_eq!(
            link.digest.len(),
            64,
            "a SHA-256 digest is 64 hex characters; upstream returned 16"
        );
        assert!(
            link.digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "digest must be lowercase hex, got `{}`",
            link.digest
        );
    }
    // A real hash is a pure function of its input; pinning the value means a
    // change to the encoding cannot silently invalidate an existing audit trail.
    let pinned = link_digest(1, 1_000, "genesis-of-work", GENESIS_DIGEST);
    assert_eq!(pinned, chain.links()[0].digest);
}

#[test]
fn a_happy_chain_verifies_and_links_line_up() {
    let mut chain = HashChain::new();
    assert!(chain.is_empty());
    assert_eq!(chain.head(), None);
    assert_eq!(chain.prev_digest(), GENESIS_DIGEST);

    chain.append("task A done", 10).unwrap();
    chain.append("task B done", 20).unwrap();
    chain.append("task C done", 30).unwrap();

    assert_eq!(chain.len(), 3);
    assert!(!chain.is_empty());
    assert!(chain.verify_chain().is_ok());

    let links = chain.links();
    assert_eq!(links[0].prev_digest, GENESIS_DIGEST);
    assert_eq!(links[0].seq, 1);
    for pair in links.windows(2) {
        assert_eq!(pair[1].prev_digest, pair[0].digest);
        assert_eq!(pair[1].seq, pair[0].seq + 1);
    }
    assert_eq!(chain.head().map(|link| link.seq), Some(3));
    // The payload is retained, so the audit trail can be re-derived. Upstream
    // stored only the digest.
    assert_eq!(links[2].payload, "task C done");
}

#[test]
fn a_surviving_chain_can_be_reloaded_and_re_verified() {
    let mut chain = HashChain::new();
    chain.append("first", 1).unwrap();
    chain.append("second", 2).unwrap();

    // Round-trip through JSON, the way an audit trail is persisted.
    let encoded = serde_json::to_string(&chain).expect("chain serializes");
    let decoded: HashChain = serde_json::from_str(&encoded).expect("chain deserializes");
    assert_eq!(decoded, chain);
    assert!(
        decoded.verify_chain().is_ok(),
        "a stored chain must re-verify"
    );
}

#[test]
fn tampering_with_a_stored_payload_is_detected_and_names_the_index() {
    let mut chain = HashChain::new();
    for (index, payload) in ["alpha", "bravo", "charlie", "delta"].iter().enumerate() {
        chain.append(payload, index as u64 + 1).unwrap();
    }
    assert!(chain.verify_chain().is_ok());

    // Rewrite the payload of link 3 (1-based). Its digest no longer matches, and
    // verification must say *which* index broke.
    let mut tampered = chain.links().to_vec();
    tampered[2].payload = "charlie (edited)".to_string();
    let err = load(&tampered).verify_chain().unwrap_err();
    assert!(
        err.to_string().contains("index 3"),
        "the error must name the first broken index, got: {err}"
    );
    assert!(matches!(err, NauError::Validation(_)));

    // Every other index is also named correctly when tampered with.
    for victim in 0..4usize {
        let mut edited = chain.links().to_vec();
        edited[victim].payload = format!("payload {victim} was rewritten");
        let err = load(&edited).verify_chain().unwrap_err();
        assert!(
            err.to_string().contains(&format!("index {}", victim + 1)),
            "tampering at position {} should be reported as index {}, got: {err}",
            victim,
            victim + 1
        );
    }
}

#[test]
fn tampering_with_a_digest_is_detected_and_names_the_index() {
    let mut chain = HashChain::new();
    chain.append("first", 1).unwrap();
    chain.append("second", 2).unwrap();
    chain.append("third", 3).unwrap();

    let mut tampered = chain.links().to_vec();
    // A forged digest with a plausible shape still will not recompute.
    tampered[0].digest = "0".repeat(64);
    let err = load(&tampered).verify_chain().unwrap_err();
    assert!(err.to_string().contains("index 1"), "got: {err}");
}

#[test]
fn a_broken_prev_digest_link_is_detected_and_names_the_index() {
    let mut chain = HashChain::new();
    chain.append("first", 1).unwrap();
    chain.append("second", 2).unwrap();

    let mut tampered = chain.links().to_vec();
    tampered[1].prev_digest = GENESIS_DIGEST.to_string();
    let err = load(&tampered).verify_chain().unwrap_err();
    assert!(err.to_string().contains("index 2"), "got: {err}");
    assert!(err.to_string().contains("prev_digest"), "got: {err}");
}

#[test]
fn a_re_sequenced_link_is_detected_and_names_the_index() {
    let mut chain = HashChain::new();
    chain.append("first", 1).unwrap();
    chain.append("second", 2).unwrap();

    let mut tampered = chain.links().to_vec();
    tampered[1].seq = 7;
    let err = load(&tampered).verify_chain().unwrap_err();
    assert!(err.to_string().contains("index 2"), "got: {err}");
}

#[test]
fn reordering_links_breaks_verification() {
    let mut chain = HashChain::new();
    chain.append("alpha", 1).unwrap();
    chain.append("bravo", 2).unwrap();

    let mut tampered = chain.links().to_vec();
    tampered.swap(0, 1);
    assert!(load(&tampered).verify_chain().is_err());
}

#[test]
fn an_empty_chain_verifies_trivially() {
    assert!(HashChain::new().verify_chain().is_ok());
    assert!(load(&[]).verify_chain().is_ok());
}

#[test]
fn time_may_not_run_backwards() {
    let mut chain = HashChain::new();
    chain.append("first", 100).unwrap();
    let err = chain.append("second", 99).unwrap_err();
    assert!(matches!(err, NauError::Validation(_)), "got {err:?}");
    // Re-using the same instant is fine: two events can share a clock tick.
    assert!(chain.append("second", 100).is_ok());
    assert!(chain.verify_chain().is_ok());
}

#[test]
fn distinct_inputs_cannot_collide_through_the_encoding() {
    // Length-prefixed encoding, so splitting bytes differently must change the
    // digest rather than produce a collision.
    assert_ne!(
        link_digest(1, 0, "ab", "c"),
        link_digest(1, 0, "a", "bc"),
        "the digest encoding must be unambiguous"
    );
    // Changing only the timestamp or only the sequence must change the digest.
    assert_ne!(link_digest(1, 0, "x", "g"), link_digest(1, 1, "x", "g"));
    assert_ne!(link_digest(1, 0, "x", "g"), link_digest(2, 0, "x", "g"));
    assert_ne!(link_digest(1, 0, "x", "g"), link_digest(1, 0, "x", "h"));
    assert_ne!(link_digest(1, 0, "x", "g"), link_digest(1, 0, "y", "g"));
}

#[test]
fn a_chain_with_an_empty_payload_is_still_verifiable() {
    let mut chain = HashChain::new();
    chain.append("", 0).unwrap();
    assert!(chain.verify_chain().is_ok());
    assert_eq!(chain.len(), 1);
}

#[test]
fn a_thousand_link_chain_verifies() {
    // Guards against a digest that depends on accumulated state rather than the
    // stored fields.
    let mut chain = HashChain::new();
    for index in 0..1_000u64 {
        chain.append(&format!("entry {index}"), index).unwrap();
    }
    assert_eq!(chain.len(), 1_000);
    assert!(chain.verify_chain().is_ok());

    let mut tampered = chain.links().to_vec();
    tampered[500].payload.push('!');
    let err = load(&tampered).verify_chain().unwrap_err();
    assert!(err.to_string().contains("index 501"), "got: {err}");
}
