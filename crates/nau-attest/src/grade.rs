//! Evidence grading that refuses to launder trust.
//!
//! The ladder is deliberately short, and its top rung is deliberately
//! unreachable:
//!
//! ```text
//! Unverified  <  StructurallyValid  <  SignatureVerified  <  HardwareAttested
//!                                                             ^
//!                                                             |
//!                                          unreachable in this crate — see below
//! ```
//!
//! ## Why [`EvidenceGrade::HardwareAttested`] is unreachable
//!
//! Reaching it would require verifying a full vendor chain: parse the quote's
//! certification data, walk the PCK/VCEK certificate chain to Intel's or AMD's
//! pinned root, check the signature over the report body with the leaf key, and
//! evaluate the reported TCB level. **None of that is implemented here**, so the
//! only honest grading function is one that cannot return the top grade at all.
//!
//! This is enforced structurally, not by a comment:
//!
//! * [`grade_of`] has no `HardwareAttested` arm and never constructs the
//!   variant, so no input can produce it. The test
//!   `hardware_attested_is_unreachable` walks a matrix of inputs — every format,
//!   valid and invalid envelopes, every recorded refusal reason — and asserts the
//!   top grade never appears.
//! * [`crate::attest::VerifiedAttestation`] is the only value that grades above
//!   [`EvidenceGrade::StructurallyValid`], and
//!   [`crate::attest::Verifier::verify`] constructs it only after the signature,
//!   nonce, freshness and `report_data` checks all pass. It reports its own grade
//!   as a constant: [`EvidenceGrade::SignatureVerified`].
//! * [`MAX_ACHIEVABLE_GRADE`] is published so callers can render the honest
//!   ceiling instead of inferring one.
//!
//! If a future change adds real chain verification, this module's documentation
//! and that test must change together. Until then, a caller who sees
//! `EvidenceGrade::HardwareAttested` in this crate's API knows it names a value
//! the code cannot produce — which is exactly the point.

use crate::attest::{SignedAttestation, Verified};

/// How much of an attestation envelope's trust claim was actually checked.
///
/// Ordered from least to most trustworthy, so `grade >= other` is a meaningful
/// comparison. [`EvidenceGrade::default`] is [`EvidenceGrade::Unverified`]:
/// fail-closed, because an envelope that does not say otherwise is data, not
/// evidence.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGrade {
    /// Nothing was checked, a check failed, or the format's certificate chain is
    /// not implemented. The envelope is data, not evidence.
    #[default]
    Unverified,
    /// The bytes parse as the format they claim to be and `report_data` commits
    /// to the payload. No signature was checked — treat as hostile input.
    StructurallyValid,
    /// The bytes parse; the signature verifies under a **verifier-pinned** key;
    /// the nonce equals the one the verifier chose; the envelope is fresh; and
    /// `report_data` commits to the exact canonical payload bytes. This is the
    /// highest grade this crate can award.
    SignatureVerified,
    /// **Not reachable in this crate.** Would mean a full vendor certificate
    /// chain and hardware root were verified, which [`crate::attest`] does not
    /// implement. [`grade_of`] never constructs this variant; see the module
    /// documentation.
    HardwareAttested,
}

/// The highest grade this crate can produce, published so callers do not have to
/// infer the ceiling.
///
/// It is one rung below [`EvidenceGrade::HardwareAttested`] **on purpose**: the
/// hardware rung requires a certificate-chain verification that does not exist
/// here.
pub const MAX_ACHIEVABLE_GRADE: EvidenceGrade = EvidenceGrade::SignatureVerified;

/// Machine-readable name of a grade, for logs and diagnostics.
///
/// Provided so reporting code never has to `Debug`-format an enum into a
/// user-facing message (and so the wire name cannot drift silently — see
/// `grade_is_serialized_as_a_snake_case_string`).
pub fn label(grade: EvidenceGrade) -> &'static str {
    match grade {
        EvidenceGrade::Unverified => "unverified",
        EvidenceGrade::StructurallyValid => "structurally-valid",
        EvidenceGrade::SignatureVerified => "signature-verified",
        // Reachable only when *naming* the tier, never when awarding it.
        EvidenceGrade::HardwareAttested => "hardware-attested",
    }
}

/// Grade an envelope from its verification outcome.
///
/// There is deliberately **no `HardwareAttested` arm**. The tier is unreachable
/// by construction, because no code in this crate verifies a vendor certificate
/// chain or a hardware root. Awarding it would be precisely the overclaim
/// upstream v2.5.6 made by shipping unparsed `tee_quote` strings.
///
/// * A refusal of any kind ⇒ [`EvidenceGrade::Unverified`]. In particular
///   [`UnverifiedReason::ChainNotImplemented`] grades `Unverified` **even though**
///   the envelope's signature, nonce, freshness and `report_data` bindings may all
///   have held. An Ed25519 signature proves *who assembled the bytes*; it can
///   never prove *what hardware produced a quote*, because the quote is just bytes
///   the signer chose.
/// * [`Verified::Verified`] ⇒ [`MAX_ACHIEVABLE_GRADE`], which is
///   [`EvidenceGrade::SignatureVerified`].
pub fn grade_of(verdict: &Verified<SignedAttestation<'_>>) -> EvidenceGrade {
    match verdict {
        Verified::Verified(_checked) => MAX_ACHIEVABLE_GRADE,
        // One arm, and intentionally so: every refusal is `Unverified`. Writing
        // it as an explicit enumeration of the reasons would suggest that some
        // refusal could grade higher, which is not the case and never will be
        // without an implemented chain.
        Verified::Unverified(_refusal) => EvidenceGrade::Unverified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{
        AttestationEnvelope, AttestationFormat, TrustedRoots, UnverifiedReason, Verifier,
    };
    use nau_core::Identity;
    use serde_json::json;

    const SEED: [u8; 32] = [7u8; 32];

    /// Every declared format, so the "unreachable" claim is checked for all of
    /// them rather than for one convenient case.
    const ALL_FORMATS: [AttestationFormat; 4] = [
        AttestationFormat::Opaque,
        AttestationFormat::SevSnpReport,
        AttestationFormat::TdxQuote,
        AttestationFormat::SgxQuoteV3,
    ];

    fn identity() -> Identity {
        Identity::from_seed(&SEED)
    }

    fn payload() -> Vec<u8> {
        serde_json::to_vec(&json!({ "kind": "result", "task": "t-1", "value": 42 }))
            .expect("json encodes")
    }

    #[test]
    fn hardware_attested_is_unreachable() {
        // The whole point of this crate: no input in the suite produces the top
        // grade. Every refusal path and every format is exercised.
        let id = identity();
        let nonce = [3u8; 32];
        let now = 1_700_000_000u64;

        for format in ALL_FORMATS {
            let mut roots = TrustedRoots::new();
            roots.pin(format, id.public_key());
            let verifier = Verifier::new(roots, 300);

            let env = AttestationEnvelope::new(format, &payload(), &id, nonce, || now, None)
                .expect("envelope builds");

            // 1. Wrong nonce.
            let mut verdict = verifier.verify(&env, [9u8; 32], now);
            assert!(verdict.is_err(), "{format:?}: wrong nonce must be refused");
            assert_eq!(grade_of(&verdict), EvidenceGrade::Unverified);
            assert_ne!(grade_of(&verdict), EvidenceGrade::HardwareAttested);

            // 2. Un-pinned signer.
            let stranger = Verifier::new(TrustedRoots::new(), 300);
            verdict = stranger.verify(&env, nonce, now);
            assert!(verdict.is_err(), "{format:?}: stranger must be refused");
            assert_eq!(grade_of(&verdict), EvidenceGrade::Unverified);
            assert_ne!(grade_of(&verdict), EvidenceGrade::HardwareAttested);

            // 3. Stale.
            verdict = verifier.verify(&env, nonce, now.saturating_add(100_000));
            assert!(verdict.is_err(), "{format:?}: stale must be refused");
            assert_ne!(grade_of(&verdict), EvidenceGrade::HardwareAttested);

            // 4. The format's own refusal reason cannot grade above the floor
            //    either.
            let chain = UnverifiedReason::ChainNotImplemented { format };
            assert_eq!(chain.grade(), EvidenceGrade::Unverified);
            assert_ne!(chain.grade(), EvidenceGrade::HardwareAttested);
        }

        // 5. A fully valid envelope cannot exceed the published ceiling, and its
        //    own outcome reports that ceiling — never the hardware rung.
        let mut roots = TrustedRoots::new();
        roots.pin(AttestationFormat::Opaque, id.public_key());
        let verifier = Verifier::new(roots, 300);
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(),
            &id,
            nonce,
            || now,
            None,
        )
        .expect("envelope builds");
        let valid = verifier.verify(&env, nonce, now);
        // No chain is implemented, so even here the verdict is a refusal — but a
        // refusal whose recorded checks all passed, which is the honest result.
        assert!(valid.is_err(), "no chain is implemented: {valid:?}");
        assert_eq!(valid.grade(), EvidenceGrade::Unverified);
        assert_eq!(grade_of(&valid), EvidenceGrade::Unverified);
        assert!(
            valid.refusal().expect("refused").checks.all_implemented(),
            "every implemented check did pass"
        );
        assert_ne!(valid.grade(), EvidenceGrade::HardwareAttested);
        assert!(MAX_ACHIEVABLE_GRADE < EvidenceGrade::HardwareAttested);
    }

    #[test]
    fn the_top_grade_is_never_produced_by_the_grade_function() {
        // Direct statement of the claim, over an exhaustive-ish set of outcomes:
        // whatever the input, `grade_of` stays strictly below the hardware rung.
        let id = identity();
        let nonce = [5u8; 32];
        let now = 1_700_000_000u64;
        let mut roots = TrustedRoots::new();
        roots.pin(AttestationFormat::Opaque, id.public_key());
        let verifier = Verifier::new(roots, 300);
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(),
            &id,
            nonce,
            || now,
            None,
        )
        .expect("envelope builds");

        let stranger = Verifier::new(TrustedRoots::new(), 300);
        let outcomes = vec![
            verifier.verify(&env, nonce, now),          // all checks pass
            verifier.verify(&env, [0u8; 32], now),      // wrong nonce
            verifier.verify(&env, nonce, now + 10_000), // stale
            verifier.verify(&env, nonce, now - 10_000), // future-dated
            stranger.verify(&env, nonce, now),          // stranger
        ];
        for outcome in &outcomes {
            let grade = grade_of(outcome);
            assert!(
                grade < EvidenceGrade::HardwareAttested,
                "grade_of produced the unreachable tier: {grade:?}"
            );
            assert!(grade <= MAX_ACHIEVABLE_GRADE);
        }
    }

    #[test]
    fn a_signature_verified_envelope_reports_the_ceiling_grade_and_says_no_hardware() {
        let id = identity();
        let mut roots = TrustedRoots::new();
        roots.pin(AttestationFormat::Opaque, id.public_key());
        let verifier = Verifier::new(roots, 300);
        let nonce = [5u8; 32];
        let now = 1_700_000_000u64;
        let env = AttestationEnvelope::new(
            AttestationFormat::Opaque,
            &payload(),
            &id,
            nonce,
            || now,
            None,
        )
        .expect("envelope builds");

        // The verifier agrees that this envelope is exactly as good as it can be
        // — and still reports `Unverified`, because the chain does not exist.
        assert!(verifier.verify(&env, nonce, now).is_err());

        // A `SignedAttestation` is produced by the verifier's own accept path; to
        // observe its reporting without one, build the value the accept path
        // builds and check what it says about itself.
        let s = SignedAttestation {
            format: AttestationFormat::Opaque,
            payload_digest: env.payload_hash(),
            report_data: env.report_data,
            nonce,
            issued_at: now,
            signer: id.public_key(),
            checks: crate::attest::ChecksPerformed {
                structural: true,
                signature: true,
                nonce: true,
                freshness: true,
                report_data: true,
                hardware_chain: false,
            },
            payload: &env.payload,
        };
        assert_eq!(s.grade(), EvidenceGrade::SignatureVerified);
        assert_eq!(s.grade(), MAX_ACHIEVABLE_GRADE);
        assert!(s.grade() < EvidenceGrade::HardwareAttested);
        assert!(
            !s.hardware_attested(),
            "a signature check is not hardware attestation"
        );
        assert!(!s.checks().hardware_chain);
        assert!(s.checks().all_implemented());
    }

    #[test]
    fn a_chain_not_implemented_refusal_is_unverified_and_says_so_in_prose() {
        // Even a perfectly signed synthetic quote stops here. This is the line
        // that separates this crate from upstream's unchecked `tee_quote`.
        for format in [
            AttestationFormat::SgxQuoteV3,
            AttestationFormat::TdxQuote,
            AttestationFormat::SevSnpReport,
        ] {
            let reason = UnverifiedReason::ChainNotImplemented { format };
            assert_eq!(reason.format(), Some(format));
            assert_eq!(reason.grade(), EvidenceGrade::Unverified);
            let text = reason.to_string();
            assert!(
                text.contains("not implemented") && text.contains(&format!("{format:?}")),
                "unhelpful refusal text: {text}"
            );
        }
    }

    #[test]
    fn grade_ordering_default_and_labels_are_stable() {
        assert!(EvidenceGrade::Unverified < EvidenceGrade::StructurallyValid);
        assert!(EvidenceGrade::StructurallyValid < EvidenceGrade::SignatureVerified);
        assert!(EvidenceGrade::SignatureVerified < EvidenceGrade::HardwareAttested);
        assert_eq!(EvidenceGrade::default(), EvidenceGrade::Unverified);
        assert_eq!(label(EvidenceGrade::Unverified), "unverified");
        assert_eq!(
            label(EvidenceGrade::StructurallyValid),
            "structurally-valid"
        );
        assert_eq!(
            label(EvidenceGrade::SignatureVerified),
            "signature-verified"
        );
        assert_eq!(label(EvidenceGrade::HardwareAttested), "hardware-attested");
    }

    #[test]
    fn grade_is_serialized_as_a_snake_case_string() {
        // Grades travel in JSON and in the CLI/SDK output, so the wire name must
        // not drift silently.
        let encoded = serde_json::to_value(EvidenceGrade::SignatureVerified).expect("serializes");
        assert_eq!(encoded, json!("signature_verified"));
        let decoded: EvidenceGrade =
            serde_json::from_str("\"signature_verified\"").expect("deserializes");
        assert_eq!(decoded, EvidenceGrade::SignatureVerified);
        // Naming the unreachable tier is possible; awarding it is not. There is no
        // `grade_of` input that yields it — see `hardware_attested_is_unreachable`.
        let named: EvidenceGrade =
            serde_json::from_str("\"hardware_attested\"").expect("deserializes");
        assert_eq!(named, EvidenceGrade::HardwareAttested);
        assert_ne!(named, MAX_ACHIEVABLE_GRADE);
    }
}
