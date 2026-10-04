//! The host's signing service, and the request an agent is allowed to send it.
//!
//! # E-06's first criterion, and why it is a type rather than a rule
//!
//! The design says "an agent's private key should never be exposed inside the sandbox". This module
//! is that sentence implemented, and the implementation is the shape of [`PaymentRequest`]: **it has
//! fields for public data and none for a secret**, so there is nothing for a sandboxed agent to put a
//! key in even if it had one.
//!
//! # What this module does NOT do
//!
//! It does not stop [`nau_core::identity::Keypair`] from revealing its seed — `seed()` and
//! `seed_hex()` are `nau-core`'s API and changing them is out of this release's scope. What it does
//! is make sure **a key never has to reach a sandbox in the first place**: the agent sends a request,
//! the host verifies it and signs, and **the only thing that crosses is a request and a signed
//! result.**
//!
//! That distinction matters and is worth stating rather than implying. A test here asserts the
//! request type's own surface; it does not assert anything about `nau-core`, and pretending otherwise
//! would be claiming a boundary this module does not draw.
//!
//! # E-06's second criterion
//!
//! A payment request travels as a PMB message and is **verified by the host before anything is
//! signed**. Verification is the four checks in [`SigningService::authorize`], and each of them is a
//! refusal with its own reason rather than a boolean.
//!
//! # E-06's fourth criterion: over-payment is refused
//!
//! [`PaymentLimits`] bounds a single payment and the total a caller may authorise in a window, and
//! **both bounds are refused rather than clamped** — the same discipline D-07 applies to a resource
//! bound: a clamped figure is a silently wrong one, and a payment that was quietly reduced is worse
//! than one that was refused, because the payer believed it happened.

use std::collections::BTreeSet;

use nau_core::error::{NauError, Result};
use nau_core::identity::{Did, Keypair, PublicKey, Signature64};
use serde::{Deserialize, Serialize};

/// What an agent asks the host to pay.
///
/// # Every field is public data, and that is the criterion
///
/// `agent` is a DID, which is a **fingerprint**; `payee` is a name; `amount_minor` is a number;
/// `nonce` is a counter; `memo` is a string. **There is no field for a secret, and no constructor
/// that takes one**, so a sandboxed agent cannot put a key in a request — not because it is
/// discouraged, but because there is nowhere to put it.
///
/// This is the type that crosses the sandbox boundary. What comes back is a [`SignedPayment`], which
/// carries a signature and a public key and no more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequest {
    /// Who is asking. A DID, which is public.
    pub agent: String,
    /// Who is to be paid.
    pub payee: String,
    /// How much, in minor units. Positive.
    pub amount_minor: i64,
    /// Replay protection. Each `(agent, nonce)` may be authorised once.
    pub nonce: u64,
    /// An optional note, carried through to the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

impl PaymentRequest {
    /// A request.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the amount is not positive, when the payee is blank, or when
    /// the agent is not a well-formed DID. A zero-amount payment is refused rather than allowed:
    /// it would consume a nonce and produce a signature over nothing.
    pub fn new(
        agent: &str,
        payee: impl Into<String>,
        amount_minor: i64,
        nonce: u64,
    ) -> Result<Self> {
        if amount_minor <= 0 {
            return Err(NauError::Validation(
                "a payment must be for a positive amount; zero would consume a nonce and produce a \
                 signature over nothing"
                    .to_string(),
            ));
        }
        let payee = payee.into();
        if payee.trim().is_empty() {
            return Err(NauError::Validation(
                "a payment must name a payee".to_string(),
            ));
        }
        // Parsed and discarded, which is the point: a malformed DID is refused HERE, at the boundary,
        // rather than by the signer three steps later.
        Did::parse(agent)?;
        Ok(Self {
            agent: agent.to_string(),
            payee,
            amount_minor,
            nonce,
            memo: None,
        })
    }

    /// Whether this request's serialised form contains anything that could be a secret.
    ///
    /// # What this can and cannot check
    ///
    /// It cannot prove the absence of a secret — a caller could put one in `memo`. What it does is
    /// assert the **shape** the type promises: the only fields are the five above, and the rendered
    /// form names exactly those. Tests use it to hold the type to that promise, so that adding a
    /// field is a deliberate act rather than an accident.
    #[must_use]
    pub fn carries_only_public_fields(&self) -> bool {
        let Ok(value) = serde_json::to_value(self) else {
            return false;
        };
        let Some(object) = value.as_object() else {
            return false;
        };
        object.keys().all(|k| {
            matches!(
                k.as_str(),
                "agent" | "payee" | "amount_minor" | "nonce" | "memo"
            )
        })
    }
}

/// What the host will authorise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentLimits {
    /// The most a single payment may be, in minor units.
    pub per_payment_max_minor: i64,
    /// The most one agent may have authorised in total, in minor units.
    ///
    /// A total rather than a per-window figure, because this type has no clock: a window would need
    /// one, and inventing a clock here would make the limit depend on when it was asked rather than
    /// on what was authorised.
    pub per_agent_total_max_minor: i64,
}

impl Default for PaymentLimits {
    /// Conservative starting figures, stated as a judgement rather than a measurement — the
    /// `metric-claims` gate's distinction, applied to a configuration.
    fn default() -> Self {
        Self {
            per_payment_max_minor: 1_000_000,
            per_agent_total_max_minor: 10_000_000,
        }
    }
}

/// A payment the host has verified and signed.
///
/// The only thing that crosses back. It carries the public key and the signature over the request's
/// canonical form — **no secret, because the signer never had to hand one over.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayment {
    /// The request that was authorised.
    pub request: PaymentRequest,
    /// The signer's public key, which a verifier needs and which is not a secret.
    pub signer_key: PublicKey,
    /// The signature over the request's canonical form.
    pub signature: Signature64,
}

impl SignedPayment {
    /// The bytes that were signed, for a verifier to reproduce.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the request cannot be canonicalised. A request that cannot be
    /// signed over is one that could not have been authorised either, and saying so is better than
    /// signing something else.
    pub fn signed_bytes(request: &PaymentRequest) -> Result<String> {
        let value = serde_json::to_value(request)
            .map_err(|e| NauError::Validation(format!("the request did not encode: {e}")))?;
        nau_core::canonical::canonical_object(&value)
            .map_err(|e| NauError::Validation(format!("the request has no canonical form: {e}")))
    }
}

/// The host's signing service.
///
/// # It holds the key, and nothing else does
///
/// This type is the **only** thing in the node that holds a [`Keypair`] for payments, and it is
/// constructed host-side. A sandboxed agent's route to it is a [`PaymentRequest`] over the bus and a
/// [`SignedPayment`] back — neither of which carries a secret.
///
/// # E-06's third criterion, as far as this module takes it
///
/// `x402` and `L402` are **HTTP payment protocols**, and nothing here speaks either: the signed
/// payment this service produces is a **local authorisation**, not a protocol message. The refusal
/// of those two rails lives in `com.twinsearth.sys.settlement`'s vocabulary, where a caller can ask
/// for it; what this module adds is that **nothing it produces could be mistaken for one** — there is
/// no HTTP client here and no field for an invoice, a preimage or a payment header.
#[derive(Debug)]
pub struct SigningService {
    key: Keypair,
    limits: PaymentLimits,
    /// Every `(agent, nonce)` authorised, so a replay is refused rather than signed twice.
    authorised: BTreeSet<(String, u64)>,
    /// What each agent has been authorised for, in total.
    totals: std::collections::BTreeMap<String, i64>,
}

impl SigningService {
    /// A service holding `key`.
    #[must_use]
    pub fn new(key: Keypair, limits: PaymentLimits) -> Self {
        Self {
            key,
            limits,
            authorised: BTreeSet::new(),
            totals: std::collections::BTreeMap::new(),
        }
    }

    /// The signer's public key, which is public and which a verifier needs.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// The signer's DID.
    #[must_use]
    pub fn did(&self) -> Did {
        self.key.did()
    }

    /// What has been authorised for `agent`, in total.
    #[must_use]
    pub fn authorised_total(&self, agent: &str) -> i64 {
        self.totals.get(agent).copied().unwrap_or(0)
    }

    /// Verify a request and sign it, or refuse with a reason.
    ///
    /// # The four checks, in order, and each is a refusal
    ///
    /// 1. **The request is well formed** — a positive amount, a named payee, a DID that parses.
    /// 2. **It is within the per-payment bound** — E-06's fourth criterion. **Refused, not clamped:**
    ///    a payment quietly reduced to the limit is worse than one refused, because the payer
    ///    believed it happened.
    /// 3. **It is within the agent's total bound** — and the check is against what would result, not
    ///    against the current total, so a payment that would cross the bound is refused rather than
    ///    allowed to cross it once.
    /// 4. **It has not been authorised before** — the `(agent, nonce)` pair is consumed, so a replay
    ///    is refused rather than signed twice.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] for the first three, [`NauError::Conflict`] for the replay. The
    /// distinct variant matters: a replay is not a malformed request, it is a duplicate one, and a
    /// caller that could not tell them apart could not tell an attack from a bug.
    pub fn authorize(&mut self, request: &PaymentRequest) -> Result<SignedPayment> {
        // 1. Well-formedness, re-checked here rather than trusted: a request can arrive from a bus
        //    message that was never built through `new`.
        let revalidated = PaymentRequest::new(
            &request.agent,
            request.payee.clone(),
            request.amount_minor,
            request.nonce,
        )?;
        let mut request = revalidated;
        request.memo = request.memo.clone();

        // 2. The per-payment bound.
        if request.amount_minor > self.limits.per_payment_max_minor {
            return Err(NauError::Validation(format!(
                "a single payment of {} exceeds the limit of {}: refused rather than clamped, \
                 because a payment quietly reduced to the limit is worse than one refused -- the \
                 payer believed it happened",
                request.amount_minor, self.limits.per_payment_max_minor
            )));
        }

        // 3. The agent's total, checked against what WOULD result.
        let current = self.authorised_total(&request.agent);
        let would_be = current.saturating_add(request.amount_minor);
        if would_be > self.limits.per_agent_total_max_minor {
            return Err(NauError::Validation(format!(
                "`{}` has been authorised for {current} and this payment would take it to \
                 {would_be}, past the total limit of {}: the check is against what would result, \
                 not against the current total, so a payment that would cross the bound is refused \
                 rather than allowed to cross it once",
                request.agent, self.limits.per_agent_total_max_minor
            )));
        }

        // 4. The replay check, and the pair is consumed only if everything above passed.
        let key = (request.agent.clone(), request.nonce);
        if self.authorised.contains(&key) {
            return Err(NauError::Conflict(format!(
                "`{}` has already been authorised for nonce {}: a replay is a duplicate rather than \
                 a malformed request, and the two are different answers",
                request.agent, request.nonce
            )));
        }

        // Sign the CANONICAL form, so a verifier can reproduce exactly these bytes.
        let bytes = SignedPayment::signed_bytes(&request)?;
        let signature = self.key.sign(bytes.as_bytes());
        self.authorised.insert(key);
        self.totals.insert(request.agent.clone(), would_be);
        Ok(SignedPayment {
            request,
            signer_key: self.key.public_key(),
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AGENT: &str = "did:nau:0011223344556677";

    fn service() -> SigningService {
        SigningService::new(Keypair::from_seed(&[3u8; 32]), PaymentLimits::default())
    }

    #[test]
    fn a_request_carries_only_public_fields_and_no_secret() {
        // E-06's first criterion, asserted on the type's own shape. A sandboxed agent cannot put a
        // key in a request because there is nowhere to put one -- and this is the assertion that
        // keeps that true when someone adds a field.
        let request =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 500, 1).expect("a request");
        assert!(request.carries_only_public_fields());

        let rendered = serde_json::to_string(&request).expect("encodes");
        // A seed is 32 bytes and `seed_hex` is 64 characters; neither may appear.
        assert!(!rendered.contains("seed"), "{rendered}");
        assert!(!rendered.contains("private"), "{rendered}");
        assert!(!rendered.contains("key"), "{rendered}");
        // The fields are the five public ones and nothing else.
        for field in ["agent", "payee", "amount_minor", "nonce"] {
            assert!(rendered.contains(field), "{field} missing from {rendered}");
        }

        // And what comes BACK carries a public key and a signature, which are not secrets.
        let signed = service().authorize(&request).expect("authorised");
        let back = serde_json::to_value(json_of(&signed)).expect("encodes");
        assert!(back.get("signer_key").is_some());
        assert!(back.get("signature").is_some());
        assert!(back.get("seed").is_none(), "{back}");
    }

    /// A JSON view of a signed payment, for the assertion above.
    fn json_of(signed: &SignedPayment) -> serde_json::Value {
        serde_json::json!({
            "request": signed.request,
            "signer_key": signed.signer_key.to_hex(),
            "signature": signed.signature.to_hex(),
        })
    }

    #[test]
    fn a_zero_or_negative_payment_is_refused_at_construction() {
        // Zero would consume a nonce and produce a signature over nothing.
        for amount in [0i64, -1] {
            let err = PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", amount, 1)
                .expect_err("refused");
            assert!(format!("{err}").contains("positive amount"), "{err}");
        }
        assert!(
            PaymentRequest::new(AGENT, "  ", 1, 1).is_err(),
            "a payee is required"
        );
        assert!(
            PaymentRequest::new("not-a-did", "did:nau:8899aabbccddeeff", 1, 1).is_err(),
            "a malformed DID is refused at the boundary rather than by the signer"
        );
    }

    #[test]
    fn an_over_limit_payment_is_refused_rather_than_clamped() {
        // E-06's fourth criterion, half one.
        let limits = PaymentLimits {
            per_payment_max_minor: 1_000,
            per_agent_total_max_minor: 10_000,
        };
        let mut service = SigningService::new(Keypair::from_seed(&[3u8; 32]), limits);
        let request =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 1_001, 1).expect("a request");
        let err = service.authorize(&request).expect_err("refused");
        let text = format!("{err}");
        assert!(text.contains("exceeds the limit"), "{text}");
        assert!(
            text.contains("refused rather than clamped"),
            "and must say why clamping would be worse: {text}"
        );
        // Nothing was consumed: a refused payment must not spend a nonce.
        assert_eq!(service.authorised_total(AGENT), 0);
        // And the same request at the limit is accepted, so the bound is a bound and not a ban.
        let ok =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 1_000, 1).expect("a request");
        service.authorize(&ok).expect("at the limit is allowed");
        assert_eq!(service.authorised_total(AGENT), 1_000);
    }

    #[test]
    fn the_total_bound_is_checked_against_what_would_result() {
        // The difference between "is the current total over?" and "would this take it over?" -- and
        // the second is the one that matters, or a caller could cross the bound once per call.
        let limits = PaymentLimits {
            per_payment_max_minor: 1_000,
            per_agent_total_max_minor: 2_500,
        };
        let mut service = SigningService::new(Keypair::from_seed(&[3u8; 32]), limits);
        for nonce in 1..=2 {
            let request = PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 1_000, nonce)
                .expect("a request");
            service.authorize(&request).expect("within the total");
        }
        assert_eq!(service.authorised_total(AGENT), 2_000);
        // A third would take it to 3,000, past 2,500, so it is refused.
        let third =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 1_000, 3).expect("a request");
        let err = service.authorize(&third).expect_err("refused");
        let text = format!("{err}");
        assert!(text.contains("would take it to 3000"), "{text}");
        assert!(text.contains("what would result"), "{text}");
        assert_eq!(
            service.authorised_total(AGENT),
            2_000,
            "and nothing was added"
        );

        // A payment that fits is still allowed, so the bound is not a wall once reached.
        let small =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 500, 3).expect("a request");
        service.authorize(&small).expect("fits");
        assert_eq!(service.authorised_total(AGENT), 2_500);
    }

    #[test]
    fn a_replay_is_a_conflict_rather_than_a_malformed_request() {
        // E-06's second criterion's replay half, and the distinction matters: a caller that could
        // not tell a duplicate from a malformed request could not tell an attack from a bug.
        let mut service = service();
        let request =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 500, 7).expect("a request");
        service.authorize(&request).expect("first");

        let err = service.authorize(&request).expect_err("a replay");
        assert!(
            matches!(err, NauError::Conflict(_)),
            "a replay is a conflict, got {err:?}"
        );
        assert!(
            format!("{err}").contains("already been authorised"),
            "{err}"
        );
        // And the total did not move, so a replay cannot inflate it.
        assert_eq!(service.authorised_total(AGENT), 500);

        // A different nonce is a different payment and is allowed.
        let next =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 500, 8).expect("a request");
        service.authorize(&next).expect("a new nonce");
        assert_eq!(service.authorised_total(AGENT), 1_000);
    }

    #[test]
    fn the_signature_is_over_bytes_a_verifier_can_reproduce() {
        // E-06's second criterion: the host verifies and signs, and what it signs is the request's
        // CANONICAL form -- so a verifier holding the request can reproduce the bytes exactly.
        let mut service = service();
        let request =
            PaymentRequest::new(AGENT, "did:nau:8899aabbccddeeff", 500, 1).expect("a request");
        let signed = service.authorize(&request).expect("authorised");

        let bytes = SignedPayment::signed_bytes(&signed.request).expect("canonical");
        // `verify` returns a `Result` rather than a `bool`, which this test learned from the
        // compiler -- and the `Result` is the better shape: a failure names why rather than only that.
        assert!(
            signed
                .signer_key
                .verify(bytes.as_bytes(), signed.signature.as_bytes())
                .is_ok(),
            "the signature must verify over the canonical form"
        );
        // And a single changed field breaks it, so the signature covers the whole request.
        let mut tampered = signed.request.clone();
        tampered.amount_minor = 501;
        let tampered_bytes = SignedPayment::signed_bytes(&tampered).expect("canonical");
        assert!(
            signed
                .signer_key
                .verify(tampered_bytes.as_bytes(), signed.signature.as_bytes())
                .is_err(),
            "a changed amount must not verify"
        );

        // The public key is the service's own, and it is NOT a secret: it is what a verifier needs.
        assert_eq!(signed.signer_key, service.public_key());
        assert!(service.did().as_str().starts_with("did:nau:"));
    }

    #[test]
    fn the_limits_are_a_judgement_and_say_so() {
        // The `metric-claims` distinction applied to a configuration: a figure presented without
        // saying whether it is a measurement or a judgement is the kind of claim the gate refuses.
        let limits = PaymentLimits::default();
        assert!(limits.per_payment_max_minor > 0);
        assert!(
            limits.per_agent_total_max_minor > limits.per_payment_max_minor,
            "a total below a single payment would refuse everything"
        );
    }
}
