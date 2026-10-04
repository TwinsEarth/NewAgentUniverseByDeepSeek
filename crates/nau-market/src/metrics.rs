//! What the resource market did, computed from what it holds.
//!
//! # D-11's first criterion: every figure is reproducible
//!
//! Every number here is **derived from the state it is about** rather than accumulated as things
//! happen. That is the lesson D-07 recorded for the resource ledger's sums and v3.8.7's byte
//! stability recorded for a merkle root, applied to reporting: **a stored aggregate is a second
//! place the same fact lives, and the two drift.**
//!
//! So [`MarketMetrics::of`] takes the books and the registry and **computes**. Two calls on the same
//! state return the same figures, and a node that re-derives them from the same journals gets the
//! same answer — which is what makes a published number something a reader can check.
//!
//! # D-11's second criterion is the `metric-claims` gate's job, not this module's
//!
//! The gate (v3.5.9) refuses a performance figure in the documentation that does not carry its five
//! elements or say it is a target. **This module's contribution is to make that possible**: a figure
//! that can be re-derived is one whose five elements can be stated, and a figure that cannot is one
//! nobody should publish at all.
//!
//! # What is deliberately absent
//!
//! There is no grand total across resource kinds, for the reason [`crate::ResourceBundle`] and
//! [`crate::ResourceAudit`] both give: six units do not add up, and a single "resources traded"
//! number would be the mixed-unit arithmetic this market is built to avoid. Utilisation and dispute
//! rate are **ratios**, which are dimensionless and therefore comparable — and they are the only two
//! figures here that are.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::resource::ResourceKind;
use crate::resource_ledger::ResourceLedger;

/// What one kind of resource did.
///
/// Per kind, always. See the module documentation for why there is no total.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindMetrics {
    /// Issued into the network, ever.
    pub issued: u64,
    /// Consumed, ever.
    pub consumed: u64,
    /// Held by every account right now.
    pub held: u64,
    /// `consumed / issued` in basis points — how much of what was made available was used.
    ///
    /// Zero when nothing was issued, which is "no utilisation" rather than a division by zero. Stated
    /// rather than left as a silent fallback, because a zero here and a zero for "issued but nothing
    /// consumed" are the same number and different facts.
    pub utilisation_bps: u32,
}

impl KindMetrics {
    /// What is left: issued minus consumed.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.issued.saturating_sub(self.consumed)
    }
}

/// What the market did, by kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketMetrics {
    /// One entry per kind that has a book.
    pub by_kind: BTreeMap<ResourceKind, KindMetrics>,
    /// How many providers are registered.
    pub providers: usize,
    /// How many of them have been measured at least once.
    ///
    /// The figure that separates "nobody is dishonest" from "nobody has looked", which are the same
    /// number in every other statistic.
    pub providers_observed: usize,
}

impl MarketMetrics {
    /// Compute the metrics of `resources` and a registry's provider set.
    ///
    /// # Determinism
    ///
    /// A `BTreeMap` keyed by [`ResourceKind`], which is ordered, so the iteration order is stable.
    /// Every figure is a pure function of the two inputs, and the resource ledger's own audit
    /// **recomputes** its sums from the balances rather than reading them back — so this inherits
    /// that property rather than depending on it by convention.
    ///
    /// `observed` is the set of provider names that have at least one measurement. It is a parameter
    /// rather than being read from a reputation store, because this crate does not hold one: what a
    /// caller passes is what the caller has, and saying so is better than guessing.
    #[must_use]
    pub fn of(resources: &ResourceLedger, providers: &[String], observed: &[String]) -> Self {
        let audit = resources.audit();
        let mut by_kind = BTreeMap::new();
        for kind in audit.kinds() {
            let book = audit.book_of(kind);
            let held = book.sum_of_balances;
            // Integer ratio, capped at the whole: `consumed` can exceed `issued` only if the books
            // were already unbalanced, and reporting 10,000 rather than a figure above it keeps the
            // metric inside the range its name implies.
            let utilisation_bps = if book.issued == 0 {
                0
            } else {
                u32::try_from(
                    book.consumed
                        .saturating_mul(10_000)
                        .checked_div(book.issued)
                        .unwrap_or(0)
                        .min(10_000),
                )
                .unwrap_or(10_000)
            };
            by_kind.insert(
                kind,
                KindMetrics {
                    issued: book.issued,
                    consumed: book.consumed,
                    held,
                    utilisation_bps,
                },
            );
        }
        // The observed count is the INTERSECTION with the registered set, so a measurement of a
        // provider that is not registered does not inflate it. Counting the parameter's length
        // instead would let a caller report an observation rate above 100%.
        let providers_observed = observed
            .iter()
            .filter(|name| providers.contains(name))
            .count();
        Self {
            by_kind,
            providers: providers.len(),
            providers_observed,
        }
    }

    /// One kind's figures. An absent kind is zeros rather than an error: nothing has happened to it,
    /// which is a fact rather than a failure.
    #[must_use]
    pub fn kind(&self, kind: ResourceKind) -> KindMetrics {
        self.by_kind.get(&kind).copied().unwrap_or_default()
    }

    /// `providers_observed / providers` in basis points.
    ///
    /// The one figure that says whether the reputation dimension means anything: an agent with a
    /// thousand settlements and no observations has a truthfulness nobody has tested, and this is
    /// the number that makes that visible rather than implied.
    ///
    /// Zero when nothing is registered — no providers is "nobody has arrived", not "nobody is
    /// measured".
    #[must_use]
    pub fn observation_coverage_bps(&self) -> u32 {
        if self.providers == 0 {
            return 0;
        }
        u32::try_from(
            self.providers_observed
                .saturating_mul(10_000)
                .checked_div(self.providers)
                .unwrap_or(0)
                .min(10_000),
        )
        .unwrap_or(10_000)
    }

    /// One line per kind, then the two whole-market figures.
    ///
    /// Every line names its unit, because a report where a reader has to remember which number is
    /// bytes and which is invocations is one where the two get compared.
    #[must_use]
    pub fn explain(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .by_kind
            .iter()
            .map(|(kind, m)| {
                format!(
                    "{}: issued {} {}, consumed {} {}, held {} {}, utilisation {} bps",
                    kind.label(),
                    m.issued,
                    kind.unit(),
                    m.consumed,
                    kind.unit(),
                    m.held,
                    kind.unit(),
                    m.utilisation_bps
                )
            })
            .collect();
        if out.is_empty() {
            out.push("no kind has a book yet".to_string());
        }
        out.push(format!(
            "providers: {} registered, {} observed, coverage {} bps",
            self.providers,
            self.providers_observed,
            self.observation_coverage_bps()
        ));
        out.push(
            "there is deliberately no total across kinds: six units do not add up, and a single \
             figure would be the mixed-unit arithmetic this market exists to avoid"
                .to_string(),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::ResourceAmount;

    fn amount(kind: ResourceKind, quantity: u64) -> ResourceAmount {
        ResourceAmount::of(kind, quantity).expect("amount")
    }

    fn ledger() -> ResourceLedger {
        let mut l = ResourceLedger::new();
        l.issue("did:a", amount(ResourceKind::Cpu, 100))
            .expect("issued");
        l.consume("did:a", amount(ResourceKind::Cpu, 40))
            .expect("consumed");
        l.issue("did:a", amount(ResourceKind::Network, 4_096))
            .expect("issued");
        l
    }

    #[test]
    fn the_same_state_gives_the_same_figures() {
        // D-11's first criterion. Everything is derived, so two calls agree -- and a node that
        // re-derives from the same journals gets the same answer, which is what makes a published
        // number something a reader can check.
        let l = ledger();
        let providers = vec!["did:a".to_string()];
        let observed = vec!["did:a".to_string()];
        let first = MarketMetrics::of(&l, &providers, &observed);
        for _ in 0..8 {
            assert_eq!(MarketMetrics::of(&l, &providers, &observed), first);
        }
        assert_eq!(
            first.explain(),
            MarketMetrics::of(&l, &providers, &observed).explain()
        );
    }

    #[test]
    fn every_figure_is_a_ratio_because_totals_across_kinds_do_not_add_up() {
        // The units differ, so the only comparable figures are the dimensionless ones.
        let m = MarketMetrics::of(&ledger(), &[], &[]);
        assert_eq!(m.kind(ResourceKind::Cpu).issued, 100);
        assert_eq!(m.kind(ResourceKind::Cpu).consumed, 40);
        assert_eq!(m.kind(ResourceKind::Cpu).held, 60);
        assert_eq!(m.kind(ResourceKind::Network).issued, 4_096);
        assert_eq!(m.kind(ResourceKind::Network).consumed, 0);
        assert_eq!(m.kind(ResourceKind::Network).held, 4_096);

        // Utilisation, in basis points, per kind.
        assert_eq!(m.kind(ResourceKind::Cpu).utilisation_bps, 4_000);
        assert_eq!(
            m.kind(ResourceKind::Network).utilisation_bps,
            0,
            "issued but never consumed is zero utilisation, not a division by zero"
        );
        // A kind nothing has happened to is zeros rather than an error and not a skip.
        assert_eq!(m.kind(ResourceKind::Snapshot), KindMetrics::default());
        assert_eq!(m.kind(ResourceKind::Snapshot).available(), 0);

        // And the module says so in its own report.
        let lines = m.explain();
        assert!(
            lines.iter().any(|l| l.contains("no total across kinds")),
            "{lines:?}"
        );
    }

    #[test]
    fn issued_less_consumed_is_what_is_held() {
        // The conservation identity, stated as a metric rather than trusted: if these disagreed, the
        // ledger's own audit would already have reported a discrepancy.
        let l = ledger();
        let m = MarketMetrics::of(&l, &[], &[]);
        for kind in m.by_kind.keys() {
            let k = m.kind(*kind);
            assert_eq!(
                k.available(),
                k.held,
                "{kind:?} disagrees with its own books"
            );
        }
        assert!(l.audit().is_conserved());
    }

    #[test]
    fn coverage_cannot_exceed_the_whole() {
        // The observed count is the INTERSECTION with the registered set. Counting the parameter's
        // length instead would let a caller report an observation rate above 100%, and a measurement
        // of somebody who is not registered is not coverage of anybody.
        let providers = vec!["did:a".to_string(), "did:b".to_string()];
        let observed = vec![
            "did:a".to_string(),
            "did:stranger".to_string(),
            "did:another-stranger".to_string(),
        ];
        let m = MarketMetrics::of(&ResourceLedger::new(), &providers, &observed);
        assert_eq!(m.providers, 2);
        assert_eq!(
            m.providers_observed, 1,
            "a measurement of somebody unregistered is not coverage"
        );
        assert_eq!(m.observation_coverage_bps(), 5_000);

        // Nobody registered is "nobody has arrived", not "nobody is measured".
        let none = MarketMetrics::of(&ResourceLedger::new(), &[], &observed);
        assert_eq!(none.observation_coverage_bps(), 0);

        // Everybody registered and observed is the whole, and never more.
        let all = MarketMetrics::of(
            &ResourceLedger::new(),
            &providers,
            &["did:a".to_string(), "did:b".to_string()],
        );
        assert_eq!(all.observation_coverage_bps(), 10_000);
    }

    #[test]
    fn a_market_that_has_done_nothing_reports_zeros_and_says_so() {
        let m = MarketMetrics::of(&ResourceLedger::new(), &[], &[]);
        assert!(m.by_kind.is_empty());
        assert_eq!(m.providers, 0);
        assert_eq!(m.observation_coverage_bps(), 0);
        let lines = m.explain();
        assert!(
            lines[0].contains("no kind has a book yet"),
            "an empty report must say it is empty rather than be empty: {lines:?}"
        );
        assert!(lines.len() >= 3, "{lines:?}");
    }

    #[test]
    fn every_line_names_its_unit() {
        // A report where a reader has to remember which number is bytes and which is invocations is
        // one where the two get compared.
        let m = MarketMetrics::of(&ledger(), &[], &[]);
        let lines = m.explain();
        let cpu_line = lines
            .iter()
            .find(|l| l.starts_with("cpu:"))
            .expect("a cpu line");
        assert!(cpu_line.contains("cpu-milliseconds"), "{cpu_line}");
        let net_line = lines
            .iter()
            .find(|l| l.starts_with("network:"))
            .expect("a network line");
        assert!(net_line.contains("bytes"), "{net_line}");
        assert!(!net_line.contains("cpu-milliseconds"), "{net_line}");
    }

    #[test]
    fn the_metrics_round_trip_through_json() {
        let m = MarketMetrics::of(&ledger(), &["did:a".to_string()], &["did:a".to_string()]);
        let text = serde_json::to_string(&m).expect("serialises");
        let back: MarketMetrics = serde_json::from_str(&text).expect("deserialises");
        assert_eq!(back, m);
        // And the key is the kind's own label, so a reader of the JSON needs no side table.
        assert!(text.contains("\"cpu\""), "{text}");
        assert!(text.contains("utilisation_bps"), "{text}");
    }
}
