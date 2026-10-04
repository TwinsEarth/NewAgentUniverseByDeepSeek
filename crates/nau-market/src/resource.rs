//! Resources as commodities: six kinds, each with its own unit, priced but never mixed.
//!
//! # Why this is a new type rather than a reinterpretation of `Quota`
//!
//! [`Quota`] has existed since v3.6.1 and answers **"is this permitted?"**. A market has to answer
//! **"what is it worth?"**. Those are different questions about the same machine, and the plan's
//! D-01 criterion says they must not become one type.
//!
//! So [`ResourceAmount`] is a **different type from `Quota`, with no conversion between them** —
//! not a method, not a `From` impl, not an `as`. A caller cannot hand a quota where an amount is
//! wanted, and the compiler is what enforces that. A comment saying "do not confuse these" would be
//! a comment; two types with no bridge between them is a rule.
//!
//! # Why the unit is carried rather than assumed
//!
//! D-01's first criterion is that the six kinds each have a unit and that the units **cannot be
//! mixed**. The strongest form of that is the same trick: [`ResourceKind::unit`] returns the unit,
//! and [`ResourceAmount::checked_add`] **refuses to add two amounts of different kinds**. So
//! "200 CPU-milliseconds plus 4 GB-seconds" is not a number nobody checked — it is an error with a
//! message naming both kinds.
//!
//! A single `u64` with a side-table of units would have made that sum compile.
//!
//! # What each unit means, and why the list is six
//!
//! | kind | unit | where it comes from |
//! |---|---|---|
//! | [`ResourceKind::Cpu`] | CPU milliseconds | the scheduler's time slices (A-11) |
//! | [`ResourceKind::Memory`] | mebibyte-seconds | the sandbox's address space over time, shared pages included (A-09) |
//! | [`ResourceKind::Storage`] | gibibyte-seconds | image chunks held, by content address (A-04) |
//! | [`ResourceKind::Network`] | bytes | image distribution and gossip (A-07) |
//! | [`ResourceKind::Snapshot`] | snapshot count | `pack_diff` environments, which are the thing this network sells that is not raw compute (B-04) |
//! | [`ResourceKind::AgentCapability`] | invocations | a published Agent's own capacity to be called |
//!
//! Memory and storage are **per second**, and that is not decoration: a mebibyte held for an hour is
//! a different quantity from a mebibyte held for a millisecond, and a market that priced them the
//! same would be selling something other than what it delivers.
//!
//! # The one thing this module deliberately does not do
//!
//! It does not price anything. [`ResourceOffer`] carries a price because an offer without one is
//! not an offer, but the **pricing rules** are D-05's, and putting them here would be a second place
//! where a price is decided.

use std::collections::BTreeMap;

use nau_core::domain::Money;
use nau_core::error::{NauError, Result};
use serde::{Deserialize, Serialize};

/// One of the six kinds of resource this network trades.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// CPU time, in milliseconds.
    Cpu,
    /// Address space held over time, in mebibyte-seconds.
    Memory,
    /// Bytes held over time, in gibibyte-seconds.
    Storage,
    /// Traffic, in bytes.
    Network,
    /// Reusable environments, counted.
    Snapshot,
    /// A published Agent's own capacity, counted in invocations.
    AgentCapability,
}

impl ResourceKind {
    /// Every kind.
    pub const ALL: [ResourceKind; 6] = [
        ResourceKind::Cpu,
        ResourceKind::Memory,
        ResourceKind::Storage,
        ResourceKind::Network,
        ResourceKind::Snapshot,
        ResourceKind::AgentCapability,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ResourceKind::Cpu => "cpu",
            ResourceKind::Memory => "memory",
            ResourceKind::Storage => "storage",
            ResourceKind::Network => "network",
            ResourceKind::Snapshot => "snapshot",
            ResourceKind::AgentCapability => "agent-capability",
        }
    }

    /// The unit an amount of this kind is counted in.
    ///
    /// Returned rather than written into a message, so that a report cannot state a unit that
    /// disagrees with the arithmetic: there is one place the unit is decided and this is it.
    #[must_use]
    pub fn unit(self) -> &'static str {
        match self {
            ResourceKind::Cpu => "cpu-milliseconds",
            ResourceKind::Memory => "mib-seconds",
            ResourceKind::Storage => "gib-seconds",
            ResourceKind::Network => "bytes",
            ResourceKind::Snapshot => "snapshots",
            ResourceKind::AgentCapability => "invocations",
        }
    }

    /// Whether an amount is a quantity held **over time** rather than a total.
    ///
    /// The distinction a market cannot ignore: a mebibyte held for an hour and a mebibyte held for a
    /// millisecond are the same number in this type and different quantities in the world, so a
    /// price that ignores the clock is selling something other than what it delivers. Pricing is
    /// D-05's; naming which kinds are rate-like is this module's, because it is a property of the
    /// kind.
    #[must_use]
    pub fn is_rate(self) -> bool {
        matches!(self, ResourceKind::Memory | ResourceKind::Storage)
    }
}

/// A quantity of one kind of resource.
///
/// Exact integers, like every other quantity in this workspace: a market that priced in floating
/// point would have a conservation law that holds until it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceAmount {
    kind: ResourceKind,
    quantity: u64,
}

impl ResourceAmount {
    /// An amount of `kind`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `quantity` is zero. A zero amount is not a small amount: it is
    /// an offer of nothing, and one that reached a matcher would be ranked against real offers.
    pub fn of(kind: ResourceKind, quantity: u64) -> Result<Self> {
        if quantity == 0 {
            return Err(NauError::Validation(format!(
                "an amount of {} must be positive; zero is an offer of nothing, not a small offer",
                kind.label()
            )));
        }
        Ok(Self { kind, quantity })
    }

    /// What kind it is.
    #[must_use]
    pub fn kind(self) -> ResourceKind {
        self.kind
    }

    /// How much.
    #[must_use]
    pub fn quantity(self) -> u64 {
        self.quantity
    }

    /// The unit, from the kind.
    #[must_use]
    pub fn unit(self) -> &'static str {
        self.kind.unit()
    }

    /// Add two amounts, or refuse because they are different kinds.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] naming **both** kinds when they differ, and when the sum overflows.
    /// This is D-01's first criterion: the units cannot be mixed, and they cannot be mixed because
    /// this is the only way to add two amounts and it says no.
    pub fn checked_add(self, other: Self) -> Result<Self> {
        if self.kind != other.kind {
            return Err(NauError::Validation(format!(
                "cannot add {} {} to {} {}: different kinds of resource are different quantities, \
                 and a sum of them is not a quantity of either",
                self.quantity,
                self.unit(),
                other.quantity,
                other.unit()
            )));
        }
        let total = self.quantity.checked_add(other.quantity).ok_or_else(|| {
            NauError::Validation(format!(
                "adding {} and {} {} overflows",
                self.quantity,
                other.quantity,
                self.unit()
            ))
        })?;
        Self::of(self.kind, total)
    }

    /// Whether `quota` permits this amount.
    ///
    /// # Why this is a method here rather than a conversion
    ///
    /// D-01's second criterion is that [`Quota`] and [`ResourceAmount`] must not be assignable to
    /// each other. This method is the **only** place the two meet, and it returns a `bool` rather
    /// than either type — so the meeting produces an answer, not a value that could then be used as
    /// the other thing.
    ///
    /// The mapping is deliberate and total: each kind has one dimension of the quota that bounds it,
    /// and a kind with none would be a resource nobody can be limited in.
    #[must_use]
    pub fn fits_within(self, quota: Quota) -> bool {
        match self.kind {
            ResourceKind::Cpu => self.quantity <= quota.cpu_ms,
            // Mebibyte-seconds against a byte figure: the quota bounds the address space, and this
            // compares the amount's *instantaneous* ceiling rather than its integral. That is a
            // deliberate approximation and it is the safe direction -- a rate that fits at every
            // instant fits in total -- but it is an approximation, and D-07 is where the resource
            // ledger stops approximating.
            ResourceKind::Memory => self.quantity <= quota.memory_bytes / (1024 * 1024),
            ResourceKind::Storage => self.quantity <= quota.disk_bytes / (1024 * 1024 * 1024),
            // The quota does not bound traffic or published capacity; those are bounded by the two
            // counts it does carry.
            ResourceKind::Network => true,
            ResourceKind::Snapshot => self.quantity <= u64::from(quota.max_sandboxes),
            ResourceKind::AgentCapability => self.quantity <= u64::from(quota.max_agents),
        }
    }
}

/// An amount held over time, for the kinds where that is what it is.
///
/// Kept separate from [`ResourceAmount`] because the fields that make it meaningful only apply to
/// rate-like kinds, and a single struct with an always-present duration would invite a duration on
/// a snapshot count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeteredAmount {
    /// The amount, whose kind must be rate-like.
    pub amount: ResourceAmount,
    /// How long it was held, in seconds.
    pub seconds: u64,
}

impl MeteredAmount {
    /// A metered amount.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the kind is not rate-like, or `seconds` is zero. A duration of
    /// zero would make every rate-like amount a total, which is the confusion this type exists to
    /// prevent.
    pub fn new(amount: ResourceAmount, seconds: u64) -> Result<Self> {
        if !amount.kind().is_rate() {
            return Err(NauError::Validation(format!(
                "{} is a total rather than a rate, so measuring it over time would multiply it by \
                 nothing meaningful",
                amount.kind().label()
            )));
        }
        if seconds == 0 {
            return Err(NauError::Validation(
                "a metered amount must be held for a positive number of seconds".to_string(),
            ));
        }
        Ok(Self { amount, seconds })
    }

    /// The integral: quantity times seconds, still in the kind's rate unit.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the product overflows.
    pub fn integral(self) -> Result<u64> {
        self.amount
            .quantity()
            .checked_mul(self.seconds)
            .ok_or_else(|| {
                NauError::Validation(format!(
                    "{} {} held for {}s overflows",
                    self.amount.quantity(),
                    self.amount.unit(),
                    self.seconds
                ))
            })
    }
}

/// One offer of one kind of resource, from one provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceOffer {
    /// Who is offering. A `Did`, as everywhere else this workspace names a party.
    pub provider: String,
    /// What they are offering.
    pub amount: ResourceAmount,
    /// What they want for it, in minor units.
    pub price: Money,
    /// How long the offer stands, in seconds. Zero is refused: an offer with no expiry is one the
    /// provider cannot withdraw by letting it lapse.
    pub expires_in: u64,
}

impl ResourceOffer {
    /// Check an offer is well-formed.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the price is not positive or the offer never expires.
    pub fn validate(&self) -> Result<()> {
        if self.price <= Money::from_minor(0) {
            return Err(NauError::Validation(format!(
                "an offer of {} {} must carry a positive price",
                self.amount.quantity(),
                self.amount.unit()
            )));
        }
        if self.expires_in == 0 {
            return Err(NauError::Validation(
                "an offer must expire; one that never does is one the provider cannot withdraw by \
                 letting it lapse"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// The price per unit, as a ratio of minor units to units.
    ///
    /// Returned as a **pair** rather than a division, because the division is not exact and this
    /// workspace does not do floating point with money. A caller that wants a number can divide;
    /// what it must not be able to do is get a rounded price from here and treat it as the price.
    #[must_use]
    pub fn unit_price_ratio(&self) -> (i64, u64) {
        (self.price.minor(), self.amount.quantity())
    }
}

/// A set of amounts, keyed by kind, that refuses to lose a kind's unit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBundle {
    amounts: BTreeMap<ResourceKind, u64>,
}

impl ResourceBundle {
    /// An empty bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an amount, summing within its kind.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the sum within a kind overflows.
    pub fn add(&mut self, amount: ResourceAmount) -> Result<()> {
        let entry = self.amounts.entry(amount.kind()).or_insert(0);
        *entry = entry.checked_add(amount.quantity()).ok_or_else(|| {
            NauError::Validation(format!("totals for {} overflow", amount.kind().label()))
        })?;
        Ok(())
    }

    /// How much of `kind`.
    #[must_use]
    pub fn get(&self, kind: ResourceKind) -> u64 {
        self.amounts.get(&kind).copied().unwrap_or(0)
    }

    /// The kinds present, with their totals.
    #[must_use]
    pub fn as_map(&self) -> &BTreeMap<ResourceKind, u64> {
        &self.amounts
    }

    /// How many kinds are present.
    #[must_use]
    pub fn len(&self) -> usize {
        self.amounts.len()
    }

    /// Whether nothing is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.amounts.is_empty()
    }

    /// **There is deliberately no `total()`.**
    ///
    /// A single number summing a bundle would be the mixed-unit arithmetic D-01 exists to prevent,
    /// and offering it as a convenience method is exactly how such a rule gets used. A caller that
    /// wants a total has to say **which kind** it means, and `get` makes it do that.
    #[must_use]
    pub fn total_of(&self, kind: ResourceKind) -> u64 {
        self.get(kind)
    }
}

use nau_core::domain::Quota;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_unit_and_no_two_share_one() {
        // D-01's first criterion, first half. Six kinds, six units, and the units are distinct --
        // so an amount's kind is recoverable from its unit.
        let mut units: Vec<&str> = ResourceKind::ALL.iter().map(|k| k.unit()).collect();
        let count = units.len();
        units.sort_unstable();
        units.dedup();
        assert_eq!(
            units.len(),
            count,
            "two kinds share a unit, which would make the unit unable to say which kind a number is"
        );
        for kind in ResourceKind::ALL {
            assert!(!kind.unit().trim().is_empty(), "{kind:?} has no unit");
        }
        assert_eq!(ResourceKind::ALL.len(), 6);
    }

    #[test]
    fn amounts_of_different_kinds_cannot_be_added() {
        // D-01's first criterion, second half: "the units cannot be mixed" is an error with a
        // message naming both kinds, not a convention.
        let cpu = ResourceAmount::of(ResourceKind::Cpu, 200).expect("amount");
        let memory = ResourceAmount::of(ResourceKind::Memory, 4).expect("amount");
        let err = cpu.checked_add(memory).expect_err("must refuse");
        let text = format!("{err}");
        assert!(text.contains("cpu-milliseconds"), "got: {text}");
        assert!(text.contains("mib-seconds"), "got: {text}");
        assert!(
            text.contains("different kinds of resource are different quantities"),
            "the refusal must say why rather than only that, got: {text}"
        );

        // And the same kind adds, so the rule is not simply always failing.
        let more = ResourceAmount::of(ResourceKind::Cpu, 300).expect("amount");
        assert_eq!(cpu.checked_add(more).expect("sums").quantity(), 500);
    }

    #[test]
    fn a_zero_amount_is_refused_rather_than_being_a_small_one() {
        // Zero is an offer of nothing, and one that reached a matcher would be ranked against real
        // offers.
        for kind in ResourceKind::ALL {
            let err = ResourceAmount::of(kind, 0).expect_err("must refuse zero");
            assert!(
                format!("{err}").contains("offer of nothing"),
                "{kind:?} refused zero without saying why"
            );
        }
    }

    #[test]
    fn an_amount_cannot_be_a_quota_and_a_quota_cannot_be_an_amount() {
        // D-01's second criterion, and the test is the TYPES rather than an assertion inside it:
        // there is no `From`, no `Into`, and no method returning the other. What this test can do is
        // pin the one place they meet, and assert that it produces a bool rather than either type.
        let amount = ResourceAmount::of(ResourceKind::Cpu, 500).expect("amount");
        let quota = Quota {
            memory_bytes: 1024 * 1024 * 64,
            cpu_ms: 1000,
            disk_bytes: 1024 * 1024 * 1024,
            max_sandboxes: 4,
            max_agents: 2,
        };
        // `fits_within` returns `bool`: the meeting produces an answer, not a value that could then
        // be used as the other thing.
        let fits: bool = amount.fits_within(quota);
        assert!(fits, "500ms of a 1000ms allowance fits");
        assert!(!ResourceAmount::of(ResourceKind::Cpu, 1001)
            .expect("amount")
            .fits_within(quota));

        // `Quota::DENIED` permits nothing, which is the kernel's own starting point and the one a
        // market must inherit rather than re-derive.
        assert!(!ResourceAmount::of(ResourceKind::Cpu, 1)
            .expect("amount")
            .fits_within(Quota::DENIED));
    }

    #[test]
    fn the_rate_like_kinds_are_the_two_held_over_time() {
        // Memory and storage are per second; the other four are totals. A price that ignored the
        // clock for these two would be selling something other than what it delivers.
        assert!(ResourceKind::Memory.is_rate());
        assert!(ResourceKind::Storage.is_rate());
        for kind in [
            ResourceKind::Cpu,
            ResourceKind::Network,
            ResourceKind::Snapshot,
            ResourceKind::AgentCapability,
        ] {
            assert!(!kind.is_rate(), "{kind:?} must not be rate-like");
        }
    }

    #[test]
    fn a_total_cannot_be_metered_and_a_zero_duration_is_refused() {
        // A duration on a snapshot count would multiply it by nothing meaningful, and a zero
        // duration would make every rate-like amount a total -- which is the confusion this type
        // exists to prevent.
        let snapshots = ResourceAmount::of(ResourceKind::Snapshot, 3).expect("amount");
        assert!(MeteredAmount::new(snapshots, 60).is_err());

        let memory = ResourceAmount::of(ResourceKind::Memory, 8).expect("amount");
        assert!(MeteredAmount::new(memory, 0).is_err());

        let metered = MeteredAmount::new(memory, 3600).expect("metered");
        assert_eq!(metered.integral().expect("integral"), 8 * 3600);
    }

    #[test]
    fn an_offer_with_no_price_or_no_expiry_is_refused() {
        let amount = ResourceAmount::of(ResourceKind::Cpu, 100).expect("amount");
        let free = ResourceOffer {
            provider: "did:example:provider".to_string(),
            amount,
            price: Money::from_minor(0),
            expires_in: 60,
        };
        assert!(free.validate().is_err(), "a free offer is not an offer");

        let forever = ResourceOffer {
            price: Money::from_minor(10),
            expires_in: 0,
            ..free.clone()
        };
        assert!(
            forever.validate().is_err(),
            "an offer that never expires is one the provider cannot withdraw by letting it lapse"
        );

        let good = ResourceOffer {
            price: Money::from_minor(10),
            expires_in: 60,
            ..free
        };
        good.validate().expect("a priced, expiring offer");
    }

    #[test]
    fn the_unit_price_is_a_ratio_because_the_division_is_not_exact() {
        // This workspace does not do floating point with money, so the ratio is handed over as a
        // pair: a caller that wants a number can divide, and cannot be handed a rounded price that
        // looks like the price.
        let offer = ResourceOffer {
            provider: "did:example:p".to_string(),
            amount: ResourceAmount::of(ResourceKind::Cpu, 3).expect("amount"),
            price: Money::from_minor(10),
            expires_in: 60,
        };
        assert_eq!(offer.unit_price_ratio(), (10, 3));
    }

    #[test]
    fn a_bundle_sums_within_a_kind_and_has_no_grand_total() {
        // The bundle has `total_of(kind)` and deliberately no `total()`: a single number summing a
        // bundle would be the mixed-unit arithmetic this module exists to prevent, and offering it
        // as a convenience is how such a rule gets used.
        let mut bundle = ResourceBundle::new();
        assert!(bundle.is_empty());
        bundle
            .add(ResourceAmount::of(ResourceKind::Cpu, 100).expect("amount"))
            .expect("added");
        bundle
            .add(ResourceAmount::of(ResourceKind::Cpu, 50).expect("amount"))
            .expect("added");
        bundle
            .add(ResourceAmount::of(ResourceKind::Network, 4096).expect("amount"))
            .expect("added");

        assert_eq!(bundle.total_of(ResourceKind::Cpu), 150);
        assert_eq!(bundle.total_of(ResourceKind::Network), 4096);
        assert_eq!(
            bundle.get(ResourceKind::Memory),
            0,
            "an absent kind is zero"
        );
        assert_eq!(bundle.len(), 2);
        assert_eq!(bundle.as_map().len(), 2);
    }

    #[test]
    fn the_labels_are_distinct_and_the_kinds_are_ordered() {
        let mut labels: Vec<&str> = ResourceKind::ALL.iter().map(|k| k.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "two kinds share a label");

        // Ordering exists so a `BTreeMap` of kinds is deterministic, which a report over a bundle
        // needs.
        let mut sorted = ResourceKind::ALL;
        sorted.sort_unstable();
        assert_eq!(sorted, ResourceKind::ALL, "ALL is already in order");
    }
}
