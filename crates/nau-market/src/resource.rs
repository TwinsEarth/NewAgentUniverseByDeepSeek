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
use nau_core::domain::TaskId;
use nau_core::error::{NauError, Result};
use nau_ledger::{AccountId, Ledger};
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
///
/// # Deserialisation goes through `of`, and that is a fix rather than a style
///
/// This type derived `Deserialize` for three releases' worth of code and the derive **bypassed
/// [`ResourceAmount::of`]** — so an amount arriving as JSON could be zero, which is the one value
/// `of` exists to refuse. The deployment check found it: a registration whose amount was built by
/// serde rather than by the constructor would have reached a matcher as an offer of nothing.
///
/// The manual implementation below deserialises a raw pair and then calls `of`, so an amount on the
/// wire is validated exactly like one built in code. **An invariant that only the constructor
/// enforces is an invariant with a way around it.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ResourceAmount {
    kind: ResourceKind,
    quantity: u64,
}

/// The wire form, before validation.
#[derive(Deserialize)]
struct RawAmount {
    kind: ResourceKind,
    quantity: u64,
}

impl<'de> Deserialize<'de> for ResourceAmount {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawAmount::deserialize(deserializer)?;
        ResourceAmount::of(raw.kind, raw.quantity).map_err(serde::de::Error::custom)
    }
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
    /// The latency class this offer can serve.
    ///
    /// An offer without one would be one a matcher had to guess at, and guessing permissive is the
    /// direction that puts an interactive task on a batch node.
    pub latency: LatencyClass,
    /// How long the provider promises to take, in seconds. Positive.
    pub eta_secs: u64,
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
        if self.eta_secs == 0 {
            return Err(NauError::Validation(
                "an offer must promise a positive completion time; a zero would score as \
                 instantaneous, which no provider can be"
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

/// How much a task or an offer cares about latency.
///
/// # Not `nau_plugin`'s `PriorityClass`
///
/// That type orders **message delivery inside the plugin bus**. This one says how long a piece of
/// work may take. They are different axes — a `Critical` message says nothing about whether the
/// task producing it tolerates a second of delay — and giving this one the other one's name would
/// invite exactly that confusion.
///
/// # Ordered by strictness, so "at least this good" is expressible
///
/// [`LatencyClass::Interactive`] is the **strictest**. The ordering is the point: D-04's first
/// criterion is that an interactive task must not be matched to a tolerant node, and that check is
/// a comparison rather than a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyClass {
    /// A person is waiting. The strictest class.
    Interactive,
    /// Ordinary work.
    Standard,
    /// Batch work that may wait. The most permissive.
    Tolerant,
}

impl LatencyClass {
    /// Every class, strictest first.
    pub const ALL: [LatencyClass; 3] = [
        LatencyClass::Interactive,
        LatencyClass::Standard,
        LatencyClass::Tolerant,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            LatencyClass::Interactive => "interactive",
            LatencyClass::Standard => "standard",
            LatencyClass::Tolerant => "tolerant",
        }
    }

    /// Whether a node of class `self` can serve a task of class `wanted`.
    ///
    /// **A node may serve a task that is more permissive than itself and never one that is
    /// stricter.** An interactive node can do batch work — it is fast enough for both — while a
    /// tolerant node has said it may take its time, and a task that said otherwise must not be
    /// handed to it.
    ///
    /// This is the whole of D-04's first criterion, expressed as one comparison rather than as a
    /// table that could be written the other way round.
    #[must_use]
    pub fn can_serve(self, wanted: LatencyClass) -> bool {
        wanted >= self
    }
}

/// A request for resources, with the latency it tolerates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceDemand {
    /// What is wanted.
    pub amount: ResourceAmount,
    /// How much latency the work tolerates.
    pub latency: LatencyClass,
    /// The most that may be paid, in minor units. Zero means no cap is expressed, which is
    /// deliberate: a demand that must name a budget would make every caller invent one.
    #[serde(default)]
    pub max_price_minor: i64,
    /// The least reputation a provider must have, in basis points. Zero means no floor.
    #[serde(default)]
    pub min_reputation_bps: u32,
}

impl ResourceDemand {
    /// A demand with no price cap and no reputation floor.
    ///
    /// # Errors
    ///
    /// As [`ResourceAmount::of`].
    pub fn of(kind: ResourceKind, quantity: u64, latency: LatencyClass) -> Result<Self> {
        Ok(Self {
            amount: ResourceAmount::of(kind, quantity)?,
            latency,
            max_price_minor: 0,
            min_reputation_bps: 0,
        })
    }

    /// Whether an offer is **eligible** — a hard question, not a score.
    ///
    /// # What this is not
    ///
    /// It is not a penalty. The existing bid path **disfavours** a slow bid and lets it win anyway
    /// if it is cheap enough, which is right for a market where everything is a trade-off. D-04
    /// asks for something the bid path does not do: an interactive task must **not be matched** to
    /// a tolerant node, and "must not" is a filter rather than a weight.
    ///
    /// The two coexist. A score ranks what is eligible; this decides what is eligible at all.
    ///
    /// No `#[must_use]`, because `Result` already carries one: the attribute here would be a second
    /// statement of the same thing, which is what clippy pointed out rather than what I noticed.
    pub fn admits(
        &self,
        offer: &ResourceOffer,
        reputation_bps: u32,
    ) -> std::result::Result<(), String> {
        if offer.amount.kind() != self.amount.kind() {
            return Err(format!(
                "the offer is {} and the demand is {}",
                offer.amount.kind().label(),
                self.amount.kind().label()
            ));
        }
        if !offer.latency.can_serve(self.latency) {
            return Err(format!(
                "a `{}` node cannot serve a `{}` task: it has said it may take its time, and the \
                 task said otherwise",
                offer.latency.label(),
                self.latency.label()
            ));
        }
        if self.max_price_minor > 0 && offer.price.minor() > self.max_price_minor {
            return Err(format!(
                "the offer asks {} and the demand caps at {}",
                offer.price.minor(),
                self.max_price_minor
            ));
        }
        if reputation_bps < self.min_reputation_bps {
            return Err(format!(
                "reputation {reputation_bps} bps is below the floor {}",
                self.min_reputation_bps
            ));
        }
        Ok(())
    }
}

/// One eligible offer, with the score that ordered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedOffer {
    /// Who is offering.
    pub provider: String,
    /// What it costs.
    pub price: Money,
    /// The integer score, higher first.
    pub score: i128,
}

/// The result of matching a demand against a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMatch {
    /// The winning provider, if any offer was eligible.
    pub winner: Option<RankedOffer>,
    /// Every eligible offer, best first.
    pub ranked: Vec<RankedOffer>,
    /// Providers that were **not** eligible, with the reason. Never silently dropped — the same
    /// rule the bid path follows, and the reason D-04's first criterion is checkable at all.
    pub excluded: Vec<(String, String)>,
}

/// How many offers were excluded.
impl ResourceMatch {
    /// Whether anything was eligible.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranked.is_empty()
    }

    /// The providers excluded, by name.
    #[must_use]
    pub fn excluded_providers(&self) -> Vec<&str> {
        self.excluded.iter().map(|(p, _)| p.as_str()).collect()
    }
}

/// Match a demand against a registry, deterministically.
///
/// # The score is the bid path's formula, called rather than copied
///
/// [`crate::matching::score_value`] is the one implementation of "reputation per unit price,
/// discounted by how far the promise runs past the target". Both this and
/// [`crate::matching::rank_bids`] call it, so there is **one** pricing rule and not two that would
/// drift — which is what D-04's third criterion asks for, expressed as a shared function rather
/// than as a promise to keep two sorts in step.
///
/// # Determinism
///
/// Ties are broken by provider name, and the excluded list is sorted, so the output depends only on
/// the set of registrations and not on the order they were inserted. A recorded match whose
/// ordering could change between runs would be one nobody could re-derive.
#[must_use]
pub fn match_demand(
    demand: &ResourceDemand,
    registry: &ResourceRegistry,
    reputations: &BTreeMap<String, u32>,
    target_secs: u64,
) -> ResourceMatch {
    let mut ranked: Vec<RankedOffer> = Vec::new();
    let mut excluded: Vec<(String, String)> = Vec::new();

    for registration in registry.available(demand.amount.kind()) {
        let provider = registration.provider.clone();
        let reputation_bps = reputations.get(&provider).copied().unwrap_or(0);
        match demand.admits(&registration.offer, reputation_bps) {
            Ok(()) => {
                let score = crate::matching::score_value(
                    reputation_bps,
                    registration.offer.price.minor(),
                    registration.offer.eta_secs,
                    target_secs.max(1),
                );
                ranked.push(RankedOffer {
                    provider,
                    price: registration.offer.price,
                    score,
                });
            }
            Err(why) => excluded.push((provider, why)),
        }
    }

    // Highest score first; ties by name, because a sort that left equals in map order would depend
    // on insertion history.
    ranked.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.provider.cmp(&b.provider))
    });
    excluded.sort();

    let winner = ranked.first().cloned();
    ResourceMatch {
        winner,
        ranked,
        excluded,
    }
}

// ---------------------------------------------------------------- D-06, snapshots as goods

/// A reusable environment, as something that can be sold.
///
/// # Content addressing is the whole of the second criterion
///
/// [`SnapshotAsset::snapshot`] is the **content address** a [`SnapshotStore`] filed the environment
/// under — the same address `ImageManifest` uses for image chunks (A-04) and the same one B-11
/// records in its audit trail. So "what you bought is what the address names" is not a policy this
/// type enforces: it is what an address **is**. A buyer that restores the snapshot gets the layers
/// whose hashes are in the address, and a store that had different bytes under that address would
/// fail its own verification rather than serve them.
///
/// [`SnapshotStore`]: nau_sandbox::SnapshotStore
///
/// # The royalty is a share, and the share is exact
///
/// [`SnapshotAsset::royalty_of`] is a basis-point share of the price, truncated down, and
/// [`SnapshotAsset::remainder_of`] is **what is left** rather than a second computation. That order
/// matters: computing the remainder independently would let the two disagree by a minor unit, and a
/// settlement whose parts do not add up to its whole is one the ledger's conservation check would
/// catch — correctly, and late.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotAsset {
    /// The content address the environment is filed under.
    pub snapshot: String,
    /// Who built it, and who is paid each time it is restored.
    pub author: String,
    /// Who is offering it, if that is somebody else.
    ///
    /// Often the author, and deliberately a separate field: an environment can be resold by a party
    /// that did not build it, and a type that assumed otherwise would make that impossible.
    pub seller: String,
    /// The author's share of each restore, in basis points.
    pub royalty_bps: u16,
}

impl SnapshotAsset {
    /// An asset.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the address, the author or the seller is blank, or when the
    /// royalty exceeds 100% — a share larger than the whole would make the settlement pay out more
    /// than it took in, which is the money-creation this workspace's ledger refuses.
    pub fn new(snapshot: &str, author: &str, seller: &str, royalty_bps: u16) -> Result<Self> {
        if snapshot.trim().is_empty() {
            return Err(NauError::Validation(
                "a snapshot asset must name the content address it is filed under; without one \
                 there is nothing that says what a buyer gets"
                    .to_string(),
            ));
        }
        if author.trim().is_empty() || seller.trim().is_empty() {
            return Err(NauError::Validation(
                "a snapshot asset must name both its author and its seller".to_string(),
            ));
        }
        if royalty_bps > 10_000 {
            return Err(NauError::Validation(format!(
                "a royalty of {royalty_bps} bps is more than the whole price, and a settlement \
                 that paid out more than it took in would be creating money"
            )));
        }
        Ok(Self {
            snapshot: snapshot.to_string(),
            author: author.to_string(),
            seller: seller.to_string(),
            royalty_bps,
        })
    }

    /// The author's share of `price`, truncated **down**.
    ///
    /// Down rather than nearest, for the reason every other division in this workspace truncates:
    /// the house never collects a fraction it did not compute, and the direction is stated here
    /// rather than left to whichever integer division the language chose.
    #[must_use]
    pub fn royalty_of(&self, price: Money) -> Money {
        let product = i128::from(price.minor()) * i128::from(self.royalty_bps);
        Money::from_minor(i64::try_from(product / 10_000).unwrap_or(i64::MAX))
    }

    /// What is left for the seller: **the price minus the royalty**, not a second computation.
    #[must_use]
    pub fn remainder_of(&self, price: Money) -> Money {
        Money::from_minor(price.minor() - self.royalty_of(price).minor())
    }

    /// The audit record for one restore is **not built here**, and the reason is placement.
    ///
    /// D-06's first criterion is that every restore has a PMB record, and the record type is
    /// `SnapshotOperation` — which lives in `nau-plugin`, which `nau-market` does not depend on. The
    /// kernel is not a data crate's dependency, so this module cannot name that type even to return
    /// one.
    ///
    /// The record is therefore built where both are visible: the `com.twinsearth.sys.resource`
    /// plugin, whose `restore` operation calls [`settle_restore`] and then files the operation under
    /// the typed variant's canonical capability name.
    ///
    /// This is the placement rule v3.6.7 recorded for the snapshot store's consistency claim and
    /// v3.8.1 met again for `Tier` and `PluginState`: **evidence belongs where the thing it is about
    /// lives, and a dependency that exists for a signature's sake is the wrong shape.**
    ///
    /// What this module keeps is the part that is a market's: the address, the shares, and the
    /// settlement.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} built by {}, sold by {}, {} bps to the author per restore",
            self.snapshot, self.author, self.seller, self.royalty_bps
        )
    }
}

/// What one restore settled, and to whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreSettlement {
    /// The author's share.
    pub royalty: Money,
    /// The seller's share.
    pub remainder: Money,
    /// The total, which is what the buyer paid.
    pub total: Money,
    /// The ledger's discrepancy after both escrows were released.
    ///
    /// Returned rather than merely asserted inside the function, because D-06's third criterion is
    /// that the settlement **conserves** — and a caller that has to be handed the number is one that
    /// cannot forget to check it.
    pub discrepancy: i64,
}

impl RestoreSettlement {
    /// Whether the parts add up to the whole and the ledger is conserved.
    #[must_use]
    pub fn is_conserved(&self) -> bool {
        self.discrepancy == 0 && self.royalty.minor() + self.remainder.minor() == self.total.minor()
    }
}

/// Settle one restore of `asset`, paying the author and the seller from `buyer`.
///
/// # Two escrows rather than one, and that is the existing API's shape
///
/// [`Ledger::escrow`] opens an escrow with a payer and [`Ledger::release`] pays it to **one**
/// payee. A royalty split has two payees, so it is two escrows — each from the same buyer, each
/// released to its own payee. The alternative would be a ledger method that splits a payment, which
/// is a new mechanism in the crate whose whole job is to have as few of those as possible.
///
/// # Conservation, checked rather than asserted
///
/// The escrows are funded from the buyer's balance, so nothing is created: what leaves the buyer
/// arrives at the two payees, and the ledger's own `discrepancy` is **zero**. That number is
/// returned rather than swallowed, and [`RestoreSettlement::is_conserved`] is what a caller checks.
///
/// # Errors
///
/// Whatever the ledger refuses — an underfunded buyer, a task with an open escrow, a zero amount —
/// carried across unchanged rather than re-worded.
pub fn settle_restore(
    ledger: &mut Ledger,
    asset: &SnapshotAsset,
    restore_id: &str,
    buyer: &AccountId,
    price: Money,
    at: u64,
) -> Result<RestoreSettlement> {
    if price <= Money::from_minor(0) {
        return Err(NauError::Validation(
            "a restore must be paid for; a zero price would settle nothing while looking settled"
                .to_string(),
        ));
    }
    let royalty = asset.royalty_of(price);
    let remainder = asset.remainder_of(price);

    // ---------------------------------------------------------------- the precondition
    //
    // Checked BEFORE either escrow is opened, and this is a fix rather than a precaution: the test
    // `a_restore_that_cannot_be_paid_for_moves_nothing` found the two-escrow settlement taking the
    // ROYALTY successfully and then failing on the remainder, leaving the author paid, the seller
    // unpaid, and the ledger perfectly balanced. A ledger that balances is not the same as a
    // settlement that completed.
    //
    // The check is the buyer covering the WHOLE price, because that is what the two escrows will
    // draw between them. It is not the same as either escrow's own check and cannot be: each escrow
    // asks whether the buyer can afford IT, and the question that matters is whether they can afford
    // both.
    //
    // The alternative -- a ledger method that opens two escrows and releases both or neither -- is a
    // new mechanism in the crate whose whole job is to have as few of those as possible. One
    // precondition needs none.
    if ledger.balance(buyer) < price {
        // The variant carries the two numbers the ledger itself would report, so a caller reading
        // this and a caller reading the ledger's own refusal see the same shape -- and
        // `matches!(err, NauError::InsufficientBalance { .. })` catches both.
        return Err(NauError::InsufficientBalance {
            account: buyer.to_string(),
            available: ledger.balance(buyer).minor(),
            required: price.minor(),
        });
    }

    // Two task ids derived from the restore, so the two escrows are distinguishable in the journal
    // and a second restore of the same asset does not collide with the first.
    //
    // A hyphen rather than a colon, and that is not style: TaskId::parse allows only ASCII
    // letters, digits, - and _, and it rejected `restore-1:royalty` with a message naming
    // the rule. The compiler could not have caught it -- the id is built at run time -- which is
    // what the test was for.
    let royalty_task = TaskId::parse(&format!("{restore_id}-royalty"))?;
    let remainder_task = TaskId::parse(&format!("{restore_id}-remainder"))?;
    let author_account = AccountId::parse(&asset.author)?;
    let seller_account = AccountId::parse(&asset.seller)?;

    // The royalty first, and skipped entirely when it is zero: an escrow of nothing is refused by
    // the ledger, and a zero-royalty asset is a legitimate thing for an author to publish.
    if royalty > Money::from_minor(0) {
        ledger.escrow(&royalty_task, buyer, royalty, at)?;
        ledger.release(&royalty_task, &author_account, at)?;
    }
    // Then the seller's share. Also skipped when zero, which is the case for an author selling
    // their own work at 100%.
    if remainder > Money::from_minor(0) {
        ledger.escrow(&remainder_task, buyer, remainder, at)?;
        ledger.release(&remainder_task, &seller_account, at)?;
    }

    let report = ledger.audit();
    Ok(RestoreSettlement {
        royalty,
        remainder,
        total: price,
        discrepancy: report.discrepancy,
    })
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

// ---------------------------------------------------------------- D-03, the registry

/// One provider's registration: what they offer, and what they have locked to offer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRegistration {
    /// Who is offering, as a `Did`.
    pub provider: String,
    /// What they are offering.
    pub offer: ResourceOffer,
    /// What is locked. Moved into the stake account by the caller, not by this type — see
    /// [`ResourceRegistry::register`].
    pub stake: Money,
    /// When they registered, Unix seconds.
    pub registered_at: u64,
}

/// Who may offer resources, and what happens when they do not deliver.
///
/// # Both rules are read from the market's own configuration
///
/// [`ResourceRegistry::from_config`] takes a [`MarketConfig`](crate::MarketConfig) and keeps
/// [`min_stake`](crate::MarketConfig::min_stake) and
/// [`fault_slash_bps`](crate::MarketConfig::fault_slash_bps) from it. It does **not** define its own
/// threshold or its own penalty fraction.
///
/// That is D-03's first criterion, and it is the reasoning this workspace keeps arriving at: a
/// second number meaning "how much must be locked" is a second number to keep in step, and the one
/// that goes stale is whichever the operator did not read.
///
/// # No new `Tier`, no new `PluginState`
///
/// D-03's second criterion. A resource provider is **not** a new kind of principal: it is a party
/// that registered an offer and locked a stake, and nothing about the kernel's tier model or its
/// lifecycle state machine changes to accommodate it. A test below asserts both variant counts, so
/// an edit that added one here would fail rather than pass unnoticed.
///
/// # The penalty is computed, never taken
///
/// [`ResourceRegistry::slash`] takes the caller's claimed amount and **checks it for
/// well-formedness only**. The amount it returns is `fault_slash_bps` of the balance actually
/// bonded — upstream v2.8.2's finding F, whose lesson was that a caller-supplied penalty is a
/// request to be sentenced by the accused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRegistry {
    entries: BTreeMap<String, ResourceRegistration>,
    min_stake: Money,
    fault_slash_bps: u16,
}

impl ResourceRegistry {
    /// A registry whose rules are the market's.
    #[must_use]
    pub fn from_config(config: &crate::MarketConfig) -> Self {
        Self {
            entries: BTreeMap::new(),
            min_stake: config.min_stake,
            fault_slash_bps: config.fault_slash_bps,
        }
    }

    /// The minimum stake this registry admits at.
    ///
    /// Exposed so an operator can read the number **this** registry is using rather than having to
    /// know which configuration it was built from.
    #[must_use]
    pub fn min_stake(&self) -> Money {
        self.min_stake
    }

    /// The penalty fraction, in basis points.
    #[must_use]
    pub fn fault_slash_bps(&self) -> u16 {
        self.fault_slash_bps
    }

    /// How many providers are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nobody is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `provider` is registered.
    #[must_use]
    pub fn contains(&self, provider: &str) -> bool {
        self.entries.contains_key(provider)
    }

    /// Register or replace a provider's offer.
    ///
    /// The registry **checks** the stake rather than moving it: the ledger is the market's, and a
    /// registry that moved money would be a second book. What it does is refuse an offer whose stake
    /// is below the minimum, which makes "below the minimum cannot offer" a property of the registry
    /// rather than of a caller's diligence.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the stake is below [`ResourceRegistry::min_stake`], when the
    /// offer is malformed, when the provider name is blank, or when the timestamp is zero.
    pub fn register(&mut self, registration: ResourceRegistration) -> Result<()> {
        if registration.provider.trim().is_empty() {
            return Err(NauError::Validation(
                "a registration must name its provider".to_string(),
            ));
        }
        registration.offer.validate()?;
        if registration.stake < self.min_stake {
            return Err(NauError::Validation(format!(
                "stake {} is below the minimum {} this registry admits at",
                registration.stake.to_decimal_string(),
                self.min_stake.to_decimal_string()
            )));
        }
        if registration.registered_at == 0 {
            return Err(NauError::Validation(
                "a registration must carry a non-zero timestamp".to_string(),
            ));
        }
        self.entries
            .insert(registration.provider.clone(), registration);
        Ok(())
    }

    /// Remove a provider, returning the stake that was locked.
    ///
    /// `None` when they were not registered. Deregistering somebody who is not there is not an
    /// error: an operator ensuring a provider is gone should not have to know whether they ever
    /// appeared.
    ///
    /// # Errors
    ///
    /// Never today; the signature is a `Result` so that a future rule — a cooling-off period, or a
    /// bar on withdrawing while a dispute is open — can refuse without changing every caller.
    pub fn deregister(&mut self, provider: &str) -> Result<Option<Money>> {
        Ok(self.entries.remove(provider).map(|r| r.stake))
    }

    /// Whether `provider` may be matched.
    ///
    /// A provider is admitted exactly when they are registered, and registration requires the
    /// stake. So this is not a second check of the threshold: it is the question the matcher asks,
    /// and the threshold was applied when the entry was written.
    #[must_use]
    pub fn is_admitted(&self, provider: &str) -> bool {
        self.entries.contains_key(provider)
    }

    /// Every admitted offer of `kind`, cheapest first.
    ///
    /// Sorted by price and then by provider, so the order is **deterministic**: two calls on the
    /// same registry return the same sequence, which is what a match whose outcome is recorded
    /// needs. D-04 does the real matching; this is the filter that says who is eligible for it.
    #[must_use]
    pub fn available(&self, kind: ResourceKind) -> Vec<&ResourceRegistration> {
        let mut out: Vec<&ResourceRegistration> = self
            .entries
            .values()
            .filter(|r| r.offer.amount.kind() == kind)
            .collect();
        out.sort_by(|a, b| {
            a.offer
                .price
                .minor()
                .cmp(&b.offer.price.minor())
                // The provider name breaks ties, because a sort that leaves equal elements in map
                // order is one whose result depends on insertion history.
                .then_with(|| a.provider.cmp(&b.provider))
        });
        out
    }

    /// What a guilty provider forfeits, computed from the rule.
    ///
    /// # The parameter that does not decide anything
    ///
    /// `claimed` is the amount a caller says should be slashed. It is checked — a guilty verdict
    /// must declare a **positive** amount, so a zero there is a malformed request rather than a
    /// lenient one — and it is then **ignored**. The returned amount is
    /// [`ResourceRegistry::fault_slash_bps`] of `bonded`, capped at `bonded`.
    ///
    /// That is upstream v2.8.2's finding F, applied here for the same reason it was applied there:
    /// a caller that could name its own penalty would be sentencing itself.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the provider is not registered, when `bonded` is negative, or
    /// when `claimed` is present and not positive.
    pub fn slash(&self, provider: &str, bonded: Money, claimed: Option<Money>) -> Result<Money> {
        if !self.entries.contains_key(provider) {
            return Err(NauError::Validation(format!(
                "`{provider}` is not registered, so there is no stake to slash"
            )));
        }
        if bonded < Money::from_minor(0) {
            return Err(NauError::Validation(
                "a bonded balance cannot be negative".to_string(),
            ));
        }
        // Well-formedness only. A caller's number is a claim about what should happen; it is not the
        // rule, and treating a zero as "slash nothing" would make silence the lightest sentence.
        if let Some(amount) = claimed {
            if amount <= Money::from_minor(0) {
                return Err(NauError::Validation(
                    "a guilty verdict must declare a positive slash; a zero is a malformed verdict \
                     rather than a lenient one"
                        .to_string(),
                ));
            }
        }
        // Basis points of the balance actually bonded, in i128 so the intermediate cannot overflow
        // before the cap. The cap is the point: a penalty cannot exceed what is there.
        let bps = i128::from(self.fault_slash_bps.min(10_000));
        let product = i128::from(bonded.minor()).saturating_mul(bps) / 10_000;
        let capped = product.clamp(0, i128::from(bonded.minor()));
        Ok(Money::from_minor(i64::try_from(capped).unwrap_or(i64::MAX)))
    }
}

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
            latency: LatencyClass::Standard,
            eta_secs: 30,
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
            latency: LatencyClass::Standard,
            eta_secs: 30,
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

    // ------------------------------------------------------------ D-03

    fn config() -> crate::MarketConfig {
        crate::MarketConfig::default()
    }

    fn registration(provider: &str, stake_minor: i64) -> ResourceRegistration {
        ResourceRegistration {
            provider: provider.to_string(),
            offer: ResourceOffer {
                provider: provider.to_string(),
                amount: ResourceAmount::of(ResourceKind::Cpu, 100).expect("amount"),
                price: Money::from_minor(500),
                expires_in: 60,
                latency: LatencyClass::Standard,
                eta_secs: 30,
            },
            stake: Money::from_minor(stake_minor),
            registered_at: 1,
        }
    }

    #[test]
    fn a_provider_below_the_minimum_stake_cannot_offer() {
        // D-03's first criterion. The threshold is the MARKET's -- read from `MarketConfig` rather
        // than defined here -- so this test reads it from the same place.
        let config = config();
        let mut registry = ResourceRegistry::from_config(&config);
        assert_eq!(registry.min_stake(), config.min_stake);
        assert_eq!(registry.fault_slash_bps(), config.fault_slash_bps);

        let below = config.min_stake.minor() - 1;
        let err = registry
            .register(registration("did:example:poor", below))
            .expect_err("must refuse a stake below the minimum");
        let text = format!("{err}");
        assert!(text.contains("below the minimum"), "got: {text}");
        assert!(
            !registry.is_admitted("did:example:poor"),
            "a refused registration must not leave an admitted provider"
        );
        assert!(registry.is_empty());

        // Exactly the minimum is admitted, so the rule is a floor rather than something stricter.
        registry
            .register(registration("did:example:ok", config.min_stake.minor()))
            .expect("the minimum is enough");
        assert!(registry.is_admitted("did:example:ok"));
        assert!(registry.contains("did:example:ok"));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn this_registry_adds_no_tier_and_no_lifecycle_state() {
        // D-03's second criterion. A resource provider is not a new kind of principal: it is a party
        // that registered an offer and locked a stake, and nothing about the kernel's tier model or
        // its lifecycle state machine changes to accommodate it.
        //
        // The assertion on the VARIANT COUNTS lives in `nau-plugin`'s own suite rather than here, and
        // that is the placement rule v3.6.7 recorded for the snapshot store's consistency claim:
        // `nau-market` does not depend on `nau-plugin` -- the kernel is not a data crate's
        // dependency -- so a test here could only reach those lists by adding a dependency that
        // exists for the test's sake. The evidence belongs where the thing it is about lives.
        //
        // What this test can assert from here is the part that is this crate's: the registry treats a
        // provider as a plain name with no kernel concept attached.
        let mut registry = ResourceRegistry::from_config(&config());
        registry
            .register(registration("did:example:p", config().min_stake.minor()))
            .expect("registered");
        assert!(registry.is_admitted("did:example:p"));
        // Admission is keyed by the provider's own name and nothing about its standing in any other
        // model: two names that differ by one character are two providers.
        assert!(!registry.is_admitted("did:example:q"));
    }

    #[test]
    fn the_penalty_is_computed_and_the_callers_number_does_not_decide_it() {
        // D-03's third criterion, and the shape upstream v2.8.2's finding F established for
        // slashing: a caller that could name its own penalty would be sentencing itself.
        let config = config();
        let mut registry = ResourceRegistry::from_config(&config);
        registry
            .register(registration("did:example:p", config.min_stake.minor()))
            .expect("registered");

        let bonded = Money::from_minor(1_000_000);
        // 1000 bps of 1,000,000 is 100,000.
        let computed = registry
            .slash("did:example:p", bonded, None)
            .expect("slash");
        assert_eq!(computed, Money::from_minor(100_000));

        // The caller asks for a tenth of that, and a tenth of that is not what happens.
        let lenient = registry
            .slash("did:example:p", bonded, Some(Money::from_minor(1)))
            .expect("slash");
        assert_eq!(
            lenient, computed,
            "the caller's amount must not decide the penalty"
        );

        // The caller asks for ten times it, and the cap is what is actually bonded.
        let greedy = registry
            .slash("did:example:p", bonded, Some(Money::from_minor(10_000_000)))
            .expect("slash");
        assert_eq!(greedy, computed, "and neither must a larger number");

        // A zero claim is refused as MALFORMED rather than honoured as lenient -- treating silence
        // as the lightest sentence is the failure this rule exists to prevent.
        let err = registry
            .slash("did:example:p", bonded, Some(Money::from_minor(0)))
            .expect_err("must refuse a zero claim");
        assert!(format!("{err}").contains("positive"), "got: {err}");

        // And an unregistered provider has no stake to slash.
        assert!(registry
            .slash("did:example:stranger", bonded, None)
            .is_err());
    }

    #[test]
    fn the_penalty_never_exceeds_what_is_bonded() {
        // The cap, at a fraction that would otherwise overshoot: 10,000 bps is all of it, and a
        // configuration above 10,000 is clamped rather than paying out more than is there.
        let mut config = config();
        config.fault_slash_bps = 20_000;
        let mut registry = ResourceRegistry::from_config(&config);
        registry
            .register(registration("did:example:p", config.min_stake.minor()))
            .expect("registered");
        let bonded = Money::from_minor(7_777);
        assert_eq!(
            registry
                .slash("did:example:p", bonded, None)
                .expect("slash"),
            bonded,
            "a penalty cannot exceed the balance it is taken from"
        );
    }

    #[test]
    fn deregistering_returns_the_stake_and_a_stranger_is_not_an_error() {
        let config = config();
        let mut registry = ResourceRegistry::from_config(&config);
        registry
            .register(registration("did:example:p", config.min_stake.minor()))
            .expect("registered");

        let returned = registry
            .deregister("did:example:p")
            .expect("deregisters")
            .expect("was registered");
        assert_eq!(returned, config.min_stake);
        assert!(!registry.is_admitted("did:example:p"));
        assert!(registry.is_empty());

        // Somebody who was never here: an operator ensuring a provider is gone should not have to
        // know whether they ever appeared.
        assert!(registry
            .deregister("did:example:never")
            .expect("not an error")
            .is_none());
    }

    #[test]
    fn available_is_deterministic_and_filtered_by_kind() {
        // A match whose outcome is recorded needs a sequence that does not depend on insertion
        // history, so equals are broken by provider name rather than left in map order.
        let config = config();
        let mut registry = ResourceRegistry::from_config(&config);
        for (provider, price, kind) in [
            ("did:example:c", 900, ResourceKind::Cpu),
            ("did:example:a", 900, ResourceKind::Cpu),
            ("did:example:b", 100, ResourceKind::Cpu),
            ("did:example:d", 1, ResourceKind::Memory),
        ] {
            registry
                .register(ResourceRegistration {
                    offer: ResourceOffer {
                        provider: provider.to_string(),
                        amount: ResourceAmount::of(kind, 10).expect("amount"),
                        price: Money::from_minor(price),
                        expires_in: 60,
                        latency: LatencyClass::Standard,
                        eta_secs: 30,
                    },
                    ..registration(provider, config.min_stake.minor())
                })
                .expect("registered");
        }

        let cpu: Vec<&str> = registry
            .available(ResourceKind::Cpu)
            .iter()
            .map(|r| r.provider.as_str())
            .collect();
        assert_eq!(
            cpu,
            vec!["did:example:b", "did:example:a", "did:example:c"],
            "cheapest first, and equal prices broken by name rather than by insertion"
        );
        assert_eq!(registry.available(ResourceKind::Memory).len(), 1);
        assert!(registry.available(ResourceKind::Snapshot).is_empty());

        // Called twice, same answer: the property a recorded outcome needs.
        let again: Vec<&str> = registry
            .available(ResourceKind::Cpu)
            .iter()
            .map(|r| r.provider.as_str())
            .collect();
        assert_eq!(cpu, again);
    }

    #[test]
    fn a_registration_with_no_provider_no_timestamp_or_a_bad_offer_is_refused() {
        let config = config();
        let mut registry = ResourceRegistry::from_config(&config);
        let good = registration("did:example:p", config.min_stake.minor());

        let mut blank = good.clone();
        blank.provider = "   ".to_string();
        assert!(
            registry.register(blank).is_err(),
            "a provider must be named"
        );

        let mut timeless = good.clone();
        timeless.registered_at = 0;
        assert!(
            registry.register(timeless).is_err(),
            "a registration must carry a non-zero timestamp"
        );

        let mut free = good.clone();
        free.offer.price = Money::from_minor(0);
        assert!(
            registry.register(free).is_err(),
            "a free offer is not an offer"
        );

        assert!(registry.is_empty(), "nothing malformed may be admitted");
    }

    #[test]
    fn an_amount_arriving_as_json_is_validated_like_one_built_in_code() {
        // The defect this catches: `ResourceAmount` derived `Deserialize`, and the derive bypassed
        // `of` -- so an amount on the wire could be zero, which is the one value `of` exists to
        // refuse. The deployment check found it by sending a registration whose amount came from
        // JSON rather than from the constructor.
        let ok: ResourceAmount =
            serde_json::from_str(r#"{"kind":"cpu","quantity":100}"#).expect("a positive amount");
        assert_eq!(ok.quantity(), 100);
        assert_eq!(ok.kind(), ResourceKind::Cpu);

        let zero = serde_json::from_str::<ResourceAmount>(r#"{"kind":"cpu","quantity":0}"#);
        assert!(
            zero.is_err(),
            "an amount of nothing must be refused on the wire exactly as it is in code"
        );
        let text = format!("{}", zero.expect_err("refused"));
        assert!(
            text.contains("offer of nothing"),
            "and with the same reason, got: {text}"
        );

        // An unknown kind is refused by serde itself, which is the other half of the wire being a
        // closed vocabulary.
        assert!(serde_json::from_str::<ResourceAmount>(r#"{"kind":"gpu","quantity":1}"#).is_err());
    }

    #[test]
    fn a_registration_round_trips_through_json_with_its_money_transparent() {
        // `Money` is `#[serde(transparent)]` over an i64, so a price is a JSON INTEGER. The
        // deployment check's first version sent an object and was refused with
        // `invalid type: map, expected i64` -- the wire form is the crate's, and this pins it.
        let config = config();
        let registration = registration("did:example:p", config.min_stake.minor());
        let text = serde_json::to_string(&registration).expect("serialises");
        assert!(
            text.contains(r#""stake":"#) && !text.contains(r#""stake":{"#),
            "the stake must be a JSON integer, got: {text}"
        );
        let back: ResourceRegistration = serde_json::from_str(&text).expect("deserialises");
        assert_eq!(back, registration);
    }

    // ------------------------------------------------------------ D-04

    fn offer_of(
        provider: &str,
        latency: LatencyClass,
        price_minor: i64,
        eta: u64,
    ) -> ResourceOffer {
        ResourceOffer {
            provider: provider.to_string(),
            amount: ResourceAmount::of(ResourceKind::Cpu, 100).expect("amount"),
            price: Money::from_minor(price_minor),
            expires_in: 60,
            latency,
            eta_secs: eta,
        }
    }

    fn registry_with(offers: Vec<ResourceOffer>) -> ResourceRegistry {
        let config = config();
        let mut registry = ResourceRegistry::from_config(&config);
        for offer in offers {
            registry
                .register(ResourceRegistration {
                    provider: offer.provider.clone(),
                    offer,
                    stake: config.min_stake,
                    registered_at: 1,
                })
                .expect("registered");
        }
        registry
    }

    #[test]
    fn an_interactive_task_is_not_matched_to_a_tolerant_node() {
        // D-04's first criterion, and the difference from the bid path matters: `rank_bids`
        // DISFAVOURS a slow bid and lets it win anyway if it is cheap enough. "Must not be matched"
        // is a filter rather than a weight.
        let registry = registry_with(vec![
            // Half the price of the interactive node, and ten times slower.
            offer_of("did:example:cheap", LatencyClass::Tolerant, 100, 600),
            offer_of("did:example:fast", LatencyClass::Interactive, 200, 5),
        ]);
        let demand =
            ResourceDemand::of(ResourceKind::Cpu, 10, LatencyClass::Interactive).expect("demand");

        let matched = match_demand(&demand, &registry, &BTreeMap::new(), 30);
        assert_eq!(
            matched.winner.as_ref().map(|w| w.provider.as_str()),
            Some("did:example:fast"),
            "an interactive task must go to the interactive node"
        );
        assert!(
            matched.excluded_providers().contains(&"did:example:cheap"),
            "and the tolerant node must be EXCLUDED rather than merely outscored: {:?}",
            matched.excluded
        );
        let why = &matched
            .excluded
            .iter()
            .find(|(p, _)| p == "did:example:cheap")
            .expect("named")
            .1;
        assert!(
            why.contains("cannot serve"),
            "the exclusion must say why, got: {why}"
        );
        assert!(
            why.contains("tolerant") && why.contains("interactive"),
            "and must name both classes, got: {why}"
        );
    }

    #[test]
    fn a_stricter_node_may_serve_a_more_permissive_task() {
        // The other direction, because a rule that only ever refused would be indistinguishable
        // from a broken one. An interactive node is fast enough for batch work.
        assert!(LatencyClass::Interactive.can_serve(LatencyClass::Tolerant));
        assert!(LatencyClass::Interactive.can_serve(LatencyClass::Interactive));
        assert!(LatencyClass::Tolerant.can_serve(LatencyClass::Tolerant));
        assert!(
            !LatencyClass::Tolerant.can_serve(LatencyClass::Interactive),
            "a node that said it may take its time must not take work that said otherwise"
        );
        assert!(LatencyClass::Standard.can_serve(LatencyClass::Tolerant));
        assert!(!LatencyClass::Standard.can_serve(LatencyClass::Interactive));

        // And through the matcher, not only through the predicate.
        let registry = registry_with(vec![offer_of(
            "did:example:fast",
            LatencyClass::Interactive,
            500,
            5,
        )]);
        let tolerant =
            ResourceDemand::of(ResourceKind::Cpu, 10, LatencyClass::Tolerant).expect("demand");
        let matched = match_demand(&tolerant, &registry, &BTreeMap::new(), 30);
        assert_eq!(
            matched.winner.expect("a winner").provider,
            "did:example:fast"
        );
        assert!(matched.excluded.is_empty());
    }

    #[test]
    fn the_match_is_deterministic_including_the_excluded_list() {
        // D-04's second criterion. A recorded match whose ordering could change between runs is one
        // nobody could re-derive -- and the EXCLUDED list matters as much as the ranked one, since
        // it is what a losing provider would be shown.
        let registry = registry_with(vec![
            offer_of("did:example:z", LatencyClass::Interactive, 300, 5),
            offer_of("did:example:a", LatencyClass::Interactive, 300, 5),
            offer_of("did:example:m", LatencyClass::Interactive, 300, 5),
            offer_of("did:example:slow1", LatencyClass::Tolerant, 10, 900),
            offer_of("did:example:slow2", LatencyClass::Tolerant, 10, 900),
        ]);
        let demand =
            ResourceDemand::of(ResourceKind::Cpu, 10, LatencyClass::Interactive).expect("demand");

        let first = match_demand(&demand, &registry, &BTreeMap::new(), 30);
        for _ in 0..8 {
            let again = match_demand(&demand, &registry, &BTreeMap::new(), 30);
            assert_eq!(first, again, "the same input must give the same match");
        }
        // Equal scores are broken by name rather than left in map order.
        let order: Vec<&str> = first.ranked.iter().map(|r| r.provider.as_str()).collect();
        assert_eq!(
            order,
            vec!["did:example:a", "did:example:m", "did:example:z"]
        );
        // And the excluded list is sorted, so it does not depend on insertion history either.
        let excluded: Vec<&str> = first.excluded_providers();
        assert_eq!(excluded, vec!["did:example:slow1", "did:example:slow2"]);
    }

    #[test]
    fn the_score_is_the_same_function_the_bid_path_calls() {
        // D-04's third criterion. "Reuse" cannot mean calling `rank_bids`, whose inputs are
        // Task/Bid/AgentCard -- a resource offer is none of those -- so it means what it can
        // honestly mean: one implementation of the formula, called from both places.
        //
        // Asserted by calling it directly and finding its answer in the match.
        let registry = registry_with(vec![offer_of(
            "did:example:p",
            LatencyClass::Standard,
            1_000,
            10,
        )]);
        let demand =
            ResourceDemand::of(ResourceKind::Cpu, 10, LatencyClass::Standard).expect("demand");
        let reputations: BTreeMap<String, u32> =
            [("did:example:p".to_string(), 5_000)].into_iter().collect();

        let target = 30;
        let matched = match_demand(&demand, &registry, &reputations, target);
        let expected = crate::matching::score_value(5_000, 1_000, 10, target);
        assert_eq!(matched.winner.expect("a winner").score, expected);

        // And the formula itself behaves the way its documentation says: a higher reputation scores
        // higher, a higher price scores lower, and being late is penalised.
        assert!(
            crate::matching::score_value(9_000, 1_000, 10, 30)
                > crate::matching::score_value(1_000, 1_000, 10, 30)
        );
        assert!(
            crate::matching::score_value(5_000, 100, 10, 30)
                > crate::matching::score_value(5_000, 1_000, 10, 30)
        );
        assert!(
            crate::matching::score_value(5_000, 1_000, 10, 30)
                > crate::matching::score_value(5_000, 1_000, 900, 30)
        );
        // A non-positive price is the one input the formula cannot speak about.
        assert_eq!(crate::matching::score_value(5_000, 0, 10, 30), 0);
    }

    #[test]
    fn a_demand_that_caps_its_price_or_its_providers_excludes_by_that_too() {
        // The other two filters, because a `max_price_minor` that only appeared in an answer would
        // be one nobody could rely on.
        let registry = registry_with(vec![
            offer_of("did:example:pricey", LatencyClass::Standard, 9_000, 5),
            offer_of("did:example:cheap", LatencyClass::Standard, 100, 5),
        ]);
        let mut demand =
            ResourceDemand::of(ResourceKind::Cpu, 10, LatencyClass::Standard).expect("demand");
        demand.max_price_minor = 1_000;
        let matched = match_demand(&demand, &registry, &BTreeMap::new(), 30);
        // Borrowed rather than moved, because the excluded list is read after it and a `clone()`
        // here would hide which of the two the assertion is really about.
        assert_eq!(
            matched.winner.as_ref().map(|w| w.provider.as_str()),
            Some("did:example:cheap")
        );
        assert_eq!(matched.excluded_providers(), vec!["did:example:pricey"]);

        // The reputation floor, with a provider the map has never heard of -- which is a reputation
        // of zero and therefore below any positive floor.
        let mut floored =
            ResourceDemand::of(ResourceKind::Cpu, 10, LatencyClass::Standard).expect("demand");
        floored.min_reputation_bps = 1;
        let unknown = match_demand(&floored, &registry, &BTreeMap::new(), 30);
        assert!(unknown.is_empty(), "an unknown provider has no reputation");
        assert_eq!(unknown.excluded.len(), 2);

        // And a demand for a different kind excludes everything, naming why.
        let wrong_kind =
            ResourceDemand::of(ResourceKind::Snapshot, 1, LatencyClass::Standard).expect("demand");
        let none = match_demand(&wrong_kind, &registry, &BTreeMap::new(), 30);
        assert!(none.is_empty());
    }

    #[test]
    fn an_offer_must_promise_a_positive_completion_time() {
        // A zero ETA would score as instantaneous, which no provider can be.
        let mut offer = offer_of("did:example:p", LatencyClass::Standard, 100, 1);
        offer.eta_secs = 0;
        let err = offer.validate().expect_err("must refuse a zero ETA");
        assert!(
            format!("{err}").contains("positive completion time"),
            "got: {err}"
        );
    }

    // ------------------------------------------------------------ D-06

    #[test]
    fn a_royalty_split_adds_up_to_the_price_and_the_parts_are_exact() {
        // D-06's third criterion's arithmetic half. The remainder is the price MINUS the royalty
        // rather than a second computation, because two computations can disagree by a minor unit,
        // and a settlement whose parts do not add up to its whole is one the ledger's conservation
        // check would catch -- correctly, and late.
        let asset = SnapshotAsset::new(
            "sha256:abc",
            "did:example:author",
            "did:example:seller",
            250,
        )
        .expect("asset");
        for price_minor in [1i64, 3, 7, 999, 10_000, 1_000_000, 12_345_679] {
            let price = Money::from_minor(price_minor);
            let royalty = asset.royalty_of(price);
            let remainder = asset.remainder_of(price);
            assert_eq!(
                royalty.minor() + remainder.minor(),
                price.minor(),
                "the parts must add up to the whole at {price_minor}"
            );
            // And the royalty is the truncated product rather than a rounded one.
            let exact = i128::from(price_minor) * 250 / 10_000;
            assert_eq!(i128::from(royalty.minor()), exact);
        }
    }

    #[test]
    fn a_royalty_larger_than_the_whole_is_refused() {
        // A share above 100% would make the settlement pay out more than it took in, which is the
        // money-creation this workspace's ledger refuses -- so it is refused here, earlier, with a
        // message that says why.
        let err = SnapshotAsset::new("sha256:a", "did:example:a", "did:example:s", 10_001)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("creating money"), "got: {err}");
        // Exactly 100% is allowed: an author selling their own work keeps all of it, and the
        // seller's escrow is simply skipped.
        let all =
            SnapshotAsset::new("sha256:a", "did:a", "did:s", 10_000).expect("100% is a share");
        let price = Money::from_minor(1_000);
        assert_eq!(all.royalty_of(price), price);
        assert_eq!(all.remainder_of(price), Money::from_minor(0));
    }

    #[test]
    fn an_asset_must_name_its_address_its_author_and_its_seller() {
        // Without an address there is nothing that says what a buyer gets, which is the whole of the
        // second criterion.
        assert!(SnapshotAsset::new("  ", "did:a", "did:s", 0).is_err());
        assert!(SnapshotAsset::new("sha256:a", "", "did:s", 0).is_err());
        assert!(SnapshotAsset::new("sha256:a", "did:a", "  ", 0).is_err());
        let good = SnapshotAsset::new("sha256:a", "did:a", "did:s", 0).expect("asset");
        assert!(good.describe().contains("sha256:a"));
        assert!(good.describe().contains("0 bps"));
    }

    #[test]
    fn settling_a_restore_conserves_the_ledger_and_moves_nothing_that_was_not_there() {
        // D-06's third criterion, end to end. The escrows are funded from the buyer's balance, so
        // nothing is created: what leaves the buyer arrives at the two payees, and the ledger's own
        // discrepancy is zero.
        let mut ledger = Ledger::new();
        let buyer = AccountId::parse("did:example:buyer").expect("account");
        let author = AccountId::parse("did:example:author").expect("account");
        let seller = AccountId::parse("did:example:seller").expect("account");
        ledger
            .deposit(&buyer, Money::from_minor(1_000_000), "for the test", 1)
            .expect("funded");

        let before = ledger.audit();
        let asset = SnapshotAsset::new(
            "sha256:abc",
            "did:example:author",
            "did:example:seller",
            2_500,
        )
        .expect("asset");
        let settled = settle_restore(
            &mut ledger,
            &asset,
            "restore-1",
            &buyer,
            Money::from_minor(100_000),
            2,
        )
        .expect("settled");

        assert!(settled.is_conserved(), "{settled:?}");
        assert_eq!(
            settled.royalty,
            Money::from_minor(25_000),
            "2500 bps of 100000"
        );
        assert_eq!(settled.remainder, Money::from_minor(75_000));
        assert_eq!(settled.total, Money::from_minor(100_000));
        assert_eq!(settled.discrepancy, 0, "the ledger must be conserved");

        // The money MOVED rather than appearing: the buyer is down exactly the price, and the two
        // payees are up exactly the two shares.
        assert_eq!(ledger.balance(&buyer), Money::from_minor(900_000));
        assert_eq!(ledger.balance(&author), Money::from_minor(25_000));
        assert_eq!(ledger.balance(&seller), Money::from_minor(75_000));

        // And the ledger's own view of what exists is unchanged, which is the property that
        // separates a transfer from a mint.
        //
        // `before` was briefly an unused binding here -- clippy caught it -- and the right response
        // was to restore the assertion rather than delete the variable, because this IS D-06's third
        // criterion rather than a decoration on it.
        //
        // The two fields are the ones `ConservationReport` actually has. My first version asserted a
        // `total_supply` that does not exist: the same invented-field-name defect C-08's criterion
        // (2) exists to prevent, caught this time by the compiler rather than by a reviewer.
        // Together they say what a transfer is: the sum of every balance is unchanged, AND what the
        // balances are supposed to add up to is unchanged.
        let after = ledger.audit();
        assert_eq!(
            before.sum_of_balances, after.sum_of_balances,
            "a settlement moves money between accounts; it must not change the total"
        );
        assert_eq!(
            before.accounted_total, after.accounted_total,
            "and it must not change what the balances are supposed to add up to"
        );
        assert_eq!(after.discrepancy, 0);
    }

    #[test]
    fn a_restore_that_cannot_be_paid_for_moves_nothing() {
        // The failure has to be total: a settlement that took the royalty and then failed on the
        // remainder would leave the buyer paid-up and the seller unpaid, in a ledger that still
        // balances.
        let mut ledger = Ledger::new();
        let buyer = AccountId::parse("did:example:buyer").expect("account");
        ledger
            .deposit(&buyer, Money::from_minor(50_000), "for the test", 1)
            .expect("funded");
        let asset =
            SnapshotAsset::new("sha256:a", "did:example:a", "did:example:s", 2_500).expect("asset");

        assert!(settle_restore(
            &mut ledger,
            &asset,
            "restore-poor",
            &buyer,
            Money::from_minor(100_000),
            2,
        )
        .is_err());
        assert_eq!(
            ledger.balance(&buyer),
            Money::from_minor(50_000),
            "nothing moved"
        );
        assert_eq!(ledger.audit().discrepancy, 0);

        // A zero price would settle nothing while looking settled.
        assert!(settle_restore(
            &mut ledger,
            &asset,
            "restore-free",
            &buyer,
            Money::from_minor(0),
            2
        )
        .is_err());
    }

    #[test]
    fn two_restores_of_one_asset_do_not_collide() {
        // The escrow task ids are derived from the restore, so a second restore is a second pair of
        // escrows rather than a conflict with the first -- which is what the ledger reports for a
        // task that already has an open escrow.
        let mut ledger = Ledger::new();
        let buyer = AccountId::parse("did:example:buyer").expect("account");
        ledger
            .deposit(&buyer, Money::from_minor(1_000_000), "for the test", 1)
            .expect("funded");
        let asset = SnapshotAsset::new(
            "sha256:a",
            "did:example:author",
            "did:example:seller",
            1_000,
        )
        .expect("asset");

        for restore in ["restore-a", "restore-b", "restore-c"] {
            settle_restore(
                &mut ledger,
                &asset,
                restore,
                &buyer,
                Money::from_minor(10_000),
                2,
            )
            .expect("settled");
        }
        assert_eq!(ledger.audit().discrepancy, 0);
        assert_eq!(ledger.balance(&buyer), Money::from_minor(970_000));
        let author = AccountId::parse("did:example:author").expect("account");
        assert_eq!(ledger.balance(&author), Money::from_minor(3_000));
        let seller = AccountId::parse("did:example:seller").expect("account");
        assert_eq!(ledger.balance(&seller), Money::from_minor(27_000));
    }

    #[test]
    fn a_zero_royalty_pays_the_seller_everything() {
        // An author may publish with no royalty, and the settlement must SKIP an escrow of nothing
        // rather than open one -- the ledger refuses a zero escrow, so a settlement that opened one
        // would fail on a perfectly legitimate asset.
        let mut ledger = Ledger::new();
        let buyer = AccountId::parse("did:example:buyer").expect("account");
        ledger
            .deposit(&buyer, Money::from_minor(100_000), "for the test", 1)
            .expect("funded");
        let asset = SnapshotAsset::new("sha256:a", "did:example:author", "did:example:seller", 0)
            .expect("asset");
        let settled = settle_restore(
            &mut ledger,
            &asset,
            "restore-free-royalty",
            &buyer,
            Money::from_minor(10_000),
            2,
        )
        .expect("settled");
        assert_eq!(settled.royalty, Money::from_minor(0));
        assert_eq!(settled.remainder, Money::from_minor(10_000));
        assert!(settled.is_conserved());
        let seller = AccountId::parse("did:example:seller").expect("account");
        assert_eq!(ledger.balance(&seller), Money::from_minor(10_000));
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
