//! Multi-track pricing: scarcity, reputation, latency and snapshot royalties.
//!
//! # D-05's first criterion, held by the type rather than by a rule
//!
//! "Pricing must be explainable — output what each term contributed, not a single number."
//!
//! The strongest form of that is a type with **nowhere to put a bare number**: [`Price`] has a base
//! and a list of [`Adjustment`]s, and [`Price::total_minor`] is **derived** from them. There is no
//! field holding the answer, so a caller cannot receive a price without receiving what produced it.
//!
//! This is the trick C-05 used for a risk assessment, applied to money — and it matters more here,
//! because a price that cannot be explained is one a buyer cannot argue with.
//!
//! # D-05's second criterion: no floating point, anywhere
//!
//! Every adjustment is an **integer number of basis points** applied to an integer base, and the
//! intermediates are `i128` so a chain of adjustments cannot overflow before the result is known.
//! There is no `f64` in this module and there is no place one could be introduced without changing
//! the shape of [`Adjustment`].
//!
//! The workspace's rule is that money is exact because a conservation law that holds in floating
//! point holds until it does not; a price is money, so the same rule applies one step earlier.
//!
//! # The four tracks, and what each is for
//!
//! | track | sign | because |
//! |---|---|---|
//! | scarcity | raises when supply is short | the same resource is worth more when fewer offer it |
//! | reputation | raises with standing | a provider with a record is worth more than one without |
//! | latency | **lowers** for a task that tolerates waiting | batch work on idle capacity should be cheaper, not the same |
//! | snapshot royalty | raises per reuse | an environment reused a hundred times earned its author something |
//!
//! The royalty is the one that is not a market signal: it is a **payment for something already
//! built**, and D-06 is where it becomes a settlement. Here it is a term in a price.

use nau_core::domain::Money;
use nau_core::error::{NauError, Result};
use serde::{Deserialize, Serialize};

use crate::resource::LatencyClass;

/// One track's contribution to a price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adjustment {
    /// Which track.
    ///
    /// Owned rather than &'static str, and that is a fix rather than a preference: a borrowed
    /// string cannot be deserialised, and a price whose terms did not survive a round trip would
    /// arrive at a settlement as a bare number -- which is the shape D-05 exists to prevent.
    pub track: String,
    /// How much it moved the price, in basis points of the base. Signed: a discount is negative.
    pub bps: i32,
    /// Why, in words.
    ///
    /// Not decoration. A basis-point figure with no reason is one a buyer can see but not dispute,
    /// and "dispute" is the whole point of showing the terms.
    pub because: String,
}

impl Adjustment {
    /// A surcharge.
    #[must_use]
    pub fn raises(track: &str, bps: i32, because: impl Into<String>) -> Self {
        Self {
            track: track.to_string(),
            bps: bps.max(0),
            because: because.into(),
        }
    }

    /// A discount.
    #[must_use]
    pub fn lowers(track: &str, bps: i32, because: impl Into<String>) -> Self {
        Self {
            track: track.to_string(),
            bps: -bps.abs(),
            because: because.into(),
        }
    }

    /// The amount this track adds to `base_minor`, in minor units.
    ///
    /// Truncating division, deliberately: rounding **down** means the house never collects a
    /// fraction it did not compute, and the direction is stated rather than left to whichever
    /// integer division the language chose.
    #[must_use]
    pub fn delta_minor(&self, base_minor: i64) -> i64 {
        let product = i128::from(base_minor) * i128::from(self.bps);
        i64::try_from(product / 10_000).unwrap_or(if product < 0 { i64::MIN } else { i64::MAX })
    }

    /// One line, as [`Price::explain`] produces it.
    #[must_use]
    pub fn line(&self, base_minor: i64) -> String {
        format!(
            "{}: {:+} bps ({:+} minor) — {}",
            self.track,
            self.bps,
            self.delta_minor(base_minor),
            self.because
        )
    }
}

/// What a price was computed from.
///
/// # Every track defaults to "not applied"
///
/// The tracks carry `#[serde(default)]`, so a caller names the ones it wants and omits the rest. The
/// alternative -- every field required -- makes a caller write zeros for the tracks it does not want,
/// and a struct whose empty state has to be spelled out is one where forgetting a field looks the
/// same as choosing it.
///
/// `base_minor` is the exception and is required: a price with no base is not a price.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingInput {
    /// The unadjusted price, in minor units.
    pub base_minor: i64,
    /// How short supply is, in basis points. Positive is scarce.
    #[serde(default)]
    pub scarcity_bps: i32,
    /// The provider's reputation, in basis points. Its **excess over the floor** is what earns a
    /// premium, so a provider at the floor earns none.
    #[serde(default)]
    pub reputation_bps: u32,
    /// The reputation at which no premium is earned.
    #[serde(default)]
    pub reputation_floor_bps: u32,
    /// What latency the work tolerates.
    #[serde(default = "default_latency")]
    pub latency: LatencyClass,
    /// How many times this environment has been reused before, if it is a snapshot.
    #[serde(default)]
    pub snapshot_reuses: u32,
}

/// The latency a pricing input has when the caller does not say.
///
/// `Standard` rather than `Tolerant`, and the direction matters: defaulting to the permissive class
/// would give every un-named task the batch discount, which is a discount nobody asked for.
fn default_latency() -> LatencyClass {
    LatencyClass::Standard
}

impl PricingInput {
    /// An input with no tracks active.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `base_minor` is not positive: a price computed from zero would
    /// be a price for nothing, and every adjustment of it would be zero too.
    pub fn of(base_minor: i64) -> Result<Self> {
        if base_minor <= 0 {
            return Err(NauError::Validation(
                "a base price must be positive; every adjustment of zero is zero, so a price from \
                 one would explain nothing while looking computed"
                    .to_string(),
            ));
        }
        Ok(Self {
            base_minor,
            scarcity_bps: 0,
            reputation_bps: 0,
            reputation_floor_bps: 0,
            latency: LatencyClass::Standard,
            snapshot_reuses: 0,
        })
    }
}

/// A price, as its terms.
///
/// # There is no amount field, and that is the design
///
/// D-05 asks that a price be explainable rather than a single number. The strongest form of that is
/// a type with nowhere to put one: what this carries is the base and the [`Adjustment`]s, and
/// [`Price::total_minor`] derives the answer.
///
/// A caller that wants a number has to ask for it, and asking for it is the moment the terms are in
/// its hands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Price {
    /// What the tracks were applied to.
    base_minor: i64,
    /// The tracks, in the order they were considered.
    adjustments: Vec<Adjustment>,
}

impl Price {
    /// Compute a price from its input.
    ///
    /// # Errors
    ///
    /// As [`PricingInput::of`] — every error path is in constructing the input, so a `Price` that
    /// exists is one that was computed from something.
    pub fn compute(input: &PricingInput) -> Result<Self> {
        if input.base_minor <= 0 {
            return Err(NauError::Validation(
                "a base price must be positive".to_string(),
            ));
        }
        let mut adjustments = Vec::new();

        // Scarcity. Signed already, so a glut is a discount rather than a second track.
        if input.scarcity_bps != 0 {
            let scarce = input.scarcity_bps > 0;
            let because = if scarce {
                format!(
                    "supply is short by {} bps, so the same resource costs more",
                    input.scarcity_bps
                )
            } else {
                format!(
                    "supply is long by {} bps, so the same resource costs less",
                    input.scarcity_bps.unsigned_abs()
                )
            };
            adjustments.push(if scarce {
                Adjustment::raises("scarcity", input.scarcity_bps, because)
            } else {
                Adjustment::lowers("scarcity", input.scarcity_bps, because)
            });
        }

        // Reputation, as the EXCESS over the floor. A provider at the floor earns no premium, which
        // makes the floor mean something rather than being a threshold that pays out at zero.
        if input.reputation_bps > input.reputation_floor_bps {
            let excess = input.reputation_bps - input.reputation_floor_bps;
            // One basis point of premium per basis point of excess, capped at 50%: a provider twice
            // the floor is worth more, and one a hundred times the floor is not worth a hundred
            // times as much.
            let bps = i32::try_from(excess.min(5_000)).unwrap_or(5_000);
            adjustments.push(Adjustment::raises(
                "reputation",
                bps,
                format!(
                    "reputation {} bps is {} above the floor of {}, at one point of premium per \
                     point of excess, capped at 50%",
                    input.reputation_bps, excess, input.reputation_floor_bps
                ),
            ));
        }

        // Latency. A task that tolerates waiting should be CHEAPER, not the same -- otherwise there
        // is no reason to run batch work on idle capacity, which is the resource this whole market
        // is about.
        match input.latency {
            LatencyClass::Interactive => adjustments.push(Adjustment::raises(
                "latency",
                3_000,
                "an interactive task needs capacity now, and now is the expensive part",
            )),
            LatencyClass::Standard => {}
            LatencyClass::Tolerant => adjustments.push(Adjustment::lowers(
                "latency",
                2_000,
                "a tolerant task can wait for idle capacity, which is the cheapest thing this \
                 network has",
            )),
        }

        // The snapshot royalty. Per reuse, capped, because a term that grew without bound would
        // make a long-lived environment cost more than building a new one.
        if input.snapshot_reuses > 0 {
            let bps =
                i32::try_from(input.snapshot_reuses.min(10).saturating_mul(100)).unwrap_or(1_000);
            adjustments.push(Adjustment::raises(
                "snapshot-royalty",
                bps,
                format!(
                    "this environment has been reused {} time(s), and its author is paid per use \
                     at 100 bps each, capped at 10 uses",
                    input.snapshot_reuses
                ),
            ));
        }

        Ok(Self {
            base_minor: input.base_minor,
            adjustments,
        })
    }

    /// What the tracks were applied to.
    #[must_use]
    pub fn base_minor(&self) -> i64 {
        self.base_minor
    }

    /// The tracks.
    #[must_use]
    pub fn adjustments(&self) -> &[Adjustment] {
        &self.adjustments
    }

    /// The total, **derived from the terms** rather than stored.
    ///
    /// Never negative: a chain of discounts cannot pay a buyer. That floor is the one place this
    /// function does more than add, and it is here rather than at the call sites so that two callers
    /// cannot disagree about whether a price may go below zero.
    #[must_use]
    pub fn total_minor(&self) -> i64 {
        let mut total = i128::from(self.base_minor);
        for adjustment in &self.adjustments {
            total += i128::from(adjustment.delta_minor(self.base_minor));
        }
        i64::try_from(total.max(0)).unwrap_or(i64::MAX)
    }

    /// The total as `Money`.
    #[must_use]
    pub fn total(&self) -> Money {
        Money::from_minor(self.total_minor())
    }

    /// The sum of the tracks' basis points.
    #[must_use]
    pub fn net_bps(&self) -> i32 {
        self.adjustments.iter().map(|a| a.bps).sum()
    }

    /// One line per track, then the total.
    #[must_use]
    pub fn explain(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .adjustments
            .iter()
            .map(|a| a.line(self.base_minor))
            .collect();
        if out.is_empty() {
            out.push(format!("base {} minor, no track applied", self.base_minor));
        }
        out.push(format!(
            "total {} minor ({:+} bps net)",
            self.total_minor(),
            self.net_bps()
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> PricingInput {
        PricingInput::of(10_000).expect("input")
    }

    #[test]
    fn a_price_carries_its_terms_and_has_nowhere_to_put_a_bare_number() {
        // D-05's first criterion, made structural. There is no amount field to assert the absence
        // of, so what this checks is that the total is DERIVED: change a term and the total follows
        // with nothing to keep in step.
        let mut i = input();
        i.reputation_bps = 5_000;
        i.reputation_floor_bps = 1_000;
        let price = Price::compute(&i).expect("price");

        assert_eq!(price.base_minor(), 10_000);
        assert_eq!(price.adjustments().len(), 1);
        assert!(
            price.adjustments()[0].because.len() > 20,
            "every term must say why, in words: {:?}",
            price.adjustments()[0]
        );
        let before = price.total_minor();
        // The derived total follows the terms rather than being cached beside them.
        let mut more = price.clone();
        more.adjustments
            .push(Adjustment::raises("invented", 1_000, "for the test"));
        assert!(
            more.total_minor() > before,
            "adding a term must move the total; a stored one would not"
        );
    }

    #[test]
    fn every_track_is_integer_basis_points_and_no_float_is_involved() {
        // D-05's second criterion. The assertion is about the SHAPE: `bps` is an `i32`, `base_minor`
        // is an `i64`, and the arithmetic in `delta_minor` goes through `i128`. A price with a
        // fractional component is not expressible here.
        let mut i = input();
        i.scarcity_bps = 2_500;
        i.reputation_bps = 9_000;
        i.reputation_floor_bps = 1_000;
        i.latency = LatencyClass::Interactive;
        i.snapshot_reuses = 3;
        let price = Price::compute(&i).expect("price");

        // Every delta is an exact integer, and the truncation direction is DOWN for a surcharge:
        // the house never collects a fraction it did not compute.
        for adjustment in price.adjustments() {
            let delta = adjustment.delta_minor(price.base_minor());
            let exact = i128::from(price.base_minor()) * i128::from(adjustment.bps) / 10_000;
            assert_eq!(i128::from(delta), exact, "{adjustment:?}");
        }

        // A base that does not divide evenly still gives an integer, and the answer is the
        // truncated one rather than a round-to-nearest.
        let odd = Adjustment::raises("t", 333, "for the test");
        assert_eq!(
            odd.delta_minor(1_001),
            33,
            "1001 * 333 / 10000 = 33.33 -> 33"
        );
        assert_eq!(odd.delta_minor(3), 0, "3 * 333 / 10000 = 0.0999 -> 0");
    }

    #[test]
    fn the_four_tracks_are_the_four_the_plan_named() {
        let mut i = input();
        i.scarcity_bps = 1_000;
        i.reputation_bps = 5_000;
        i.reputation_floor_bps = 1_000;
        i.latency = LatencyClass::Tolerant;
        i.snapshot_reuses = 1;
        let price = Price::compute(&i).expect("price");
        let tracks: Vec<&str> = price
            .adjustments()
            .iter()
            .map(|a| a.track.as_str())
            .collect();
        assert_eq!(
            tracks,
            vec!["scarcity", "reputation", "latency", "snapshot-royalty"]
        );
    }

    #[test]
    fn a_tolerant_task_is_cheaper_and_an_interactive_one_is_dearer() {
        // The direction that makes idle capacity worth using: if a task that can wait cost the same
        // as one that cannot, there would be no reason to schedule it onto idle cycles -- which is
        // the resource this market exists to sell.
        let base = Price::compute(&input()).expect("price");
        let mut tolerant = input();
        tolerant.latency = LatencyClass::Tolerant;
        let mut interactive = input();
        interactive.latency = LatencyClass::Interactive;

        let cheap = Price::compute(&tolerant).expect("price");
        let dear = Price::compute(&interactive).expect("price");
        assert!(
            cheap.total_minor() < base.total_minor(),
            "a tolerant task must be cheaper: {} vs {}",
            cheap.total_minor(),
            base.total_minor()
        );
        assert!(
            dear.total_minor() > base.total_minor(),
            "an interactive one must be dearer: {} vs {}",
            dear.total_minor(),
            base.total_minor()
        );
    }

    #[test]
    fn a_provider_at_the_floor_earns_no_premium() {
        // Otherwise the floor would be a threshold that pays out at zero, which makes it a number
        // with no consequence.
        let mut at_floor = input();
        at_floor.reputation_bps = 1_000;
        at_floor.reputation_floor_bps = 1_000;
        assert!(Price::compute(&at_floor)
            .expect("price")
            .adjustments()
            .is_empty());

        let mut above = input();
        above.reputation_bps = 1_001;
        above.reputation_floor_bps = 1_000;
        assert_eq!(
            Price::compute(&above).expect("price").adjustments().len(),
            1
        );

        let mut below = input();
        below.reputation_bps = 999;
        below.reputation_floor_bps = 1_000;
        assert!(
            Price::compute(&below)
                .expect("price")
                .adjustments()
                .is_empty(),
            "below the floor is not a discount either; it is simply no premium"
        );
    }

    #[test]
    fn the_reputation_premium_and_the_royalty_are_capped() {
        // A term that grew without bound would make a long-lived environment cost more than
        // building a new one, and a provider a hundred times the floor is not worth a hundred
        // times as much.
        let mut extreme = input();
        extreme.reputation_bps = 1_000_000;
        extreme.reputation_floor_bps = 0;
        let price = Price::compute(&extreme).expect("price");
        assert_eq!(price.adjustments()[0].bps, 5_000, "capped at 50%");

        let mut reused = input();
        reused.snapshot_reuses = 1_000;
        let price = Price::compute(&reused).expect("price");
        assert_eq!(price.adjustments()[0].bps, 1_000, "capped at 10 uses");
    }

    #[test]
    fn a_chain_of_discounts_cannot_pay_a_buyer() {
        // The one place `total_minor` does more than add, and it is here rather than at the call
        // sites so two callers cannot disagree about whether a price may go below zero.
        let mut i = input();
        i.scarcity_bps = -9_000;
        i.latency = LatencyClass::Tolerant;
        let price = Price::compute(&i).expect("price");
        assert!(price.total_minor() >= 0, "got {}", price.total_minor());
        // And it is not merely clamped to zero by luck: the raw sum is negative here.
        assert!(price.net_bps() < -10_000 || price.total_minor() < price.base_minor());
    }

    #[test]
    fn a_price_from_nothing_is_refused() {
        // Every adjustment of zero is zero, so a price from one would explain nothing while looking
        // computed.
        assert!(PricingInput::of(0).is_err());
        assert!(PricingInput::of(-1).is_err());
        let mut zero = input();
        zero.base_minor = 0;
        assert!(Price::compute(&zero).is_err());
    }

    #[test]
    fn the_explanation_names_every_track_and_the_total() {
        let mut i = input();
        i.scarcity_bps = 1_000;
        i.latency = LatencyClass::Tolerant;
        let price = Price::compute(&i).expect("price");
        let lines = price.explain();
        assert_eq!(lines.len(), 3, "two tracks and a total: {lines:?}");
        assert!(lines[0].contains("scarcity"), "{lines:?}");
        assert!(lines[0].contains("bps"), "{lines:?}");
        assert!(lines[0].contains("minor"), "{lines:?}");
        assert!(lines[1].contains("latency"), "{lines:?}");
        assert!(lines[2].contains("total"), "{lines:?}");

        // With no track applied, the explanation says so rather than being empty -- an empty
        // explanation would read as a price nobody computed.
        let bare = Price::compute(&input()).expect("price");
        let lines = bare.explain();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("no track applied"), "{lines:?}");
    }

    #[test]
    fn the_adjustment_constructors_carry_their_sign() {
        let up = Adjustment::raises("t", 100, "because");
        let down = Adjustment::lowers("t", 100, "because");
        assert_eq!(up.bps, 100);
        assert_eq!(down.bps, -100);
        // A negative passed to `raises` would invert the meaning of the name.
        assert_eq!(Adjustment::raises("t", -100, "x").bps, 0);
        assert_eq!(Adjustment::lowers("t", -100, "x").bps, -100);
        assert_eq!(up.delta_minor(10_000), 100);
        assert_eq!(down.delta_minor(10_000), -100);
    }

    #[test]
    fn a_price_round_trips_through_json_with_its_terms() {
        // A price whose terms did not survive serialisation would arrive as a number, which is the
        // shape D-05 exists to prevent.
        let mut i = input();
        i.scarcity_bps = 500;
        i.latency = LatencyClass::Tolerant;
        let price = Price::compute(&i).expect("price");
        let text = serde_json::to_string(&price).expect("serialises");
        let back: Price = serde_json::from_str(&text).expect("deserialises");
        assert_eq!(back, price);
        assert_eq!(back.total_minor(), price.total_minor());
        assert_eq!(back.explain(), price.explain());
    }
}
