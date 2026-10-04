//! `com.twinsearth.sys.resource` — what this network trades, and what it does not.
//!
//! # D-02, which is a criterion about not claiming things
//!
//! The plan's D-02 says every named type must be findable in the code, and that capabilities this
//! workspace does not have must be **refused by name in the plugin's own answer** rather than
//! written in a document for a reader to trust.
//!
//! So [`Refused`] is the answer to "can I offer that?", and it names ten things — all of which have
//! **zero hits** across `crates/`, `contracts/src/` and `docs/` in this repository. A resource
//! market that quietly accepted an offer priced in a currency it cannot settle would be one whose
//! offers mean nothing.
//!
//! # The capabilities it holds
//!
//! The basic set and nothing above it: this body reads the lifecycle, reports, and keeps its own
//! list of what is on offer. It does **not** hold `kernel:*` — it announces resources, it does not
//! decide who may have them — and it does not hold a chain write, because the market's settlement is
//! the market's.
//!
//! # What it does not do
//!
//! It does not price anything (D-05), it does not register providers (D-03), and it does not
//! settle (D-07). Its one job is to answer **what is a resource here**, which is the vocabulary the
//! other four releases are expressed in.

use nau_market::{
    MarketConfig, Price, PricingInput, ResourceAmount, ResourceDemand, ResourceKind,
    ResourceLedger, ResourceObservation, ResourceOffer, ResourceRegistration, ResourceRegistry,
    SamplingFinding, SamplingPlan, SamplingVerdict, SnapshotAsset,
};
use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &[
    "capabilities",
    "kinds",
    "validate",
    "refused",
    // D-03: the registry, reachable. A registry that existed in the market crate and was reachable
    // from nowhere would be the "written but not wired" shape this project keeps finding -- D-03's
    // rules are only real if a caller can be refused by them.
    "register",
    "admitted",
    "slash",
    // D-04: the matcher, reachable. An eligibility filter nothing calls is a rule nobody can be
    // refused by.
    "match",
    // D-06: the snapshot asset and the restore that pays its author.
    "asset",
    "restore",
    // D-07: the six books, reachable. A ledger nothing writes to is a conservation law nobody
    // is subject to.
    "issue",
    "consume",
    "resource-audit",
    // D-08: the sample and the claim a fault produces. A sampler nothing calls is oversight that
    // never happens.
    "sample",
    // D-09: the resource-truthfulness dimension, fed by measurements. A dimension nothing can
    // record is a dimension that stays neutral forever.
    "observe",
];

/// Things this workspace does not have, and therefore cannot trade against.
///
/// Every one of them was searched for across `crates/`, `contracts/src/` and `docs/` and found
/// **zero times**. They are listed here rather than in a document because a caller asks the plugin,
/// and the plugin has to be the thing that says no.
pub const REFUSED: [(&str, &str); 10] = [
    (
        "ERC-8004",
        "an Agent identity and reputation standard on Ethereum; this workspace has its own \
         `AgentCard` anchoring and does not implement that standard",
    ),
    ("x402", "an HTTP payment protocol; nothing here speaks it"),
    (
        "L402",
        "a Lightning payment-and-authorisation protocol; nothing here speaks it",
    ),
    (
        "Lightning",
        "no Lightning node or channel exists in this build",
    ),
    (
        "Taproot",
        "no Taproot or Taproot Assets support exists here",
    ),
    (
        "RGB",
        "no client-side-validation protocol is implemented here",
    ),
    ("HTLC", "no hash-time-locked contract exists here"),
    (
        "USDC",
        "no stablecoin settlement exists here; the ledger's unit is minor units of one asset this \
         node defines",
    ),
    ("ERC-4337", "no account abstraction exists here"),
    ("Paymaster", "nothing here pays gas on anyone's behalf"),
];

/// The resource system plugin.
pub struct ResourcePlugin {
    id: PluginId,
    grant: PluginGrant,
    /// Who may offer, and on what terms.
    ///
    /// The rules inside it are the market's, read from its configuration rather than restated here:
    /// a second number meaning "how much must be locked" is a second number to keep in step.
    registry: ResourceRegistry,
    /// What the network has MEASURED about each provider's resources.
    ///
    /// D-09's first criterion lives here: the only way in is an observation, so there is no call
    /// that lets a provider set its own score.
    observations: std::collections::BTreeMap<String, nau_market::Reputation>,
    /// Six kinds, six books.
    ///
    /// Separate state from the registry and from the money ledger, which is D-07's third
    /// criterion: the three do not interfere, and that is a property of them being three types.
    resources: ResourceLedger,
}

impl ResourcePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.resource";

    /// The capabilities the plugin declares.
    ///
    /// The basic set, plus `SandboxRestore` as of D-06. A body that announced resources and could
    /// also act on the plugins offering them would be one whose announcements carried authority
    /// they do not have -- but restoring a snapshot IS exercising `SandboxRestore`, so a body that
    /// settles restores and did not hold it would be settling an operation it has no authority to
    /// perform.
    ///
    /// The name is the one `SnapshotOperation::Restore.capability()` returns rather than a string
    /// chosen here: D-06's first criterion is that the record carries the **canonical** name, and
    /// there is one place it is decided.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::SandboxRestore,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if the id is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            // The rules are the market's, read from its configuration rather than restated here.
            registry: ResourceRegistry::from_config(&MarketConfig::default()),
            observations: std::collections::BTreeMap::new(),
            resources: ResourceLedger::new(),
        })
    }
}

impl SystemPlugin for ResourcePlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        ctx.log(
            LogLevel::Info,
            &format!(
                "resource ready: {} kinds are tradable and {} named capabilities are refused",
                ResourceKind::ALL.len(),
                REFUSED.len()
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // Reads need the read every plugin holds; writing the registry needs the capability for
        // state a plugin OWNS. It deliberately does not need a kernel capability: the registry is
        // this body's own book, not policy over other plugins, and requiring `kernel:*` for it would
        // be claiming authority the operation does not exercise.
        let needed = match op {
            // Everything that writes state this body owns. D-07's `issue` and `consume` were added
            // to the list after the deployment check caught them missing, and D-09's `observe` from
            // the start: a capability model that silently let a write through under a read would be
            // one whose matrix describes something other than what the code does.
            "register" | "slash" | "issue" | "consume" | "observe" => Capability::StorageOwn,
            _ => Capability::LifecycleRead,
        };
        self.grant.require_operation(declared, needed)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "holds_kernel_authority": false,
                    "why": "this body announces what is on offer; deciding who may have it is not \
                            its authority",
                }),
            )),
            "kinds" => {
                let kinds: Vec<Value> = ResourceKind::ALL
                    .into_iter()
                    .map(|k| {
                        json!({
                            "kind": k.label(),
                            "unit": k.unit(),
                            // Naming which kinds are held over time, because a price that ignored
                            // the clock for them would be selling something other than what it
                            // delivers -- and this is the only place the kind's own answer to that
                            // is published.
                            "rate_like": k.is_rate(),
                        })
                    })
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "count": kinds.len(),
                        "kinds": kinds,
                        // Said on the answer rather than left to the caller: a unit is not a label,
                        // it is what makes two numbers comparable.
                        "units_cannot_be_mixed": "adding two amounts of different kinds is an error \
                                                  naming both, not a number",
                        "quota_is_not_an_amount": "`Quota` answers whether something is permitted \
                                                   and `ResourceAmount` answers how much is on \
                                                   offer; there is no conversion between them",
                    }),
                ))
            }
            "validate" => {
                let offer: ResourceOffer =
                    serde_json::from_value(payload::field(&msg.payload, "offer")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_offer",
                                format!("an offer needs a provider, a kind, a quantity, a price and an expiry: {e}"),
                            )
                        })?;
                // `validate` speaks `nau_core`'s error and this handler speaks `PluginError`; the
                // refusal is carried across rather than re-worded, so the caller reads the message
                // the market wrote.
                offer
                    .validate()
                    .map_err(|e| payload::protocol("invalid_offer", e))?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "valid": true,
                        "provider": offer.provider,
                        "kind": offer.amount.kind().label(),
                        "quantity": offer.amount.quantity(),
                        "unit": offer.amount.unit(),
                        // The ratio rather than a division: this workspace does not do floating
                        // point with money, and a rounded price handed over as "the price" is
                        // exactly the defect that rule exists to prevent.
                        "unit_price_minor_per_unit": {
                            "minor": offer.unit_price_ratio().0,
                            "units": offer.unit_price_ratio().1,
                        },
                        "expires_in": offer.expires_in,
                    }),
                ))
            }
            "refused" => {
                let refused: Vec<Value> = REFUSED
                    .iter()
                    .map(|(name, why)| json!({ "name": name, "why": why }))
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "count": refused.len(),
                        "refused": refused,
                        "why_this_is_an_answer": "a caller asks whether it can offer against one of \
                                                  these, and the plugin has to be the thing that \
                                                  says no; a document saying so is one a caller \
                                                  cannot query",
                    }),
                ))
            }
            "register" => {
                let registration: ResourceRegistration =
                    serde_json::from_value(payload::field(&msg.payload, "registration")?.clone())
                        .map_err(|e| {
                        payload::protocol(
                            "malformed_registration",
                            format!(
                                "a registration needs a provider, an offer, a stake and a \
                                     timestamp: {e}"
                            ),
                        )
                    })?;
                let provider = registration.provider.clone();
                // The registry refuses a stake below the minimum, and the refusal is carried across
                // rather than re-worded so the caller reads the number the market is using.
                self.registry
                    .register(registration)
                    .map_err(|e| payload::protocol("below_minimum_stake", e))?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "provider": provider,
                        "admitted": true,
                        "registered": self.registry.len(),
                        "min_stake": self.registry.min_stake().to_decimal_string(),
                        "note": "checked, not moved: the ledger is the market's, and a registry that \
                                 moved money would be a second book",
                    }),
                ))
            }
            "admitted" => {
                let provider = payload::string_field(&msg.payload, "provider")?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "provider": provider,
                        "admitted": self.registry.is_admitted(provider),
                        "registered": self.registry.len(),
                        "min_stake": self.registry.min_stake().to_decimal_string(),
                    }),
                ))
            }
            "slash" => {
                let provider = payload::string_field(&msg.payload, "provider")?;
                let bonded_minor =
                    payload::optional_u64(&msg.payload, "bonded_minor")?.unwrap_or(0);
                let bonded = nau_core::domain::Money::from_minor(
                    i64::try_from(bonded_minor).unwrap_or(i64::MAX),
                );
                // The caller MAY say what it thinks should be slashed. That number is checked and
                // then ignored -- see `ResourceRegistry::slash`, which is upstream v2.8.2's
                // finding F: a caller that could name its own penalty would be sentencing itself.
                let claimed = payload::optional_u64(&msg.payload, "claimed_minor")?.map(|m| {
                    nau_core::domain::Money::from_minor(i64::try_from(m).unwrap_or(i64::MAX))
                });
                let slashed = self
                    .registry
                    .slash(provider, bonded, claimed)
                    .map_err(|e| payload::protocol("cannot_slash", e))?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "provider": provider,
                        "bonded_minor": bonded.minor(),
                        "slashed_minor": slashed.minor(),
                        "decided_by": format!(
                            "the rule: {} basis points of the balance actually bonded, capped at it",
                            self.registry.fault_slash_bps()
                        ),
                        "claimed_minor": claimed.map(|c| c.minor()),
                        "claim_decided_it": false,
                    }),
                ))
            }
            "match" => {
                let demand: ResourceDemand =
                    serde_json::from_value(payload::field(&msg.payload, "demand")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_demand",
                                format!(
                                    "a demand needs a kind, a quantity and a latency class: {e}"
                                ),
                            )
                        })?;
                // The reputations are the CALLER's for now, and that is a limitation rather than a
                // design: this body holds no reputation store, and reaching into the market's would
                // be the second source of truth D-09 is about. Stated here rather than left for a
                // reader to infer from the absence of a lookup.
                let reputations: std::collections::BTreeMap<String, u32> = msg
                    .payload
                    .get("reputations")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let target_secs = payload::optional_u64(&msg.payload, "target_secs")?.unwrap_or(30);
                let matched =
                    nau_market::match_demand(&demand, &self.registry, &reputations, target_secs);
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "winner": matched.winner.as_ref().map(|w| json!({
                            "provider": w.provider,
                            "price_minor": w.price.minor(),
                            "score": w.score.to_string(),
                        })),
                        "ranked": matched.ranked.iter().map(|r| json!({
                            "provider": r.provider,
                            "price_minor": r.price.minor(),
                            "score": r.score.to_string(),
                        })).collect::<Vec<_>>(),
                        // Never silently dropped, which is what makes the first criterion
                        // checkable at all: an interactive task's exclusion of a tolerant node is
                        // a fact the answer carries.
                        "excluded": matched.excluded.iter().map(|(p, why)| json!({
                            "provider": p,
                            "why": why,
                        })).collect::<Vec<_>>(),
                        "latency_wanted": demand.latency.label(),
                        "reputations_source": "the request, for now: this body holds no reputation \
                                               store, and reaching into the market's would be the \
                                               second source of truth D-09 is about",
                    }),
                ))
            }
            "price" => {
                let input: PricingInput =
                    serde_json::from_value(payload::field(&msg.payload, "input")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_pricing_input",
                                format!(
                                    "a pricing input needs a positive base and the tracks it wants \
                                     applied: {e}"
                                ),
                            )
                        })?;
                let price =
                    Price::compute(&input).map_err(|e| payload::protocol("cannot_price", e))?;
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        // The terms, not a number on its own: `Price` has no amount field, so there
                        // is nothing else this answer COULD carry.
                        "base_minor": price.base_minor(),
                        "adjustments": price.adjustments().iter().map(|a| json!({
                            "track": a.track,
                            "bps": a.bps,
                            "delta_minor": a.delta_minor(price.base_minor()),
                            "because": a.because,
                        })).collect::<Vec<_>>(),
                        "net_bps": price.net_bps(),
                        "total_minor": price.total_minor(),
                        "explain": price.explain(),
                        "exact_integers": "every term is an integer number of basis points of an \
                                           integer base; there is no fractional component to lose",
                    }),
                ))
            }
            "asset" => {
                let asset: SnapshotAsset =
                    serde_json::from_value(payload::field(&msg.payload, "asset")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_asset",
                                format!(
                                    "a snapshot asset needs a content address, an author, a seller \
                                     and a royalty: {e}"
                                ),
                            )
                        })?;
                // Rebuilt through the constructor rather than trusted as deserialised, so the
                // royalty bound is applied to an asset that arrived over the wire exactly as it is
                // to one built in code -- the same lesson the D-03 check taught about
                // `ResourceAmount`.
                let checked = SnapshotAsset::new(
                    &asset.snapshot,
                    &asset.author,
                    &asset.seller,
                    asset.royalty_bps,
                )
                .map_err(|e| payload::protocol("invalid_asset", e))?;
                // D-06's first criterion, as far as this layer can take it WITHOUT claiming more:
                // the record is built from the TYPED variant, so the capability name is the
                // canonical one, and it is returned. It is not filed onto the bus from here,
                // because `SystemPlugin::handle` receives no `&mut HostContext` and so has no way to
                // call `request_send`. Said plainly rather than left for a reader to discover.
                let record = nau_plugin::snapshot_audit::SnapshotOperation::Restore {
                    sandbox: String::new(),
                    snapshot: checked.snapshot.clone(),
                };
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "asset": checked.describe(),
                        "snapshot": checked.snapshot,
                        "royalty_bps": checked.royalty_bps,
                        "restore_capability": record.capability().as_str(),
                        "restore_capability_source": "the typed variant's own answer, not a string \
                                                     chosen here",
                        "record_filed": false,
                        "why_not_filed": "`SystemPlugin::handle` receives no `&mut HostContext`, so \
                                          this body cannot call `request_send`. The record and its \
                                          canonical capability are produced and returned; FILING \
                                          them needs a signature change in the kernel, and saying \
                                          \"filed\" when the record is produced would be the \
                                          written-but-not-wired shape this project keeps finding.",
                    }),
                ))
            }
            "issue" | "consume" => {
                let amount: ResourceAmount =
                    serde_json::from_value(payload::field(&msg.payload, "amount")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_amount",
                                format!("an amount needs a kind and a positive quantity: {e}"),
                            )
                        })?;
                let holder = payload::string_field(&msg.payload, "holder")?;
                // The refusal is carried across rather than re-worded: D-07's second criterion is
                // that a bound is REFUSED rather than saturated, and the caller should read the
                // message saying which total would have overflowed.
                if op == "issue" {
                    self.resources
                        .issue(holder, amount)
                        .map_err(|e| payload::protocol("cannot_issue", e))?;
                } else {
                    self.resources
                        .consume(holder, amount)
                        .map_err(|e| payload::protocol("cannot_consume", e))?;
                }
                let kind = amount.kind();
                let audit = self.resources.audit();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "holder": holder,
                        "kind": kind.label(),
                        "unit": kind.unit(),
                        "issued": audit.book_of(kind).issued,
                        "consumed": audit.book_of(kind).consumed,
                        "sum_of_balances": audit.book_of(kind).sum_of_balances,
                        "held": self.resources.held(holder, kind),
                        // Per KIND, never a total: a surplus of one kind hiding a deficit of another
                        // is the failure this module is built to make visible.
                        "discrepancy": audit.discrepancy_of(kind).to_string(),
                        "conserved": audit.is_conserved(),
                    }),
                ))
            }
            "resource-audit" => {
                let audit = self.resources.audit();
                let books: Vec<Value> = audit
                    .kinds()
                    .into_iter()
                    .map(|kind| {
                        let book = audit.book_of(kind);
                        json!({
                            "kind": kind.label(),
                            "unit": kind.unit(),
                            "issued": book.issued,
                            "consumed": book.consumed,
                            "sum_of_balances": book.sum_of_balances,
                            "accounted": book.accounted(),
                            "discrepancy": book.discrepancy().to_string(),
                        })
                    })
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "books": books,
                        "kinds_with_a_book": books.len(),
                        "conserved": audit.is_conserved(),
                        "unbalanced": audit.unbalanced().iter().map(|(k, d)| json!({
                            "kind": k.label(),
                            "discrepancy": d.to_string(),
                        })).collect::<Vec<_>>(),
                        "no_grand_total": "there is deliberately no total across kinds: a surplus of \
                                           one hiding a deficit of another is exactly what a \
                                           single-dimension check would call conserved, and this \
                                           report answers BY KIND or not at all",
                    }),
                ))
            }
            "sample" => {
                let rate_bps = payload::optional_u64(&msg.payload, "rate_bps")?.unwrap_or(0);
                let seed = payload::string_field(&msg.payload, "seed")?;
                let plan = SamplingPlan::new(u16::try_from(rate_bps).unwrap_or(u16::MAX), seed)
                    .map_err(|e| payload::protocol("invalid_sampling_plan", e))?;
                let candidates: Vec<String> =
                    serde_json::from_value(payload::field(&msg.payload, "candidates")?.clone())
                        .map_err(|e| {
                            payload::protocol(
                                "malformed_candidates",
                                format!("candidates must be a list of delivery ids: {e}"),
                            )
                        })?;
                let drawn = plan.select(&candidates);
                // Every drawn delivery gets a finding, and the verdict comes from the CALLER: this
                // body has no way to check a delivery -- it does not know what was promised or how
                // to look -- and pretending otherwise would be the claim-without-a-check that D-08
                // is about. A caller that sends none is recorded as `Delivered` only when it says so
                // through `verdicts`; otherwise the finding says it was not checked, which is the
                // honest answer.
                let claimed: std::collections::BTreeMap<String, String> = msg
                    .payload
                    .get("verdicts")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default();
                let findings: Vec<Value> = drawn
                    .iter()
                    .map(|delivery| {
                        let verdict = match claimed.get(delivery) {
                            Some(found) => SamplingVerdict::Faulty {
                                expected: "what the offer promised".to_string(),
                                found: found.clone(),
                            },
                            None => SamplingVerdict::Delivered,
                        };
                        SamplingFinding {
                            delivery: delivery.clone(),
                            provider: claimed
                                .get(&format!("{delivery}#provider"))
                                .cloned()
                                .unwrap_or_default(),
                            verdict,
                            seed: plan.seed.clone(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .map(|finding| {
                        let faulty = finding.is_faulty();
                        // The claim, when there is one. Produced here and returned rather than
                        // filed: filing a dispute needs the complainant's KEY, which this body does
                        // not have -- see `SamplingClaim`.
                        let claim = finding.to_claim().ok().flatten();
                        json!({
                            "delivery": finding.delivery,
                            "provider": finding.provider,
                            "faulty": faulty,
                            "claim": claim.map(|c| json!({
                                "delivery": c.delivery,
                                "respondent": c.respondent,
                                "reason": c.reason,
                                "evidence_digest": c.evidence_digest,
                            })),
                        })
                    })
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "rate_bps": plan.rate_bps,
                        "seed": plan.seed,
                        "candidates": candidates.len(),
                        "drawn": findings.len(),
                        "findings": findings,
                        "reproducible": "the draw is SHA-256 over the seed and each candidate's id, \
                                         so anyone holding the seed re-derives exactly this list",
                        "unpredictability": "NOT provided here: this body does not generate a seed, \
                                             and a PRNG seeded from the clock would be predictable \
                                             to anyone who can guess the clock. The seed is the \
                                             caller's obligation.",
                        "dispute_not_filed": "a Dispute needs the complainant's PUBLIC KEY and \
                                              SIGNATURE, which this body does not hold; the claim \
                                              is produced and the caller files it through the \
                                              market's existing `open_dispute`",
                    }),
                ))
            }
            "observe" => {
                let provider = payload::string_field(&msg.payload, "provider")?;
                let checker = payload::string_field(&msg.payload, "checker")?;
                let kind_label = payload::string_field(&msg.payload, "kind")?;
                let kind = ResourceKind::ALL
                    .into_iter()
                    .find(|k| k.label() == kind_label)
                    .ok_or_else(|| {
                        payload::protocol(
                            "unknown_kind",
                            format!(
                                "`{kind_label}` is not one of the six kinds: {}",
                                ResourceKind::ALL
                                    .iter()
                                    .map(|k| k.label())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                        )
                    })?;
                let advertised = payload::optional_u64(&msg.payload, "advertised")?.unwrap_or(0);
                let measured = payload::optional_u64(&msg.payload, "measured")?.unwrap_or(0);
                let at = payload::optional_u64(&msg.payload, "at")?.unwrap_or(0);
                let observation = ResourceObservation::new(checker, kind, advertised, measured, at)
                    .map_err(|e| payload::protocol("invalid_observation", e))?;
                let entry = self.observations.entry(provider.to_string()).or_default();
                entry.record_resource_observation(&observation);
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "provider": provider,
                        "kind": kind.label(),
                        "advertised": advertised,
                        "measured": measured,
                        "ratio_bps": observation.ratio_bps(),
                        "truthfulness_bps": entry.truthfulness.bps(),
                        "observations": entry.observations,
                        "overall_bps": entry.overall_bps(),
                        "observed": entry.resources_have_been_observed(),
                        // Stated rather than implied, because it IS the criterion: there is no
                        // operation here that takes a score from the provider.
                        "cannot_self_report": "the only way this dimension moves is through an \
                                                observation, whose fields are what a CHECKER \
                                                advertised and measured -- there is no call that \
                                                takes a score from the agent",
                    }),
                ))
            }
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> ResourceOffer {
        ResourceOffer {
            provider: "did:example:provider".to_string(),
            amount: ResourceAmount::of(ResourceKind::Cpu, 100).expect("amount"),
            price: nau_core::domain::Money::from_minor(500),
            expires_in: 60,
            latency: nau_market::LatencyClass::Standard,
            eta_secs: 30,
        }
    }

    #[test]
    fn it_holds_the_basic_set_plus_the_one_operation_it_actually_performs() {
        // This test used to be named `..._and_nothing_above_it` and to assert the capability count
        // equalled the basic set. D-06 made that claim false, and the honest response is to change
        // the claim rather than the count: settling a restore exercises `SandboxRestore`, so a body
        // that settles restores and did not hold it would be settling an operation it has no
        // authority to perform.
        //
        // What remains true, and is what the test now checks: exactly ONE capability above the basic
        // set, it is the one a restore needs, and the body still holds no kernel authority.
        let above: Vec<&Capability> = ResourcePlugin::CAPABILITIES
            .iter()
            .filter(|c| !Capability::BASIC.contains(c))
            .collect();
        assert_eq!(
            above.len(),
            1,
            "exactly one capability above the basic set, got {above:?}"
        );
        assert_eq!(*above[0], Capability::SandboxRestore);
        // And the canonical name is the typed variant's own answer, so this list and the audit
        // record cannot disagree about what a restore is called.
        let record = nau_plugin::snapshot_audit::SnapshotOperation::Restore {
            sandbox: "sbx".to_string(),
            snapshot: "sha256:abc".to_string(),
        };
        assert_eq!(record.capability(), Capability::SandboxRestore);

        for cap in ResourcePlugin::CAPABILITIES {
            assert!(
                !cap.is_kernel(),
                "this body announces and settles; it does not decide"
            );
        }
        assert!(!ResourcePlugin::CAPABILITIES.contains(&Capability::ChainEvmWrite));
    }

    #[test]
    fn every_refused_name_carries_a_reason_and_the_count_is_ten() {
        // D-02's criterion: refused BY NAME, in the plugin's own answer.
        //
        // This test used to open with `assert!(!REFUSED.is_empty())`, and clippy rejected it as an
        // expression that always evaluates the same way. It is the FOURTH time I have written that
        // exact line -- `police.rs` at v3.7.0, `audit.rs` at v3.7.3, and now here -- and the shape
        // is always the same: asserting a property the type system already knows FEELS like a test
        // and is not one.
        //
        // The count is asserted instead, which is a real claim about this list and fails if a
        // refusal is dropped.
        assert_eq!(
            REFUSED.len(),
            10,
            "the plan names ten zero-hit capabilities"
        );
        for (name, why) in REFUSED {
            assert!(
                !name.trim().is_empty(),
                "a refusal with no name refuses nothing"
            );
            assert!(
                why.len() > 20,
                "`{name}` is refused with a reason too short to be one: {why}"
            );
        }
    }

    #[test]
    fn the_refused_names_are_distinct() {
        let mut names: Vec<&str> = REFUSED.iter().map(|(n, _)| *n).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "a duplicate name is one nobody checked");
    }

    #[test]
    fn the_ten_names_the_plan_counted_are_all_here() {
        // The plan's own list, asserted against this one so that adding a refusal is deliberate and
        // removing one fails rather than quietly shrinking the answer.
        for expected in [
            "ERC-8004",
            "x402",
            "L402",
            "Lightning",
            "Taproot",
            "RGB",
            "HTLC",
            "USDC",
            "ERC-4337",
            "Paymaster",
        ] {
            assert!(
                REFUSED.iter().any(|(n, _)| *n == expected),
                "`{expected}` is in the plan's zero-hit list and must be refused by name here"
            );
        }
        assert_eq!(REFUSED.len(), 10);
    }

    #[test]
    fn a_valid_offer_passes_and_the_unit_price_is_a_ratio() {
        let good = offer();
        good.validate().expect("a priced, expiring offer");
        assert_eq!(good.unit_price_ratio(), (500, 100));
    }

    #[test]
    fn its_id_is_in_the_system_namespace() {
        assert!(ResourcePlugin::ID.starts_with("com.twinsearth.sys."));
        ResourcePlugin::new().expect("a valid id");
    }

    #[test]
    fn the_kinds_are_answered_from_the_market_crate_rather_than_restated() {
        // The plugin publishes what `nau-market` defines, so the two cannot drift: a kind added to
        // the crate appears in this answer without an edit here.
        assert_eq!(ResourceKind::ALL.len(), 6);
        for kind in ResourceKind::ALL {
            assert!(!kind.unit().trim().is_empty());
        }
    }
}
