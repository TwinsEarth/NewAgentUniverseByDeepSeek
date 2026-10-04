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

use nau_market::{ResourceKind, ResourceOffer};
use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "kinds", "validate", "refused"];

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
}

impl ResourcePlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.resource";

    /// The capabilities the plugin declares.
    ///
    /// The basic set and nothing above it. A body that announced resources and could also act on
    /// the plugins offering them would be one whose announcements carried authority they do not
    /// have.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
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
        // Every operation here is a read: this body announces, and announcing changes nothing.
        self.grant
            .require_operation(declared, Capability::LifecycleRead)?;

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
    use nau_market::ResourceAmount;

    fn offer() -> ResourceOffer {
        ResourceOffer {
            provider: "did:example:provider".to_string(),
            amount: ResourceAmount::of(ResourceKind::Cpu, 100).expect("amount"),
            price: nau_core::domain::Money::from_minor(500),
            expires_in: 60,
        }
    }

    #[test]
    fn it_holds_the_basic_set_and_nothing_above_it() {
        // Announcing resources is not authority over them.
        assert_eq!(ResourcePlugin::CAPABILITIES.len(), Capability::BASIC.len());
        for cap in ResourcePlugin::CAPABILITIES {
            assert!(!cap.is_kernel(), "this body announces, it does not decide");
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
