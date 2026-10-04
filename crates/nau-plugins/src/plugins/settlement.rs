//! `com.twinsearth.sys.settlement` — the vocabulary of settlement rails, and which of them exist.
//!
//! # E-01's shape, and why it is a vocabulary rather than an integration
//!
//! This is A-03's method applied to money. A-03 built `EnforcementSupport` — `Available { via }` or
//! `Refused { reason }` — before there was any enforcement, so that "this platform cannot do that"
//! would be **a typed refusal with a reason** rather than a silent downgrade.
//!
//! E-01 does the same for settlement. Every rail the design has ever mentioned is a variant of
//! [`SettlementRail`], and every one of them answers [`SettlementRail::support`]:
//!
//! * [`RailSupport::Available`] names **how**, in terms that are in this repository.
//! * [`RailSupport::Refused`] names **why not**, in terms of what is missing.
//!
//! There is no third answer. A rail that is neither available nor refused would be one a caller
//! could not act on, and the point of this release is that **a caller can ask**.
//!
//! # E-02, or: the plan's hit table is no longer true, and this file says so
//!
//! `docs/DEVELOPMENT-PLAN-v3.8-v3.9-Economy.md` records ten nouns as having **zero** hits in this
//! repository. That was true when the plan was written and **it is no longer true**: v3.8.0's
//! `com.twinsearth.sys.resource` plugin lists all ten in its `REFUSED` table, so each of them now
//! has hits — **in a refusal, which is the right kind of hit but not a zero.**
//!
//! That is worth stating precisely rather than repeating the plan's number, and
//! `docs/SETTLEMENT-NOUN-AUDIT.md` carries the re-run. The distinction matters because "zero hits"
//! and "appears only in a refusal" support different sentences: the first can be written as "this
//! repository does not mention X", and the second cannot.
//!
//! # The four contracts that DO exist
//!
//! `contracts/src/` holds `GovernanceToken.sol`, `Settlement.sol`, `ReputationRegistry.sol` and
//! `AgentCardAnchor.sol`, with `contracts/test/SettlementInvariant.t.sol` among their tests. Those
//! are the on-chain surface this repository actually has, and every rail below either names one of
//! them or says what it would need that no of them provides.

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "rails", "route", "nouns"];

/// How a rail is provided, or why it is not.
///
/// The same two-case shape A-03's `EnforcementSupport` uses, and for the same reason: a caller that
/// asked "can you settle this?" must get an answer it can act on, and "no" without a reason is one it
/// cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RailSupport {
    /// It exists, and here is what provides it.
    Available {
        /// What provides it, in terms that are in this repository.
        via: &'static str,
    },
    /// It does not, and here is what is missing.
    Refused {
        /// Why not. A sentence a caller can act on.
        reason: &'static str,
    },
}

/// A way value can move.
///
/// Every variant is a rail the design has named. The ones this repository provides come first, so
/// that a reader meets what exists before what does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettlementRail {
    /// The node's own ledger: exact integer minor units, conserved, no network.
    ///
    /// This is the only rail that has ever carried a balance in this workspace, and E-04's criterion
    /// keeps it the source of truth even once other rails exist.
    LocalLedger,
    /// The EVM contracts in `contracts/src/`.
    ///
    /// `Settlement.sol` exists and its invariants are tested. What the node does **not** have is a
    /// key that can sign for it, which is why the rail below is separate.
    EvmContracts,
    /// An EVM transaction signed by a key this node holds.
    ///
    /// Distinct from [`SettlementRail::EvmContracts`] because the contracts existing and the node
    /// being able to write to them are different facts, and a rail that conflated them would report
    /// the first as if it were the second.
    EvmSignedWrite,
    /// Bitcoin UTXO value.
    Bitcoin,
    /// A hash-time-locked swap between chains.
    Htlc,
    /// The Lightning network.
    Lightning,
    /// Client-side-validated assets (RGB).
    Rgb,
    /// Taproot and Taproot Assets.
    Taproot,
    /// A stablecoin.
    Stablecoin,
    /// Account abstraction (ERC-4337) and a paymaster.
    AccountAbstraction,
    /// An agent identity and reputation standard on a chain (ERC-8004).
    AgentIdentityStandard,
    /// HTTP-native machine payment (x402).
    HttpPayment,
    /// Payment-as-authorisation over Lightning (L402).
    LightningAuth,
}

impl SettlementRail {
    /// Every rail, in the order above.
    pub const ALL: [SettlementRail; 13] = [
        SettlementRail::LocalLedger,
        SettlementRail::EvmContracts,
        SettlementRail::EvmSignedWrite,
        SettlementRail::Bitcoin,
        SettlementRail::Htlc,
        SettlementRail::Lightning,
        SettlementRail::Rgb,
        SettlementRail::Taproot,
        SettlementRail::Stablecoin,
        SettlementRail::AccountAbstraction,
        SettlementRail::AgentIdentityStandard,
        SettlementRail::HttpPayment,
        SettlementRail::LightningAuth,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SettlementRail::LocalLedger => "local-ledger",
            SettlementRail::EvmContracts => "evm-contracts",
            SettlementRail::EvmSignedWrite => "evm-signed-write",
            SettlementRail::Bitcoin => "bitcoin",
            SettlementRail::Htlc => "htlc",
            SettlementRail::Lightning => "lightning",
            SettlementRail::Rgb => "rgb",
            SettlementRail::Taproot => "taproot",
            SettlementRail::Stablecoin => "stablecoin",
            SettlementRail::AccountAbstraction => "account-abstraction",
            SettlementRail::AgentIdentityStandard => "agent-identity-standard",
            SettlementRail::HttpPayment => "http-payment",
            SettlementRail::LightningAuth => "lightning-auth",
        }
    }

    /// Whether this rail can move value **without leaving the node**.
    ///
    /// The distinction the router turns on, and the one that keeps this release honest: a rail that
    /// needs a network is one this workspace cannot exercise end to end, whatever the contracts say.
    #[must_use]
    pub fn is_local(self) -> bool {
        matches!(
            self,
            SettlementRail::LocalLedger | SettlementRail::EvmContracts
        )
    }

    /// How this rail is provided, or why it is not.
    ///
    /// # E-01's first criterion, and the whole of this release
    ///
    /// Every rail answers, and the two answers are distinguishable. A rail that returned
    /// `Available` for something this repository does not have would be the "written but not wired"
    /// shape this project keeps finding, one level up: **a vocabulary that described a capability
    /// nobody implemented.**
    #[must_use]
    pub fn support(self) -> RailSupport {
        match self {
            SettlementRail::LocalLedger => RailSupport::Available {
                via: "nau-ledger: exact integer minor units with a conservation check, and the only \
                      rail that has ever carried a balance here",
            },
            SettlementRail::EvmContracts => RailSupport::Available {
                via: "contracts/src/Settlement.sol and its invariants, plus GovernanceToken.sol, \
                      ReputationRegistry.sol and AgentCardAnchor.sol; deployable and testable with \
                      forge, with no node-side key involved",
            },
            SettlementRail::EvmSignedWrite => RailSupport::Refused {
                reason: "the contracts exist but this node holds no key that may sign for them, and \
                         E-06's criterion says a private key never enters a sandbox -- so a signed \
                         write is a separate rail from the contracts rather than a use of them",
            },
            SettlementRail::Bitcoin => RailSupport::Refused {
                reason: "no Bitcoin node, no UTXO set and no `bitcoin:*` capability exist in this \
                         repository (E-03 declares them; until then this is a refusal)",
            },
            SettlementRail::Htlc => RailSupport::Refused {
                reason: "no hash-time-locked contract exists here, on any chain",
            },
            SettlementRail::Lightning => RailSupport::Refused {
                reason: "no Lightning node, channel or invoice exists in this build",
            },
            SettlementRail::Rgb => RailSupport::Refused {
                reason: "no client-side-validation protocol is implemented here",
            },
            SettlementRail::Taproot => RailSupport::Refused {
                reason: "no Taproot or Taproot Assets support exists here",
            },
            SettlementRail::Stablecoin => RailSupport::Refused {
                reason: "no stablecoin settlement exists here; the ledger's unit is minor units of \
                         one asset this node defines, and it is not pegged to anything",
            },
            SettlementRail::AccountAbstraction => RailSupport::Refused {
                reason: "no account abstraction and no paymaster exist here; nothing in this \
                         workspace pays gas on anyone's behalf",
            },
            SettlementRail::AgentIdentityStandard => RailSupport::Refused {
                reason: "this workspace has its own `AgentCard` anchoring in \
                         contracts/src/AgentCardAnchor.sol and does not implement any external \
                         agent-identity standard",
            },
            SettlementRail::HttpPayment => RailSupport::Refused {
                reason: "nothing here speaks an HTTP payment protocol, and the sandbox refuses \
                         outbound network access -- so an agent inside one could not use it even if \
                         the node could",
            },
            SettlementRail::LightningAuth => RailSupport::Refused {
                reason: "it is Lightning plus HTTP payment, and neither exists here",
            },
        }
    }

    /// Whether this rail is available.
    #[must_use]
    pub fn is_available(self) -> bool {
        matches!(self.support(), RailSupport::Available { .. })
    }

    /// The reason it is not, if it is not.
    #[must_use]
    pub fn refusal(self) -> Option<&'static str> {
        match self.support() {
            RailSupport::Available { .. } => None,
            RailSupport::Refused { reason } => Some(reason),
        }
    }
}

/// What a route decision was based on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRequest {
    /// The amount, in minor units.
    pub amount_minor: i64,
    /// Whether the payer will wait for a network.
    pub tolerates_network: bool,
    /// Whether the payee will accept the node's own ledger unit.
    pub payee_accepts_local: bool,
}

/// A route decision, as its reasoning.
///
/// # E-01's second criterion: the decision is explainable
///
/// [`Route::considered`] carries **every rail that was looked at and why it was not chosen**, which
/// is the same shape the matcher uses for excluded bidders and the sampler for undrawn deliveries.
/// A router that returned only its choice would be one a payer could not argue with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The rail chosen, if one was.
    pub chosen: Option<SettlementRail>,
    /// Every rail considered and rejected, with the reason.
    pub considered: Vec<(SettlementRail, String)>,
}

impl Route {
    /// One line per rejected rail, then the choice.
    #[must_use]
    pub fn explain(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .considered
            .iter()
            .map(|(rail, why)| format!("{}: not chosen because {why}", rail.label()))
            .collect();
        match self.chosen {
            Some(rail) => out.push(format!("chosen: {}", rail.label())),
            None => out.push(
                "chosen: nothing -- no rail this node has can carry this settlement".to_string(),
            ),
        }
        out
    }
}

/// Choose a rail, and say why the others were not.
///
/// # The rules, in order, and none of them is a preference
///
/// 1. **A rail that is not available is never chosen**, and appears in `considered` with its own
///    refusal reason rather than a generic one. That is E-01's first criterion reaching the router:
///    an unavailable rail is not a cheaper option, it is an option that does not exist.
/// 2. **A local rail is preferred when the payee accepts the ledger's unit**, because it settles
///    without a network and therefore cannot fail half-way. The preference is stated rather than
///    implied, and the reason it is safe is that the ledger conserves.
/// 3. **A payer who will not wait is told the truth**: if nothing local is acceptable, the answer is
///    that nothing is chosen, rather than a rail that would need a network they said they would not
///    wait for.
///
/// # Determinism
///
/// Pure, and the rails are iterated in their declared order, so two callers with the same request
/// and the same node get the same route.
#[must_use]
pub fn route(request: &RouteRequest) -> Route {
    let mut considered = Vec::new();
    let mut chosen = None;
    for rail in SettlementRail::ALL {
        if !rail.is_available() {
            considered.push((rail, rail.refusal().unwrap_or("unavailable").to_string()));
            continue;
        }
        if chosen.is_some() {
            // Already settled on one; the rest are still recorded so the explanation is complete.
            considered.push((
                rail,
                "a rail was already chosen above it in order".to_string(),
            ));
            continue;
        }
        match rail {
            SettlementRail::LocalLedger => {
                if request.payee_accepts_local {
                    chosen = Some(rail);
                } else {
                    considered.push((
                        rail,
                        "the payee does not accept this node's own ledger unit".to_string(),
                    ));
                }
            }
            SettlementRail::EvmContracts => {
                if request.tolerates_network {
                    chosen = Some(rail);
                } else {
                    considered.push((
                        rail,
                        "the payer will not wait for a network, and a contract settlement needs \
                         one"
                        .to_string(),
                    ));
                }
            }
            other => considered.push((
                other,
                "available but not reachable from a ledger-only request".to_string(),
            )),
        }
    }
    Route { chosen, considered }
}

/// The settlement system plugin.
pub struct SettlementPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl SettlementPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.settlement";

    /// The capabilities it declares.
    ///
    /// The basic set and nothing above it, and that is the point of this release: **a body that
    /// describes settlement rails has no authority to move anything.** When a later release wires a
    /// rail, it declares the capability that rail needs, and the diff is the record of what changed.
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

impl SystemPlugin for SettlementPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        let available = SettlementRail::ALL
            .iter()
            .filter(|r| r.is_available())
            .count();
        ctx.log(
            LogLevel::Info,
            &format!(
                "settlement vocabulary ready: {} of {} rails are available, and every other one \
                 refuses by name",
                available,
                SettlementRail::ALL.len()
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // Every operation here is a read: this body describes rails and chooses among them, and
        // choosing is not moving. It holds no capability that could move value, which is what makes
        // that a fact rather than a claim.
        self.grant
            .require_operation(declared, Capability::LifecycleRead)?;

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "holds_no_value_authority": true,
                    "why": "this body describes rails and chooses among them; moving value needs a \
                            capability it does not hold, and when a later release wires a rail the \
                            diff will be the record of what changed",
                }),
            )),
            "rails" => {
                let rails: Vec<Value> = SettlementRail::ALL
                    .into_iter()
                    .map(|rail| {
                        let support = rail.support();
                        json!({
                            "rail": rail.label(),
                            "local": rail.is_local(),
                            "available": rail.is_available(),
                            "via": match support {
                                RailSupport::Available { via } => Some(via),
                                RailSupport::Refused { .. } => None,
                            },
                            "refused_because": rail.refusal(),
                        })
                    })
                    .collect();
                let available = rails
                    .iter()
                    .filter(|r| r["available"] == json!(true))
                    .count();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "total": rails.len(),
                        "available": available,
                        "refused": rails.len() - available,
                        "rails": rails,
                        "two_answers_only": "a rail is Available with how, or Refused with why; a \
                                             third answer would be one a caller could not act on",
                    }),
                ))
            }
            "route" => {
                let amount_minor = i64::try_from(
                    payload::optional_u64(&msg.payload, "amount_minor")?.unwrap_or(0),
                )
                .unwrap_or(i64::MAX);
                let tolerates_network = msg
                    .payload
                    .get("tolerates_network")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let payee_accepts_local = msg
                    .payload
                    .get("payee_accepts_local")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true);
                let request = RouteRequest {
                    amount_minor,
                    tolerates_network,
                    payee_accepts_local,
                };
                let decision = route(&request);
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "chosen": decision.chosen.map(|r| r.label()),
                        "explain": decision.explain(),
                        "considered": decision.considered.iter().map(|(rail, why)| json!({
                            "rail": rail.label(),
                            "why_not": why,
                        })).collect::<Vec<_>>(),
                        "deterministic": "pure, and the rails are iterated in their declared order, \
                                          so two callers with the same request get the same route",
                    }),
                ))
            }
            "nouns" => {
                // E-02's first criterion: the zero-hit nouns are named in the plugin's own answer.
                //
                // The COUNT is deliberately not carried here. My first version hard-coded "3" for all
                // ten, and a scan showed the real figures differ wildly -- USDC appears many times in
                // `crates/` and Paymaster a handful -- because a substring count depends entirely on
                // which directories are searched and which matching rule is used. Ten invented numbers
                // would have been the invented-field defect for the fifth time, in the one release
                // whose job is auditing numbers.
                //
                // So the answer names the nouns, names the rail, and points at the document that
                // carries the re-run WITH ITS METHOD. A count without a method is not a finding.
                let nouns: Vec<Value> = SETTLEMENT_NOUNS
                    .iter()
                    .map(|(noun, rail)| {
                        json!({
                            "noun": noun,
                            "rail": rail.label(),
                            "code_hits_when_the_plan_was_written": 0,
                            "available": rail.is_available(),
                            "refused_because": rail.refusal(),
                        })
                    })
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "nouns": nouns,
                        "existing_contracts": EXISTING_CONTRACTS,
                        "why_no_count_here": "a hit count depends on which directories are searched \
                                              and which matching rule is used, so a number without \
                                              a method is not a finding. The re-run and its method \
                                              are in docs/SETTLEMENT-NOUN-AUDIT.md, and this answer \
                                              names the nouns rather than quoting a figure.",
                        "the_plan_is_no_longer_right": "the plan records all ten as zero hits; \
                                                        v3.8.0's REFUSED table put every one of them \
                                                        into the code, so zero is not what a search \
                                                        finds now -- and the difference between \
                                                        absent and present-only-in-a-refusal is the \
                                                        difference between two sentences",
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

/// The ten nouns the plan recorded as having zero hits, with the rail each belongs to.
///
/// **No counts here, deliberately.** The plan's zero was true when it was written and is not true
/// now, and a count depends on the search method — so the figure lives in
/// `docs/SETTLEMENT-NOUN-AUDIT.md` with the method that produced it, and this constant carries only
/// what is stable: the noun and the rail it would need. My first version hard-coded `3` for all ten;
/// a scan showed they differ, which is the invented-number defect arriving in an audit.
pub const SETTLEMENT_NOUNS: [(&str, SettlementRail); 10] = [
    ("ERC-8004", SettlementRail::AgentIdentityStandard),
    ("x402", SettlementRail::HttpPayment),
    ("L402", SettlementRail::LightningAuth),
    ("Lightning", SettlementRail::Lightning),
    ("Taproot", SettlementRail::Taproot),
    ("RGB", SettlementRail::Rgb),
    ("HTLC", SettlementRail::Htlc),
    ("USDC", SettlementRail::Stablecoin),
    ("ERC-4337", SettlementRail::AccountAbstraction),
    ("Paymaster", SettlementRail::AccountAbstraction),
];

/// The on-chain surface this repository actually has.
pub const EXISTING_CONTRACTS: [&str; 4] = [
    "contracts/src/GovernanceToken.sol",
    "contracts/src/Settlement.sol",
    "contracts/src/ReputationRegistry.sol",
    "contracts/src/AgentCardAnchor.sol",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rail_answers_and_the_two_answers_are_distinguishable() {
        // E-01's first criterion, and the whole of this release: a caller that asks "can you settle
        // this?" gets an answer it can act on.
        assert_eq!(SettlementRail::ALL.len(), 13);
        let mut labels: Vec<&str> = SettlementRail::ALL.iter().map(|r| r.label()).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count, "two rails share a label");

        for rail in SettlementRail::ALL {
            match rail.support() {
                RailSupport::Available { via } => {
                    assert!(!via.trim().is_empty(), "{rail:?} is available with no how");
                    assert!(rail.is_available());
                    assert!(rail.refusal().is_none());
                }
                RailSupport::Refused { reason } => {
                    assert!(
                        reason.len() > 30,
                        "{rail:?} refuses with a reason too short to act on: {reason}"
                    );
                    assert!(!rail.is_available());
                    assert_eq!(rail.refusal(), Some(reason));
                }
            }
        }
    }

    #[test]
    fn exactly_two_rails_are_local_and_the_rest_need_a_network() {
        // The distinction the router turns on. A rail that needed a network but reported itself
        // local would be one this workspace could not exercise end to end, reported as if it could.
        let local: Vec<&str> = SettlementRail::ALL
            .iter()
            .filter(|r| r.is_local())
            .map(|r| r.label())
            .collect();
        assert_eq!(local, vec!["local-ledger", "evm-contracts"]);
    }

    #[test]
    fn the_only_available_rails_are_the_ones_this_repository_actually_has() {
        // The available set is asserted as a WHOLE rather than per rail, so a future release that
        // flipped one to `Available` without doing the work would fail here rather than pass.
        let available: Vec<&str> = SettlementRail::ALL
            .iter()
            .filter(|r| r.is_available())
            .map(|r| r.label())
            .collect();
        assert_eq!(
            available,
            vec!["local-ledger", "evm-contracts"],
            "every other rail names something this repository does not have"
        );
    }

    #[test]
    fn the_ten_nouns_of_the_plan_are_all_here_and_all_refused() {
        // E-02's first criterion. And every one of them must map to a rail that is NOT available,
        // so the table and the rails cannot disagree.
        assert_eq!(SETTLEMENT_NOUNS.len(), 10);
        let mut names: Vec<&str> = SETTLEMENT_NOUNS.iter().map(|(n, _)| *n).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "a duplicate noun is one nobody checked");

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
            let (_, rail) = SETTLEMENT_NOUNS
                .iter()
                .find(|(n, _)| *n == expected)
                .unwrap_or_else(|| panic!("`{expected}` is in the plan's list"));
            assert!(
                !rail.is_available(),
                "`{expected}` maps to an available rail, which would mean this repository has it"
            );
        }
    }

    #[test]
    fn the_table_carries_no_count_because_a_count_without_a_method_is_not_a_finding() {
        // E-02's real content, and the correction this release made to itself.
        //
        // My first version hard-coded `3` for all ten nouns. A scan showed the figures differ -- the
        // exact value depends on which directories are searched and which matching rule is used --
        // so ten invented numbers were about to ship in the one release whose job is auditing
        // numbers. The table now carries the noun and the rail only, and the count lives in
        // `docs/SETTLEMENT-NOUN-AUDIT.md` WITH ITS METHOD.
        //
        // What can be asserted from here is the part that is stable: every noun maps to a rail that
        // is not available, and the x402 refusal names the sandbox rule that refuses it twice over.
        assert!(
            SettlementRail::HttpPayment
                .refusal()
                .unwrap_or("")
                .contains("sandbox"),
            "the x402 refusal must name the sandbox's outbound rule: the node has no such rail AND \
             an agent in a sandbox could not use one"
        );
        assert!(
            SettlementRail::LocalLedger.is_available(),
            "and the contrast: the one rail this repository does have"
        );
    }

    #[test]
    fn the_four_contracts_are_listed_by_path() {
        // E-02's second criterion. Paths rather than names, because a name is what the plan uses and
        // a path is what a reader can open.
        assert_eq!(EXISTING_CONTRACTS.len(), 4);
        for path in EXISTING_CONTRACTS {
            assert!(
                path.starts_with("contracts/src/") && path.ends_with(".sol"),
                "a contract must be given as a path a reader can open: {path}"
            );
        }
        assert!(EXISTING_CONTRACTS.contains(&"contracts/src/Settlement.sol"));
    }

    #[test]
    fn a_local_rail_is_chosen_when_the_payee_accepts_it() {
        let decision = route(&RouteRequest {
            amount_minor: 1_000,
            tolerates_network: true,
            payee_accepts_local: true,
        });
        assert_eq!(decision.chosen, Some(SettlementRail::LocalLedger));
        // And the explanation names every rail that was not chosen.
        let lines = decision.explain();
        assert!(
            lines.iter().any(|l| l.starts_with("chosen: local-ledger")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("lightning: not chosen because")),
            "{lines:?}"
        );
        assert_eq!(
            decision.considered.len(),
            SettlementRail::ALL.len() - 1,
            "every other rail must appear in the explanation"
        );
    }

    #[test]
    fn an_unavailable_rail_is_never_chosen_however_cheap_it_sounds() {
        // E-01's first criterion reaching the router: an unavailable rail is not a cheaper option,
        // it is an option that does not exist.
        let decision = route(&RouteRequest {
            amount_minor: 1,
            tolerates_network: false,
            payee_accepts_local: false,
        });
        assert_eq!(
            decision.chosen, None,
            "nothing local is acceptable and the payer will not wait"
        );
        let lines = decision.explain();
        assert!(
            lines.last().expect("a last line").contains("nothing"),
            "{lines:?}"
        );
        // And the refusal reasons are the rails' own, not a generic one.
        let lightning = decision
            .considered
            .iter()
            .find(|(r, _)| *r == SettlementRail::Lightning)
            .expect("lightning is considered");
        assert!(
            lightning.1.contains("Lightning node"),
            "the rail's own reason: {}",
            lightning.1
        );
    }

    #[test]
    fn a_payer_who_will_not_wait_is_told_the_truth() {
        // A payee that does not accept the ledger's unit, and a payer who will not wait for a
        // network: the answer is that nothing is chosen, rather than a rail they said they would not
        // wait for.
        let decision = route(&RouteRequest {
            amount_minor: 10_000,
            tolerates_network: false,
            payee_accepts_local: false,
        });
        assert_eq!(decision.chosen, None);

        // The same payee, a payer who WILL wait: the contracts are chosen, and the reason the ledger
        // was not is recorded.
        let patient = route(&RouteRequest {
            amount_minor: 10_000,
            tolerates_network: true,
            payee_accepts_local: false,
        });
        assert_eq!(patient.chosen, Some(SettlementRail::EvmContracts));
        assert!(
            patient.considered.iter().any(
                |(r, why)| *r == SettlementRail::LocalLedger && why.contains("does not accept")
            ),
            "{:?}",
            patient.considered
        );
    }

    #[test]
    fn the_route_is_deterministic() {
        let request = RouteRequest {
            amount_minor: 500,
            tolerates_network: true,
            payee_accepts_local: false,
        };
        let first = route(&request);
        for _ in 0..8 {
            assert_eq!(route(&request), first, "the route must be pure");
        }
        assert_eq!(route(&request).explain(), first.explain());
    }

    #[test]
    fn it_holds_no_capability_that_could_move_value() {
        // The claim the plugin's own answer makes, asserted where the capabilities are.
        assert_eq!(
            SettlementPlugin::CAPABILITIES.len(),
            Capability::BASIC.len()
        );
        for cap in SettlementPlugin::CAPABILITIES {
            assert!(
                !cap.is_kernel(),
                "describing rails is not authority over them"
            );
        }
        assert!(!SettlementPlugin::CAPABILITIES.contains(&Capability::ChainEvmWrite));
        assert!(SettlementPlugin::ID.starts_with("com.twinsearth.sys."));
        SettlementPlugin::new().expect("a valid id");
    }
}
