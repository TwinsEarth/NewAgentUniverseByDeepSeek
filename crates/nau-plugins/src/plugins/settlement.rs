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
pub const OPERATIONS: &[&str] = &[
    "capabilities",
    "rails",
    "route",
    "nouns",
    // E-03: the Bitcoin vocabulary, and the platform question.
    "bitcoin",
    // E-07: what a settlement makes public, item by item.
    "privacy",
];

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

/// The Bitcoin capabilities the design names, and which of them exist here.
///
/// # E-03's first criterion, and the correction it needed
///
/// The plan says `Lightning`, `Taproot` and `RGB` have **zero hits** in this repository and that this
/// is why they must not be claimed. **That was true when the plan was written and is not true now**:
/// v3.8.0's `REFUSED` table and v3.9.0's `SETTLEMENT_NOUNS` both name them, so a search finds them.
///
/// **The conclusion survives; the premise does not**, and this is worth stating precisely rather than
/// quoting a stale figure. What the hits are is **refusals** — the right kind of appearance and not
/// support — so "must not claim support" is still exactly right, for the reason that every appearance
/// is inside a refusal or inside an audit of refusals.
///
/// # Why these names are not `Capability` variants
///
/// `Capability` is the list of what a body **may hold**, and `nau-plugin`'s `Capability::as_str` is
/// the wire form of that list. Adding `bitcoin:utxo:read` to it would say a body might hold it, and
/// **no body can**: nothing in this workspace reads a UTXO set or signs a Bitcoin transaction.
///
/// So the names live here, as a vocabulary this plugin can **answer about**, and every one of them
/// refuses. That is the difference between a name a caller can ask about and a capability a plugin
/// could be granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BitcoinCapability {
    /// Read the unspent-output set.
    UtxoRead,
    /// Sign a Bitcoin transaction.
    TxSign,
    /// Run a Bitcoin node.
    ///
    /// The one of the three that is a **platform** question rather than an implementation question,
    /// which is why E-03 splits it out: a node is a process, and the answer depends on where the node
    /// is running.
    NodeRun,
}

impl BitcoinCapability {
    /// Every one, in order.
    pub const ALL: [BitcoinCapability; 3] = [
        BitcoinCapability::UtxoRead,
        BitcoinCapability::TxSign,
        BitcoinCapability::NodeRun,
    ];

    /// The capability's name, spelled as the design spells it.
    ///
    /// The same `chain:evm:read` shape the existing capabilities use, so that a reader meeting both
    /// does not have to work out whether the colons mean the same thing. They do.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            BitcoinCapability::UtxoRead => "bitcoin:utxo:read",
            BitcoinCapability::TxSign => "bitcoin:tx:sign",
            BitcoinCapability::NodeRun => "bitcoin:node:run",
        }
    }

    /// Whether this capability is provided here, and why not when it is not.
    ///
    /// # E-03's second and third criteria
    ///
    /// The second: a declared capability that is not implemented **refuses when called**, and the
    /// refusal names what is missing. The first two names never reach `Available`, on any platform.
    ///
    /// The third: the node-running capability is a **platform** question. It is available on Linux
    /// and refused elsewhere — **refused, not degraded**: E-03's platform column says "Linux (node
    /// running only)", and a node that ran a Bitcoin process on a platform it was not built for would
    /// be one whose behaviour nobody had tested.
    #[must_use]
    pub fn support(self) -> RailSupport {
        match self {
            BitcoinCapability::UtxoRead => RailSupport::Refused {
                reason: "this workspace has no Bitcoin node, no UTXO set and no indexer; nothing \
                         here can answer what outputs exist, so the capability is declared and \
                         refuses on every platform",
            },
            BitcoinCapability::TxSign => RailSupport::Refused {
                reason: "nothing here holds a Bitcoin key or produces a Bitcoin signature, and \
                         E-06's criterion keeps private keys out of sandboxes -- so there is no \
                         signer to hold this capability, on any platform",
            },
            BitcoinCapability::NodeRun => {
                if cfg!(target_os = "linux") {
                    RailSupport::Refused {
                        reason: "the platform allows it, and this build still has no Bitcoin node \
                                 binary or configuration to run: E-03 delivers the vocabulary and \
                                 the refusal, not the node",
                    }
                } else {
                    RailSupport::Refused {
                        reason: "running a Bitcoin node is Linux-only in this build, and this is not \
                                 Linux -- refused rather than degraded, because a node started on a \
                                 platform it was not built for is one whose behaviour nobody tested",
                    }
                }
            }
        }
    }

    /// Whether it is available.
    #[must_use]
    pub fn is_available(self) -> bool {
        matches!(self.support(), RailSupport::Available { .. })
    }

    /// The reason it is not.
    #[must_use]
    pub fn refusal(self) -> &'static str {
        match self.support() {
            RailSupport::Available { .. } => "",
            RailSupport::Refused { reason } => reason,
        }
    }

    /// Whether this capability's answer depends on the platform.
    ///
    /// Exposed so a caller can tell "we have not built it" from "this platform cannot", which are
    /// different answers to the same question and support different responses.
    #[must_use]
    pub fn is_platform_dependent(self) -> bool {
        matches!(self, BitcoinCapability::NodeRun)
    }
}

/// One thing a settlement would put on a public chain.
///
/// # E-07's second criterion, itemised
///
/// "Declare **what will be exposed on-chain** (amount, address, time), listed item by item."
///
/// A prose sentence saying "settlement is public" is one a reader can agree with and cannot act on.
/// This is the same claim as a **list of named items**, each saying **where it comes from** — so a
/// party deciding whether to use this rail can see exactly which of its facts would become visible.
///
/// The items are drawn from `contracts/src/Settlement.sol`'s own events rather than from the design
/// prose, because the events are what actually goes on-chain:
/// `TaskCreated(taskId, requester, budget, ...)`, `TaskSettled(taskId, executor, reward)`,
/// `TaskDisputed(taskId, by, against)`. A list assembled from the design would be a list of what
/// somebody intended to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Exposure {
    /// How much moved. `TaskSettled`'s `reward` and `TaskCreated`'s `budget`.
    Amount,
    /// The paying party's address. `TaskCreated`'s `requester`.
    PayerAddress,
    /// The paid party's address. `TaskSettled`'s indexed `executor`.
    PayeeAddress,
    /// The task's identifier, which links a settlement to everything else said about that task.
    TaskId,
    /// When it happened. Not an event field, and on-chain **by construction**: a block has a
    /// timestamp and an event has a block. This is the item a list assembled from event signatures
    /// alone would miss, and it is the one that makes the other items linkable over time.
    Time,
    /// Who disputed whom. `TaskDisputed`'s indexed `by` and `against`.
    DisputeParties,
    /// The digest of the result, if one is anchored. A digest is not the result, and it is a
    /// commitment to it: the same digest from two parties proves they hold the same bytes.
    DeliverableDigest,
}

impl Exposure {
    /// Every item.
    pub const ALL: [Exposure; 7] = [
        Exposure::Amount,
        Exposure::PayerAddress,
        Exposure::PayeeAddress,
        Exposure::TaskId,
        Exposure::Time,
        Exposure::DisputeParties,
        Exposure::DeliverableDigest,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Exposure::Amount => "amount",
            Exposure::PayerAddress => "payer-address",
            Exposure::PayeeAddress => "payee-address",
            Exposure::TaskId => "task-id",
            Exposure::Time => "time",
            Exposure::DisputeParties => "dispute-parties",
            Exposure::DeliverableDigest => "deliverable-digest",
        }
    }

    /// Where on-chain this comes from.
    #[must_use]
    pub fn source(self) -> &'static str {
        match self {
            Exposure::Amount => "contracts/src/Settlement.sol: TaskSettled's `reward`",
            Exposure::PayerAddress => "contracts/src/Settlement.sol: TaskCreated's `requester`",
            Exposure::PayeeAddress => {
                "contracts/src/Settlement.sol: TaskSettled's indexed `executor`"
            }
            Exposure::TaskId => "contracts/src/Settlement.sol: every event's indexed `taskId`",
            Exposure::Time => {
                "by construction: a block has a timestamp and an event has a block, \
                               so no event signature mentions it and every one carries it"
            }
            Exposure::DisputeParties => {
                "contracts/src/Settlement.sol: TaskDisputed's `by` and \
                                         `against`"
            }
            Exposure::DeliverableDigest => {
                "an anchor, where one is filed: a commitment to the \
                                            result rather than the result"
            }
        }
    }

    /// Whether an observer can link two settlements by this item.
    ///
    /// The distinction that turns a list of disclosures into a privacy statement: an amount alone
    /// says how much; an amount with a time and an address says **who, when and how much**, and a
    /// sequence of them says what that party has been doing. Every item here is linkable except the
    /// digest, which is a commitment and not an identity.
    #[must_use]
    pub fn is_linkable(self) -> bool {
        !matches!(self, Exposure::DeliverableDigest)
    }
}

/// Whether private settlement is provided here.
///
/// # E-07's first and third criteria, and there is no third variant
///
/// The first: `SNARK` appears **once** in this repository's Rust code, and **that one appearance is a
/// negation** — `nau-attest`'s commitment module says "There is no SNARK, no STARK, no PCP". So
/// nothing here may claim zero-knowledge settlement, and this module does not.
///
/// The third: "**not doing private payments** is also an explicit, checkable option." That is the
/// strongest form of the same trick every refusal in this family uses: the answer is `Refused` with a
/// reason, **not a silence** — a caller asks and gets told, rather than inferring it from the absence
/// of a feature.
///
/// Note that the plan's premise **still holds** here, unlike E-02's, E-03's and E-05's: the count is
/// one and it says there is none. That is worth recording, because three consecutive releases needed
/// the same correction and a reader should not assume a fourth does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacySupport {
    /// It exists, and here is what provides it.
    Available {
        /// What provides it.
        via: &'static str,
    },
    /// It does not, and here is what is missing.
    Refused {
        /// Why not.
        reason: &'static str,
    },
}

impl PrivacySupport {
    /// What this node provides.
    #[must_use]
    pub fn current() -> Self {
        PrivacySupport::Refused {
            reason: "nothing here implements zero-knowledge or confidential settlement: `SNARK` \
                     appears once in this repository's Rust and that appearance is a NEGATION \
                     (`nau-attest`: \"There is no SNARK, no STARK, no PCP\"). Every settlement this \
                     node can perform is public in the items listed below, and saying so is the \
                     deliverable -- the alternative would be a document implying confidentiality \
                     that no code provides.",
        }
    }

    /// Whether private settlement is available.
    #[must_use]
    pub fn is_available(self) -> bool {
        matches!(self, PrivacySupport::Available { .. })
    }

    /// The reason it is not, if it is not.
    #[must_use]
    pub fn refusal(self) -> Option<&'static str> {
        match self {
            PrivacySupport::Available { .. } => None,
            PrivacySupport::Refused { reason } => Some(reason),
        }
    }
}

/// The privacy boundary: what a settlement makes visible, and what it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyBoundary {
    /// Whether private settlement exists.
    pub support: PrivacySupport,
    /// What would be public, item by item.
    pub exposes: Vec<Exposure>,
    /// What does **not** go on-chain, item by item.
    ///
    /// The other half of the boundary, and the one a document about privacy usually omits: a list of
    /// exposures alone leaves a reader to assume that everything else is safe, which is a different
    /// claim from the one being made.
    pub withholds: Vec<&'static str>,
}

impl PrivacyBoundary {
    /// The boundary as it stands.
    #[must_use]
    pub fn current() -> Self {
        Self {
            support: PrivacySupport::current(),
            exposes: Exposure::ALL.to_vec(),
            withholds: vec![
                "the task's content: what was asked for is in the task, not in the settlement",
                "the result itself: only a digest is anchored, where one is filed",
                "the parties' DIDs: the chain sees addresses, and the binding from an address to a \
                 DID is a separate act (E-05's anchor, which this node also cannot perform)",
                "anything about a party's other settlements: the chain sees transactions, and \
                 linking them is a reading of the chain rather than a field in it",
            ],
        }
    }

    /// How many items are disclosed and how many withheld.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.exposes.len(), self.withholds.len())
    }

    /// One line per exposure, then one per withholding.
    #[must_use]
    pub fn explain(&self) -> Vec<String> {
        let mut out = vec![format!(
            "private settlement: {}",
            match self.support {
                PrivacySupport::Available { via } => format!("available via {via}"),
                PrivacySupport::Refused { .. } => "NOT available".to_string(),
            }
        )];
        for exposure in &self.exposes {
            out.push(format!(
                "exposed: {} ({}){}",
                exposure.label(),
                exposure.source(),
                if exposure.is_linkable() {
                    " -- linkable"
                } else {
                    " -- a commitment, not an identity"
                }
            ));
        }
        for withheld in &self.withholds {
            out.push(format!("withheld: {withheld}"));
        }
        out
    }
}

/// What a route decision was based on.
///
/// Restored, because inserting `BitcoinCapability` above it separated this struct from its doc
/// comment and clippy's `missing_docs` caught the orphan. The house rule is that every public item
/// carries a doc comment, and this one had one -- it was simply no longer attached to anything.
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
            "bitcoin" => {
                // E-03's second criterion, structurally: every one of these refuses, and the
                // refusal is the SAME function the vocabulary answers with. There is no path here
                // that reports a Bitcoin capability as available, because none of them is.
                let capabilities: Vec<Value> = BitcoinCapability::ALL
                    .into_iter()
                    .map(|cap| {
                        json!({
                            "capability": cap.name(),
                            "available": cap.is_available(),
                            "refused_because": cap.refusal(),
                            "platform_dependent": cap.is_platform_dependent(),
                        })
                    })
                    .collect();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "capabilities": capabilities,
                        "any_available": BitcoinCapability::ALL
                            .iter()
                            .any(|c| c.is_available()),
                        "target_os": std::env::consts::OS,
                        "not_capability_variants": "these names are NOT `Capability` variants: that \
                                                    list is what a body may HOLD, and adding one \
                                                    would say a body might hold it when nothing in \
                                                    this workspace can read a UTXO set or sign a \
                                                    Bitcoin transaction",
                        "the_plan_premise_changed": "E-03 says Lightning/Taproot/RGB have zero hits \
                                                     here; v3.8.0 and v3.9.0 named all three in \
                                                     refusals, so a search finds them. The \
                                                     CONCLUSION survives -- none may be claimed as \
                                                     supported -- and every appearance is inside a \
                                                     refusal or an audit of refusals.",
                    }),
                ))
            }
            // E-07. The boundary, itemised, and the refusal that is the deliverable.
            "privacy" => {
                let boundary = PrivacyBoundary::current();
                let (exposed, withheld) = boundary.counts();
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "private_settlement_available": boundary.support.is_available(),
                        "refused_because": boundary.support.refusal(),
                        "exposes": boundary.exposes.iter().map(|e| json!({
                            "item": e.label(),
                            "source": e.source(),
                            "linkable": e.is_linkable(),
                        })).collect::<Vec<_>>(),
                        "withholds": boundary.withholds,
                        "counts": { "exposed": exposed, "withheld": withheld },
                        "explain": boundary.explain(),
                        "not_an_absence": "not doing private payments is an EXPLICIT answer a caller \
                                           can query, not a silence to be inferred from a missing \
                                           feature",
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

    // ---------------------------------------------------------------- E-03

    #[test]
    fn every_bitcoin_capability_refuses_and_the_names_are_the_designs() {
        // E-03's second criterion, structurally: there is no path that reports one available.
        assert_eq!(BitcoinCapability::ALL.len(), 3);
        for cap in BitcoinCapability::ALL {
            assert!(
                !cap.is_available(),
                "{:?} must not be available: this workspace has no Bitcoin node, no UTXO set and no \
                 signer",
                cap
            );
            assert!(
                cap.refusal().len() > 30,
                "{:?} refuses with a reason too short to act on: {}",
                cap,
                cap.refusal()
            );
            assert!(
                cap.name().starts_with("bitcoin:"),
                "the name must use the same colon shape as chain:evm:read: {}",
                cap.name()
            );
        }
        // The names exactly as the plan spells them.
        assert_eq!(BitcoinCapability::UtxoRead.name(), "bitcoin:utxo:read");
        assert_eq!(BitcoinCapability::TxSign.name(), "bitcoin:tx:sign");
    }

    #[test]
    fn the_node_running_answer_is_the_platforms_and_says_which_question_it_answered() {
        // E-03's third criterion: the platform question, and the answer is checkable on EVERY
        // platform rather than only where it is interesting.
        assert!(BitcoinCapability::NodeRun.is_platform_dependent());
        assert!(!BitcoinCapability::UtxoRead.is_platform_dependent());
        assert!(!BitcoinCapability::TxSign.is_platform_dependent());

        // It refuses everywhere this build runs, and the REASON differs by platform: on Linux it is
        // "the platform allows it and we have not built it", elsewhere it is "this platform cannot".
        // Asserting only that it refuses would lose the distinction that makes the answer useful.
        let reason = BitcoinCapability::NodeRun.refusal();
        if cfg!(target_os = "linux") {
            assert!(
                reason.contains("no Bitcoin node binary"),
                "on Linux the reason is what is missing from the BUILD: {reason}"
            );
        } else {
            assert!(
                reason.contains("not Linux"),
                "elsewhere the reason is the PLATFORM: {reason}"
            );
            assert!(
                reason.contains("refused rather than degraded"),
                "and it must say it is a refusal rather than a downgrade: {reason}"
            );
        }
    }

    #[test]
    fn the_three_nouns_are_not_claimed_as_supported_and_the_premise_is_recorded() {
        // E-03's first criterion. The plan's premise -- that Lightning/Taproot/RGB have zero hits --
        // is no longer true, because v3.8.0 and v3.9.0 named all three in refusals. The CONCLUSION
        // is unchanged and is what this asserts: none of them may be claimed as supported.
        for rail in [
            SettlementRail::Lightning,
            SettlementRail::Taproot,
            SettlementRail::Rgb,
        ] {
            assert!(
                !rail.is_available(),
                "{} must not be available",
                rail.label()
            );
            assert!(
                rail.refusal().unwrap_or("").len() > 30,
                "{} must refuse with a reason, and `SettlementRail::refusal` returns an Option \
                 because an available rail has none -- which is the shape that keeps the two \
                 answers distinguishable",
                rail.label()
            );
        }
        // And the whole available set, so a future release that flipped one fails here.
        let available: Vec<&str> = SettlementRail::ALL
            .iter()
            .filter(|r| r.is_available())
            .map(|r| r.label())
            .collect();
        assert!(
            !available.contains(&"lightning")
                && !available.contains(&"taproot")
                && !available.contains(&"rgb"),
            "got {available:?}"
        );
    }
    // ---------------------------------------------------------------- E-07

    #[test]
    fn zero_knowledge_is_not_claimed_and_the_one_hit_is_a_negation() {
        // E-07's first criterion. `SNARK` appears exactly once in this repository's Rust, and that
        // one appearance is `nau-attest`'s module saying there is none -- so nothing here may claim
        // confidential settlement, and the refusal says where its own evidence comes from.
        let support = PrivacySupport::current();
        assert!(!support.is_available());
        let reason = support.refusal().expect("a reason");
        assert!(reason.contains("SNARK"), "{reason}");
        assert!(
            reason.contains("NEGATION"),
            "and must say that the one hit is a negation rather than a feature: {reason}"
        );
        assert!(
            reason.contains("nau-attest"),
            "and must name where the count comes from: {reason}"
        );
        // The claim is absent from the vocabulary too: no exposure item and no withholding mentions
        // a proof system as something provided.
        let boundary = PrivacyBoundary::current();
        for line in boundary.explain() {
            assert!(
                !line.contains("available via"),
                "no line may report private settlement as available: {line}"
            );
        }
    }

    #[test]
    fn every_exposure_is_named_and_says_where_on_chain_it_comes_from() {
        // E-07's second criterion. A prose sentence saying "settlement is public" is one a reader can
        // agree with and cannot act on; this is the same claim as named items with sources.
        let boundary = PrivacyBoundary::current();
        assert_eq!(boundary.exposes.len(), Exposure::ALL.len());
        for exposure in &boundary.exposes {
            assert!(!exposure.label().is_empty(), "{exposure:?}");
            assert!(
                exposure.source().len() > 20,
                "{exposure:?} must say where it comes from: {}",
                exposure.source()
            );
        }
        // The three the plan names explicitly are present.
        for required in [Exposure::Amount, Exposure::PayerAddress, Exposure::Time] {
            assert!(
                boundary.exposes.contains(&required),
                "{required:?} is named in the plan and must be in the list"
            );
        }
        // TIME is the item a list assembled from event signatures alone would miss, and its source
        // says so -- it is on-chain by construction rather than by a field.
        assert!(
            Exposure::Time.source().contains("by construction"),
            "{}",
            Exposure::Time.source()
        );
        // Six of the seven are linkable and the digest is not, which is what turns a list of
        // disclosures into a privacy statement.
        let linkable = boundary.exposes.iter().filter(|e| e.is_linkable()).count();
        assert_eq!(
            linkable, 6,
            "every item but the digest links settlements to each other"
        );
        assert!(!Exposure::DeliverableDigest.is_linkable());
    }

    #[test]
    fn not_doing_private_payments_is_an_answer_rather_than_an_absence() {
        // E-07's third criterion. A silence is something a caller has to interpret; this is something
        // it can query.
        let boundary = PrivacyBoundary::current();
        assert!(!boundary.support.is_available());
        assert!(
            boundary.support.refusal().is_some(),
            "the refusal must be present, not merely the absence of an Available"
        );
        // And the boundary states the other half too: what is NOT published. A list of exposures
        // alone leaves a reader to assume everything else is safe, which is a different claim.
        assert!(
            !boundary.withholds.is_empty(),
            "a privacy boundary that lists only exposures is half a boundary"
        );
        for withheld in &boundary.withholds {
            assert!(withheld.len() > 30, "too short to act on: {withheld}");
        }
        let (exposed, withheld) = boundary.counts();
        assert_eq!(exposed, 7);
        assert!(withheld >= 4, "got {withheld}");

        // The explanation carries both halves and the headline.
        let lines = boundary.explain();
        assert!(lines[0].contains("NOT available"), "{}", lines[0]);
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("exposed:")).count(),
            exposed
        );
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("withheld:")).count(),
            withheld
        );
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
