//! The capability model: what a plugin may do, decided by its tier.
//!
//! # Why this is a token and not a table lookup at the call site
//!
//! A permission check that every call site performs is a check every call site can
//! forget. Here the kernel issues a [`CapabilityToken`] **once**, at load time,
//! bound to the plugin id *and* to the manifest digest that was verified. The bus
//! consults the token, not the manifest — so a plugin cannot present a different
//! manifest later, and a call site has nothing to remember.
//!
//! # The three-way decision
//!
//! [`Capability::decision`] answers for a `(capability, tier)` pair with one of
//! three outcomes, and the middle one is the honest one:
//!
//! * [`Grant::Always`] — the tier holds it by construction;
//! * [`Grant::RequiresApproval`] — the tier *may* hold it, but only after a named
//!   approval step (the request is not silently downgraded to a refusal, and it is
//!   certainly not silently granted);
//! * [`Grant::Refused`] — the tier may never hold it, whatever anyone approves.
//!
//! The matrix is total: every capability is decided for every tier, and a test
//! walks the full cross product so a new variant cannot be added without a decision.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{PluginError, Result};
use crate::tier::Tier;

/// Who approved a capability the tier does not hold unconditionally.
///
/// Recorded in the token so an audit can say *who* let a plugin do this, not merely
/// that it was allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// The host grants it automatically: the tier is trusted by construction.
    Host,
    /// The vendor team reviewed it.
    VendorTeam,
    /// The certification committee reviewed it.
    CertificationCommittee,
    /// The operator accepted the risk explicitly, on this machine.
    Operator,
}

impl Approval {
    /// Every approval authority.
    pub const ALL: [Approval; 4] = [
        Approval::Host,
        Approval::VendorTeam,
        Approval::CertificationCommittee,
        Approval::Operator,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Approval::Host => "host",
            Approval::VendorTeam => "vendor-team",
            Approval::CertificationCommittee => "certification-committee",
            Approval::Operator => "operator",
        }
    }
}

/// What a `(capability, tier)` pair resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// Held by construction.
    Always,
    /// Held only after the named approval.
    RequiresApproval(Approval),
    /// Never held by this tier.
    Refused {
        /// Why, in one clause, for the refusal message and the audit log.
        reason: &'static str,
    },
}

/// A capability a plugin can hold.
///
/// Exhaustive, not `#[non_exhaustive]`: adding a variant must break
/// [`Capability::ALL`] and every match on it, so the matrix cannot gain a row that
/// no test covers. That is the same discipline [`Tier`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    // ---- basic: every plugin has these --------------------------------
    /// Read its own lifecycle state.
    LifecycleRead,
    /// Send a message on the plugin bus.
    MessageSend,
    /// Read and write its own sandbox directory.
    StorageOwn,

    // ---- network ------------------------------------------------------
    /// Read from the DHT.
    DhtRead,
    /// Write to the DHT.
    DhtWrite,
    /// Publish on GossipSub.
    GossipPublish,
    /// Subscribe on GossipSub.
    GossipSubscribe,

    // ---- chain --------------------------------------------------------
    /// Read chain state.
    ChainEvmRead,
    /// Submit a chain transaction.
    ChainEvmWrite,

    // ---- agent and economy --------------------------------------------
    /// Create an AgentCard.
    AgentCardCreate,
    /// Update an AgentCard.
    AgentCardUpdate,
    /// Settle an economy movement.
    EconomySettle,
    /// Participate in swarm consensus.
    SwarmConsensus,
    /// Open an end-to-end encrypted channel to another plugin, which the host cannot
    /// read. Refused outright to the third-party tier: a channel the host cannot audit
    /// is a channel a plugin may not open on its own authority.
    CryptoChannel,

    // ---- kernel -------------------------------------------------------
    /// Manage the plugin lifecycle of others.
    KernelPluginManage,
    /// Write security policy.
    KernelPolicyWrite,
    /// Configure isolation.
    KernelIsolationConfigure,

    // ---- sandbox infrastructure (AUSec, v3.5.0) ----------------------
    /// Create a sandbox.
    ///
    /// Split from [`Capability::SandboxConfigure`] deliberately. Together they are a
    /// privilege-escalation path: whatever can create a sandbox *and* choose its
    /// isolation parameters can create a weakly-isolated one and run code in it. Held
    /// apart, creating is routine and configuring is the step worth a second look.
    SandboxCreate,
    /// Choose a sandbox's isolation parameters.
    ///
    /// The narrower half of the pair above, and the one a caller should have to justify.
    /// A plugin that can create sandboxes but not configure them cannot weaken the
    /// isolation of the ones it makes.
    SandboxConfigure,
    // ---- snapshots (Agent Council, v3.6.0) ---------------------------
    /// Take a snapshot of a sandbox's state.
    ///
    /// A third member of the sandbox family rather than a widening of
    /// [`Capability::SandboxCreate`], because the three failures are different: creating a
    /// sandbox spends resources, configuring one can weaken its isolation, and snapshotting
    /// one **reads its memory**. A plugin that only needs to start sandboxes should not be
    /// able to copy what is inside them.
    SandboxSnapshot,
    /// Restore a sandbox from a snapshot.
    ///
    /// Split from [`Capability::SandboxSnapshot`] for the mirror-image reason: reading a
    /// snapshot is a disclosure, and writing one back is a **substitution** — a restored
    /// sandbox runs whatever the snapshot holds, so a plugin that can restore from a
    /// snapshot it did not take can put arbitrary prior state in front of a caller that
    /// asked for a fresh sandbox.
    SandboxRestore,
    // Neither of the two above is in `is_kernel()`, and the distinction is worth stating
    // because the opposite reading is available. Kernel authority is about **what the kernel
    // will enforce**: `SandboxCreate` and `SandboxConfigure` decide a sandbox's isolation,
    // which is why they are reserved to the system tier and no approval can grant them.
    // Snapshot and restore operate **inside a boundary that has already been decided** -- they
    // move a sandbox's state around, they do not change what that sandbox is confined by.
    //
    // Marking them kernel would therefore be wrong twice over: it would overstate what they
    // can do, and it would make them unholdable by the official-tier plugin that exists to
    // use them (`com.twinsearth.official.agent-council`), because `decision()` refuses every
    // kernel capability outside the system tier. They are instead granted at Official with
    // `Approval::VendorTeam`, which is the scrutiny a state-copying capability deserves.
    // A test asserts this, so a later reader cannot quietly move them.
}

impl Capability {
    /// Every capability.
    ///
    /// Exhaustive on purpose; see the type's documentation.
    pub const ALL: [Capability; 21] = [
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::DhtRead,
        Capability::DhtWrite,
        Capability::GossipPublish,
        Capability::GossipSubscribe,
        Capability::ChainEvmRead,
        Capability::ChainEvmWrite,
        Capability::AgentCardCreate,
        Capability::AgentCardUpdate,
        Capability::EconomySettle,
        Capability::SwarmConsensus,
        Capability::CryptoChannel,
        Capability::KernelPluginManage,
        Capability::KernelPolicyWrite,
        Capability::KernelIsolationConfigure,
        Capability::SandboxCreate,
        Capability::SandboxConfigure,
        Capability::SandboxSnapshot,
        Capability::SandboxRestore,
    ];

    /// The three capabilities every plugin holds.
    pub const BASIC: [Capability; 3] = [
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
    ];

    /// The wire name, as it appears in a manifest and in the audit log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::LifecycleRead => "plugin:lifecycle:read",
            Capability::MessageSend => "plugin:message:send",
            Capability::StorageOwn => "plugin:storage:own",
            Capability::DhtRead => "net:dht:read",
            Capability::DhtWrite => "net:dht:write",
            Capability::GossipPublish => "net:gossip:publish",
            Capability::GossipSubscribe => "net:gossip:subscribe",
            Capability::ChainEvmRead => "chain:evm:read",
            Capability::ChainEvmWrite => "chain:evm:write",
            Capability::AgentCardCreate => "agent:card:create",
            Capability::AgentCardUpdate => "agent:card:update",
            Capability::EconomySettle => "economy:settle",
            Capability::SwarmConsensus => "swarm:consensus",
            Capability::CryptoChannel => "crypto:channel",
            Capability::KernelPluginManage => "kernel:plugin:manage",
            Capability::KernelPolicyWrite => "kernel:policy:write",
            Capability::KernelIsolationConfigure => "kernel:isolation:configure",
            Capability::SandboxCreate => "sandbox:create",
            Capability::SandboxConfigure => "sandbox:configure",
            Capability::SandboxSnapshot => "sandbox:snapshot",
            Capability::SandboxRestore => "sandbox:restore",
        }
    }

    /// Parse a wire name.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] naming the unknown value. An unknown capability
    /// is refused rather than ignored: silently dropping it would grant a plugin
    /// *fewer* rights than it asked for, which reads as a bug rather than a policy,
    /// and would make a typo look like a successful load.
    pub fn parse(name: &str) -> Result<Self> {
        Capability::ALL
            .into_iter()
            .find(|c| c.as_str() == name)
            .ok_or_else(|| {
                PluginError::Capability(format!(
                    "`{name}` is not a known capability; the known set is {}",
                    Capability::ALL
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }

    /// Whether this is one of the basic capabilities.
    #[must_use]
    pub fn is_basic(self) -> bool {
        Capability::BASIC.contains(&self)
    }

    /// Whether holding this capability implies authority over the kernel itself.
    ///
    /// The two sandbox capabilities are kernel-class even though their wire names begin
    /// with `sandbox:` rather than `kernel:`. What decides it is who may hold them: a
    /// capability that chooses how strongly another plugin is isolated is authority over
    /// the isolation guarantee itself, and granting it to a non-system tier would let a
    /// downloadable plugin weaken the boundary it runs inside.
    #[must_use]
    pub fn is_kernel(self) -> bool {
        matches!(
            self,
            Capability::KernelPluginManage
                | Capability::KernelPolicyWrite
                | Capability::KernelIsolationConfigure
                | Capability::SandboxCreate
                | Capability::SandboxConfigure
        )
    }

    /// The decision for this capability at `tier`.
    ///
    /// Total over `Capability::ALL × Tier::ALL`; see `the_matrix_is_total` in the
    /// tests below.
    #[must_use]
    pub fn decision(self, tier: Tier) -> Grant {
        if tier == Tier::Blacklisted {
            return Grant::Refused {
                reason: "a quarantined plugin holds nothing, including the basic set",
            };
        }
        if self.is_basic() {
            // The basic set is what makes a plugin a plugin. It is granted to every
            // loadable tier, including third-party code.
            return Grant::Always;
        }
        if self.is_kernel() {
            // Kernel authority is not a matter of approval: no approval authority
            // exists that could grant it to a non-system plugin, which is why this
            // branch ignores the tier rather than consulting an approval table.
            return if tier == Tier::System {
                Grant::Always
            } else {
                Grant::Refused {
                    reason: "kernel authority is reserved to the system tier",
                }
            };
        }
        match tier {
            Tier::System => Grant::Always,
            Tier::Official => Grant::RequiresApproval(Approval::VendorTeam),
            Tier::Certified => Grant::RequiresApproval(Approval::CertificationCommittee),
            // Third-party plugins have no counter-signature and therefore no
            // authority to appeal to. Network, chain, economy and consensus access
            // are refused outright rather than left to an operator to enable: an
            // operator toggling them on would be trusting code nobody audited, and
            // the honest way to run such code is at a tier that was audited.
            Tier::ThirdParty => Grant::Refused {
                reason: "the third-party tier holds the basic set only",
            },
            Tier::Blacklisted => Grant::Refused {
                reason: "a quarantined plugin holds nothing",
            },
        }
    }

    /// Resolve a requested set for `tier`, or refuse the whole request.
    ///
    /// All-or-nothing on purpose: granting a subset would load a plugin that cannot
    /// do its job and fails later, in a way that is much harder to attribute.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] naming the first capability the tier may not hold,
    /// or the approval it still needs.
    pub fn resolve(requested: &[Capability], tier: Tier) -> Result<Vec<(Capability, Approval)>> {
        let mut out = Vec::new();
        for cap in requested {
            match cap.decision(tier) {
                Grant::Always => out.push((*cap, Approval::Host)),
                Grant::RequiresApproval(authority) => {
                    return Err(PluginError::Capability(format!(
                        "`{}` needs approval from the {} at tier {tier}",
                        cap.as_str(),
                        authority.label()
                    )));
                }
                Grant::Refused { reason } => {
                    return Err(PluginError::Capability(format!(
                        "`{}` is refused at tier {tier}: {reason}",
                        cap.as_str()
                    )));
                }
            }
        }
        Ok(out)
    }

    /// Resolve a requested set for `tier`, honouring approvals the caller supplies.
    ///
    /// # Why this function has to exist
    ///
    /// [`Capability::resolve`] refuses every [`Grant::RequiresApproval`], which means
    /// that without this one the approval branch of the matrix is **unreachable** and an
    /// Official or Certified plugin can hold nothing but the basic set — a tier model
    /// the architecture document describes and the code could not express. That gap was
    /// reported by the agent that built the plugin fixtures, when its realistic
    /// `official.market` manifest could only ever be a *refusal* fixture. A rule that
    /// cannot be satisfied is a rule that is not implemented.
    ///
    /// The three-way decision becomes concrete here:
    ///
    /// * [`Grant::Always`] — granted; the supplied approvals are not consulted;
    /// * [`Grant::RequiresApproval`] — granted **only** by exactly the named authority.
    ///   A different authority does not substitute: an operator cannot stand in for the
    ///   certification committee, because the authority is named precisely so that the
    ///   tier's review has to have actually happened;
    /// * [`Grant::Refused`] — never granted, whatever is supplied. This branch does not
    ///   read `approvals` at all, which is what makes kernel authority unapprovable
    ///   rather than merely unapproved.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] naming the capability, the authority it needs, and
    /// what was offered instead.
    pub fn resolve_with_approvals(
        requested: &[Capability],
        tier: Tier,
        approvals: &[(Capability, Approval)],
    ) -> Result<Vec<(Capability, Approval)>> {
        let mut out = Vec::new();
        for cap in requested {
            match cap.decision(tier) {
                Grant::Always => out.push((*cap, Approval::Host)),
                Grant::RequiresApproval(required) => {
                    if approvals.iter().any(|(c, a)| c == cap && *a == required) {
                        out.push((*cap, required));
                    } else {
                        let offered: Vec<&str> = approvals
                            .iter()
                            .filter(|(c, _)| c == cap)
                            .map(|(_, a)| a.label())
                            .collect();
                        return Err(PluginError::Capability(format!(
                            "`{}` needs approval from the {} at tier {tier}; {}",
                            cap.as_str(),
                            required.label(),
                            if offered.is_empty() {
                                "none was supplied".to_string()
                            } else {
                                format!(
                                    "only {} was supplied, which is a different authority",
                                    offered.join(", ")
                                )
                            }
                        )));
                    }
                }
                Grant::Refused { reason } => {
                    return Err(PluginError::Capability(format!(
                        "`{}` is refused at tier {tier}: {reason}; no approval can grant it",
                        cap.as_str()
                    )));
                }
            }
        }
        Ok(out)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The authority a token was issued under, and the digest it is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    plugin: String,
    granted: BTreeSet<Capability>,
    approvals: Vec<(Capability, Approval)>,
    /// The digest of the manifest this token was issued against. A plugin that
    /// presents a different manifest has a different token; the two cannot be
    /// combined.
    manifest_digest: String,
    issued_at: u64,
}

impl CapabilityToken {
    /// Issue a token for a verified manifest.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the requested set cannot be resolved for the
    /// tier, or when the digest is empty (an empty digest would bind the token to
    /// nothing).
    pub fn issue(
        plugin: &str,
        tier: Tier,
        requested: &[Capability],
        manifest_digest: &str,
        issued_at: u64,
    ) -> Result<Self> {
        if manifest_digest.trim().is_empty() {
            return Err(PluginError::Capability(
                "a capability token must be bound to a manifest digest".into(),
            ));
        }
        let approvals = Capability::resolve(requested, tier)?;
        Ok(Self {
            plugin: plugin.to_string(),
            granted: approvals.iter().map(|(c, _)| *c).collect(),
            approvals,
            manifest_digest: manifest_digest.to_string(),
            issued_at,
        })
    }

    /// Issue a token for a verified manifest, with approvals that were actually granted.
    ///
    /// This is the door that makes the approval half of the matrix reachable; see
    /// [`Capability::resolve_with_approvals`] for what an approval can and cannot do.
    /// `approvals` is the list of `(capability, authority)` pairs some authority has
    /// granted for this plugin — it is **not** a list of capabilities the caller wants,
    /// because a caller that could name its own authority would not need one.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the digest is empty, when a capability is
    /// refused at this tier (no approval can grant it), or when a capability needs an
    /// authority that is not in `approvals`.
    pub fn issue_with_approvals(
        plugin: &str,
        tier: Tier,
        requested: &[Capability],
        approvals: &[(Capability, Approval)],
        manifest_digest: &str,
        issued_at: u64,
    ) -> Result<Self> {
        if manifest_digest.trim().is_empty() {
            return Err(PluginError::Capability(
                "a capability token must be bound to a manifest digest".into(),
            ));
        }
        let resolved = Capability::resolve_with_approvals(requested, tier, approvals)?;
        Ok(Self {
            plugin: plugin.to_string(),
            granted: resolved.iter().map(|(c, _)| *c).collect(),
            approvals: resolved,
            manifest_digest: manifest_digest.to_string(),
            issued_at,
        })
    }

    /// The plugin this token was issued to.
    #[must_use]
    pub fn plugin(&self) -> &str {
        &self.plugin
    }

    /// The digest the token is bound to.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// When it was issued.
    #[must_use]
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Whether this token allows `cap`.
    #[must_use]
    pub fn allows(&self, cap: Capability) -> bool {
        self.granted.contains(&cap)
    }

    /// The granted set.
    #[must_use]
    pub fn granted(&self) -> &BTreeSet<Capability> {
        &self.granted
    }

    /// Who approved each granted capability.
    #[must_use]
    pub fn approvals(&self) -> &[(Capability, Approval)] {
        &self.approvals
    }

    /// Refuse unless the token allows `cap`, naming the plugin and the token it holds.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] with a message that names the plugin, the refused
    /// capability and the digest the token is bound to — enough to answer "why was
    /// this call refused?" from a log line alone.
    pub fn require(&self, cap: Capability) -> Result<()> {
        if self.allows(cap) {
            return Ok(());
        }
        Err(PluginError::Capability(format!(
            "plugin `{}` (manifest {}) does not hold `{}`; it holds {}",
            self.plugin,
            &self.manifest_digest[..self.manifest_digest.len().min(12)],
            cap.as_str(),
            if self.granted.is_empty() {
                "nothing".to_string()
            } else {
                self.granted
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_matrix_is_total_over_every_capability_and_tier() {
        // Every pair resolves to some decision, and the array is exhaustive, so a new
        // capability or tier cannot appear without a decision here.
        for cap in Capability::ALL {
            for tier in Tier::ALL {
                let decision = cap.decision(tier);
                if tier == Tier::Blacklisted {
                    assert!(
                        matches!(decision, Grant::Refused { .. }),
                        "{cap} must be refused for a quarantined plugin"
                    );
                }
            }
        }
        // The count is a tripwire, not the assertion: the loops above are what prove
        // totality, and this line exists so that growing the capability set is a
        // decision someone makes on purpose rather than a number that drifts.
        //
        // 21 as of B-02, which added `sandbox:snapshot` and `sandbox:restore`. Neither is
        // kernel-class -- see `the_snapshot_capabilities_are_not_kernel_authority` below --
        // so the third-party refusal test covers them by falling through to the approval
        // table rather than by being edited, which is the point of asserting the cross
        // product instead of listing examples.
        assert_eq!(Capability::ALL.len(), 21);
    }

    #[test]
    fn the_snapshot_capabilities_are_not_kernel_authority() {
        // The decision this test pins is argued in the enum's documentation, and it is the kind
        // of decision a later reader could reverse without noticing what it breaks -- so it is
        // asserted rather than left to the comment.
        //
        // `is_kernel()` capabilities are reserved to the system tier and **no approval can
        // grant them elsewhere**. If snapshot and restore were kernel-class, the official-tier
        // plugin that exists to use them could not hold them, and B-02 would be unbuildable.
        // They are not kernel-class because they operate inside a boundary that has already
        // been decided: they move a sandbox's state, they do not change what confines it.
        for cap in [Capability::SandboxSnapshot, Capability::SandboxRestore] {
            assert!(
                !cap.is_kernel(),
                "{} must not be kernel authority: it would then be unholdable by the official \
                 tier that needs it, and it would overstate what a state-copying capability does",
                cap.as_str()
            );
            // And the positive half: the official tier can hold it, with approval.
            assert_eq!(
                cap.decision(Tier::Official),
                Grant::RequiresApproval(Approval::VendorTeam),
                "{} must be grantable at the official tier with vendor approval",
                cap.as_str()
            );
            // The negative half: the third-party tier still cannot have it.
            assert!(
                matches!(cap.decision(Tier::ThirdParty), Grant::Refused { .. }),
                "{} must be refused to third-party plugins",
                cap.as_str()
            );
        }
    }

    #[test]
    fn the_basic_set_reaches_every_loadable_tier() {
        for tier in Tier::LOADABLE {
            for cap in Capability::BASIC {
                assert_eq!(
                    cap.decision(tier),
                    Grant::Always,
                    "{cap} must be held by {tier}"
                );
            }
        }
    }

    #[test]
    fn a_third_party_plugin_can_never_hold_a_sensitive_capability() {
        // This is the security claim the whole tier model rests on. It is asserted
        // over the cross product rather than for a hand-picked example, so a new
        // sensitive capability is covered the moment it is added.
        for cap in Capability::ALL {
            if cap.is_basic() {
                continue;
            }
            assert!(
                matches!(cap.decision(Tier::ThirdParty), Grant::Refused { .. }),
                "a third-party plugin must never be able to hold {cap}"
            );
        }
    }

    #[test]
    fn kernel_authority_has_no_approval_path() {
        for cap in Capability::ALL.into_iter().filter(|c| c.is_kernel()) {
            assert_eq!(cap.decision(Tier::System), Grant::Always);
            for tier in [Tier::Official, Tier::Certified, Tier::ThirdParty] {
                match cap.decision(tier) {
                    Grant::Refused { .. } => {}
                    other => panic!("{cap} at {tier} must be Refused, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn official_and_certified_hold_sensitive_capabilities_only_with_approval() {
        let cap = Capability::EconomySettle;
        assert_eq!(
            cap.decision(Tier::Official),
            Grant::RequiresApproval(Approval::VendorTeam)
        );
        assert_eq!(
            cap.decision(Tier::Certified),
            Grant::RequiresApproval(Approval::CertificationCommittee)
        );
    }

    #[test]
    fn resolving_an_over_reaching_request_is_all_or_nothing() {
        // A third-party plugin asking for a network capability gets nothing, not a
        // subset: a partially-granted plugin fails later and harder to attribute.
        let err = Capability::resolve(
            &[Capability::MessageSend, Capability::DhtRead],
            Tier::ThirdParty,
        )
        .expect_err("must be refused");
        assert!(matches!(err, PluginError::Capability(_)));
        assert!(err.to_string().contains("net:dht:read"), "{err}");
        assert!(err.to_string().contains("3rd"), "{err}");
    }

    #[test]
    fn resolving_a_request_that_needs_approval_says_who_must_approve() {
        let err = Capability::resolve(&[Capability::EconomySettle], Tier::Certified)
            .expect_err("must need approval");
        assert!(err.to_string().contains("certification-committee"), "{err}");
    }

    #[test]
    fn an_unknown_capability_name_is_refused_not_ignored() {
        let err = Capability::parse("net:dht:reed").expect_err("must be refused");
        assert!(err.to_string().contains("net:dht:read"), "{err}");
    }

    #[test]
    fn every_capability_round_trips_through_its_wire_name() {
        for cap in Capability::ALL {
            assert_eq!(Capability::parse(cap.as_str()).expect("parses"), cap);
        }
    }

    #[test]
    fn wire_names_are_unique() {
        let mut names: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate wire name: {names:?}");
    }

    #[test]
    fn a_token_is_bound_to_the_manifest_it_was_issued_for() {
        let token = CapabilityToken::issue(
            "com.twinsearth.official.market",
            Tier::Official,
            &[Capability::MessageSend, Capability::StorageOwn],
            DIGEST,
            1_750_000_000,
        )
        .expect("issuable");
        assert_eq!(token.manifest_digest(), DIGEST);
        assert!(token.allows(Capability::MessageSend));
        assert!(!token.allows(Capability::DhtWrite));
    }

    #[test]
    fn an_unbound_token_cannot_be_issued() {
        assert!(CapabilityToken::issue("io.example.a", Tier::ThirdParty, &[], "  ", 0).is_err());
    }

    #[test]
    fn requiring_an_ungranted_capability_names_the_plugin_and_the_capability() {
        let token = CapabilityToken::issue(
            "io.example.a",
            Tier::ThirdParty,
            &[Capability::MessageSend],
            DIGEST,
            0,
        )
        .expect("issuable");
        let err = token
            .require(Capability::GossipPublish)
            .expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("io.example.a"), "{text}");
        assert!(text.contains("net:gossip:publish"), "{text}");
        assert!(text.contains("0123456789ab"), "{text}");
    }

    #[test]
    fn a_token_cannot_be_conjured_for_a_tier_that_may_not_hold_the_capability() {
        let err = CapabilityToken::issue(
            "io.example.a",
            Tier::ThirdParty,
            &[Capability::EconomySettle],
            DIGEST,
            0,
        )
        .expect_err("must be refused");
        assert!(matches!(err, PluginError::Capability(_)));
    }

    #[test]
    fn the_approval_branch_of_the_matrix_is_reachable() {
        // Before `resolve_with_approvals` existed this was impossible: `resolve` refuses
        // every `RequiresApproval` and `issue` could not carry one, so an Official or
        // Certified plugin could hold nothing but the basic set. The architecture
        // document described a model the code could not express -- a rule that cannot be
        // satisfied is a rule that is not implemented. This test is what keeps the
        // branch reachable.
        let granted = Capability::resolve_with_approvals(
            &[Capability::MessageSend, Capability::EconomySettle],
            Tier::Official,
            &[(Capability::EconomySettle, Approval::VendorTeam)],
        )
        .expect("a vendor-team approval should grant economy:settle at the official tier");
        assert_eq!(granted.len(), 2);
        assert!(granted.contains(&(Capability::MessageSend, Approval::Host)));
        assert!(granted.contains(&(Capability::EconomySettle, Approval::VendorTeam)));
    }

    #[test]
    fn a_certified_plugin_is_granted_by_the_committee_and_not_by_the_vendor_team() {
        let cap = Capability::EconomySettle;
        let committee = Capability::resolve_with_approvals(
            &[cap],
            Tier::Certified,
            &[(cap, Approval::CertificationCommittee)],
        )
        .expect("the committee is the authority for the certified tier");
        assert_eq!(committee, vec![(cap, Approval::CertificationCommittee)]);

        let wrong = Capability::resolve_with_approvals(
            &[cap],
            Tier::Certified,
            &[(cap, Approval::VendorTeam)],
        )
        .expect_err("the vendor team is not the authority for the certified tier");
        assert!(
            wrong.to_string().contains("certification-committee"),
            "{wrong}"
        );
    }

    #[test]
    fn a_different_authority_does_not_substitute() {
        let err = Capability::resolve_with_approvals(
            &[Capability::EconomySettle],
            Tier::Official,
            &[(Capability::EconomySettle, Approval::Operator)],
        )
        .expect_err("an operator cannot stand in for the vendor team");
        let text = err.to_string();
        assert!(text.contains("vendor-team"), "{text}");
        assert!(text.contains("different authority"), "{text}");
    }

    #[test]
    fn no_approval_and_no_authority_grants_a_refused_capability() {
        // Over every authority and every capability the third-party tier refuses: the
        // branch that returns `Refused` must not read the approvals list at all. That is
        // what makes kernel authority unapprovable rather than merely unapproved.
        let mut checked = 0;
        for authority in Approval::ALL {
            for cap in Capability::ALL.into_iter().filter(|c| !c.is_basic()) {
                if !matches!(cap.decision(Tier::ThirdParty), Grant::Refused { .. }) {
                    continue;
                }
                let err = Capability::resolve_with_approvals(
                    &[cap],
                    Tier::ThirdParty,
                    &[(cap, authority)],
                )
                .expect_err("must be refused");
                assert!(
                    err.to_string().contains("no approval can grant it"),
                    "{cap} + {authority:?}: {err}"
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "the cross product must have covered something");

        // And kernel authority specifically, at every tier below system, with every
        // authority in existence.
        for authority in Approval::ALL {
            for tier in [Tier::Official, Tier::Certified, Tier::ThirdParty] {
                for cap in Capability::ALL.into_iter().filter(|c| c.is_kernel()) {
                    assert!(
                        Capability::resolve_with_approvals(&[cap], tier, &[(cap, authority)])
                            .is_err(),
                        "{cap} at {tier} must not be grantable by {authority:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn an_approved_capability_is_recorded_with_the_authority_that_granted_it() {
        let token = CapabilityToken::issue_with_approvals(
            "com.twinsearth.official.market",
            Tier::Official,
            &[Capability::MessageSend, Capability::EconomySettle],
            &[(Capability::EconomySettle, Approval::VendorTeam)],
            DIGEST,
            1_750_000_000,
        )
        .expect("issuable");
        assert!(token.allows(Capability::EconomySettle));
        assert!(token.allows(Capability::MessageSend));
        assert!(token
            .approvals()
            .contains(&(Capability::EconomySettle, Approval::VendorTeam)));
        // The basic capability records the host, not the vendor: an audit has to be able
        // to say who let what through.
        assert!(token
            .approvals()
            .contains(&(Capability::MessageSend, Approval::Host)));
    }

    #[test]
    fn the_approval_door_is_still_closed_without_an_approval() {
        let err = CapabilityToken::issue_with_approvals(
            "com.twinsearth.official.market",
            Tier::Official,
            &[Capability::EconomySettle],
            &[],
            DIGEST,
            0,
        )
        .expect_err("must be refused");
        assert!(err.to_string().contains("none was supplied"), "{err}");
    }

    #[test]
    fn the_approval_door_also_requires_a_bound_digest() {
        assert!(CapabilityToken::issue_with_approvals(
            "io.example.a",
            Tier::Official,
            &[],
            &[],
            "",
            0
        )
        .is_err());
    }
}
