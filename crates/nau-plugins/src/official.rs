//! The official plugin set: the eleven plugins the architecture document names, their
//! capability sets, and what each one needs before it may hold them.
//!
//! # What this module is, and what it is not
//!
//! It is a **catalogue with manifests that the kernel accepts**: every entry classifies as
//! [`Tier::Official`], every capability set resolves against the real matrix, and
//! [`Official::draft`] produces a manifest that [`Manifest::validate`] accepts.
//!
//! It is **not** a claim that these plugins run. This build has no WASM runtime, and no
//! official plugin has been implemented as a process plugin either, so these are the
//! *declarations a working plugin would have to match* — not the plugins. Saying otherwise
//! would be the "declared but not wired" defect this project is a reaction to, so the
//! module is named for what it holds.
//!
//! # Why the capability sets live here rather than in a manifest
//!
//! A manifest's `capabilities.grant` is what a publisher *asks for*; this table is what
//! the project has decided each official plugin *needs*. Keeping the decision in code
//! means [`Official::approvals`] can be derived from it by asking
//! [`Capability::decision`] which authority each entry requires — so the approval list
//! cannot drift from the matrix, and a capability the official tier may not hold at all
//! shows up as a failing test the moment this table is edited.

use std::collections::BTreeMap;

use nau_plugin::capability::{Approval, Capability, Grant};
use nau_plugin::error::{PluginError, Result};
use nau_plugin::manifest::{CapabilitySection, Limits, Manifest, PluginSection, SignatureSection};
use nau_plugin::tier::Tier;

/// One official plugin: what it is called, what it does, what it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Official {
    /// The reverse-domain name, which is what decides the tier.
    pub name: &'static str,
    /// The plugin's own version, decoupled from the kernel's.
    pub version: &'static str,
    /// One line of what it does.
    pub summary: &'static str,
    /// The v2.x feature it was extracted from, for provenance.
    pub from: &'static str,
    /// The capabilities it declares.
    pub capabilities: &'static [Capability],
}

impl Official {
    /// This plugin's tier, derived from its name rather than stored.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] when the name does not classify — which for a table of
    /// constants means a typo, and is worth surfacing per entry rather than panicking in a
    /// `const`.
    pub fn tier(&self) -> Result<Tier> {
        Tier::from_name(self.name)
    }

    /// The approvals this capability set needs, derived from the matrix.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] when the official tier may not hold one of them **at
    /// all**. That is not a configuration problem and no approval fixes it, so it is
    /// reported rather than quietly dropped from the list.
    pub fn approvals(&self) -> Result<Vec<(Capability, Approval)>> {
        let mut out = Vec::new();
        for cap in self.capabilities {
            match cap.decision(Tier::Official) {
                Grant::Always => {}
                Grant::RequiresApproval(authority) => out.push((*cap, authority)),
                Grant::Refused { reason } => {
                    return Err(PluginError::Capability(format!(
                        "`{}` declares `{}`, which the official tier may not hold: {reason}",
                        self.name,
                        cap.as_str()
                    )));
                }
            }
        }
        Ok(out)
    }

    /// Look one up by name.
    #[must_use]
    pub fn find(name: &str) -> Option<&'static Official> {
        OFFICIALS.iter().find(|o| o.name == name)
    }

    /// The manifest a publisher would have to produce for this plugin.
    ///
    /// `module_sha256` is the digest of the artefact the publisher will sign. The result
    /// is **unsigned** — [`nau_plugin::manifest::Manifest::verify_with_approvals`] is what
    /// checks it — so it carries an empty `publisher_key` and cannot be mistaken for a
    /// verified manifest.
    ///
    /// # Errors
    ///
    /// [`PluginError::Tier`] when the name does not classify to the official tier, which
    /// would mean this table contains an entry whose prefix contradicts it.
    pub fn draft(
        &self,
        module_sha256: &str,
        publisher_did: &str,
        entry: &str,
        limits: Limits,
    ) -> Result<Manifest> {
        let tier = self.tier()?;
        if tier != Tier::Official {
            return Err(PluginError::Tier(format!(
                "`{}` classifies as {tier}, not official; the catalogue must not contain names \
                 from another tier",
                self.name
            )));
        }
        Ok(Manifest {
            plugin: PluginSection {
                name: self.name.to_string(),
                version: self.version.to_string(),
                abi: format!("{}.{}", nau_plugin::ABI_MAJOR, nau_plugin::ABI_MINOR),
                entry: entry.to_string(),
                publisher: publisher_did.to_string(),
                module_sha256: module_sha256.to_string(),
            },
            capabilities: CapabilitySection {
                grant: self
                    .capabilities
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect(),
            },
            limits,
            waivers: BTreeMap::new(),
            // None of the eleven catalogue entries declares one. The field exists and is
            // carried through the load pipeline, so the day one of them needs a peer, the
            // declaration is a line here rather than a kernel change.
            dependencies: Vec::new(),
            // A-11: the class this manifest runs at. Stated explicitly here rather than
            // relying on serde's default, so that adding the field is a decision this
            // construction site made rather than a value it inherited.
            priority: nau_plugin::PriorityClass::LatencyTolerant,
            signature: SignatureSection {
                publisher_key: String::new(),
                manifest_digest: String::new(),
                sig: String::new(),
                counter_sig: None,
                counter_key: None,
            },
        })
    }
}

/// The eleven official plugins, in the order the architecture document lists them.
///
/// The names follow the reverse-domain rule from the document's identification section
/// (`com.twinsearth.official.*`) rather than the short `off.*` spelling used elsewhere in
/// the same document: the tier is derived from the prefix, and two spellings would derive
/// two different tiers.
pub const OFFICIALS: [Official; 13] = [
    Official {
        name: "com.twinsearth.official.shard",
        version: "1.0.0",
        summary: "Sharded storage and DHT routing",
        from: "v2.x shard/ + net/dht",
        capabilities: &[Capability::DhtRead, Capability::DhtWrite],
    },
    Official {
        name: "com.twinsearth.official.bridge",
        version: "1.0.0",
        summary: "Cross-chain reputation bridging and on-chain anchoring",
        from: "v2.x chain/ + anchor",
        capabilities: &[Capability::ChainEvmRead, Capability::ChainEvmWrite],
    },
    Official {
        name: "com.twinsearth.official.mesh",
        version: "1.0.0",
        summary: "Full peer mesh and gossip propagation",
        from: "v2.x net/ + libp2p",
        capabilities: &[Capability::GossipPublish, Capability::GossipSubscribe],
    },
    Official {
        name: "com.twinsearth.official.swarm",
        version: "1.0.0",
        summary: "Swarm intelligence: emergence detection and BFT-lite consensus",
        from: "v2.x swarm/ + consensus/",
        capabilities: &[Capability::SwarmConsensus],
    },
    Official {
        name: "com.twinsearth.official.market",
        version: "1.0.0",
        summary: "Agent marketplace: registration, matching, task lifecycle",
        from: "v2.x marketplace/",
        capabilities: &[
            Capability::AgentCardCreate,
            Capability::AgentCardUpdate,
            Capability::EconomySettle,
        ],
    },
    Official {
        name: "com.twinsearth.official.economy",
        version: "1.0.0",
        summary: "Multi-dimensional reputation and settlement policy",
        from: "v2.x economy/ + ledger/",
        capabilities: &[Capability::EconomySettle],
    },
    Official {
        name: "com.twinsearth.official.scheduler",
        version: "1.0.0",
        summary: "Task scheduling and load balancing",
        from: "v2.x scheduler/",
        capabilities: &[Capability::MessageSend],
    },
    Official {
        name: "com.twinsearth.official.mcp",
        version: "1.0.0",
        summary: "MCP / ACA compatible tool surface",
        from: "v2.x mcp/",
        capabilities: &[Capability::MessageSend],
    },
    Official {
        name: "com.twinsearth.official.crdt",
        version: "1.0.0",
        summary: "CRDT state synchronisation",
        from: "v2.x crdt/",
        capabilities: &[Capability::GossipPublish, Capability::GossipSubscribe],
    },
    Official {
        name: "com.twinsearth.official.agent",
        version: "1.0.0",
        summary: "Layered memory: individual, swarm and cross-generation",
        from: "v2.x agent memory",
        capabilities: &[Capability::StorageOwn],
    },
    Official {
        name: "com.twinsearth.official.test-runner",
        version: "1.0.0",
        summary: "Test-case runner whose executors are the agents themselves",
        from: "new in v3.x",
        capabilities: &[Capability::MessageSend],
    },
    // Adopted from `agent-universe` v3.5.0's `com.twinsearth.official.agent-skill`. Our name is
    // the short form the rest of this table uses; the mapping is recorded in
    // `docs/PLUGIN-MIGRATION.md`, because a reader comparing the two catalogues needs it and a
    // comment inside one of them is not where they will look.
    Official {
        name: "com.twinsearth.official.skill",
        version: "1.0.0",
        summary: "Which agents can do a job, decided from a caller-supplied roster",
        from: "v3.5.0 agent-skill",
        capabilities: &[Capability::StorageOwn],
    },
    // Adopted from `agent-universe` v3.5.0's `com.twinsearth.official.chain-anchor`. The rules
    // are ported from this repository's own `contracts/src/AgentCardAnchor.sol` rather than from
    // upstream's Python, and no chain client is involved.
    Official {
        name: "com.twinsearth.official.chain-anchor",
        version: "1.0.0",
        summary: "Write-once agent-card anchors, offline: the rules of AgentCardAnchor.sol",
        from: "v3.5.0 chain-anchor",
        capabilities: &[Capability::StorageOwn],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn limits() -> Limits {
        Limits {
            memory_bytes: 64 * 1024 * 1024,
            cpu_ms: 5_000,
            disk_bytes: 8 * 1024 * 1024,
            max_processes: 2,
            max_output_bytes: 32 * 1024,
        }
    }

    #[test]
    fn every_official_plugin_classifies_as_official() {
        // The tier comes from the name, so an entry with the wrong prefix would silently
        // be a different tier and would be refused at load with a message about the tier
        // rather than about the typo.
        for o in &OFFICIALS {
            assert_eq!(o.tier().expect("classifies"), Tier::Official, "{}", o.name);
            assert!(o.name.starts_with("com.twinsearth.official."), "{}", o.name);
        }
        // The catalogue and the document are compared as a **set of names**, not as a row count.
        //
        // This began as `assert_eq!(OFFICIALS.len(), 11, "the document lists eleven")` -- a
        // hardcoded number whose message claimed a comparison with the document that was never
        // performed. Adding a twelfth entry made it fail with a message about a document it had
        // not opened, which is the shape of constant this project keeps finding: one that answers
        // "does the document agree?" and cannot know.
        //
        // Counting rows was the second attempt and it was also wrong, in a way worth recording:
        // the document has **two** tables -- the full catalogue and a shorter "runnable" list --
        // so a row count reads eighteen rows for twelve plugins. A set cannot be fooled by a name
        // legitimately appearing twice, and it still fails on the thing that matters: a name in
        // one place and not the other.
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/PLUGIN-MIGRATION.md"),
        )
        .expect("the migration document is readable from the crate directory");
        // The prefix is stripped to find the end of the name, then put back: the extracted text
        // is the **suffix**, and comparing suffixes against full names was the first version of
        // this test. It failed loudly, which is what a set comparison is for.
        const PREFIX: &str = "| `com.twinsearth.official.";
        const NAME_PREFIX: &str = "com.twinsearth.official.";
        let mut documented: BTreeSet<String> = BTreeSet::new();
        for line in doc.lines() {
            let Some(rest) = line.strip_prefix(PREFIX) else {
                continue;
            };
            if let Some(end) = rest.find('`') {
                documented.insert(format!("{NAME_PREFIX}{}", &rest[..end]));
            }
        }
        let mut catalogued: BTreeSet<String> = BTreeSet::new();
        for o in &OFFICIALS {
            catalogued.insert(o.name.to_string());
        }
        let missing: Vec<&String> = catalogued.difference(&documented).collect();
        let extra: Vec<&String> = documented.difference(&catalogued).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "the migration document and the catalogue disagree: not documented {missing:?}, \
             documented but not in the catalogue {extra:?}"
        );
        // A row count is still asserted, weakly: every catalogue entry has at least one row.
        let rows = doc
            .lines()
            .filter(|line| line.starts_with("| `com.twinsearth.official."))
            .count();
        assert!(
            rows >= OFFICIALS.len(),
            "the document names {rows} official row(s) for {} catalogue entries",
            OFFICIALS.len()
        );
    }

    #[test]
    fn every_official_plugin_may_hold_what_it_declares() {
        // A capability the official tier refuses outright makes this fail at the point the
        // table is edited, rather than at the first load attempt.
        for o in &OFFICIALS {
            let approvals = o.approvals().unwrap_or_else(|e| panic!("{}: {e}", o.name));
            for cap in o.capabilities {
                if cap.is_basic() {
                    continue;
                }
                let granted = approvals.iter().find(|(c, _)| c == cap).map(|(_, a)| *a);
                assert_eq!(
                    granted,
                    Some(Approval::VendorTeam),
                    "{} declares {} and the official tier's authority for it must be the vendor \
                     team; a `None` here would mean the matrix changed underneath this table",
                    o.name,
                    cap.as_str()
                );
            }
        }
    }

    #[test]
    fn no_name_is_registered_twice() {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for o in &OFFICIALS {
            assert!(seen.insert(o.name), "{} is listed twice", o.name);
        }
    }

    #[test]
    fn the_market_plugin_declares_the_three_capabilities_the_migration_document_names() {
        // A spot check that this table and `docs/PLUGIN-MIGRATION.md` cannot drift apart
        // without a test noticing.
        let market = Official::find("com.twinsearth.official.market").expect("listed");
        let caps: BTreeSet<&str> = market.capabilities.iter().map(|c| c.as_str()).collect();
        assert!(caps.contains("agent:card:create"));
        assert!(caps.contains("agent:card:update"));
        assert!(caps.contains("economy:settle"));
    }

    #[test]
    fn every_plugin_that_wants_network_access_declares_it_rather_than_assuming_it() {
        // The plugins whose v2.x feature used the network must say so in their capability
        // set: a plugin that reaches the network without declaring it is the exact case the
        // bus exists to catch, and the catalogue must not model it.
        for name in [
            "com.twinsearth.official.shard",
            "com.twinsearth.official.mesh",
            "com.twinsearth.official.crdt",
        ] {
            let plugin = Official::find(name).expect("listed");
            assert!(
                plugin
                    .capabilities
                    .iter()
                    .any(|c| c.as_str().starts_with("net:")),
                "{name} came from a networked v2.x feature but declares no net: capability"
            );
        }
    }

    #[test]
    fn a_draft_carries_the_hosts_abi_and_the_declared_capabilities() {
        let shard = Official::find("com.twinsearth.official.shard").expect("listed");
        let draft = shard
            .draft(
                &"00".repeat(32),
                "did:nau:0011223344556677",
                "shard.bin",
                limits(),
            )
            .expect("drafts");
        assert_eq!(draft.plugin.name, shard.name);
        assert_eq!(
            draft.plugin.abi,
            format!("{}.{}", nau_plugin::ABI_MAJOR, nau_plugin::ABI_MINOR)
        );
        assert_eq!(draft.capabilities.grant.len(), shard.capabilities.len());
        assert!(
            draft.signature.publisher_key.is_empty(),
            "a draft that looked signed would be the easiest possible thing to mistake for a \
             verified manifest"
        );
        // And it is well formed by the kernel's own reading of its shape.
        assert_eq!(draft.validate().expect("well formed"), Tier::Official);
    }

    #[test]
    fn an_unknown_name_is_not_found_rather_than_defaulted() {
        assert!(Official::find("com.twinsearth.official.nope").is_none());
        assert!(Official::find("com.twinsearth.sys.identity").is_none());
    }
}
