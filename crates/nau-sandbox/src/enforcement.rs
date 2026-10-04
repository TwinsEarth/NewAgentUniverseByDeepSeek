//! OS-level enforcement: AppArmor confinement and eBPF network whitelisting.
//!
//! # What this module is, and what it is not
//!
//! It is the **declaration** of two Linux mechanisms, their **premises**, and the **typed refusal**
//! every other platform gets. It is not an implementation of either: this build does not generate
//! AppArmor profiles or load eBPF programs, and nothing here pretends to.
//!
//! That is the same shape A-09 and A-10 took. The value of declaring a mechanism before having one
//! is that asking for it produces **a refusal with a reason** instead of running without it — which
//! is the difference between a sandbox that is weaker than advertised and one that says so.
//!
//! # The premise, written down rather than left to be inferred
//!
//! The design says AppArmor confines a sandbox **"even if the Agent gained administrator rights"**.
//! That is true, and it is true **conditionally**: AppArmor's confinement is enforced by the kernel
//! against a task's profile, and a process holding **`CAP_MAC_ADMIN`** can **change the profile it
//! is confined by**. Root alone does not confer that — `CAP_MAC_ADMIN` is a distinct capability in
//! the `CAP_*` set — so the sentence is correct for root and **wrong** for a process that holds it.
//!
//! [`PREMISES`] states that, and states the others, because a security claim whose condition is not
//! written next to it is one a reader will assume unconditionally.
//!
//! # Policy is replaceable, not a one-time configuration
//!
//! [`PolicySet::replace`] swaps the whole set and [`PolicySet::apply`] adds one, both returning the
//! revision they produced. C-09 asks that policy be updatable in real time rather than configured
//! once, and the reason is the one this repository keeps arriving at: a rule that can only be set at
//! start-up is a rule that cannot answer anything that was not known at start-up.

use std::collections::BTreeMap;

use nau_core::error::{NauError, Result};
use serde::{Deserialize, Serialize};

/// One OS mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    /// Kernel path and socket confinement by profile.
    AppArmor,
    /// Connection filtering by program.
    EbpfWhitelist,
}

impl Mechanism {
    /// Every mechanism.
    pub const ALL: [Mechanism; 2] = [Mechanism::AppArmor, Mechanism::EbpfWhitelist];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Mechanism::AppArmor => "apparmor",
            Mechanism::EbpfWhitelist => "ebpf-whitelist",
        }
    }

    /// What it confines, in one phrase.
    #[must_use]
    pub fn confines(self) -> &'static str {
        match self {
            Mechanism::AppArmor => "file and socket access, by path and by profile",
            Mechanism::EbpfWhitelist => "network destinations, by address, port and protocol",
        }
    }
}

/// Whether a mechanism is available on this build, and if not, why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementSupport {
    /// Declared and usable on this platform.
    Available {
        /// The interface the mechanism is driven through.
        via: &'static str,
    },
    /// Refused, with the reason a caller can read.
    Refused {
        /// Why.
        reason: &'static str,
    },
}

impl EnforcementSupport {
    /// The interface, if available.
    #[must_use]
    pub fn interface(self) -> Option<&'static str> {
        match self {
            EnforcementSupport::Available { via } => Some(via),
            EnforcementSupport::Refused { .. } => None,
        }
    }

    /// The reason, if refused.
    #[must_use]
    pub fn refusal(self) -> Option<&'static str> {
        match self {
            EnforcementSupport::Available { .. } => None,
            EnforcementSupport::Refused { reason } => Some(reason),
        }
    }
}

/// Whether AppArmor is available here.
pub const APPARMOR_SUPPORT: EnforcementSupport = if cfg!(target_os = "linux") {
    EnforcementSupport::Available {
        via: "the apparmor LSM, through its profile interface",
    }
} else {
    EnforcementSupport::Refused {
        reason: "AppArmor is a Linux security module, and this build is not running on Linux. \
                 The confinement is refused rather than skipped: a sandbox that reported the \
                 mechanism as applied without applying it would be weaker than it says",
    }
};

/// Whether the eBPF network whitelist is available here.
pub const EBPF_SUPPORT: EnforcementSupport = if cfg!(target_os = "linux") {
    EnforcementSupport::Available {
        via: "a cgroup-attached eBPF program",
    }
} else {
    EnforcementSupport::Refused {
        reason: "eBPF network filtering needs the Linux kernel's verifier and a cgroup to attach \
                 to, and this build is not running on Linux. Refused rather than skipped, for the \
                 same reason as AppArmor",
    }
};

/// The support for `mechanism`.
#[must_use]
pub fn support(mechanism: Mechanism) -> EnforcementSupport {
    match mechanism {
        Mechanism::AppArmor => APPARMOR_SUPPORT,
        Mechanism::EbpfWhitelist => EBPF_SUPPORT,
    }
}

/// A condition a claim depends on, stated next to the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Premise {
    /// The mechanism.
    pub mechanism: Mechanism,
    /// What is claimed.
    pub claim: &'static str,
    /// **What the claim depends on.**
    pub depends_on: &'static str,
    /// What happens when the condition does not hold.
    pub otherwise: &'static str,
}

/// The premises these claims rest on.
///
/// Written down because a security claim whose condition is not beside it is one a reader will
/// assume unconditionally. The first entry is the one the design's wording invites: AppArmor does
/// confine root, and **that is not the same as confining a process that can edit its own profile**.
pub const PREMISES: [Premise; 3] = [
    Premise {
        mechanism: Mechanism::AppArmor,
        claim: "a confined process stays confined after gaining root",
        depends_on: "the process does NOT hold CAP_MAC_ADMIN. Root alone does not confer it -- \
                     CAP_MAC_ADMIN is a distinct capability in the CAP_* set, and a process holding \
                     it can change the profile that confines it, which is the whole of the \
                     confinement",
        otherwise: "the process can replace its own profile and the confinement becomes a statement \
                    about what it chose to do rather than about what it was permitted to do",
    },
    Premise {
        mechanism: Mechanism::AppArmor,
        claim: "the profile applies to the sandbox's processes",
        depends_on: "every process is spawned under the profile. A process that escapes the profile \
                     by exec'ing outside it is not confined by it",
        otherwise: "the confinement covers the processes it was applied to and no others",
    },
    Premise {
        mechanism: Mechanism::EbpfWhitelist,
        claim: "the sandbox can reach only the destinations the policy names",
        depends_on: "the program is attached to the cgroup every egress path goes through. A socket \
                     created outside that cgroup is not filtered",
        otherwise: "the whitelist bounds the traffic that goes through the filtered path and says \
                    nothing about the rest",
    },
];

/// The premises for `mechanism`.
#[must_use]
pub fn premises_of(mechanism: Mechanism) -> Vec<Premise> {
    PREMISES
        .into_iter()
        .filter(|p| p.mechanism == mechanism)
        .collect()
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// What the rule is about: a path, a socket, or a destination.
    pub subject: String,
    /// Whether it permits or denies.
    pub allow: bool,
    /// Why the rule exists, so a reviewer can disagree with the reason rather than the syntax.
    pub because: String,
}

/// A set of rules, replaceable at runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySet {
    /// The rules, keyed by subject so a rule about one thing is one entry.
    rules: BTreeMap<String, Rule>,
    /// How many times the set has been changed. Starts at zero and is never reused.
    revision: u64,
}

impl PolicySet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether it holds no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The current revision.
    ///
    /// C-09 asks that policy be updatable in real time rather than configured once. A revision is
    /// what makes "the policy that was in force when this happened" a question with an answer: two
    /// policy sets that differ are two policies, and a decision recorded without a revision cannot
    /// say which one it was made under.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The rules, by subject.
    #[must_use]
    pub fn rules(&self) -> &BTreeMap<String, Rule> {
        &self.rules
    }

    /// Whether `subject` is allowed.
    ///
    /// A subject with no rule is **denied**, which is the direction this whole module is about: a
    /// whitelist that permitted what nobody had written a rule for would be a blacklist with extra
    /// steps.
    #[must_use]
    pub fn allows(&self, subject: &str) -> bool {
        self.rules.get(subject).is_some_and(|r| r.allow)
    }

    /// Add or replace one rule, and return the new revision.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when `subject` is blank or `because` is blank — a rule with no
    /// reason is one a reviewer can neither agree nor disagree with.
    pub fn apply(&mut self, rule: Rule) -> Result<u64> {
        if rule.subject.trim().is_empty() {
            return Err(NauError::Validation(
                "a rule must name its subject".to_string(),
            ));
        }
        if rule.because.trim().is_empty() {
            return Err(NauError::Validation(
                "a rule must say why it exists; a rule with no reason is one nobody can review"
                    .to_string(),
            ));
        }
        self.rules.insert(rule.subject.clone(), rule);
        self.revision = self.revision.saturating_add(1);
        Ok(self.revision)
    }

    /// Replace the whole set, and return the new revision.
    ///
    /// The real-time path: a set that could only be built once would be one that cannot answer
    /// anything nobody knew at start-up.
    ///
    /// # Errors
    ///
    /// As [`PolicySet::apply`], for every rule in `rules`. The set is left **unchanged** when any
    /// rule is refused, because a partial replacement is a policy nobody wrote.
    pub fn replace(&mut self, rules: impl IntoIterator<Item = Rule>) -> Result<u64> {
        let mut next = BTreeMap::new();
        for rule in rules {
            if rule.subject.trim().is_empty() {
                return Err(NauError::Validation(
                    "a rule must name its subject".to_string(),
                ));
            }
            if rule.because.trim().is_empty() {
                return Err(NauError::Validation(
                    "a rule must say why it exists; a rule with no reason is one nobody can review"
                        .to_string(),
                ));
            }
            next.insert(rule.subject.clone(), rule);
        }
        self.rules = next;
        self.revision = self.revision.saturating_add(1);
        Ok(self.revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(subject: &str, allow: bool) -> Rule {
        Rule {
            subject: subject.to_string(),
            allow,
            because: "for the test".to_string(),
        }
    }

    #[test]
    fn every_platform_gets_an_answer_and_a_non_linux_build_gets_a_reason() {
        // C-09's first criterion. On Linux both mechanisms are declared available; anywhere else
        // both are refused AND the refusal says why. The assertion is written so it holds on either
        // platform, because the test suite runs on three and the property is "there is always an
        // answer, and a refusal always has a reason".
        for mechanism in Mechanism::ALL {
            let support = support(mechanism);
            match support {
                EnforcementSupport::Available { via } => {
                    assert!(!via.trim().is_empty(), "{mechanism:?} names no interface");
                    assert!(support.refusal().is_none());
                }
                EnforcementSupport::Refused { reason } => {
                    assert!(
                        !reason.trim().is_empty(),
                        "{mechanism:?} is refused with no reason, which is the silent skip this \
                         module exists to prevent"
                    );
                    assert!(support.interface().is_none());
                }
            }
        }
    }

    #[test]
    fn this_builds_platform_is_the_one_the_constants_describe() {
        // Written as a `cfg!` in the constants themselves, so this test asserts the two agree
        // rather than restating which platform this is.
        let linux = cfg!(target_os = "linux");
        assert_eq!(APPARMOR_SUPPORT.interface().is_some(), linux);
        assert_eq!(EBPF_SUPPORT.interface().is_some(), linux);
        if !linux {
            assert!(
                APPARMOR_SUPPORT
                    .refusal()
                    .is_some_and(|r| r.contains("not running on Linux")),
                "the refusal must name the platform, not merely that something is unavailable"
            );
            assert!(EBPF_SUPPORT
                .refusal()
                .is_some_and(|r| r.contains("not running on Linux")));
        }
    }

    #[test]
    fn apparmors_premise_names_the_capability_and_says_that_root_is_not_it() {
        // The wording C-09 requires be tightened. The design's sentence is correct for root and
        // wrong for a process holding CAP_MAC_ADMIN, and the difference has to be in the text
        // rather than in a reader's head.
        let apparmor = premises_of(Mechanism::AppArmor);
        assert!(!apparmor.is_empty());
        let confinement = apparmor
            .iter()
            .find(|p| p.claim.contains("root"))
            .expect("the claim about root must be stated");
        assert!(
            confinement.depends_on.contains("CAP_MAC_ADMIN"),
            "the premise must name the capability, got: {}",
            confinement.depends_on
        );
        assert!(
            confinement
                .depends_on
                .contains("Root alone does not confer it"),
            "and must say that root is not the same thing, got: {}",
            confinement.depends_on
        );
        assert!(
            confinement.otherwise.contains("replace its own profile"),
            "and what happens when the premise fails, got: {}",
            confinement.otherwise
        );
    }

    #[test]
    fn every_premise_names_a_condition_and_a_consequence() {
        // A premise with no condition is an unconditional claim wearing the shape of a careful one.
        for premise in PREMISES {
            assert!(
                !premise.claim.trim().is_empty(),
                "{:?} states no claim",
                premise.mechanism
            );
            assert!(
                !premise.depends_on.trim().is_empty(),
                "{:?} depends on nothing, which means the claim is unconditional",
                premise.mechanism
            );
            assert!(
                !premise.otherwise.trim().is_empty(),
                "{:?} does not say what happens when the condition fails",
                premise.mechanism
            );
        }
        // And both mechanisms have at least one, so neither is declared without its conditions.
        for mechanism in Mechanism::ALL {
            assert!(
                !premises_of(mechanism).is_empty(),
                "{mechanism:?} is declared as a mechanism with no premises at all"
            );
        }
    }

    #[test]
    fn an_unwritten_subject_is_denied_rather_than_allowed() {
        // The direction of the whole module. A whitelist that permitted what nobody had written a
        // rule for would be a blacklist with extra steps.
        let set = PolicySet::new();
        assert!(!set.allows("/etc/shadow"));
        assert!(!set.allows("10.0.0.1:443"));
        assert!(set.is_empty());
        assert_eq!(set.revision(), 0);
    }

    #[test]
    fn a_rule_can_be_applied_and_the_revision_moves() {
        // C-09's third criterion: policy is updatable rather than configured once.
        let mut set = PolicySet::new();
        let first = set.apply(rule("/usr/bin/python3", true)).expect("applied");
        assert_eq!(first, 1);
        assert!(set.allows("/usr/bin/python3"));
        assert!(!set.allows("/usr/bin/curl"));

        let second = set.apply(rule("/usr/bin/curl", false)).expect("applied");
        assert_eq!(second, 2, "the revision must move on every change");
        assert!(
            !set.allows("/usr/bin/curl"),
            "an explicit deny is still a deny"
        );
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn replacing_the_whole_set_is_a_live_operation_and_is_all_or_nothing() {
        let mut set = PolicySet::new();
        set.apply(rule("/old", true)).expect("applied");
        let revision = set.replace([rule("/new", true)]).expect("replaced");
        assert_eq!(revision, 2);
        assert!(set.allows("/new"));
        assert!(!set.allows("/old"), "a replacement replaces");

        // A refused rule leaves the set exactly as it was: a partial replacement is a policy nobody
        // wrote, and a policy nobody wrote is one nobody reviewed.
        let before = set.clone();
        let bad = set.replace([rule("/a", true), rule("  ", true)]);
        assert!(bad.is_err(), "a blank subject must be refused");
        assert_eq!(set, before, "a refused replacement must change nothing");
    }

    #[test]
    fn a_rule_without_a_reason_is_refused() {
        // A rule with no reason is one a reviewer can neither agree nor disagree with.
        let mut set = PolicySet::new();
        let mut unreasoned = rule("/x", true);
        unreasoned.because = "   ".to_string();
        assert!(set.apply(unreasoned).is_err());
        assert!(set.is_empty());
        assert_eq!(
            set.revision(),
            0,
            "a refused rule must not move the revision"
        );
    }

    #[test]
    fn a_blank_subject_is_refused() {
        let mut set = PolicySet::new();
        assert!(set.apply(rule("", true)).is_err());
        assert!(set.apply(rule("  ", true)).is_err());
        assert!(set.is_empty());
    }

    #[test]
    fn the_mechanism_labels_are_distinct_and_say_what_they_confine() {
        let mut labels: Vec<&str> = Mechanism::ALL.iter().map(|m| m.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count);
        for mechanism in Mechanism::ALL {
            assert!(
                !mechanism.confines().trim().is_empty(),
                "{mechanism:?} does not say what it confines"
            );
        }
        assert_ne!(
            Mechanism::AppArmor.confines(),
            Mechanism::EbpfWhitelist.confines()
        );
    }
}
