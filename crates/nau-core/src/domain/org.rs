//! Agents organised into a body with roles and quotas.
//!
//! # Why roles are permission sets and not ranks
//!
//! The obvious model is `enum Role { Owner = 3, Coordinator = 2, Member = 1 }` and a rule that a
//! higher rank may do anything a lower one may. It is obvious and it is wrong, for a reason that
//! shows up the first time a role is added: a rank is a **total order**, and permissions are a
//! **partial** one. The moment one role may do something another may not — a treasurer who may
//! spend but not invite, a coordinator who may invite but not spend — any ranking puts one of
//! them above the other and silently grants the wrong one.
//!
//! So [`OrgRole::permits`] answers per action, from a table, and there is no `Ord` on `OrgRole`.
//! A test asserts the table is total over `OrgAction::ALL`, so a new action cannot be added
//! without every role deciding about it.
//!
//! # Why a quota is a type and not a number
//!
//! A quota that is stored and never consulted is the "written but not wired" failure in its
//! quietest form: the field is there, the document says the limit exists, and nothing refuses
//! anything. [`Quota::check`] is therefore the only way to ask whether a request fits, and it
//! returns a refusal naming **which** dimension was exceeded rather than a bare `false` — a
//! caller that cannot say which limit it hit cannot report it either.
//!
//! What this module does **not** do is enforce a quota at the point of use. It decides whether a
//! request fits; spending the resource is the caller's job, and pretending otherwise would put a
//! decision here and an effect somewhere else with no link between them.

use serde::{Deserialize, Serialize};

use crate::error::{NauError, Result};
use crate::identity::{canonical::payload_digest_hex, Did};

/// An organisation's identifier.
///
/// A validated token rather than a bare `String`, because it reaches storage keys, audit entries
/// and message routing, and an id carrying a path separator is a traversal in whichever of those
/// forgets to check.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrgId(String);

impl OrgId {
    /// The longest an id may be.
    pub const MAX_BYTES: usize = 128;

    /// Parse an id.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the id is empty, longer than [`OrgId::MAX_BYTES`], or
    /// carries a separator, a traversal or a NUL.
    pub fn parse(text: &str) -> Result<Self> {
        if text.trim().is_empty() {
            return Err(NauError::Validation(
                "an organisation id must not be empty".to_string(),
            ));
        }
        if text.len() > Self::MAX_BYTES {
            return Err(NauError::Validation(format!(
                "organisation id is {} bytes; the limit is {}",
                text.len(),
                Self::MAX_BYTES
            )));
        }
        for bad in ['/', '\\', '\0'] {
            if text.contains(bad) {
                return Err(NauError::Validation(format!(
                    "organisation id {text:?} carries {bad:?}"
                )));
            }
        }
        if text.contains("..") {
            return Err(NauError::Validation(format!(
                "organisation id {text:?} carries a traversal"
            )));
        }
        Ok(Self(text.to_string()))
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a member may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgAction {
    /// Read the organisation's description and membership.
    Read,
    /// Add a member.
    InviteMember,
    /// Remove a member.
    RemoveMember,
    /// Change a member's role.
    ChangeRole,
    /// Create a sandbox charged to the organisation's quota.
    CreateSandbox,
    /// Spend from the organisation's budget.
    Spend,
    /// Change the organisation's quota.
    SetQuota,
    /// Dissolve the organisation.
    Dissolve,
}

impl OrgAction {
    /// Every action, exhaustive.
    ///
    /// The role table is asserted total over this array, so a new action cannot be introduced
    /// without every role deciding about it.
    pub const ALL: [OrgAction; 8] = [
        OrgAction::Read,
        OrgAction::InviteMember,
        OrgAction::RemoveMember,
        OrgAction::ChangeRole,
        OrgAction::CreateSandbox,
        OrgAction::Spend,
        OrgAction::SetQuota,
        OrgAction::Dissolve,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            OrgAction::Read => "read",
            OrgAction::InviteMember => "invite_member",
            OrgAction::RemoveMember => "remove_member",
            OrgAction::ChangeRole => "change_role",
            OrgAction::CreateSandbox => "create_sandbox",
            OrgAction::Spend => "spend",
            OrgAction::SetQuota => "set_quota",
            OrgAction::Dissolve => "dissolve",
        }
    }

    /// Whether this action changes the organisation's shape or its resources.
    ///
    /// Read is the only action that does not, and saying so as a method keeps the distinction in
    /// one place. It is what the observer role is built from.
    #[must_use]
    pub fn is_mutating(self) -> bool {
        !matches!(self, OrgAction::Read)
    }
}

/// A member's role.
///
/// **No `Ord`.** See the module documentation: permissions are a partial order and ranking these
/// silently grants the wrong role the moment two of them differ in a way a line cannot express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgRole {
    /// Runs the organisation. May do everything.
    Owner,
    /// Runs its day-to-day work: adds people, creates sandboxes, spends.
    ///
    /// Notably **not** `SetQuota` or `Dissolve`: a coordinator who could raise the organisation's
    /// own quota would be able to give themselves an unbounded budget, and one who could dissolve
    /// it could destroy what they were trusted to run.
    Coordinator,
    /// Does the work. Reads, and creates sandboxes within quota.
    ///
    /// Notably **not** `Spend`: spending is a financial act and the coordinator holds it.
    Member,
    /// Watches. Reads and nothing else.
    Observer,
}

impl OrgRole {
    /// Every role, exhaustive.
    pub const ALL: [OrgRole; 4] = [
        OrgRole::Owner,
        OrgRole::Coordinator,
        OrgRole::Member,
        OrgRole::Observer,
    ];

    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            OrgRole::Owner => "owner",
            OrgRole::Coordinator => "coordinator",
            OrgRole::Member => "member",
            OrgRole::Observer => "observer",
        }
    }

    /// Whether this role may perform `action`.
    ///
    /// Total over [`OrgAction::ALL`] for every role, by construction: the match is exhaustive on
    /// both sides and a test walks the cross product.
    #[must_use]
    pub fn permits(self, action: OrgAction) -> bool {
        match self {
            OrgRole::Owner => true,
            OrgRole::Coordinator => matches!(
                action,
                OrgAction::Read
                    | OrgAction::InviteMember
                    | OrgAction::RemoveMember
                    | OrgAction::ChangeRole
                    | OrgAction::CreateSandbox
                    | OrgAction::Spend
            ),
            OrgRole::Member => matches!(action, OrgAction::Read | OrgAction::CreateSandbox),
            OrgRole::Observer => matches!(action, OrgAction::Read),
        }
    }

    /// The actions this role may perform.
    #[must_use]
    pub fn permitted(self) -> Vec<OrgAction> {
        OrgAction::ALL
            .into_iter()
            .filter(|a| self.permits(*a))
            .collect()
    }
}

/// One member of an organisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgMember {
    /// The member's DID.
    pub did: Did,
    /// The member's role.
    pub role: OrgRole,
}

/// A resource quota.
///
/// Every field is present and there is no `Option`, for the reason the sandbox crate gives about
/// its own limits: an absent quota cannot be distinguished from an unlimited one, and the
/// difference between "we forgot to set it" and "we meant infinity" is the whole question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// Address space a sandbox may use.
    pub memory_bytes: u64,
    /// CPU milliseconds a sandbox may use.
    pub cpu_ms: u64,
    /// Bytes a sandbox may write.
    pub disk_bytes: u64,
    /// Sandboxes the organisation may have at once.
    pub max_sandboxes: u32,
    /// Agents the organisation may have.
    pub max_agents: u32,
}

impl Quota {
    /// A quota that permits nothing.
    ///
    /// The starting point for an organisation that has not been granted anything, so that
    /// "no quota set" and "unlimited" cannot be confused: the default is zero, not infinity.
    pub const DENIED: Quota = Quota {
        memory_bytes: 0,
        cpu_ms: 0,
        disk_bytes: 0,
        max_sandboxes: 0,
        max_agents: 0,
    };

    /// Whether every dimension is zero.
    #[must_use]
    pub fn is_denied(self) -> bool {
        self == Self::DENIED
    }

    /// Check that a request fits.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] naming **which** dimension was exceeded and by how much. A bare
    /// `false` would leave a caller unable to report the refusal, and a refusal a caller cannot
    /// report is one that surfaces as a generic failure three layers away.
    pub fn check(self, request: &Quota) -> Result<()> {
        let dimensions = [
            ("memory_bytes", self.memory_bytes, request.memory_bytes),
            ("cpu_ms", self.cpu_ms, request.cpu_ms),
            ("disk_bytes", self.disk_bytes, request.disk_bytes),
            (
                "max_sandboxes",
                u64::from(self.max_sandboxes),
                u64::from(request.max_sandboxes),
            ),
            (
                "max_agents",
                u64::from(self.max_agents),
                u64::from(request.max_agents),
            ),
        ];
        for (name, allowed, asked) in dimensions {
            if asked > allowed {
                return Err(NauError::Validation(format!(
                    "the quota allows {allowed} {name} and the request asks for {asked}"
                )));
            }
        }
        Ok(())
    }
}

/// An organisation of agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentOrg {
    /// The organisation's id.
    pub id: OrgId,
    /// A human-readable name. Not an identifier: two organisations may share one.
    pub name: String,
    /// The members.
    pub members: Vec<OrgMember>,
    /// The organisation's quota.
    pub quota: Quota,
}

impl AgentOrg {
    /// A new organisation with `owner` as its only member and [`Quota::DENIED`].
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] when the name is empty. An organisation with no members cannot be
    /// expressed through this constructor, which is the point: every organisation has an owner,
    /// and an ownerless one would be a set of permissions nobody holds.
    pub fn new(id: OrgId, name: &str, owner: Did) -> Result<Self> {
        if name.trim().is_empty() {
            return Err(NauError::Validation(
                "an organisation needs a name".to_string(),
            ));
        }
        Ok(Self {
            id,
            name: name.to_string(),
            members: vec![OrgMember {
                did: owner,
                role: OrgRole::Owner,
            }],
            quota: Quota::DENIED,
        })
    }

    /// The member with this DID, if any.
    #[must_use]
    pub fn member(&self, did: &Did) -> Option<&OrgMember> {
        self.members.iter().find(|m| &m.did == did)
    }

    /// Whether this DID is a member.
    #[must_use]
    pub fn contains(&self, did: &Did) -> bool {
        self.member(did).is_some()
    }

    /// How many members hold each role.
    #[must_use]
    pub fn count_by_role(&self, role: OrgRole) -> usize {
        self.members.iter().filter(|m| m.role == role).count()
    }

    /// The organisation's own content address.
    ///
    /// Over the canonical payload, so two processes that build the same organisation agree on its
    /// name — the same rule v3.5.1 applied to image manifests, for the same reason.
    ///
    /// # Errors
    ///
    /// [`NauError::Canonical`] if the organisation cannot be canonicalised.
    pub fn digest_hex(&self) -> Result<String> {
        payload_digest_hex(self).map_err(NauError::from)
    }

    /// Authorize `actor` to perform `action`.
    ///
    /// # Errors
    ///
    /// [`NauError::Unauthorized`] with a message naming the actor, the action and the role that
    /// would have permitted it. A refusal that says only "not permitted" leaves the caller unable
    /// to tell a missing membership from an insufficient role, which are different problems.
    pub fn authorize(&self, actor: &Did, action: OrgAction) -> Result<&OrgMember> {
        let member = self.member(actor).ok_or_else(|| {
            NauError::Unauthorized(format!(
                "{actor} is not a member of organisation {} and may not {}",
                self.id,
                action.label()
            ))
        })?;
        if member.role.permits(action) {
            return Ok(member);
        }
        let could = OrgRole::ALL
            .into_iter()
            .filter(|r| r.permits(action))
            .map(OrgRole::label)
            .collect::<Vec<_>>()
            .join(" or ");
        Err(NauError::Unauthorized(format!(
            "{} holds `{}` and may not {}; that needs `{could}`",
            actor,
            member.role.label(),
            action.label()
        )))
    }

    /// Add a member, authorizing the actor first.
    ///
    /// # Errors
    ///
    /// [`NauError::Unauthorized`] when the actor may not invite;
    /// [`NauError::Conflict`] when the DID is already a member — refusing rather than replacing,
    /// because a silent role change through the invite path is how a member is promoted without
    /// anyone deciding to.
    pub fn invite(&mut self, actor: &Did, did: Did, role: OrgRole) -> Result<()> {
        self.authorize(actor, OrgAction::InviteMember)?;
        if self.contains(&did) {
            return Err(NauError::Conflict(format!(
                "{did} is already a member of {}",
                self.id
            )));
        }
        self.members.push(OrgMember { did, role });
        Ok(())
    }

    /// Set the quota, authorizing the actor first.
    ///
    /// # Errors
    ///
    /// [`NauError::Unauthorized`] when the actor may not set the quota.
    pub fn set_quota(&mut self, actor: &Did, quota: Quota) -> Result<()> {
        self.authorize(actor, OrgAction::SetQuota)?;
        self.quota = quota;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Keypair;

    fn did(seed: u8) -> Did {
        Keypair::from_seed(&[seed; 32]).did()
    }

    fn org() -> AgentOrg {
        AgentOrg::new(OrgId::parse("acme").expect("id"), "Acme", did(1)).expect("org")
    }

    #[test]
    fn the_role_table_is_total_over_every_action() {
        // The reason a role is not a rank, checked mechanically: every role answers for every
        // action, so adding an action cannot leave a role undecided.
        for role in OrgRole::ALL {
            let permitted = role.permitted();
            for action in OrgAction::ALL {
                let expected = permitted.contains(&action);
                assert_eq!(
                    role.permits(action),
                    expected,
                    "{:?} and permitted() disagree about {:?}",
                    role,
                    action
                );
            }
        }
    }

    #[test]
    fn an_owner_may_do_everything_and_an_observer_only_reads() {
        for action in OrgAction::ALL {
            assert!(
                OrgRole::Owner.permits(action),
                "owner may {}",
                action.label()
            );
        }
        assert_eq!(OrgRole::Observer.permitted(), vec![OrgAction::Read]);
    }

    #[test]
    fn a_coordinator_may_run_the_org_but_not_redefine_or_dissolve_it() {
        // The two omissions that matter. A coordinator who could set the quota could give
        // themselves an unbounded budget, and one who could dissolve could destroy what they were
        // trusted to run.
        assert!(OrgRole::Coordinator.permits(OrgAction::Spend));
        assert!(OrgRole::Coordinator.permits(OrgAction::InviteMember));
        assert!(!OrgRole::Coordinator.permits(OrgAction::SetQuota));
        assert!(!OrgRole::Coordinator.permits(OrgAction::Dissolve));
    }

    #[test]
    fn a_member_does_not_spend() {
        // Creating a sandbox and spending money are different acts, and a role that does the work
        // is not necessarily one that pays for it.
        assert!(OrgRole::Member.permits(OrgAction::CreateSandbox));
        assert!(!OrgRole::Member.permits(OrgAction::Spend));
        assert!(!OrgRole::Member.permits(OrgAction::InviteMember));
    }

    #[test]
    fn only_read_leaves_the_organisation_unchanged() {
        assert!(!OrgAction::Read.is_mutating());
        assert_eq!(
            OrgAction::ALL.iter().filter(|a| !a.is_mutating()).count(),
            1,
            "read is the only non-mutating action, and the observer role is built from that"
        );
    }

    #[test]
    fn a_non_member_is_refused_and_the_refusal_says_so() {
        let org = org();
        let err = org
            .authorize(&did(9), OrgAction::Read)
            .expect_err("must refuse");
        let text = format!("{err}");
        assert!(text.contains("not a member"), "got: {text}");
        assert!(
            text.contains("read"),
            "the refusal must name the action, got: {text}"
        );
    }

    #[test]
    fn an_insufficient_role_is_refused_and_the_refusal_names_the_role_that_would_do() {
        // "Not permitted" alone leaves a caller unable to tell a missing membership from an
        // insufficient role. They are different problems and the refusal distinguishes them.
        let mut org = org();
        org.invite(&did(1), did(2), OrgRole::Member)
            .expect("invite");

        let ok = org.authorize(&did(2), OrgAction::CreateSandbox);
        assert!(ok.is_ok(), "a member may create sandboxes");

        let err = org
            .authorize(&did(2), OrgAction::Spend)
            .expect_err("must refuse");
        let text = format!("{err}");
        assert!(
            text.contains("member"),
            "it must name the actor's role, got: {text}"
        );
        assert!(
            text.contains("spend"),
            "it must name the action, got: {text}"
        );
        assert!(
            text.contains("owner") && text.contains("coordinator"),
            "it must name which roles could, got: {text}"
        );
    }

    #[test]
    fn inviting_the_same_member_twice_is_refused_rather_than_promoting_them() {
        // A silent role change through the invite path is how a member gets promoted without
        // anyone deciding to.
        let mut org = org();
        org.invite(&did(1), did(2), OrgRole::Observer)
            .expect("first");
        let err = org
            .invite(&did(1), did(2), OrgRole::Owner)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("already a member"), "got: {err}");
        assert_eq!(
            org.member(&did(2)).map(|m| m.role),
            Some(OrgRole::Observer),
            "the refusal must leave the original role alone"
        );
    }

    #[test]
    fn a_new_organisation_has_an_owner_and_no_quota() {
        // The default is zero, not infinity: an absent quota and an unlimited one must not be
        // confusable.
        let org = org();
        assert_eq!(org.count_by_role(OrgRole::Owner), 1);
        assert!(org.quota.is_denied());
        assert_eq!(org.quota, Quota::DENIED);
    }

    #[test]
    fn a_quota_refusal_names_the_dimension_that_was_exceeded() {
        // Each dimension is checked on its own, so the message says which one.
        let allowed = Quota {
            memory_bytes: 100,
            cpu_ms: 100,
            disk_bytes: 100,
            max_sandboxes: 1,
            max_agents: 1,
        };
        allowed
            .check(&allowed)
            .expect("a request equal to the quota fits");

        for (name, request) in [
            (
                "memory_bytes",
                Quota {
                    memory_bytes: 101,
                    ..allowed
                },
            ),
            (
                "max_sandboxes",
                Quota {
                    max_sandboxes: 2,
                    ..allowed
                },
            ),
        ] {
            let err = allowed.check(&request).expect_err("must refuse");
            let text = format!("{err}");
            assert!(
                text.contains(name) && text.contains("101") || text.contains("2"),
                "the refusal must name {name} and the amount asked for, got: {text}"
            );
        }
    }

    #[test]
    fn a_denied_quota_refuses_everything_non_zero() {
        let err = Quota::DENIED
            .check(&Quota {
                memory_bytes: 1,
                ..Quota::DENIED
            })
            .expect_err("must refuse");
        assert!(format!("{err}").contains("memory_bytes"), "got: {err}");
        Quota::DENIED
            .check(&Quota::DENIED)
            .expect("nothing fits in nothing");
    }

    #[test]
    fn only_an_owner_may_set_the_quota() {
        let mut org = org();
        org.invite(&did(1), did(2), OrgRole::Coordinator)
            .expect("invite");
        let raised = Quota {
            memory_bytes: 1024,
            ..Quota::DENIED
        };
        let err = org
            .set_quota(&did(2), raised)
            .expect_err("a coordinator must not raise the quota");
        assert!(format!("{err}").contains("set_quota"), "got: {err}");
        assert!(
            org.quota.is_denied(),
            "the refusal must not have applied anything"
        );

        org.set_quota(&did(1), raised).expect("the owner may");
        assert_eq!(org.quota.memory_bytes, 1024);
    }

    #[test]
    fn an_organisation_survives_a_round_trip_through_json() {
        let mut org = org();
        org.invite(&did(1), did(2), OrgRole::Member)
            .expect("invite");
        let text = serde_json::to_string(&org).expect("serialise");
        let back: AgentOrg = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(org, back);
        assert_eq!(
            org.digest_hex().expect("a"),
            back.digest_hex().expect("b"),
            "the canonical digest must be stable across a round trip"
        );
    }

    #[test]
    fn the_digest_is_content_sensitive() {
        // The same rule v3.5.1 applied to manifests: the digest has to move when the content
        // does, or a signature over it would authorise something else.
        let a = org();
        let mut b = org();
        b.name = "Acme Holdings".to_string();
        assert_ne!(a.digest_hex().expect("a"), b.digest_hex().expect("b"));

        let mut c = org();
        c.invite(&did(1), did(2), OrgRole::Member).expect("invite");
        assert_ne!(a.digest_hex().expect("a"), c.digest_hex().expect("c"));
    }

    #[test]
    fn an_organisation_id_that_could_escape_is_refused() {
        for bad in ["", "   ", "a/b", "a\\b", "..", "a\0b", "../x"] {
            assert!(
                OrgId::parse(bad).is_err(),
                "{bad:?} must not parse as an organisation id"
            );
        }
        assert!(OrgId::parse("acme").is_ok());
        assert!(OrgId::parse(&"x".repeat(128)).is_ok());
        assert!(OrgId::parse(&"x".repeat(129)).is_err());
    }

    #[test]
    fn an_organisation_needs_a_name() {
        assert!(AgentOrg::new(OrgId::parse("x").expect("id"), "  ", did(1)).is_err());
    }

    #[test]
    fn the_role_labels_are_unique() {
        let mut labels: Vec<&str> = OrgRole::ALL.iter().map(|r| r.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count);

        let mut action_labels: Vec<&str> = OrgAction::ALL.iter().map(|a| a.label()).collect();
        action_labels.sort_unstable();
        let action_count = action_labels.len();
        action_labels.dedup();
        assert_eq!(action_labels.len(), action_count);
    }
}
