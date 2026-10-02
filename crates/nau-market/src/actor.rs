//! Who is acting, and by what authority.
//!
//! upstream v2.8.2 fix (finding F): upstream's `open_dispute` mutated the task
//! state directly and its `arbitrate` took no actor at all — any caller who could
//! reach the function was, implicitly, the arbitrator, and the `slash_amount` was
//! whatever the caller put in the signed body. Here every privileged market
//! operation takes an explicit [`Actor`]: a DID **and** the [`Authority`] it is
//! acting under. The signature on the domain object proves *who signed*; the
//! authority value proves *what they are entitled to do*, and the market checks
//! the two against each other.

use nau_core::Did;
use serde::{Deserialize, Serialize};

/// The capacity in which an actor is acting.
///
/// Deliberately not derived from the signed object: deriving the authority from
/// the object under check is how upstream ended up with "the caller decides".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    /// A party to a task: its requester or its assigned executor.
    Party,
    /// A neutral decider, who must not be a party to the dispute being ruled on.
    Arbitrator,
    /// The node operator, acting for the market itself.
    Operator,
}

impl Authority {
    /// A stable, machine-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Authority::Party => "party",
            Authority::Arbitrator => "arbitrator",
            Authority::Operator => "operator",
        }
    }
}

/// An authenticated principal: a DID plus the authority it is acting under.
///
/// The market never invents one of these from the object it is asked to accept.
/// A caller (an API principal, an MCP tool identity, a test) must construct it
/// explicitly, and [`crate::Market`] checks that the actor's DID is the DID that
/// signed the object *and* that the authority is one the operation accepts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Actor {
    did: Did,
    authority: Authority,
}

impl Actor {
    /// An actor acting as a party to a task.
    pub fn party(did: Did) -> Self {
        Self {
            did,
            authority: Authority::Party,
        }
    }

    /// An actor acting as a neutral arbitrator.
    pub fn arbitrator(did: Did) -> Self {
        Self {
            did,
            authority: Authority::Arbitrator,
        }
    }

    /// An actor acting as the market operator.
    pub fn operator(did: Did) -> Self {
        Self {
            did,
            authority: Authority::Operator,
        }
    }

    /// The DID this actor acts as.
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// The authority this actor claims.
    pub fn authority(&self) -> Authority {
        self.authority
    }
}

impl std::fmt::Display for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} as {}", self.did, self.authority.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nau_core::Identity;

    #[test]
    fn authority_is_explicit_and_constructors_do_not_guess() {
        let id = Identity::from_seed(&[7u8; 32]);
        assert_eq!(Actor::party(id.did()).authority(), Authority::Party);
        assert_eq!(
            Actor::arbitrator(id.did()).authority(),
            Authority::Arbitrator
        );
        assert_eq!(Actor::operator(id.did()).authority(), Authority::Operator);
        // The DID is carried as given, never re-derived from anything else.
        assert_eq!(Actor::party(id.did()).did(), &id.did());
        assert_eq!(Authority::Party.label(), "party");
    }
}
