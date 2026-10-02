//! Per-caller identity for the MCP surface: principals, scopes and the single
//! place a caller is turned into one.
//!
//! ## Why this module exists
//!
//! upstream v2.8.2 fix (finding 6): upstream's MCP-over-HTTP transport gates 15
//! mutating tools behind **one shared secret** with no per-caller identity and no
//! scopes. A single leaked string is therefore *every* caller's authority, no
//! audit line can say who acted, and no per-caller ownership rule is expressible.
//!
//! Here a caller is a [`Principal`] with a stable id and a set of [`Scope`]s:
//!
//! * a `Principal` is **only** obtainable in two ways — [`Principal::anonymous`],
//!   which is read-only, or [`Authenticator::authenticate`], which checks a
//!   credential against the configured token table. There is no public
//!   constructor that grants the write scope, so "authenticated" is a property of
//!   the type rather than a check a transport could forget;
//! * every transport must hand a `Principal` to
//!   [`crate::server::McpServer::dispatch`], the single dispatch point, which
//!   refuses a mutating tool for a principal without
//!   [`Scope::Write`] *before* any handler or validation runs;
//! * [`Authenticator::deny_all`] is the default: with nothing configured, no
//!   credential authenticates, so every mutating tool is refused.
//!
//! ## What is deliberately *not* here
//!
//! * No hashing of stored tokens. The comparison is byte-wise and
//!   length-independent for equal-length inputs; the *length* of a configured
//!   token is observable through timing. That is documented rather than papered
//!   over, and it is acceptable for a token that never leaves the local process
//!   environment. A networked deployment should put a real bearer-token layer in
//!   front of the transport.
//! * No session or expiry handling: a credential is evaluated per message.

use std::fmt;

use nau_core::{NauError, Result};

/// What a caller is allowed to do.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Scope {
    /// Read state. Every principal has this, including an anonymous one.
    Read,
    /// Mutate state. Only a caller who presented a valid credential has this.
    Write,
}

impl Scope {
    /// The wire name, used in configuration and in refusals.
    pub const fn label(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
        }
    }

    /// Parse a scope name. Unknown names are an error, never a silent default:
    /// a typo in a scope list must not widen a credential.
    pub fn parse(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "read" | "ro" => Ok(Scope::Read),
            "write" | "rw" | "mutate" => Ok(Scope::Write),
            other => Err(NauError::Validation(format!(
                "unknown scope `{other}`; expected `read` or `write`"
            ))),
        }
    }
}

/// A caller, as the server sees it.
///
/// Construct one with [`Principal::anonymous`] (read-only) or let an
/// [`Authenticator`] produce it from a credential. There is deliberately no way
/// to build a write-capable principal without a configured token.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Principal {
    id: String,
    did: Option<String>,
    scopes: Vec<Scope>,
}

impl Principal {
    /// The read-only principal used when no credential was presented.
    ///
    /// `anonymous` can never mutate: the write scope is absent from its scope
    /// list, and [`Principal::may`] is the only authority check in the crate.
    pub fn anonymous() -> Self {
        Self {
            id: "anonymous".to_string(),
            did: None,
            scopes: vec![Scope::Read],
        }
    }

    /// The caller's stable identity, for audit lines and refusals.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The DID this caller acts as, when the credential was bound to one.
    ///
    /// A principal bound to a DID may only act on the objects that DID owns; a
    /// principal with no DID is a service credential and carries no ownership
    /// binding (the market's own authorization still applies).
    pub fn did(&self) -> Option<&str> {
        self.did.as_deref()
    }

    /// The caller's scopes.
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Whether the caller holds `scope`.
    pub fn may(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// The single authorization decision.
    ///
    /// # Errors
    ///
    /// [`NauError::Unauthorized`] naming the principal, the scope it lacks and
    /// what it would have to present. Every refusal in this crate goes through
    /// this function, so the message a caller sees cannot drift.
    pub fn require(&self, scope: Scope) -> Result<()> {
        if self.may(scope) {
            return Ok(());
        }
        Err(NauError::Unauthorized(format!(
            "caller `{}` lacks the `{}` scope; present a credential configured with it",
            self.id,
            scope.label()
        )))
    }
}

/// A presented credential.
///
/// Wrapped so that it cannot be logged by accident: `Debug` prints
/// `<redacted credential>` and never the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
    /// Wrap a credential string.
    ///
    /// A blank credential is refused, because an empty bearer token that
    /// authenticates is an unauthenticated endpoint wearing a header.
    pub fn new(secret: impl Into<String>) -> Result<Self> {
        let secret = secret.into();
        if secret.trim().is_empty() {
            return Err(NauError::Validation(
                "a credential must not be empty or whitespace".into(),
            ));
        }
        Ok(Self(secret))
    }

    /// The `Authorization: Bearer <token>` form, which is what an HTTP transport
    /// receives.
    pub fn from_authorization_header(value: &str) -> Option<Self> {
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        Credential::new(token).ok()
    }

    /// The secret. Deliberately not `Deref`/`AsRef<str>`: reading it must be
    /// explicit at every call site.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted credential>")
    }
}

/// The configured token table: which credential is which caller.
///
/// The **default** is [`Authenticator::deny_all`]: with nothing configured, no
/// credential authenticates and no mutating tool can be called. That default is
/// the whole point of finding 6 — "unconfigured" must mean *refuse*, not *allow*.
#[derive(Clone, Default)]
pub struct Authenticator {
    entries: Vec<(String, Principal)>,
    token_env: Option<String>,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the tokens nor the principals' DIDs are printed.
        f.debug_struct("Authenticator")
            .field("configured_callers", &self.entries.len())
            .field("token_env", &self.token_env)
            .finish_non_exhaustive()
    }
}

/// The environment variable an [`Authenticator`] reads its *own* credential from
/// when a transport has no header to look at (the stdio transport).
pub const DEFAULT_TOKEN_ENV: &str = "NAU_MCP_TOKEN";

/// The environment variable holding the token table, as
/// `id:token[:did][:scope,scope]` entries separated by `;`.
pub const TOKENS_ENV: &str = "NAU_MCP_TOKENS";

impl Authenticator {
    /// An authenticator that accepts nothing.
    ///
    /// This is the default, and it is what makes "nothing configured" refuse
    /// rather than allow.
    pub fn deny_all() -> Self {
        Self {
            entries: Vec::new(),
            token_env: Some(DEFAULT_TOKEN_ENV.to_string()),
        }
    }

    /// Register `token` as caller `id` with `scopes`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] for a blank token, a blank id, an empty scope
    /// list, or a duplicate token (which would make the earlier caller
    /// unreachable and hide a configuration mistake).
    pub fn with_token(
        mut self,
        token: &str,
        id: &str,
        did: Option<&str>,
        scopes: &[Scope],
    ) -> Result<Self> {
        let credential = Credential::new(token)?;
        if id.trim().is_empty() {
            return Err(NauError::Validation(
                "a caller id must not be empty or whitespace".into(),
            ));
        }
        if scopes.is_empty() {
            return Err(NauError::Validation(format!(
                "caller `{id}` was configured with no scopes, so it could do nothing; list `read` \
                 and/or `write`"
            )));
        }
        let entry = (
            credential.expose().to_string(),
            Principal {
                id: id.trim().to_string(),
                did: did.map(|did| did.trim().to_string()),
                scopes: scopes.to_vec(),
            },
        );
        if self
            .entries
            .iter()
            .any(|(existing, _)| tokens_match(existing, &entry.0))
        {
            return Err(NauError::Conflict(
                "that credential is already registered to another caller".into(),
            ));
        }
        self.entries.push(entry);
        Ok(self)
    }

    /// How many callers are configured. Zero means every mutating tool is
    /// refused.
    pub fn configured_callers(&self) -> usize {
        self.entries.len()
    }

    /// The environment variable this authenticator presents as its own
    /// credential.
    pub fn token_env(&self) -> Option<&str> {
        self.token_env.as_deref()
    }

    /// Parse the token table from the process environment.
    ///
    /// `NAU_MCP_TOKENS` holds `id:token[:did][:scope,scope]` entries separated by
    /// `;`. A malformed entry **fails the whole parse** rather than being skipped:
    /// silently dropping a caller's credential turns a configuration mistake into
    /// a mysterious refusal, and silently *keeping* a half-parsed one could widen
    /// it.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] naming the malformed entry.
    pub fn from_env() -> Result<Self> {
        let mut authenticator = Self::deny_all();
        let Ok(raw) = std::env::var(TOKENS_ENV) else {
            return Ok(authenticator);
        };
        for entry in raw.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let fields: Vec<&str> = entry.split(':').collect();
            if fields.len() < 2 {
                return Err(NauError::Validation(format!(
                    "`{TOKENS_ENV}` entry `{entry}` is not `id:token[:did][:scope,scope]`"
                )));
            }
            let id = fields[0];
            let token = fields[1];
            let did = fields.get(2).copied().filter(|did| !did.trim().is_empty());
            let scopes: Vec<Scope> = match fields.get(3) {
                Some(list) => list
                    .split(',')
                    .map(Scope::parse)
                    .collect::<Result<Vec<Scope>>>()?,
                // A credential with no explicit scope list is read-only. Failing
                // closed here means a truncated configuration cannot accidentally
                // grant write access.
                None => vec![Scope::Read],
            };
            authenticator = authenticator.with_token(token, id, did, &scopes)?;
        }
        Ok(authenticator)
    }

    /// The credential this process was handed, for a transport with no header.
    ///
    /// Returns `None` when the variable is unset or blank, which callers must
    /// treat as [`Principal::anonymous`] — never as "trusted".
    pub fn credential_from_env(&self) -> Option<Credential> {
        let name = self.token_env.as_deref()?;
        let value = std::env::var(name).ok()?;
        Credential::new(value).ok()
    }

    /// Resolve a credential into a principal.
    ///
    /// # Errors
    ///
    /// [`NauError::Unauthorized`] when no credential was presented or it matches
    /// no configured caller. A missing credential never degrades to an
    /// authenticated principal: the caller must decide explicitly to fall back to
    /// [`Principal::anonymous`], which cannot mutate.
    pub fn authenticate(&self, credential: Option<&Credential>) -> Result<Principal> {
        let Some(credential) = credential else {
            return Err(NauError::Unauthorized(
                "no credential was presented; every mutating tool requires one".into(),
            ));
        };
        for (token, principal) in &self.entries {
            if tokens_match(token, credential.expose()) {
                return Ok(principal.clone());
            }
        }
        Err(NauError::Unauthorized(format!(
            "the presented credential matches none of the {} configured caller(s)",
            self.entries.len()
        )))
    }

    /// Resolve a credential, falling back to the read-only anonymous principal.
    ///
    /// This is the convenience a *transport* uses: an unauthenticated message is
    /// still served, but as a read-only caller, so a `tools/call` for a mutating
    /// tool is refused by [`crate::server::McpServer::dispatch`].
    pub fn principal_or_anonymous(&self, credential: Option<&Credential>) -> Principal {
        self.authenticate(credential)
            .unwrap_or_else(|_| Principal::anonymous())
    }
}

/// Compare two secrets without an early exit on the first differing byte.
///
/// The length is compared first, so the *length* of a configured token is
/// observable through timing; the contents are not. This is documented in the
/// module header rather than hidden, and it is why the module also says a
/// networked deployment belongs behind a real bearer-token layer.
fn tokens_match(configured: &str, presented: &str) -> bool {
    let configured = configured.as_bytes();
    let presented = presented.as_bytes();
    if configured.len() != presented.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in configured.iter().zip(presented.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unconfigured_authenticator_accepts_nothing() {
        let authenticator = Authenticator::deny_all();
        assert_eq!(authenticator.configured_callers(), 0);
        assert!(authenticator.authenticate(None).is_err());
        let credential = Credential::new("anything").expect("a non-blank credential");
        assert!(
            authenticator.authenticate(Some(&credential)).is_err(),
            "an unconfigured authenticator must refuse, not allow"
        );
        let principal = authenticator.principal_or_anonymous(Some(&credential));
        assert!(!principal.may(Scope::Write));
        assert_eq!(principal.id(), "anonymous");
    }

    #[test]
    fn a_configured_token_maps_to_its_own_principal() {
        let authenticator = Authenticator::deny_all()
            .with_token(
                "secret-a",
                "alice",
                Some("did:nau:aaaa"),
                &[Scope::Read, Scope::Write],
            )
            .expect("configures")
            .with_token("secret-b", "bob", Some("did:nau:bbbb"), &[Scope::Read])
            .expect("configures");

        assert_eq!(authenticator.configured_callers(), 2);

        let alice = authenticator
            .authenticate(Some(&Credential::new("secret-a").expect("ok")))
            .expect("alice's token works");
        assert_eq!(alice.id(), "alice");
        assert_eq!(alice.did(), Some("did:nau:aaaa"));
        assert!(alice.may(Scope::Write));

        let bob = authenticator
            .authenticate(Some(&Credential::new("secret-b").expect("ok")))
            .expect("bob's token works");
        assert_eq!(bob.id(), "bob");
        assert!(
            !bob.may(Scope::Write),
            "one caller's scopes must not leak into another's"
        );
        assert!(bob.require(Scope::Write).is_err());

        assert!(authenticator
            .authenticate(Some(&Credential::new("secret-a ").expect("ok")))
            .is_err());
    }

    #[test]
    fn a_blank_or_duplicate_credential_is_refused() {
        assert!(Credential::new("").is_err());
        assert!(Credential::new("   ").is_err());
        let authenticator = Authenticator::deny_all()
            .with_token("same", "alice", None, &[Scope::Write])
            .expect("configures");
        assert!(authenticator
            .with_token("same", "bob", None, &[Scope::Write])
            .is_err());
        assert!(Authenticator::deny_all()
            .with_token("t", "nobody", None, &[])
            .is_err());
    }

    #[test]
    fn a_credential_never_prints_its_secret() {
        let credential = Credential::new("super-secret").expect("ok");
        let printed = format!("{credential:?}");
        assert!(!printed.contains("super-secret"), "{printed}");
        assert_eq!(printed, "<redacted credential>");
    }

    #[test]
    fn the_bearer_header_form_is_parsed_and_anything_else_is_not() {
        assert_eq!(
            Credential::from_authorization_header("Bearer abc")
                .expect("bearer")
                .expose(),
            "abc"
        );
        assert!(Credential::from_authorization_header("bearer abc").is_some());
        assert!(Credential::from_authorization_header("Basic abc").is_none());
        assert!(Credential::from_authorization_header("Bearer ").is_none());
        assert!(Credential::from_authorization_header("abc").is_none());
    }

    #[test]
    fn an_unknown_scope_name_is_an_error_not_a_default() {
        assert_eq!(Scope::parse("read").expect("read"), Scope::Read);
        assert_eq!(Scope::parse("WRITE").expect("write"), Scope::Write);
        assert!(Scope::parse("admin").is_err());
    }
}
