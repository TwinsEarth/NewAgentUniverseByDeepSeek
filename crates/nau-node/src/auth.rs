//! Authentication, caller identity and cross-origin policy for the privileged
//! local API — **one small module**, so another agent's changes to the router's
//! state can merge with it.
//!
//! ## What upstream v2.8.2 did instead
//!
//! upstream v2.8.2 fix (finding 6): upstream's REST twins of the mutating tools
//! are called with no authentication at all (`node.rs:1107-1152` calls the router
//! with nothing), while its MCP-over-HTTP path gates 15 mutating tools behind a
//! single shared secret with no per-caller identity and no scopes. A web page the
//! operator merely *visits* can therefore drive the daemon, and no rule of the
//! form "this caller may only touch its own account" can be expressed.
//!
//! upstream v2.8.2 fix (finding 7): upstream answers with
//! `Access-Control-Allow-Origin: *` and validates neither `Origin` nor `Host`
//! (`node.rs:741-746`), which is the same exposure with a friendlier header.
//!
//! ## What this module guarantees
//!
//! * **Unconfigured means refuse.** [`Authenticator::deny_all`] is the default:
//!   with no tokens configured, no credential authenticates, so every mutating
//!   route is refused. There is no "allow if nothing is configured" branch.
//! * **One identity per caller.** A configured token maps to a [`Principal`] with
//!   a stable id, an optional DID, and a set of [`Scope`]s. A principal can only
//!   carry write authority if a token was configured for it — there is no public
//!   constructor that grants it.
//! * **Per-caller ownership.** When a principal is bound to a DID, a mutating
//!   request whose body names a different actor is refused (see
//!   [`crate::api::require_actor`]). A credential configured *without* a DID is a
//!   service credential and is not identity-bound; that is a deliberate,
//!   documented privilege, not an accident.
//! * **No wildcard CORS, and a hostile `Origin` is never echoed.** A request that
//!   carries an `Origin` is refused unless that origin is explicitly
//!   allow-listed; an allowed origin is echoed *exactly*, one value, with
//!   `Vary: Origin`. `Host` is checked too, because DNS rebinding reaches a
//!   loopback daemon through a *hostname* the browser resolves to 127.0.0.1.
//! * **No dependency on the environment at construction time.** [`ApiPolicy`] is
//!   plain data, so the router stays a pure function and every rule below is
//!   testable without a socket.

use std::fmt;

use nau_core::{Did, NauError, Result};

/// What a caller is allowed to do.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Scope {
    /// Read state: the `GET` routes.
    Read,
    /// Mutate state: publishing, bidding, depositing, settling.
    Write,
    /// Decide disputes, which can slash another account's stake.
    Admin,
}

impl Scope {
    /// The wire name, used in configuration and in refusals.
    pub const fn label(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
            Scope::Admin => "admin",
        }
    }

    /// Parse a scope name. An unknown name is an error, never a default: a typo
    /// in a scope list must not widen a credential.
    pub fn parse(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "read" | "ro" => Ok(Scope::Read),
            "write" | "rw" | "mutate" => Ok(Scope::Write),
            "admin" => Ok(Scope::Admin),
            other => Err(NauError::Validation(format!(
                "unknown scope `{other}`; expected `read`, `write` or `admin`"
            ))),
        }
    }
}

/// A caller, as the API sees it.
///
/// Construct one with [`Principal::anonymous`] (read-only) or let an
/// [`Authenticator`] produce it from a credential. There is deliberately no way
/// to build a write-capable principal without a configured token.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Principal {
    id: String,
    did: Option<Did>,
    scopes: Vec<Scope>,
}

impl Principal {
    /// The read-only principal used when no credential was presented.
    ///
    /// It cannot mutate: the write scope is absent, and
    /// [`Principal::require`] is the only authority check.
    pub fn anonymous() -> Self {
        Self {
            id: "anonymous".to_string(),
            did: None,
            scopes: vec![Scope::Read],
        }
    }

    /// The caller's stable identity, for logs and refusals.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The DID this caller acts as, when the credential was bound to one.
    pub fn did(&self) -> Option<&Did> {
        self.did.as_ref()
    }

    /// The caller's scopes.
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Whether the caller holds `scope`.
    pub fn may(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }

    /// The single authority check.
    ///
    /// # Errors
    ///
    /// [`NauError::Unauthorized`] naming the caller, the scope it lacks and what
    /// it would have to present.
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
/// Wrapped so it cannot be logged by accident: `Debug` prints
/// `<redacted credential>`.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(String);

impl Credential {
    /// Wrap a credential string.
    ///
    /// A blank credential is refused: an empty bearer token that authenticates is
    /// an unauthenticated endpoint wearing a header.
    pub fn new(secret: impl Into<String>) -> Result<Self> {
        let secret = secret.into();
        if secret.trim().is_empty() {
            return Err(NauError::Validation(
                "a credential must not be empty or whitespace".into(),
            ));
        }
        Ok(Self(secret))
    }

    /// Parse `Authorization: Bearer <token>`.
    pub fn from_authorization_header(value: &str) -> Option<Self> {
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        Credential::new(token).ok()
    }

    /// The secret. Reading it must be explicit at every call site.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted credential>")
    }
}

/// The environment variable holding the token table, as
/// `id:token[:did][:scope,scope]` entries separated by `;`.
pub const TOKENS_ENV: &str = "NAU_API_TOKENS";

/// The environment variable that explicitly re-opens anonymous writes.
///
/// **Development only.** The default is to refuse, and the operator has to ask
/// for this by name (`NAU_API_ALLOW_ANONYMOUS_WRITES=1`) *and* bind a loopback
/// address (enforced in [`crate::api::serve`]). It exists so a local script or a
/// desktop client that has no token yet can still talk to a loopback daemon
/// during the migration to authenticated callers; using it on a routable address
/// is refused outright.
pub const ANONYMOUS_WRITES_ENV: &str = "NAU_API_ALLOW_ANONYMOUS_WRITES";

/// The configured token table, plus the anonymous-write escape hatch.
///
/// Default: [`Authenticator::deny_all`] — nothing configured, nothing mutates.
#[derive(Clone, Default)]
pub struct Authenticator {
    entries: Vec<(String, Principal)>,
    anonymous_writes: bool,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the tokens nor the principals are printed: a `Debug` of the
        // node's configuration must be safe to log.
        f.debug_struct("Authenticator")
            .field("configured_callers", &self.entries.len())
            .field("anonymous_writes", &self.anonymous_writes)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// An authenticator that accepts nothing and refuses every mutation.
    pub fn deny_all() -> Self {
        Self {
            entries: Vec::new(),
            anonymous_writes: false,
        }
    }

    /// Register `token` as caller `id` with `scopes`.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] for a blank token or id, an empty scope list, or
    /// a DID that does not parse; [`NauError::Conflict`] for a duplicate token,
    /// which would leave the earlier caller unreachable.
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
                "caller `{id}` was configured with no scopes, so it could do nothing; list `read`, \
                 `write` and/or `admin`"
            )));
        }
        let did = match did {
            Some(did) if !did.trim().is_empty() => {
                Some(Did::parse(did.trim()).map_err(|error| {
                    NauError::Validation(format!(
                        "caller `{id}` was bound to an invalid DID: {error}"
                    ))
                })?)
            }
            _ => None,
        };
        if self
            .entries
            .iter()
            .any(|(existing, _)| tokens_match(existing, credential.expose()))
        {
            return Err(NauError::Conflict(
                "that credential is already registered to another caller".into(),
            ));
        }
        self.entries.push((
            credential.expose().to_string(),
            Principal {
                id: id.trim().to_string(),
                did,
                scopes: scopes.to_vec(),
            },
        ));
        Ok(self)
    }

    /// Re-open anonymous writes, explicitly.
    ///
    /// See [`ANONYMOUS_WRITES_ENV`]: this is the documented escape hatch for a
    /// loopback development daemon, and [`crate::api::serve`] refuses to honour it
    /// on a non-loopback bind.
    pub fn with_anonymous_writes(mut self, allowed: bool) -> Self {
        self.anonymous_writes = allowed;
        self
    }

    /// How many callers are configured. Zero means every mutating route is
    /// refused unless anonymous writes were explicitly enabled.
    pub fn configured_callers(&self) -> usize {
        self.entries.len()
    }

    /// Whether anonymous writes were explicitly enabled.
    pub fn anonymous_writes_allowed(&self) -> bool {
        self.anonymous_writes
    }

    /// Parse the token table from the process environment.
    ///
    /// `NAU_API_TOKENS` holds `id:token[:did][:scope,scope]` entries separated by
    /// `;`; `NAU_API_ALLOW_ANONYMOUS_WRITES=1` enables the escape hatch. A
    /// malformed entry **fails the whole parse** rather than being skipped.
    ///
    /// # Errors
    ///
    /// [`NauError::Validation`] naming the malformed entry or scope.
    pub fn from_env() -> Result<Self> {
        let mut authenticator = Self::deny_all();
        if let Ok(raw) = std::env::var(TOKENS_ENV) {
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
                    // A credential with no explicit scope list is read-only:
                    // failing closed means a truncated configuration cannot
                    // accidentally grant write access.
                    None => vec![Scope::Read],
                };
                authenticator = authenticator.with_token(token, id, did, &scopes)?;
            }
        }
        let anonymous = std::env::var(ANONYMOUS_WRITES_ENV)
            .map(|value| value.trim() == "1")
            .unwrap_or(false);
        Ok(authenticator.with_anonymous_writes(anonymous))
    }

    /// Resolve a presented credential into a principal.
    ///
    /// A credential that matches nothing yields [`Principal::anonymous`] (unless
    /// anonymous writes were explicitly enabled, in which case the anonymous
    /// principal is granted the write scope). A *presented but unknown* credential
    /// is refused by [`ApiPolicy::authorize`], never upgraded.
    pub fn resolve(&self, credential: Option<&Credential>) -> Principal {
        match credential {
            Some(credential) => self
                .entries
                .iter()
                .find(|(token, _)| tokens_match(token, credential.expose()))
                .map(|(_, principal)| principal.clone())
                .unwrap_or_else(|| self.anonymous()),
            None => self.anonymous(),
        }
    }

    /// The anonymous principal, with the write scope when the operator asked for
    /// it by name.
    fn anonymous(&self) -> Principal {
        let mut principal = Principal::anonymous();
        if self.anonymous_writes {
            principal.scopes.push(Scope::Write);
        }
        principal
    }

    /// Whether the credential authenticates a configured caller.
    pub fn authenticates(&self, credential: &Credential) -> bool {
        self.entries
            .iter()
            .any(|(token, _)| tokens_match(token, credential.expose()))
    }
}

/// Compare two secrets without an early exit on the first differing byte.
///
/// The length is compared first, so the *length* of a configured token is
/// observable through timing; the contents are not. Documented rather than
/// hidden, and the reason a routable deployment belongs behind a real
/// bearer-token layer.
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

/// Why a request was refused, and what HTTP status that is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// No credential was presented for a route that requires one.
    MissingCredential {
        /// The scope the route requires.
        scope: Scope,
    },
    /// A credential was presented but matches no configured caller.
    UnknownCredential,
    /// The credential authenticated, but the caller lacks the scope.
    InsufficientScope {
        /// The caller's id.
        caller: String,
        /// The scope it lacks.
        scope: Scope,
    },
    /// The `Authorization` header is not `Bearer <token>`.
    MalformedCredential,
    /// The caller acts as another identity.
    WrongActor {
        /// The caller's id.
        caller: String,
        /// The DID the caller is bound to.
        did: String,
        /// The actor the request named.
        claimed: String,
    },
    /// The request carries an `Origin` that is not allow-listed.
    ForbiddenOrigin {
        /// The origin that was refused.
        origin: String,
    },
    /// The `Host` header is not one this deployment serves.
    ForbiddenHost {
        /// The host that was refused.
        host: String,
    },
}

impl Refusal {
    /// The HTTP status for this refusal.
    ///
    /// A missing or unusable credential is `401` (the caller can fix it by
    /// authenticating); an authenticated caller that lacks authority, a
    /// cross-origin request and a wrong-actor request are `403`.
    pub fn status(&self) -> u16 {
        match self {
            Refusal::MissingCredential { .. }
            | Refusal::UnknownCredential
            | Refusal::MalformedCredential => 401,
            Refusal::InsufficientScope { .. }
            | Refusal::WrongActor { .. }
            | Refusal::ForbiddenOrigin { .. }
            | Refusal::ForbiddenHost { .. } => 403,
        }
    }

    /// A machine-readable code, used as the `error` field of the body.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::MissingCredential { .. } => "credential_required",
            Refusal::UnknownCredential => "unknown_credential",
            Refusal::MalformedCredential => "malformed_credential",
            Refusal::InsufficientScope { .. } => "insufficient_scope",
            Refusal::WrongActor { .. } => "wrong_actor",
            Refusal::ForbiddenOrigin { .. } => "forbidden_origin",
            Refusal::ForbiddenHost { .. } => "forbidden_host",
        }
    }

    /// What to tell the caller.
    pub fn message(&self) -> String {
        match self {
            Refusal::MissingCredential { scope } => format!(
                "this route requires authentication with the `{}` scope; send \
                 `Authorization: Bearer <token>` (no caller is configured, so this deployment \
                 refuses mutating requests by default)",
                scope.label()
            ),
            Refusal::UnknownCredential => {
                "the presented credential matches no configured caller".to_string()
            }
            Refusal::InsufficientScope { caller, scope } => {
                format!("caller `{caller}` lacks the `{}` scope", scope.label())
            }
            Refusal::MalformedCredential => {
                "the `Authorization` header must be `Bearer <token>`".to_string()
            }
            Refusal::WrongActor {
                caller,
                did,
                claimed,
            } => format!("caller `{caller}` acts as `{did}` and may not act for `{claimed}`"),
            Refusal::ForbiddenOrigin { origin } => format!(
                "cross-origin requests are refused: `{origin}` is not an allow-listed origin"
            ),
            Refusal::ForbiddenHost { host } => format!(
                "the `Host` header `{host}` is not a host this API serves (a loopback bind serves \
                 loopback names only)"
            ),
        }
    }
}

/// The whole request policy: who may call, and from where.
#[derive(Clone, Debug)]
pub struct ApiPolicy {
    authenticator: Authenticator,
    allowed_origins: Vec<String>,
    allowed_hosts: Vec<String>,
    allow_loopback_hosts: bool,
}

impl Default for ApiPolicy {
    fn default() -> Self {
        Self {
            authenticator: Authenticator::deny_all(),
            allowed_origins: Vec::new(),
            allowed_hosts: Vec::new(),
            allow_loopback_hosts: true,
        }
    }
}

impl ApiPolicy {
    /// A policy that refuses every mutation and every cross-origin request.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Build from the process environment.
    ///
    /// # Errors
    ///
    /// Propagates [`Authenticator::from_env`].
    pub fn from_env() -> Result<Self> {
        let mut policy = Self {
            authenticator: Authenticator::from_env()?,
            ..Self::default()
        };
        if let Ok(origins) = std::env::var("NAU_API_ORIGINS") {
            for origin in origins.split(',').map(str::trim).filter(|o| !o.is_empty()) {
                policy = policy.allow_origin(origin);
            }
        }
        if let Ok(hosts) = std::env::var("NAU_API_HOSTS") {
            for host in hosts.split(',').map(str::trim).filter(|h| !h.is_empty()) {
                policy = policy.allow_host(host);
            }
        }
        Ok(policy)
    }

    /// Replace the authenticator.
    pub fn with_authenticator(mut self, authenticator: Authenticator) -> Self {
        self.authenticator = authenticator;
        self
    }

    /// Allow one exact origin, e.g. `http://127.0.0.1:1420`.
    ///
    /// `*` is refused: a wildcard on a privileged local API is the defect this
    /// module exists to remove, and accepting the string would let an operator
    /// re-introduce it by configuration.
    ///
    /// # Panics
    ///
    /// Never. A `*` is ignored rather than panicking, and a test asserts that.
    pub fn allow_origin(mut self, origin: &str) -> Self {
        let origin = origin.trim();
        if origin.is_empty() || origin == "*" || origin.contains('*') {
            return self;
        }
        if !self.allowed_origins.iter().any(|known| known == origin) {
            self.allowed_origins.push(origin.to_string());
        }
        self
    }

    /// Allow one exact `Host` value, e.g. `nau.internal:4002`.
    pub fn allow_host(mut self, host: &str) -> Self {
        let host = host.trim();
        if host.is_empty() || host.contains('*') {
            return self;
        }
        if !self.allowed_hosts.iter().any(|known| known == host) {
            self.allowed_hosts.push(host.to_string());
        }
        self
    }

    /// Stop accepting the usual loopback names in `Host`.
    pub fn without_loopback_hosts(mut self) -> Self {
        self.allow_loopback_hosts = false;
        self
    }

    /// The authenticator.
    pub fn authenticator(&self) -> &Authenticator {
        &self.authenticator
    }

    /// The allow-listed origins, in configuration order.
    pub fn allowed_origins(&self) -> &[String] {
        &self.allowed_origins
    }

    /// Whether `origin` may drive this API.
    ///
    /// A request **without** an `Origin` header is not a browser request (a
    /// browser sends the header on every cross-origin request, including a plain
    /// form POST and a `no-cors` fetch) and is not subject to this check; `Host`
    /// covers it instead.
    pub fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|known| known == origin)
    }

    /// Whether `host` is a name this deployment answers to.
    ///
    /// DNS rebinding is why this exists: a hostile page can make its own hostname
    /// resolve to `127.0.0.1`, and the `Origin` check alone does not stop a
    /// request that the browser considers same-origin.
    pub fn host_allowed(&self, host: &str) -> bool {
        if host.trim().is_empty() {
            // No `Host` at all: an HTTP/1.0 client or a local tool. Admission
            // still requires a credential for a mutating route.
            return true;
        }
        if self.allowed_hosts.iter().any(|known| known == host) {
            return true;
        }
        if !self.allow_loopback_hosts {
            return false;
        }
        let name = host_name(host);
        matches!(name, "127.0.0.1" | "localhost" | "::1" | "[::1]")
    }

    /// Check the transport-level rules that apply to **every** request.
    ///
    /// # Errors
    ///
    /// [`Refusal::ForbiddenOrigin`] or [`Refusal::ForbiddenHost`].
    pub fn check_transport(
        &self,
        origin: Option<&str>,
        host: Option<&str>,
    ) -> std::result::Result<(), Refusal> {
        if let Some(origin) = origin.map(str::trim).filter(|o| !o.is_empty()) {
            if !self.origin_allowed(origin) {
                return Err(Refusal::ForbiddenOrigin {
                    origin: origin.to_string(),
                });
            }
        }
        if let Some(host) = host {
            if !self.host_allowed(host) {
                return Err(Refusal::ForbiddenHost {
                    host: host.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Authenticate the request and require `scope`.
    ///
    /// This is the single authorization entry point the router uses.
    ///
    /// # Errors
    ///
    /// * [`Refusal::MalformedCredential`] when an `Authorization` header is
    ///   present but is not `Bearer <token>`, or is blank;
    /// * [`Refusal::MissingCredential`] when the route requires a scope and no
    ///   credential was presented;
    /// * [`Refusal::UnknownCredential`] when the credential matches no configured
    ///   caller — a *presented* credential is never downgraded to anonymous;
    /// * [`Refusal::InsufficientScope`] when it authenticates but lacks `scope`.
    pub fn authorize(
        &self,
        authorization: Option<&str>,
        scope: Scope,
    ) -> std::result::Result<Principal, Refusal> {
        let credential = match authorization
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(header) => match Credential::from_authorization_header(header) {
                Some(credential) => Some(credential),
                None => return Err(Refusal::MalformedCredential),
            },
            None => None,
        };
        if let Some(credential) = &credential {
            if !self.authenticator.authenticates(credential) {
                return Err(Refusal::UnknownCredential);
            }
        }
        let principal = self.authenticator.resolve(credential.as_ref());
        if !principal.may(scope) {
            return Err(match credential {
                Some(_) => Refusal::InsufficientScope {
                    caller: principal.id().to_string(),
                    scope,
                },
                None => Refusal::MissingCredential { scope },
            });
        }
        Ok(principal)
    }
}

/// The host part of a `Host` header, without the port.
///
/// Handles the bracketed IPv6 form (`[::1]:4002`), because splitting on `:` would
/// turn `::1` into an empty string and admit it by accident.
fn host_name(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((name, _)) => name,
            None => host,
        };
    }
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE_DID: &str = "did:nau:1111111111111111";
    const BOB_DID: &str = "did:nau:2222222222222222";

    fn policy() -> ApiPolicy {
        ApiPolicy::deny_all().with_authenticator(
            Authenticator::deny_all()
                .with_token(
                    "a-token",
                    "alice",
                    Some(ALICE_DID),
                    &[Scope::Read, Scope::Write],
                )
                .expect("configures")
                .with_token(
                    "b-token",
                    "bob",
                    Some(BOB_DID),
                    &[Scope::Read, Scope::Write],
                )
                .expect("configures")
                .with_token("svc-token", "service", None, &[Scope::Read, Scope::Write])
                .expect("configures")
                .with_token("arb-token", "arbiter", None, &[Scope::Read, Scope::Admin])
                .expect("configures"),
        )
    }

    #[test]
    fn nothing_configured_refuses_every_write() {
        // The central claim of finding 6: unconfigured means *refuse*. A read is
        // still served — an anonymous caller holds the read scope, and only the
        // read scope — so the two halves of the policy are asserted together.
        let policy = ApiPolicy::deny_all();
        assert_eq!(policy.authenticator().configured_callers(), 0);
        assert!(!policy.authenticator().anonymous_writes_allowed());

        let reader = policy
            .authorize(None, Scope::Read)
            .expect("an anonymous read is served");
        assert_eq!(reader.id(), "anonymous");
        assert!(!reader.may(Scope::Write));
        assert!(!reader.may(Scope::Admin));

        for scope in [Scope::Write, Scope::Admin] {
            let error = policy
                .authorize(None, scope)
                .expect_err("no credential authenticates a mutation");
            assert_eq!(error.status(), 401);
            assert!(matches!(error, Refusal::MissingCredential { .. }));
        }
        // Even a credential that looks plausible.
        let error = policy
            .authorize(Some("Bearer anything"), Scope::Write)
            .expect_err("an unconfigured deployment refuses");
        assert_eq!(error, Refusal::UnknownCredential);
    }

    #[test]
    fn anonymous_writes_must_be_asked_for_by_name() {
        let policy = ApiPolicy::deny_all()
            .with_authenticator(Authenticator::deny_all().with_anonymous_writes(true));
        let principal = policy
            .authorize(None, Scope::Write)
            .expect("explicitly allowed");
        assert_eq!(principal.id(), "anonymous");
        assert!(principal.may(Scope::Write));
        assert!(
            !principal.may(Scope::Admin),
            "the escape hatch grants write, never admin"
        );
    }

    #[test]
    fn the_same_token_is_always_the_same_principal() {
        let policy = policy();
        let alice = policy
            .authorize(Some("Bearer a-token"), Scope::Write)
            .expect("alice");
        assert_eq!(alice.id(), "alice");
        assert_eq!(alice.did().map(Did::to_string), Some(ALICE_DID.to_string()));
        assert!(alice.may(Scope::Write));
        assert!(!alice.may(Scope::Admin));

        // A different token is a different principal with different authority.
        let arbiter = policy
            .authorize(Some("Bearer arb-token"), Scope::Admin)
            .expect("arbiter");
        assert_eq!(arbiter.id(), "arbiter");
        assert!(arbiter.require(Scope::Write).is_err());

        // A service credential carries no DID, so it is not identity-bound.
        let service = policy
            .authorize(Some("Bearer svc-token"), Scope::Write)
            .expect("service");
        assert!(service.did().is_none());
    }

    #[test]
    fn a_presented_credential_is_never_downgraded_to_anonymous() {
        let policy = policy();
        for header in [
            "Bearer not-configured",
            "Basic a-token",
            "Bearer ",
            "a-token",
            "bearer",
        ] {
            let error = policy
                .authorize(Some(header), Scope::Read)
                .expect_err("a header that does not authenticate must not become anonymous");
            assert!(
                matches!(
                    error,
                    Refusal::UnknownCredential | Refusal::MalformedCredential
                ),
                "for `{header}`: {error:?}"
            );
            assert_eq!(error.status(), 401);
        }
    }

    #[test]
    fn a_credential_error_never_mentions_the_secret() {
        let policy = policy();
        let error = policy
            .authorize(Some("Bearer a-token-that-is-wrong"), Scope::Write)
            .expect_err("refused");
        let rendered = format!("{error:?} {}", error.message());
        assert!(!rendered.contains("a-token-that-is-wrong"), "{rendered}");
        let credential = Credential::new("super-secret").expect("ok");
        assert_eq!(format!("{credential:?}"), "<redacted credential>");
    }

    #[test]
    fn a_wildcard_origin_is_refused_at_configuration() {
        let policy = ApiPolicy::deny_all()
            .allow_origin("*")
            .allow_origin("http://x/*");
        assert!(
            policy.allowed_origins().is_empty(),
            "a wildcard must never be allow-listed: {:?}",
            policy.allowed_origins()
        );
        let policy = policy.allow_origin("http://127.0.0.1:1420");
        assert!(policy.origin_allowed("http://127.0.0.1:1420"));
        assert!(!policy.origin_allowed("http://127.0.0.1:1421"));
        assert!(
            !policy.origin_allowed("http://evil.example"),
            "a hostile origin is never allowed"
        );
    }

    #[test]
    fn transport_checks_admit_loopback_and_refuse_everything_else() {
        let policy = policy();
        // No Origin (not a browser request) and a loopback Host: admitted.
        assert!(policy.check_transport(None, Some("127.0.0.1:4002")).is_ok());
        assert!(policy.check_transport(None, Some("localhost:4002")).is_ok());
        assert!(policy.check_transport(None, Some("[::1]:4002")).is_ok());
        assert!(policy.check_transport(None, None).is_ok());
        // A hostile Origin is refused even with a good Host.
        let error = policy
            .check_transport(Some("http://evil.example"), Some("127.0.0.1:4002"))
            .expect_err("a hostile origin is refused");
        assert_eq!(error.status(), 403);
        // A rebinding Host is refused even with no Origin.
        let error = policy
            .check_transport(None, Some("evil.example"))
            .expect_err("a non-loopback host is refused");
        assert_eq!(error.status(), 403);
        // A configured origin and host are admitted.
        let policy = policy
            .allow_origin("http://127.0.0.1:1420")
            .allow_host("nau.internal:4002");
        assert!(policy
            .check_transport(Some("http://127.0.0.1:1420"), Some("nau.internal:4002"))
            .is_ok());
        assert!(policy
            .check_transport(Some("http://127.0.0.1:1420"), Some("evil.example"))
            .is_err());
    }

    #[test]
    fn a_malformed_token_table_fails_rather_than_being_skipped() {
        // Exercised through the parser's rules rather than the process
        // environment, so the test cannot race another test in this binary.
        assert!(Authenticator::deny_all()
            .with_token("", "x", None, &[Scope::Read])
            .is_err());
        assert!(Authenticator::deny_all()
            .with_token("t", "  ", None, &[Scope::Read])
            .is_err());
        assert!(Authenticator::deny_all()
            .with_token("t", "x", None, &[])
            .is_err());
        assert!(Authenticator::deny_all()
            .with_token("t", "x", Some("not-a-did"), &[Scope::Read])
            .is_err());
        assert!(Scope::parse("admin").is_ok());
        assert!(Scope::parse("root").is_err());
        let duplicate = Authenticator::deny_all()
            .with_token("same", "alice", None, &[Scope::Read])
            .expect("configures");
        assert!(duplicate
            .with_token("same", "bob", None, &[Scope::Read])
            .is_err());
    }

    #[test]
    fn the_scope_ladder_is_ordered_and_named() {
        assert!(Scope::Read < Scope::Write);
        assert!(Scope::Write < Scope::Admin);
        assert_eq!(Scope::Write.label(), "write");
    }
}
