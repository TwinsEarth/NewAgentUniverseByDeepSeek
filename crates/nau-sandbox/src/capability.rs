//! Capabilities: what a backend is able to enforce, and the refusal that turns
//! every other policy field into a decision rather than a comment.
//!
//! ## The rule
//!
//! A boundary that is documented but not enforced is worse than no boundary,
//! because it launders trust. So a policy field has exactly two possible fates:
//!
//! 1. the backend declares the matching [`Capability`] and enforces it, or
//! 2. [`crate::executor::SandboxExecutor::validate`] fails with
//!    [`SandboxError::PolicyNotEnforceable`], naming the boundary.
//!
//! There is no third fate. In particular there is no `bool` that a caller can
//! ignore by accident: [`check_boundary`] returns `Result<(), SandboxError>`.
//!
//! Upstream v2.8.2 fix: `NetworkGuard::check_egress` (`security.rs:55-78`),
//! `PermissionChecker::check` (`:188`), `AuditLog::append` and
//! `ExecutionToken::authorize` had **zero** production callers, so "default deny
//! egress" was documentation only and sandboxed code had unbounded egress. Here
//! the boundary is a value that a backend must publish, and a policy field that
//! no backend publishes is refused by name.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SandboxError};

/// A boundary a backend can enforce.
///
/// # Naming
///
/// Variants are named after the *mechanism-independent* boundary, not the
/// syscall, because the whole point is that two backends can agree on the
/// boundary while implementing it differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Capability {
    /// The child's environment is constructed from an explicit allowlist; the
    /// daemon's own environment is never inherited.
    EnvAllowlist,
    /// stdout/stderr are capped in the parent, and truncation is reported.
    OutputCap,
    /// The sandbox is killed after `timeout_ms`, including its whole process
    /// tree, not just the direct child.
    Timeout,
    /// The child's `current_dir` is a directory created for this sandbox alone,
    /// under a root fixed at process start.
    WorkDirIsolation,
    /// Outbound network access can actually be denied.
    NetworkDenyAll,
    /// Outbound network access can be restricted to a named destination set.
    NetworkAllowList,
    /// Address-space / commit memory can be capped and overruns kill the process.
    MemoryLimit,
    /// CPU time can be capped.
    CpuLimit,
    /// Bytes written to disk can be capped.
    DiskQuota,
    /// The number of processes in the sandbox can be capped.
    ProcessCountLimit,
    /// The number of open file descriptors/handles can be capped.
    OpenFileLimit,
    /// The child can be confined to a subtree of the filesystem.
    FilesystemConfinement,
    /// A page shared between sandboxes can be made read-only **by a mechanism**, so that no
    /// guest can write content other guests are reading.
    ///
    /// The plan calls this the single most important security requirement in AUSec: a
    /// writable shared page lets one MicroVM contaminate every MicroVM on the host that maps
    /// it, which in a multi-tenant deployment is cross-tenant contamination. A backend that
    /// cannot enforce it must refuse the request rather than share the page anyway, which is
    /// what this variant being in [`Capability`] buys — the refusal machinery already exists
    /// and does not need a second mechanism.
    SharedPageReadOnly,
    /// A guest's idle pages can be returned to the host **and the counters say so**.
    ///
    /// The distinction from [`Capability::MemoryLimit`] matters: that one caps what a
    /// sandbox may take, this one gives back what it is not using. A backend that can do the
    /// first and not the second must refuse the second rather than report a pass that
    /// returned nothing — a caller sizing the next sandbox against memory that was never
    /// returned would be working from a number that was never true.
    MemoryReclaim,
}

impl Capability {
    /// The stable name used in errors, JSON and the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EnvAllowlist => "env_allowlist",
            Self::OutputCap => "output_cap",
            Self::Timeout => "timeout",
            Self::WorkDirIsolation => "work_dir_isolation",
            Self::NetworkDenyAll => "network_deny_all",
            Self::NetworkAllowList => "network_allow_list",
            Self::MemoryLimit => "memory_limit",
            Self::CpuLimit => "cpu_limit",
            Self::DiskQuota => "disk_quota",
            Self::ProcessCountLimit => "process_count_limit",
            Self::OpenFileLimit => "open_file_limit",
            Self::FilesystemConfinement => "filesystem_confinement",
            Self::SharedPageReadOnly => "shared_page_read_only",
            Self::MemoryReclaim => "memory_reclaim",
        }
    }

    /// Every capability, for exhaustive tests and for reporting.
    ///
    /// The length is written out so that adding a capability without adding it here is a
    /// compile error rather than a silently shorter list.
    pub const ALL: [Capability; 14] = [
        Self::EnvAllowlist,
        Self::OutputCap,
        Self::Timeout,
        Self::WorkDirIsolation,
        Self::NetworkDenyAll,
        Self::NetworkAllowList,
        Self::MemoryLimit,
        Self::CpuLimit,
        Self::DiskQuota,
        Self::ProcessCountLimit,
        Self::OpenFileLimit,
        Self::FilesystemConfinement,
        Self::SharedPageReadOnly,
        Self::MemoryReclaim,
    ];
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a backend enforces, and why for each thing it does not.
///
/// This is data rather than documentation: [`Capabilities::require`] is the only
/// consumer, and it is called on every `create`, `exec` and `validate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Capabilities {
    backend: String,
    enforced: Vec<Capability>,
    unenforced: Vec<UnenforcedCapability>,
}

/// A capability a backend does not enforce, with the reason it cannot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UnenforcedCapability {
    /// The boundary.
    pub boundary: Capability,
    /// Why the backend cannot deliver it on this platform.
    pub reason: String,
}

impl std::fmt::Display for UnenforcedCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.boundary, self.reason)
    }
}

impl Capabilities {
    /// Declare a backend's capabilities.
    ///
    /// `unenforced` must carry a reason for every entry; [`Capabilities::new`]
    /// rejects an entry whose reason is empty, because "not enforced" with no
    /// explanation is exactly the drift this module exists to prevent.
    pub fn new(
        backend: impl Into<String>,
        enforced: impl IntoIterator<Item = Capability>,
        unenforced: impl IntoIterator<Item = (Capability, String)>,
    ) -> std::result::Result<Self, String> {
        let backend = backend.into();
        if backend.trim().is_empty() {
            return Err("a backend must be named".to_string());
        }
        let enforced: Vec<Capability> = enforced.into_iter().collect();
        let mut unenforced: Vec<UnenforcedCapability> = unenforced
            .into_iter()
            .map(|(boundary, reason)| UnenforcedCapability { boundary, reason })
            .collect();
        for entry in &unenforced {
            if entry.reason.trim().is_empty() {
                return Err(format!(
                    "backend `{backend}` declares `{}` unenforced with no reason",
                    entry.boundary
                ));
            }
        }
        for entry in &unenforced {
            if enforced.contains(&entry.boundary) {
                return Err(format!(
                    "backend `{backend}` declares `{}` both enforced and unenforced",
                    entry.boundary
                ));
            }
        }
        // Deterministic order, so two backends with the same claim compare equal
        // regardless of the order the caller listed them in.
        unenforced.sort_by_key(|entry| entry.boundary as u8);
        Ok(Self {
            backend,
            enforced,
            unenforced,
        })
    }

    /// Build a declaration from an already-validated pair of lists.
    ///
    /// This is not a second, unchecked constructor: it exists only so that a
    /// **constant** declaration inside this crate needs no `Result` and no
    /// `expect`. The caller takes responsibility for the two rules
    /// [`Capabilities::new`] enforces — every unenforced entry has a non-empty
    /// reason, and the two lists are disjoint — which for a literal written in
    /// source next to the code that implements it is checkable by reading.
    pub(crate) fn from_parts(
        backend: &str,
        enforced: Vec<Capability>,
        mut unenforced: Vec<UnenforcedCapability>,
    ) -> Self {
        unenforced.sort_by_key(|entry| entry.boundary as u8);
        Self {
            backend: backend.to_string(),
            enforced,
            unenforced,
        }
    }

    /// The backend's name.
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// True when this backend enforces `cap`.
    pub fn enforces(&self, cap: Capability) -> bool {
        self.enforced.contains(&cap)
    }

    /// Why this backend does not enforce `cap`, if it does not.
    pub fn reason_unenforced(&self, cap: Capability) -> Option<&str> {
        self.unenforced
            .iter()
            .find(|entry| entry.boundary == cap)
            .map(|entry| entry.reason.as_str())
    }

    /// The unenforced half of the declaration, for reporting and the audit log.
    pub fn unenforced(&self) -> &[UnenforcedCapability] {
        &self.unenforced
    }

    /// The full declaration, for reporting and the audit log.
    pub fn declaration(&self) -> Vec<(Capability, bool, Option<&str>)> {
        Capability::ALL
            .iter()
            .map(|cap| (*cap, self.enforces(*cap), self.reason_unenforced(*cap)))
            .collect()
    }

    /// Require `cap`, or fail with a typed refusal naming it.
    ///
    /// This is **the** enforcement point for the "documented but not enforced"
    /// defect: every policy field in [`crate::SandboxSpec`] calls it, so a field
    /// is either backed by an enforcing backend or the request fails.
    pub fn require(&self, cap: Capability) -> Result<()> {
        if self.enforces(cap) {
            return Ok(());
        }
        Err(SandboxError::PolicyNotEnforceable {
            boundary: cap,
            backend: self.backend.clone(),
            detail: self
                .reason_unenforced(cap)
                .unwrap_or("this backend publishes no enforcement for it")
                .to_string(),
        })
    }
}

/// A boundary that a backend is *asked* for, or an explicit exemption.
///
/// The third variant is the only way to run without a boundary, and it is
/// deliberately awkward: it must name the operator's justification, and the
/// manager records both the name and the justification in the audit log. There
/// is no `Option<bool>` here and no default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BoundaryRequest {
    /// Enforce this boundary, or fail naming it.
    Required(Capability),
    /// Run without this boundary, because `justification` says so. Recorded.
    Waived {
        /// The boundary being waived.
        boundary: Capability,
        /// Why. The audit log refuses an empty justification.
        justification: String,
    },
}

impl BoundaryRequest {
    /// The boundary this request is about.
    pub fn boundary(&self) -> Capability {
        match self {
            Self::Required(cap) => *cap,
            Self::Waived { boundary, .. } => *boundary,
        }
    }

    /// Apply the request against a backend's declaration.
    ///
    /// * `Required` and enforced → `Ok`.
    /// * `Required` and not enforced → [`SandboxError::PolicyNotEnforceable`].
    /// * `Waived` with a non-empty justification → `Ok`, and the caller must log
    ///   it (see [`crate::manager::SandboxManager::create`], which refuses an
    ///   empty justification before reaching here).
    pub fn apply(&self, caps: &Capabilities) -> Result<()> {
        match self {
            Self::Required(cap) => caps.require(*cap),
            Self::Waived {
                boundary,
                justification,
            } => {
                if justification.trim().is_empty() {
                    return Err(SandboxError::PolicyNotEnforceable {
                        boundary: *boundary,
                        backend: caps.backend().to_string(),
                        detail: "a waiver requires a non-empty justification for the audit log"
                            .to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

/// The pure half of the capability check, usable without a backend.
///
/// Kept separate from [`Capabilities::require`] so that a caller holding only a
/// declaration (a config file, a test fixture) can ask the same question and get
/// the same typed answer.
pub fn check_boundary(caps: &Capabilities, requests: &[BoundaryRequest]) -> Result<()> {
    for request in requests {
        request.apply(caps)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(enforced: &[Capability], unenforced: &[(Capability, &str)]) -> Capabilities {
        Capabilities::new(
            "test-backend",
            enforced.iter().copied(),
            unenforced
                .iter()
                .map(|(c, r)| (*c, (*r).to_string()))
                .collect::<Vec<_>>(),
        )
        .expect("declaration")
    }

    /// Upstream v2.8.2 fix: the absence of a capability check was silent. This
    /// walks **every** capability in both directions, so neither a false
    /// "enforced" nor a false "refused" can pass unnoticed.
    #[test]
    fn every_capability_is_exercised_in_both_directions() {
        for cap in Capability::ALL {
            let enforcing = caps(&[cap], &[]);
            assert!(enforcing.enforces(cap), "{cap} should be enforced");
            assert!(enforcing.require(cap).is_ok(), "{cap} should be usable");
            assert_eq!(
                BoundaryRequest::Required(cap).apply(&enforcing),
                Ok(()),
                "{cap} required + enforced"
            );

            let other = Capability::ALL
                .iter()
                .copied()
                .filter(|c| *c != cap)
                .collect::<Vec<_>>();
            let refusing = caps(&other, &[(cap, "no primitive on this platform")]);
            assert!(!refusing.enforces(cap), "{cap} should be refused");
            let err = refusing.require(cap).expect_err("must refuse");
            match err {
                SandboxError::PolicyNotEnforceable {
                    boundary,
                    ref backend,
                    ref detail,
                } => {
                    assert_eq!(boundary, cap);
                    assert_eq!(backend, "test-backend");
                    assert_eq!(detail, "no primitive on this platform");
                }
                other => panic!("{cap} gave {other:?}"),
            }
            let err = BoundaryRequest::Required(cap)
                .apply(&refusing)
                .expect_err("must refuse");
            assert!(
                matches!(err, SandboxError::PolicyNotEnforceable { boundary, .. } if boundary == cap),
                "{cap} gave {err:?}"
            );
        }
    }

    /// A waiver is the only way to run without a boundary, and it needs a reason.
    #[test]
    fn a_waiver_needs_a_justification_and_a_requirement_does_not_become_one() {
        let refusing = caps(&[], &[(Capability::NetworkDenyAll, "no packet filter")]);
        let no_reason = BoundaryRequest::Waived {
            boundary: Capability::NetworkDenyAll,
            justification: "   ".to_string(),
        };
        assert!(
            no_reason.apply(&refusing).is_err(),
            "empty waiver must fail"
        );
        let reasoned = BoundaryRequest::Waived {
            boundary: Capability::NetworkDenyAll,
            justification: "air-gapped CI host, ticket SEC-42".to_string(),
        };
        assert_eq!(reasoned.apply(&refusing), Ok(()));
        // A `Required` request of the same boundary still fails: the waiver is a
        // different value, not a global setting.
        assert!(BoundaryRequest::Required(Capability::NetworkDenyAll)
            .apply(&refusing)
            .is_err());
    }

    #[test]
    fn a_declaration_cannot_contradict_itself_or_hide_a_reason() {
        assert!(Capabilities::new("b", [Capability::Timeout], []).is_ok());
        assert!(Capabilities::new(
            "b",
            [Capability::Timeout],
            [(Capability::Timeout, "x".into())]
        )
        .is_err());
        assert!(Capabilities::new("b", [], [(Capability::Timeout, "  ".into())]).is_err());
        assert!(Capabilities::new("  ", [Capability::Timeout], []).is_err());
        // An unnamed capability is reported as unenforced with no reason.
        let c = caps(&[Capability::Timeout], &[]);
        assert!(!c.enforces(Capability::DiskQuota));
        assert!(c.reason_unenforced(Capability::DiskQuota).is_none());
        let err = c.require(Capability::DiskQuota).expect_err("must refuse");
        assert!(
            matches!(err, SandboxError::PolicyNotEnforceable { boundary, .. } if boundary == Capability::DiskQuota)
        );
    }

    #[test]
    fn check_boundary_reports_the_first_failing_request() {
        let refusing = caps(
            &[Capability::Timeout],
            &[(Capability::MemoryLimit, "no job object")],
        );
        let requests = [
            BoundaryRequest::Required(Capability::Timeout),
            BoundaryRequest::Required(Capability::MemoryLimit),
            BoundaryRequest::Required(Capability::DiskQuota),
        ];
        let err = check_boundary(&refusing, &requests).expect_err("second request fails");
        assert!(
            matches!(err, SandboxError::PolicyNotEnforceable { boundary, .. } if boundary == Capability::MemoryLimit)
        );
    }

    #[test]
    fn the_declaration_lists_every_capability_exactly_once() {
        let c = caps(
            &[Capability::Timeout],
            &[(Capability::DiskQuota, "no quota")],
        );
        let listed = c.declaration();
        assert_eq!(listed.len(), Capability::ALL.len());
        for cap in Capability::ALL {
            assert_eq!(
                listed.iter().filter(|(c, _, _)| *c == cap).count(),
                1,
                "{cap} listed once"
            );
        }
    }
}
