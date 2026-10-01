//! [`SandboxSpec`] — the complete, non-optional description of one sandbox run.
//!
//! ## No optional limits
//!
//! Upstream v2.8.2 fix: `cpu_millis`, `mem_mb` and `disk_mb` were validated
//! `> 0` and then never read, and the Windows branch applied no limits at all, so
//! "unbounded" was not a decision anybody made — it was the default that survived
//! because nobody filled the field in. Here every limit is a required field of a
//! required struct: **omitting one is a compile error**, and the only way to run
//! without a particular boundary is to ask for a named waiver that the audit log
//! records (see [`crate::capability::BoundaryRequest`]).
//!
//! ## No string reaches a shell
//!
//! The interpreter is an enum ([`Interpreter`]) and the program is a
//! [`AbsoluteProgramPath`]. There is no `command: String` field anywhere in this
//! crate that is split on whitespace or handed to `sh -c`; the child is always
//! started with an explicit argv vector. A script body travels on **stdin**
//! ([`crate::ExecRequest::stdin`]), never as an interpolated argument.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::capability::{BoundaryRequest, Capability};
use crate::error::{Result, SandboxError};

/// Absolute path to one file that can be executed.
///
/// Relative paths are refused at parse time. Upstream v2.8.2 fix: the program
/// was chosen by an arbitrary string that reached `Command::new("bash")`, and a
/// bare name would have been resolved against the daemon's `PATH`. With a fixed
/// safe `PATH` there is nothing to resolve against, so an implicit lookup is a
/// refusal rather than an accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AbsoluteProgramPath(PathBuf);

impl AbsoluteProgramPath {
    /// Accept an absolute path, or refuse it.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(SandboxError::Start(format!(
                "program path `{}` must be absolute: there is no PATH lookup in the sandbox",
                path.display()
            )));
        }
        if path.file_name().is_none() {
            return Err(SandboxError::Start(format!(
                "program path `{}` names a directory, not a file",
                path.display()
            )));
        }
        Ok(Self(path))
    }

    /// The path.
    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
}

impl std::fmt::Display for AbsoluteProgramPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// How a script body is executed.
///
/// The variants exist so that "run this Python" is a *typed* request rather than
/// a string concatenated into a command line. Upstream v2.8.2 fix: `exec` took
/// arbitrary Python or JavaScript and ran it, so the language selector was
/// untrusted data on a command line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Interpreter {
    /// Read the program from stdin and hand it to the named interpreter.
    ///
    /// The interpreter is started as `interpreter -` (Python, Node and `sh` all
    /// read a script from `-`), so no script text is ever part of the argv
    /// vector.
    Script {
        /// The interpreter binary. Must be an absolute path.
        bin: AbsoluteProgramPath,
    },
    /// Start `bin` with these argv entries. No shell is involved.
    Argv {
        /// The binary. Must be an absolute path.
        bin: AbsoluteProgramPath,
        /// The argv entries after `argv[0]`.
        args: Vec<String>,
    },
    /// Run `bin` with no arguments. The simplest escape-free form.
    Binary(AbsoluteProgramPath),
    /// Start a shell anyway — an **explicit, auditable** decision.
    ///
    /// `sh -c -` with the script on stdin. The script still arrives on stdin
    /// rather than through argv, but a shell interprets it. This variant exists
    /// because pretending a shell is never needed would be dishonest; it does not
    /// exist as a default, and the manager records its use in the audit log.
    Shell(AbsoluteProgramPath),
}

impl Interpreter {
    /// The binary this interpreter starts.
    pub fn bin(&self) -> &AbsoluteProgramPath {
        match self {
            Self::Script { bin } => bin,
            Self::Argv { bin, .. } => bin,
            Self::Binary(bin) => bin,
            Self::Shell(bin) => bin,
        }
    }

    /// The argv after `argv[0]`.
    fn args(&self) -> Vec<String> {
        match self {
            Self::Script { .. } => vec!["-".to_string()],
            Self::Argv { args, .. } => args.clone(),
            Self::Binary(_) => Vec::new(),
            Self::Shell(_) => vec!["-c".to_string(), "-".to_string()],
        }
    }

    /// Build the `std::process::Command` for this interpreter.
    ///
    /// This is the **only** place in the crate that constructs a `Command`, and
    /// it uses the argv vector form exclusively: `Command::new(bin).args(argv)`.
    /// There is no `sh -c "$USER_INPUT"` anywhere.
    pub fn command(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(self.bin().as_path());
        cmd.args(self.args());
        cmd
    }

    /// True when a script body must be supplied on stdin.
    pub fn needs_script(&self) -> bool {
        matches!(self, Self::Script { .. } | Self::Shell(_))
    }

    /// A label for the audit log. Never the script text.
    pub fn label(&self) -> String {
        match self {
            Self::Script { .. } => format!("script:{}", self.bin()),
            Self::Argv { .. } => format!("argv:{}", self.bin()),
            Self::Binary(_) => format!("binary:{}", self.bin()),
            Self::Shell(_) => format!("shell:{}", self.bin()),
        }
    }
}

/// What may leave the sandbox.
///
/// Upstream v2.8.2 fix: `NetworkGuard::check_egress` had zero production
/// callers, so "default deny egress" was false and a sandbox could POST back to
/// the daemon's own API (SSRF). There is no `Default` implementation here, and
/// the most permissive variant is spelled out so that choosing it is visible in
/// a diff, in a request body and in the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkPolicy {
    /// No outbound traffic at all. A backend without an egress primitive must
    /// refuse this rather than accept it.
    DenyAll,
    /// Outbound traffic only to these `host:port` destinations.
    AllowList {
        /// Exact `host:port` destinations.
        hosts: Vec<String>,
    },
    /// Unrestricted egress. Running with this records an audit entry.
    Unrestricted {
        /// Why unrestricted egress was allowed. The audit log refuses an empty
        /// justification.
        justification: String,
    },
}

impl NetworkPolicy {
    /// The stable name used in errors and the audit log.
    pub fn name(&self) -> &'static str {
        match self {
            Self::DenyAll => "deny_all",
            Self::AllowList { .. } => "allow_list",
            Self::Unrestricted { .. } => "unrestricted",
        }
    }

    /// Rank, most restrictive first.
    ///
    /// Used by [`SandboxSpec::tightens_only_against`] so that an exec-time
    /// override can only ever *reduce* what a sandbox may do.
    pub fn restrictiveness(&self) -> u8 {
        match self {
            Self::DenyAll => 0,
            Self::AllowList { .. } => 1,
            Self::Unrestricted { .. } => 2,
        }
    }
}

/// Whether a backend must confine the child's filesystem view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confinement {
    /// The child must not be able to reach outside the work directory. A backend
    /// without a confinement primitive must refuse this.
    Required,
    /// The child may reach the whole host filesystem. Requires a justification on
    /// [`Waivers::filesystem_confinement`] and is recorded in the audit log.
    WholeHost,
}

/// What the child may read and write.
///
/// Upstream v2.8.2 fix: `FilesystemPolicy` (`config.rs:88-97`) had **zero**
/// enforcement sites, so executed code read and wrote the entire host filesystem.
/// This type carries a required [`Confinement`] instead of a bare list, so a
/// backend that cannot confine refuses a request that asks it to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Whether the child is confined to the work directory.
    pub confinement: Confinement,
    /// Absolute paths that may be read *in addition* to the work directory.
    pub extra_readable: Vec<PathBuf>,
    /// Absolute paths that may be written, in addition to the work directory.
    pub writable: Vec<PathBuf>,
}

impl FilesystemPolicy {
    /// Confined policy with nothing extra readable or writable.
    pub fn confined() -> Self {
        Self {
            confinement: Confinement::Required,
            extra_readable: Vec::new(),
            writable: Vec::new(),
        }
    }
}

/// The environment a child is given.
///
/// Upstream v2.8.2 fix: the child ran as the daemon's own OS user with the
/// daemon's environment available, so a sandbox could read host secrets. Here the
/// environment is *constructed*: a fixed safe `PATH` plus exactly the listed
/// `NAME=value` pairs, and nothing else. [`crate::process::apply_env`] is the
/// only writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct EnvPolicy {
    /// Whether any part of the daemon environment is passed on. `false` is not
    /// offered: there is no variant that inherits, because inheriting is the
    /// defect. The field exists so a future reader can see the decision.
    pub inherit: InheritPolicy,
    /// `NAME=value` pairs to set, in addition to the fixed `PATH`.
    pub vars: Vec<(String, String)>,
}

/// Whether any part of the daemon environment is passed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InheritPolicy {
    /// Inherit nothing. This is the only value that constructs an environment.
    Nothing,
}

impl EnvPolicy {
    /// A policy with the fixed safe `PATH` and no extra variables.
    pub fn empty() -> Self {
        Self {
            inherit: InheritPolicy::Nothing,
            vars: Vec::new(),
        }
    }
}

/// Resource limits, all of them required.
///
/// # Units
///
/// All are integers. There is no `Option`, no "`0` means unlimited", and no
/// floating point: `0` is refused by [`SandboxSpec::validate`], so "unlimited"
/// cannot be expressed by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Limits {
    /// Wall-clock budget for one `exec`, in milliseconds.
    pub timeout_ms: u64,
    /// Address-space/commit cap for the whole sandbox, in bytes.
    pub memory_bytes: u64,
    /// CPU-time cap for the whole sandbox, in milliseconds.
    pub cpu_ms: u64,
    /// Bytes the sandbox may write to disk. A backend without a quota primitive
    /// must refuse this rather than accept and ignore it.
    pub disk_bytes: u64,
    /// Maximum number of processes in the sandbox, the direct child included.
    pub max_processes: u32,
    /// Maximum open files/handles per process in the sandbox.
    pub max_open_files: u32,
    /// Maximum bytes retained from stdout and stderr **each**.
    pub max_output_bytes: usize,
}

/// Which boundaries to waive, and why.
///
/// A waiver is the only way to run without a boundary a [`Capability`] would
/// otherwise refuse. It is not a boolean on the spec: the reason is part of the
/// value and the manager writes it to the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Waivers {
    /// Waive filesystem confinement, with a reason.
    pub filesystem_confinement: Option<String>,
    /// Waive disk quota, with a reason.
    pub disk_bytes: Option<String>,
    /// Waive the CPU-time cap, with a reason.
    pub cpu_ms: Option<String>,
    /// Waive the open-file cap, with a reason.
    pub max_open_files: Option<String>,
}

impl Waivers {
    /// No waivers: every capability is required.
    pub fn none() -> Self {
        Self {
            filesystem_confinement: None,
            disk_bytes: None,
            cpu_ms: None,
            max_open_files: None,
        }
    }

    /// Every declared waiver, as `(capability, justification)` pairs.
    pub fn declared(&self) -> Vec<(Capability, &str)> {
        let mut out = Vec::new();
        if let Some(reason) = self.filesystem_confinement.as_deref() {
            out.push((Capability::FilesystemConfinement, reason));
        }
        if let Some(reason) = self.disk_bytes.as_deref() {
            out.push((Capability::DiskQuota, reason));
        }
        if let Some(reason) = self.cpu_ms.as_deref() {
            out.push((Capability::CpuLimit, reason));
        }
        if let Some(reason) = self.max_open_files.as_deref() {
            out.push((Capability::OpenFileLimit, reason));
        }
        out
    }

    /// Turn the declared waivers into boundary requests.
    pub fn requests(&self) -> Vec<BoundaryRequest> {
        self.declared()
            .into_iter()
            .map(|(boundary, justification)| BoundaryRequest::Waived {
                boundary,
                justification: justification.to_string(),
            })
            .collect()
    }
}

/// The full description of one sandbox.
///
/// Every field is required. See the module docs for why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SandboxSpec {
    /// How the program is executed.
    pub interpreter: Interpreter,
    /// Resource limits. All of them.
    pub limits: Limits,
    /// What may leave.
    pub network: NetworkPolicy,
    /// What may be read and written.
    pub filesystem: FilesystemPolicy,
    /// The constructed environment.
    pub env: EnvPolicy,
    /// Boundaries explicitly waived, with reasons.
    pub waivers: Waivers,
}

impl SandboxSpec {
    /// Reject a spec whose limits are self-contradictory.
    ///
    /// Zero is refused everywhere rather than treated as "unlimited": upstream's
    /// six-limit table had three fields that were only ever checked `> 0` and
    /// then ignored, so a zero meaning unlimited would reintroduce exactly the
    /// silent default this crate exists to remove.
    pub fn validate(&self) -> Result<()> {
        let l = &self.limits;
        for (value, name) in [
            (l.timeout_ms, "timeout_ms"),
            (l.memory_bytes, "memory_bytes"),
            (l.cpu_ms, "cpu_ms"),
            (l.disk_bytes, "disk_bytes"),
        ] {
            if value == 0 {
                return Err(SandboxError::Limit {
                    limit: format!("{name} must be greater than zero"),
                });
            }
        }
        if l.max_processes == 0 {
            return Err(SandboxError::Limit {
                limit: "max_processes must be at least 1 (the sandbox process itself)".to_string(),
            });
        }
        if l.max_open_files == 0 {
            return Err(SandboxError::Limit {
                limit: "max_open_files must be greater than zero".to_string(),
            });
        }
        if l.max_output_bytes == 0 {
            return Err(SandboxError::Limit {
                limit: "max_output_bytes must be greater than zero".to_string(),
            });
        }
        match &self.network {
            NetworkPolicy::Unrestricted { justification } => {
                if justification.trim().is_empty() {
                    return Err(SandboxError::PolicyNotEnforceable {
                        boundary: Capability::NetworkDenyAll,
                        backend: "spec".to_string(),
                        detail: "an unrestricted network policy requires a justification for the \
                                 audit log"
                            .to_string(),
                    });
                }
            }
            NetworkPolicy::AllowList { hosts } => {
                if hosts.is_empty() {
                    return Err(SandboxError::PolicyNotEnforceable {
                        boundary: Capability::NetworkAllowList,
                        backend: "spec".to_string(),
                        detail:
                            "an empty allow list is a deny-all in disguise; ask for `deny_all` \
                                 explicitly so the refusal path is exercised"
                                .to_string(),
                    });
                }
                for host in hosts {
                    if host.trim().is_empty() || host.contains('/') {
                        return Err(SandboxError::Limit {
                            limit: format!("`{host}` is not a host:port destination"),
                        });
                    }
                }
            }
            NetworkPolicy::DenyAll => {}
        }
        for (name, _) in &self.env.vars {
            if name.is_empty() || name.contains('=') || name.contains('\0') {
                return Err(SandboxError::Limit {
                    limit: format!("`{name}` is not a usable environment variable name"),
                });
            }
            if name.eq_ignore_ascii_case("PATH") {
                return Err(SandboxError::Limit {
                    limit: "PATH is fixed by the sandbox and cannot be overridden".to_string(),
                });
            }
        }
        for path in self
            .filesystem
            .extra_readable
            .iter()
            .chain(self.filesystem.writable.iter())
        {
            if !path.is_absolute() {
                return Err(SandboxError::Limit {
                    limit: format!("`{}` must be absolute", path.display()),
                });
            }
        }
        Ok(())
    }

    /// The boundary requests this spec implies: every capability it uses, or a
    /// waiver where it uses one.
    pub fn boundary_requests(&self) -> Vec<BoundaryRequest> {
        let mut out = vec![
            BoundaryRequest::Required(Capability::EnvAllowlist),
            BoundaryRequest::Required(Capability::OutputCap),
            BoundaryRequest::Required(Capability::Timeout),
            BoundaryRequest::Required(Capability::WorkDirIsolation),
            BoundaryRequest::Required(Capability::MemoryLimit),
            BoundaryRequest::Required(Capability::ProcessCountLimit),
        ];
        out.push(match &self.network {
            NetworkPolicy::DenyAll => BoundaryRequest::Required(Capability::NetworkDenyAll),
            NetworkPolicy::AllowList { .. } => {
                BoundaryRequest::Required(Capability::NetworkAllowList)
            }
            NetworkPolicy::Unrestricted { justification } => BoundaryRequest::Waived {
                boundary: Capability::NetworkDenyAll,
                justification: justification.clone(),
            },
        });
        out.push(match self.filesystem.confinement {
            Confinement::Required => BoundaryRequest::Required(Capability::FilesystemConfinement),
            Confinement::WholeHost => BoundaryRequest::Waived {
                boundary: Capability::FilesystemConfinement,
                justification: self
                    .waivers
                    .filesystem_confinement
                    .clone()
                    .unwrap_or_else(|| "filesystem.confinement = whole_host".to_string()),
            },
        });
        out.push(waiver_or_required(
            Capability::CpuLimit,
            &self.waivers.cpu_ms,
        ));
        out.push(waiver_or_required(
            Capability::DiskQuota,
            &self.waivers.disk_bytes,
        ));
        out.push(waiver_or_required(
            Capability::OpenFileLimit,
            &self.waivers.max_open_files,
        ));
        out
    }

    /// True when `self` is no more permissive than `base` in every dimension an
    /// exec-time override can change.
    ///
    /// Upstream v2.8.2 fix: the request body was parsed and discarded
    /// (`api.rs:85-89` then `acquire(None)`), so no caller could set a policy —
    /// and the obvious first fix, letting the body replace the policy, would let
    /// any caller widen its own sandbox after creation. An override may only
    /// tighten.
    pub fn tightens_only_against(&self, base: &SandboxSpec) -> Result<()> {
        let tighten = |field: &str, base_v: u64, new_v: u64| -> Result<()> {
            if new_v > base_v {
                return Err(SandboxError::PolicyNotEnforceable {
                    boundary: Capability::Timeout,
                    backend: "spec-override".to_string(),
                    detail: format!(
                        "{field} may only be tightened: the sandbox was created with {base_v} and \
                         this override asks for {new_v}"
                    ),
                });
            }
            Ok(())
        };
        tighten("timeout_ms", base.limits.timeout_ms, self.limits.timeout_ms)?;
        tighten(
            "memory_bytes",
            base.limits.memory_bytes,
            self.limits.memory_bytes,
        )?;
        tighten("cpu_ms", base.limits.cpu_ms, self.limits.cpu_ms)?;
        tighten("disk_bytes", base.limits.disk_bytes, self.limits.disk_bytes)?;
        tighten(
            "max_processes",
            u64::from(base.limits.max_processes),
            u64::from(self.limits.max_processes),
        )?;
        tighten(
            "max_open_files",
            u64::from(base.limits.max_open_files),
            u64::from(self.limits.max_open_files),
        )?;
        tighten(
            "max_output_bytes",
            base.limits.max_output_bytes as u64,
            self.limits.max_output_bytes as u64,
        )?;
        if self.network.restrictiveness() > base.network.restrictiveness() {
            return Err(SandboxError::PolicyNotEnforceable {
                boundary: Capability::NetworkDenyAll,
                backend: "spec-override".to_string(),
                detail: format!(
                    "the network policy may only be tightened: the sandbox was created with `{}` \
                     and this override asks for `{}`",
                    base.network.name(),
                    self.network.name()
                ),
            });
        }
        if self.filesystem.confinement != base.filesystem.confinement {
            return Err(SandboxError::PolicyNotEnforceable {
                boundary: Capability::FilesystemConfinement,
                backend: "spec-override".to_string(),
                detail: "the filesystem confinement mode is fixed at creation".to_string(),
            });
        }
        for path in &self.filesystem.writable {
            if !base.filesystem.writable.contains(path) {
                return Err(SandboxError::Limit {
                    limit: format!(
                        "`{}` was not writable when the sandbox was created, and an override may \
                         only tighten",
                        path.display()
                    ),
                });
            }
        }
        for path in &self.filesystem.extra_readable {
            if !base.filesystem.extra_readable.contains(path) {
                return Err(SandboxError::Limit {
                    limit: format!(
                        "`{}` was not readable when the sandbox was created, and an override may \
                         only tighten",
                        path.display()
                    ),
                });
            }
        }
        if self.waivers != base.waivers {
            return Err(SandboxError::PolicyNotEnforceable {
                boundary: Capability::FilesystemConfinement,
                backend: "spec-override".to_string(),
                detail: "waivers are fixed at creation and cannot be added by a request"
                    .to_string(),
            });
        }
        // The interpreter is NOT overridable: swapping the program is not a
        // tightening, and allowing it would let a request change what runs.
        if self.interpreter != base.interpreter {
            return Err(SandboxError::PolicyNotEnforceable {
                boundary: Capability::FilesystemConfinement,
                backend: "spec-override".to_string(),
                detail: "the interpreter is fixed at creation; an override may only tighten limits"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// A required boundary, or the audit-recorded waiver that replaces it.
fn waiver_or_required(cap: Capability, waiver: &Option<String>) -> BoundaryRequest {
    match waiver {
        Some(reason) => BoundaryRequest::Waived {
            boundary: cap,
            justification: reason.clone(),
        },
        None => BoundaryRequest::Required(cap),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            timeout_ms: 5_000,
            memory_bytes: 256 * 1024 * 1024,
            cpu_ms: 5_000,
            disk_bytes: 16 * 1024 * 1024,
            max_processes: 4,
            max_open_files: 64,
            max_output_bytes: 64 * 1024,
        }
    }

    fn spec() -> SandboxSpec {
        SandboxSpec {
            interpreter: Interpreter::Binary(
                AbsoluteProgramPath::new(std::env::current_exe().expect("current exe"))
                    .expect("absolute"),
            ),
            limits: limits(),
            network: NetworkPolicy::DenyAll,
            filesystem: FilesystemPolicy::confined(),
            env: EnvPolicy::empty(),
            waivers: Waivers::none(),
        }
    }

    #[test]
    fn a_complete_spec_validates() {
        assert_eq!(spec().validate(), Ok(()));
    }

    /// Upstream v2.8.2 fix: `cpu_millis`/`mem_mb`/`disk_mb` were only checked
    /// `> 0` and then never read, and an absent limit silently meant unbounded.
    /// Zero is refused here rather than reinterpreted.
    #[test]
    fn every_zero_limit_is_refused_rather_than_read_as_unlimited() {
        let base = spec();
        for mutate in [
            (|l: &mut Limits| l.timeout_ms = 0) as fn(&mut Limits),
            (|l: &mut Limits| l.memory_bytes = 0) as fn(&mut Limits),
            (|l: &mut Limits| l.cpu_ms = 0) as fn(&mut Limits),
            (|l: &mut Limits| l.disk_bytes = 0) as fn(&mut Limits),
            (|l: &mut Limits| l.max_processes = 0) as fn(&mut Limits),
            (|l: &mut Limits| l.max_open_files = 0) as fn(&mut Limits),
            (|l: &mut Limits| l.max_output_bytes = 0) as fn(&mut Limits),
        ] {
            let mut s = base.clone();
            mutate(&mut s.limits);
            let err = s.validate().expect_err("zero must be refused");
            assert!(
                matches!(err, SandboxError::Limit { .. }),
                "expected a Limit error, got {err:?}"
            );
        }
    }

    #[test]
    fn an_unrestricted_network_policy_needs_a_justification() {
        let mut s = spec();
        s.network = NetworkPolicy::Unrestricted {
            justification: "  ".to_string(),
        };
        assert!(s.validate().is_err());
        s.network = NetworkPolicy::Unrestricted {
            justification: "air-gapped host".to_string(),
        };
        assert_eq!(s.validate(), Ok(()));
    }

    #[test]
    fn an_empty_allow_list_is_refused_as_a_deny_all_in_disguise() {
        let mut s = spec();
        s.network = NetworkPolicy::AllowList { hosts: Vec::new() };
        assert!(s.validate().is_err());
        s.network = NetworkPolicy::AllowList {
            hosts: vec!["api.example:443".to_string()],
        };
        assert_eq!(s.validate(), Ok(()));
        s.network = NetworkPolicy::AllowList {
            hosts: vec!["http://api.example".to_string()],
        };
        assert!(s.validate().is_err(), "a URL is not a host:port");
    }

    #[test]
    fn a_relative_program_path_is_refused() {
        // Upstream resolved an arbitrary program name against `PATH`.
        assert!(AbsoluteProgramPath::new("sh").is_err());
        assert!(AbsoluteProgramPath::new("./sh").is_err());
        assert!(AbsoluteProgramPath::new("..\\sh").is_err());
    }

    #[test]
    fn path_cannot_be_overridden_through_the_env_allowlist() {
        let mut s = spec();
        s.env.vars.push(("PATH".to_string(), "/evil".to_string()));
        assert!(s.validate().is_err());
        let mut s = spec();
        s.env.vars.push(("path".to_string(), "/evil".to_string()));
        assert!(s.validate().is_err(), "the check is case-insensitive");
    }

    #[test]
    fn the_interpreter_builds_an_argv_vector_and_never_a_shell_string() {
        let bin = AbsoluteProgramPath::new(if cfg!(windows) {
            PathBuf::from("C:\\Windows\\System32\\cmd.exe")
        } else {
            PathBuf::from("/bin/sh")
        })
        .expect("absolute");
        let argv = Interpreter::Argv {
            bin: bin.clone(),
            args: vec!["--version".to_string(), "a b".to_string()],
        };
        let rendered: Vec<String> = argv
            .command()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // `a b` stayed one argument: no whitespace splitting anywhere.
        assert_eq!(rendered, vec!["--version", "a b"]);
        let script = Interpreter::Script { bin: bin.clone() };
        assert_eq!(
            script
                .command()
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["-"]
        );
        assert!(script.needs_script());
        assert!(!Interpreter::Binary(bin.clone()).needs_script());
        assert!(Interpreter::Shell(bin).label().starts_with("shell:"));
    }

    #[test]
    fn boundary_requests_cover_every_limit() {
        let requests = spec().boundary_requests();
        let boundaries: Vec<Capability> = requests.iter().map(|r| r.boundary()).collect();
        for cap in [
            Capability::EnvAllowlist,
            Capability::OutputCap,
            Capability::Timeout,
            Capability::WorkDirIsolation,
            Capability::MemoryLimit,
            Capability::ProcessCountLimit,
            Capability::NetworkDenyAll,
            Capability::FilesystemConfinement,
            Capability::CpuLimit,
            Capability::DiskQuota,
            Capability::OpenFileLimit,
        ] {
            assert!(boundaries.contains(&cap), "{cap} must be requested");
        }
        // A waiver replaces exactly its own boundary.
        let mut s = spec();
        s.waivers.disk_bytes = Some("no quota primitive".to_string());
        let requests = s.boundary_requests();
        let disk = requests
            .iter()
            .find(|r| r.boundary() == Capability::DiskQuota)
            .expect("disk request");
        assert!(matches!(disk, BoundaryRequest::Waived { .. }));
    }

    #[test]
    fn an_override_may_tighten_but_never_widen() {
        let base = spec();
        let mut tighter = base.clone();
        tighter.limits.timeout_ms = base.limits.timeout_ms - 1;
        tighter.limits.memory_bytes = base.limits.memory_bytes / 2;
        tighter.limits.max_output_bytes = base.limits.max_output_bytes / 2;
        assert_eq!(tighter.tightens_only_against(&base), Ok(()));

        // A named alias rather than an inline `Vec<Box<dyn Fn(..)>>`: the inline
        // form is what `clippy::type_complexity` refuses.
        type SpecMutation = Box<dyn Fn(&mut SandboxSpec)>;
        let wideners: Vec<SpecMutation> = vec![
            Box::new(move |s: &mut SandboxSpec| s.limits.timeout_ms = base.limits.timeout_ms + 1),
            Box::new(move |s: &mut SandboxSpec| {
                s.limits.memory_bytes = base.limits.memory_bytes + 1
            }),
            Box::new(move |s: &mut SandboxSpec| s.limits.cpu_ms = base.limits.cpu_ms + 1),
            Box::new(move |s: &mut SandboxSpec| s.limits.disk_bytes = base.limits.disk_bytes + 1),
            Box::new(move |s: &mut SandboxSpec| {
                s.limits.max_processes = base.limits.max_processes + 1
            }),
            Box::new(move |s: &mut SandboxSpec| {
                s.limits.max_open_files = base.limits.max_open_files + 1
            }),
            Box::new(move |s: &mut SandboxSpec| {
                s.limits.max_output_bytes = base.limits.max_output_bytes + 1
            }),
            Box::new(|s: &mut SandboxSpec| {
                s.network = NetworkPolicy::AllowList {
                    hosts: vec!["a:1".to_string()],
                }
            }),
            Box::new(|s: &mut SandboxSpec| {
                s.network = NetworkPolicy::Unrestricted {
                    justification: "because".to_string(),
                }
            }),
            Box::new(|s: &mut SandboxSpec| s.filesystem.writable.push(PathBuf::from("/etc"))),
            Box::new(|s: &mut SandboxSpec| s.waivers.disk_bytes = Some("just because".to_string())),
            Box::new(|s: &mut SandboxSpec| {
                s.interpreter = Interpreter::Binary(
                    AbsoluteProgramPath::new(if cfg!(windows) {
                        PathBuf::from("C:\\Windows\\System32\\cmd.exe")
                    } else {
                        PathBuf::from("/bin/sh")
                    })
                    .expect("absolute"),
                )
            }),
        ];
        for mutate in &wideners {
            let mut widened = base.clone();
            mutate(&mut widened);
            assert!(
                widened.tightens_only_against(&base).is_err(),
                "must refuse a widening override"
            );
        }

        // Tightening the network policy from unrestricted to deny-all is allowed.
        let mut loose = base.clone();
        loose.network = NetworkPolicy::Unrestricted {
            justification: "operator decision".to_string(),
        };
        assert_eq!(base.tightens_only_against(&loose), Ok(()));
    }

    #[test]
    fn the_spec_is_json_round_trippable_and_rejects_unknown_fields() {
        let s = spec();
        let json = serde_json::to_string(&s).expect("serialise");
        let back: SandboxSpec = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, s);
        // A typo must fail rather than fall back to a default.
        let broken = json.replace("\"timeout_ms\"", "\"timeout_millis\"");
        assert!(
            serde_json::from_str::<SandboxSpec>(&broken).is_err(),
            "an unknown field must be refused"
        );
    }
}
