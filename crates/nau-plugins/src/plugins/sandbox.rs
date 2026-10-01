//! `com.twinsearth.sys.sandbox` — the isolation boundary, reported as data.
//!
//! # What the answer is, and what it is deliberately not
//!
//! This plugin wraps `nau-sandbox`'s capability declaration. It answers two questions:
//!
//! * `platform` — which backend is being described, which boundaries it **enforces**,
//!   and which it **cannot** enforce together with the backend's own reason for each;
//! * `preflight` — can this backend serve one [`SandboxSpec`], and if not, exactly which
//!   boundaries are in the way.
//!
//! The second question is answered by *naming* the boundaries rather than by returning a
//! boolean, because a boolean is what upstream v2.8.2 shipped: `PermissionChecker::check`
//! and `NetworkGuard::check_egress` existed, were unit-tested, and had zero production
//! callers. `nau_sandbox::Capabilities::require` is the enforcement point that replaced
//! them, and this plugin returns its refusals rather than a summary of them.
//!
//! # The honesty rule this file exists to obey
//!
//! The plugin reports `enforced` and `unenforced` exactly as the backend declares them,
//! including the boundaries it cannot deliver on this platform — egress denial, filesystem
//! confinement, disk quota, and (on Windows) CPU time and open-handle caps. It never
//! reports a boundary as enforced because the architecture document wishes it were, and it
//! never converts an unenforced boundary into a silent allow.
//!
//! `RealProcessExecutor` is the backend [`SandboxPlugin::new`] describes, because that is
//! the platform backend a deployment would execute in. `nau_sandbox`'s own
//! `DefaultExecutor` type alias is still `NullExecutor`, which executes nothing and
//! therefore declares **every** boundary unenforced; a host that wants that honest
//! baseline instead can build the plugin with
//! `SandboxPlugin::with_executor(nau_sandbox::shared(nau_sandbox::NullExecutor::new()))`
//! and will see all twelve boundaries reported as unenforced.
//!
//! # Operations
//!
//! | `op` | Fields | Answer |
//! |---|---|---|
//! | `platform` | — | `backend`, `platform`, `enforced`, `unenforced` (each with `reason`), `boundaries` |
//! | `preflight` | `spec` (a `SandboxSpec` object) | `backend`, `satisfiable`, `requests`, `unmet` (each naming a boundary) |
//!
//! Both operations require the request to declare `kernel:isolation:configure`: the plugin
//! declares that capability because isolation configuration is its whole subject matter,
//! and the bus checks the *caller's* token for it before the message is delivered — so an
//! official or third-party plugin cannot even reach this door.

use std::sync::Arc;

use nau_plugin::bus::PmbMessage;
use nau_plugin::{Capability, PluginId, Result};
use nau_sandbox::{
    AbsoluteProgramPath, Capabilities, Capability as BoundaryCapability, RealProcessExecutor,
    SandboxExecutor, SandboxSpec, PLATFORM_BACKEND,
};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// Error code: the specification was not one this plugin could preflight.
pub const CODE_SANDBOX_SPEC: &str = "sandbox_spec_refused";

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["platform", "preflight"];

/// The reason reported for a boundary that is neither enforced nor given one by the
/// backend. The same sentence `nau_sandbox::Capabilities::require` falls back to, so the
/// report and the refusal cannot disagree about what silence means.
const NO_REASON: &str = "this backend publishes no enforcement for it";

/// The sandbox system plugin.
pub struct SandboxPlugin {
    id: PluginId,
    grant: PluginGrant,
    /// The backend whose declaration is reported. Constructor wiring, not ambient
    /// authority: the context carries no sandbox manager, so the host chooses this when it
    /// compiles the plugin in — see [`SandboxPlugin::with_executor`].
    executor: Arc<dyn SandboxExecutor>,
}

impl SandboxPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.sandbox";

    /// The capabilities the plugin declares: the basic set plus
    /// `kernel:isolation:configure`.
    ///
    /// It declares the kernel capability because isolation is the thing it is the door
    /// onto; a caller must hold `kernel:isolation:configure` for the bus to deliver its
    /// request, and only the system tier can hold it.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
        Capability::KernelIsolationConfigure,
    ];

    /// Build the plugin, describing this platform's real process backend.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if [`SandboxPlugin::ID`] is not a valid plugin
    /// name, which cannot happen for this constant but is returned rather than asserted.
    pub fn new() -> Result<Self> {
        Self::with_executor(nau_sandbox::shared(RealProcessExecutor::new()))
    }

    /// Build the plugin around an explicit backend declaration.
    ///
    /// Exists so a host can wire the backend it actually runs — including
    /// `NullExecutor`, whose declaration is "every boundary unenforced" — without editing
    /// this plugin. The backend is used for exactly two things: reading its
    /// [`SandboxExecutor::capabilities`] and asking its
    /// [`SandboxExecutor::validate`]; this plugin never creates, executes or destroys a
    /// sandbox.
    ///
    /// # Errors
    ///
    /// As [`SandboxPlugin::new`].
    pub fn with_executor(executor: Arc<dyn SandboxExecutor>) -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
            executor,
        })
    }

    /// The name of the backend this plugin describes.
    #[must_use]
    pub fn backend(&self) -> &str {
        self.executor.capabilities().backend()
    }

    /// `preflight`: can the backend serve this specification?
    ///
    /// A specification that is not self-consistent at all (a zero limit, a relative
    /// filesystem path, an empty allow list) is a [`CODE_SANDBOX_SPEC`] refusal: it is not
    /// a boundary question, and answering "unsatisfiable" would let a caller believe the
    /// *backend* was the obstacle. Everything else is answered with `satisfiable` plus
    /// **every** unmet boundary, not only the first: a caller fixing one boundary at a
    /// time should not have to ask this plugin three times.
    fn preflight(&self, request: &Value) -> Result<Value> {
        let spec_value = payload::field(request, "spec")?;
        let spec: SandboxSpec = serde_json::from_value(spec_value.clone()).map_err(|e| {
            payload::protocol(
                CODE_SANDBOX_SPEC,
                format!("`spec` is not a sandbox specification: {e}"),
            )
        })?;
        // `AbsoluteProgramPath`'s serde implementation is transparent over `PathBuf`, so a
        // relative program path survives deserialisation without passing the constructor
        // that refuses it. Re-run that constructor here rather than hand the executor a
        // spec whose program would be looked up on `PATH`.
        AbsoluteProgramPath::new(spec.interpreter.bin().as_path()).map_err(|e| {
            payload::protocol(
                CODE_SANDBOX_SPEC,
                format!("the program this specification names cannot be started: {e}"),
            )
        })?;
        spec.validate().map_err(|e| {
            payload::protocol(
                CODE_SANDBOX_SPEC,
                format!("the specification is not self-consistent: {e}"),
            )
        })?;

        let caps = self.executor.capabilities();
        // `SandboxSpec::boundary_requests` and `Waivers::requests` can name the same
        // boundary twice — a waiver for disk quota appears in both — so both lists are
        // applied, and both the request list and the unmet list are deduplicated by
        // boundary. A caller must not be told "disk_quota" twice and conclude it has two
        // problems.
        let mut requests: Vec<&'static str> = Vec::new();
        let mut unmet: Vec<(&'static str, String)> = Vec::new();
        for boundary_request in spec
            .boundary_requests()
            .into_iter()
            .chain(spec.waivers.requests())
        {
            let name = boundary_request.boundary().as_str();
            if !requests.contains(&name) {
                requests.push(name);
            }
            if let Err(refusal) = boundary_request.apply(caps) {
                if !unmet.iter().any(|(seen, _)| *seen == name) {
                    unmet.push((name, refusal.to_string()));
                }
            }
        }
        let satisfiable = unmet.is_empty();
        if satisfiable {
            // The backend's own `validate` is the authority on whether a spec may run. If
            // it refused a spec this loop judged satisfiable, the loop and the executor
            // disagree, and the refusal is what gets reported -- a plugin must never claim
            // "satisfiable" on the strength of its own re-implementation of the check.
            self.executor.validate(&spec).map_err(|e| {
                payload::protocol(
                    CODE_SANDBOX_SPEC,
                    format!(
                        "the backend refused a specification this plugin's own boundary check \
                         accepted: {e}"
                    ),
                )
            })?;
        }
        let unmet_json: Vec<Value> = unmet
            .iter()
            .map(|(boundary, detail)| json!({ "boundary": boundary, "detail": detail }))
            .collect();
        let requests_json: Vec<Value> = requests.iter().map(|name| json!(name)).collect();
        Ok(payload::answer(
            Self::ID,
            "preflight",
            json!({
                "backend": caps.backend(),
                "platform": PLATFORM_BACKEND,
                "satisfiable": satisfiable,
                "requests": requests_json,
                "unmet": unmet_json,
            }),
        ))
    }
}

impl SystemPlugin for SandboxPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        let caps = self.executor.capabilities();
        ctx.log(
            LogLevel::Info,
            &format!(
                "sandbox ready: backend `{}` enforces {} of {} boundaries; {} are published as \
                 unenforced",
                caps.backend(),
                enforced_names(caps).len(),
                BoundaryCapability::ALL.len(),
                caps.unenforced().len()
            ),
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        self.grant
            .require_operation(declared, Capability::KernelIsolationConfigure)?;
        let op = payload::operation(&msg.payload)?;
        match op {
            "platform" => Ok(payload::answer(
                Self::ID,
                "platform",
                platform_json(self.executor.capabilities()),
            )),
            "preflight" => self.preflight(&msg.payload),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        // Nothing to release but the grant: this plugin holds no sandbox, no directory and
        // no state between calls.
        self.grant.release();
        Ok(())
    }
}

/// The backend's whole declaration as JSON.
///
/// Built from [`Capabilities::declaration`], which walks `Capability::ALL` and answers
/// `(boundary, enforced, reason)` for each — so the enforced and unenforced lists are two
/// views of one traversal and cannot list a boundary twice or omit it.
#[must_use]
pub fn platform_json(caps: &Capabilities) -> Value {
    let mut enforced: Vec<Value> = Vec::new();
    let mut unenforced: Vec<Value> = Vec::new();
    for (boundary, is_enforced, reason) in caps.declaration() {
        if is_enforced {
            enforced.push(json!(boundary.as_str()));
        } else {
            unenforced.push(json!({
                "boundary": boundary.as_str(),
                "reason": reason.unwrap_or(NO_REASON),
            }));
        }
    }
    json!({
        "backend": caps.backend(),
        "platform": PLATFORM_BACKEND,
        "enforced": enforced,
        "unenforced": unenforced,
        "boundaries": BoundaryCapability::ALL.len(),
    })
}

/// The boundaries `caps` enforces, as a vector of names.
///
/// Used for the one number in the startup log; `platform_json` is what callers see.
fn enforced_names(caps: &Capabilities) -> Vec<&'static str> {
    caps.declaration()
        .into_iter()
        .filter(|(_, is_enforced, _)| *is_enforced)
        .map(|(boundary, _, _)| boundary.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{HostLimits, SystemPluginHost};
    use ed25519_dalek::SigningKey;
    use nau_plugin::bus::{PmbKind, Target};
    use nau_plugin::lifecycle::PluginState;
    use nau_plugin::{CapabilityToken, Tier, VerifiedManifest};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NOW: u64 = 1_750_000_000;

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn verified_manifest(plugin: &impl SystemPlugin) -> VerifiedManifest {
        crate::sign::verified_system(
            plugin.id().as_str(),
            plugin.capabilities(),
            &signing_key(7),
            &signing_key(9),
        )
        .expect("the system manifest verifies")
    }

    fn started(caps: &[Capability]) -> SandboxPlugin {
        let mut plugin = SandboxPlugin::new().expect("valid id");
        let token = CapabilityToken::issue(SandboxPlugin::ID, Tier::System, caps, DIGEST, NOW)
            .expect("issuable");
        let mut ctx = HostContext::new(token, HostLimits::default()).expect("context");
        plugin.init(&mut ctx).expect("inits");
        plugin
    }

    fn request(capability: &str, payload: Value) -> PmbMessage {
        let id = PluginId::parse("com.twinsearth.official.market").expect("id");
        PmbMessage::new(
            &id,
            Target::Plugin(SandboxPlugin::ID.to_string()),
            Capability::parse(capability).expect("known"),
            PmbKind::Request,
            payload,
            NOW,
        )
    }

    fn limits() -> Value {
        json!({
            "timeout_ms": 1_000,
            "memory_bytes": 1_048_576,
            "cpu_ms": 1_000,
            "disk_bytes": 1_048_576,
            "max_processes": 2,
            "max_open_files": 8,
            "max_output_bytes": 1_024,
        })
    }

    fn spec(network: Value, confinement: &str, waivers: Value) -> Value {
        json!({
            "op": "preflight",
            "spec": {
                "interpreter": {
                    "binary": std::env::current_exe()
                        .expect("the test binary has a path")
                        .display()
                        .to_string()
                },
                "limits": limits(),
                "network": network,
                "filesystem": {
                    "confinement": confinement,
                    "extra_readable": [],
                    "writable": [],
                },
                "env": { "inherit": "nothing", "vars": [] },
                "waivers": waivers,
            }
        })
    }

    fn no_waivers() -> Value {
        json!({
            "filesystem_confinement": null,
            "disk_bytes": null,
            "cpu_ms": null,
            "max_open_files": null,
        })
    }

    #[test]
    fn the_plugin_registers_initialises_and_reaches_running() {
        let plugin = SandboxPlugin::new().expect("valid id");
        assert_eq!(plugin.id().as_str(), SandboxPlugin::ID);
        let verified = verified_manifest(&plugin);
        let mut host = SystemPluginHost::new(HostLimits::default()).expect("host");
        host.register(Box::new(plugin), &verified, NOW)
            .expect("registers against its own system manifest");
        assert_eq!(host.state(SandboxPlugin::ID), Some(PluginState::Loaded));
        host.init(SandboxPlugin::ID, NOW).expect("inits");
        assert_eq!(host.state(SandboxPlugin::ID), Some(PluginState::Running));
    }

    #[test]
    fn the_platform_report_is_the_backends_own_declaration_of_what_it_cannot_enforce() {
        let mut plugin = started(SandboxPlugin::CAPABILITIES);
        let answer = plugin
            .handle(&request(
                "kernel:isolation:configure",
                json!({ "op": "platform" }),
            ))
            .expect("answers");
        assert_eq!(answer["ok"], json!(true));
        assert_eq!(answer["backend"], json!(plugin.backend()));

        let expected = RealProcessExecutor::new().capabilities().clone();
        let enforced: Vec<String> = answer["enforced"]
            .as_array()
            .expect("enforced is an array")
            .iter()
            .map(|name| name.as_str().unwrap_or_default().to_string())
            .collect();
        let unenforced: Vec<String> = answer["unenforced"]
            .as_array()
            .expect("unenforced is an array")
            .iter()
            .map(|entry| {
                assert!(
                    !entry["reason"].as_str().unwrap_or_default().is_empty(),
                    "every unenforced boundary must carry its backend's reason: {entry}"
                );
                entry["boundary"].as_str().unwrap_or_default().to_string()
            })
            .collect();

        // The report is the declaration, boundary for boundary, in both directions.
        for (boundary, is_enforced, _) in expected.declaration() {
            let name = boundary.as_str().to_string();
            if is_enforced {
                assert!(
                    enforced.contains(&name),
                    "{name} is enforced but unreported"
                );
            } else {
                assert!(
                    unenforced.contains(&name),
                    "{name} is not enforced but was reported as if it were"
                );
            }
            assert!(
                !(enforced.contains(&name) && unenforced.contains(&name)),
                "{name} is listed in both halves"
            );
        }
        assert_eq!(
            enforced.len() + unenforced.len(),
            BoundaryCapability::ALL.len()
        );

        // The boundaries this project keeps being told it has, and does not.
        for boundary in [
            BoundaryCapability::NetworkDenyAll,
            BoundaryCapability::FilesystemConfinement,
            BoundaryCapability::DiskQuota,
        ] {
            assert!(
                unenforced.contains(&boundary.as_str().to_string()),
                "{} must be reported unenforced, not wished for",
                boundary.as_str()
            );
        }
        // On Windows the job object also has no CPU-time or handle cap. On Unix both are
        // enforced through `setrlimit`, and the crate says that path is unverified there.
        #[cfg(windows)]
        for boundary in [
            BoundaryCapability::CpuLimit,
            BoundaryCapability::OpenFileLimit,
        ] {
            assert!(
                unenforced.contains(&boundary.as_str().to_string()),
                "{} must be reported unenforced on Windows",
                boundary.as_str()
            );
        }
        #[cfg(unix)]
        for boundary in [
            BoundaryCapability::CpuLimit,
            BoundaryCapability::OpenFileLimit,
        ] {
            assert!(
                enforced.contains(&boundary.as_str().to_string()),
                "{} is enforced through setrlimit on Unix",
                boundary.as_str()
            );
        }
    }

    #[test]
    fn a_preflight_names_the_boundaries_this_backend_cannot_deliver() {
        let mut plugin = started(SandboxPlugin::CAPABILITIES);

        // Deny-all egress and filesystem confinement: nobody enforces either on this
        // platform, so the preflight must say so by name rather than by "false".
        let answer = plugin
            .handle(&request(
                "kernel:isolation:configure",
                spec(json!("deny_all"), "required", no_waivers()),
            ))
            .expect("answers");
        assert_eq!(answer["satisfiable"], json!(false));
        let unmet: Vec<String> = answer["unmet"]
            .as_array()
            .expect("unmet is an array")
            .iter()
            .map(|entry| entry["boundary"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(unmet.contains(&"network_deny_all".to_string()), "{unmet:?}");
        assert!(
            unmet.contains(&"filesystem_confinement".to_string()),
            "{unmet:?}"
        );
        for entry in answer["unmet"].as_array().expect("unmet is an array") {
            assert!(
                entry["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .contains(entry["boundary"].as_str().unwrap_or_default()),
                "the detail must name the boundary: {entry}"
            );
        }

        // The same shape, with every boundary this backend cannot hold waived by name,
        // *is* satisfiable. A preflight that could only ever answer "no" would be a
        // refusal wearing an answer's clothes.
        let waivers = json!({
            "filesystem_confinement": "test: the platform has no confinement primitive",
            "disk_bytes": "test: no quota primitive on this platform",
            "cpu_ms": "test: the wall-clock timeout is the enforced bound",
            "max_open_files": "test: no handle cap on this platform",
        });
        let answer = plugin
            .handle(&request(
                "kernel:isolation:configure",
                spec(
                    json!({ "unrestricted": { "justification": "test: no egress filter exists" } }),
                    "whole_host",
                    waivers,
                ),
            ))
            .expect("answers");
        assert_eq!(
            answer["satisfiable"],
            json!(true),
            "unmet: {}",
            answer["unmet"]
        );
        // Every boundary the spec touches, each named once -- including the waived ones,
        // which `boundary_requests` and `waivers.requests` both name.
        let requests: Vec<String> = answer["requests"]
            .as_array()
            .expect("requests is an array")
            .iter()
            .map(|name| name.as_str().unwrap_or_default().to_string())
            .collect();
        assert_eq!(requests.len(), 11, "{requests:?}");
        for name in ["disk_quota", "cpu_limit", "open_file_limit"] {
            assert_eq!(
                requests.iter().filter(|seen| *seen == name).count(),
                1,
                "`{name}` must be named exactly once: {requests:?}"
            );
        }
    }

    #[test]
    fn a_request_declaring_a_capability_the_plugin_does_not_hold_is_refused_by_name() {
        let mut plugin = started(SandboxPlugin::CAPABILITIES);

        let err = plugin
            .handle(&request("chain:evm:write", json!({ "op": "platform" })))
            .expect_err("must be refused");
        assert!(err.to_string().contains("chain:evm:write"), "{err}");

        // Held, but not the capability this door needs: the operation gate refuses and
        // names what it required as well as what was declared.
        let err = plugin
            .handle(&request(
                "plugin:lifecycle:read",
                json!({ "op": "platform" }),
            ))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("kernel:isolation:configure"), "{text}");
        assert!(text.contains("plugin:lifecycle:read"), "{text}");
    }
}
