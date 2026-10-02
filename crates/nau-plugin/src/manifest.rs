//! The signed plugin manifest: the one artefact that decides everything else.
//!
//! # Why the manifest is the security boundary
//!
//! Tier, capabilities, limits, entry point and module digest all live in one
//! document, and that document is **signed as a whole**. So changing any of them —
//! including the digest of the code itself — invalidates the signature. There is no
//! second place to look and no field that a forger can adjust independently.
//!
//! # Format deviation, with the reason
//!
//! The draft architecture used `plugin.toml`. This kernel uses **JSON**
//! (`plugin.json`), because the signature is computed over this project's existing
//! *canonical* JSON form — the one that is already byte-identical across Rust,
//! Python and JavaScript and pinned by ten conformance vectors. Signing TOML would
//! require a second canonicaliser for a second syntax, and two canonicalisers are
//! two chances for the signed bytes and the verified bytes to diverge. That is a
//! security argument, not a convenience one.
//!
//! The canonicaliser drops every object key named `signature` at every depth, so the
//! `signature` section below is excluded from the digest by construction rather than
//! by remembering to exclude it.
//!
//! # The four checks
//!
//! [`Manifest::verify`] performs all four, and reports which one failed by
//! [`LoadRefusal`]:
//!
//! 1. the name classifies to a tier, and the tier is loadable;
//! 2. the recomputed digest equals the signed one;
//! 3. the publisher signature verifies under the declared key;
//! 4. the counter-signature verifies under a *trusted vendor* key, for the tiers
//!    that require one — and the module bytes hash to the digest the manifest covers.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capability::{Approval, Capability, CapabilityToken};
use crate::error::{LoadRefusal, PluginError, Result};
use crate::tier::{PluginId, Tier};

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_BYTES: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_BYTES: usize = 64;

/// Length of a SHA-256 digest in hex characters.
pub const DIGEST_HEX_CHARS: usize = 64;

/// Longest accepted `entry` path, in bytes.
pub const MAX_ENTRY_BYTES: usize = 128;

/// The `plugin` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSection {
    /// Reverse-domain plugin name; the prefix decides the tier.
    pub name: String,
    /// The plugin's own semantic version, independent of the kernel's.
    pub version: String,
    /// The ABI the plugin was built against, `major.minor`.
    pub abi: String,
    /// Entry point, relative to the plugin directory and a single path component.
    pub entry: String,
    /// The publisher's DID, for attribution and for binding to the signing key.
    pub publisher: String,
    /// SHA-256 of the entry artefact, covered by the signature.
    pub module_sha256: String,
}

/// The `capabilities` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySection {
    /// Wire names of the capabilities the plugin asks to hold.
    pub grant: Vec<String>,
}

/// The `limits` section.
///
/// Every field is required and every field must be non-zero: the sandbox work in
/// V1.2.3 established that an optional limit is a limit that is silently absent, so
/// there is no `Option` and no `Default` here either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Peak memory the plugin may use, in bytes.
    pub memory_bytes: u64,
    /// Wall-clock budget per call, in milliseconds.
    pub cpu_ms: u64,
    /// Bytes the plugin may write to its own directory.
    pub disk_bytes: u64,
    /// Processes the plugin may have, itself included.
    pub max_processes: u32,
    /// Bytes retained from the plugin's stdout and stderr **each**.
    pub max_output_bytes: u32,
}

impl Limits {
    /// Validate that no limit is zero.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] naming the zero field. Zero is refused rather than
    /// read as "unlimited": those two meanings must not share a spelling.
    pub fn validate(&self) -> Result<()> {
        let zeroed: Vec<&str> = [
            ("memory_bytes", self.memory_bytes == 0),
            ("cpu_ms", self.cpu_ms == 0),
            ("disk_bytes", self.disk_bytes == 0),
            ("max_processes", self.max_processes == 0),
            ("max_output_bytes", self.max_output_bytes == 0),
        ]
        .into_iter()
        .filter_map(|(name, is_zero)| is_zero.then_some(name))
        .collect();
        if zeroed.is_empty() {
            return Ok(());
        }
        Err(PluginError::Manifest(format!(
            "these limits are zero, which is not the same as unlimited: {}",
            zeroed.join(", ")
        )))
    }

    /// The strictest limit in each dimension, for clamping a declared set against a
    /// tier ceiling.
    #[must_use]
    pub fn clamped_to(self, ceiling: Limits) -> Limits {
        Limits {
            memory_bytes: self.memory_bytes.min(ceiling.memory_bytes),
            cpu_ms: self.cpu_ms.min(ceiling.cpu_ms),
            disk_bytes: self.disk_bytes.min(ceiling.disk_bytes),
            max_processes: self.max_processes.min(ceiling.max_processes),
            max_output_bytes: self.max_output_bytes.min(ceiling.max_output_bytes),
        }
    }

    /// Whether `self` asks for more than `ceiling` in any dimension.
    #[must_use]
    pub fn exceeds(self, ceiling: Limits) -> Option<&'static str> {
        if self.memory_bytes > ceiling.memory_bytes {
            Some("memory_bytes")
        } else if self.cpu_ms > ceiling.cpu_ms {
            Some("cpu_ms")
        } else if self.disk_bytes > ceiling.disk_bytes {
            Some("disk_bytes")
        } else if self.max_processes > ceiling.max_processes {
            Some("max_processes")
        } else if self.max_output_bytes > ceiling.max_output_bytes {
            Some("max_output_bytes")
        } else {
            None
        }
    }
}

/// The `signature` section.
///
/// Excluded from the digest by the canonicaliser (it drops every key named
/// `signature`), so the signature cannot cover itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSection {
    /// The publisher's Ed25519 public key, lower-case hex (32 bytes).
    pub publisher_key: String,
    /// The digest the signature covers, lower-case hex (32 bytes).
    pub manifest_digest: String,
    /// Ed25519 signature over the digest bytes, lower-case hex (64 bytes).
    pub sig: String,
    /// Vendor counter-signature, required for the tiers that cannot self-authorise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_sig: Option<String>,
    /// The vendor key that produced `counter_sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_key: Option<String>,
}

/// A parsed plugin manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Identity, version, ABI, entry, publisher, module digest.
    pub plugin: PluginSection,
    /// The capabilities the plugin asks to hold.
    pub capabilities: CapabilitySection,
    /// The resources the plugin asks for.
    pub limits: Limits,
    /// Boundaries the publisher waives, keyed by `Boundary::waiver_key`, with the
    /// reason. This is part of the **signed** payload, so a waiver cannot be added
    /// to a manifest after the fact.
    ///
    /// It is `#[serde(default)]` rather than required, because a plugin that needs no
    /// waiver should not have to write an empty section — and a plugin that *does*
    /// need one is refused by the runtime with the boundary named, which is a better
    /// error than a schema violation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub waivers: BTreeMap<String, String>,
    /// Other plugins this one must be started after.
    ///
    /// # Why this field had to exist for the dependency machinery to mean anything
    ///
    /// [`Registry::load_order`](crate::registry::Registry::load_order) sorts a dependency
    /// graph, `HotPlug::start_order` and `stop_plan` answer from it, and `sys.orchestrator`
    /// exists to report it. **None of that could ever do anything**, because a plugin had no
    /// way to declare an edge: this struct had no field for one, and the only caller of
    /// `LoadRequest::depending_on` in the whole repository was a kernel test. Every order was
    /// therefore an order over a graph with no edges, which is the insertion order.
    ///
    /// `#[serde(default)]` because most plugins depend on nothing, and
    /// `skip_serializing_if` because the serialised manifest is what the signature covers:
    /// emitting an empty array for every existing plugin would change every digest and
    /// invalidate every signature already in the field. A manifest that declares nothing
    /// serialises **byte-for-byte as it did before this field existed**.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<crate::registry::Dependency>,
    /// Signatures. Never covered by the digest.
    pub signature: SignatureSection,
}

/// A manifest that passed all four checks, together with the token it earned.
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    /// The verified manifest.
    pub manifest: Manifest,
    /// Its tier, recomputed from the signed name.
    pub tier: Tier,
    /// The validated plugin id.
    pub id: PluginId,
    /// The capability token, bound to the manifest digest.
    pub token: CapabilityToken,
    /// The digest of the entry artefact that was hashed.
    pub module_digest: String,
}

impl Manifest {
    /// Parse a manifest from JSON.
    ///
    /// # Errors
    ///
    /// [`PluginError::Json`] when the document is not valid JSON or does not match
    /// the schema, and [`PluginError::Manifest`] when it parses but is not
    /// self-consistent. `deny_unknown_fields` is on everywhere: a typo'd key must be
    /// a refusal, not a silently-ignored line, because the line a plugin author got
    /// wrong is exactly the line they believed was in force.
    pub fn parse(json: &str) -> Result<Self> {
        let manifest: Self = serde_json::from_str(json)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Check the manifest for internal consistency and return its tier.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] or [`PluginError::Name`] naming the first problem.
    pub fn validate(&self) -> Result<Tier> {
        let tier = Tier::from_name(&self.plugin.name)?;
        if !tier.is_loadable() {
            return Err(PluginError::Tier(format!(
                "`{}` classifies as {tier}, which is never loadable",
                self.plugin.name
            )));
        }
        validate_semver(&self.plugin.version)
            .map_err(|e| PluginError::Manifest(format!("plugin.version: {e}")))?;
        validate_abi(&self.plugin.abi)?;
        validate_entry(&self.plugin.entry)?;
        validate_hex(
            &self.plugin.module_sha256,
            DIGEST_HEX_CHARS,
            "plugin.module_sha256",
        )?;
        if !self.plugin.publisher.starts_with("did:") {
            return Err(PluginError::Manifest(format!(
                "plugin.publisher `{}` is not a DID",
                self.plugin.publisher
            )));
        }
        self.limits.validate()?;
        // Capabilities are parsed here so that an unknown wire name is refused at
        // load time rather than at first use, when the plugin is already running.
        for name in &self.capabilities.grant {
            Capability::parse(name)?;
        }
        let mut seen = BTreeSet::new();
        for name in &self.capabilities.grant {
            if !seen.insert(name.as_str()) {
                return Err(PluginError::Manifest(format!(
                    "capabilities.grant lists `{name}` twice"
                )));
            }
        }
        Ok(tier)
    }

    /// The capabilities the manifest asks for, parsed.
    ///
    /// # Errors
    ///
    /// [`PluginError::Capability`] for an unknown wire name; unreachable after
    /// [`Manifest::validate`], but callers outside this crate have not necessarily
    /// validated.
    pub fn requested_capabilities(&self) -> Result<Vec<Capability>> {
        self.capabilities
            .grant
            .iter()
            .map(|name| Capability::parse(name))
            .collect()
    }

    /// The canonical bytes the signature covers: the whole manifest, minus every key
    /// named `signature`.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when canonicalisation fails, which cannot happen for
    /// this schema (integers only, object root) but is returned rather than unwrapped.
    pub fn canonical(&self) -> Result<String> {
        nau_core::identity::canonical::canonical_payload_string(self)
            .map_err(|e| PluginError::Manifest(format!("cannot canonicalise manifest: {e}")))
    }

    /// SHA-256 of [`Manifest::canonical`], lower-case hex.
    ///
    /// # Errors
    ///
    /// As [`Manifest::canonical`].
    pub fn digest_hex(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(self.canonical()?.as_bytes())))
    }

    /// Perform all four checks and, on success, mint the capability token.
    ///
    /// `module` is the bytes of the entry artefact; `trust` decides which keys are
    /// acceptable; `now` is the issue time recorded in the token.
    ///
    /// Equivalent to [`Manifest::verify_with_approvals`] with an empty approval list, so a
    /// capability that needs an authority is refused here. That is the right default for
    /// a caller that has not decided who may approve anything.
    ///
    /// # Errors
    ///
    /// [`PluginError`] whose message begins with the refusal code, so a caller can
    /// report *which* check failed without parsing prose. The variants used are
    /// [`PluginError::Signature`], [`PluginError::Tier`] and
    /// [`PluginError::Capability`].
    pub fn verify(&self, module: &[u8], trust: &TrustStore, now: u64) -> Result<VerifiedManifest> {
        self.verify_with_approvals(module, trust, now, &[])
    }

    /// The same four checks, with approvals that were actually granted.
    ///
    /// # Why this exists
    ///
    /// `Capability::resolve_with_approvals` made the approval branch of the tier matrix
    /// reachable, but nothing could *reach* it through verification: `verify` minted the
    /// token with `CapabilityToken::issue`, which refuses every `RequiresApproval` entry.
    /// So an Official plugin still could not hold a capability its tier is allowed to
    /// hold after review — the model was expressible and not reachable, which is the same
    /// defect one level down. This is the door that joins them.
    ///
    /// `approvals` is the list of `(capability, authority)` pairs some authority has
    /// granted for this plugin. It is **not** a request: a caller that could name its own
    /// authority would not need one. Whatever is not approved is refused, and whatever the
    /// tier refuses outright cannot be approved at all.
    ///
    /// # Errors
    ///
    /// As [`Manifest::verify`], plus [`PluginError::Capability`] naming a capability whose
    /// required authority is absent.
    pub fn verify_with_approvals(
        &self,
        module: &[u8],
        trust: &TrustStore,
        now: u64,
        approvals: &[(Capability, Approval)],
    ) -> Result<VerifiedManifest> {
        let tier = self.validate()?;
        let id = PluginId::parse(&self.plugin.name)?;

        // 2. the digest is recomputed, never trusted
        let recomputed = self.digest_hex()?;
        if !constant_time_eq_hex(&recomputed, &self.signature.manifest_digest) {
            return Err(refusal(
                LoadRefusal::ManifestInvalid,
                format!(
                    "manifest digest mismatch: the document hashes to {} but the signature covers {}",
                    short(&recomputed),
                    short(&self.signature.manifest_digest)
                ),
            ));
        }

        // 3. the publisher signature verifies over the digest bytes
        let publisher_key = parse_key(&self.signature.publisher_key, "publisher_key")?;
        verify_over_digest(&publisher_key, &self.signature.sig, &recomputed).map_err(|e| {
            refusal(
                LoadRefusal::SignatureInvalid,
                format!("publisher signature: {e}"),
            )
        })?;

        // 4. the module bytes hash to what the manifest covers
        let module_digest = hex::encode(Sha256::digest(module));
        if !constant_time_eq_hex(&module_digest, &self.plugin.module_sha256) {
            return Err(refusal(
                LoadRefusal::ModuleDigestMismatch,
                format!(
                    "the entry artefact hashes to {} but the manifest covers {}",
                    short(&module_digest),
                    short(&self.plugin.module_sha256)
                ),
            ));
        }

        // 1b. the counter-signature, for the tiers that cannot self-authorise
        if tier.requires_counter_signature() {
            let counter_sig = self.signature.counter_sig.as_deref().ok_or_else(|| {
                refusal(
                    LoadRefusal::CounterSignatureMissing,
                    format!(
                        "tier {tier} requires a vendor counter-signature; the manifest carries none \
                         (a publisher key alone cannot authorise this tier)"
                    ),
                )
            })?;
            let counter_key_hex = self.signature.counter_key.as_deref().ok_or_else(|| {
                refusal(
                    LoadRefusal::CounterSignatureMissing,
                    "a counter-signature was supplied without `counter_key`, so it cannot be \
                     attributed to a trusted vendor key"
                        .to_string(),
                )
            })?;
            if !trust.is_trusted_vendor_key(counter_key_hex) {
                return Err(refusal(
                    LoadRefusal::UntrustedPublisher,
                    format!(
                        "counter-signature key {} is not in the vendor trust store",
                        short(counter_key_hex)
                    ),
                ));
            }
            let counter_key = parse_key(counter_key_hex, "counter_key")?;
            verify_over_digest(&counter_key, counter_sig, &recomputed).map_err(|e| {
                refusal(
                    LoadRefusal::SignatureInvalid,
                    format!("vendor counter-signature: {e}"),
                )
            })?;
        } else if !trust.is_trusted_third_party_key(&self.signature.publisher_key) {
            // Third-party plugins need no counter-signature, so the only thing that
            // can vouch for them is the operator having trusted this key. Without it
            // the plugin is not loadable — the tier is deliberately the strictest but
            // it is not "accept anything signed by anyone".
            return Err(refusal(
                LoadRefusal::UntrustedPublisher,
                format!(
                    "third-party publisher {} is not in the operator's trusted key list; add it \
                     explicitly before this plugin can load",
                    short(&self.signature.publisher_key)
                ),
            ));
        }

        // Clamp declared limits to the tier ceiling, and record the clamping: a plugin
        // that asks for more than its tier allows is not an error, but it must not get
        // more than the ceiling either.
        let requested = self.requested_capabilities()?;
        // Every refusal this function produces carries a `LoadRefusal` code, so a
        // caller (and the tests) can branch on the kind without matching prose. The
        // capability path was the one place that did not, which a test caught.
        let token = CapabilityToken::issue_with_approvals(
            &self.plugin.name,
            tier,
            &requested,
            approvals,
            &recomputed,
            now,
        )
        .map_err(|e| {
            let text = e.to_string();
            // The two capability refusals mean different things to an operator, so they are
            // different codes: one says "ask the authority named here", the other says "no
            // authority can grant this". Collapsing them made `capability_not_approved`
            // unreachable from any pipeline stage -- a code in the vocabulary that nothing
            // could produce, reported by the system plugin that reads the vocabulary.
            let which = if text.contains("needs approval from") {
                LoadRefusal::CapabilityNotApproved
            } else {
                LoadRefusal::CapabilityNotPermitted
            };
            refusal(which, text)
        })?;

        Ok(VerifiedManifest {
            manifest: self.clone(),
            tier,
            id,
            token,
            module_digest,
        })
    }

    /// The tier this manifest classifies as.
    ///
    /// # Errors
    ///
    /// [`PluginError::Name`] when the name is unclassifiable.
    pub fn tier(&self) -> Result<Tier> {
        Tier::from_name(&self.plugin.name)
    }

    /// The ABI the plugin was built against.
    ///
    /// This is what the arbiter consults to decide whether the host can *serve* the
    /// plugin — a separate question from whether the manifest is authentic, and the one
    /// an [`crate::hot::AdapterRegistry`] answers.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when `plugin.abi` is malformed or from the future.
    pub fn abi(&self) -> Result<crate::hot::Abi> {
        let (major, minor) = validate_abi(&self.plugin.abi)?;
        Ok(crate::hot::Abi::new(major, minor))
    }
}

/// Which keys this host accepts.
///
/// Fail-closed by construction: [`TrustStore::deny_all`] is the default, so an
/// unconfigured host trusts no publisher and loads no plugin. That is the same
/// posture the V1.2.3 REST surface took (unconfigured means refuse), and it is the
/// opposite of the upstream defect where an empty trust configuration meant
/// "anything goes".
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    vendor_keys: BTreeSet<String>,
    third_party_keys: BTreeSet<String>,
}

impl TrustStore {
    /// A store that trusts nobody.
    #[must_use]
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Trust a vendor key (one that may counter-sign official and certified plugins).
    pub fn trust_vendor_key(&mut self, hex_key: &str) -> Result<()> {
        validate_hex(hex_key, PUBLIC_KEY_BYTES * 2, "vendor key")?;
        let _ = parse_key(hex_key, "vendor key")?;
        self.vendor_keys.insert(hex_key.to_ascii_lowercase());
        Ok(())
    }

    /// Trust a third-party publisher key.
    pub fn trust_third_party_key(&mut self, hex_key: &str) -> Result<()> {
        validate_hex(hex_key, PUBLIC_KEY_BYTES * 2, "publisher key")?;
        let _ = parse_key(hex_key, "publisher key")?;
        self.third_party_keys.insert(hex_key.to_ascii_lowercase());
        Ok(())
    }

    /// Whether `key` may counter-sign.
    #[must_use]
    pub fn is_trusted_vendor_key(&self, key: &str) -> bool {
        self.vendor_keys.contains(&key.to_ascii_lowercase())
    }

    /// Whether `key` is an operator-trusted third-party publisher.
    #[must_use]
    pub fn is_trusted_third_party_key(&self, key: &str) -> bool {
        self.third_party_keys.contains(&key.to_ascii_lowercase())
    }

    /// How many keys are trusted, for reporting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vendor_keys.len() + self.third_party_keys.len()
    }

    /// Whether nothing is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An error carrying a [`LoadRefusal`] code in a machine-readable prefix.
fn refusal(why: LoadRefusal, detail: String) -> PluginError {
    let message = format!("{}: {detail}", why.code());
    match why {
        LoadRefusal::UntrustedPublisher
        | LoadRefusal::CounterSignatureMissing
        | LoadRefusal::CertificationMissing => PluginError::Signature(message),
        LoadRefusal::SignatureInvalid | LoadRefusal::ModuleDigestMismatch => {
            PluginError::Signature(message)
        }
        LoadRefusal::Blacklisted => PluginError::Blacklist(message),
        LoadRefusal::CapabilityNotPermitted | LoadRefusal::CapabilityNotApproved => {
            PluginError::Capability(message)
        }
        LoadRefusal::IsolationNotEnforceable => PluginError::Runtime(message),
        LoadRefusal::DependencyUnsatisfied => PluginError::Manifest(message),
        LoadRefusal::AbiIncompatible => PluginError::Manifest(message),
        LoadRefusal::NameInvalid | LoadRefusal::ManifestInvalid => PluginError::Manifest(message),
    }
}

/// Validate `major.minor.patch`, all numeric.
fn validate_semver(version: &str) -> std::result::Result<(), String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("`{version}` is not major.minor.patch"));
    }
    for part in parts {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("`{version}` has a non-numeric component"));
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err(format!("`{version}` has a leading zero in `{part}`"));
        }
    }
    Ok(())
}

/// Validate the ABI string, refusing only what no adapter could ever fix.
///
/// # Why an older major is accepted here
///
/// Authenticity and compatibility are two different questions. `verify` answers the
/// first: is this manifest what its publisher signed, and is it well formed. Whether
/// *this host* can serve a plugin built for an older ABI is the second, and from V3.2.1
/// it is answered by the arbiter through an [`crate::hot::AdapterRegistry`] — so a `2.x`
/// plugin verifies here and is then either adapted or refused, with the adapter named in
/// the load trace either way.
///
/// What is still refused here is an ABI **from the future**: no adapter can translate
/// downwards, because the host cannot know what the newer ABI added. That refusal cannot
/// be moved to a later stage without pretending otherwise.
fn validate_abi(abi: &str) -> Result<(u32, u32)> {
    let parts: Vec<&str> = abi.split('.').collect();
    if parts.len() != 2 {
        return Err(PluginError::Manifest(format!(
            "plugin.abi `{abi}` is not major.minor"
        )));
    }
    let parse = |s: &str| -> Result<u32> {
        s.parse::<u32>().map_err(|_| {
            PluginError::Manifest(format!("plugin.abi `{abi}` has a non-numeric component"))
        })
    };
    let (major, minor) = (parse(parts[0])?, parse(parts[1])?);
    if major > crate::ABI_MAJOR || (major == crate::ABI_MAJOR && minor > crate::ABI_MINOR) {
        return Err(refusal(
            LoadRefusal::AbiIncompatible,
            format!(
                "plugin.abi is {major}.{minor}, newer than this host's {}.{}; a newer ABI cannot be \
                 adapted downwards, because the host does not know what it added",
                crate::ABI_MAJOR,
                crate::ABI_MINOR
            ),
        ));
    }
    Ok((major, minor))
}

/// Validate `entry`: one path component, no separators, no traversal.
fn validate_entry(entry: &str) -> Result<()> {
    if entry.is_empty() {
        return Err(PluginError::Manifest("plugin.entry is empty".into()));
    }
    if entry.len() > MAX_ENTRY_BYTES {
        return Err(PluginError::Manifest(format!(
            "plugin.entry is {} bytes; the maximum is {MAX_ENTRY_BYTES}",
            entry.len()
        )));
    }
    if entry.contains('/') || entry.contains('\\') || entry.contains("..") {
        return Err(PluginError::Manifest(format!(
            "plugin.entry `{entry}` must be a single path component with no separators or traversal"
        )));
    }
    if entry.contains('\0') {
        return Err(PluginError::Manifest(
            "plugin.entry contains a NUL byte".into(),
        ));
    }
    if entry.starts_with('.') {
        return Err(PluginError::Manifest(format!(
            "plugin.entry `{entry}` must not be a dot-file"
        )));
    }
    Ok(())
}

/// Validate a lower-case hex string of an exact length.
fn validate_hex(value: &str, expected_chars: usize, field: &str) -> Result<()> {
    if value.len() != expected_chars {
        return Err(PluginError::Manifest(format!(
            "{field} is {} hex characters; {expected_chars} are required",
            value.len()
        )));
    }
    if value != value.to_ascii_lowercase() {
        return Err(PluginError::Manifest(format!(
            "{field} must be lower-case hex"
        )));
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PluginError::Manifest(format!(
            "{field} contains a non-hex character"
        )));
    }
    Ok(())
}

/// Parse a hex Ed25519 public key.
fn parse_key(hex_key: &str, field: &str) -> Result<VerifyingKey> {
    validate_hex(hex_key, PUBLIC_KEY_BYTES * 2, field)?;
    let bytes = hex::decode(hex_key)
        .map_err(|e| PluginError::Signature(format!("{field} is not hex: {e}")))?;
    let arr: [u8; PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| PluginError::Signature(format!("{field} is not {PUBLIC_KEY_BYTES} bytes")))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| PluginError::Signature(format!("{field} is not a valid Ed25519 key: {e}")))
}

/// Verify a hex signature over the ASCII bytes of a hex digest.
fn verify_over_digest(key: &VerifyingKey, sig_hex: &str, digest_hex: &str) -> Result<()> {
    validate_hex(sig_hex, SIGNATURE_BYTES * 2, "signature")?;
    let raw = hex::decode(sig_hex)
        .map_err(|e| PluginError::Signature(format!("signature is not hex: {e}")))?;
    let arr: [u8; SIGNATURE_BYTES] = raw
        .try_into()
        .map_err(|_| PluginError::Signature("signature is not 64 bytes".into()))?;
    let signature = Signature::from_bytes(&arr);
    key.verify(digest_hex.as_bytes(), &signature)
        .map_err(|e| PluginError::Signature(format!("does not verify: {e}")))
}

/// Compare two hex strings without an early exit.
///
/// The values compared here are public digests, so timing is not a secret-leak
/// concern today; it is done this way because the same helper is the obvious place a
/// future caller would reach for when comparing something that *is* secret, and a
/// function that is right for both is better than one that has to be remembered.
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// First 12 characters of a hex string, for messages.
fn short(s: &str) -> &str {
    &s[..s.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_750_000_000;

    fn keypair(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key_hex(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    fn limits() -> Limits {
        Limits {
            memory_bytes: 256 * 1024 * 1024,
            cpu_ms: 20_000,
            disk_bytes: 64 * 1024 * 1024,
            max_processes: 4,
            max_output_bytes: 256 * 1024,
        }
    }

    fn module() -> Vec<u8> {
        b"#!/bin/sh\necho hello\n".to_vec()
    }

    /// A manifest for `name` at `tier`, signed by `publisher`, before the digest and
    /// signature fields are filled in.
    fn draft(name: &str, abi: &str, caps: &[&str], publisher: &SigningKey) -> Manifest {
        Manifest {
            plugin: PluginSection {
                name: name.to_string(),
                // A plugin's own version, deliberately not the kernel's: tying a
                // fixture to the release version makes a routine bump rewrite fixtures.
                version: "1.4.0".into(),
                abi: abi.to_string(),
                entry: "plugin.bin".into(),
                publisher: "did:nau:0011223344556677".into(),
                module_sha256: hex::encode(Sha256::digest(module())),
            },
            capabilities: CapabilitySection {
                grant: caps.iter().map(|s| (*s).to_string()).collect(),
            },
            limits: limits(),
            waivers: BTreeMap::new(),
            dependencies: Vec::new(),
            signature: SignatureSection {
                publisher_key: key_hex(publisher),
                manifest_digest: String::new(),
                sig: String::new(),
                counter_sig: None,
                counter_key: None,
            },
        }
    }

    /// Sign a draft in place: digest first, then the signature over the digest.
    fn sign(manifest: &mut Manifest, publisher: &SigningKey) {
        manifest.signature.manifest_digest = manifest.digest_hex().expect("digest");
        let digest = manifest.signature.manifest_digest.clone();
        let sig = publisher.sign(digest.as_bytes());
        manifest.signature.sig = hex::encode(sig.to_bytes());
    }

    fn counter_sign(manifest: &mut Manifest, vendor: &SigningKey) {
        let digest = manifest.signature.manifest_digest.clone();
        manifest.signature.counter_sig =
            Some(hex::encode(vendor.sign(digest.as_bytes()).to_bytes()));
        manifest.signature.counter_key = Some(key_hex(vendor));
    }

    /// A fully signed official plugin plus a trust store that accepts its vendor key.
    fn official_fixture() -> (Manifest, TrustStore) {
        let vendor = keypair(9);
        let publisher = keypair(7);
        let mut m = draft(
            "com.twinsearth.official.market",
            "2.2",
            &["plugin:message:send", "plugin:storage:own"],
            &publisher,
        );
        sign(&mut m, &publisher);
        counter_sign(&mut m, &vendor);
        let mut trust = TrustStore::deny_all();
        trust.trust_vendor_key(&key_hex(&vendor)).expect("trust");
        (m, trust)
    }

    #[test]
    fn a_fully_signed_official_manifest_verifies_and_yields_a_token() {
        let (m, trust) = official_fixture();
        let v = m.verify(&module(), &trust, NOW).expect("verifies");
        assert_eq!(v.tier, Tier::Official);
        assert_eq!(v.id.as_str(), "com.twinsearth.official.market");
        assert!(v.token.allows(Capability::MessageSend));
        assert!(!v.token.allows(Capability::DhtWrite));
        assert_eq!(v.token.manifest_digest(), m.signature.manifest_digest);
    }

    #[test]
    fn the_digest_does_not_cover_the_signature_section() {
        // If it did, signing would be impossible (the digest would depend on the
        // signature that depends on the digest). This pins the canonicaliser's
        // drop-`signature`-at-every-depth rule actually applying here.
        let (m, _) = official_fixture();
        let before = m.digest_hex().expect("digest");
        let mut tampered = m.clone();
        tampered.signature.sig = "ab".repeat(64);
        tampered.signature.counter_sig = Some("cd".repeat(64));
        assert_eq!(
            before,
            tampered.digest_hex().expect("digest"),
            "changing the signature section must not change the digest"
        );
    }

    #[test]
    fn editing_any_signed_field_invalidates_the_digest() {
        let (m, trust) = official_fixture();
        /// One edit a forger would attempt.
        type Mutation = fn(&mut Manifest);
        // Each of these is a field a forger would want to change.
        let mutations: [(&str, Mutation); 4] = [
            ("capabilities", |m| {
                m.capabilities.grant.push("kernel:policy:write".into())
            }),
            ("entry", |m| m.plugin.entry = "other.bin".into()),
            ("version", |m| m.plugin.version = "9.9.9".into()),
            ("module digest", |m| {
                m.plugin.module_sha256 = "00".repeat(32);
            }),
        ];
        for (what, mutate) in mutations {
            let mut edited = m.clone();
            mutate(&mut edited);
            let err = edited
                .verify(&module(), &trust, NOW)
                .expect_err("an edited manifest must not verify");
            assert!(
                err.to_string().contains("manifest_invalid"),
                "{what}: {err}"
            );
        }
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_refused() {
        let (mut m, trust) = official_fixture();
        let attacker = keypair(3);
        m.signature.publisher_key = key_hex(&attacker);
        let err = m
            .verify(&module(), &trust, NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("signature_invalid"), "{err}");
    }

    #[test]
    fn replacing_the_module_without_resigning_is_refused() {
        let (m, trust) = official_fixture();
        let err = m
            .verify(b"totally different bytes", &trust, NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("module_digest_mismatch"), "{err}");
    }

    #[test]
    fn an_official_manifest_without_a_counter_signature_is_refused() {
        let publisher = keypair(7);
        let mut m = draft(
            "com.twinsearth.official.market",
            "2.2",
            &["plugin:message:send"],
            &publisher,
        );
        sign(&mut m, &publisher);
        let err = m
            .verify(&module(), &TrustStore::deny_all(), NOW)
            .expect_err("must be refused");
        assert!(
            err.to_string().contains("counter_signature_missing"),
            "{err}"
        );
    }

    #[test]
    fn a_counter_signature_from_an_untrusted_key_is_refused() {
        let (mut m, trust) = official_fixture();
        let rogue_vendor = keypair(11);
        counter_sign(&mut m, &rogue_vendor);
        let err = m
            .verify(&module(), &trust, NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("untrusted_publisher"), "{err}");
    }

    #[test]
    fn a_counter_signature_without_a_key_cannot_be_attributed() {
        let (mut m, trust) = official_fixture();
        m.signature.counter_key = None;
        let err = m
            .verify(&module(), &trust, NOW)
            .expect_err("must be refused");
        assert!(
            err.to_string().contains("counter_signature_missing"),
            "{err}"
        );
    }

    #[test]
    fn a_third_party_plugin_needs_the_operator_to_trust_its_key() {
        let publisher = keypair(5);
        let mut m = draft(
            "io.example.analytics",
            "2.2",
            &["plugin:message:send"],
            &publisher,
        );

        // Unconfigured host: refused.
        sign(&mut m, &publisher);
        let err = m
            .verify(&module(), &TrustStore::deny_all(), NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("untrusted_publisher"), "{err}");

        // After the operator trusts the key explicitly: accepted.
        let mut trust = TrustStore::deny_all();
        trust
            .trust_third_party_key(&key_hex(&publisher))
            .expect("trust");
        let v = m.verify(&module(), &trust, NOW).expect("verifies");
        assert_eq!(v.tier, Tier::ThirdParty);
        assert!(!v.token.allows(Capability::DhtRead));
    }

    #[test]
    fn a_third_party_plugin_asking_for_a_sensitive_capability_is_refused() {
        let publisher = keypair(5);
        let mut m = draft("io.example.analytics", "2.2", &["net:dht:read"], &publisher);
        sign(&mut m, &publisher);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_third_party_key(&key_hex(&publisher))
            .expect("trust");
        let err = m
            .verify(&module(), &trust, NOW)
            .expect_err("must be refused");
        assert!(
            err.to_string().contains("capability_not_permitted"),
            "{err}"
        );
        assert!(err.to_string().contains("net:dht:read"), "{err}");
    }

    #[test]
    fn a_future_abi_is_refused_and_an_older_one_verifies() {
        let publisher = keypair(5);
        let mut trust = TrustStore::deny_all();
        trust
            .trust_third_party_key(&key_hex(&publisher))
            .expect("trust");

        // From the future: newer minor of the host's major, and a newer major. Neither
        // can be adapted downwards, so `verify` is where they stop.
        for abi in ["3.9", "4.0"] {
            let mut future = draft("io.example.a", abi, &["plugin:message:send"], &publisher);
            sign(&mut future, &publisher);
            let err = future
                .verify(&module(), &trust, NOW)
                .expect_err("an ABI from the future must be refused");
            let text = err.to_string();
            assert!(text.contains("abi_incompatible"), "{abi}: {text}");
            assert!(
                text.contains("cannot be adapted downwards"),
                "{abi}: {text}"
            );
        }

        // An older major now **verifies**: authenticity is what this function answers.
        // Whether the host can serve it is the arbiter's decision, made through the
        // adapter registry, and that separation is the whole of hot compatibility.
        for abi in ["2.0", "2.2", "3.0"] {
            let mut older = draft("io.example.a", abi, &["plugin:message:send"], &publisher);
            sign(&mut older, &publisher);
            assert!(
                older.verify(&module(), &trust, NOW).is_ok(),
                "ABI {abi} should verify; compatibility is decided later"
            );
        }
    }

    #[test]
    fn a_different_abi_major_is_refused_with_a_migration_hint() {
        let publisher = keypair(5);
        let mut m = draft("io.example.a", "4.0", &["plugin:message:send"], &publisher);
        sign(&mut m, &publisher);
        let err = m
            .verify(&module(), &TrustStore::deny_all(), NOW)
            .expect_err("must be refused");
        assert!(err.to_string().contains("abi_incompatible"), "{err}");
        assert!(
            err.to_string().contains("cannot be adapted downwards"),
            "the refusal must say why no adapter can help: {err}"
        );
    }

    #[test]
    fn a_zero_limit_is_refused_rather_than_read_as_unlimited() {
        let publisher = keypair(5);
        let mut m = draft("io.example.a", "2.2", &["plugin:message:send"], &publisher);
        m.limits.memory_bytes = 0;
        let err = m.validate().expect_err("must be refused");
        assert!(err.to_string().contains("memory_bytes"), "{err}");
        assert!(
            err.to_string().contains("not the same as unlimited"),
            "{err}"
        );
    }

    #[test]
    fn unknown_manifest_keys_are_refused_not_ignored() {
        // The failure mode: a plugin author writes `memory_mb` where the schema says
        // `memory_bytes`, and the limit they believed was in force silently is not.
        let json = r#"{
            "plugin": {
                "name": "io.example.a", "version": "1.4.0", "abi": "2.2",
                "entry": "plugin.bin", "publisher": "did:nau:00",
                "module_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            },
            "capabilities": { "grant": [] },
            "limits": {
                "memory_bytes": 1, "cpu_ms": 1, "disk_bytes": 1,
                "max_processes": 1, "max_output_bytes": 1, "memory_mb": 256
            },
            "signature": { "publisher_key": "00", "manifest_digest": "00", "sig": "00" }
        }"#;
        let err = Manifest::parse(json).expect_err("must be refused");
        assert!(err.to_string().contains("memory_mb"), "{err}");
    }

    #[test]
    fn an_entry_with_a_separator_or_traversal_is_refused() {
        for bad in [
            "../escape",
            "dir/plugin.bin",
            "dir\\plugin.bin",
            ".hidden",
            "",
        ] {
            let publisher = keypair(5);
            let mut m = draft("io.example.a", "2.2", &[], &publisher);
            m.plugin.entry = bad.to_string();
            assert!(m.validate().is_err(), "entry `{bad}` must be refused");
        }
    }

    /// A manifest that declares nothing serialises exactly as it did before the field existed.
    ///
    /// # Why this is the load-bearing test for the dependency field
    ///
    /// The serialised manifest is what the publisher's signature covers. Had adding
    /// `dependencies` emitted an empty array for every plugin, **every digest would change and
    /// every signature already in the field would stop verifying** — and this build promises
    /// that a 2.x plugin still loads here. `skip_serializing_if` is what keeps that promise;
    /// this test is what keeps `skip_serializing_if`.
    #[test]
    fn a_manifest_without_dependencies_serialises_without_the_key() {
        let m = draft("io.example.a", "2.2", &["plugin:message:send"], &keypair(5));
        assert!(m.dependencies.is_empty(), "the fixture declares nothing");
        let text = serde_json::to_string(&m).expect("serialises");
        assert!(
            !text.contains("dependencies"),
            "an empty dependency list must not appear in the signed payload, or every existing \
             signature breaks: {text}"
        );
        // And the omission still round-trips, so it is not read back as a missing field.
        let back: Manifest = serde_json::from_str(&text).expect("round-trips");
        assert_eq!(back.dependencies, Vec::new());
        assert_eq!(back, m);
    }

    /// A declared edge survives serialisation, because it is part of the signed payload.
    #[test]
    fn a_declared_dependency_is_in_the_signed_payload() {
        let mut m = draft("io.example.b", "2.2", &["plugin:message:send"], &keypair(6));
        m.dependencies = vec![crate::registry::Dependency {
            name: "io.example.a".to_string(),
            min_version: "1.2.0".to_string(),
        }];
        let text = serde_json::to_string(&m).expect("serialises");
        assert!(
            text.contains("dependencies"),
            "a declared edge must be in the payload a signature covers: {text}"
        );
        let back: Manifest = serde_json::from_str(&text).expect("round-trips");
        assert_eq!(back.dependencies, m.dependencies);
    }

    #[test]
    fn a_duplicate_capability_is_refused() {
        let publisher = keypair(5);
        let m = draft(
            "io.example.a",
            "2.2",
            &["plugin:message:send", "plugin:message:send"],
            &publisher,
        );
        let err = m.validate().expect_err("must be refused");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    #[test]
    fn a_non_did_publisher_is_refused() {
        let publisher = keypair(5);
        let mut m = draft("io.example.a", "2.2", &[], &publisher);
        m.plugin.publisher = "alice".into();
        assert!(m.validate().is_err());
    }

    #[test]
    fn semver_shape_is_enforced() {
        for bad in ["2.2", "2.2.2.2", "2.2.x", "02.2.2", "2.2.02", ""] {
            assert!(validate_semver(bad).is_err(), "`{bad}` must be refused");
        }
        for good in ["0.0.0", "1.4.0", "10.20.30"] {
            assert!(validate_semver(good).is_ok(), "`{good}` must be accepted");
        }
    }

    #[test]
    fn limits_clamp_to_a_tier_ceiling_and_report_excess() {
        let asked = limits();
        let ceiling = Limits {
            memory_bytes: 128 * 1024 * 1024,
            ..limits()
        };
        assert_eq!(asked.exceeds(ceiling), Some("memory_bytes"));
        assert_eq!(asked.clamped_to(ceiling).memory_bytes, 128 * 1024 * 1024);
        assert!(limits().exceeds(limits()).is_none());
    }

    #[test]
    fn an_empty_trust_store_trusts_nobody() {
        let trust = TrustStore::deny_all();
        assert!(trust.is_empty());
        assert_eq!(trust.len(), 0);
        assert!(!trust.is_trusted_vendor_key(&"11".repeat(32)));
        assert!(!trust.is_trusted_third_party_key(&"11".repeat(32)));
    }

    #[test]
    fn a_malformed_trust_key_is_refused_at_the_point_it_is_added() {
        let mut trust = TrustStore::deny_all();
        // Length and alphabet are decided here.
        assert!(trust.trust_vendor_key("short").is_err());
        assert!(trust.trust_vendor_key(&"zz".repeat(32)).is_err());
        assert!(
            trust.trust_vendor_key(&"AB".repeat(32)).is_err(),
            "upper case is refused"
        );
        // Whether 32 hex bytes decompress to a curve point is the curve library's
        // decision, and asserting a particular byte pattern is invalid would be a
        // test of ed25519-dalek rather than of this function -- `ff` repeated happens
        // to decompress, so the earlier form of this test was simply wrong about the
        // library. What is asserted here is that a key which *is* accepted ends up in
        // the store and changes behaviour.
        let good = hex::encode(keypair(5).verifying_key().to_bytes());
        assert!(trust.trust_vendor_key(&good).is_ok());
        assert!(trust.is_trusted_vendor_key(&good));
        assert_eq!(trust.len(), 1);
    }
}
