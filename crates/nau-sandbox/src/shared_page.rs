//! Read-only shared pages, and why a writable one must not exist.
//!
//! # The requirement
//!
//! AUSec shares read-only pages between sandboxes so that a hundred guests running the same
//! base image do not each hold their own copy. The design says the shared content is
//! **read-only**. It does not say what enforces that, and the plan marks this as the single
//! most important security requirement in the whole document:
//!
//! > If a guest can write a shared page, one MicroVM pollutes every MicroVM on the host that
//! > maps it. In a multi-tenant deployment that is cross-tenant contamination — a security
//! > defect, not a performance one.
//!
//! # How it is enforced here
//!
//! Three layers, in order of strength:
//!
//! 1. **The type system.** [`SharedPage::attach`] takes a [`SharedPageAccess`], and a
//!    read-write attach is **refused at runtime**; there is no constructor that produces a
//!    writable shared view at all. A writable shared page is not something a caller can ask
//!    for and receive — it is something they can ask for and be told no.
//! 2. **The platform mechanism.** On Linux the backing region is mapped with `PROT_READ`
//!    ([`crate::platform`]), so the refusal is also an OS-level fact rather than only a
//!    library convention. On every other platform [`SHARED_PAGE_SUPPORT`] reports a typed
//!    refusal, and a request for the capability fails with a reason instead of running
//!    without it.
//! 3. **The capability report.** [`crate::Capability::SharedPageReadOnly`] is what a backend
//!    publishes, so `check_boundary` refuses a request for it where it is not enforced —
//!    which is the crate's standing rule for every policy field.
//!
//! Layer 1 is the one that holds everywhere, including on this machine; layer 2 is the one
//! that has to be verified on Linux, and [`SHARED_PAGE_SUPPORT`] says where it stands.
//!
//! # What is verified here and what is not
//!
//! The refusal of a read-write attach, the platform declaration, and the capability report
//! are tested in this crate's suite and run on every platform.
//!
//! The Linux mapping is **type-checked** from any host (`cargo check --target
//! x86_64-unknown-linux-gnu`) but its **runtime behaviour against a real `virtio-pmem`
//! device is not verified by this project's CI**: presenting the device to a guest read-only
//! is a hypervisor configuration concern, and a GitHub runner has no `/dev/kvm`. Saying so is
//! the point — a claim of enforcement that has never run against the mechanism is the kind of
//! documentation this crate exists to replace.

use std::sync::Arc;

use nau_core::image::ChunkDigest;

use crate::capability::Capability;
use crate::component::SafeComponent;
use crate::error::{Result, SandboxError};

/// How a sandbox asks to attach to a shared page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedPageAccess {
    /// Map it read-only. The only access a shared page admits.
    ReadOnly,
    /// Map it writable.
    ///
    /// Refused for a shared page. The variant exists so that the refusal is an answer to a
    /// question a caller can ask, rather than an absence of API that a caller has to infer.
    ReadWrite,
}

impl SharedPageAccess {
    /// A label for reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            SharedPageAccess::ReadOnly => "read-only",
            SharedPageAccess::ReadWrite => "read-write",
        }
    }

    /// Whether this access is admissible for a shared page.
    #[must_use]
    pub fn is_admissible(self) -> bool {
        matches!(self, SharedPageAccess::ReadOnly)
    }
}

/// Whether this platform can enforce read-only sharing, and by what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedPageSupport {
    /// Enforced, with the mechanism named.
    Enforced {
        /// What enforces it.
        mechanism: &'static str,
    },
    /// Not enforced here, with a reason a caller can act on.
    Refused {
        /// Why it cannot be enforced.
        reason: &'static str,
    },
}

impl SharedPageSupport {
    /// Whether sharing is enforced on this build.
    #[must_use]
    pub fn is_enforced(self) -> bool {
        matches!(self, SharedPageSupport::Enforced { .. })
    }

    /// The mechanism, if enforced.
    #[must_use]
    pub fn mechanism(self) -> Option<&'static str> {
        match self {
            SharedPageSupport::Enforced { mechanism } => Some(mechanism),
            SharedPageSupport::Refused { .. } => None,
        }
    }

    /// The refusal reason, if refused.
    #[must_use]
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            SharedPageSupport::Refused { reason } => Some(reason),
            SharedPageSupport::Enforced { .. } => None,
        }
    }
}

/// What this build can do about shared pages.
///
/// A `const` rather than a function so the claim is compiled into the binary and cannot
/// depend on how it was called.
pub const SHARED_PAGE_SUPPORT: SharedPageSupport = if cfg!(target_os = "linux") {
    SharedPageSupport::Enforced {
        mechanism: "the region is mapped PROT_READ and the mapping is never upgraded; the \
                    device is presented to the guest read-only",
    }
} else {
    SharedPageSupport::Refused {
        reason: "read-only shared pages need a host memory mechanism (virtio-pmem + DAX on \
                 Linux) that this platform does not have; sharing is refused rather than \
                 downgraded, because a writable shared page lets one sandbox contaminate \
                 every other sandbox mapping it. Run without sharing (each sandbox holds its \
                 own copy) or run on Linux",
    }
};

/// A page that several sandboxes may map, read-only.
#[derive(Debug, Clone)]
pub struct SharedPage {
    name: SafeComponent,
    digest: ChunkDigest,
    bytes: Arc<[u8]>,
}

impl SharedPage {
    /// A shared page over `bytes`, named and addressed by its content.
    ///
    /// # Errors
    ///
    /// [`SandboxError::Component`] when the name is not a safe path component. The name
    /// reaches a filesystem path and a hypervisor argument, and the validation goes through
    /// [`SafeComponent::parse`] rather than a check written here: this crate has exactly one
    /// place that decides what a component is, and a second one would be a second thing to
    /// keep right — which is the rule the crate's own documentation states.
    pub fn new(name: &str, bytes: Vec<u8>) -> Result<Self> {
        let name = SafeComponent::parse(name)?;
        // The same content address as an image chunk. A shared page *is* a chunk of an
        // image, and a second hashing implementation here would be a second thing to keep
        // right -- so the workspace keeps exactly one.
        Ok(Self {
            name,
            digest: ChunkDigest::of(&bytes),
            bytes: Arc::from(bytes.into_boxed_slice()),
        })
    }

    /// The page's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// The page's content address.
    #[must_use]
    pub fn digest(&self) -> &ChunkDigest {
        &self.digest
    }

    /// The page's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the page is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Attach to this page with the requested access.
    ///
    /// # Errors
    ///
    /// [`SandboxError::PolicyNotEnforceable`] when read-write is asked for. This is the
    /// security requirement expressed as an API: there is no way to obtain a writable view
    /// of a shared page, so no caller can hand one to a guest, and the refusal is the same
    /// class of answer the crate gives every other policy it cannot honour.
    pub fn attach(&self, access: SharedPageAccess) -> Result<SharedPageView> {
        if !access.is_admissible() {
            let detail = SHARED_PAGE_SUPPORT.refusal_reason().map_or_else(
                || {
                    "a shared page is mapped read-only by construction; a writable mapping \
                     would let this sandbox modify content that other sandboxes on the host \
                     are reading"
                        .to_string()
                },
                |why| why.to_string(),
            );
            return Err(SandboxError::PolicyNotEnforceable {
                boundary: Capability::SharedPageReadOnly,
                backend: crate::PLATFORM_BACKEND.to_string(),
                detail: format!(
                    "shared page {} cannot be attached {}: {detail}",
                    self.name.as_str(),
                    access.label()
                ),
            });
        }

        // On Linux the bytes are read back through a mapping that was downgraded to
        // `PROT_READ`, so "the guest cannot write it" is the MMU's answer rather than this
        // library's. Elsewhere there is no sharing mechanism, so a read-only attach is served
        // from this process's own copy -- which is not sharing, and `SHARED_PAGE_SUPPORT`
        // says so rather than letting a caller believe otherwise.
        #[cfg(target_os = "linux")]
        let mapping = crate::platform::map_readonly(&self.bytes)?;

        Ok(SharedPageView {
            name: self.name.as_str().to_string(),
            digest: self.digest.clone(),
            #[cfg(not(target_os = "linux"))]
            bytes: Arc::clone(&self.bytes),
            #[cfg(target_os = "linux")]
            mapping,
            access: SharedPageAccess::ReadOnly,
        })
    }
}

/// A read-only view of a [`SharedPage`].
///
/// The view exposes no mutation. It is a distinct type from a writable buffer so that
/// "this came from a shared page" is visible in a signature rather than in a comment.
///
/// **Not `Clone`.** On Linux the view owns a mapping, and two handles to one mapping would
/// each `munmap` it on drop. The type's capabilities are constrained by the mechanism under
/// it, and a caller who wants another view calls `attach` again — which is also the honest
/// description of what a second guest does.
#[derive(Debug)]
pub struct SharedPageView {
    name: String,
    digest: ChunkDigest,
    /// On non-Linux platforms the bytes are this process's own copy.
    #[cfg(not(target_os = "linux"))]
    bytes: Arc<[u8]>,
    /// On Linux the bytes are read through a mapping the kernel made read-only, so the
    /// view's data path *is* the enforcement rather than sitting beside it.
    #[cfg(target_os = "linux")]
    mapping: crate::platform::ReadOnlyMap,
    access: SharedPageAccess,
}

impl SharedPageView {
    /// The page's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The page's content address.
    #[must_use]
    pub fn digest(&self) -> &ChunkDigest {
        &self.digest
    }

    /// The access this view was obtained with. Always
    /// [`SharedPageAccess::ReadOnly`], and reported so a caller can assert it rather than
    /// assume it.
    #[must_use]
    pub fn access(&self) -> SharedPageAccess {
        self.access
    }

    /// The bytes, read-only.
    ///
    /// On Linux these come from the mapping the kernel downgraded to `PROT_READ`; elsewhere
    /// from this process's own copy. Either way the return type is `&[u8]` and there is no
    /// `&mut` counterpart, which is the type-level half of the read-only guarantee.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        #[cfg(target_os = "linux")]
        {
            self.mapping.as_slice()
        }
        #[cfg(not(target_os = "linux"))]
        {
            &self.bytes
        }
    }

    /// The page's length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether the page is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> SharedPage {
        SharedPage::new("base-image", vec![1_u8; 64]).expect("page")
    }

    #[test]
    fn a_shared_page_can_be_attached_read_only() {
        let view = page().attach(SharedPageAccess::ReadOnly).expect("attach");
        assert_eq!(view.access(), SharedPageAccess::ReadOnly);
        assert_eq!(view.len(), 64);
        assert_eq!(view.as_slice(), &[1_u8; 64]);
        assert_eq!(view.name(), "base-image");
    }

    #[test]
    fn attaching_a_shared_page_read_write_is_refused() {
        // A-09's security requirement, as an API fact: there is no way to obtain a writable
        // view of a shared page, so no caller can hand one to a guest. Before this, the
        // design said the content was read-only and nothing said what enforced it.
        let err = page()
            .attach(SharedPageAccess::ReadWrite)
            .expect_err("must refuse");
        let text = format!("{err}");
        assert!(
            text.contains("read-write"),
            "the refusal must name the access asked for, got: {text}"
        );
        assert!(
            text.contains("base-image"),
            "the refusal must name the page, got: {text}"
        );
    }

    #[test]
    fn the_read_write_refusal_names_the_cross_tenant_risk() {
        // The reason has to be actionable, and on a platform without the mechanism the
        // actionable part is "run without sharing, or run on Linux". A refusal that only
        // said "unsupported" would leave the reader where they started.
        let err = page()
            .attach(SharedPageAccess::ReadWrite)
            .expect_err("must refuse");
        let text = format!("{err}");
        assert!(
            text.contains("contaminate") || text.contains("read-only by construction"),
            "the refusal must say what goes wrong, got: {text}"
        );
    }

    #[test]
    fn only_read_only_access_is_admissible() {
        assert!(SharedPageAccess::ReadOnly.is_admissible());
        assert!(!SharedPageAccess::ReadWrite.is_admissible());
        assert_eq!(SharedPageAccess::ReadOnly.label(), "read-only");
        assert_eq!(SharedPageAccess::ReadWrite.label(), "read-write");
    }

    #[test]
    fn the_platform_declaration_answers_exactly_one_of_two_ways() {
        // Totality: on this build it is either enforced with a mechanism named, or refused
        // with a reason given. Never both, never neither.
        match SHARED_PAGE_SUPPORT {
            SharedPageSupport::Enforced { mechanism } => {
                assert!(!mechanism.trim().is_empty());
                assert!(SHARED_PAGE_SUPPORT.is_enforced());
                assert!(SHARED_PAGE_SUPPORT.refusal_reason().is_none());
                assert_eq!(SHARED_PAGE_SUPPORT.mechanism(), Some(mechanism));
            }
            SharedPageSupport::Refused { reason } => {
                assert!(!reason.trim().is_empty());
                assert!(!SHARED_PAGE_SUPPORT.is_enforced());
                assert!(SHARED_PAGE_SUPPORT.mechanism().is_none());
                assert!(
                    reason.contains("refused rather than"),
                    "the refusal must say it is a refusal and not a downgrade, got: {reason}"
                );
            }
        }
    }

    #[test]
    fn this_platform_is_the_one_the_declaration_was_written_for() {
        // The declaration is `cfg!`-derived, so this asserts the two agree -- a mismatch
        // would mean the constant had drifted from the build it describes.
        assert_eq!(
            SHARED_PAGE_SUPPORT.is_enforced(),
            cfg!(target_os = "linux"),
            "the support declaration must match the platform it was compiled for"
        );
    }

    #[test]
    fn a_page_is_addressed_by_its_content() {
        let a = SharedPage::new("p", vec![7_u8; 32]).expect("a");
        let b = SharedPage::new("p", vec![7_u8; 32]).expect("b");
        let c = SharedPage::new("p", vec![8_u8; 32]).expect("c");
        assert_eq!(a.digest(), b.digest(), "same content, same address");
        assert_ne!(a.digest(), c.digest());
        assert_eq!(a.digest().as_str().len(), 64);
        // The same address an image chunk of these bytes would have: one content-addressing
        // implementation in the workspace, not two.
        assert_eq!(a.digest(), &ChunkDigest::of(&[7_u8; 32]));
    }

    #[test]
    fn a_page_name_that_could_escape_is_refused() {
        // The name reaches a filesystem path and a hypervisor argument.
        for bad in ["", "   ", "../etc/passwd", "a/b", "a\\b"] {
            assert!(
                SharedPage::new(bad, vec![0_u8; 8]).is_err(),
                "{bad:?} must not be accepted as a page name"
            );
        }
        assert!(SharedPage::new("ok-name_1", vec![0_u8; 8]).is_ok());
    }

    #[test]
    fn a_view_exposes_no_mutation() {
        // The strongest form of the requirement that a test can state in this crate: the
        // only way to read a shared page yields a `&[u8]`. There is no `&mut`, no `Vec`, and
        // no setter, so "the guest cannot write it" starts being true at the type level
        // before any platform mechanism is involved.
        let view = page().attach(SharedPageAccess::ReadOnly).expect("attach");
        let slice: &[u8] = view.as_slice();
        assert_eq!(slice.len(), 64);
        // A second view of the same page sees the same bytes and cannot change them.
        let other = page().attach(SharedPageAccess::ReadOnly).expect("attach");
        assert_eq!(view.as_slice(), other.as_slice());
    }
}
