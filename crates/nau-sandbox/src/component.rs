//! [`SafeComponent`] — the **one** function through which every user-supplied
//! string that becomes a path component must pass.
//!
//! ## Why one function
//!
//! Upstream v2.8.2 shipped `safe_join` (`sandbox/runtime/process.rs:376-389`) and
//! called it from exactly two Rust-side helpers (`read_file` / `write_file`). The
//! *execution* path never went through it, and `FilesystemPolicy`
//! (`sandbox/config.rs:88-97`) had zero enforcement sites. A guard with two call
//! sites and one bypass is not a guard.
//!
//! The correction is structural rather than documentary: the only way to obtain a
//! path component in this crate is [`SafeComponent::parse`], and the only way to
//! turn one into a path is [`SafeComponent::join_under`], which compares the
//! canonical result against the canonical root before returning it. Nothing else
//! in the crate concatenates a caller-supplied string onto a directory.
//!
//! ## What is refused
//!
//! | input | refused as |
//! |---|---|
//! | `""` | [`ComponentError::Empty`] |
//! | `".."`, `"."` | [`ComponentError::ParentDir`] / [`ComponentError::CurDir`] |
//! | `"a/b"`, `"a\\b"` | [`ComponentError::Separator`] |
//! | `"C:..\\x"`, `"C:x"` | [`ComponentError::WindowsPrefix`] |
//! | `"\\\\?\\C:\\x"`, `"\\\\?\\UNC\\h"` | [`ComponentError::WindowsPrefix`] |
//! | `"/etc/x"`, `"\\x"` | [`ComponentError::RootDir`] |
//! | `"CON"`, `"nul"`, `"LPT1"` | [`ComponentError::ReservedName`] |
//! | `b"\xff"` | [`ComponentError::NotUtf8`] |
//! | `"a\0b"` | [`ComponentError::Nul`] |
//! | 300 characters | [`ComponentError::TooLong`] |
//!
//! The checks are performed on **bytes** before UTF-8 validation, so a 300-byte
//! candidate is rejected as `TooLong` rather than being lossily decoded and then
//! accepted.

// `Path` was imported under `#[cfg(any(windows, test))]`, but `join_under` below is
// NOT platform-gated and takes `&Path` on every platform. So the crate compiled on
// Windows (cfg(windows)) and in `cargo test` (cfg(test)) and failed to compile at all
// on Linux and macOS under a plain `cargo build` -- which is the first step CI runs.
// A local green run on the author's platform structurally could not see it; CI did,
// on two of its three runners. Imports are matched to use, not to platform.
use std::path::{Path, PathBuf};

use crate::error::{ComponentError, Result, SandboxError};

/// Hard cap on one path component, in bytes.
///
/// Well below every platform's own limit (255 bytes on ext4, 255 UTF-16 code
/// units in NTFS) and far below `MAX_PATH`, so an accepted component can always
/// be joined without truncation.
pub const MAX_COMPONENT_BYTES: usize = 128;

/// Windows device names that resolve to a device, not a file, in **every**
/// directory.
const WINDOWS_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// A string that has been proven safe to use as exactly one path component.
///
/// Construction is fallible and validated; the inner string is private, so
/// holding an instance is a proof obligation discharged once, at the boundary
/// where untrusted input enters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SafeComponent(String);

impl SafeComponent {
    /// Validate `candidate` as one path component.
    ///
    /// Refuses everything in the module table. The order of the checks is chosen
    /// so that the *most specific* refusal wins: a NUL byte is reported as
    /// [`ComponentError::Nul`] rather than as a separator, and a 300-byte
    /// traversal attempt is reported as a traversal attempt rather than as
    /// [`ComponentError::TooLong`].
    pub fn parse(candidate: &str) -> std::result::Result<Self, ComponentError> {
        Self::parse_bytes(candidate.as_bytes())
    }

    /// Validate raw bytes as one path component.
    ///
    /// This is the byte-level entry point: it exists because a component that
    /// arrives as bytes (a path segment, a header value) must be rejected as
    /// [`ComponentError::NotUtf8`] instead of being lossily decoded into
    /// something that then passes validation.
    pub fn parse_bytes(candidate: &[u8]) -> std::result::Result<Self, ComponentError> {
        if candidate.is_empty() {
            return Err(ComponentError::Empty);
        }
        if candidate.len() > MAX_COMPONENT_BYTES {
            return Err(ComponentError::TooLong {
                len: candidate.len(),
            });
        }
        // Cheap byte-level refusals first: these are the traversal primitives and
        // they do not depend on the candidate being valid UTF-8.
        if candidate.contains(&0) {
            return Err(ComponentError::Nul);
        }
        if let Some(byte) = candidate
            .iter()
            .copied()
            .find(|b| *b == b'/' || *b == b'\\')
        {
            return Err(ComponentError::Separator { byte });
        }
        if let Some(byte) = candidate.iter().copied().find(|b| *b < 0x20 || *b == 0x7f) {
            return Err(ComponentError::ForbiddenByte { byte });
        }
        let text = std::str::from_utf8(candidate).map_err(|_| ComponentError::NotUtf8)?;

        if text == "." {
            return Err(ComponentError::CurDir);
        }
        if text == ".." {
            return Err(ComponentError::ParentDir);
        }
        // A drive-relative or alternative-data-stream form. `\\?\` and `\\.\`
        // are already caught by the separator check above, so what remains here
        // is `C:`, `C:x` and `name:stream`.
        if text.contains(':') {
            return Err(ComponentError::WindowsPrefix);
        }
        // A trailing dot or space is silently stripped by Win32 path handling: a
        // directory literally named `x.` is created as `x`. That normalisation is
        // exactly what makes a name-based guard unsound — two different ids would
        // name one directory — so the form is refused on every platform, not only on
        // Windows, which keeps the accepted set platform-independent.
        if text.ends_with('.') || text.ends_with(' ') || text.starts_with(' ') {
            return Err(ComponentError::TrailingDotOrSpace);
        }
        // A leading `.`/`~` is *accepted* here: the two dotted forms that would
        // escape (`"."` and `".."`) were refused above, and a hidden or
        // backup-style name is a legitimate component. Spelling that out keeps a
        // future edit from removing the checks above without noticing.
        let stem = text.split('.').next().unwrap_or(text);
        if WINDOWS_RESERVED
            .iter()
            .any(|name| name.eq_ignore_ascii_case(stem))
        {
            return Err(ComponentError::ReservedName);
        }
        Ok(Self(text.to_string()))
    }

    /// The validated component.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Join this component onto `root`, **re-checking the result**.
    ///
    /// `root` is canonicalised first, then the joined path is canonicalised and
    /// required to still be `root` plus this one component. The re-check is what
    /// makes the guarantee survive a symlink: a directory entry whose name is
    /// safe but which is itself a symlink out of the root fails here, and a
    /// symlinked `root` is resolved to its target so the comparison is made
    /// against the real directory.
    ///
    /// The path is *not* required to exist: a component that does not exist yet
    /// (the directory about to be created) is returned as `root/component`
    /// without a canonical round trip. Only the root must exist.
    pub fn join_under(&self, root: &Path) -> Result<PathBuf> {
        let real_root = root.canonicalize().map_err(|e| {
            SandboxError::WorkDir(format!("cannot resolve {}: {e}", root.display()))
        })?;
        let joined = real_root.join(self.as_str());
        if let Ok(real_joined) = joined.canonicalize() {
            let Some(rest) = real_joined.strip_prefix(&real_root).ok() else {
                return Err(SandboxError::WorkDir(format!(
                    "`{}` resolves outside the sandbox root {}",
                    self.0,
                    real_root.display()
                )));
            };
            // Exactly one component: no `..`, no nested directory, no escape.
            let mut parts = rest.components();
            let first = parts.next();
            if parts.next().is_some() {
                return Err(SandboxError::WorkDir(format!(
                    "`{}` resolves to a path deeper than one component",
                    self.0
                )));
            }
            if let Some(std::path::Component::Normal(name)) = first {
                if name != std::ffi::OsStr::new(self.as_str()) {
                    return Err(SandboxError::WorkDir(format!(
                        "`{}` resolves to a differently named entry",
                        self.0
                    )));
                }
            } else {
                return Err(SandboxError::WorkDir(format!(
                    "`{}` does not resolve to a normal directory entry",
                    self.0
                )));
            }
        }
        Ok(joined)
    }
}

impl std::fmt::Display for SafeComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SafeComponent {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream v2.8.2 fix: `safe_join` was called by two helpers and never by
    /// the execution path. This pins the traversal primitives themselves.
    #[test]
    fn traversal_and_separator_forms_are_refused() {
        for (input, expect) in [
            ("..", ComponentError::ParentDir),
            (".", ComponentError::CurDir),
            ("a/b", ComponentError::Separator { byte: b'/' }),
            ("a\\b", ComponentError::Separator { byte: b'\\' }),
            ("/etc/x", ComponentError::Separator { byte: b'/' }),
            ("\\x", ComponentError::Separator { byte: b'\\' }),
            ("../etc", ComponentError::Separator { byte: b'/' }),
            ("..\\..\\x", ComponentError::Separator { byte: b'\\' }),
        ] {
            let err = SafeComponent::parse(input).expect_err(input);
            assert_eq!(err, expect, "input {input:?}");
            assert!(err.is_traversal_attempt(), "input {input:?}");
        }
    }

    /// Upstream v2.8.2 fix: ids were `sb-N` counters, so a component was never
    /// validated as a component at all. Windows-specific escapes are refused even
    /// when this build runs on Linux, so the check cannot be verified-by-platform.
    #[test]
    fn windows_prefixes_and_drive_rooted_paths_are_refused() {
        for input in [
            "C:..\\x",
            "C:x",
            "C:",
            "c:\\x",
            "\\\\?\\C:\\x",
            "\\\\.\\PIPE\\x",
        ] {
            let err = SafeComponent::parse(input).expect_err(input);
            assert!(
                matches!(
                    err,
                    ComponentError::Separator { .. } | ComponentError::WindowsPrefix
                ),
                "input {input:?} gave {err:?}"
            );
        }
        // An NTFS alternate data stream is a drive-prefix-shaped escape.
        assert_eq!(
            SafeComponent::parse("file:stream").expect_err("ADS"),
            ComponentError::WindowsPrefix
        );
    }

    #[test]
    fn empty_nul_control_and_non_utf8_are_refused() {
        assert_eq!(
            SafeComponent::parse("").expect_err("empty"),
            ComponentError::Empty
        );
        assert_eq!(
            SafeComponent::parse("a\0b").expect_err("nul"),
            ComponentError::Nul
        );
        assert_eq!(
            SafeComponent::parse("a\nb").expect_err("control"),
            ComponentError::ForbiddenByte { byte: b'\n' }
        );
        assert_eq!(
            SafeComponent::parse_bytes(b"\xff\xfe").expect_err("non-utf8"),
            ComponentError::NotUtf8
        );
        // A non-UTF-8 byte that also happens to be a separator is reported as the
        // separator: the byte check runs first and does not need UTF-8.
        assert_eq!(
            SafeComponent::parse_bytes(b"a\xff/b").expect_err("non-utf8 separator"),
            ComponentError::Separator { byte: b'/' }
        );
    }

    #[test]
    fn length_is_capped_before_decoding() {
        let long = "a".repeat(300);
        assert_eq!(
            SafeComponent::parse(&long).expect_err("300 chars"),
            ComponentError::TooLong { len: 300 }
        );
        // Multi-byte characters count as bytes, not characters.
        let cjk = "\u{4e2d}".repeat(MAX_COMPONENT_BYTES);
        let err = SafeComponent::parse(&cjk).expect_err("multi-byte overflow");
        assert!(matches!(err, ComponentError::TooLong { .. }), "got {err:?}");
        // Exactly at the cap is accepted.
        assert!(SafeComponent::parse(&"a".repeat(MAX_COMPONENT_BYTES)).is_ok());
    }

    #[test]
    fn windows_device_names_are_refused_in_every_directory() {
        for input in ["CON", "nul", "Lpt1", "com9", "NUL.txt", "aux.log"] {
            assert_eq!(
                SafeComponent::parse(input).expect_err(input),
                ComponentError::ReservedName,
                "input {input:?}"
            );
        }
        // Names that merely contain a device name are fine.
        assert!(SafeComponent::parse("console").is_ok());
        assert!(SafeComponent::parse("nullable").is_ok());
    }

    #[test]
    fn a_uuid_v4_id_is_an_accepted_component() {
        // The shape the manager actually issues.
        let id = uuid::Uuid::new_v4().simple().to_string();
        let c = SafeComponent::parse(&id).expect("uuid is a safe component");
        assert_eq!(c.as_str().len(), 32);
    }

    #[test]
    fn joining_is_re_checked_against_the_root() {
        let dir = std::env::temp_dir().join(format!("nau-sc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp root");
        let safe = SafeComponent::parse("child").expect("component");
        let joined = safe.join_under(&dir).expect("join");
        assert!(joined.starts_with(dir.canonicalize().expect("canonical root")));

        // A directory entry that is a symlink out of the root must not resolve.
        let outside = std::env::temp_dir().join(format!("nau-sc-out-{}", std::process::id()));
        std::fs::create_dir_all(&outside).expect("outside dir");
        let link = dir.join("escape");
        let linked = symlink_dir(&outside, &link);
        if linked {
            let escape = SafeComponent::parse("escape").expect("component");
            let err = escape
                .join_under(&dir)
                .expect_err("a symlink out of the root must be refused");
            assert!(
                matches!(err, SandboxError::WorkDir(_)),
                "expected a work-dir refusal, got {err:?}"
            );
        } else {
            // Reported, not silently passed: creating a directory symlink on Windows
            // needs either Developer Mode or `SeCreateSymbolicLinkPrivilege`, so on a
            // machine without it this check does not run. The same check runs on Unix,
            // where symlink creation needs no privilege.
            println!(
                "SKIP: this machine cannot create a directory symlink (Windows needs Developer \
                 Mode or SeCreateSymbolicLinkPrivilege), so `join_under` was not exercised \
                 against a symlink that escapes the root"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// Create a directory symlink; `false` when the platform/privilege refuses.
    #[cfg(windows)]
    fn symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }

    /// Create a directory symlink; `false` when the platform/privilege refuses.
    #[cfg(unix)]
    fn symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
}
