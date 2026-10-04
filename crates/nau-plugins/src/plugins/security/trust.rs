//! A trust store that survives a restart, and refuses everything until it does not.
//!
//! # C-06's second criterion
//!
//! The plan says the trust store must **persist and survive a restart**. A store held in memory
//! satisfies neither, and the failure is worse than it sounds: a node that re-verifies every plugin
//! at every boot has not forgotten a decision so much as never recorded one — an operator who
//! trusted a publisher would do it again after every restart, which is a ritual rather than a
//! decision.
//!
//! # Why this holds its own key set instead of serialising the kernel's
//!
//! [`TrustStore`]'s fields are private and it exposes no iterator, which is the right shape for a
//! type whose whole job is to answer two questions. So this file holds the keys and **builds** a
//! `TrustStore` from them on demand, going through [`TrustStore::trust_vendor_key`] and
//! [`TrustStore::trust_third_party_key`] so that the kernel's own validation — the hex length and
//! the key parse — is what accepts a key. Reimplementing that check here would be a second opinion
//! about what a valid key is.
//!
//! # Fail-closed, and where that lives
//!
//! [`TrustFile::store`] starts from [`TrustStore::deny_all`] and adds only what is in the file. An
//! empty file therefore produces a store that trusts **nobody**, which is the default the kernel
//! already chose: `deny_all` is a method rather than a comment because "no keys configured" and
//! "trust everything" must not be one keystroke apart.
//!
//! # Atomic rather than appended
//!
//! A trust store is a **set**, not a log, so it is written whole to a temporary file and renamed
//! over the old one. A crash mid-write leaves the previous store intact; an append-based store that
//! crashed mid-line would leave a key half-written, and a half-written key is one that fails to
//! parse at boot — which, with a fail-closed store, means the node refuses to trust a publisher it
//! was told to trust, for a reason nobody can see from the file.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use nau_plugin::{PluginError, Result, TrustStore};
use serde::{Deserialize, Serialize};

/// A refusal from the trust file.
fn refusal(what: impl std::fmt::Display) -> PluginError {
    PluginError::Runtime(what.to_string())
}

/// What is on disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    /// Keys that may counter-sign official and certified plugins.
    #[serde(default)]
    vendor: Vec<String>,
    /// Keys of operator-trusted third-party publishers.
    #[serde(default)]
    third_party: Vec<String>,
}

/// The durable trust store.
#[derive(Debug)]
pub struct TrustFile {
    path: PathBuf,
    vendor: BTreeSet<String>,
    third_party: BTreeSet<String>,
}

impl TrustFile {
    /// Open a store, reading what is already there.
    ///
    /// A missing file is an **empty** store rather than an error, and an empty store trusts nobody.
    /// That is the fail-closed direction: the first boot of a node has decided nothing, and a node
    /// that refused to start because nobody had been trusted yet would invert the point.
    ///
    /// # Errors
    ///
    /// A refusal when the file exists but cannot be read or parsed. A store that silently skipped
    /// what it could not read would trust less than it was told to, without saying so.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut store = Self {
            path,
            vendor: BTreeSet::new(),
            third_party: BTreeSet::new(),
        };
        if !store.path.exists() {
            return Ok(store);
        }
        let text = std::fs::read_to_string(&store.path).map_err(|e| {
            refusal(format!(
                "cannot read the trust store at {}: {e}",
                store.path.display()
            ))
        })?;
        let stored: Stored = serde_json::from_str(&text).map_err(|e| {
            refusal(format!(
                "{} is not a trust store: {e}",
                store.path.display()
            ))
        })?;
        // Validated on the way in as well as on the way out. A file edited by hand is the ordinary
        // way a key gets added on a machine with no operator tooling, and a key that is not a key
        // must be refused when it is read rather than when it is first used.
        for key in stored.vendor {
            store.insert_vendor(&key)?;
        }
        for key in stored.third_party {
            store.insert_third_party(&key)?;
        }
        Ok(store)
    }

    /// The path this store is written to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many keys are trusted, of either kind.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vendor.len() + self.third_party.len()
    }

    /// Whether nothing is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vendor.is_empty() && self.third_party.is_empty()
    }

    /// The trusted vendor keys, sorted.
    #[must_use]
    pub fn vendor_keys(&self) -> Vec<&str> {
        self.vendor.iter().map(String::as_str).collect()
    }

    /// The trusted third-party keys, sorted.
    #[must_use]
    pub fn third_party_keys(&self) -> Vec<&str> {
        self.third_party.iter().map(String::as_str).collect()
    }

    /// The kernel's store, built from what is here.
    ///
    /// # Errors
    ///
    /// A refusal if a stored key is not one the kernel accepts. It cannot happen for a key that
    /// came through [`TrustFile::trust_vendor`], and it is returned rather than unwrapped for the
    /// case where the file was edited between the read and this call.
    pub fn store(&self) -> Result<TrustStore> {
        // `deny_all` first, then add: the direction matters, and starting from anything else would
        // make an empty file mean something other than "trust nobody".
        let mut store = TrustStore::deny_all();
        for key in &self.vendor {
            store.trust_vendor_key(key)?;
        }
        for key in &self.third_party {
            store.trust_third_party_key(key)?;
        }
        Ok(store)
    }

    /// Trust a vendor key, and write the store.
    ///
    /// # Errors
    ///
    /// A refusal when the kernel does not accept the key, or when the write fails. The key is **not**
    /// added in memory unless the disk took it: a store that reported a key it did not persist would
    /// forget it at the next restart, which is the failure this type exists to prevent.
    pub fn trust_vendor(&mut self, hex_key: &str) -> Result<()> {
        self.insert_vendor(hex_key)?;
        if let Err(e) = self.save() {
            // Put memory back the way the disk is, so the two do not disagree.
            self.vendor.remove(&hex_key.to_ascii_lowercase());
            return Err(e);
        }
        Ok(())
    }

    /// Trust a third-party publisher key, and write the store.
    ///
    /// # Errors
    ///
    /// As [`TrustFile::trust_vendor`].
    pub fn trust_third_party(&mut self, hex_key: &str) -> Result<()> {
        self.insert_third_party(hex_key)?;
        if let Err(e) = self.save() {
            self.third_party.remove(&hex_key.to_ascii_lowercase());
            return Err(e);
        }
        Ok(())
    }

    /// Stop trusting `hex_key`, of either kind.
    ///
    /// Returns whether it was trusted. Revoking a key that is not there is not an error: an
    /// operator ensuring a key is gone should not have to know whether it was ever added.
    ///
    /// # Errors
    ///
    /// A refusal when the write fails.
    pub fn revoke(&mut self, hex_key: &str) -> Result<bool> {
        let key = hex_key.to_ascii_lowercase();
        let was_vendor = self.vendor.remove(&key);
        let was_third_party = self.third_party.remove(&key);
        if !was_vendor && !was_third_party {
            return Ok(false);
        }
        if let Err(e) = self.save() {
            // The disk is the one that survives, so put memory back to match it.
            if was_vendor {
                self.vendor.insert(key.clone());
            }
            if was_third_party {
                self.third_party.insert(key);
            }
            return Err(e);
        }
        Ok(true)
    }

    /// Validate against the kernel and insert, without writing.
    fn insert_vendor(&mut self, hex_key: &str) -> Result<()> {
        // Through the kernel's own check, on a scratch store: it knows what a key is and this does
        // not, and a second opinion here is one that can disagree with the verifier.
        let mut scratch = TrustStore::deny_all();
        scratch.trust_vendor_key(hex_key)?;
        self.vendor.insert(hex_key.to_ascii_lowercase());
        Ok(())
    }

    /// As [`TrustFile::insert_vendor`], for the third-party set.
    fn insert_third_party(&mut self, hex_key: &str) -> Result<()> {
        let mut scratch = TrustStore::deny_all();
        scratch.trust_third_party_key(hex_key)?;
        self.third_party.insert(hex_key.to_ascii_lowercase());
        Ok(())
    }

    /// Write the whole store, atomically.
    fn save(&self) -> Result<()> {
        let stored = Stored {
            vendor: self.vendor.iter().cloned().collect(),
            third_party: self.third_party.iter().cloned().collect(),
        };
        let text = serde_json::to_string_pretty(&stored)
            .map_err(|e| refusal(format!("cannot serialise the trust store: {e}")))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| refusal(format!("cannot create {}: {e}", parent.display())))?;
        }
        // A sibling temporary file, so the rename is within one directory and therefore atomic on
        // every platform this builds for.
        let temp = self.path.with_extension("json.tmp");
        {
            let mut file = std::fs::File::create(&temp)
                .map_err(|e| refusal(format!("cannot create {}: {e}", temp.display())))?;
            file.write_all(text.as_bytes())
                .map_err(|e| refusal(format!("cannot write {}: {e}", temp.display())))?;
            file.sync_data()
                .map_err(|e| refusal(format!("cannot sync {}: {e}", temp.display())))?;
        }
        std::fs::rename(&temp, &self.path).map_err(|e| {
            refusal(format!(
                "cannot replace {} with {}: {e}",
                self.path.display(),
                temp.display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nau-trust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("trust.json")
    }

    fn key(seed: u8) -> String {
        nau_plugins_fixture_key(seed)
    }

    /// A valid public key, produced the way the crate's own tests produce them.
    fn nau_plugins_fixture_key(seed: u8) -> String {
        use ed25519_dalek::SigningKey;
        use std::fmt::Write as _;
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        bytes[31] = seed.wrapping_mul(7);
        let signing = SigningKey::from_bytes(&bytes);
        // A `write!` loop rather than `.map(format!).collect()`, which clippy rejects for building
        // a string out of an iterator: that shape allocates one String per byte and immediately
        // throws each away.
        let mut hex = String::with_capacity(64);
        for byte in signing.verifying_key().to_bytes() {
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    #[test]
    fn a_missing_file_trusts_nobody_rather_than_everybody() {
        // The fail-closed direction. A node that refused to start because nobody had been trusted
        // yet would invert the point; one that started trusting everybody would be worse.
        let file = TrustFile::open(scratch("empty")).expect("opens");
        assert!(file.is_empty());
        assert_eq!(file.len(), 0);
        let store = file.store().expect("builds");
        assert!(
            store.is_empty(),
            "an empty file must produce a store that trusts nobody"
        );
        assert!(!store.is_trusted_vendor_key(&key(1)));
        assert!(!store.is_trusted_third_party_key(&key(1)));
    }

    #[test]
    fn a_trusted_key_survives_reopening() {
        // C-06's second criterion, checked through a NEW `TrustFile` so nothing is served from the
        // first one's memory.
        let path = scratch("durable");
        {
            let mut file = TrustFile::open(&path).expect("opens");
            file.trust_vendor(&key(3)).expect("trust");
            file.trust_third_party(&key(4)).expect("trust");
            assert_eq!(file.len(), 2);
        }
        let reopened = TrustFile::open(&path).expect("reopens");
        assert_eq!(reopened.len(), 2, "the keys must come back from the file");
        assert_eq!(reopened.vendor_keys(), vec![key(3).as_str()]);
        assert_eq!(reopened.third_party_keys(), vec![key(4).as_str()]);

        let store = reopened.store().expect("builds");
        assert!(store.is_trusted_vendor_key(&key(3)));
        assert!(store.is_trusted_third_party_key(&key(4)));
        // And the two sets stay separate: a vendor key is not a third-party publisher.
        assert!(!store.is_trusted_third_party_key(&key(3)));
        assert!(!store.is_trusted_vendor_key(&key(4)));
    }

    #[test]
    fn a_key_the_kernel_rejects_is_refused_and_does_not_reach_the_disk() {
        // The kernel knows what a key is and this does not, so the check is delegated. A file with
        // something that is not a key in it must not exist afterwards.
        let path = scratch("badkey");
        let mut file = TrustFile::open(&path).expect("opens");
        for bad in ["", "not hex at all", "00", &"zz".repeat(32)] {
            let err = file
                .trust_vendor(bad)
                .expect_err("must refuse a key the kernel rejects");
            assert!(
                !format!("{err}").is_empty(),
                "the refusal must say something about `{bad}`"
            );
        }
        assert!(file.is_empty(), "nothing invalid may be remembered");
        assert!(!path.exists(), "and nothing invalid may reach the disk");
    }

    #[test]
    fn revoking_removes_a_key_from_both_sets_and_survives_a_reopen() {
        let path = scratch("revoke");
        {
            let mut file = TrustFile::open(&path).expect("opens");
            file.trust_vendor(&key(5)).expect("trust");
            assert!(file.revoke(&key(5)).expect("revoke"), "it was trusted");
            assert!(!file.revoke(&key(5)).expect("revoke"), "and now it is not");
        }
        let reopened = TrustFile::open(&path).expect("reopens");
        assert!(reopened.is_empty(), "a revoked key must not come back");
        assert!(!reopened
            .store()
            .expect("builds")
            .is_trusted_vendor_key(&key(5)));
    }

    #[test]
    fn a_file_that_is_not_a_store_refuses_to_open() {
        // A store that silently skipped what it could not read would trust less than it was told
        // to, without saying so.
        let path = scratch("corrupt");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, "{ this is not json }").expect("write");
        let err = TrustFile::open(&path).expect_err("must refuse");
        assert!(
            format!("{err}").contains("is not a trust store"),
            "got: {err}"
        );
    }

    #[test]
    fn a_hand_edited_file_with_an_invalid_key_refuses_to_open() {
        // Editing the file is the ordinary way a key gets added on a machine with no operator
        // tooling, so the validation has to happen on the read path as well as the write path.
        let path = scratch("handedited");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, r#"{"vendor":["not-a-key"],"third_party":[]}"#).expect("write");
        let err = TrustFile::open(&path).expect_err("must refuse");
        assert!(!format!("{err}").is_empty());
    }

    #[test]
    fn the_store_is_written_whole_rather_than_appended() {
        // A set is not a log. Writing the same key twice must not grow the file, and the temporary
        // file must not be left behind.
        let path = scratch("atomic");
        let mut file = TrustFile::open(&path).expect("opens");
        file.trust_vendor(&key(6)).expect("trust");
        let first = std::fs::read_to_string(&path).expect("read");
        file.trust_vendor(&key(6)).expect("trust again");
        let second = std::fs::read_to_string(&path).expect("read");
        assert_eq!(first, second, "re-trusting a key must not change the file");
        assert_eq!(file.len(), 1, "and must not duplicate it");
        assert!(
            !path.with_extension("json.tmp").exists(),
            "the temporary file must be renamed away, not left behind"
        );
    }
}
