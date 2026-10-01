//! Hot update, hot plug, and compatibility with older plugin ABIs.
//!
//! # The three things, and what makes each one hard
//!
//! **Hot compatibility** is the precondition for the other two. A host that has moved to
//! ABI `3.x` and refuses every `2.x` plugin has not become extensible, it has become
//! incompatible — and "publish a new build" is not an answer when the publisher is
//! someone else. So the host carries **adapters**: a named translation from an older ABI
//! onto the current one. An ABI with no adapter is still refused, with the migration path
//! named, because a silent downgrade is worse than a refusal.
//!
//! **Hot update** is double buffering. A new version is prepared *beside* the running
//! one — parsed, verified, health-checked — and only then is the routing table switched.
//! The switch is a single pointer replacement, so a request either sees the old table or
//! the new one and never a half-built mixture. The old instance is drained afterwards,
//! and a failure while draining does not resurrect it: the new version is already serving.
//!
//! **Hot plug** is the dependency graph. Starting something whose dependencies are not
//! running produces a plugin that fails later, in a way that is hard to attribute, so the
//! order is computed rather than hoped for. Stopping something that others depend on
//! requires pausing those dependents *first*, in reverse order — otherwise they keep
//! calling into a stopped plugin and the failure surfaces somewhere else entirely.
//!
//! # What this module does not do
//!
//! It does not start processes or call plugins. It decides **what the routing table
//! should contain and in what order things may move**, and it performs the switch. The
//! actual start/stop belongs to the runtime, which the host owns — the same split the
//! isolation port already uses.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};

use crate::bus::{PmbKind, PmbMessage};
use crate::error::{LoadRefusal, PluginError, Result};
use crate::registry::Registry;
use crate::runtime::{PluginInstance, RuntimeKind};

/// An ABI version, major and minor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Abi {
    /// Breaking changes live here.
    pub major: u32,
    /// Additive changes live here.
    pub minor: u32,
}

impl Abi {
    /// An ABI version.
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// This host's ABI.
    #[must_use]
    pub const fn host() -> Self {
        Self::new(crate::ABI_MAJOR, crate::ABI_MINOR)
    }

    /// Whether a plugin built for `self` can run here without an adapter.
    #[must_use]
    pub fn is_directly_compatible_with(self, host: Abi) -> bool {
        self.major == host.major && self.minor <= host.minor
    }

    /// Whether `self` is *newer* than the host, which no adapter can fix.
    #[must_use]
    pub fn is_from_the_future(self, host: Abi) -> bool {
        self.major > host.major || (self.major == host.major && self.minor > host.minor)
    }
}

impl std::fmt::Display for Abi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A translation from an older plugin ABI onto this host's bus.
///
/// The trait is deliberately about **messages**, not about code. An adapter cannot make
/// an old binary run new code; it can make the old binary's *messages* understood. That
/// is the honest limit of compatibility, and stating it here keeps anyone from expecting
/// a magic shim.
pub trait AbiAdapter: Send + Sync + std::fmt::Debug {
    /// The ABI this adapter accepts. Named `accepts` rather than `from_abi` because
    /// `from_*` is Rust's constructor convention and this is a getter -- a distinction
    /// clippy enforces, and one that reads better anyway.
    fn accepts(&self) -> Abi;
    /// The ABI it produces.
    fn produces(&self) -> Abi;
    /// A human-readable name, for the load trace and for diagnostics.
    fn name(&self) -> &str;
    /// Translate one message.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when the message cannot be expressed on the new bus.
    /// A refusal here is ordinary: an operation that the new ABI dropped has no
    /// translation, and inventing one would be worse than saying so.
    fn adapt(&self, message: &PmbMessage) -> Result<PmbMessage>;
}

/// The `2.x → 3.x` adapter this host ships.
///
/// # What actually changed between 2.x and 3.x
///
/// The bus stayed canonical JSON, so a 2.x message is already readable. What 3.x added is
/// the `crypto:channel` capability and made `Target::Broadcast` require an explicit
/// topic. A 2.x broadcast without a topic is therefore **not translatable** — it is not
/// that the adapter is lazy, it is that the message cannot be addressed, and inventing a
/// topic would silently change who receives it.
#[derive(Debug, Default)]
pub struct Abi2To3;

impl AbiAdapter for Abi2To3 {
    fn accepts(&self) -> Abi {
        Abi::new(2, 0)
    }

    fn produces(&self) -> Abi {
        Abi::new(3, 0)
    }

    fn name(&self) -> &str {
        "abi-2-to-3"
    }

    fn adapt(&self, message: &PmbMessage) -> Result<PmbMessage> {
        use crate::bus::Target;
        if message.target == Target::Broadcast && message.topic.is_none() {
            return Err(PluginError::Manifest(
                "abi-2-to-3: a 2.x broadcast without a topic cannot be addressed on the 3.x \
                 bus; the sender must name a topic, because choosing one here would change \
                 who receives the message"
                    .into(),
            ));
        }
        // Everything else is structurally the same: canonical JSON on both sides, the
        // same envelope fields. The adapter exists so that the *fact* of translation is
        // recorded in the load trace, not because bytes have to move.
        let mut adapted = message.clone();
        adapted.kind = match message.kind {
            // A 2.x `Event` with a correlation id was a request in all but name; 3.x
            // split those, and the correlation id is the discriminator.
            PmbKind::Event if message.corr_id.is_some() => PmbKind::Request,
            other => other,
        };
        Ok(adapted)
    }
}

/// Which adapter an ABI needs, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compat {
    /// The plugin speaks this host's ABI.
    Direct,
    /// An adapter covers it.
    Adapted {
        /// The adapter's name, recorded in the load trace.
        adapter: String,
        /// The ABI the adapter accepts.
        from: Abi,
    },
}

/// The adapters this host knows.
#[derive(Debug, Default)]
pub struct AdapterRegistry {
    adapters: Vec<Arc<dyn AbiAdapter>>,
}

impl AdapterRegistry {
    /// An empty registry: nothing older is accepted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The registry this host runs with.
    ///
    /// Not the default, deliberately: an empty registry is the fail-closed state, and a
    /// host that wants compatibility has to say so.
    #[must_use]
    pub fn with_shipped_adapters() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(Abi2To3));
        registry
    }

    /// Add an adapter.
    pub fn register(&mut self, adapter: Arc<dyn AbiAdapter>) {
        self.adapters.push(adapter);
    }

    /// How many adapters are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.adapters.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty()
    }

    /// The adapter names, in registration order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.adapters.iter().map(|a| a.name()).collect()
    }

    /// Decide how, or whether, a plugin ABI can run here.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] with [`LoadRefusal::AbiIncompatible`] when the ABI is
    /// from the future (no adapter can help), or when it is older and no adapter covers
    /// it — in which case the refusal names the adapters that *are* available, because
    /// "incompatible" without that list is a dead end rather than a diagnosis.
    pub fn compatibility(&self, plugin: Abi) -> Result<Compat> {
        let host = Abi::host();
        if plugin.is_directly_compatible_with(host) {
            return Ok(Compat::Direct);
        }
        if plugin.is_from_the_future(host) {
            return Err(PluginError::Manifest(format!(
                "{}: the plugin speaks ABI {plugin} and this host speaks {host}; a newer ABI \
                 cannot be adapted downwards, because the host does not know what it added",
                LoadRefusal::AbiIncompatible.code()
            )));
        }
        let found = self
            .adapters
            .iter()
            .find(|a| a.accepts().major == plugin.major && a.produces().major == host.major);
        match found {
            Some(adapter) => Ok(Compat::Adapted {
                adapter: adapter.name().to_string(),
                from: adapter.accepts(),
            }),
            None => Err(PluginError::Manifest(format!(
                "{}: the plugin speaks ABI {plugin} and this host speaks {host}, and no adapter \
                 covers that step; registered adapters: {}",
                LoadRefusal::AbiIncompatible.code(),
                if self.adapters.is_empty() {
                    "none — this host runs only plugins built for its own ABI".to_string()
                } else {
                    self.names().join(", ")
                }
            ))),
        }
    }

    /// Find the adapter for a plugin ABI, if one covers it.
    #[must_use]
    pub fn adapter_for(&self, plugin: Abi) -> Option<&Arc<dyn AbiAdapter>> {
        let host = Abi::host();
        self.adapters
            .iter()
            .find(|a| a.accepts().major == plugin.major && a.produces().major == host.major)
    }
}

/// One plugin's entry in the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSlot {
    /// The plugin's name.
    pub id: String,
    /// The plugin's own version.
    pub version: String,
    /// The ABI it was built against.
    pub abi: Abi,
    /// Which generation of this plugin's life this slot is. Increments on every swap, so
    /// a request can be attributed to a specific version even while both exist.
    pub generation: u64,
    /// What is running it.
    pub runtime: RuntimeKind,
    /// The runtime's handle.
    pub instance: Option<PluginInstance>,
}

/// The table the bus routes with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingTable {
    entries: BTreeMap<String, PluginSlot>,
}

impl RoutingTable {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many plugins are routable.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is routable.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look one up.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PluginSlot> {
        self.entries.get(name)
    }

    /// Every name, in order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    /// A copy with `slot` inserted or replaced.
    #[must_use]
    pub fn with_slot(&self, slot: PluginSlot) -> Self {
        let mut next = self.clone();
        next.entries.insert(slot.id.clone(), slot);
        next
    }

    /// A copy without `name`.
    #[must_use]
    pub fn without(&self, name: &str) -> Self {
        let mut next = self.clone();
        next.entries.remove(name);
        next
    }
}

/// What a swap did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapRecord {
    /// The plugin.
    pub id: String,
    /// The version that was serving before.
    pub from_version: Option<String>,
    /// The version serving now.
    pub to_version: String,
    /// The new generation.
    pub generation: u64,
    /// Whether the old instance drained cleanly.
    pub drained: bool,
}

/// Why a swap did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapRefusal {
    /// The plugin is not routable, so there is nothing to replace.
    NotRunning,
    /// The new version failed its health check, so the switch never happened.
    Unhealthy(String),
    /// The name in the slot does not match the name being swapped.
    NameMismatch,
}

impl SwapRefusal {
    /// A stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            SwapRefusal::NotRunning => "swap_not_running",
            SwapRefusal::Unhealthy(_) => "swap_unhealthy",
            SwapRefusal::NameMismatch => "swap_name_mismatch",
        }
    }
}

impl std::fmt::Display for SwapRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapRefusal::NotRunning => {
                f.write_str("swap_not_running: the plugin is not in the routing table")
            }
            SwapRefusal::Unhealthy(why) => write!(f, "swap_unhealthy: {why}"),
            SwapRefusal::NameMismatch => f.write_str(
                "swap_name_mismatch: the slot's name differs from the name being swapped",
            ),
        }
    }
}

/// A hot-update coordinator: double buffered, single atomic switch, with rollback.
///
/// # Why the table lives behind an `RwLock<Arc<_>>`
///
/// The switch has to be atomic with respect to readers: a request must see either the old
/// table or the new one, never a mix. Replacing an `Arc` under a lock gives exactly that
/// — a reader takes the lock only long enough to clone the pointer, then works from an
/// immutable snapshot while the switch proceeds.
///
/// `arc-swap` would do the same without the lock, and it is **not a dependency of this
/// project**. Its absence is not a reason to fake the guarantee, and it is also not a
/// reason to skip the feature: a short read lock is correct, and its cost is stated here
/// rather than hidden.
#[derive(Debug)]
pub struct HotSwapper {
    table: RwLock<Arc<RoutingTable>>,
    generation: AtomicU64,
    history: Mutex<Vec<SwapRecord>>,
}

impl Default for HotSwapper {
    fn default() -> Self {
        Self::new()
    }
}

impl HotSwapper {
    /// A coordinator with an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: RwLock::new(Arc::new(RoutingTable::new())),
            generation: AtomicU64::new(1),
            history: Mutex::new(Vec::new()),
        }
    }

    /// An immutable snapshot of the routing table.
    ///
    /// This is what a request handler holds: one `Arc` clone, taken once, used for the
    /// whole request. A swap during the request cannot change what it sees.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RoutingTable> {
        match self.table.read() {
            Ok(guard) => Arc::clone(&guard),
            // A poisoned lock means a writer panicked while holding it. The table is an
            // `Arc` behind the lock, so the previous value is still structurally valid;
            // serving from it is strictly better than refusing every request, and the
            // poison is reported by `history` being short rather than hidden.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// How many swaps have happened.
    #[must_use]
    pub fn history(&self) -> Vec<SwapRecord> {
        match self.history.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The current generation counter.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Register a plugin that was not previously routable.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when the name is already routable: an upgrade is a
    /// swap, and doing it by insertion would replace a running instance without draining
    /// it.
    pub fn insert(&self, slot: PluginSlot) -> Result<u64> {
        let current = self.snapshot();
        if current.get(&slot.id).is_some() {
            return Err(PluginError::Lifecycle(format!(
                "`{}` is already routable; use `swap` so the running instance is drained",
                slot.id
            )));
        }
        let generation = self.generation.fetch_add(1, Ordering::SeqCst);
        let mut slot = slot;
        slot.generation = generation;
        let next = current.with_slot(slot);
        self.publish(next);
        Ok(generation)
    }

    /// Swap in a new version of a routable plugin.
    ///
    /// The order is the whole point:
    ///
    /// 1. **health** — the new slot is checked *before* anything changes, so a bad build
    ///    never reaches the table and no rollback is needed for the common failure;
    /// 2. **switch** — one pointer replacement under the write lock;
    /// 3. **drain** — the old instance is released afterwards. Its failure is recorded
    ///    and does **not** resurrect it: the new version is already serving, and putting
    ///    the old one back because it would not stop cleanly would be a downgrade
    ///    disguised as a rollback.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] carrying a [`SwapRefusal`] code.
    pub fn swap<H, D>(&self, slot: PluginSlot, health: H, drain: D) -> Result<SwapRecord>
    where
        H: FnOnce(&PluginSlot) -> std::result::Result<(), String>,
        D: FnOnce(&PluginSlot) -> std::result::Result<(), String>,
    {
        let current = self.snapshot();
        let Some(old) = current.get(&slot.id).cloned() else {
            return Err(refuse(SwapRefusal::NotRunning));
        };
        if slot.id != old.id {
            return Err(refuse(SwapRefusal::NameMismatch));
        }
        if let Err(why) = health(&slot) {
            return Err(refuse(SwapRefusal::Unhealthy(why)));
        }

        let generation = self.generation.fetch_add(1, Ordering::SeqCst);
        let mut new_slot = slot;
        new_slot.generation = generation;
        let next = current.with_slot(new_slot);
        self.publish(next);

        let drained = drain(&old).is_ok();
        let record = SwapRecord {
            id: old.id.clone(),
            from_version: Some(old.version.clone()),
            to_version: current
                .get(&old.id)
                .map(|s| s.version.clone())
                .unwrap_or_default(),
            generation,
            drained,
        };
        // `to_version` must be the *new* version, not the old table's.
        let record = SwapRecord {
            to_version: self
                .snapshot()
                .get(&record.id)
                .map(|s| s.version.clone())
                .unwrap_or(record.to_version),
            ..record
        };
        self.record(record.clone());
        Ok(record)
    }

    /// Put a previous version back, deliberately.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when the plugin is not routable.
    pub fn rollback(&self, id: &str, previous: PluginSlot) -> Result<u64> {
        let current = self.snapshot();
        if current.get(id).is_none() {
            return Err(refuse(SwapRefusal::NotRunning));
        }
        let generation = self.generation.fetch_add(1, Ordering::SeqCst);
        let mut slot = previous;
        slot.generation = generation;
        let from_version = current.get(id).map(|s| s.version.clone());
        let to_version = slot.version.clone();
        let next = current.with_slot(slot);
        self.publish(next);
        self.record(SwapRecord {
            id: id.to_string(),
            from_version,
            to_version,
            generation,
            drained: false,
        });
        Ok(generation)
    }

    /// Remove a plugin from the table.
    ///
    /// # Errors
    ///
    /// [`PluginError::Lifecycle`] when it is not routable.
    pub fn remove(&self, id: &str) -> Result<()> {
        let current = self.snapshot();
        if current.get(id).is_none() {
            return Err(refuse(SwapRefusal::NotRunning));
        }
        self.publish(current.without(id));
        Ok(())
    }

    /// Replace the whole table. Used at boot.
    pub fn publish(&self, table: RoutingTable) {
        match self.table.write() {
            Ok(mut guard) => *guard = Arc::new(table),
            Err(poisoned) => *poisoned.into_inner() = Arc::new(table),
        }
    }

    /// Append to the swap history.
    fn record(&self, record: SwapRecord) {
        match self.history.lock() {
            Ok(mut guard) => guard.push(record),
            Err(poisoned) => poisoned.into_inner().push(record),
        }
    }
}

/// Build the lifecycle refusal that carries a swap code.
fn refuse(why: SwapRefusal) -> PluginError {
    PluginError::Lifecycle(why.to_string())
}

/// Dependency-ordered start and stop, for hot plugging.
#[derive(Debug, Default)]
pub struct HotPlug;

impl HotPlug {
    /// The order in which plugins may be started, dependencies first.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] on a cycle, from the registry's own order computation —
    /// one implementation, so the two cannot disagree.
    pub fn start_order(registry: &Registry) -> Result<Vec<String>> {
        registry.load_order()
    }

    /// What must happen to stop `name` safely.
    ///
    /// Returns the dependents that must be paused first, in reverse dependency order,
    /// followed by `name` itself. Stopping a plugin while something still calls it moves
    /// the failure somewhere else entirely, which is why this is computed rather than
    /// left to the caller's judgement.
    ///
    /// # Errors
    ///
    /// [`PluginError::Manifest`] when `name` is not registered.
    pub fn stop_plan(registry: &Registry, name: &str) -> Result<Vec<String>> {
        if registry.get(name).is_none() {
            return Err(PluginError::Manifest(format!(
                "`{name}` is not registered, so there is nothing to stop"
            )));
        }
        // Transitive dependents, closest first.
        let mut plan: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut frontier = vec![name.to_string()];
        while let Some(target) = frontier.pop() {
            for candidate in registry.names() {
                if candidate == target || seen.contains(&candidate) {
                    continue;
                }
                let depends = registry
                    .get(&candidate)
                    .is_some_and(|e| e.dependencies.iter().any(|d| d.name == target));
                if depends {
                    seen.insert(candidate.clone());
                    plan.push(candidate.clone());
                    frontier.push(candidate);
                }
            }
        }
        // Reverse dependency order: the furthest dependent stops first. `plan` is built
        // closest-first, so reversing it gives the safe order.
        plan.reverse();
        plan.push(name.to_string());
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{PmbMessage, Priority, Target};
    use crate::capability::Capability;
    use crate::tier::PluginId;

    fn slot(id: &str, version: &str) -> PluginSlot {
        PluginSlot {
            id: id.to_string(),
            version: version.to_string(),
            abi: Abi::host(),
            generation: 0,
            runtime: RuntimeKind::Process,
            instance: None,
        }
    }

    #[test]
    fn a_plugin_at_the_hosts_own_abi_needs_no_adapter() {
        let registry = AdapterRegistry::new();
        assert_eq!(
            registry.compatibility(Abi::host()).expect("direct"),
            Compat::Direct
        );
        // An older minor of the same major is also direct: the bus is additive within a
        // major, which is what makes a minor bump safe.
        let older_minor = Abi::new(crate::ABI_MAJOR, 0);
        assert_eq!(
            registry.compatibility(older_minor).expect("direct"),
            Compat::Direct
        );
    }

    #[test]
    fn an_older_major_is_adapted_when_the_host_ships_an_adapter() {
        let registry = AdapterRegistry::with_shipped_adapters();
        assert_eq!(registry.len(), 1);
        let compat = registry
            .compatibility(Abi::new(2, 2))
            .expect("the shipped adapter covers 2.x");
        assert_eq!(
            compat,
            Compat::Adapted {
                adapter: "abi-2-to-3".to_string(),
                from: Abi::new(2, 0),
            }
        );
    }

    #[test]
    fn an_older_major_without_an_adapter_is_refused_and_names_what_is_registered() {
        // The fail-closed default: a host that has registered no adapter accepts nothing
        // but its own ABI, and says which adapters it does have.
        let registry = AdapterRegistry::new();
        let err = registry
            .compatibility(Abi::new(2, 2))
            .expect_err("must be refused");
        let text = err.to_string();
        assert!(text.contains("abi_incompatible"), "{text}");
        assert!(text.contains("no adapter covers that step"), "{text}");
        assert!(text.contains("none"), "{text}");
    }

    #[test]
    fn a_future_abi_is_refused_and_no_adapter_can_change_that() {
        let registry = AdapterRegistry::with_shipped_adapters();
        let future = Abi::new(crate::ABI_MAJOR + 1, 0);
        let err = registry.compatibility(future).expect_err("must be refused");
        assert!(
            err.to_string().contains("cannot be adapted downwards"),
            "{err}"
        );

        // Same major, newer minor: also from the future, and also refused.
        let newer_minor = Abi::new(crate::ABI_MAJOR, crate::ABI_MINOR + 1);
        assert!(registry.compatibility(newer_minor).is_err());
    }

    #[test]
    fn the_2_to_3_adapter_translates_what_it_can_and_refuses_what_it_cannot() {
        let adapter = Abi2To3;
        assert_eq!(adapter.accepts(), Abi::new(2, 0));
        assert_eq!(adapter.produces(), Abi::new(3, 0));
        assert_eq!(adapter.name(), "abi-2-to-3");

        let source = PluginId::parse("io.example.a").expect("id");
        // A topic-less broadcast cannot be addressed on the 3.x bus, so it is refused
        // rather than given a topic the sender did not choose.
        let untopiced = PmbMessage::new(
            &source,
            Target::Broadcast,
            Capability::MessageSend,
            PmbKind::Event,
            serde_json::json!({}),
            1_750_000_000,
        );
        let err = adapter.adapt(&untopiced).expect_err("must be refused");
        assert!(err.to_string().contains("cannot be addressed"), "{err}");

        // With a topic it passes through.
        let topiced = untopiced.clone().with_topic("market.task.settled");
        assert!(adapter.adapt(&topiced).is_ok());

        // A 2.x `Event` carrying a correlation id was a request in all but name.
        let requestish = PmbMessage::new(
            &source,
            Target::Host,
            Capability::MessageSend,
            PmbKind::Event,
            serde_json::json!({}),
            1_750_000_000,
        )
        .answering("corr-1");
        let adapted = adapter.adapt(&requestish).expect("translates");
        assert_eq!(adapted.kind, PmbKind::Request);
        assert_eq!(
            adapted.priority,
            Priority::Normal,
            "other fields are preserved"
        );
    }

    #[test]
    fn inserting_a_plugin_publishes_a_new_generation() {
        let swapper = HotSwapper::new();
        assert!(swapper.snapshot().is_empty());
        let g1 = swapper
            .insert(slot("io.example.a", "1.0.0"))
            .expect("inserts");
        assert_eq!(swapper.snapshot().len(), 1);
        assert_eq!(
            swapper
                .snapshot()
                .get("io.example.a")
                .expect("there")
                .generation,
            g1
        );

        // A second insert of the same name is an upgrade, and must go through `swap`.
        let err = swapper
            .insert(slot("io.example.a", "2.0.0"))
            .expect_err("must refuse");
        assert!(err.to_string().contains("use `swap`"), "{err}");
    }

    #[test]
    fn a_swap_checks_health_before_it_changes_anything() {
        let swapper = HotSwapper::new();
        swapper
            .insert(slot("io.example.a", "1.0.0"))
            .expect("inserts");

        let err = swapper
            .swap(
                slot("io.example.a", "2.0.0"),
                |_| Err("the new build does not answer on its socket".to_string()),
                |_| Ok(()),
            )
            .expect_err("an unhealthy build must not be swapped in");
        assert!(err.to_string().contains("swap_unhealthy"), "{err}");

        // The table is untouched: a failed swap leaves no trace at all, which is why the
        // common failure needs no rollback.
        let table = swapper.snapshot();
        assert_eq!(table.get("io.example.a").expect("there").version, "1.0.0");
        assert!(swapper.history().is_empty());
    }

    #[test]
    fn a_healthy_swap_switches_the_table_and_drains_the_old_instance() {
        use std::sync::atomic::AtomicBool;
        let drained = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&drained);

        let swapper = HotSwapper::new();
        swapper
            .insert(slot("io.example.a", "1.0.0"))
            .expect("inserts");
        let before = swapper.snapshot();

        let record = swapper
            .swap(
                slot("io.example.a", "2.0.0"),
                |_| Ok(()),
                move |old| {
                    assert_eq!(old.version, "1.0.0", "the drained slot is the old one");
                    flag.store(true, Ordering::SeqCst);
                    Ok(())
                },
            )
            .expect("swaps");

        assert_eq!(record.from_version.as_deref(), Some("1.0.0"));
        assert_eq!(record.to_version, "2.0.0");
        assert!(record.drained);
        assert!(drained.load(Ordering::SeqCst));

        // The snapshot taken before the swap still sees the old version: a request that
        // started before the switch is not retargeted underneath itself.
        assert_eq!(before.get("io.example.a").expect("there").version, "1.0.0");
        assert_eq!(
            swapper
                .snapshot()
                .get("io.example.a")
                .expect("there")
                .version,
            "2.0.0"
        );
        assert_eq!(swapper.history().len(), 1);
    }

    #[test]
    fn a_drain_failure_does_not_resurrect_the_old_version() {
        // Putting the old version back because it would not stop cleanly would be a
        // downgrade disguised as a rollback.
        let swapper = HotSwapper::new();
        swapper
            .insert(slot("io.example.a", "1.0.0"))
            .expect("inserts");
        let record = swapper
            .swap(
                slot("io.example.a", "2.0.0"),
                |_| Ok(()),
                |_| Err("the old process ignored SIGTERM".to_string()),
            )
            .expect("the swap still happens");
        assert!(!record.drained, "the drain failure is recorded");
        assert_eq!(
            swapper
                .snapshot()
                .get("io.example.a")
                .expect("there")
                .version,
            "2.0.0",
            "the new version keeps serving"
        );
    }

    #[test]
    fn swapping_a_plugin_that_is_not_routable_is_refused() {
        let swapper = HotSwapper::new();
        let err = swapper
            .swap(slot("io.example.absent", "1.0.0"), |_| Ok(()), |_| Ok(()))
            .expect_err("must be refused");
        assert!(err.to_string().contains("swap_not_running"), "{err}");
    }

    #[test]
    fn a_deliberate_rollback_puts_a_previous_version_back() {
        let swapper = HotSwapper::new();
        swapper
            .insert(slot("io.example.a", "1.0.0"))
            .expect("inserts");
        let previous = swapper
            .snapshot()
            .get("io.example.a")
            .expect("there")
            .clone();
        swapper
            .swap(slot("io.example.a", "2.0.0"), |_| Ok(()), |_| Ok(()))
            .expect("swaps");
        assert_eq!(
            swapper
                .snapshot()
                .get("io.example.a")
                .expect("there")
                .version,
            "2.0.0"
        );

        swapper
            .rollback("io.example.a", previous)
            .expect("rolls back");
        let table = swapper.snapshot();
        assert_eq!(table.get("io.example.a").expect("there").version, "1.0.0");
        assert_eq!(
            swapper.history().len(),
            2,
            "both the swap and the rollback are recorded"
        );
    }

    #[test]
    fn removing_a_plugin_takes_it_out_of_the_routing_table() {
        let swapper = HotSwapper::new();
        swapper
            .insert(slot("io.example.a", "1.0.0"))
            .expect("inserts");
        swapper.remove("io.example.a").expect("removes");
        assert!(swapper.snapshot().is_empty());
        assert!(
            swapper.remove("io.example.a").is_err(),
            "removing twice is refused"
        );
    }

    #[test]
    fn abi_ordering_knows_the_direction_of_time() {
        let host = Abi::new(3, 2);
        assert!(!Abi::new(2, 9).is_directly_compatible_with(host));
        assert!(Abi::new(3, 0).is_directly_compatible_with(host));
        assert!(Abi::new(3, 3).is_from_the_future(host));
        assert!(Abi::new(4, 0).is_from_the_future(host));
        assert!(!Abi::new(2, 0).is_from_the_future(host));
        // A future minor of the same major is not "directly compatible" and is future.
        assert!(!Abi::new(3, 3).is_directly_compatible_with(host));
    }

    #[test]
    fn the_routing_table_is_immutable_once_snapshotted() {
        let table = RoutingTable::new().with_slot(slot("a", "1.0.0"));
        let derived = table.with_slot(slot("b", "1.0.0"));
        assert_eq!(table.len(), 1, "the original is untouched");
        assert_eq!(derived.len(), 2);
        assert_eq!(table.without("a").len(), 0);
    }
}
