//! The host half of the process-plugin runtime, driven for real.
//!
//! # What was missing before this file
//!
//! `nau_plugin::runtime::ProcessRuntime::call` refuses on purpose, with a message saying the
//! exec "is performed by the host against handle …". No host performed it: `nau-node`
//! referenced the sandbox, the frame codec and the process runtime nowhere at all. A process
//! plugin could be started and stopped, and could never be called.
//!
//! So this file has two jobs. The portable tests pin the refusals and the **order** — the
//! runtime is asked before a sandbox directory is created, so a refused plugin leaves
//! nothing behind. The Windows-gated test runs a real binary through
//! [`ProcessPluginHost`] and reads a real answer back, which is the part that turns the
//! sentence in that error message into something true.
//!
//! # Why the end-to-end test is Windows-gated
//!
//! The sandbox backend behaves differently per platform, and CI established the matrix:
//! Windows runs and enforces; Linux runs; **macOS refuses with `EINVAL`** inside the
//! manager. Asserting a launch where the backend cannot be shown to deliver it published a
//! red CI on 2026-10-01, and the honest fix was to stop asserting it there rather than to
//! weaken the assertion. The portable declaration test lives in
//! `nau-plugins/tests/process_plugin.rs`; `docs/VERIFICATION.md` §5.2 records the matrix.

use std::collections::BTreeMap;
use std::path::PathBuf;

use nau_node::plugin_process::{required_waivers, ProcessPluginHost};
use nau_plugin::runtime::{NativeRuntime, ProcessRuntime, StartSpec};
use nau_plugin::{PluginId, Tier};
use nau_plugins::frame;

/// The directory cargo built into, derived from this test binary's own location.
///
/// `CARGO_BIN_EXE_<name>` is only set for binaries of the crate under test, and the plugin
/// binaries belong to `nau-plugins` while this test belongs to `nau-node` -- so the path has
/// to be derived. The test binary lives at `<target>/<profile>/deps/<name>-<hash>`, which
/// makes the profile directory its grandparent.
fn built_binary(name: &str) -> PathBuf {
    let mut dir = std::env::current_exe().expect("the test binary has a path");
    dir.pop(); // deps/
    dir.pop(); // <profile>/
    let mut path = dir.join(name);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

fn limits() -> nau_plugin::Limits {
    nau_plugins::sign::limits()
}

fn full_waivers() -> BTreeMap<String, String> {
    nau_plugins::sign::process_waivers(nau_plugins::sign::FIXTURE_WAIVER_REASON)
}

fn spec(entry: PathBuf, tier: Tier, waivers: BTreeMap<String, String>) -> StartSpec {
    StartSpec {
        plugin: PluginId::parse(frame::ECHO_PLUGIN).expect("a valid plugin name"),
        tier,
        entry,
        limits: limits(),
        waivers,
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nau-node-process-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn the_host_refuses_a_runtime_that_is_not_the_process_runtime() {
    // A native plugin shares the host's address space and has no child process to start.
    // Returning an empty sandbox for one would be the quiet widening that makes the
    // boundary meaningless, so it is a refusal that names what was passed.
    let root = scratch("native");
    let host = ProcessPluginHost::open(&root, 1_750_000_000).expect("the host opens");
    let err = host
        .start(
            &NativeRuntime::new(),
            &spec(
                built_binary("nau-plugin-echo"),
                Tier::ThirdParty,
                full_waivers(),
            ),
        )
        .expect_err("a native runtime must be refused by this host");
    assert!(err.contains("process runtime"), "{err}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_refused_plugin_creates_no_sandbox_directory() {
    // The order in `start` is the claim under test: the runtime is asked **first**, so the
    // tier gate, the waiver requirement and the existence check all answer before the
    // manager makes a directory. Creating the sandbox first would leave one behind for
    // every refused plugin, and a refused plugin is a normal outcome here.
    let root = scratch("refused");
    let host = ProcessPluginHost::open(&root, 1_750_000_000).expect("the host opens");
    let before = count_dirs(&root);

    // No waivers: the runtime refuses, naming the first boundary it cannot enforce.
    let err = host
        .start(
            &ProcessRuntime::new(),
            &spec(
                built_binary("nau-plugin-echo"),
                Tier::ThirdParty,
                BTreeMap::new(),
            ),
        )
        .expect_err("a plugin with no waivers must be refused");
    assert!(err.contains("isolation_not_enforceable"), "{err}");

    assert_eq!(
        count_dirs(&root),
        before,
        "a refused plugin must not leave a sandbox directory behind"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Directories under `root`, one level deep.
fn count_dirs(root: &std::path::Path) -> usize {
    std::fs::read_dir(root)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn the_required_waivers_are_exactly_the_boundaries_the_backend_cannot_enforce() {
    // Reported rather than discovered one refusal at a time. A manifest author needs this
    // list, and the test asserts what the backend actually cannot enforce -- if one
    // appears, or one is silently dropped, this fails.
    //
    // The expectation is **nine as of A-02**, and the history of this number is the point
    // of the test:
    //   * the first version said four, written from the four fields `nau_sandbox::Waivers`
    //     carries -- a different question from which boundaries the process backend
    //     declines. `cpu_ms` is waivable *and* unenforced, and the test caught that.
    //   * A-02 added `PmemSharedReadOnly`, `IoctlFilter`, `NetworkEgressAllowlist` and
    //     `PriorityClass` to `Boundary`, and the process runtime cannot enforce any of the
    //     four -- it shares no page cache, has no ioctl filter, has no egress primitive at
    //     all, and does not touch scheduling. The set went from five to nine.
    //
    // Growing this list is a decision, not a fix: every one of the four is a boundary the
    // process backend **cannot** enforce, so a manifest that needs one is refused rather
    // than quietly running without it.
    let waivers = required_waivers();
    let mut keys: Vec<&str> = waivers.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "cpu_ms",
            "disk_bytes",
            "filesystem_confinement",
            "ioctl_filter",
            "max_open_files",
            "network",
            "network_egress_allowlist",
            "pmem_shared_read_only",
            "priority_class",
        ],
        "the unenforced boundary set changed; every claim that depends on it has to change too"
    );
    for (key, why) in &waivers {
        assert!(
            !why.trim().is_empty(),
            "`{key}` must say why it cannot be enforced"
        );
    }
}

/// The official market plugin, started and called through the host.
///
/// # What this test is, and what it is not
///
/// It is the first execution of the path that `ProcessRuntime::call`'s refusal message
/// described and nothing implemented: **an official (T1) plugin running in a real sandbox,
/// answering over the frame ABI**. Before this, an official plugin was a manifest and
/// nothing else — `docs/PLUGIN-MIGRATION.md` said "eleven manifests, zero runnable".
///
/// What it is **not** is proof that `rank` computes correct rankings through the boundary.
/// That needs a valid `Task` and `Bid`, which are ten-field domain structures, and building
/// them as JSON here would duplicate the domain model into a test. The delegation itself is
/// proven in the binary's own test, which calls `rank` with real input and compares the
/// answer against a direct `rank_bids`. The evidence is therefore split on purpose: the
/// binary's test proves the logic, this one proves the process boundary. Neither alone
/// would justify the sentence "an official plugin runs", and the two together do.
#[cfg(windows)]
#[test]
fn the_official_market_plugin_runs_in_a_sandbox_and_answers_through_the_host() {
    let root = scratch("market");
    let host = ProcessPluginHost::open(&root, 1_750_000_000).expect("the host opens");
    let entry = built_binary("nau-plugin-market");
    assert!(
        entry.exists(),
        "the market binary must have been built for this test: {}",
        entry.display()
    );

    let start = StartSpec {
        plugin: PluginId::parse("com.twinsearth.official.market").expect("a valid plugin name"),
        // Official, not third-party: this is the tier the architecture document calls T1,
        // and it is the tier that had no runnable member before this test.
        tier: Tier::Official,
        entry,
        limits: limits(),
        waivers: full_waivers(),
    };
    let plugin = host
        .start(&ProcessRuntime::new(), &start)
        .expect("the official plugin starts in a real sandbox");
    assert_eq!(plugin.instance.plugin, "com.twinsearth.official.market");
    assert!(
        !plugin.sandbox_id().is_empty(),
        "the host must report the sandbox the plugin is in"
    );

    // `capabilities` is answerable with no domain input, and it is the op a host uses to
    // compare what a plugin declares against what it implements -- so it is the right first
    // thing to ask across a boundary that has never carried a request before.
    let answer = call(&host, &plugin, "capabilities", serde_json::json!({}));
    assert!(answer.ok, "{answer:?}");
    assert_eq!(answer.plugin, "com.twinsearth.official.market");
    let payload = answer
        .payload
        .expect("`capabilities` answers with a payload");
    let ops = payload["implemented_ops"]
        .as_array()
        .unwrap_or_else(|| panic!("implemented_ops must be an array: {payload}"));
    assert!(
        ops.iter().any(|op| op == "rank"),
        "the plugin must report the op this test drives: {payload}"
    );

    // The honest half of `capabilities`, kept in the assertion on purpose. The plugin holds
    // `agent:card:create`, `agent:card:update` and `economy:settle` in its manifest, and
    // **none of them is exercised by the ops it implements**: `rank` is matching, and the
    // capability matrix has no matching token. A host that read the declaration as a list of
    // implemented features would be wrong, and the field saying so is the reason it cannot.
    assert_eq!(
        payload["declared_capabilities_backed_by_ops"],
        serde_json::json!(false),
        "if this ever becomes true, the plugin implements an op that exercises a declared \
         capability and this test's reasoning about the declaration changes: {payload}"
    );

    // And a request it cannot satisfy comes back as a typed refusal rather than a crash or
    // a hang: `rank` without a `task` is missing a required field. This is the other half of
    // the round trip, and it is the half that a plugin which only works on the happy path
    // would fail.
    let refused = call(&host, &plugin, "rank", serde_json::json!({}));
    assert!(
        !refused.ok,
        "`rank` with no task must be refused, not answered: {refused:?}"
    );
    assert!(
        refused.code.is_some(),
        "a refusal must carry a machine-readable code: {refused:?}"
    );
    assert!(
        refused
            .message
            .as_deref()
            .is_some_and(|m| !m.trim().is_empty()),
        "a refusal must say what was wrong: {refused:?}"
    );

    host.stop(&plugin).expect("the sandbox is destroyed");
    let _ = std::fs::remove_dir_all(&root);
}

/// The **certified** plugin, started and called through the host.
///
/// # The half the binary's own author could not prove
///
/// `nau-plugin-swarm` was verified to speak the frame ABI, to refuse an unknown op with a
/// typed code, and to tally ballots signed in another process — all of that by running the
/// executable directly. What that evidence cannot show is that the plugin runs **under the
/// host**, in a sandbox, started by the runtime the architecture names for its tier. Its
/// author said so rather than implying otherwise, which is why this test exists.
///
/// The plugin is named `com.twinsearth.certified.swarm`, so `Tier::from_name` classifies it
/// as certified and `ProcessRuntime` starts it in a sandbox — the same path
/// `nau-node`'s `ProcessPluginHost` drives for the official plugin.
#[cfg(windows)]
#[test]
fn the_certified_swarm_plugin_runs_in_a_sandbox_and_answers_through_the_host() {
    let root = scratch("swarm");
    let host = ProcessPluginHost::open(&root, 1_750_000_000).expect("the host opens");
    let entry = built_binary("nau-plugin-swarm");
    assert!(
        entry.exists(),
        "the swarm binary must have been built for this test: {}",
        entry.display()
    );

    let start = StartSpec {
        plugin: PluginId::parse("com.twinsearth.certified.swarm").expect("a valid plugin name"),
        // The tier that exists to be certified, and the first plugin published under it.
        tier: Tier::Certified,
        entry,
        limits: limits(),
        waivers: full_waivers(),
    };
    let plugin = host
        .start(&ProcessRuntime::new(), &start)
        .expect("the certified plugin starts in a real sandbox");

    let answer = call(&host, &plugin, "capabilities", serde_json::json!({}));
    assert!(answer.ok, "{answer:?}");
    assert_eq!(answer.plugin, "com.twinsearth.certified.swarm");
    let payload = answer
        .payload
        .expect("`capabilities` answers with a payload");

    // It reports the tier the kernel classifies it as, and that the tier requires a
    // counter-signature -- which is the requirement its manifest has to satisfy to load.
    assert_eq!(payload["tier"], serde_json::json!("certified"), "{payload}");
    assert_eq!(
        payload["requires_counter_signature"],
        serde_json::json!(true),
        "{payload}"
    );

    let ops = payload["implemented_ops"]
        .as_array()
        .unwrap_or_else(|| panic!("implemented_ops must be an array: {payload}"));
    assert!(
        ops.iter().any(|op| op == "tally"),
        "the plugin must report the op this tier exists for: {payload}"
    );

    // The approval-gated capability, and the authority whose approval the certification
    // scope supplies. This is the link between the review flow and the load path: the
    // plugin says which authority it needs, and `Arbiter::with_certification` derives that
    // approval from the scope it is handed.
    let approvals = payload["required_approvals"]
        .as_array()
        .unwrap_or_else(|| panic!("required_approvals must be an array: {payload}"));
    assert!(
        approvals.iter().any(|row| {
            row["capability"] == serde_json::json!("swarm:consensus")
                && row["authority"] == serde_json::json!("certification-committee")
        }),
        "the plugin must name the authority that must approve its gated capability: {payload}"
    );

    // And a call it does not implement is a typed refusal, not a crash or a hang.
    let refused = call(&host, &plugin, "rank", serde_json::json!({}));
    assert!(!refused.ok, "an unknown op must be refused: {refused:?}");
    assert!(refused.code.is_some(), "{refused:?}");

    host.stop(&plugin).expect("the sandbox is destroyed");
    let _ = std::fs::remove_dir_all(&root);
}

/// The **third-party** plugin, started and called through the host.
///
/// # The half its author could not prove, again
///
/// `nau-plugin-reputation` was verified against the real executable — including an answer
/// compared field by field with an independent process applying the same events directly on
/// `nau_market` (`MISMATCHES=0`). What that cannot show is that it runs **under the host**,
/// in a sandbox, started by the runtime its tier names. Its author said so rather than
/// implying otherwise.
///
/// This is the tier the registration-and-review flow was built for, and the tier a
/// blacklist entry stops, so it is also the object those two paths had never met.
#[cfg(windows)]
#[test]
fn the_third_party_reputation_plugin_runs_in_a_sandbox_and_answers_through_the_host() {
    let root = scratch("reputation");
    let host = ProcessPluginHost::open(&root, 1_750_000_000).expect("the host opens");
    let entry = built_binary("nau-plugin-reputation");
    assert!(
        entry.exists(),
        "the reputation binary must have been built for this test: {}",
        entry.display()
    );

    let start = StartSpec {
        // A third-party name: any reverse-domain name that is not under `com.twinsearth.`,
        // which is reserved.
        plugin: PluginId::parse("com.example.reputation").expect("a valid plugin name"),
        tier: Tier::ThirdParty,
        entry,
        limits: limits(),
        waivers: full_waivers(),
    };
    let plugin = host
        .start(&ProcessRuntime::new(), &start)
        .expect("the third-party plugin starts in a real sandbox");

    let answer = call(&host, &plugin, "capabilities", serde_json::json!({}));
    assert!(answer.ok, "{answer:?}");
    assert_eq!(answer.plugin, "com.example.reputation");
    let payload = answer
        .payload
        .expect("`capabilities` answers with a payload");

    // The tier the kernel classifies it as, spelled the way `Tier::label` spells it.
    assert_eq!(payload["tier"], serde_json::json!("3rd"), "{payload}");
    // A third-party manifest needs no counter-signature -- that is the certified tier's
    // requirement -- so a plugin that said `true` here would be describing someone else.
    assert_eq!(
        payload["requires_counter_signature"],
        serde_json::json!(false),
        "{payload}"
    );
    // And it holds nothing above the basic set, which is what the tier permits. A third-party
    // plugin declaring more would be refused at load, so an accurate `true` here is the thing
    // that lets it be published at all.
    assert_eq!(
        payload["declares_only_the_basic_set"],
        serde_json::json!(true),
        "{payload}"
    );
    assert_eq!(
        payload["required_approvals"],
        serde_json::json!([]),
        "the third-party tier has no authority to appeal to: {payload}"
    );

    let ops = payload["implemented_ops"]
        .as_array()
        .unwrap_or_else(|| panic!("implemented_ops must be an array: {payload}"));
    assert!(
        ops.iter().any(|op| op == "advise"),
        "the plugin must report its own op: {payload}"
    );

    // A call it does not implement is a typed refusal, not a crash or a hang.
    let refused = call(&host, &plugin, "settle", serde_json::json!({}));
    assert!(!refused.ok, "an unknown op must be refused: {refused:?}");
    assert!(refused.code.is_some(), "{refused:?}");

    host.stop(&plugin).expect("the sandbox is destroyed");
    let _ = std::fs::remove_dir_all(&root);
}

/// The host can hot-swap a running plugin, and a bad replacement never takes traffic.
///
/// # Why this test exists
///
/// `nau-plugin`'s `hot::HotSwapper` implemented the whole mechanism — prepare beside the
/// running version, health-check before the switch, one pointer replacement, then drain —
/// and **no production code constructed one**. `HOT_SWAP_SUPPORTED` is `true`, and that
/// constant's own documentation pointed at `HotSwapper` as the mechanism, while the only
/// references to it outside its module were its own tests. A headline claim resting on a
/// mechanism nothing used is exactly the "written but not wired" shape this project exists to
/// find, so this is the caller it was missing.
///
/// Both halves are asserted, because "a swap succeeds" alone would pass on an implementation
/// that swaps to anything: a healthy replacement takes over, and an unhealthy one does not.
#[cfg(windows)]
#[test]
fn a_running_plugin_can_be_hot_swapped_and_an_unhealthy_replacement_never_takes_traffic() {
    let root = scratch("hot-swap");
    let host = ProcessPluginHost::open(&root, 1_750_000_000).expect("the host opens");
    let entry = built_binary("nau-plugin-echo");
    assert!(
        entry.exists(),
        "the echo binary must exist: {}",
        entry.display()
    );

    let spec = StartSpec {
        plugin: PluginId::parse(frame::ECHO_PLUGIN).expect("a valid name"),
        tier: Tier::ThirdParty,
        entry,
        limits: limits(),
        waivers: full_waivers(),
    };
    let first = host
        .start(&ProcessRuntime::new(), &spec)
        .expect("the first version starts");
    assert!(
        host.generation_of(frame::ECHO_PLUGIN).is_some(),
        "a started plugin must be routable, or there is nothing for a swap to replace"
    );

    // A probe the plugin actually answers. `call` frames what it is given, so these are the
    // **request bytes**, not a frame -- double-framing is what the first version of this test
    // did, and the plugin's own `abi_payload_not_json` refusal is how it was found.
    let healthy_probe = serde_json::to_vec(&frame::Request {
        abi: frame::abi_version(),
        id: "probe".to_string(),
        op: "echo".to_string(),
        payload: serde_json::json!({ "healthy": true }),
    })
    .expect("the probe encodes");

    // 1. A healthy replacement takes over.
    let (second, record) = host
        .swap(
            &first,
            &ProcessRuntime::new(),
            &spec,
            "2.0.0",
            &healthy_probe,
        )
        .expect("a healthy replacement swaps in");
    assert_eq!(record.to_version, "2.0.0", "{record:?}");
    assert!(
        record.generation > 0,
        "a swap must take a new generation, or two versions are indistinguishable: {record:?}"
    );
    assert_eq!(
        host.version_of(frame::ECHO_PLUGIN).as_deref(),
        Some("2.0.0")
    );
    assert_eq!(
        host.generation_of(frame::ECHO_PLUGIN),
        Some(record.generation)
    );
    assert_eq!(
        host.swap_history().len(),
        1,
        "a swap that cannot be audited is indistinguishable from a restart"
    );

    // The replacement answers, so the caller was handed a working instance rather than a
    // handle to something already drained.
    let answered = call(
        &host,
        &second,
        "echo",
        serde_json::json!({ "swapped": true }),
    );
    assert!(answered.ok, "{answered:?}");

    // 2. A replacement that **refuses** its health probe must not take traffic, and the
    //    version currently serving must not change.
    let refusing_probe = serde_json::to_vec(&frame::Request {
        abi: frame::abi_version(),
        id: "probe".to_string(),
        // The echo plugin refuses an op it does not implement.
        op: "definitely-not-an-op".to_string(),
        payload: serde_json::json!({}),
    })
    .expect("the probe encodes");
    let failed = host.swap(
        &second,
        &ProcessRuntime::new(),
        &spec,
        "3.0.0",
        &refusing_probe,
    );
    assert!(
        failed.is_err(),
        "a replacement that refuses the health probe must fail the swap, not serve"
    );
    assert_eq!(
        host.version_of(frame::ECHO_PLUGIN).as_deref(),
        Some("2.0.0"),
        "a failed swap must leave the running version serving"
    );
    assert_eq!(
        host.swap_history().len(),
        1,
        "a failed swap must not be recorded as one"
    );

    // And the version that kept serving still answers.
    let still = call(&host, &second, "echo", serde_json::json!({ "still": true }));
    assert!(still.ok, "{still:?}");

    host.stop(&second).expect("the sandbox is destroyed");
    let _ = std::fs::remove_dir_all(&root);
}

/// The two new **official** plugins, started and called through the host.
///
/// # The half their author could not prove, for the third time
///
/// Both were verified against the real executables, including answers compared field by
/// field with the crates called directly in another process (`MISMATCHES=0`). Running under
/// `ProcessPluginHost`, in a sandbox, is a different claim, and their author said so rather
/// than implying it. Three rounds of that pattern is why this is a routine rather than a
/// favour.
///
/// One test over both, because the claim is the same for both and one table is easier to
/// keep honest than two near-identical bodies.
#[cfg(windows)]
#[test]
fn the_official_mcp_and_scheduler_plugins_run_in_a_sandbox_and_answer_through_the_host() {
    for (name, binary, op) in [
        (
            "com.twinsearth.official.mcp",
            "nau-plugin-mcp",
            "initialize",
        ),
        (
            "com.twinsearth.official.scheduler",
            "nau-plugin-scheduler",
            "validate",
        ),
        // Third entry in the table, and the reason the table exists: the claim is the same
        // for each of these, and one body is easier to keep honest than three near-identical
        // ones.
        (
            "com.twinsearth.official.agent",
            "nau-plugin-agent",
            "validate",
        ),
        // The two business-enabled plugins adopted from `agent-universe` v3.5.0. Their author
        // tested both against the real executables and reported, as every author before him
        // has, that neither had ever run under this host -- so they go in the same table rather
        // than getting a fourth near-identical body.
        //
        // `official.swarm`'s op is `detect`, and the interesting thing to assert is that it
        // runs at all: the op deliberately makes **no** emergence judgement (our crates have no
        // detector, and upstream's criterion takes a caller-supplied threshold), so a test that
        // looked for a verdict would be demanding the plugin invent one.
        (
            "com.twinsearth.official.swarm",
            "nau-plugin-emergence",
            "detect",
        ),
        // Upstream's `official.agent-skill` under our catalogue's short name. Its op answers
        // from a caller-supplied roster, which is what a process plugin can honestly do: it
        // cannot read the market, and the market is where the real skill index lives.
        ("com.twinsearth.official.skill", "nau-plugin-skill", "match"),
        // Upstream's `official.chain-anchor`, whose rules are ported from this repository's own
        // `contracts/src/AgentCardAnchor.sol`. Its `anchor` op takes a caller-supplied set of
        // existing anchors, which is what a process plugin can honestly do with no chain client.
        (
            "com.twinsearth.official.chain-anchor",
            "nau-plugin-chain-anchor",
            "anchor",
        ),
        // `official.bridge` commits a set of reputation snapshots and verifies inclusion in it,
        // offline. It is the plugin that made "no Rust chain client" stop being a blocker: the
        // bridge's semantics never needed one.
        (
            "com.twinsearth.official.bridge",
            "nau-plugin-bridge",
            "commit",
        ),
    ] {
        let root = scratch(&format!("official-{binary}"));
        let host = ProcessPluginHost::open(&root, 1_750_000_000).expect("the host opens");
        let entry = built_binary(binary);
        assert!(
            entry.exists(),
            "the {binary} binary must have been built for this test: {}",
            entry.display()
        );

        let start = StartSpec {
            plugin: PluginId::parse(name).expect("a valid plugin name"),
            tier: Tier::Official,
            entry,
            limits: limits(),
            waivers: full_waivers(),
        };
        let plugin = host
            .start(&ProcessRuntime::new(), &start)
            .unwrap_or_else(|e| panic!("`{name}` should start in a real sandbox: {e}"));

        let answer = call(&host, &plugin, "capabilities", serde_json::json!({}));
        assert!(answer.ok, "{name}: {answer:?}");
        assert_eq!(answer.plugin, name);
        let payload = answer
            .payload
            .unwrap_or_else(|| panic!("{name}: no payload"));

        assert_eq!(
            payload["tier"],
            serde_json::json!("official"),
            "{name}: {payload}"
        );
        let ops = payload["implemented_ops"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: implemented_ops must be an array"));
        assert!(
            ops.iter().any(|listed| listed == op),
            "{name} must report its own op `{op}`: {payload}"
        );

        // The op answers with an empty payload -- as a refusal or a result, whichever the
        // plugin's own validation decides. What is asserted is that the host gets an answer
        // at all rather than a hang, because that is the boundary's job and not the
        // plugin's.
        let answer = call(&host, &plugin, op, serde_json::json!({}));
        assert!(
            answer.code.is_some() || answer.payload.is_some(),
            "{name}: `{op}` with an empty payload must answer or refuse, not neither: {answer:?}"
        );

        let refused = call(&host, &plugin, "not-an-op", serde_json::json!({}));
        assert!(
            !refused.ok,
            "{name}: an unknown op must be refused: {refused:?}"
        );

        host.stop(&plugin).expect("the sandbox is destroyed");
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// One request through the host, decoded.
#[cfg(windows)]
fn call(
    host: &ProcessPluginHost,
    plugin: &nau_node::plugin_process::ProcessPlugin,
    op: &str,
    payload: serde_json::Value,
) -> frame::Response {
    let request = frame::Request {
        abi: frame::abi_version(),
        id: "e2e-1".to_string(),
        op: op.to_string(),
        payload,
    };
    let encoded = serde_json::to_vec(&request).expect("the request encodes");
    let response = host.call(plugin, &encoded).expect("the plugin answers");
    frame::decode_response(&response).expect("the answer is a response frame")
}
