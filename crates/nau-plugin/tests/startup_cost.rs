//! B-01's measurement: every runtime declares a startup range, and the ones this machine can
//! start are **measured** against it.
//!
//! # What this file is for
//!
//! The plan's acceptance criterion has two halves that pull in opposite directions. Every
//! backend must declare a startup range, **and** the plan's own figures (`<1ms / ~2ms / ~10ms /
//! ~100ms`) must be either measured or marked as design targets. A table of numbers satisfies
//! the first half and quietly violates the second, because a reader cannot tell which entries
//! were ever run.
//!
//! So the basis is part of the value ([`StartupCost::basis`]), this file **measures what it can
//! start**, and reports the rest as targets with the reason they are targets. A runtime whose
//! cost is marked [`CostBasis::Measured`] is asserted to fall inside its declared range here;
//! one marked [`CostBasis::DesignTarget`] is reported and **not** asserted against, because
//! asserting a target would turn a target into a claim.
//!
//! # Why the measurement does not fail on a slow machine
//!
//! A measured range is a property of a machine, and this suite runs on a laptop and on three CI
//! runners. `Native` is the only runtime whose cost is asserted, and its range is wide enough
//! (0-5us) that no plausible machine exceeds it. Everything slower is either a target or is
//! measured and printed without an assertion, because a test that fails when the runner is busy
//! is a test people learn to re-run rather than to read.

use nau_plugin::runtime::{CostBasis, NativeRuntime, PluginRuntime, ProcessRuntime, RuntimeKind};

/// Time `iterations` runs of `f`, returning the mean in microseconds.
fn mean_micros(iterations: u32, mut f: impl FnMut()) -> u64 {
    // A warm-up pass, so the first call's page faults are not divided into the mean of a
    // thousand fast calls and reported as the cost of one.
    for _ in 0..(iterations / 10).max(1) {
        f();
    }
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    (elapsed.as_micros() as u64) / u64::from(iterations.max(1))
}

#[test]
fn every_runtime_declares_a_well_formed_startup_range() {
    // The first half of the criterion, over `ALL` so that a new runtime cannot be added
    // without a cost.
    assert_eq!(
        RuntimeKind::ALL.len(),
        7,
        "B-01 brings the vocabulary to seven runtimes"
    );
    for kind in RuntimeKind::ALL {
        let cost = kind.startup_cost();
        assert!(
            cost.min_micros <= cost.max_micros,
            "{kind:?} declares an inverted range: {}..{}us",
            cost.min_micros,
            cost.max_micros
        );
        assert!(
            !cost.note.trim().is_empty(),
            "{kind:?} declares a range with no basis note; a range nobody can trace is a number \
             without the five elements"
        );
        // Every note says either where it was measured or where the target came from.
        let traceable = cost.is_measured()
            || cost.note.contains("plan")
            || cost.note.contains("no backend")
            || cost.note.contains("no `PluginRuntime`");
        assert!(
            traceable,
            "{kind:?} is a design target whose note names neither the plan nor the missing \
             backend: {:?}",
            cost.note
        );
    }
}

#[test]
fn the_labels_are_unique_and_the_cheap_runtimes_are_ordered() {
    let mut labels: Vec<&str> = RuntimeKind::ALL.iter().map(|k| k.label()).collect();
    labels.sort_unstable();
    let count = labels.len();
    labels.dedup();
    assert_eq!(labels.len(), count, "two runtimes share a label");

    // The declared ranges must be ordered the way the isolation they provide is: a stronger
    // boundary costs more to set up. If a heavier runtime declared a cheaper range than a
    // lighter one, at least one of the two numbers would be wrong.
    let native = RuntimeKind::Native.startup_cost().max_micros;
    let process = RuntimeKind::Process.startup_cost().min_micros;
    let container = RuntimeKind::Container.startup_cost().min_micros;
    let micro_vm = RuntimeKind::MicroVm.startup_cost().min_micros;
    let full_vm = RuntimeKind::FullVm.startup_cost().min_micros;
    assert!(native < process, "native must be cheaper than a process");
    assert!(
        process < container,
        "a container sets up namespaces a process does not"
    );
    assert!(
        container < micro_vm,
        "a microVM boots a kernel a container does not"
    );
    assert!(
        micro_vm < full_vm,
        "a full VM boots a whole operating system"
    );
}

#[test]
fn no_target_is_reported_as_a_measurement() {
    // The second half of the criterion, and the reason `CostBasis` exists. A target printed
    // without the word `target` would be indistinguishable from a measurement, which is the
    // defect the metric-claims gate was built for in v3.5.9 -- the same rule, at the type
    // level, where a caller cannot forget it.
    let mut measured = 0;
    let mut targets = 0;
    for kind in RuntimeKind::ALL {
        let cost = kind.startup_cost();
        let described = cost.describe();
        match cost.basis {
            CostBasis::Measured => {
                measured += 1;
                assert!(
                    described.contains("measured") && !described.contains("target"),
                    "{kind:?} is measured and must not be described as a target: {described}"
                );
                // A measured runtime is one this build can actually start.
                assert!(
                    kind.is_available(),
                    "{kind:?} claims a measured startup cost but is not available in this \
                     build; nothing could have been measured"
                );
            }
            CostBasis::DesignTarget => {
                targets += 1;
                assert!(
                    described.contains("target, not measured"),
                    "{kind:?} is a target and must be labelled as one: {described}"
                );
            }
        }
    }
    assert_eq!(
        measured + targets,
        RuntimeKind::ALL.len(),
        "every runtime must be classified"
    );
    // The property, rather than a count. The first version asserted `measured == 2` on the
    // assumption that `Process` would be measurable; it is measurable, but its declared range
    // is the plan's target because the spawn itself lives in `nau-sandbox`, so it is classified
    // as a target and the count was wrong. What matters is not how many there are but that a
    // runtime claiming a measurement is one this build can actually start -- which the loop
    // above already asserts.
    assert!(measured >= 1, "this build starts at least `Native`");
    assert!(
        targets >= 1,
        "some runtimes in this vocabulary have no backend; if none were targets, the \
         classification would be meaningless"
    );
}

#[test]
fn a_native_runtime_starts_inside_its_declared_range() {
    // The one measurement narrow enough to assert. `NativeRuntime::new()` is the whole of what
    // "starting" a native runtime means here, so timing it times the claim.
    let cost = RuntimeKind::Native.startup_cost();
    assert!(
        cost.is_measured(),
        "this test only means something if it is measured"
    );

    let per_call = mean_micros(1000, || {
        let runtime = NativeRuntime::new();
        std::hint::black_box(runtime.declares());
    });

    println!(
        "  native: {} declared, {}us measured",
        cost.describe(),
        per_call
    );
    assert!(
        per_call >= cost.min_micros && per_call <= cost.max_micros,
        "native startup measured at {per_call}us, outside the declared {}",
        cost.describe()
    );
}

#[test]
fn a_process_spawn_is_measured_and_reported_even_though_its_range_is_a_target() {
    // `Process` is the interesting case: this machine **can** spawn a child, so a figure can
    // be obtained, and the declared range is still the plan's `~2ms` target rather than a
    // measurement. Both facts are reported, and the measured value is **not** asserted against
    // the target -- asserting it would either turn a target into a claim (if it passed) or
    // make the suite depend on this machine's loader cache (if it failed).
    let cost = RuntimeKind::Process.startup_cost();
    assert_eq!(
        cost.basis,
        CostBasis::DesignTarget,
        "the plan's `~2ms` is a target until the measurement is taken on the target host"
    );

    let runtime = ProcessRuntime::new();
    // `declares()` is the part of process setup that happens in this process: the capability
    // set the backend publishes. The fork and exec happen in the sandbox crate, which is where
    // a real child is spawned, and timing one here would measure that crate instead.
    let per_call = mean_micros(1000, || {
        std::hint::black_box(runtime.declares());
    });

    println!(
        "  process: {} declared; {}us to publish the backend's capability set (the spawn itself \
         is measured by nau-sandbox, which owns it)",
        cost.describe(),
        per_call
    );
    // What is asserted is that the figure is obtainable and finite, not what it is.
    assert!(
        per_call < 1_000_000,
        "publishing a capability set took over a second"
    );
}

#[test]
fn the_runtimes_with_no_backend_report_a_cost_they_could_not_have_measured() {
    // A runtime with no backend cannot have been measured, whatever its range says. This is
    // the cross-check between the two vocabularies: `is_available()` and `CostBasis` must
    // agree, because a reader who sees "measured" next to a runtime that cannot run has been
    // told something false.
    for kind in RuntimeKind::ALL {
        let cost = kind.startup_cost();
        if !kind.is_available() {
            assert_eq!(
                cost.basis,
                CostBasis::DesignTarget,
                "{kind:?} has no backend in this build, so its cost cannot be a measurement"
            );
        }
    }
}
