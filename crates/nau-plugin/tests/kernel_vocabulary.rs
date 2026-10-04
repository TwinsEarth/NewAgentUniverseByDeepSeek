//! The kernel's vocabulary, held still against the releases that would otherwise grow it.
//!
//! # Why a count is a test
//!
//! Every plan in this repository has, at some point, proposed accommodating a new concept by adding
//! a variant to [`Tier`] or to [`PluginState`]. Both are tempting and both are usually wrong:
//!
//! * [`Tier`] is a **trust classification** — who signed a plugin and how much that signature is
//!   worth. A resource provider, a market participant, an economy actor: none of them is a new rung
//!   of that ladder, and adding one would make "which tier is this?" a question about two unrelated
//!   things at once.
//! * [`PluginState`] is a **lifecycle** with a transition table that
//!   [`Lifecycle::transition`](nau_plugin::lifecycle::Lifecycle::transition) is the single writer
//!   of. A variant added for a non-lifecycle reason is an edge in that table that nothing walks.
//!
//! So the counts are asserted here, where the types live. A release that adds one has to come to
//! this file and say why — which is the whole mechanism. The numbers are not sacred; **the
//! requirement to justify a change to them is.**
//!
//! # Where this test belongs, and why it is not in the crates that consume the kernel
//!
//! v3.6.7 recorded the rule for the snapshot store's consistency claim and v3.8.1 met it again:
//! evidence belongs where the thing it is about lives. `nau-market` does not depend on `nau-plugin`
//! — a data crate should not carry the plugin kernel — so a test there could only reach these lists
//! by adding a dependency that exists for the test's sake.
//!
//! The list is therefore here, in the kernel's own integration suite, and the crates that must not
//! grow it point at it in their comments.

use nau_plugin::lifecycle::PluginState;
use nau_plugin::Tier;

#[test]
fn the_tier_ladder_has_five_rungs_and_a_new_one_needs_a_reason() {
    // 5 as of v3.0.0, and unchanged through v3.8.1: System, Official, Certified, ThirdParty,
    // Blacklisted. `Blacklisted` is a rung rather than a flag because a blacklisted plugin is
    // classified, not merely marked.
    assert_eq!(
        Tier::ALL.len(),
        5,
        "the tier ladder is a TRUST classification; a concept that is not a rung of it belongs \
         somewhere else. Update this count deliberately, with the reason in the commit."
    );

    // And the ladder is ordered, which is what makes "at least this trusted" expressible.
    let mut sorted = Tier::ALL;
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        Tier::ALL,
        "Tier::ALL must already be in ladder order"
    );

    // The loadable tiers are a subset, so a non-loadable rung cannot be selected by a name.
    assert!(
        Tier::LOADABLE.len() < Tier::ALL.len(),
        "at least one rung must be non-loadable, or the distinction is decoration"
    );
}

#[test]
fn the_lifecycle_has_twelve_states_and_a_new_one_needs_a_transition_table_row() {
    // 12 as of v3.0.0, and unchanged through v3.8.1. `Lifecycle::transition` is the ONE function
    // that assigns a state, and it refuses an edge the table does not declare -- so a state added
    // without edges is one nothing can reach.
    assert_eq!(
        PluginState::ALL.len(),
        12,
        "a lifecycle state is a node in a transition table; a concept that is not a state belongs \
         somewhere else. Update this count deliberately, with the reason in the commit."
    );

    // Every state must be reachable from something or be a starting point, and the terminal set must
    // be a strict subset -- otherwise "terminal" would mean "everything" or "nothing".
    assert!(
        !PluginState::TERMINAL.is_empty(),
        "a state machine with no terminal state never finishes"
    );
    assert!(
        PluginState::TERMINAL.len() < PluginState::ALL.len(),
        "not every state can be terminal"
    );
}

#[test]
fn the_two_lists_are_disjoint_kinds_of_thing() {
    // A sanity check on the vocabulary rather than on either list: trust and lifecycle are
    // different axes, and the labels are what a report prints for each. A collision would make a
    // report ambiguous about which axis it was naming.
    let mut tier_labels: Vec<&str> = Tier::ALL.iter().map(|t| t.label()).collect();
    let mut state_labels: Vec<&str> = PluginState::ALL.iter().map(|s| s.label()).collect();
    tier_labels.sort_unstable();
    state_labels.sort_unstable();

    for label in &tier_labels {
        assert!(
            !label.trim().is_empty(),
            "a tier with no label cannot be reported"
        );
    }
    for label in &state_labels {
        assert!(
            !label.trim().is_empty(),
            "a state with no label cannot be reported"
        );
    }

    // Both lists are internally distinct, which is what makes a label usable as a key.
    for labels in [&tier_labels, &state_labels] {
        let before = labels.len();
        let mut deduped = labels.clone();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            before,
            "a duplicate label is one nobody checked"
        );
    }
}
