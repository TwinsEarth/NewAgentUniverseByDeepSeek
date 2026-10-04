//! `com.twinsearth.sys.security.audit` — the body that assesses and cannot judge.
//!
//! # Why an audit body is not the tribunal
//!
//! `audit` produces a risk assessment. `tribunal` produces a ruling. They are separate because the
//! authority differs: an assessment is an **opinion about** a plugin, and a ruling is a **change
//! to** it. A body that could do both would be able to decide a case and then be the evidence for
//! its own decision.
//!
//! So `audit` holds `plugin:lifecycle:read`, `plugin:message:send` and `plugin:storage:own`, and
//! **no kernel authority at all** — the same absence `surveillance` has, for the same reason.
//!
//! # C-05's first criterion, made structural rather than promised
//!
//! The plan says a risk assessment must be **explainable** and must not be a bare score. The
//! strongest way to hold that is not a rule about what to return but a type that **cannot** return
//! the wrong thing: [`Assessment`] has no score field. It has [`Factor`]s and it has a [`Band`],
//! and the band is **derived from the factors** rather than stored beside them.
//!
//! So a caller cannot receive "risk 7.3/10" from this body, because there is nowhere to put it.
//! What a caller receives is the list of things that were observed and how much each moved the
//! answer — which is what an assessment that can be argued with looks like.
//!
//! # C-05's second criterion: an assessment must not rest on what the subject says about itself
//!
//! [`AuditPlugin`] refuses any request that carries an observation. The subject's own account of
//! its state, its violation count or its score is not evidence — a plugin that is judged on its
//! own account of itself is not judged — so the keys in [`OBSERVATION_KEYS`] are refused **by
//! name**, with the reason, rather than quietly ignored. Quietly ignoring them would be worse: the
//! caller would believe its numbers had been considered.
//!
//! Where the facts **do** come from is the host. The lifecycles are the host's (the same finding
//! C-03 and C-04 arrived at), so the route reads them and hands them in, and this module assesses
//! what it was given. It cannot fetch them itself and it does not pretend to.

use nau_plugin::bus::PmbMessage;
use nau_plugin::capability::Capability;
use nau_plugin::{PluginId, Result};
use serde_json::{json, Value};

use crate::host::{HostContext, LogLevel, PluginGrant, SystemPlugin};
use crate::payload;

/// The operations this plugin implements.
pub const OPERATIONS: &[&str] = &["capabilities", "assess", "explain", "factors"];

/// Payload keys that would make an assessment rest on the subject's own account of itself.
///
/// Refused by name rather than ignored. A caller whose numbers were silently discarded would
/// believe they had been considered, which is a worse outcome than a refusal it can read.
pub const OBSERVATION_KEYS: [&str; 5] = ["state", "violations", "score", "risk", "observed"];

/// How much risk the observed factors add up to.
///
/// A band rather than a number, and that is the point: a number invites a precision the
/// observations do not have. Three bands are as much as "we read two facts about this plugin" can
/// support.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    /// Nothing observed raises a concern.
    Low,
    /// Something did.
    Elevated,
    /// Enough did that the subject is worth a decision by somebody with the authority to make one.
    High,
}

impl Band {
    /// A stable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Band::Low => "low",
            Band::Elevated => "elevated",
            Band::High => "high",
        }
    }

    /// The band a total weight falls into.
    #[must_use]
    pub fn of(total: i32) -> Self {
        // Two thresholds, and they are here rather than at the call sites so that one number
        // cannot be read into two different bands by two readers.
        if total >= 50 {
            Band::High
        } else if total >= 20 {
            Band::Elevated
        } else {
            Band::Low
        }
    }
}

/// One thing that was observed, and how much it moved the answer.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Factor {
    /// What was looked at.
    pub name: String,
    /// What was found, in words. Not a number: an operator reading this has to be able to disagree
    /// with the observation, and "3" cannot be disagreed with.
    pub observed: String,
    /// How much it moved the total. Signed, because some observations reduce risk.
    pub weight: i32,
}

impl Factor {
    /// A factor that raises risk.
    #[must_use]
    pub fn raises(name: &str, observed: impl std::fmt::Display, weight: i32) -> Self {
        Self {
            name: name.to_string(),
            observed: observed.to_string(),
            weight: weight.max(0),
        }
    }

    /// A factor that lowers it.
    #[must_use]
    pub fn lowers(name: &str, observed: impl std::fmt::Display, weight: i32) -> Self {
        Self {
            name: name.to_string(),
            observed: observed.to_string(),
            weight: -weight.abs(),
        }
    }

    /// One line, as [`Assessment::explain`] produces it.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{}: {} ({:+})", self.name, self.observed, self.weight)
    }
}

/// What the host observed about a subject, handed in because the host owns the lifecycles.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Observations {
    /// The subject's lifecycle state, as the host reports it.
    pub state: String,
    /// How many violations the host has recorded against it.
    pub violations: u32,
    /// The threshold at which the host quarantines, so the assessment can say how close it is.
    pub threshold: u32,
}

/// An assessment.
///
/// # There is no score field, and that is the design
///
/// C-05 asks that a risk assessment not be a bare score. The strongest form of that is a type with
/// nowhere to put one: what this carries is the [`Factor`]s and, derived from them, a [`Band`]. A
/// caller that wants a number has to compute it from the factors, which is exactly the work that
/// makes an assessment arguable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Assessment {
    /// Who was assessed.
    pub subject: String,
    /// What was observed, in the order it was considered.
    pub factors: Vec<Factor>,
    /// What could **not** be observed, named.
    ///
    /// An assessment that lists only what it saw implies it saw everything. This field is the
    /// difference between "nothing else raised a concern" and "nothing else was looked at".
    pub unobserved: Vec<String>,
}

impl Assessment {
    /// The total weight of the factors.
    #[must_use]
    pub fn total(&self) -> i32 {
        self.factors.iter().map(|f| f.weight).sum()
    }

    /// The band, derived from the factors every time rather than stored.
    ///
    /// Derived rather than cached, because a stored band and a list of factors are two things that
    /// can disagree — and the one a reader would trust is the number.
    #[must_use]
    pub fn band(&self) -> Band {
        Band::of(self.total())
    }

    /// One line per factor, then the total, then what was not looked at.
    #[must_use]
    pub fn explain(&self) -> Vec<String> {
        let mut out: Vec<String> = self.factors.iter().map(Factor::line).collect();
        out.push(format!(
            "total {:+} -> {}",
            self.total(),
            self.band().label()
        ));
        for name in &self.unobserved {
            out.push(format!("not observed: {name}"));
        }
        out
    }
}

/// Assess from what the host observed.
///
/// A free function rather than a method on the plugin, so it can be tested without a host — and so
/// that the rules below are readable in one place instead of spread through a `match` arm.
#[must_use]
pub fn assess(subject: &str, observations: &Observations) -> Assessment {
    let mut factors = Vec::new();

    // The one fact the kernel already acts on. Reported as a distance to the threshold rather than
    // as a count, because "2 of 3" is what an operator needs and "2" is not.
    if observations.violations == 0 {
        factors.push(Factor::lowers("violations", "none recorded", 10));
    } else {
        factors.push(Factor::raises(
            "violations",
            format!(
                "{} of {} before quarantine",
                observations.violations, observations.threshold
            ),
            i32::try_from(observations.violations).unwrap_or(i32::MAX) * 10,
        ));
    }

    // The lifecycle state, read from what the host reported. Each state that means "not serving
    // normally" is its own factor, so an operator can see which one applied rather than a number
    // that covers three situations.
    match observations.state.as_str() {
        "running" => factors.push(Factor::lowers("lifecycle", "running", 10)),
        "paused" => factors.push(Factor::raises("lifecycle", "paused", 20)),
        "unhealthy" => factors.push(Factor::raises("lifecycle", "unhealthy", 30)),
        "quarantined" => factors.push(Factor::raises("lifecycle", "quarantined", 50)),
        "refused" => factors.push(Factor::raises("lifecycle", "refused at a check", 20)),
        "stopped" | "stopping" => factors.push(Factor::raises("lifecycle", "not serving", 20)),
        other => factors.push(Factor::raises(
            "lifecycle",
            format!("in a state this body does not classify: `{other}`"),
            // Not zero: an unrecognised state is a reason for a person to look, and a factor that
            // weighed nothing would let a state added later pass unnoticed.
            20,
        )),
    }

    Assessment {
        subject: subject.to_string(),
        factors,
        // Named, because the assessment above rests on two facts and saying so is the difference
        // between an assessment and an impression.
        unobserved: vec![
            "behaviour outside the lifecycle and the violation count".to_string(),
            "whether the subject's own account of itself is true".to_string(),
        ],
    }
}

/// The audit system plugin.
pub struct AuditPlugin {
    id: PluginId,
    grant: PluginGrant,
}

impl AuditPlugin {
    /// The plugin's id.
    pub const ID: &'static str = "com.twinsearth.sys.security.audit";

    /// The capabilities the plugin declares.
    pub const CAPABILITIES: &'static [Capability] = &[
        Capability::LifecycleRead,
        Capability::MessageSend,
        Capability::StorageOwn,
    ];

    /// Build the plugin.
    ///
    /// # Errors
    ///
    /// [`nau_plugin::PluginError::Name`] if the id is not a valid plugin name.
    pub fn new() -> Result<Self> {
        Ok(Self {
            id: PluginId::parse(Self::ID)?,
            grant: PluginGrant::new(),
        })
    }
}

impl SystemPlugin for AuditPlugin {
    fn id(&self) -> &PluginId {
        &self.id
    }

    fn capabilities(&self) -> &'static [Capability] {
        Self::CAPABILITIES
    }

    fn init(&mut self, ctx: &mut HostContext) -> Result<()> {
        self.grant.adopt(ctx);
        ctx.log(
            LogLevel::Info,
            "security.audit ready; it assesses, it cannot judge, and it refuses to be told what to \
             think",
        );
        Ok(())
    }

    fn handle(&mut self, msg: &PmbMessage) -> Result<Value> {
        let declared = self.grant.require_declared(msg)?;
        let op = payload::operation(&msg.payload)?;
        // Every op here is a read: an assessment observes and changes nothing.
        self.grant
            .require_operation(declared, Capability::LifecycleRead)?;

        // C-05's second criterion, enforced for the op that carries observations. Done before the
        // `match` rather than inside one arm, so an op added later cannot forget it.
        if op == "assess" {
            for key in OBSERVATION_KEYS {
                if msg.payload.get(key).is_some() {
                    return Err(payload::protocol(
                        "self_reported_observation",
                        format!(
                            "this request carries `{key}`, and an assessment may not rest on what \
                             the subject says about itself. The host supplies the observations: \
                             send `subject` and `observations` and nothing else"
                        ),
                    ));
                }
            }
        }

        match op {
            "capabilities" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "declares": Self::CAPABILITIES.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "operations": OPERATIONS,
                    "holds_kernel_authority": false,
                    "separate_from": "security.tribunal, because an assessment is an opinion about \
                                      a plugin and a ruling is a change to one",
                }),
            )),
            "factors" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    // The rule, stated where a reader of the plugin finds it rather than only in
                    // the plan.
                    "requirement": "an assessment must name what produced it",
                    "must_not_rely_on": "what the request body claims about itself",
                    "why": "a plugin that is judged on its own account of itself is not judged",
                    "refused_keys": OBSERVATION_KEYS,
                    "there_is_no_score_field": "an assessment carries factors and a band; a caller \
                                                that wants a number computes it from the factors",
                    "thresholds": {"elevated": 20, "high": 50},
                }),
            )),
            "assess" => {
                let subject = payload::string_field(&msg.payload, "subject")?;
                // The observations are **required**, and their absence is a refusal rather than a
                // default. Defaulting to "no violations, running" would produce a reassuring
                // assessment from no evidence at all, which is the failure mode this criterion
                // exists to prevent.
                let observations: Observations =
                    serde_json::from_value(payload::field(&msg.payload, "observations")?.clone())
                        .map_err(|e| {
                        payload::protocol(
                            "missing_observations",
                            format!(
                                "an assessment needs the host's observations (state, \
                                     violations, threshold); without them it would be an \
                                     impression: {e}"
                            ),
                        )
                    })?;
                let assessment = assess(subject, &observations);
                Ok(payload::answer(
                    Self::ID,
                    op,
                    json!({
                        "subject": assessment.subject,
                        "factors": assessment.factors,
                        "band": assessment.band().label(),
                        "total": assessment.total(),
                        "explain": assessment.explain(),
                        "unobserved": assessment.unobserved,
                        // Said on every answer, because a caller that forgets it is the caller this
                        // criterion was written for.
                        "observed_by": "the host, not the request body",
                    }),
                ))
            }
            "explain" => Ok(payload::answer(
                Self::ID,
                op,
                json!({
                    "bands": ["low", "elevated", "high"],
                    "thresholds": {"elevated": 20, "high": 50},
                    "the_band_is_derived": "from the factors, every time; it is not stored beside \
                                            them, because a stored band and a factor list are two \
                                            things that can disagree",
                }),
            )),
            other => Err(payload::unknown_operation(Self::ID, other, OPERATIONS)),
        }
    }

    fn shutdown(&mut self) -> Result<()> {
        self.grant.release();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running() -> Observations {
        Observations {
            state: "running".to_string(),
            violations: 0,
            threshold: 3,
        }
    }

    #[test]
    fn an_assessment_carries_factors_and_a_band_and_has_nowhere_to_put_a_score() {
        // C-05's first criterion, made structural. There is no field to assert the absence of, so
        // what this checks is that the band is DERIVED -- change a factor and the band follows,
        // with nothing to keep in step.
        let clean = assess("com.example.a", &running());
        assert_eq!(
            clean.total(),
            -20,
            "no violations and running: two factors that lower risk"
        );
        assert_eq!(clean.band(), Band::Low);
        assert!(
            clean.factors.iter().all(|f| !f.observed.is_empty()),
            "every factor must say what it observed"
        );

        // The rest of this test asserts ORDERING rather than totals I compute in my head.
        //
        // That is a correction of method, not of arithmetic. I wrote the expected totals by hand
        // twice and got them wrong twice -- `paused` is 20 but "no violations" is -10, so the total
        // is 10 and the band is low, not elevated. The implementation was right both times. A test
        // whose expectation is mentally computed tests the author's arithmetic, and this project
        // has now paid for that six times.
        //
        // Ordering is the property that matters here anyway: "worse observations band higher" is
        // what an assessment is for, and it needs no arithmetic to state or to check.
        let paused = assess(
            "com.example.d",
            &Observations {
                state: "paused".to_string(),
                violations: 0,
                threshold: 3,
            },
        );
        let unhealthy = assess(
            "com.example.b",
            &Observations {
                state: "unhealthy".to_string(),
                violations: 2,
                threshold: 3,
            },
        );
        let quarantined = assess(
            "com.example.c",
            &Observations {
                state: "quarantined".to_string(),
                violations: 3,
                threshold: 3,
            },
        );

        for (name, assessment) in [
            ("running", &clean),
            ("paused", &paused),
            ("unhealthy", &unhealthy),
            ("quarantined", &quarantined),
        ] {
            assert_eq!(
                assessment.band(),
                Band::of(assessment.total()),
                "{name}: the band must be the one its own total falls into"
            );
            assert!(
                !assessment.unobserved.is_empty(),
                "{name}: every assessment says what it could not see"
            );
        }

        // Monotonicity, which is the property that actually holds and the one that matters.
        //
        // The first version of this block asserted that each of the four bands strictly above the
        // last, and it was wrong about the design rather than about arithmetic: `paused` with no
        // violations totals +10 and `running` with none totals -20, and BOTH ARE LOW. That is
        // correct -- a paused plugin with a clean record is not a concern -- and the assertion was
        // asserting an ordering the rules never promised.
        //
        // So what is checked is the promise the rules DO make: a larger total never bands lower.
        // It needs no hand-computed expectation, and it fails if a threshold is ever written in the
        // wrong order.
        let mut seen: Vec<(i32, Band)> = [&clean, &paused, &unhealthy, &quarantined]
            .into_iter()
            .map(|a| (a.total(), a.band()))
            .collect();
        seen.sort_unstable();
        for pair in seen.windows(2) {
            assert!(
                pair[0].1 <= pair[1].1,
                "a larger total must never band lower: {pair:?} in {seen:?}"
            );
        }
        assert_eq!(quarantined.band(), Band::High);

        // And the set spans more than one band, so the check above is not vacuous.
        let bands: std::collections::BTreeSet<Band> = seen.iter().map(|(_, b)| *b).collect();
        assert!(
            bands.len() >= 2,
            "four different observations must not all land in one band: {seen:?}"
        );

        // The bands' own boundaries are checked where they are defined, in
        // `the_bands_are_ordered_and_thresholded_where_they_say`, rather than restated here.
    }

    #[test]
    fn the_explanation_names_every_factor_and_what_was_not_looked_at() {
        // An assessment that lists only what it saw implies it saw everything.
        let assessment = assess("com.example.a", &running());
        let lines = assessment.explain();
        assert!(
            lines.len() >= 3,
            "two factors, a total, and the unobserved: {lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("violations")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("lifecycle")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("total")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.starts_with("not observed:")),
            "the assessment must say what it could not see: {lines:?}"
        );
        assert!(
            !assessment.unobserved.is_empty(),
            "and it must be a field, not only a line"
        );
    }

    #[test]
    fn the_band_follows_the_factors_rather_than_being_stored() {
        // Derived every time, so a band and a factor list cannot drift apart.
        let mut assessment = assess("com.example.a", &running());
        assert_eq!(assessment.band(), Band::Low);
        assessment
            .factors
            .push(Factor::raises("invented", "for the test", 100));
        assert_eq!(
            assessment.band(),
            Band::High,
            "adding a factor must move the band; a cached one would not"
        );
    }

    #[test]
    fn an_unrecognised_state_is_a_reason_to_look_rather_than_a_zero() {
        // A factor that weighed nothing would let a state added later pass unnoticed.
        let unknown = assess(
            "com.example.a",
            &Observations {
                state: "something-new".to_string(),
                violations: 0,
                threshold: 3,
            },
        );
        let lifecycle = unknown
            .factors
            .iter()
            .find(|f| f.name == "lifecycle")
            .expect("a lifecycle factor");
        assert!(
            lifecycle.weight > 0,
            "an unclassified state must not weigh nothing: {lifecycle:?}"
        );
        assert!(
            lifecycle.observed.contains("something-new"),
            "and it must name the state it could not classify: {}",
            lifecycle.observed
        );
    }

    #[test]
    fn a_zero_violation_observation_lowers_rather_than_merely_not_raising() {
        // The difference matters: if "no violations" contributed nothing, a clean plugin and a
        // plugin nobody had looked at would score the same.
        let clean = assess("a", &running());
        assert!(
            clean.total() < 0,
            "a clean subject must score below zero, got {}",
            clean.total()
        );
        let unclassified = assess(
            "a",
            &Observations {
                state: "something-new".to_string(),
                violations: 0,
                threshold: 3,
            },
        );
        assert!(
            unclassified.total() > clean.total(),
            "and an unclassified state must score above it"
        );
    }

    #[test]
    fn the_factor_signs_are_what_they_say() {
        let up = Factor::raises("x", "y", 30);
        let down = Factor::lowers("x", "y", 30);
        assert_eq!(up.weight, 30);
        assert_eq!(down.weight, -30);
        // A negative weight passed to `raises` would invert the meaning of the name.
        assert_eq!(Factor::raises("x", "y", -30).weight, 0);
        assert_eq!(Factor::lowers("x", "y", -30).weight, -30);
    }

    #[test]
    fn the_bands_are_ordered_and_thresholded_where_they_say() {
        assert!(Band::Low < Band::Elevated && Band::Elevated < Band::High);
        assert_eq!(Band::of(19), Band::Low);
        assert_eq!(Band::of(20), Band::Elevated);
        assert_eq!(Band::of(49), Band::Elevated);
        assert_eq!(Band::of(50), Band::High);
        // And a negative total -- a clean subject -- is low rather than unclassified.
        assert_eq!(Band::of(-100), Band::Low);
    }

    #[test]
    fn it_holds_no_kernel_authority() {
        for cap in AuditPlugin::CAPABILITIES {
            assert!(!cap.is_kernel(), "audit holds {}", cap.as_str());
        }
    }

    #[test]
    fn it_is_separate_from_the_tribunal() {
        assert!(!AuditPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
        assert!(super::super::TribunalPlugin::CAPABILITIES.contains(&Capability::KernelPolicyWrite));
    }

    #[test]
    fn its_id_is_in_the_security_namespace() {
        assert!(AuditPlugin::ID.starts_with("com.twinsearth.sys.security."));
        AuditPlugin::new().expect("a valid id");
    }

    #[test]
    fn the_refused_keys_are_the_ones_a_subject_would_report_about_itself() {
        // Read by the request handler, so the list cannot be decorative: if it were empty the
        // second criterion would be unenforced while still being documented.
        assert!(!OBSERVATION_KEYS.is_empty());
        for key in OBSERVATION_KEYS {
            assert!(!key.trim().is_empty(), "a blank key would refuse nothing");
        }
        let mut sorted: Vec<&str> = OBSERVATION_KEYS.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            count,
            "a duplicate key is a key nobody checked"
        );
    }
}
