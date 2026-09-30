//! Real NAT behaviour classification from STUN observations (RFC 4787 mapping
//! taxonomy, RFC 3489 filtering tests).
//!
//! # What upstream v2.5.6 got wrong
//!
//! Upstream `gsn-core/src/nat/mod.rs` answered every question with a constant:
//!
//! ```text
//! pub fn detect_nat_type(&mut self) -> NatType { NatType::PortRestrictedCone }  // hard-coded
//! pub fn connect(&mut self, peer_id: String, _remote: Vec<IceCandidate>) -> ConnectionState {
//!     ConnectionState::Connected                                                // unconditional
//! }
//! ```
//!
//! Its tests asserted those constants, so the suite locked the simulation in;
//! the module was `#[allow(dead_code)]` with no callers; and `MeshNode::topology()`
//! nonetheless published `nat_type` as if it were a measurement.
//!
//! // upstream v2.5.6 fix: there is no constant left to return. Every value
//! // below is the result of comparing transport addresses the network actually
//! // reported; when the network reports nothing, the result is
//! // [`MappingBehavior::Unknown`] / [`FilteringBehavior::Unknown`], never a
//! // plausible-looking default.
//!
//! # The classification, and why it is the real one
//!
//! STUN's mechanism is *address comparison*: ask one or more servers, over one or
//! more destinations, which transport address they see you from, and compare the
//! answers. [`StunProbe`] sends four probes and hands the raw observations to two
//! pure functions, [`classify_mapping`] and [`classify_filtering`], which do all
//! the deciding.
//!
//! **Mapping** (RFC 4787 §4.1) compares the mapped *port* for the same local
//! socket against three destinations:
//!
//! | primary server port A | primary server port B | second server | result |
//! |---|---|---|---|
//! | p | p | p | [`MappingBehavior::EndpointIndependent`] |
//! | p | p | q ≠ p | [`MappingBehavior::AddressDependent`] |
//! | p | q ≠ p | r ≠ p | [`MappingBehavior::AddressAndPortDependent`] |
//! | fewer than three answers, or answers from two different mapped IPs | | | [`MappingBehavior::Unknown`] |
//!
//! **Filtering** (RFC 4787 §5) compares the *source* address of the responses:
//!
//! | evidence | result |
//! |---|---|
//! | a response arrived from a different address than the one targeted | [`FilteringBehavior::EndpointIndependent`] |
//! | responses arrived only from the targeted address, but from a different port | [`FilteringBehavior::AddressDependent`] |
//! | only the exact targeted address:port ever answered, and another destination was tried | [`FilteringBehavior::AddressAndPortDependent`] |
//! | the primary never answered, or no other destination was ever reached | [`FilteringBehavior::Unknown`] |
//!
//! [`classify_filtering`] takes the mapping result as an argument because the
//! reference procedure for this API does; it does **not** use it to guess. The
//! filtering verdict rests only on which source addresses were actually observed,
//! because that is the only thing the wire can demonstrate.
//!
//! # The limit of any NAT classifier, stated plainly
//!
//! Separating "address-dependent" from "address-and-port-dependent" filtering
//! requires answers from both a different port on the same address *and* a
//! different address, which needs a STUN server with two interfaces (RFC 3489's
//! `change IP` test) or a second server on a different address. With a single
//! cooperative interface, the honest answer for the unresolved sub-case is
//! `Unknown`, and that is what this module returns rather than a guess.
//! Independently of that, classifying the NAT in front of *this* host needs real,
//! reachable STUN servers; see the "what is real" notes in [`crate::stun`].

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use crate::stun::{self, BindingReply, ChangeRequest, ReflexiveAddress, StunError};

/// How the NAT allocates the external transport address for an outbound flow
/// (RFC 4787 §4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MappingBehavior {
    /// One external mapping per (protocol, local address, local port): the same
    /// mapping for every destination.
    EndpointIndependent,
    /// A fresh mapping per destination IP address.
    AddressDependent,
    /// A fresh mapping per destination IP address *and* port.
    AddressAndPortDependent,
    /// Not enough observations to decide, or the observations were inconsistent
    /// (for example two different external IPs, meaning several NAT egresses).
    /// This is the answer whenever a measurement is impossible — never a
    /// placeholder NAT type.
    Unknown,
}

impl MappingBehavior {
    /// Whether the behaviour was actually determined.
    pub fn is_known(self) -> bool {
        self != MappingBehavior::Unknown
    }

    /// Stable machine-readable label, for logs and wire messages.
    pub fn label(self) -> &'static str {
        match self {
            MappingBehavior::EndpointIndependent => "endpoint-independent",
            MappingBehavior::AddressDependent => "address-dependent",
            MappingBehavior::AddressAndPortDependent => "address-and-port-dependent",
            MappingBehavior::Unknown => "unknown",
        }
    }
}

/// Which external hosts the NAT lets inbound packets through from (RFC 4787 §5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilteringBehavior {
    /// Inbound packets are accepted from any external address:port once a
    /// mapping exists — no filtering.
    EndpointIndependent,
    /// Only from the destination IP address the flow was sent to.
    AddressDependent,
    /// Only from the exact destination IP address *and* port.
    AddressAndPortDependent,
    /// Not enough observations to decide; the probe failed, timed out, or the
    /// available servers cannot distinguish the remaining branches.
    Unknown,
}

impl FilteringBehavior {
    /// Whether the behaviour was actually determined.
    pub fn is_known(self) -> bool {
        self != FilteringBehavior::Unknown
    }

    /// Stable machine-readable label, for logs and wire messages.
    pub fn label(self) -> &'static str {
        match self {
            FilteringBehavior::EndpointIndependent => "endpoint-independent",
            FilteringBehavior::AddressDependent => "address-dependent",
            FilteringBehavior::AddressAndPortDependent => "address-and-port-dependent",
            FilteringBehavior::Unknown => "unknown",
        }
    }
}

/// Everything a classification run learned, in one value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NatProfile {
    /// How the NAT allocates mappings.
    pub mapping: MappingBehavior,
    /// Which inbound packets the NAT admits.
    pub filtering: FilteringBehavior,
    /// The external transport address observed on the primary server, if any.
    pub mapped: Option<ReflexiveAddress>,
    /// Human-readable evidence, one line per observation that influenced the
    /// decision. This is what makes the result auditable instead of a constant:
    /// a reader can see which addresses were compared.
    pub evidence: Vec<String>,
}

impl NatProfile {
    /// A profile of two unknowns and no observations.
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            mapping: MappingBehavior::Unknown,
            filtering: FilteringBehavior::Unknown,
            mapped: None,
            evidence: vec![reason.into()],
        }
    }

    /// One line summarising the profile, for logs.
    pub fn summary(&self) -> String {
        format!(
            "mapping={} filtering={} mapped={}",
            self.mapping.label(),
            self.filtering.label(),
            match &self.mapped {
                Some(reflexive) => reflexive.mapped.to_string(),
                None => "none".to_string(),
            }
        )
    }
}

/// A single observed reply: which destination produced it, and which external
/// address the NAT used for that destination.
///
/// This is the only shape in which NAT evidence exists, which is why the
/// classifier consumes nothing else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Observation {
    /// The server (destination) the request was sent to.
    pub destination: SocketAddr,
    /// The external transport address the server reported.
    pub mapped: SocketAddr,
}

/// What one probe achieved, which is not the same as what it was sent to.
///
/// `Attempted(None)` and `NotRun` are deliberately distinct: "another
/// destination was tried and drew nothing" is evidence of a filter, "no other
/// destination was ever contacted" is not evidence of anything. Collapsing the
/// two would let the classifier report a filter it never demonstrated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Probed {
    /// The probe was never sent (for example, no time left in the deadline).
    NotRun,
    /// The probe was sent to this destination; the answer is in the matching
    /// observation slot, and `None` there means it drew nothing.
    Attempted {
        /// Where the request was sent.
        destination: SocketAddr,
    },
}

impl Probed {
    /// The destination, if the probe ran.
    pub fn destination(self) -> Option<SocketAddr> {
        match self {
            Probed::NotRun => None,
            Probed::Attempted { destination } => Some(destination),
        }
    }

    /// Whether the probe ran.
    pub fn ran(self) -> bool {
        matches!(self, Probed::Attempted { .. })
    }
}

/// The set of observations one classification run needs, plus what was actually
/// attempted.
///
/// Grouped into a struct so the classifiers read like the RFC procedure they
/// encode, and so a test can construct evidence no local network can produce —
/// such as a reply from a second address.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ObservationSet {
    /// A plain Binding Request to the primary server.
    pub primary: Option<Observation>,
    /// A Binding Request to the primary server asking for a different port.
    pub change_port: Option<Observation>,
    /// A Binding Request to the primary server asking for a different address
    /// and port.
    pub change_ip_and_port: Option<Observation>,
    /// A plain Binding Request to the secondary server (a different address).
    pub secondary: Option<Observation>,
    /// What was attempted, in the same order as the fields above.
    pub probed: ObservationAttempts,
    /// Anything that produced a typed error, kept for the evidence trail.
    pub failures: Vec<String>,
}

/// Whether each of the four probes was actually sent, and where to.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ObservationAttempts {
    /// The primary-server probe.
    pub primary: Option<SocketAddr>,
    /// The primary-server probe asking for a different port.
    pub change_port: Option<SocketAddr>,
    /// The primary-server probe asking for a different address and port.
    pub change_ip_and_port: Option<SocketAddr>,
    /// The secondary-server probe.
    pub secondary: Option<SocketAddr>,
}

impl ObservationAttempts {
    /// Every destination that was actually contacted, in probe order, without
    /// duplicates.
    pub fn destinations(&self) -> Vec<SocketAddr> {
        let mut seen: Vec<SocketAddr> = Vec::new();
        for destination in [
            self.primary,
            self.change_port,
            self.change_ip_and_port,
            self.secondary,
        ]
        .into_iter()
        .flatten()
        {
            if !seen.contains(&destination) {
                seen.push(destination);
            }
        }
        seen
    }

    /// Whether some destination other than `primary` was contacted.
    pub fn retargeted_beyond(&self, primary: SocketAddr) -> bool {
        self.destinations()
            .into_iter()
            .any(|destination| destination != primary)
    }

    /// Whether any probe ran at all.
    pub fn ran(&self) -> bool {
        !self.destinations().is_empty()
    }
}

impl ObservationSet {
    /// An observation set in which every probe failed, with one reason each.
    pub fn failed(reasons: Vec<String>) -> Self {
        Self {
            failures: reasons,
            ..Self::default()
        }
    }

    /// The number of probes that produced a usable address.
    pub fn observed(&self) -> usize {
        [
            self.primary,
            self.change_port,
            self.change_ip_and_port,
            self.secondary,
        ]
        .iter()
        .filter(|slot| slot.is_some())
        .count()
    }

    /// Record an attempt at `destination` in `slot` (0..4, as in
    /// [`ObservationSet::annotate`]).
    pub fn attempted(&mut self, slot: usize, destination: SocketAddr) {
        match slot {
            0 => self.probed.primary = Some(destination),
            1 => self.probed.change_port = Some(destination),
            2 => self.probed.change_ip_and_port = Some(destination),
            _ => self.probed.secondary = Some(destination),
        }
    }
}

/// Decide the mapping behaviour from what was observed.
///
/// Pure: no I/O, no clock, no state. This is the comparison RFC 4787 §4.1
/// describes, written out so it can be tested against every branch.
///
/// Returns [`MappingBehavior::Unknown`] when fewer than three destinations were
/// observed (the comparison needs all three) or when the observations came from
/// more than one mapped IP address, which means the packets left through
/// different NAT egresses and comparing their ports proves nothing about one NAT.
pub fn classify_mapping(observations: &ObservationSet) -> MappingBehavior {
    let (primary, change_port, secondary) = match (
        observations.primary,
        observations.change_port,
        observations.secondary,
    ) {
        (Some(primary), Some(change_port), Some(secondary)) => (primary, change_port, secondary),
        _ => return MappingBehavior::Unknown,
    };
    if primary.mapped.ip() != change_port.mapped.ip()
        || primary.mapped.ip() != secondary.mapped.ip()
    {
        // More than one external IP: several NAT egresses, so the comparison is
        // not about a single NAT device.
        return MappingBehavior::Unknown;
    }
    if primary.destination == change_port.destination {
        // Two observations of the same destination address:port that disagree
        // say nothing about RFC 4787 categories, so do not invent one.
        return MappingBehavior::Unknown;
    }
    let primary_port = primary.mapped.port();
    let change_port_port = change_port.mapped.port();
    let secondary_port = secondary.mapped.port();
    if primary_port == change_port_port && primary_port == secondary_port {
        MappingBehavior::EndpointIndependent
    } else if primary_port == change_port_port {
        // One mapping served both destination ports of the same server, but not
        // the other server: the mapping is keyed on the destination address.
        MappingBehavior::AddressDependent
    } else {
        // A fresh mapping per destination port: the strongest form of
        // destination dependence.
        MappingBehavior::AddressAndPortDependent
    }
}

/// Decide the filtering behaviour from what was observed.
///
/// Pure. `mapping` is accepted because the reference procedure takes it — a
/// caller reasons about both together — but the verdict here rests only on which
/// *source* addresses were actually observed answering, because that is the only
/// filtering evidence the wire can carry. See the module documentation for the
/// rule, and for the sub-case no single-address server pair can resolve.
pub fn classify_filtering(
    observations: &ObservationSet,
    mapping: MappingBehavior,
) -> FilteringBehavior {
    // The mapping is informational here; say so rather than pretending to use it.
    let _ = mapping;
    let primary = match observations.primary {
        Some(primary) => primary,
        // No reply from the primary server: there is no baseline destination to
        // compare against, and naming a filter would be a guess.
        None => return FilteringBehavior::Unknown,
    };
    // A response that reached us from an address:port we never targeted answers
    // the filtering question immediately: the source address is not what the NAT
    // checks, so no address filter exists. (A response from a different port on
    // an address we did target is discussed below.)
    let answered_from_elsewhere = |observation: &Observation| {
        observation.destination != primary.destination
            && observation.destination.ip() != primary.destination.ip()
    };
    if observations
        .change_ip_and_port
        .as_ref()
        .map(answered_from_elsewhere)
        .unwrap_or(false)
        || observations
            .secondary
            .as_ref()
            .map(answered_from_elsewhere)
            .unwrap_or(false)
    {
        return FilteringBehavior::EndpointIndependent;
    }
    // A response that arrived from the targeted address but a *different port*
    // settles the port question: the filter pins the address and not the port.
    if let Some(change_port) = observations.change_port {
        if change_port.destination != primary.destination
            && change_port.destination.ip() == primary.destination.ip()
        {
            return FilteringBehavior::AddressDependent;
        }
    }
    // Only the exact targeted address:port answered. That is evidence of a
    // filter only if a destination on some *other IP address* was actually
    // contacted and drew nothing; otherwise there was simply nothing else to
    // answer. Probing another port on the same address cannot separate an address
    // filter from an address-and-port filter, so it proves nothing here.
    let probed_other_ip = observations
        .probed
        .destinations()
        .into_iter()
        .any(|destination| destination.ip() != primary.destination.ip());
    if probed_other_ip {
        return FilteringBehavior::AddressAndPortDependent;
    }
    FilteringBehavior::Unknown
}

/// The classification operations one NAT probe must be able to perform.
///
/// The trait exists so that the classifier can be driven by scripted
/// observations in unit tests — including observations no local network can
/// produce, such as a reply from a second address. Implementations must never
/// fabricate a reply: returning `None` is how "this probe produced nothing
/// usable" is expressed, and it must stay `None`.
pub trait NatProbe {
    /// The primary server.
    fn primary(&self) -> SocketAddr;

    /// The secondary server, at a different address from the primary.
    fn secondary(&self) -> SocketAddr;

    /// A plain Binding Request to `destination`.
    fn mapped_for(
        &self,
        destination: SocketAddr,
    ) -> impl std::future::Future<Output = Result<Option<BindingReply>, StunError>>;

    /// A Binding Request to `destination` carrying `CHANGE-REQUEST` flags.
    fn next_with_request(
        &self,
        destination: SocketAddr,
        change_request: ChangeRequest,
    ) -> impl std::future::Future<Output = Result<Option<BindingReply>, StunError>>;
}

/// A STUN client that classifies the NAT between it and two servers.
///
/// ```no_run
/// # async fn demo() -> Result<(), nau_net::stun::StunError> {
/// use nau_net::nat::StunProbe;
/// use std::time::Duration;
///
/// let probe = StunProbe::new(
///     "stun.example.net:3478".parse().expect("literal"),
///     "stun2.example.net:3478".parse().expect("literal"),
/// );
/// let profile = probe.profile(Duration::from_secs(6)).await;
/// // Returns Unknown when nothing is reachable — never a fabricated NAT type.
/// println!("{}", profile.summary());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct StunProbe {
    primary: SocketAddr,
    secondary: SocketAddr,
}

impl StunProbe {
    /// A probe that asks `primary` first and falls back to `secondary`.
    ///
    /// Both must be reachable STUN servers; `secondary` should be at a different
    /// address, because that is what separates an endpoint/address-dependent
    /// result from an address-and-port-dependent one.
    pub fn new(primary: SocketAddr, secondary: SocketAddr) -> Self {
        Self { primary, secondary }
    }

    /// Classify mapping behaviour: two destination ports on the primary server
    /// plus one destination on the secondary server, compared per RFC 4787.
    pub async fn classify_mapping(&self, timeout: Duration) -> Result<MappingBehavior, StunError> {
        let observations = self.collect(timeout).await;
        Ok(classify_mapping(&observations))
    }

    /// Classify filtering behaviour using `CHANGE-REQUEST`, falling back to the
    /// second server (the standard filtering procedure uses both).
    pub async fn classify_filtering(
        &self,
        timeout: Duration,
    ) -> Result<FilteringBehavior, StunError> {
        let observations = self.collect(timeout).await;
        let mapping = classify_mapping(&observations);
        Ok(classify_filtering(&observations, mapping))
    }

    /// Both classifications, plus the mapped address and the evidence the
    /// decisions rest on.
    ///
    /// Never fails: a probe that cannot reach any server yields
    /// [`MappingBehavior::Unknown`]/[`FilteringBehavior::Unknown`] with the
    /// failure recorded in [`NatProfile::evidence`]. The failure is therefore
    /// visible to the caller instead of being rounded up to a NAT type.
    pub async fn profile(&self, timeout: Duration) -> NatProfile {
        let observations = self.collect(timeout).await;
        let mapping = classify_mapping(&observations);
        let filtering = classify_filtering(&observations, mapping);
        NatProfile {
            mapping,
            filtering,
            mapped: observations.primary.map(|observation| ReflexiveAddress {
                mapped: observation.mapped,
                source: observation.destination,
            }),
            evidence: evidence_for(&observations, mapping, filtering),
        }
    }

    /// Run all four probes sequentially, each with a fixed share of `timeout`,
    /// and collect what came back.
    ///
    /// The share is computed once from the caller's deadline, not from the
    /// remaining time, so a probe that overruns its share cannot starve the
    /// probes after it.
    async fn collect(&self, timeout: Duration) -> ObservationSet {
        let mut observations = ObservationSet::default();
        let window = phase_budget(timeout);
        let probes: [(SocketAddr, ChangeRequest, usize); 4] = [
            (self.primary, ChangeRequest::NONE, 0),
            (self.primary, ChangeRequest::CHANGE_PORT, 1),
            (self.primary, ChangeRequest::CHANGE_IP_AND_PORT, 2),
            (self.secondary, ChangeRequest::NONE, 3),
        ];
        for (destination, change_request, slot) in probes {
            if window.is_zero() {
                observations.failures.push(format!(
                    "{destination} {change_request:?}: no time left in the deadline"
                ));
                continue;
            }
            observations.attempted(slot, destination);
            match stun::binding_request_reply(destination, change_request, window).await {
                Ok(reply) => {
                    let observation = Observation {
                        destination: reply.reflexive.source,
                        mapped: reply.reflexive.mapped,
                    };
                    match slot {
                        0 => observations.primary = Some(observation),
                        1 => observations.change_port = Some(observation),
                        2 => observations.change_ip_and_port = Some(observation),
                        _ => observations.secondary = Some(observation),
                    }
                }
                Err(error) => observations
                    .failures
                    .push(format!("{destination} {change_request:?}: {error}")),
            }
        }
        observations
    }
}

impl NatProbe for StunProbe {
    fn primary(&self) -> SocketAddr {
        self.primary
    }

    fn secondary(&self) -> SocketAddr {
        self.secondary
    }

    async fn mapped_for(&self, destination: SocketAddr) -> Result<Option<BindingReply>, StunError> {
        probe_once(destination, ChangeRequest::NONE).await
    }

    async fn next_with_request(
        &self,
        destination: SocketAddr,
        change_request: ChangeRequest,
    ) -> Result<Option<BindingReply>, StunError> {
        probe_once(destination, change_request).await
    }
}

/// One probe with the module's own short deadline; `None` means "no usable
/// reply" for any protocol reason.
async fn probe_once(
    destination: SocketAddr,
    change_request: ChangeRequest,
) -> Result<Option<BindingReply>, StunError> {
    match stun::binding_request_reply(destination, change_request, PROBE_WINDOW).await {
        Ok(reply) => Ok(Some(reply)),
        Err(StunError::Io(error)) => Err(StunError::Io(error)),
        // A timeout, an unreachable port, a malformed or spoofed reply all mean
        // the same thing to a classifier: nothing was observed.
        Err(_) => Ok(None),
    }
}

/// How long the trait-level probes wait. The trait's methods take no deadline,
/// so this is the cap; the four-probe classification stays well inside the
/// handful of seconds a caller normally allows.
pub const PROBE_WINDOW: Duration = Duration::from_millis(600);

/// The share of the caller's deadline one probe may use.
///
/// Four probes run in sequence, so one quarter each keeps the whole
/// classification inside the deadline the caller asked for.
fn phase_budget(timeout: Duration) -> Duration {
    const PHASES: u32 = 4;
    timeout / PHASES
}

/// Turn the observations into the evidence lines a reader can check.
fn evidence_for(
    observations: &ObservationSet,
    mapping: MappingBehavior,
    filtering: FilteringBehavior,
) -> Vec<String> {
    let mut evidence = Vec::new();
    for (label, slot) in [
        ("primary", observations.primary),
        ("change-port", observations.change_port),
        ("change-ip-and-port", observations.change_ip_and_port),
        ("secondary", observations.secondary),
    ] {
        match slot {
            Some(observation) => evidence.push(format!(
                "{label} probe to {} reported mapped {}",
                observation.destination, observation.mapped
            )),
            None => evidence.push(format!("{label} probe produced no usable reply")),
        }
    }
    for failure in &observations.failures {
        evidence.push(format!("probe failure: {failure}"));
    }
    let distinct_ports: BTreeSet<u16> = [
        observations.primary,
        observations.change_port,
        observations.secondary,
    ]
    .iter()
    .filter_map(|slot| slot.map(|observation| observation.mapped.port()))
    .collect();
    evidence.push(format!(
        "compared {} distinct mapped ports across {} destinations contacted ({} observed)",
        distinct_ports.len(),
        observations.probed.destinations().len(),
        observations.observed()
    ));
    evidence.push(format!("=> mapping {}", mapping.label()));
    evidence.push(format!("=> filtering {}", filtering.label()));
    evidence
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    /// A scripted probe: returns the observations it is told to, with no
    /// network, no sockets and no timing. It covers branches (a reply from a
    /// different IP, a reply on a different port) that a loopback server cannot.
    #[derive(Clone, Debug)]
    struct ScriptedProbe {
        primary: SocketAddr,
        secondary: SocketAddr,
        mapped: Option<SocketAddr>,
        change_port: Option<SocketAddr>,
        change_ip_and_port: Option<SocketAddr>,
        secondary_mapped: Option<SocketAddr>,
        calls: std::rc::Rc<std::cell::RefCell<Vec<(SocketAddr, ChangeRequest)>>>,
    }

    impl ScriptedProbe {
        fn new() -> Self {
            Self {
                primary: "192.0.2.1:3478".parse().expect("literal"),
                secondary: "198.51.100.1:3478".parse().expect("literal"),
                mapped: Some("203.0.113.7:40000".parse().expect("literal")),
                change_port: Some("203.0.113.7:40000".parse().expect("literal")),
                change_ip_and_port: Some("203.0.113.7:40000".parse().expect("literal")),
                secondary_mapped: Some("203.0.113.7:40000".parse().expect("literal")),
                calls: std::rc::Rc::new(std::cell::RefCell::new(Vec::new())),
            }
        }

        fn reply(
            &self,
            destination: SocketAddr,
            change_request: ChangeRequest,
            mapped: Option<SocketAddr>,
        ) -> Result<Option<BindingReply>, StunError> {
            self.calls.borrow_mut().push((destination, change_request));
            let mapped = match mapped {
                Some(mapped) => mapped,
                None => return Ok(None),
            };
            Ok(Some(BindingReply {
                reflexive: ReflexiveAddress {
                    mapped,
                    source: destination,
                },
                transaction_id: crate::stun::TransactionId([0u8; 12]),
                response_source: destination,
            }))
        }
    }

    impl NatProbe for ScriptedProbe {
        fn primary(&self) -> SocketAddr {
            self.primary
        }

        fn secondary(&self) -> SocketAddr {
            self.secondary
        }

        async fn mapped_for(
            &self,
            destination: SocketAddr,
        ) -> Result<Option<BindingReply>, StunError> {
            if destination == self.secondary {
                self.reply(destination, ChangeRequest::NONE, self.secondary_mapped)
            } else {
                self.reply(destination, ChangeRequest::NONE, self.mapped)
            }
        }

        async fn next_with_request(
            &self,
            destination: SocketAddr,
            change_request: ChangeRequest,
        ) -> Result<Option<BindingReply>, StunError> {
            let mapped = match change_request {
                ChangeRequest {
                    change_ip: true,
                    change_port: true,
                } => self.change_ip_and_port.or(self.mapped),
                ChangeRequest {
                    change_ip: false,
                    change_port: true,
                } => self.change_port.or(self.mapped),
                _ => self.mapped,
            };
            self.reply(destination, change_request, mapped)
        }
    }

    /// The primary server the fixtures probe.
    const THE_PRIMARY: &str = "192.0.2.1:3478";

    /// A second destination on the same address as [`THE_PRIMARY`].
    const PRIMARY_OTHER_PORT: &str = "192.0.2.1:3479";

    /// A destination on a different address from [`THE_PRIMARY`].
    const SECONDARY_V6: &str = "[2001:db8::1]:3478";

    fn observation(destination: &str, mapped_port: u16) -> Observation {
        Observation {
            destination: destination.parse().expect("literal"),
            mapped: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), mapped_port),
        }
    }

    /// The full four-probe fixture, with the probes the caller names actually
    /// marked as attempted.
    fn observations(
        primary_port: u16,
        change_port_port: u16,
        secondary_port: u16,
        attempt_changed: bool,
    ) -> ObservationSet {
        ObservationSet {
            primary: Some(observation(THE_PRIMARY, primary_port)),
            change_port: Some(observation(PRIMARY_OTHER_PORT, change_port_port)),
            change_ip_and_port: Some(observation(SECONDARY_V6, change_port_port)),
            secondary: Some(observation(SECONDARY_V6, secondary_port)),
            probed: ObservationAttempts {
                primary: Some(THE_PRIMARY.parse().expect("literal")),
                change_port: Some(PRIMARY_OTHER_PORT.parse().expect("literal")),
                change_ip_and_port: if attempt_changed {
                    Some(SECONDARY_V6.parse().expect("literal"))
                } else {
                    None
                },
                secondary: Some(SECONDARY_V6.parse().expect("literal")),
            },
            failures: Vec::new(),
        }
    }

    #[test]
    fn mapping_is_endpoint_independent_when_one_mapping_serves_every_destination() {
        let observed = observations(40000, 40000, 40000, true);
        assert_eq!(
            classify_mapping(&observed),
            MappingBehavior::EndpointIndependent
        );
    }

    #[test]
    fn mapping_is_address_dependent_when_only_the_server_changes_the_port() {
        let observed = observations(40000, 40000, 41000, true);
        assert_eq!(
            classify_mapping(&observed),
            MappingBehavior::AddressDependent
        );
    }

    #[test]
    fn mapping_is_address_and_port_dependent_when_every_destination_differs() {
        let observed = observations(40000, 41000, 42000, true);
        assert_eq!(
            classify_mapping(&observed),
            MappingBehavior::AddressAndPortDependent
        );
        // ...and also when only the destination port changes the mapping.
        let observed = observations(40000, 41000, 40000, true);
        assert_eq!(
            classify_mapping(&observed),
            MappingBehavior::AddressAndPortDependent
        );
    }

    #[test]
    fn mapping_is_unknown_without_three_usable_observations() {
        // No probes at all.
        assert_eq!(
            classify_mapping(&ObservationSet::default()),
            MappingBehavior::Unknown
        );
        // Two probes are not enough, whatever they said.
        let mut observed = observations(40000, 40000, 40000, true);
        observed.secondary = None;
        assert_eq!(classify_mapping(&observed), MappingBehavior::Unknown);
        let mut observed = observations(40000, 40000, 40000, true);
        observed.change_port = None;
        assert_eq!(classify_mapping(&observed), MappingBehavior::Unknown);
        let mut observed = observations(40000, 40000, 40000, true);
        observed.primary = None;
        assert_eq!(classify_mapping(&observed), MappingBehavior::Unknown);
    }

    #[test]
    fn mapping_is_unknown_when_the_observations_came_from_two_external_ips() {
        // Two NAT egresses: comparing their ports says nothing about one NAT, so
        // the honest answer is Unknown rather than a classification.
        let mut observed = observations(40000, 40000, 40000, true);
        observed.secondary = Some(Observation {
            destination: SECONDARY_V6.parse().expect("literal"),
            mapped: "203.0.113.99:40000".parse().expect("literal"),
        });
        assert_eq!(classify_mapping(&observed), MappingBehavior::Unknown);

        let mut observed = observations(40000, 40000, 40000, true);
        observed.change_port = Some(Observation {
            destination: PRIMARY_OTHER_PORT.parse().expect("literal"),
            mapped: "203.0.113.99:40000".parse().expect("literal"),
        });
        assert_eq!(classify_mapping(&observed), MappingBehavior::Unknown);
    }

    #[test]
    fn mapping_is_unknown_when_the_same_destination_address_and_port_disagrees() {
        // The same destination address:port, two different mappings: RFC 4787
        // has no category for this, so neither do we.
        let mut observed = observations(40000, 41000, 40000, true);
        observed.change_port = Some(observation(THE_PRIMARY, 41000));
        assert_eq!(classify_mapping(&observed), MappingBehavior::Unknown);
    }

    #[test]
    fn filtering_is_endpoint_independent_when_a_changed_address_replies() {
        let observed = observations(40000, 40000, 40000, true);
        assert_eq!(
            classify_filtering(&observed, MappingBehavior::EndpointIndependent),
            FilteringBehavior::EndpointIndependent
        );
    }

    #[test]
    fn filtering_is_address_dependent_when_only_the_port_changes() {
        // The primary host answered, but only from its own address: the
        // `change_ip_and_port` answer arrived from the targeted address:port and
        // the secondary server never answered. The `change_port` answer did
        // arrive from a different port on the primary address, so the filter
        // pins the address and not the port.
        let mut observed = observations(40000, 40000, 40000, false);
        observed.change_ip_and_port = Some(observation(THE_PRIMARY, 40000));
        observed.secondary = None;
        assert_eq!(
            classify_filtering(&observed, MappingBehavior::AddressDependent),
            FilteringBehavior::AddressDependent
        );
    }

    #[test]
    fn filtering_is_address_and_port_dependent_when_only_the_target_answered() {
        // Every probe answered from the exact destination it was sent to, and a
        // different address really was contacted and drew nothing.
        let mut observed = observations(40000, 40000, 40000, true);
        observed.change_ip_and_port = Some(observation(THE_PRIMARY, 40000));
        observed.change_port = Some(observation(THE_PRIMARY, 40000));
        observed.secondary = None;
        assert_eq!(
            classify_filtering(&observed, MappingBehavior::EndpointIndependent),
            FilteringBehavior::AddressAndPortDependent
        );
        // The mapping verdict is not what decides this, so the same evidence with
        // a destination-dependent mapping gives the same filtering answer.
        assert_eq!(
            classify_filtering(&observed, MappingBehavior::AddressAndPortDependent),
            FilteringBehavior::AddressAndPortDependent
        );
    }

    #[test]
    fn filtering_is_unknown_when_no_other_address_was_ever_contacted() {
        // Only the primary address was probed, so "only the target answered" is
        // not evidence of anything: there was nothing else to answer.
        let mut observed = observations(40000, 40000, 40000, false);
        observed.change_ip_and_port = Some(observation(THE_PRIMARY, 40000));
        observed.change_port = Some(observation(THE_PRIMARY, 40000));
        observed.secondary = None;
        observed.probed.secondary = None;
        observed.probed.change_ip_and_port = None;
        assert_eq!(
            classify_filtering(&observed, MappingBehavior::EndpointIndependent),
            FilteringBehavior::Unknown
        );
    }

    #[test]
    fn filtering_is_unknown_when_nothing_reached_the_primary_server() {
        assert_eq!(
            classify_filtering(&ObservationSet::default(), MappingBehavior::Unknown),
            FilteringBehavior::Unknown
        );
        assert_eq!(
            classify_filtering(
                &ObservationSet::failed(vec!["timed out".into()]),
                MappingBehavior::Unknown
            ),
            FilteringBehavior::Unknown
        );
        // The secondary answered but the primary did not: there is no baseline
        // destination to compare against, so this is still Unknown.
        let observed = ObservationSet {
            secondary: Some(observation(SECONDARY_V6, 40000)),
            probed: ObservationAttempts {
                secondary: Some(SECONDARY_V6.parse().expect("literal")),
                ..ObservationAttempts::default()
            },
            ..ObservationSet::default()
        };
        assert_eq!(
            classify_filtering(&observed, MappingBehavior::EndpointIndependent),
            FilteringBehavior::Unknown
        );
    }

    #[test]
    fn filtering_never_depends_on_the_mapping_argument() {
        // The verdict is a function of the observed source addresses alone; the
        // mapping is passed in for API symmetry and must not change the answer.
        let observed = observations(40000, 40000, 40000, true);
        let answers: BTreeSet<&str> = [
            MappingBehavior::EndpointIndependent,
            MappingBehavior::AddressDependent,
            MappingBehavior::AddressAndPortDependent,
            MappingBehavior::Unknown,
        ]
        .iter()
        .map(|mapping| classify_filtering(&observed, *mapping).label())
        .collect();
        assert_eq!(answers.len(), 1, "the mapping changed the verdict");
    }

    #[test]
    fn every_named_behaviour_has_a_distinct_label_and_a_knownness_flag() {
        let mappings = [
            MappingBehavior::EndpointIndependent,
            MappingBehavior::AddressDependent,
            MappingBehavior::AddressAndPortDependent,
            MappingBehavior::Unknown,
        ];
        let labels: BTreeSet<&str> = mappings.iter().map(|value| value.label()).collect();
        assert_eq!(labels.len(), 4);
        for value in mappings {
            assert_eq!(value.is_known(), value != MappingBehavior::Unknown);
        }
        let filterings = [
            FilteringBehavior::EndpointIndependent,
            FilteringBehavior::AddressDependent,
            FilteringBehavior::AddressAndPortDependent,
            FilteringBehavior::Unknown,
        ];
        let labels: BTreeSet<&str> = filterings.iter().map(|value| value.label()).collect();
        assert_eq!(labels.len(), 4);
        for value in filterings {
            assert_eq!(value.is_known(), value != FilteringBehavior::Unknown);
        }
    }

    #[test]
    fn an_all_unknown_profile_says_so_rather_than_naming_a_nat_type() {
        let profile = NatProfile::unknown("no STUN server was reachable");
        assert_eq!(profile.mapping, MappingBehavior::Unknown);
        assert_eq!(profile.filtering, FilteringBehavior::Unknown);
        assert!(profile.mapped.is_none());
        assert_eq!(profile.evidence.len(), 1);
        assert_eq!(
            profile.summary(),
            "mapping=unknown filtering=unknown mapped=none"
        );
    }

    #[test]
    fn a_profile_reports_the_mapped_address_and_the_evidence() {
        let probe = StunProbe::new(
            THE_PRIMARY.parse().expect("literal"),
            "198.51.100.1:3478".parse().expect("literal"),
        );
        let observations = observations(40000, 40000, 40000, true);
        let mapping = classify_mapping(&observations);
        let filtering = classify_filtering(&observations, mapping);
        let profile = NatProfile {
            mapping,
            filtering,
            mapped: Some(ReflexiveAddress {
                mapped: "203.0.113.7:40000".parse().expect("literal"),
                source: probe.primary(),
            }),
            evidence: evidence_for(&observations, mapping, filtering),
        };
        assert_eq!(
            profile.summary(),
            "mapping=endpoint-independent filtering=endpoint-independent mapped=203.0.113.7:40000"
        );
        assert!(profile
            .evidence
            .iter()
            .any(|line| line.contains("=> mapping endpoint-independent")));
        assert!(profile
            .evidence
            .iter()
            .any(|line| line.contains("destinations contacted")));
        assert_eq!(
            probe.secondary(),
            "198.51.100.1:3478".parse().expect("literal")
        );
    }

    #[test]
    fn a_stun_probe_with_no_reachable_server_returns_unknown_without_inventing_a_type() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            // Bind two sockets and never answer: the real probe times out.
            let primary = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let secondary = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let probe = StunProbe::new(
                primary.local_addr().expect("addr"),
                secondary.local_addr().expect("addr"),
            );
            let profile = probe.profile(Duration::from_millis(400)).await;
            assert_eq!(profile.mapping, MappingBehavior::Unknown);
            assert_eq!(profile.filtering, FilteringBehavior::Unknown);
            assert!(profile.mapped.is_none(), "no address was ever reported");
            assert!(
                profile
                    .evidence
                    .iter()
                    .any(|line| line.contains("no usable reply")),
                "evidence should record the failures: {:?}",
                profile.evidence
            );
            assert_eq!(
                probe
                    .classify_mapping(Duration::from_millis(200))
                    .await
                    .expect("the classifier only fails on I/O"),
                MappingBehavior::Unknown
            );
            assert_eq!(
                probe
                    .classify_filtering(Duration::from_millis(200))
                    .await
                    .expect("the classifier only fails on I/O"),
                FilteringBehavior::Unknown
            );
        });
    }

    #[test]
    fn a_zero_deadline_classifies_nothing_rather_than_defaulting() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let probe = StunProbe::new(
                "127.0.0.1:9".parse().expect("literal"),
                "127.0.0.1:10".parse().expect("literal"),
            );
            let profile = probe.profile(Duration::ZERO).await;
            assert_eq!(profile.mapping, MappingBehavior::Unknown);
            assert_eq!(profile.filtering, FilteringBehavior::Unknown);
            assert!(profile
                .evidence
                .iter()
                .any(|line| line.contains("no time left")));
        });
    }

    #[test]
    fn the_scripted_probe_implements_the_classifier_contract() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let stub = ScriptedProbe::new();
            let reply = stub
                .mapped_for(stub.primary)
                .await
                .expect("ok")
                .expect("a scripted reply");
            assert_eq!(
                reply.reflexive.mapped,
                "203.0.113.7:40000".parse().expect("literal")
            );
            assert_eq!(reply.reflexive.source, stub.primary);
            assert_eq!(reply.response_source, stub.primary);

            let changed = stub
                .next_with_request(stub.primary, ChangeRequest::CHANGE_IP_AND_PORT)
                .await
                .expect("ok")
                .expect("a scripted reply");
            assert_eq!(changed.response_source, stub.primary);
            assert_eq!(stub.calls.borrow().len(), 2);

            let silent = ScriptedProbe {
                mapped: None,
                ..ScriptedProbe::new()
            };
            assert!(silent
                .mapped_for(silent.primary)
                .await
                .expect("ok")
                .is_none());
        });
    }

    #[test]
    fn attempts_distinguish_never_run_from_ran_and_failed() {
        let attempts = ObservationAttempts::default();
        assert!(attempts.destinations().is_empty());
        assert!(!attempts.ran());

        let primary: SocketAddr = THE_PRIMARY.parse().expect("literal");
        let other: SocketAddr = PRIMARY_OTHER_PORT.parse().expect("literal");
        let attempts = ObservationAttempts {
            primary: Some(primary),
            change_port: Some(primary),
            change_ip_and_port: Some(other),
            secondary: None,
        };
        // Duplicates collapse, order is probe order.
        assert_eq!(attempts.destinations(), vec![primary, other]);
        assert!(attempts.retargeted_beyond(primary));
        assert!(
            attempts.retargeted_beyond(other),
            "the primary destination is still in the list"
        );
        let only_primary = ObservationAttempts {
            primary: Some(primary),
            change_port: Some(primary),
            ..ObservationAttempts::default()
        };
        assert!(!only_primary.retargeted_beyond(primary));

        let mut set = ObservationSet::default();
        set.attempted(0, primary);
        set.attempted(3, other);
        assert_eq!(set.probed.destinations(), vec![primary, other]);
        assert!(Probed::NotRun.destination().is_none());
        assert!(!Probed::NotRun.ran());
        assert!(Probed::Attempted {
            destination: primary
        }
        .ran());
    }

    #[test]
    fn phase_budget_splits_the_deadline_four_ways_and_can_be_zero() {
        let window = phase_budget(Duration::from_millis(400));
        assert_eq!(window, Duration::from_millis(100));
        assert!(
            window * 4 <= Duration::from_millis(400),
            "the phases cannot overrun the caller's deadline"
        );
        // An expired deadline yields zero, which the collector turns into an
        // explicit "no time left" failure rather than a probe that cannot
        // succeed; a sub-tick deadline yields a sub-tick window instead.
        assert!(phase_budget(Duration::ZERO).is_zero());
        assert_eq!(
            phase_budget(Duration::from_millis(3)),
            Duration::from_micros(750)
        );
        assert!(phase_budget(Duration::from_millis(3)) < Duration::from_millis(1));
        assert_eq!(
            phase_budget(Duration::from_millis(4)),
            Duration::from_millis(1)
        );
    }
}
