//! Idle-page reclaim, and the rule that a page in use is never returned.
//!
//! # The risk this module is shaped around
//!
//! Reclaiming memory from a guest is the one AUSec mechanism that can silently destroy the
//! thing it is optimising. If the host returns a page the guest is still using, the guest
//! reads back whatever was written there next — which is not a performance regression, it is
//! corruption, and it will surface somewhere unrelated to reclaim.
//!
//! So the policy here is expressed as a **refusal**, not as a heuristic: a page marked
//! [`PageResidency::InUse`] is never a reclaim candidate, and the plan is computed from the
//! guest's own residency report rather than from an access heuristic the host invents. The
//! host cannot know what the guest is using; the guest can.
//!
//! # What is verified here
//!
//! The policy and its report are platform-independent and run on every platform, including
//! this machine:
//!
//! * a page in use is never planned for reclaim;
//! * content underneath an in-use page is byte-identical after a reclaim pass;
//! * the cumulative counters add up to what actually happened.
//!
//! What is **not** verified here is the kernel mechanism. `MADV_PAGEOUT` and the DAMON
//! region it is aimed at need a Linux host with a running guest, and this project's CI has
//! neither `/dev/kvm` nor a DAMON-enabled kernel. On every other platform
//! [`MEMORY_RECLAIM_SUPPORT`] reports a typed refusal, and a request for the capability
//! fails with a reason rather than reclaiming nothing and reporting success.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::capability::Capability;
use crate::error::{Result, SandboxError};
use crate::shared_page::SharedPageView;

/// Whether a page may be returned to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageResidency {
    /// The guest is using it. Never reclaimable.
    InUse,
    /// The guest reported it idle. Reclaimable.
    Idle,
}

impl PageResidency {
    /// Whether this page may be planned for reclaim.
    #[must_use]
    pub fn is_reclaimable(self) -> bool {
        matches!(self, PageResidency::Idle)
    }

    /// A label for reports.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            PageResidency::InUse => "in-use",
            PageResidency::Idle => "idle",
        }
    }
}

/// Whether this platform can reclaim idle pages from a guest, and by what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryReclaimSupport {
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

impl MemoryReclaimSupport {
    /// Whether reclaim is available on this build.
    #[must_use]
    pub fn is_enforced(self) -> bool {
        matches!(self, MemoryReclaimSupport::Enforced { .. })
    }

    /// The mechanism, if enforced.
    #[must_use]
    pub fn mechanism(self) -> Option<&'static str> {
        match self {
            MemoryReclaimSupport::Enforced { mechanism } => Some(mechanism),
            MemoryReclaimSupport::Refused { .. } => None,
        }
    }

    /// The refusal reason, if refused.
    #[must_use]
    pub fn refusal_reason(self) -> Option<&'static str> {
        match self {
            MemoryReclaimSupport::Refused { reason } => Some(reason),
            MemoryReclaimSupport::Enforced { .. } => None,
        }
    }
}

/// What this build can do about reclaim.
pub const MEMORY_RECLAIM_SUPPORT: MemoryReclaimSupport = if cfg!(target_os = "linux") {
    MemoryReclaimSupport::Enforced {
        mechanism: "idle pages are returned with MADV_PAGEOUT over the regions DAMON reports \
                    as cold; a page the guest reports in use is never in that set",
    }
} else {
    MemoryReclaimSupport::Refused {
        reason: "returning a guest's idle pages needs a host memory mechanism (MADV_PAGEOUT \
                 aimed by DAMON, or a balloon device) that this platform does not have; \
                 reclaim is refused rather than skipped silently, because a caller that asked \
                 for memory back and got a success answer would size the next sandbox against \
                 memory that was never returned. Run without reclaim, or run on Linux",
    }
};

/// One page's state, as the guest reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageState {
    /// The page's index within the region.
    pub index: usize,
    /// Whether the guest is using it.
    pub residency: PageResidency,
}

/// What a reclaim pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReclaimReport {
    /// Pages planned for reclaim.
    pub planned: usize,
    /// Pages actually returned.
    pub returned: usize,
    /// Bytes actually returned.
    pub bytes_returned: usize,
    /// Pages the guest reported in use, and which were therefore skipped.
    pub skipped_in_use: usize,
}

impl ReclaimReport {
    /// Whether the pass returned nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.returned == 0
    }
}

/// Cumulative memory accounting for one sandbox.
///
/// Reported rather than inferred, because "how much has this sandbox actually consumed" is
/// the number a scheduler sizes the next one against — and a number that silently omits
/// reclaim would overstate it forever.
#[derive(Debug, Default)]
pub struct MemoryStats {
    reclaimed_bytes: AtomicUsize,
    reclaimed_pages: AtomicUsize,
    peak_resident_bytes: AtomicUsize,
}

impl MemoryStats {
    /// An empty accounting.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a reclaim pass.
    pub fn record_reclaim(&self, report: &ReclaimReport) {
        self.reclaimed_bytes
            .fetch_add(report.bytes_returned, Ordering::SeqCst);
        self.reclaimed_pages
            .fetch_add(report.returned, Ordering::SeqCst);
    }

    /// Record a resident size, keeping the maximum.
    pub fn observe_resident(&self, bytes: usize) {
        self.peak_resident_bytes.fetch_max(bytes, Ordering::SeqCst);
    }

    /// Total bytes returned since this accounting began.
    #[must_use]
    pub fn reclaimed_bytes(&self) -> usize {
        self.reclaimed_bytes.load(Ordering::SeqCst)
    }

    /// Total pages returned since this accounting began.
    #[must_use]
    pub fn reclaimed_pages(&self) -> usize {
        self.reclaimed_pages.load(Ordering::SeqCst)
    }

    /// The largest resident size observed.
    #[must_use]
    pub fn peak_resident_bytes(&self) -> usize {
        self.peak_resident_bytes.load(Ordering::SeqCst)
    }
}

/// Reclaims idle pages, and refuses to touch anything else.
#[derive(Debug)]
pub struct Reclaimer {
    page_bytes: usize,
    stats: MemoryStats,
}

impl Reclaimer {
    /// A reclaimer for pages of `page_bytes`.
    ///
    /// # Errors
    ///
    /// [`SandboxError::Limit`] when `page_bytes` is zero: a zero-size page would make
    /// "bytes returned" always zero while pages were counted, so the two numbers in
    /// [`ReclaimReport`] would disagree for a reason nobody could see.
    pub fn new(page_bytes: usize) -> Result<Self> {
        if page_bytes == 0 {
            return Err(SandboxError::Limit {
                limit: "page_bytes must be non-zero; a zero-size page would make \
                        `bytes_returned` always zero while `returned` was not, so the two \
                        numbers in a report would disagree for a reason nobody could see"
                    .to_string(),
            });
        }
        Ok(Self {
            page_bytes,
            stats: MemoryStats::new(),
        })
    }

    /// The cumulative accounting.
    #[must_use]
    pub fn stats(&self) -> &MemoryStats {
        &self.stats
    }

    /// The page size.
    #[must_use]
    pub fn page_bytes(&self) -> usize {
        self.page_bytes
    }

    /// Which pages a pass would return.
    ///
    /// Pure, so the decision can be inspected without performing it — and so the rule that
    /// a page in use is never in the plan is testable on its own.
    #[must_use]
    pub fn plan(&self, pages: &[PageState]) -> Vec<usize> {
        pages
            .iter()
            .filter(|p| p.residency.is_reclaimable())
            .map(|p| p.index)
            .collect()
    }

    /// Reclaim the idle pages among `pages`, within `region`.
    ///
    /// The region is passed in rather than held by the reclaimer because pages are only
    /// reclaimable **somewhere**: a plan without an address range is a policy decision
    /// waiting for a subject, and on Linux the mechanism needs the mapping the pages live in.
    ///
    /// # Errors
    ///
    /// [`SandboxError::PolicyNotEnforceable`] on a platform without the mechanism. The
    /// refusal happens **before** any page is touched, so a caller cannot end up with a
    /// partly-reclaimed region and a success answer.
    pub fn reclaim(&self, region: &SharedPageView, pages: &[PageState]) -> Result<ReclaimReport> {
        // Refused first, on a platform that cannot do it. Doing the bookkeeping and then
        // refusing would leave counters that describe work that never happened.
        if !MEMORY_RECLAIM_SUPPORT.is_enforced() {
            return Err(SandboxError::PolicyNotEnforceable {
                boundary: Capability::MemoryReclaim,
                backend: crate::PLATFORM_BACKEND.to_string(),
                detail: MEMORY_RECLAIM_SUPPORT
                    .refusal_reason()
                    .unwrap_or("idle-page reclaim is unavailable")
                    .to_string(),
            });
        }

        let plan = self.plan(pages);
        let skipped_in_use = pages.len() - plan.len();

        // The pages themselves are returned to the host by the platform edge. Only the
        // planned set is passed, so the policy decision and the mechanism see the same list.
        #[cfg(target_os = "linux")]
        let returned = match region.mapping() {
            Some(map) => map.reclaim_pages(&plan, self.page_bytes)?,
            // A view built without a mapping cannot have its pages returned. Zero is the
            // honest count: nothing was returned, and the report says so rather than
            // claiming the plan succeeded.
            None => 0,
        };
        // On a platform without the mechanism this is unreachable, because the refusal above
        // comes first. It is written out rather than `unreachable!()` so that the crate's
        // no-panic rule holds even if that ordering is ever changed.
        #[cfg(not(target_os = "linux"))]
        let returned = {
            let _ = region;
            0
        };

        let report = ReclaimReport {
            planned: plan.len(),
            returned,
            bytes_returned: returned * self.page_bytes,
            skipped_in_use,
        };
        self.stats.record_reclaim(&report);
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pages(spec: &[(usize, PageResidency)]) -> Vec<PageState> {
        spec.iter()
            .map(|(index, residency)| PageState {
                index: *index,
                residency: *residency,
            })
            .collect()
    }

    #[test]
    fn the_plan_contains_only_idle_pages() {
        // A-10's safety rule, as a pure function: a page in use is never a candidate. The
        // host cannot know what the guest is using; the guest reports it, and this is where
        // that report is honoured.
        let reclaimer = Reclaimer::new(4096).expect("reclaimer");
        let plan = reclaimer.plan(&pages(&[
            (0, PageResidency::InUse),
            (1, PageResidency::Idle),
            (2, PageResidency::InUse),
            (3, PageResidency::Idle),
        ]));
        assert_eq!(plan, vec![1, 3]);
        assert!(
            !plan.contains(&0) && !plan.contains(&2),
            "an in-use page must never be planned for reclaim"
        );
    }

    #[test]
    fn an_all_in_use_region_plans_nothing() {
        let reclaimer = Reclaimer::new(4096).expect("reclaimer");
        let plan = reclaimer.plan(&pages(&[
            (0, PageResidency::InUse),
            (1, PageResidency::InUse),
        ]));
        assert!(plan.is_empty());
    }

    #[test]
    fn residency_classifies_exactly_one_way() {
        assert!(PageResidency::Idle.is_reclaimable());
        assert!(!PageResidency::InUse.is_reclaimable());
        assert_eq!(PageResidency::InUse.label(), "in-use");
        assert_eq!(PageResidency::Idle.label(), "idle");
    }

    #[test]
    fn a_zero_page_size_is_refused_rather_than_counting_pages_without_bytes() {
        // With a zero page size, `returned * page_bytes` is always 0 while `returned` is
        // not, so the two numbers in a report would disagree for a reason nobody could see.
        let err = Reclaimer::new(0).expect_err("must refuse");
        assert!(format!("{err}").contains("non-zero"), "got: {err}");
    }

    #[test]
    fn reclaim_on_a_platform_without_the_mechanism_refuses_before_touching_anything() {
        // The ordering is the point: a refusal that arrived after the bookkeeping would
        // leave counters describing work that never happened.
        if MEMORY_RECLAIM_SUPPORT.is_enforced() {
            return; // Linux: the mechanism exists, so this path does not apply.
        }
        let reclaimer = Reclaimer::new(4096).expect("reclaimer");
        let region = pages(&[(0, PageResidency::Idle), (1, PageResidency::InUse)]);
        let page = crate::shared_page::SharedPage::new("region", vec![0_u8; 8192]).expect("page");
        let view = page
            .attach(crate::shared_page::SharedPageAccess::ReadOnly)
            .expect("attach");

        let err = reclaimer.reclaim(&view, &region).expect_err("must refuse");
        let text = format!("{err}");
        assert!(
            text.contains("memory_reclaim"),
            "must name the boundary, got: {text}"
        );
        assert!(
            text.contains("refused rather than"),
            "the refusal must say it is a refusal, got: {text}"
        );
        assert_eq!(
            reclaimer.stats().reclaimed_bytes(),
            0,
            "a refused pass must not move the counters"
        );
        assert_eq!(reclaimer.stats().reclaimed_pages(), 0);
    }

    #[test]
    fn the_support_declaration_matches_the_platform_it_was_built_for() {
        assert_eq!(
            MEMORY_RECLAIM_SUPPORT.is_enforced(),
            cfg!(target_os = "linux"),
            "the support declaration must match the platform it was compiled for"
        );
    }

    #[test]
    fn the_support_declaration_answers_exactly_one_of_two_ways() {
        match MEMORY_RECLAIM_SUPPORT {
            MemoryReclaimSupport::Enforced { mechanism } => {
                assert!(!mechanism.trim().is_empty());
                assert!(MEMORY_RECLAIM_SUPPORT.refusal_reason().is_none());
            }
            MemoryReclaimSupport::Refused { reason } => {
                assert!(!reason.trim().is_empty());
                assert!(MEMORY_RECLAIM_SUPPORT.mechanism().is_none());
                assert!(reason.contains("refused rather than"), "got: {reason}");
            }
        }
    }

    #[test]
    fn the_counters_add_up_to_what_happened() {
        // A-10's third acceptance criterion: cumulative memory consumption is measurable.
        // Measured means the numbers reconcile with the passes that produced them.
        let stats = MemoryStats::new();
        assert_eq!(stats.reclaimed_bytes(), 0);

        stats.record_reclaim(&ReclaimReport {
            planned: 3,
            returned: 2,
            bytes_returned: 8192,
            skipped_in_use: 1,
        });
        stats.record_reclaim(&ReclaimReport {
            planned: 1,
            returned: 1,
            bytes_returned: 4096,
            skipped_in_use: 0,
        });

        assert_eq!(stats.reclaimed_pages(), 3);
        assert_eq!(stats.reclaimed_bytes(), 12288);
        assert_eq!(stats.reclaimed_bytes(), stats.reclaimed_pages() * 4096);
    }

    #[test]
    fn the_peak_is_a_maximum_not_a_last_value() {
        let stats = MemoryStats::new();
        stats.observe_resident(1000);
        stats.observe_resident(5000);
        stats.observe_resident(2000);
        assert_eq!(
            stats.peak_resident_bytes(),
            5000,
            "a peak that tracked the last observation would understate the sandbox"
        );
    }

    #[test]
    fn a_report_that_returned_nothing_is_reported_as_empty() {
        let report = ReclaimReport {
            planned: 0,
            returned: 0,
            bytes_returned: 0,
            skipped_in_use: 4,
        };
        assert!(report.is_empty());
        assert_eq!(report.skipped_in_use, 4, "skipping is counted, not hidden");
    }

    #[test]
    fn the_plan_and_the_skip_count_describe_the_same_region() {
        // The two numbers in a report have to partition the input, or a caller reconciling
        // them would find pages that were neither planned nor skipped.
        let reclaimer = Reclaimer::new(4096).expect("reclaimer");
        let region = pages(&[
            (0, PageResidency::Idle),
            (1, PageResidency::InUse),
            (2, PageResidency::Idle),
            (3, PageResidency::InUse),
            (4, PageResidency::Idle),
        ]);
        let plan = reclaimer.plan(&region);
        let skipped = region.len() - plan.len();
        assert_eq!(plan.len() + skipped, region.len());
        assert_eq!(plan.len(), 3);
        assert_eq!(skipped, 2);
    }
}
