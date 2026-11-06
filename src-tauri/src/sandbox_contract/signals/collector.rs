//! A small bounded collector of the adapters' outcomes, batched per sandbox (VM part §8.2:
//! "Bound attacker-controlled log fields and emission rate"; VM-W43).
//!
//! Each draft is checked by V14 on the way in ([`MonitoringSignal::new`]), so a batch
//! holds only signals V14 accepts; a draft V14 refuses is returned as a refusal and
//! counted, never kept. Resource samples are refused too: V14 judges them over sustained
//! windows ([`ResourceMonitor`](crate::sandbox_contract::response::ResourceMonitor)), not
//! as violations. Host anomaly notices are kept beside the signals in the same batch.
//!
//! Each sandbox has its own batch of at most `per_sandbox` signals, of which guest reports
//! may take at most `guest_reports`, so at least one place is always left for host
//! observations, and at most `per_sandbox` anomaly notices. Nothing is dropped silently:
//!
//! - an observation the batch already holds (same class, subject, source, reading, grant
//!   and clock session) is merged into it and keeps the newer time, the one V14's
//!   assessment reads, so a flood of one observation takes one place;
//! - one observer's violation supersedes the passed checks that observer made of the same
//!   subject at or before it, so an earlier check never makes a later violation look
//!   contradicted; a later check stays and does contradict it, since V14 lets a check
//!   never clear a violation by itself;
//! - when a batch is full, a host observation takes the place of the oldest guest report;
//!   otherwise the incoming signal is dropped; either drop is counted as overflow;
//! - when every batch is taken, a host observation takes the place of a batch holding only
//!   guest reports, whose reports are counted as unbatched, so one sandbox's guest reports
//!   never block another sandbox's host observation; otherwise the incoming outcome is
//!   counted as unbatched.
//!
//! A batch never holds more signals than V14 assesses at once
//! ([`MAX_OBSERVATIONS_PER_ASSESSMENT`]), so each of its incidents goes to
//! [`assess_violation`](crate::sandbox_contract::response::assess_violation) whole. An
//! incident whose observations name different grants (a grant re-issued between them) is
//! handed over naming none, so V14 still responds to the sandbox and revokes no grant
//! elsewhere.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::ids::ExecutionId;
use crate::sandbox_contract::response::{
    IncidentKey, MonitoredResource, MonitoringSignal, Reading, SignalClass, SignalDraft,
    SignalRefusal, MAX_OBSERVATIONS_PER_ASSESSMENT,
};

use super::observed::{draft_of, AnomalyNotice, Classification};

/// The collector's bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollectorBounds {
    per_sandbox: usize,
    guest_reports: usize,
    sandboxes: usize,
}

impl CollectorBounds {
    /// At most `per_sandbox` signals per batch, which V14 must be able to assess at once,
    /// of which at most `guest_reports` guest reports, fewer than `per_sandbox`; at most
    /// `sandboxes` batches.
    pub fn new(
        per_sandbox: usize,
        guest_reports: usize,
        sandboxes: usize,
    ) -> Result<Self, CollectorProblem> {
        if per_sandbox == 0 {
            return Err(CollectorProblem::ZeroPerSandbox);
        }
        if per_sandbox > MAX_OBSERVATIONS_PER_ASSESSMENT {
            return Err(CollectorProblem::PerSandboxAboveAssessment {
                given: per_sandbox,
                max: MAX_OBSERVATIONS_PER_ASSESSMENT,
            });
        }
        if guest_reports >= per_sandbox {
            return Err(CollectorProblem::NoPlaceForHostObservations {
                guest_reports,
                per_sandbox,
            });
        }
        if sandboxes == 0 {
            return Err(CollectorProblem::ZeroSandboxes);
        }
        Ok(Self {
            per_sandbox,
            guest_reports,
            sandboxes,
        })
    }

    /// The most signals one batch keeps.
    pub const fn per_sandbox(&self) -> usize {
        self.per_sandbox
    }

    /// The most guest reports one batch keeps.
    pub const fn guest_reports(&self) -> usize {
        self.guest_reports
    }

    /// The most batches kept at once.
    pub const fn sandboxes(&self) -> usize {
        self.sandboxes
    }
}

/// Why bounds were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorProblem {
    /// A batch must keep at least one signal.
    ZeroPerSandbox,
    /// A batch must fit one V14 assessment.
    PerSandboxAboveAssessment { given: usize, max: usize },
    /// Guest reports may not take every place of a batch.
    NoPlaceForHostObservations {
        guest_reports: usize,
        per_sandbox: usize,
    },
    /// The collector must keep at least one batch.
    ZeroSandboxes,
}

impl fmt::Display for CollectorProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroPerSandbox => f.write_str("a batch must keep at least one signal"),
            Self::PerSandboxAboveAssessment { given, max } => write!(
                f,
                "a batch of {given} signals exceeds the {max} one assessment reads"
            ),
            Self::NoPlaceForHostObservations {
                guest_reports,
                per_sandbox,
            } => write!(
                f,
                "{guest_reports} guest reports would leave none of a batch's {per_sandbox} \
                 places to host observations"
            ),
            Self::ZeroSandboxes => f.write_str("the collector must keep at least one batch"),
        }
    }
}

impl std::error::Error for CollectorProblem {}

/// Why a draft was not collected. It is counted in the totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectRefusal {
    /// V14 refused the draft.
    Signal(SignalRefusal),
    /// A resource sample, which V14 judges over sustained windows.
    ResourceSample { resource: MonitoredResource },
}

impl fmt::Display for CollectRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(refusal) => fmt::Display::fmt(refusal, f),
            Self::ResourceSample { resource } => write!(
                f,
                "{} is judged over sustained windows, not batched as a violation",
                resource.label()
            ),
        }
    }
}

impl std::error::Error for CollectRefusal {}

/// What the collector did with one checked draft or notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Collected {
    /// Kept in the sandbox's batch.
    Kept,
    /// The batch held the same observation; the newer time was kept.
    Merged,
    /// A passed check no newer than a violation the same observer reported about the same
    /// subject: dropped, so it never makes the violation look contradicted.
    Superseded,
    /// The batch was full: this host observation took the place of the oldest guest
    /// report, which was dropped. `overflowed` counts the batch's drops so far.
    DisplacedGuestReport { overflowed: u64 },
    /// The batch was full, or held its share of guest reports: this outcome was dropped.
    /// `overflowed` counts the batch's drops so far.
    Overflowed { overflowed: u64 },
    /// Every batch was taken: this host observation was kept in a new batch in place of
    /// `sandbox`'s, which held only guest reports; its `dropped` reports were counted as
    /// unbatched.
    DisplacedGuestBatch { sandbox: ExecutionId, dropped: u64 },
    /// Every batch is taken by other sandboxes' host observations, or this is a guest
    /// report: it was dropped. `unbatched` counts such drops so far.
    NoBatchFree { unbatched: u64 },
}

/// Counts of what the collector did since it was made.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CollectorTotals {
    /// Signals and notices kept in a batch.
    pub kept: u64,
    /// Signals and notices merged into one a batch held.
    pub merged: u64,
    /// Passed checks dropped or removed because a violation of the same observer and
    /// subject superseded them.
    pub superseded: u64,
    /// Signals and notices dropped from or at a full batch.
    pub overflowed: u64,
    /// Signals and notices dropped because no batch was free for their sandbox, and guest
    /// reports dropped with a batch a host observation took the place of.
    pub unbatched: u64,
    /// Drafts refused.
    pub refused: u64,
}

/// One sandbox's collected signals and anomaly notices, and how many it dropped since the
/// last take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalBatch {
    sandbox: ExecutionId,
    signals: Vec<MonitoringSignal>,
    anomalies: Vec<AnomalyNotice>,
    overflowed: u64,
}

impl SignalBatch {
    fn new(sandbox: ExecutionId) -> Self {
        Self {
            sandbox,
            signals: Vec::new(),
            anomalies: Vec::new(),
            overflowed: 0,
        }
    }

    /// The sandbox every signal and notice is about.
    pub fn sandbox(&self) -> &ExecutionId {
        &self.sandbox
    }

    /// The signals, in arrival order.
    pub fn signals(&self) -> &[MonitoringSignal] {
        &self.signals
    }

    /// The host anomaly notices, in arrival order; each carries V14's uncertain result.
    pub fn anomalies(&self) -> &[AnomalyNotice] {
        &self.anomalies
    }

    /// Signals and notices the batch dropped while full.
    pub const fn overflowed(&self) -> u64 {
        self.overflowed
    }

    /// Whether the batch holds guest reports and nothing a host observed.
    fn guest_only(&self) -> bool {
        self.anomalies.is_empty()
            && self
                .signals
                .iter()
                .all(|signal| !signal.source().is_host_observed())
    }

    fn overflow(&mut self, totals: &mut CollectorTotals) -> Collected {
        self.overflowed = self.overflowed.saturating_add(1);
        totals.overflowed = totals.overflowed.saturating_add(1);
        Collected::Overflowed {
            overflowed: self.overflowed,
        }
    }

    /// The signals grouped by incident, each group ready for one
    /// [`assess_violation`](crate::sandbox_contract::response::assess_violation). A group
    /// whose violation observations name different grants names none.
    pub fn incidents(&self) -> Vec<(IncidentKey, Vec<MonitoringSignal>)> {
        let mut groups: BTreeMap<IncidentKey, Vec<MonitoringSignal>> = BTreeMap::new();
        for signal in &self.signals {
            groups
                .entry(IncidentKey {
                    sandbox: signal.sandbox().clone(),
                    class: signal.class(),
                    subject: *signal.subject(),
                })
                .or_default()
                .push(signal.clone());
        }
        groups
            .into_iter()
            .map(|(key, signals)| {
                let grants: BTreeSet<_> = signals
                    .iter()
                    .filter(|signal| signal.reading() == Reading::ViolationObserved)
                    .filter_map(MonitoringSignal::violated_grant)
                    .collect();
                if grants.len() > 1 {
                    (key, signals.iter().map(without_grant).collect())
                } else {
                    (key, signals)
                }
            })
            .collect()
    }
}

/// `signal` naming no grant. Dropping the grant leaves every check V14 makes satisfied.
fn without_grant(signal: &MonitoringSignal) -> MonitoringSignal {
    let mut draft = draft_of(signal);
    draft.violated_grant = None;
    MonitoringSignal::new(draft).unwrap_or_else(|_| signal.clone())
}

/// Whether two signals are one observation, apart from its time.
fn same_observation(left: &MonitoringSignal, right: &MonitoringSignal) -> bool {
    same_subject_and_observer(left, right)
        && left.reading() == right.reading()
        && left.violated_grant() == right.violated_grant()
}

/// Whether two signals are about one subject from one source on one clock session.
fn same_subject_and_observer(left: &MonitoringSignal, right: &MonitoringSignal) -> bool {
    left.class() == right.class()
        && left.subject() == right.subject()
        && left.source() == right.source()
        && left.session() == right.session()
}

/// Whether `check` is a passed check that `violation`, a violation of the same host
/// observer about the same subject, supersedes.
fn supersedes(violation: &MonitoringSignal, check: &MonitoringSignal) -> bool {
    violation.source().is_host_observed()
        && violation.reading() == Reading::ViolationObserved
        && check.reading() == Reading::CheckPassed
        && same_subject_and_observer(violation, check)
        && check.observed_at() <= violation.observed_at()
}

/// The bounded collector (see the module documentation).
#[derive(Clone, Debug)]
pub struct SignalCollector {
    bounds: CollectorBounds,
    batches: BTreeMap<ExecutionId, SignalBatch>,
    totals: CollectorTotals,
}

impl SignalCollector {
    /// An empty collector.
    pub fn new(bounds: CollectorBounds) -> Self {
        Self {
            bounds,
            batches: BTreeMap::new(),
            totals: CollectorTotals::default(),
        }
    }

    /// The bounds.
    pub const fn bounds(&self) -> CollectorBounds {
        self.bounds
    }

    /// Counts of what the collector did.
    pub const fn totals(&self) -> CollectorTotals {
        self.totals
    }

    /// The signals and notices waiting for `sandbox`.
    pub fn pending(&self, sandbox: &ExecutionId) -> usize {
        self.batches.get(sandbox).map_or(0, |batch| {
            batch.signals.len().saturating_add(batch.anomalies.len())
        })
    }

    /// Makes sure `sandbox` has a batch: its own, a free one, or for a host observation
    /// the place of a batch holding only guest reports, which is dropped and returned as
    /// the outcome to report. `Err` when no batch can be had, counted as unbatched.
    fn place(&mut self, sandbox: &ExecutionId, host: bool) -> Result<Option<Collected>, Collected> {
        if !self.batches.contains_key(sandbox) && self.batches.len() >= self.bounds.sandboxes {
            let evicted = host
                .then(|| {
                    self.batches
                        .iter()
                        .find(|(_, batch)| batch.guest_only())
                        .map(|(owner, _)| owner.clone())
                })
                .flatten()
                .and_then(|owner| self.batches.remove(&owner));
            let Some(evicted) = evicted else {
                self.totals.unbatched = self.totals.unbatched.saturating_add(1);
                return Err(Collected::NoBatchFree {
                    unbatched: self.totals.unbatched,
                });
            };
            let dropped = u64::try_from(evicted.signals.len()).unwrap_or(u64::MAX);
            self.totals.unbatched = self.totals.unbatched.saturating_add(dropped);
            self.batches
                .insert(sandbox.clone(), SignalBatch::new(sandbox.clone()));
            return Ok(Some(Collected::DisplacedGuestBatch {
                sandbox: evicted.sandbox,
                dropped,
            }));
        }
        self.batches
            .entry(sandbox.clone())
            .or_insert_with(|| SignalBatch::new(sandbox.clone()));
        Ok(None)
    }

    /// Checks one draft with V14 and batches it under its sandbox.
    pub fn collect(&mut self, draft: SignalDraft) -> Result<Collected, CollectRefusal> {
        if let SignalClass::Resource { resource } = draft.class {
            self.totals.refused = self.totals.refused.saturating_add(1);
            return Err(CollectRefusal::ResourceSample { resource });
        }
        let signal = MonitoringSignal::new(draft).map_err(|refusal| {
            self.totals.refused = self.totals.refused.saturating_add(1);
            CollectRefusal::Signal(refusal)
        })?;
        let host = signal.source().is_host_observed();
        let displaced = match self.place(signal.sandbox(), host) {
            Ok(displaced) => displaced,
            Err(unbatched) => return Ok(unbatched),
        };
        let bounds = self.bounds;
        let totals = &mut self.totals;
        let Some(batch) = self.batches.get_mut(signal.sandbox()) else {
            totals.unbatched = totals.unbatched.saturating_add(1);
            return Ok(Collected::NoBatchFree {
                unbatched: totals.unbatched,
            });
        };
        if let Some(held) = batch
            .signals
            .iter_mut()
            .find(|held| same_observation(held, &signal))
        {
            if signal.observed_at() > held.observed_at() {
                *held = signal;
            }
            totals.merged = totals.merged.saturating_add(1);
            return Ok(Collected::Merged);
        }
        if batch.signals.iter().any(|held| supersedes(held, &signal)) {
            totals.superseded = totals.superseded.saturating_add(1);
            return Ok(Collected::Superseded);
        }
        let before = batch.signals.len();
        batch.signals.retain(|held| !supersedes(&signal, held));
        let removed = u64::try_from(before.saturating_sub(batch.signals.len())).unwrap_or(u64::MAX);
        totals.superseded = totals.superseded.saturating_add(removed);
        let guests = batch
            .signals
            .iter()
            .filter(|held| !held.source().is_host_observed())
            .count();
        if !host && guests >= bounds.guest_reports {
            return Ok(batch.overflow(totals));
        }
        if batch.signals.len() >= bounds.per_sandbox {
            let oldest_report = batch
                .signals
                .iter()
                .enumerate()
                .filter(|(_, held)| !held.source().is_host_observed())
                .min_by_key(|(_, held)| held.observed_at())
                .map(|(index, _)| index);
            let (true, Some(index)) = (host, oldest_report) else {
                return Ok(batch.overflow(totals));
            };
            batch.signals.remove(index);
            batch.signals.push(signal);
            batch.overflowed = batch.overflowed.saturating_add(1);
            totals.overflowed = totals.overflowed.saturating_add(1);
            totals.kept = totals.kept.saturating_add(1);
            return Ok(Collected::DisplacedGuestReport {
                overflowed: batch.overflowed,
            });
        }
        batch.signals.push(signal);
        totals.kept = totals.kept.saturating_add(1);
        Ok(displaced.unwrap_or(Collected::Kept))
    }

    /// Batches one host anomaly notice under its sandbox.
    pub fn collect_anomaly(&mut self, notice: AnomalyNotice) -> Collected {
        let displaced = match self.place(&notice.sandbox, true) {
            Ok(displaced) => displaced,
            Err(unbatched) => return unbatched,
        };
        let per_sandbox = self.bounds.per_sandbox;
        let totals = &mut self.totals;
        let Some(batch) = self.batches.get_mut(&notice.sandbox) else {
            totals.unbatched = totals.unbatched.saturating_add(1);
            return Collected::NoBatchFree {
                unbatched: totals.unbatched,
            };
        };
        if let Some(held) = batch.anomalies.iter_mut().find(|held| {
            held.anomaly == notice.anomaly
                && held.subject == notice.subject
                && held.observer == notice.observer
                && held.session == notice.session
        }) {
            if notice.observed_at > held.observed_at {
                *held = notice;
            }
            totals.merged = totals.merged.saturating_add(1);
            return Collected::Merged;
        }
        if batch.anomalies.len() >= per_sandbox {
            return batch.overflow(totals);
        }
        batch.anomalies.push(notice);
        totals.kept = totals.kept.saturating_add(1);
        displaced.unwrap_or(Collected::Kept)
    }

    /// Collects an adapter's outcome: its draft or anomaly notice; nothing for an ordinary
    /// outcome, which has none.
    pub fn collect_outcome<V>(
        &mut self,
        outcome: Classification<V>,
    ) -> Result<Option<Collected>, CollectRefusal> {
        match outcome {
            Classification::Violation { draft, .. } | Classification::CheckPassed { draft } => {
                self.collect(draft).map(Some)
            }
            Classification::HostAnomaly { notice } => Ok(Some(self.collect_anomaly(notice))),
            Classification::Ordinary { .. } => Ok(None),
        }
    }

    /// Takes `sandbox`'s batch, freeing its place.
    pub fn take(&mut self, sandbox: &ExecutionId) -> Option<SignalBatch> {
        self.batches.remove(sandbox)
    }

    /// Takes every batch, in sandbox order.
    pub fn take_all(&mut self) -> Vec<SignalBatch> {
        std::mem::take(&mut self.batches).into_values().collect()
    }
}
