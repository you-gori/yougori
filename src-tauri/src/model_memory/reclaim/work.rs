//! What every model step shares (GPU-W05; `foundation::ledger::reclaim`): the work a
//! component reports, the rule by which a step gives reservations up, and how the work
//! behind what the ledger acted on is stopped.
//!
//! A step reclaims in three phases around one admission:
//!
//! 1. Prepare: before the ledger runs the ladder, the step surveys its component through
//!    a [`WorkSource`] and keeps the [`Candidate`]s, each with the ledger reservations that
//!    stopping it would release and what holds it ([`Hold`]).
//! 2. Reclaim: the ledger asks the step, as a
//!    [`Reclaimer`](crate::foundation::ledger::Reclaimer), what it gives up for what is
//!    still missing. It names only reservations its owner filed that are still granted or
//!    in use and that the ledger would act on, never anything pinned or leased, and only as
//!    much as covers what is missing of each limiting resource:
//!    - first, in the source's own order, free work whose reservations are all granted and
//!      not yet created, which returns at once;
//!    - then, in the same order, free work in use, which only begins releasing. What the
//!      earlier steps of the same admission set releasing counts here too
//!      ([`ReleasesUnderWay`]), so a later, costlier step does not stop more work for
//!      memory whose release is already under way; it gives up nothing instead, and the
//!      request waits for those releases.
//!
//!    When it gives up nothing for any other cause it says why ([`DeclineReason`]).
//! 3. Settle: once the admission is answered, the step stops through the source the
//!    work behind every candidate whose reservations the ledger acted on, and leaves the
//!    rest running. A reservation in use only began releasing: its amounts count until a
//!    source with authority observes the release (GPU part §3.6 step 7; S10 line 185),
//!    which the [`Settlement`] lists for the caller to confirm. A step never confirms a
//!    release itself.
//!
//! The ledger stays locked only for the admission. A source that reaches the ledger locks
//! the shared handle itself, so neither preparing nor settling may run under the caller's
//! lock.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::foundation::coordination::{ModelRefusal, SharedLedger};
use crate::foundation::ledger::{
    DeclineReason, LadderReport, Ledger, ReclaimNeed, ReclaimResponse, ReclaimStep, Requester,
    ReservationId, ReservationState, ResourceKey, StepOutcome,
};
use crate::model_memory::executor::{CancelError, CloseError};
use crate::model_memory::placement::SlotError;
use crate::model_memory::residency::eviction::NotDroppable;
use crate::model_memory::tiers::{
    GpuRefusal, HostRefusal, LocalRefusal, PinnedRefusal, RepresentationRefusal, Tier,
};

/// What keeps one unit of work from being given up now (§3.9: "queue rather than loop
/// forever when all remaining allocations are leased or pinned").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    /// Nothing: the work may be stopped and its reservations given up.
    Free,
    /// Its owner keeps it; a step that declines counts it as pinned.
    Pinned(PinnedBy),
    /// Requests or other work in flight use it; a step that declines counts it as leased.
    Leased(LeasedBy),
}

impl Hold {
    /// Whether nothing holds the work.
    pub const fn is_free(self) -> bool {
        matches!(self, Self::Free)
    }
}

impl fmt::Display for Hold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Free => f.write_str("free"),
            Self::Pinned(by) => write!(f, "pinned: {by}"),
            Self::Leased(by) => write!(f, "leased: {by}"),
        }
    }
}

/// Why the owner keeps work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinnedBy {
    /// The owner's retention policy pins it.
    Policy,
    /// A user's original, never evicted to meet a budget (§3.4).
    Original,
    /// The verified copy that rebuilds weights still resident on a GPU (§1.1 line 307,
    /// §3.9).
    CanonicalCopyNeeded,
    /// The catalog would not evict it now: leased, needed by another object or no longer
    /// reconstructible (§3.4).
    CatalogKeeps,
    /// No canonical state can rebuild it, so stopping it would lose it (§3.6; GPU-W05:
    /// "clean-drop parking only when canonical state can reconstruct exact weights").
    NoCanonicalState,
    /// It takes part in an activation or handover in progress (§3.6).
    Transition,
    /// Its value cannot be measured, so nothing shows it is of low value.
    Unvalued,
    /// A session still live may use it again, such as KV kept for a resume (§3.9).
    LiveSession,
}

impl fmt::Display for PinnedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Policy => "pinned by its owner's policy",
            Self::Original => "a user's original",
            Self::CanonicalCopyNeeded => "the copy that rebuilds resident weights",
            Self::CatalogKeeps => "kept by the catalog",
            Self::NoCanonicalState => "no canonical state can rebuild it",
            Self::Transition => "part of an activation in progress",
            Self::Unvalued => "its value cannot be measured",
            Self::LiveSession => "a live session may use it again",
        })
    }
}

/// What in flight uses work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeasedBy {
    /// Request leases that may still use it.
    Requests { leases: usize },
    /// Other jobs subscribe to it or still hold it (§3.5: one cancellation never cancels
    /// another subscriber's work).
    OtherWork { holders: usize },
    /// Work in flight uses it now, such as staging slots or a ring's transfers.
    InFlight,
    /// Executions, captured graphs or imports still reference the GPU allocation
    /// (GPU-W05 line 1056: reference lifetimes across mappings, graphs and imports).
    Referenced { references: usize },
    /// It is a shared physical extent that other holders still hold; the last holder
    /// releases it (S03).
    SharedExtent { holders: usize },
}

impl fmt::Display for LeasedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requests { leases } => write!(f, "{leases} request lease(s) may use it"),
            Self::OtherWork { holders } => write!(f, "{holders} other holder(s) use it"),
            Self::InFlight => f.write_str("work in flight uses it"),
            Self::Referenced { references } => {
                write!(f, "{references} reference(s) still hold it")
            }
            Self::SharedExtent { holders } => {
                write!(f, "{holders} holder(s) still share the extent")
            }
        }
    }
}

/// One unit of work a source could stop, with the ledger reservations it holds.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate<W> {
    pub work: W,
    /// The ledger reservations held for this work alone, which stopping it releases.
    pub reservations: Vec<ReservationId>,
    pub hold: Hold,
    /// The source's own order: lower is given up first, such as least expected value or
    /// least value per byte. Ties keep the order of the survey.
    pub rank: f64,
}

/// The component behind one step, as the step sees it: it reports its work and stops
/// it. Implementations adapt an existing component through its public API.
pub trait WorkSource {
    /// Names one unit of work.
    type Work: Clone + fmt::Debug + fmt::Display;

    /// The requester that filed the reservations of this work in the ledger.
    fn owner(&self) -> Requester;

    /// The work it could stop now, each with its reservations and what holds it. Called
    /// before the ledger runs the ladder, never under the caller's ledger lock.
    fn survey(&mut self) -> Vec<Candidate<Self::Work>>;

    /// Stops `work`, some or all of whose reservations the ledger has given up. Called
    /// after the admission, never under the caller's ledger lock.
    fn stop(&mut self, work: &Self::Work) -> Result<(), StopError>;
}

/// What a survey found, by what holds each candidate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Survey {
    pub free: usize,
    pub pinned: usize,
    pub leased: usize,
}

impl Survey {
    fn of<W>(candidates: &[Candidate<W>]) -> Self {
        candidates
            .iter()
            .fold(Self::default(), |mut survey, candidate| {
                match candidate.hold {
                    Hold::Free => survey.free += 1,
                    Hold::Pinned(_) => survey.pinned += 1,
                    Hold::Leased(_) => survey.leased += 1,
                }
                survey
            })
    }
}

/// Why a step refused to work with a source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReclaimError {
    /// The source's work is filed by another requester than the one the step acts for:
    /// a step gives up only its owner's reservations.
    OwnerMismatch {
        step: ReclaimStep,
        acts_for: Requester,
        source: Requester,
    },
}

impl fmt::Display for ReclaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnerMismatch {
                step,
                acts_for,
                source,
            } => write!(
                f,
                "the {step} step acts for {acts_for:?}, but the source's work is filed by \
                 {source:?}"
            ),
        }
    }
}

impl std::error::Error for ReclaimError {}

/// Why work whose reservations the ledger gave up could not be stopped. A component's
/// refusal is boxed to keep the error small.
#[derive(Clone, Debug, PartialEq)]
pub enum StopError {
    /// The work is no longer there.
    Gone,
    /// A user's original is never evicted (§3.4 line 552).
    Original,
    /// The transfer executor refused to cancel the job.
    Cancel(Box<CancelError>),
    /// The transfer executor refused to close.
    Close(Box<CloseError>),
    /// The pinned host tier refused.
    Pinned(Box<PinnedRefusal>),
    /// The reclaimable host tier refused.
    Host(Box<HostRefusal>),
    /// Local storage or its catalog refused.
    Local(Box<LocalRefusal>),
    /// The representation store refused.
    Representation(Box<RepresentationRefusal>),
    /// The placement slot refused.
    Slot(Box<SlotError>),
    /// The coordination protocol refused.
    Model(Box<ModelRefusal>),
    /// The source was not given the tier that holds the work.
    TierNotGiven { tier: Tier },
    /// The GPU tier refused, such as while something still maps or references the
    /// allocation.
    Gpu(Box<GpuRefusal>),
    /// Something took hold of the work after the survey, as `hold` says, so it is kept.
    Held { hold: Hold },
    /// T08's clean-eviction rule keeps the GPU copy now: no verified copy in a tier that
    /// guarantees availability would rebuild it (§1.1 line 307).
    Retained { because: NotDroppable },
    /// Another source refused, as it says.
    Refused { reason: String },
}

impl fmt::Display for StopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone => f.write_str("the work is no longer there"),
            Self::Original => f.write_str("a user's original is never evicted"),
            Self::Cancel(error) => write!(f, "the executor did not cancel the job: {error}"),
            Self::Close(error) => write!(f, "the executor did not close: {error}"),
            Self::Pinned(refusal) => write!(f, "the pinned host tier refused: {refusal}"),
            Self::Host(refusal) => write!(f, "the reclaimable host tier refused: {refusal}"),
            Self::Local(refusal) => write!(f, "local storage refused: {refusal}"),
            Self::Representation(refusal) => {
                write!(f, "the representation store refused: {refusal}")
            }
            Self::Slot(error) => write!(f, "the placement slot refused: {error}"),
            Self::Model(refusal) => write!(f, "the coordination protocol refused: {refusal}"),
            Self::TierNotGiven { tier } => write!(f, "the source was not given the {tier} tier"),
            Self::Gpu(refusal) => write!(f, "the GPU tier refused: {refusal}"),
            Self::Held { hold } => write!(f, "it is held now ({hold})"),
            Self::Retained { because } => write!(
                f,
                "the clean-eviction rule keeps it: {}",
                match because {
                    NotDroppable::Dirty => "it changed since any copy was made",
                    NotDroppable::NoVerifiedCopy => "no verified copy would rebuild it",
                }
            ),
            Self::Refused { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for StopError {}

/// Work that was stopped because the ledger acted on its reservations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoppedWork {
    pub work: String,
    /// Returned at once: granted and never created.
    pub returned: Vec<ReservationId>,
    /// Releasing: counted until a source with authority observes the release.
    pub releasing: Vec<ReservationId>,
}

/// Work whose reservations the ledger acted on but which could not be stopped. Its
/// releasing reservations stay counted; the caller must not confirm their release.
#[derive(Clone, Debug, PartialEq)]
pub struct UnstoppedWork {
    pub work: String,
    pub returned: Vec<ReservationId>,
    pub releasing: Vec<ReservationId>,
    pub error: StopError,
}

/// What one step did once the admission was answered.
#[derive(Clone, Debug, PartialEq)]
pub struct Settlement {
    pub step: ReclaimStep,
    pub owner: Requester,
    /// Stopped, because the ledger acted on its reservations.
    pub stopped: Vec<StoppedWork>,
    /// Given up, but the ledger acted on none of its reservations: the request fit first
    /// or the ledger refused them. Left running.
    pub kept: Vec<String>,
    /// Given up and acted on, but not stopped.
    pub not_stopped: Vec<UnstoppedWork>,
}

impl Settlement {
    fn new(step: ReclaimStep, owner: Requester) -> Self {
        Self {
            step,
            owner,
            stopped: Vec::new(),
            kept: Vec::new(),
            not_stopped: Vec::new(),
        }
    }

    /// Releasing reservations behind stopped work: confirm each once a source with
    /// authority observes its memory free, never before (S10 line 185).
    pub fn awaiting_release(&self) -> Vec<ReservationId> {
        self.stopped
            .iter()
            .flat_map(|stopped| stopped.releasing.iter().copied())
            .collect()
    }

    /// Whether the step gave nothing up.
    pub fn is_empty(&self) -> bool {
        self.stopped.is_empty() && self.kept.is_empty() && self.not_stopped.is_empty()
    }
}

/// What the model steps of one admission set releasing so far, by resource. Steps that
/// share it count those releases toward what is missing, so a later step gives up work in
/// use only for what the releases under way do not cover. A release never counts as
/// returned in the ledger: the request still waits for it. [`register_model_reclaimers`]
/// shares a new one among the steps it registers, for one admission.
///
/// [`register_model_reclaimers`]: super::register_model_reclaimers
#[derive(Clone, Debug, Default)]
pub struct ReleasesUnderWay(Arc<Mutex<BTreeMap<ResourceKey, u64>>>);

impl ReleasesUnderWay {
    /// Nothing releasing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// How much of `resource` the steps sharing it set releasing.
    pub fn amount(&self, resource: ResourceKey) -> u64 {
        self.amounts().get(&resource).copied().unwrap_or(0)
    }

    fn amounts(&self) -> MutexGuard<'_, BTreeMap<ResourceKey, u64>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add(&self, resource: ResourceKey, amount: u64) {
        let mut amounts = self.amounts();
        let held = amounts.entry(resource).or_default();
        *held = held.saturating_add(amount);
    }
}

/// Free work the ledger would act on, as one step ranks it.
struct Offer<'c, W> {
    candidate: &'c Candidate<W>,
    reservations: Vec<ReservationId>,
}

/// One step's state across the three phases: what the survey found and what was given
/// up, for one owner.
#[derive(Clone, Debug)]
pub(super) struct Rung<W> {
    step: ReclaimStep,
    owner: Requester,
    candidates: Vec<Candidate<W>>,
    nominated: Vec<(W, Vec<ReservationId>)>,
    releases: Option<ReleasesUnderWay>,
}

impl<W: Clone + fmt::Display> Rung<W> {
    pub(super) fn new(step: ReclaimStep, owner: Requester) -> Self {
        Self {
            step,
            owner,
            candidates: Vec::new(),
            nominated: Vec::new(),
            releases: None,
        }
    }

    pub(super) fn step(&self) -> ReclaimStep {
        self.step
    }

    pub(super) fn owner(&self) -> Requester {
        self.owner
    }

    pub(super) fn candidates(&self) -> &[Candidate<W>] {
        &self.candidates
    }

    fn check(&self, source: Requester) -> Result<(), ReclaimError> {
        if source == self.owner {
            Ok(())
        } else {
            Err(ReclaimError::OwnerMismatch {
                step: self.step,
                acts_for: self.owner,
                source,
            })
        }
    }

    /// Phase 1: surveys the source. Anything given up for an earlier admission and never
    /// settled is forgotten, and so are the releases shared for it.
    pub(super) fn prepare<S>(&mut self, source: &mut S) -> Result<Survey, ReclaimError>
    where
        S: WorkSource<Work = W> + ?Sized,
    {
        self.check(source.owner())?;
        self.nominated.clear();
        self.releases = None;
        self.candidates = source.survey();
        Ok(Survey::of(&self.candidates))
    }

    /// Counts, for this admission, what the steps sharing `releases` set releasing.
    pub(super) fn share_releases(&mut self, releases: &ReleasesUnderWay) {
        self.releases = Some(releases.clone());
    }

    /// Phase 2: what this step gives up for `need`.
    pub(super) fn reclaim(&mut self, need: &ReclaimNeed<'_>) -> ReclaimResponse {
        self.nominated.clear();
        if need.step() != self.step || need.owner() != self.owner {
            return ReclaimResponse::Decline(DeclineReason::NothingToReclaim);
        }
        let limiting: BTreeSet<ResourceKey> = need
            .shortfalls()
            .iter()
            .map(|shortfall| shortfall.resource)
            .collect();
        let mut order: Vec<&Candidate<W>> = self.candidates.iter().collect();
        order.sort_by(|left, right| left.rank.total_cmp(&right.rank));
        let mut claimed: BTreeSet<ReservationId> = BTreeSet::new();
        let (mut pinned, mut leased, mut holds_any) = (0u32, 0u32, false);
        let mut returning = Vec::new();
        let mut releasing = Vec::new();
        for candidate in order {
            let live: Vec<ReservationId> = candidate
                .reservations
                .iter()
                .copied()
                .filter(|reservation| !claimed.contains(reservation))
                .filter(|reservation| self.may_give_up(need, *reservation))
                .collect();
            if live.is_empty() {
                continue;
            }
            holds_any = true;
            claimed.extend(live.iter().copied());
            let helpful: Vec<ReservationId> = live
                .into_iter()
                .filter(|reservation| need.would_help(*reservation))
                .collect();
            if helpful.is_empty() {
                continue;
            }
            match candidate.hold {
                Hold::Pinned(_) => pinned = pinned.saturating_add(1),
                Hold::Leased(_) => leased = leased.saturating_add(1),
                Hold::Free => {
                    let created = helpful.iter().any(|reservation| {
                        need.reservation(*reservation)
                            .is_some_and(|record| record.state() == ReservationState::InUse)
                    });
                    let offer = Offer {
                        candidate,
                        reservations: helpful,
                    };
                    if created {
                        releasing.push(offer);
                    } else {
                        returning.push(offer);
                    }
                }
            }
        }
        let offered = !returning.is_empty() || !releasing.is_empty();
        // What returns at once first; then what only begins releasing, counting what the
        // earlier steps of this admission set releasing.
        let mut given: BTreeMap<ResourceKey, u64> = BTreeMap::new();
        let mut nominated = Vec::new();
        for offer in returning {
            if covered(&limiting, &given, need) {
                break;
            }
            add_amounts(&mut given, &limiting, need, &offer.reservations);
            nominated.push((offer.candidate.work.clone(), offer.reservations));
        }
        if let Some(releases) = &self.releases {
            for resource in &limiting {
                let held = given.entry(*resource).or_default();
                *held = held.saturating_add(releases.amount(*resource));
            }
        }
        let mut started: BTreeMap<ResourceKey, u64> = BTreeMap::new();
        for offer in releasing {
            if covered(&limiting, &given, need) {
                break;
            }
            add_amounts(&mut given, &limiting, need, &offer.reservations);
            add_amounts(&mut started, &limiting, need, &offer.reservations);
            nominated.push((offer.candidate.work.clone(), offer.reservations));
        }
        if let Some(releases) = &self.releases {
            for (resource, amount) in started {
                releases.add(resource, amount);
            }
        }
        if offered {
            // Free work was on offer: an empty answer means the releases under way cover
            // what is missing, and the request waits for them.
            let reservations = nominated
                .iter()
                .flat_map(|(_, reservations)| reservations.iter().copied())
                .collect();
            self.nominated = nominated;
            return ReclaimResponse::Release(reservations);
        }
        ReclaimResponse::Decline(if pinned > 0 || leased > 0 {
            DeclineReason::Held { pinned, leased }
        } else if holds_any {
            DeclineReason::NotOnLimitingResources
        } else {
            DeclineReason::NothingToReclaim
        })
    }

    /// Whether `reservation` is one this step may give up at all: open, filed by its
    /// owner and granted or in use. One already releasing is stopping already.
    fn may_give_up(&self, need: &ReclaimNeed<'_>, reservation: ReservationId) -> bool {
        need.reservation(reservation).is_some_and(|record| {
            record.provenance().requester == self.owner
                && matches!(
                    record.state(),
                    ReservationState::Granted | ReservationState::InUse
                )
        })
    }

    /// Phase 3: stops the work behind every reservation of this step the ledger acted on
    /// in `report`. A source of another owner is refused and nothing is stopped.
    pub(super) fn settle<S>(
        &mut self,
        report: &LadderReport,
        source: &mut S,
    ) -> Result<Settlement, ReclaimError>
    where
        S: WorkSource<Work = W> + ?Sized,
    {
        self.check(source.owner())?;
        let mut returned = BTreeSet::new();
        let mut releasing = BTreeSet::new();
        for step in report
            .steps()
            .iter()
            .filter(|step| step.step == self.step && step.owner == Some(self.owner))
        {
            if let StepOutcome::Released {
                returned: back,
                releasing: going,
                ..
            } = &step.outcome
            {
                returned.extend(back.iter().map(|returned| returned.reservation));
                releasing.extend(going.iter().copied());
            }
        }
        let mut settlement = Settlement::new(self.step, self.owner);
        self.releases = None;
        for (work, reservations) in std::mem::take(&mut self.nominated) {
            let back: Vec<ReservationId> = reservations
                .iter()
                .copied()
                .filter(|reservation| returned.contains(reservation))
                .collect();
            let going: Vec<ReservationId> = reservations
                .iter()
                .copied()
                .filter(|reservation| releasing.contains(reservation))
                .collect();
            if back.is_empty() && going.is_empty() {
                settlement.kept.push(work.to_string());
                continue;
            }
            match source.stop(&work) {
                Ok(()) => settlement.stopped.push(StoppedWork {
                    work: work.to_string(),
                    returned: back,
                    releasing: going,
                }),
                Err(error) => settlement.not_stopped.push(UnstoppedWork {
                    work: work.to_string(),
                    returned: back,
                    releasing: going,
                    error,
                }),
            }
        }
        self.candidates.clear();
        Ok(settlement)
    }
}

/// Whether what was given up holds, of every limiting resource, what is still missing.
fn covered(
    limiting: &BTreeSet<ResourceKey>,
    given: &BTreeMap<ResourceKey, u64>,
    need: &ReclaimNeed<'_>,
) -> bool {
    limiting
        .iter()
        .all(|resource| given.get(resource).copied().unwrap_or(0) >= need.missing(*resource))
}

/// Adds what `reservations` hold of each limiting resource to `total`.
fn add_amounts(
    total: &mut BTreeMap<ResourceKey, u64>,
    limiting: &BTreeSet<ResourceKey>,
    need: &ReclaimNeed<'_>,
    reservations: &[ReservationId],
) {
    for reservation in reservations {
        let Some(record) = need.reservation(*reservation) else {
            continue;
        };
        for resource in limiting {
            let held = total.entry(*resource).or_default();
            *held = held.saturating_add(record.current().get(*resource));
        }
    }
}

/// The shared ledger, locked as its other clients lock it.
pub(super) fn lock<C>(ledger: &SharedLedger<C>) -> MutexGuard<'_, Ledger<C>> {
    ledger.lock().unwrap_or_else(PoisonError::into_inner)
}
