//! The reclamation ladder (GPU-W05, docs/combined-gpu-memory-and-vm-sandbox-plan.md line
//! 1158: "Register model reclamation actions with CORE-03 in this order: cancel
//! speculation, reclaim unused scratch, drop low-value caches, park eligible idle models,
//! then queue/reject").
//!
//! The ledger never calls model code. The owner of reclaimable work, model memory or any
//! other requester, implements [`Reclaimer`] and registers it for one [`ReclaimStep`] on a
//! [`ReclaimLadder`] that it lends to
//! [`Ledger::reserve_reclaiming`](super::Ledger::reserve_reclaiming) for one admission, the
//! way the ledger itself is lent to its ports for one operation.
//!
//! When a foreground request does not fit and only releases can make it fit, the ledger
//! runs the registered steps once, in the fixed order of [`ReclaimStep::ORDER`], and stops
//! as soon as the request fits:
//!
//! 1. Each implementation is told what is still missing ([`ReclaimNeed`]) and answers with
//!    reservations to give up, or a typed reason to give up none ([`DeclineReason`]).
//! 2. The ledger cancels each reservation given up after checking that it is open, that the
//!    step's owner filed it, and that it holds a resource the request falls short of under
//!    the same limit. One granted but not created returns at once. One in use only begins
//!    releasing: its amounts count until a source with authority observes the release
//!    (GPU part §3.6 step 7; S10 line 185), so a promised release frees nothing yet.
//! 3. The ledger measures progress by its own accounting, assessing the request again; once
//!    it fits, the remaining reservations given up are left alone.
//!
//! A request that still does not fit is queued or refused as before, and its
//! [`CapacityError`](super::CapacityError) lists each step tried and why it freed nothing
//! (§3.9: "queue rather than loop forever when all remaining allocations are leased or
//! pinned"). The ladder is bounded: it runs at most once per admission and never for a
//! queued request, and serving the queue never reclaims. Background requests never
//! reclaim other work.

use std::collections::BTreeMap;
use std::fmt;

use super::admission::Admission;
use super::error::{LedgerError, Shortfall};
use super::fairness::takes_from;
use super::record::ReservationRecord;
use super::request::{Requester, ReservationId, ReservationRequest};
use super::resource::{Amounts, ResourceKey};

/// One rung of the reclamation ladder, in the order the ledger runs them (GPU-W05).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReclaimStep {
    /// Cancel speculative work no request waits for yet, such as prefetches (GPU part
    /// §2.9, §3.5).
    CancelSpeculation,
    /// Return scratch reserved and not in use, such as idle staging buffers (§3.5).
    ReclaimUnusedScratch,
    /// Drop caches of low value per byte, such as dead session KV (§2.7, §3.9).
    DropLowValueCaches,
    /// Park idle models that may be parked: no leased request depends on them and their
    /// canonical state can rebuild them (§3.6, GPU-W05).
    ParkEligibleIdleModels,
}

impl ReclaimStep {
    /// Every step, in the order the ledger runs them.
    pub const ORDER: [Self; 4] = [
        Self::CancelSpeculation,
        Self::ReclaimUnusedScratch,
        Self::DropLowValueCaches,
        Self::ParkEligibleIdleModels,
    ];

    /// The step in words, for messages.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CancelSpeculation => "cancel speculation",
            Self::ReclaimUnusedScratch => "reclaim unused scratch",
            Self::DropLowValueCaches => "drop low-value caches",
            Self::ParkEligibleIdleModels => "park eligible idle models",
        }
    }
}

impl fmt::Display for ReclaimStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// An owner's implementation of one or more ladder steps.
pub trait Reclaimer {
    /// Called at most once per admission for each registration: answers with the
    /// reservations it gives up for `need`, or why it gives up none. The ledger cancels
    /// what it accepts; the implementation stops the work behind those reservations.
    fn reclaim(&mut self, need: &ReclaimNeed<'_>) -> ReclaimResponse;
}

/// What a request still falls short of, as one step is asked to reclaim for it.
pub struct ReclaimNeed<'a> {
    step: ReclaimStep,
    owner: Requester,
    request: &'a ReservationRequest,
    shortfalls: &'a [Shortfall],
    open: &'a BTreeMap<ReservationId, ReservationRecord>,
}

impl<'a> ReclaimNeed<'a> {
    pub(super) fn new(
        step: ReclaimStep,
        owner: Requester,
        request: &'a ReservationRequest,
        shortfalls: &'a [Shortfall],
        open: &'a BTreeMap<ReservationId, ReservationRecord>,
    ) -> Self {
        Self {
            step,
            owner,
            request,
            shortfalls,
            open,
        }
    }

    /// The step being asked.
    pub fn step(&self) -> ReclaimStep {
        self.step
    }

    /// The requester the asked implementation acts for: it may give up only reservations
    /// this requester filed.
    pub fn owner(&self) -> Requester {
        self.owner
    }

    /// The request that does not fit.
    pub fn request(&self) -> &ReservationRequest {
        self.request
    }

    /// Every shortfall still in the way, each of which a release can lift.
    pub fn shortfalls(&self) -> &[Shortfall] {
        self.shortfalls
    }

    /// The most of `resource` still to be released under any one limit before the request
    /// fits; zero when it falls short of none.
    pub fn missing(&self, resource: ResourceKey) -> u64 {
        self.shortfalls
            .iter()
            .filter(|shortfall| shortfall.resource == resource)
            .map(|shortfall| shortfall.requested.saturating_sub(shortfall.available))
            .max()
            .unwrap_or(0)
    }

    /// An open reservation's record.
    pub fn reservation(&self, reservation: ReservationId) -> Option<&ReservationRecord> {
        self.open.get(&reservation)
    }

    /// Whether the ledger would act on `reservation` if it were given up now: it is open,
    /// the owner filed it, and it holds a resource the request falls short of under the
    /// same limit.
    pub fn would_help(&self, reservation: ReservationId) -> bool {
        self.open.get(&reservation).is_some_and(|record| {
            nomination_refusal(record, self.owner, self.shortfalls.iter()).is_none()
        })
    }
}

/// Why the ledger does not act on the open reservation `record` that a step acting for
/// `owner` gave up while the request falls short as `shortfalls` say; `None` when it acts.
pub(super) fn nomination_refusal<'s>(
    record: &ReservationRecord,
    owner: Requester,
    mut shortfalls: impl Iterator<Item = &'s Shortfall>,
) -> Option<NominationRefusal> {
    if record.provenance.requester != owner {
        return Some(NominationRefusal::NotOwned {
            requester: record.provenance.requester,
        });
    }
    let helps = shortfalls.any(|shortfall| {
        takes_from(
            &record.provenance.tenant,
            record.parent,
            &record.current,
            shortfall,
        )
    });
    (!helps).then_some(NominationRefusal::DoesNotHelp)
}

/// A step's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReclaimResponse {
    /// Gives these reservations up; the ledger cancels each one it accepts, in order.
    Release(Vec<ReservationId>),
    /// Gives nothing up.
    Decline(DeclineReason),
}

/// Why a step gives nothing up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclineReason {
    /// The owner holds nothing this step reclaims.
    NothingToReclaim,
    /// Everything the step could reclaim is pinned or leased by requests in flight.
    Held { pinned: u32, leased: u32 },
    /// Nothing the owner holds counts against what the request falls short of.
    NotOnLimitingResources,
}

impl fmt::Display for DeclineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NothingToReclaim => f.write_str("nothing to reclaim"),
            Self::Held { pinned, leased } => match (pinned, leased) {
                (_, 0) => write!(f, "all {pinned} pinned"),
                (0, _) => write!(f, "all {leased} leased by requests in flight"),
                _ => write!(
                    f,
                    "{pinned} pinned and {leased} leased by requests in flight"
                ),
            },
            Self::NotOnLimitingResources => {
                f.write_str("nothing it holds counts against the limiting resources")
            }
        }
    }
}

/// Why the ledger did not act on a reservation a step gave up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NominationRefusal {
    /// This ledger never granted it.
    Unknown,
    /// It is closed already; cancelling again changes nothing.
    AlreadyClosed,
    /// Another requester filed it; a step gives up only its owner's reservations.
    NotOwned { requester: Requester },
    /// It holds nothing the request falls short of under the same limit.
    DoesNotHelp,
    /// The request fit before it was needed.
    NotNeeded,
}

/// A reservation a step gave up that returned its amounts at once, by the ledger's own
/// accounting: it was granted and not created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReturnedReservation {
    pub reservation: ReservationId,
    pub amounts: Amounts,
}

/// A reservation a step gave up that the ledger did not act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusedNomination {
    pub reservation: ReservationId,
    pub reason: NominationRefusal,
}

/// What one registered implementation of a step did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// No owner registered an implementation of this step.
    NotRegistered,
    /// The owner gave nothing up.
    Declined(DeclineReason),
    /// The owner gave reservations up.
    Released {
        /// Returned at once.
        returned: Vec<ReturnedReservation>,
        /// In use and now releasing; their amounts count until their release is observed.
        releasing: Vec<ReservationId>,
        /// Not acted on, with why.
        refused: Vec<RefusedNomination>,
    },
}

impl StepOutcome {
    /// Whether the step returned nothing at once.
    pub fn freed_nothing(&self) -> bool {
        match self {
            Self::Released { returned, .. } => returned.is_empty(),
            Self::NotRegistered | Self::Declined(_) => true,
        }
    }
}

impl fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegistered => f.write_str("no owner registered it"),
            Self::Declined(reason) => write!(f, "declined, {reason}"),
            Self::Released {
                returned,
                releasing,
                refused,
            } => {
                let mut parts = Vec::new();
                if !returned.is_empty() {
                    parts.push(format!("{} returned at once", count(returned.len())));
                }
                if !releasing.is_empty() {
                    parts.push(format!(
                        "{} releasing, counted until the release is observed",
                        count(releasing.len())
                    ));
                }
                if !refused.is_empty() {
                    parts.push(format!("{} not acted on", count(refused.len())));
                }
                if parts.is_empty() {
                    f.write_str("gave nothing up")
                } else {
                    f.write_str(&parts.join(", "))
                }
            }
        }
    }
}

fn count(reservations: usize) -> String {
    match reservations {
        1 => "1 reservation".into(),
        many => format!("{many} reservations"),
    }
}

/// One registered implementation's turn on the ladder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepReport {
    pub step: ReclaimStep,
    /// The requester the implementation acts for; `None` when no owner registered the step.
    pub owner: Option<Requester>,
    pub outcome: StepOutcome,
}

/// Why the ladder did not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LadderSkip {
    /// The request fit without it.
    NotNeeded,
    /// The request was invalid.
    Invalid,
    /// Background requests never reclaim other work.
    Background,
    /// A limit no release can lift stands in the way: a limit is exceeded outright, the
    /// host's observation is missing or stale, or a hold denies the request.
    NoReleaseHelps,
}

/// What the ladder did for one admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LadderReport {
    skipped: Option<LadderSkip>,
    steps: Vec<StepReport>,
    covered: bool,
}

impl LadderReport {
    pub(super) fn skipped(reason: LadderSkip) -> Self {
        Self {
            skipped: Some(reason),
            steps: Vec::new(),
            covered: false,
        }
    }

    pub(super) fn ran(steps: Vec<StepReport>, covered: bool) -> Self {
        Self {
            skipped: None,
            steps,
            covered,
        }
    }

    /// Why the ladder did not run; `None` when it ran.
    pub fn skipped_because(&self) -> Option<LadderSkip> {
        self.skipped
    }

    /// Each registered implementation tried, in order, and every step tried that no owner
    /// registered.
    pub fn steps(&self) -> &[StepReport] {
        &self.steps
    }

    /// Whether the steps made the request fit.
    pub fn covered(&self) -> bool {
        self.covered
    }

    /// Everything returned at once, by the ledger's own accounting.
    pub fn returned(&self) -> Amounts {
        self.steps
            .iter()
            .flat_map(|report| match &report.outcome {
                StepOutcome::Released { returned, .. } => returned.as_slice(),
                StepOutcome::NotRegistered | StepOutcome::Declined(_) => &[],
            })
            .fold(Amounts::new(), |total, returned| {
                returned
                    .amounts
                    .iter()
                    .fold(total, |total, (resource, amount)| {
                        total.with(resource, amount)
                    })
            })
    }

    /// Reservations now releasing because a step gave them up.
    pub fn releasing(&self) -> Vec<ReservationId> {
        self.steps
            .iter()
            .flat_map(|report| match &report.outcome {
                StepOutcome::Released { releasing, .. } => releasing.as_slice(),
                StepOutcome::NotRegistered | StepOutcome::Declined(_) => &[],
            })
            .copied()
            .collect()
    }
}

impl fmt::Display for LadderReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.skipped {
            Some(LadderSkip::NotNeeded) => return f.write_str("reclamation was not needed"),
            Some(LadderSkip::Invalid) => {
                return f.write_str("reclamation did not run for an invalid request")
            }
            Some(LadderSkip::Background) => {
                return f.write_str(
                    "reclamation did not run: background requests do not reclaim other work",
                )
            }
            Some(LadderSkip::NoReleaseHelps) => {
                return f.write_str("reclamation did not run: no release can make it fit")
            }
            None => {}
        }
        if self.covered {
            f.write_str("reclamation made room")?;
        } else if self
            .steps
            .iter()
            .all(|report| report.outcome.freed_nothing())
        {
            f.write_str("reclamation freed nothing")?;
        } else {
            f.write_str("reclamation did not free enough")?;
        }
        let mut separator = ": ";
        for report in &self.steps {
            write!(f, "{separator}{} {}", report.step, report.outcome)?;
            separator = "; ";
        }
        Ok(())
    }
}

/// The steps lent for one admission, each with the requester whose reservations it may
/// give up. Steps run in [`ReclaimStep::ORDER`] whatever the order of registration; several
/// implementations of one step run in the order they were registered.
#[derive(Default)]
pub struct ReclaimLadder<'a> {
    registrations: Vec<Registration<'a>>,
}

pub(super) struct Registration<'a> {
    pub(super) step: ReclaimStep,
    pub(super) owner: Requester,
    pub(super) reclaimer: &'a mut dyn Reclaimer,
}

impl<'a> ReclaimLadder<'a> {
    /// A ladder with no steps registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `reclaimer` for `step`, acting for `owner`: it may give up only
    /// reservations that `owner` filed.
    pub fn register(
        &mut self,
        step: ReclaimStep,
        owner: Requester,
        reclaimer: &'a mut dyn Reclaimer,
    ) -> &mut Self {
        self.registrations.push(Registration {
            step,
            owner,
            reclaimer,
        });
        self
    }

    /// Each registered step and the requester it acts for, in the order they run.
    pub fn registered(&self) -> Vec<(ReclaimStep, Requester)> {
        ReclaimStep::ORDER
            .into_iter()
            .flat_map(|step| {
                self.registrations
                    .iter()
                    .filter(move |registration| registration.step == step)
                    .map(|registration| (registration.step, registration.owner))
            })
            .collect()
    }

    pub(super) fn implementations(
        &mut self,
        step: ReclaimStep,
    ) -> impl Iterator<Item = &mut Registration<'a>> {
        self.registrations
            .iter_mut()
            .filter(move |registration| registration.step == step)
    }
}

/// The result of [`Ledger::reserve_reclaiming`](super::Ledger::reserve_reclaiming): the
/// admission as [`Ledger::reserve`](super::Ledger::reserve) would give it, and what the
/// ladder did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReclaimAdmission {
    pub admission: Result<Admission, LedgerError>,
    pub report: LadderReport,
}
