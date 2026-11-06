//! Refusals: the actionable capacity error and the ledger's typed errors (S10 line 179:
//! "The output identifies the limiting resource and whether a retry can make progress").

use std::fmt;
use std::time::Duration;

use super::admission::ownership::OwnershipError;
use super::fairness::QueueClaim;
use super::reclaim::LadderReport;
use super::record::ReservationState;
use super::request::{HoldId, QueueTicket, ReservationId};
use super::resource::{DeviceId, ResourceKey};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{ExecutionId, MonotonicTime, TenantId};

/// The limit a request ran into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Limit {
    /// The host's physical capacity less the supervisor reserve, which is never granted;
    /// the usage the host observed outside the ledger is not free either.
    PhysicalCapacity,
    /// The host has not observed this resource's capacity, so none of it is free.
    CapacityNotObserved,
    /// The host's latest observation of this resource's unmanaged usage (host pressure)
    /// is `age` old, past `max_age`, so how much is free is unknown and nothing more is
    /// granted until the host observes it again (S2 CORE-03; CORE-01 freshness).
    StaleHostObservation {
        observed_at: MonotonicTime,
        age: Duration,
        max_age: Duration,
    },
    /// The tenant's budget, charged separately from physical capacity (S2 CORE-03).
    TenantBudget { tenant: TenantId },
    /// The parent reservation the request is carved from (S3.2).
    ParentReservation { parent: ReservationId },
    /// An owner resource-return hold denies new background reservations (S10 line 185).
    OwnerReturnHold { hold: HoldId },
}

/// Whether, and after what, a retry can make progress (S10 line 179).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryProspect {
    /// Fits once this much more is released, in the resource's unit.
    FitsAfterRelease { shortfall: u64 },
    /// Exceeds the limit itself, so no release makes it fit and a retry cannot succeed.
    ExceedsLimit { limit: u64 },
    /// Can fit only after the host observes the resource: its capacity, or its usage
    /// again when the latest observation is stale.
    AfterHostObservation,
    /// Denied until the hold ends.
    AfterHoldEnds,
}

impl RetryProspect {
    /// Whether a later retry can succeed at all.
    pub const fn can_progress(self) -> bool {
        !matches!(self, Self::ExceedsLimit { .. })
    }

    /// Whether waiting in the queue can help: only a release can. A hold, an unobserved
    /// capacity or a stale observation is a denial, and an exceeded limit never fits.
    pub const fn waitable(self) -> bool {
        matches!(self, Self::FitsAfterRelease { .. })
    }

    const fn rank(self) -> u8 {
        match self {
            Self::ExceedsLimit { .. } => 0,
            Self::AfterHostObservation => 1,
            Self::AfterHoldEnds => 2,
            Self::FitsAfterRelease { .. } => 3,
        }
    }
}

/// One resource a request does not fit under one limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shortfall {
    pub resource: ResourceKey,
    pub limit: Limit,
    /// The amount requested, in the resource's unit.
    pub requested: u64,
    /// The amount free under this limit now.
    pub available: u64,
    pub prospect: RetryProspect,
}

impl fmt::Display for Shortfall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unit = self.resource.unit().name();
        let resource = self.resource;
        let requested = self.requested;
        let limit = match &self.limit {
            Limit::PhysicalCapacity => "this host's capacity after its supervisor reserve".into(),
            Limit::CapacityNotObserved => "this host's observed capacity".into(),
            Limit::StaleHostObservation { .. } => "this host's latest observation".into(),
            Limit::TenantBudget { tenant } => format!("the budget of tenant {tenant}"),
            Limit::ParentReservation { parent } => format!("{parent}, its parent"),
            Limit::OwnerReturnHold { hold } => format!("{hold}"),
        };
        match self.prospect {
            RetryProspect::ExceedsLimit { limit: amount } => write!(
                f,
                "{resource}: {requested} {unit} exceeds {limit} of {amount} {unit}; a retry \
                 cannot succeed"
            ),
            RetryProspect::FitsAfterRelease { shortfall } => write!(
                f,
                "{resource}: {requested} {unit} requested, {} {unit} free under {limit}; it \
                 fits after {shortfall} {unit} is released",
                self.available
            ),
            RetryProspect::AfterHostObservation => match &self.limit {
                Limit::StaleHostObservation { age, max_age, .. } => write!(
                    f,
                    "{resource}: the host last observed its usage {} ms ago, past the {} ms \
                     limit, so none is free; refresh the host observation",
                    age.as_millis(),
                    max_age.as_millis()
                ),
                _ => write!(
                    f,
                    "{resource}: the host has not observed its capacity, so none is free; \
                     retry after a host probe"
                ),
            },
            RetryProspect::AfterHoldEnds => write!(
                f,
                "{resource}: background reservations are denied while {limit} returns it to \
                 its owner; retry after the hold ends"
            ),
        }
    }
}

/// Why a request was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueRefusal {
    /// The request asked not to wait.
    NotRequested,
    /// Waiting cannot help: a limit is exceeded, capacity is unobserved, the host's
    /// observation is stale or a hold denies the request.
    NotWaitable,
    /// The queue holds its maximum number of entries.
    Full { max_entries: usize },
    /// The tenant holds its maximum number of queue entries.
    TenantFull { max_entries: usize },
}

/// An actionable capacity error (S10 line 179): the limiting resource first, then every
/// other shortfall, and whether a retry can make progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapacityError {
    /// Boxed so that every error result stays small.
    limiting: Box<Shortfall>,
    others: Vec<Shortfall>,
    queue: Option<QueueRefusal>,
    /// Capacity kept for earlier queued requests and what reclamation did; boxed, and
    /// absent when neither applies.
    context: Option<Box<Context>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Context {
    kept_for: Vec<QueueClaim>,
    reclaim: Option<LadderReport>,
}

impl CapacityError {
    /// Orders shortfalls so that the one deciding the outcome comes first: an exceeded
    /// limit, then an unobserved capacity, then a hold, then a release to wait for.
    pub(super) fn from_shortfalls(mut shortfalls: Vec<Shortfall>) -> Option<Self> {
        shortfalls.sort_by_key(|shortfall| shortfall.prospect.rank());
        let mut shortfalls = shortfalls.into_iter();
        let limiting = shortfalls.next()?;
        Some(Self {
            limiting: Box::new(limiting),
            others: shortfalls.collect(),
            queue: None,
            context: None,
        })
    }

    pub(super) fn with_queue(mut self, refusal: QueueRefusal) -> Self {
        self.queue = Some(refusal);
        self
    }

    /// Names the earlier queued requests whose claims kept capacity from this request.
    pub(super) fn with_kept_for(mut self, kept_for: Vec<QueueClaim>) -> Self {
        if !kept_for.is_empty() {
            self.context.get_or_insert_with(Box::default).kept_for = kept_for;
        }
        self
    }

    /// Records what reclamation did when the request was admitted.
    pub(super) fn with_reclaim(mut self, report: LadderReport) -> Self {
        self.context.get_or_insert_with(Box::default).reclaim = Some(report);
        self
    }

    /// Keeps the reclamation record of an earlier error of the same request.
    pub(super) fn with_reclaim_of(self, earlier: &CapacityError) -> Self {
        match earlier.reclaim() {
            Some(report) => self.with_reclaim(report.clone()),
            None => self,
        }
    }

    /// The shortfall that decides the outcome.
    pub fn limiting(&self) -> &Shortfall {
        &self.limiting
    }

    /// The limiting resource.
    pub fn resource(&self) -> ResourceKey {
        self.limiting.resource
    }

    /// Every shortfall, the limiting one first.
    pub fn shortfalls(&self) -> impl Iterator<Item = &Shortfall> {
        std::iter::once(&*self.limiting).chain(self.others.iter())
    }

    /// Whether a retry can make progress: no limit is exceeded outright.
    pub fn retry_can_progress(&self) -> bool {
        self.shortfalls()
            .all(|shortfall| shortfall.prospect.can_progress())
    }

    /// Whether waiting for releases alone can let the request fit.
    pub fn waitable(&self) -> bool {
        self.shortfalls()
            .all(|shortfall| shortfall.prospect.waitable())
    }

    /// Why the request was not queued, when the ledger refused it.
    pub fn queue_refusal(&self) -> Option<QueueRefusal> {
        self.queue
    }

    /// Earlier queued requests whose demand was kept ahead of this request by the queue's
    /// fairness rules, so that it did not fit even where the capacity was otherwise free.
    pub fn kept_for(&self) -> &[QueueClaim] {
        self.context
            .as_deref()
            .map_or(&[], |context| context.kept_for.as_slice())
    }

    /// What the reclamation ladder did when the request was admitted, when one was lent:
    /// each step tried and why it freed nothing (GPU-W05).
    pub fn reclaim(&self) -> Option<&LadderReport> {
        self.context
            .as_deref()
            .and_then(|context| context.reclaim.as_ref())
    }
}

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.limiting)?;
        for other in &self.others {
            write!(f, "; also {other}")?;
        }
        let mut separator = "; capacity is kept for ";
        for claim in self.kept_for() {
            write!(f, "{separator}{claim}")?;
            separator = " and ";
        }
        match self.queue {
            None | Some(QueueRefusal::NotRequested) | Some(QueueRefusal::NotWaitable) => {}
            Some(QueueRefusal::Full { max_entries }) => {
                write!(f, "; the queue is full at {max_entries} entries")?
            }
            Some(QueueRefusal::TenantFull { max_entries }) => {
                write!(f, "; the tenant already has {max_entries} queued requests")?
            }
        }
        match self.reclaim() {
            Some(report) => write!(f, "; {report}"),
            None => Ok(()),
        }
    }
}

impl std::error::Error for CapacityError {}

/// Which field of a child request differs from its parent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParentField {
    Tenant,
    Execution,
    Priority,
}

/// A state change a reservation's state does not allow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    BeginCreate,
    Reconcile,
}

/// Why the ledger refused an operation (CORE-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    /// The request does not fit; see [`CapacityError`].
    Capacity(CapacityError),
    /// A queued request reached its age limit before it fit.
    QueueWaitExpired {
        ticket: QueueTicket,
        waited: Duration,
        waiting_for: CapacityError,
    },
    /// The execution's reservations were cancelled, as on revocation (INT-02).
    ExecutionCancelled {
        execution: ExecutionId,
    },
    EmptyDemand,
    UnknownReservation {
        reservation: ReservationId,
    },
    UnknownTicket {
        ticket: QueueTicket,
    },
    UnknownHold {
        hold: HoldId,
    },
    /// The reservation is closed; its resources were returned.
    Closed {
        reservation: ReservationId,
    },
    /// The parent is closed or releasing, so nothing more is carved from it.
    ParentNotOpen {
        parent: ReservationId,
    },
    /// A child's workload is created only inside a parent whose workload exists.
    ParentNotInUse {
        parent: ReservationId,
    },
    /// A child keeps its parent's tenant, execution and priority.
    ParentMismatch {
        parent: ReservationId,
        field: ParentField,
    },
    NestingTooDeep {
        max_depth: u8,
    },
    InvalidTransition {
        reservation: ReservationId,
        state: ReservationState,
        transition: Transition,
    },
    /// Only an observation from `required` or a stronger source can change accounting
    /// (S2 CORE-03, S3.2).
    SourceNotAuthoritative {
        source: SourceClass,
        required: SourceClass,
    },
    /// A probe is in the future, expired, or older than this resource's last probe.
    ObservationNotCurrent {
        resource: ResourceKey,
        observed_at: crate::foundation::ids::MonotonicTime,
        now: crate::foundation::ids::MonotonicTime,
    },
    /// A child's observed use does not fit its parent's room.
    ExceedsParent {
        reservation: ReservationId,
        parent: ReservationId,
        resource: ResourceKey,
        observed: u64,
        room: u64,
    },
    /// A parent cannot shrink below what its children hold.
    BelowChildren {
        reservation: ReservationId,
        resource: ResourceKey,
        observed: u64,
        children: u64,
    },
    ReserveExceedsCapacity {
        resource: ResourceKey,
        total: u64,
        supervisor_reserve: u64,
    },
    CapacityNotDeclared {
        resource: ResourceKey,
    },
    /// The device is on another machine; this ledger counts one host.
    ForeignDevice {
        device: DeviceId,
    },
    /// The ledger has issued every identifier it can.
    IdentifiersExhausted,
    /// A lifecycle owner, transition peak, shared extent or observed over-use refused the
    /// operation (S03).
    Ownership(OwnershipError),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity(error) => write!(f, "{error}"),
            Self::QueueWaitExpired {
                ticket,
                waited,
                waiting_for,
            } => write!(
                f,
                "{ticket} reached its wait limit after {} ms without fitting: {waiting_for}",
                waited.as_millis()
            ),
            Self::ExecutionCancelled { execution } => {
                write!(
                    f,
                    "the reservations of execution {execution} were cancelled"
                )
            }
            Self::EmptyDemand => f.write_str("the request reserves nothing"),
            Self::UnknownReservation { reservation } => {
                write!(f, "{reservation} was never granted by this ledger")
            }
            Self::UnknownTicket { ticket } => {
                write!(f, "{ticket} was never issued by this ledger")
            }
            Self::UnknownHold { hold } => write!(f, "{hold} was never started by this ledger"),
            Self::Closed { reservation } => write!(f, "{reservation} is closed"),
            Self::ParentNotOpen { parent } => {
                write!(
                    f,
                    "{parent} is closed or releasing; nothing more is carved from it"
                )
            }
            Self::ParentNotInUse { parent } => write!(
                f,
                "{parent} has not started creating its workload, so its children cannot"
            ),
            Self::ParentMismatch { parent, field } => {
                let field = match field {
                    ParentField::Tenant => "tenant",
                    ParentField::Execution => "execution",
                    ParentField::Priority => "priority",
                };
                write!(f, "a child of {parent} must keep its {field}")
            }
            Self::NestingTooDeep { max_depth } => {
                write!(f, "reservations nest at most {max_depth} levels deep")
            }
            Self::InvalidTransition {
                reservation,
                state,
                transition,
            } => {
                let state = match state {
                    ReservationState::Granted => "granted but not created",
                    ReservationState::InUse => "in use",
                    ReservationState::Releasing => "releasing",
                    ReservationState::Closed => "closed",
                };
                let transition = match transition {
                    Transition::BeginCreate => "begin creating its workload",
                    Transition::Reconcile => "be reconciled",
                };
                write!(f, "{reservation} is {state} and cannot {transition}")
            }
            Self::SourceNotAuthoritative { source, required } => write!(
                f,
                "a {source} is an observation, not authority; this change needs a {required}"
            ),
            Self::ObservationNotCurrent { resource, .. } => write!(
                f, "{resource}: the host probe is expired, out of order or from a future clock; refresh it"
            ),
            Self::ExceedsParent {
                reservation,
                parent,
                resource,
                observed,
                room,
            } => write!(
                f,
                "{reservation} was observed using {observed} {} of {resource}, more than the \
                 {room} its parent {parent} leaves it",
                resource.unit().name()
            ),
            Self::BelowChildren {
                reservation,
                resource,
                observed,
                children,
            } => write!(
                f,
                "{reservation} cannot shrink to {observed} {unit} of {resource} while its \
                 children hold {children} {unit}",
                unit = resource.unit().name()
            ),
            Self::ReserveExceedsCapacity {
                resource,
                total,
                supervisor_reserve,
            } => write!(
                f,
                "the supervisor reserve of {supervisor_reserve} exceeds the {total} {} of \
                 {resource}",
                resource.unit().name()
            ),
            Self::CapacityNotDeclared { resource } => {
                write!(f, "the host has not observed the capacity of {resource}")
            }
            Self::ForeignDevice { device } => {
                write!(f, "{device} is on another machine than this ledger's host")
            }
            Self::IdentifiersExhausted => {
                f.write_str("this ledger has issued every identifier it can")
            }
            Self::Ownership(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for LedgerError {}
