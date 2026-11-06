//! Who and what owns a reservation beyond its request (S03 in
//! docs/combined-plan-leftover-tasks.md; CORE-03 in
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2 line 212; GPU-W02 line 1182:
//! "Supply model demand and GPU allocation accounting to CORE-03, including transition
//! peaks and shared physical allocations").
//!
//! Four parts, each in its own module beside this one:
//!
//! - `lifecycle`: a parent reservation owned by a lifecycle, one execution, one VM boot or
//!   one model activation generation, under its tenant. When the lifecycle drains,
//!   nothing more is carved from what it owns; when it ends or is revoked, what it owns is
//!   released with everything carved from it.
//! - `transition`: a bounded, time-limited transition peak on a steady reservation, for
//!   the overlap while a new generation loads before the old one releases (GPU part §3.6
//!   step 1), admitted against the same capacity and falling back to the steady amounts.
//! - `sharing`: one physical extent several holders share, counted once, released when
//!   its last holder leaves, and attributed to each holder for cost without double
//!   counting (GPU part §2.7, §3.7).
//! - `observed`: an authoritative observation of the actual allocations of each owner.
//!   Use beyond a reservation is counted and flagged, and the owner may grow no further;
//!   unused amounts are recorded and kept.
//!
//! This module holds their state inside the [`Ledger`], the refusal they share
//! ([`OwnershipError`]), and the three places where the ledger consults them: before
//! anything new is carved from a reservation or grown on it, before a reservation is
//! cancelled, and each time the queue is served, when time limits and departed holders
//! are settled.

use std::fmt;
use std::time::Duration;

use super::lifecycle::{Lifecycle, LifecycleEnd, LifecycleStatus, Lifecycles};
use super::observed::Usage;
use super::sharing::{ExtentKey, ShareRefusal, Shares};
use super::transition::Peaks;
use super::{Ledger, ReleaseOutcome};
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::ledger::{Amounts, LedgerError, ParentField, ReservationId, ResourceKey};

/// The ownership state one ledger keeps.
#[derive(Debug, Default)]
pub(super) struct Ownership {
    pub(super) lifecycles: Lifecycles,
    pub(super) peaks: Peaks,
    pub(super) shares: Shares,
    pub(super) usage: Usage,
}

/// Why nothing more may be carved from a reservation or grown on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrowthRefusal {
    /// The lifecycle that owns it drains: what it holds keeps running, nothing new starts
    /// (GPU part §3.6 step 6).
    LifecycleDraining {
        lifecycle: Lifecycle,
        since: MonotonicTime,
    },
    /// The lifecycle that owns it ended or was revoked.
    LifecycleEnded {
        lifecycle: Lifecycle,
        end: LifecycleEnd,
        at: MonotonicTime,
    },
    /// An authoritative observation found it using this much beyond its reservation.
    OverUse { excess: Amounts },
    /// Its transition peak outlived its window while its workload exists; it stays counted
    /// until its end is observed.
    PeakOverdue { deadline: MonotonicTime },
}

impl fmt::Display for GrowthRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LifecycleDraining { lifecycle, .. } => write!(f, "{lifecycle} is draining"),
            Self::LifecycleEnded { lifecycle, end, .. } => write!(f, "{lifecycle} {end}"),
            Self::OverUse { excess } => {
                f.write_str("it was observed using more than it reserved")?;
                let mut separator = ": ";
                for (resource, amount) in excess.iter() {
                    write!(
                        f,
                        "{separator}{amount} {} of {resource}",
                        resource.unit().name()
                    )?;
                    separator = ", ";
                }
                Ok(())
            }
            Self::PeakOverdue { deadline } => write!(
                f,
                "its transition peak passed its deadline at {} ns and is counted until its end \
                 is observed",
                deadline.as_nanos()
            ),
        }
    }
}

/// Why the ledger refused an ownership operation (S03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnershipError {
    /// Nothing more may be carved from `reservation` or grown on it, nor on anything
    /// carved from it.
    GrowthRefused {
        reservation: ReservationId,
        reason: GrowthRefusal,
    },
    /// A reservation keeps the tenant and execution of the lifecycle that owns it.
    LifecycleMismatch { field: ParentField },
    /// The lifecycle drains or ended, so nothing new is bound to it.
    LifecycleNotLive {
        lifecycle: Lifecycle,
        status: LifecycleStatus,
    },
    /// Another lifecycle owns the reservation.
    AlreadyOwned {
        reservation: ReservationId,
        lifecycle: Lifecycle,
    },
    /// A transition peak is already open on the reservation.
    PeakAlreadyOpen { reservation: ReservationId },
    /// No transition peak is open on the reservation.
    NoPeak { reservation: ReservationId },
    /// A transition peak's window must be longer than zero and at most `max`.
    PeakWindow { window: Duration, max: Duration },
    /// A transition peak holds at most one more copy of the steady amounts, of resources
    /// the steady reservation holds.
    PeakExceedsSteady {
        reservation: ReservationId,
        resource: ResourceKey,
        peak: u64,
        steady: u64,
    },
    /// The extent is released when its last holder leaves, not before.
    ExtentHeld {
        reservation: ReservationId,
        key: ExtentKey,
        holders: usize,
    },
    /// A shared extent refused a holder or a request.
    Share {
        key: ExtentKey,
        refusal: ShareRefusal,
    },
}

impl fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GrowthRefused {
                reservation,
                reason,
            } => write!(
                f,
                "nothing more is carved from or grown on {reservation}: {reason}"
            ),
            Self::LifecycleMismatch { field } => {
                let field = match field {
                    ParentField::Tenant => "tenant",
                    ParentField::Execution => "execution",
                    ParentField::Priority => "priority",
                };
                write!(
                    f,
                    "a reservation keeps the {field} of the lifecycle that owns it"
                )
            }
            Self::LifecycleNotLive { lifecycle, status } => {
                write!(f, "{lifecycle} {status}; nothing new is bound to it")
            }
            Self::AlreadyOwned {
                reservation,
                lifecycle,
            } => write!(f, "{reservation} is already owned by {lifecycle}"),
            Self::PeakAlreadyOpen { reservation } => {
                write!(f, "{reservation} already holds a transition peak")
            }
            Self::NoPeak { reservation } => {
                write!(f, "{reservation} holds no transition peak")
            }
            Self::PeakWindow { window, max } => write!(
                f,
                "a transition peak lasts more than 0 ms and at most {} ms, not {} ms",
                max.as_millis(),
                window.as_millis()
            ),
            Self::PeakExceedsSteady {
                reservation,
                resource,
                peak,
                steady,
            } => write!(
                f,
                "a transition peak of {peak} {unit} of {resource} exceeds the {steady} {unit} \
                 {reservation} holds; the overlap is at most one more steady copy",
                unit = resource.unit().name()
            ),
            Self::ExtentHeld {
                reservation,
                key,
                holders,
            } => write!(
                f,
                "{reservation} is {key}, still held by {holders}; it is released when the last \
                 holder leaves"
            ),
            Self::Share { key, refusal } => write!(f, "{key}: {refusal}"),
        }
    }
}

impl std::error::Error for OwnershipError {}

impl From<OwnershipError> for LedgerError {
    fn from(error: OwnershipError) -> Self {
        Self::Ownership(error)
    }
}

impl<C: Clock> Ledger<C> {
    /// Why nothing new may be carved from `reservation` or grown on it: the reservation or
    /// one it is carved from belongs to a draining or ended lifecycle, was observed using
    /// more than it reserved, or holds an overdue transition peak. `None` when it may grow.
    pub(super) fn growth_refusal(&self, reservation: ReservationId) -> Option<LedgerError> {
        let mut cursor = Some(reservation);
        while let Some(id) = cursor {
            let record = self.open.get(&id)?;
            if let Some(reason) = self.growth_refusal_at(id) {
                return Some(LedgerError::Ownership(OwnershipError::GrowthRefused {
                    reservation: id,
                    reason,
                }));
            }
            cursor = record.parent;
        }
        None
    }

    fn growth_refusal_at(&self, reservation: ReservationId) -> Option<GrowthRefusal> {
        if let Some(reason) = self.lifecycle_refusal(reservation) {
            return Some(reason);
        }
        if let Some(over) = self.ownership.usage.over.get(&reservation) {
            return Some(GrowthRefusal::OverUse {
                excess: over.excess.clone(),
            });
        }
        self.ownership
            .peaks
            .open
            .get(&reservation)
            .filter(|peak| peak.overdue_since().is_some())
            .map(|peak| GrowthRefusal::PeakOverdue {
                deadline: peak.deadline(),
            })
    }

    /// Why `reservation` may not be cancelled now: it is a shared extent that live holders
    /// still hold. `None` otherwise.
    pub(super) fn share_guard(&self, reservation: ReservationId) -> Option<LedgerError> {
        let (key, holders) = self.held_extent(reservation)?;
        Some(LedgerError::Ownership(OwnershipError::ExtentHeld {
            reservation,
            key,
            holders,
        }))
    }

    /// Settles what time and other operations changed, before the queue is served: owned
    /// requests the queue granted, transition peaks past their window or absorbed by a
    /// reconciliation, holders whose reservations are gone, and state of closed
    /// reservations.
    pub(super) fn settle_ownership(&mut self, now: MonotonicTime) {
        self.resolve_pending_owners();
        self.settle_peaks(now);
        self.settle_shares(now);
        self.settle_usage();
        self.forget_lifecycles();
    }

    /// Cancels a reservation whatever shares it: a lifecycle that owns an extent releases
    /// it even while holders remain, and they lose it.
    pub(super) fn release_owned(
        &mut self,
        reservation: ReservationId,
        now: MonotonicTime,
    ) -> Result<ReleaseOutcome, LedgerError> {
        self.unshare(reservation, now);
        self.cancel_at(reservation, now)
    }
}
