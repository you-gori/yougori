//! Observed allocations per owner (S03: "actual allocation observations", "finer observed
//! allocation ownership"; S2 CORE-03 line 212: unknown guest usage is never verified free
//! capacity; S10 line 351; GPU part §2.7 and §3.7: physical allocations, not mapped bytes,
//! are what is used).
//!
//! A source with authority, the same as for a release (a host observation at host level,
//! the runtime's own report for a child), observes what each owner, one open reservation,
//! actually holds: everything its workload allocated, its children's included. Every
//! owner's observation is checked before any is applied, so a refused observation changes
//! nothing.
//!
//! - Use beyond the reservation is counted, never ignored: the owner's amounts grow to
//!   what was observed. A child whose parent has no room left for it grows the parent as
//!   far as the source has the parent's own authority too: a host observation reaches host
//!   level, where the use counts against physical capacity and the tenant's budget, so
//!   the ledger never shows memory in use as free. A runtime's report never changes
//!   host-level amounts: past its authority the use is reported as uncounted and the
//!   ancestor is flagged instead, since the host enforces its parents (S3.2).
//! - The owner, and every ancestor that had to grow or could not, is flagged
//!   ([`OverUse`]): nothing more is carved from or grown on it until an observation with
//!   its authority finds it back within what it was entitled to, or an authoritative
//!   reconciliation brings it back.
//! - Use below the reservation is recorded ([`UnderUse`]) and kept: an observation never
//!   returns amounts on its own. Returning them is an explicit
//!   [`Ledger::reconcile`](super::Ledger::reconcile) or release by its owner.
//!
//! An observation of a reservation that closed meanwhile is reported and skipped. One of a
//! reservation whose workload was never created is refused, as a reconciliation is.

use std::collections::BTreeMap;

use super::{release_authority, require_source, Ledger};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::ledger::{
    AmountChange, Amounts, ChangeCause, LedgerError, RecordedObservation, ReservationId,
    ReservationState, Transition,
};

/// What a source with authority observed each owner actually holding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationObservation {
    pub source: SourceClass,
    /// Per open reservation, everything its workload holds, its children's included.
    pub usage: BTreeMap<ReservationId, Amounts>,
}

/// What an observation found for one owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerFinding {
    pub reservation: ReservationId,
    /// Use beyond what it held.
    pub over: Amounts,
    /// The part of `over` the source had no authority to count: it exceeds the room of an
    /// ancestor whose amounts only a stronger source changes. That ancestor is flagged.
    pub uncounted: Amounts,
    /// Held and unused, recorded and kept.
    pub under: Amounts,
    /// Ancestors that grew because their room could not hold the use beyond, innermost
    /// first.
    pub grew: Vec<ReservationId>,
}

/// What an observation did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllocationReport {
    /// One finding per open owner, deepest first.
    pub findings: Vec<OwnerFinding>,
    /// Owners that closed before the observation was applied; nothing changed for them.
    pub closed: Vec<ReservationId>,
}

/// A reservation observed using more than it was entitled to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverUse {
    pub reservation: ReservationId,
    /// When use beyond its entitlement was first observed.
    pub since: MonotonicTime,
    /// The latest observation that found it.
    pub observed_at: MonotonicTime,
    pub source: SourceClass,
    /// What it held before use beyond was first counted.
    pub entitled: Amounts,
    /// The use beyond `entitled` observed so far, counted or not.
    pub excess: Amounts,
}

/// A reservation observed using less than it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnderUse {
    pub reservation: ReservationId,
    pub observed_at: MonotonicTime,
    pub source: SourceClass,
    /// Held and unused at the latest observation.
    pub unused: Amounts,
}

/// The over- and under-use one ledger keeps, per open reservation.
#[derive(Debug, Default)]
pub(super) struct Usage {
    pub(super) over: BTreeMap<ReservationId, OverUse>,
    under: BTreeMap<ReservationId, UnderUse>,
}

/// Per resource, the larger of the two.
fn larger(left: &Amounts, right: &Amounts) -> Amounts {
    let mut larger = left.clone();
    for (resource, amount) in right.iter() {
        larger.set(resource, amount.max(left.get(resource)));
    }
    larger
}

impl<C: Clock> Ledger<C> {
    /// Applies an authoritative observation of what each owner actually holds (see the
    /// module documentation).
    pub fn observe_allocations(
        &mut self,
        observation: AllocationObservation,
    ) -> Result<AllocationReport, LedgerError> {
        self.run(|ledger, now| {
            let mut report = AllocationReport::default();
            let mut owners = Vec::new();
            for (reservation, in_use) in &observation.usage {
                let record = match ledger.open_record(*reservation) {
                    Ok(record) => record,
                    Err(LedgerError::Closed { .. }) => {
                        report.closed.push(*reservation);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if record.state == ReservationState::Granted {
                    return Err(LedgerError::InvalidTransition {
                        reservation: *reservation,
                        state: record.state,
                        transition: Transition::Reconcile,
                    });
                }
                require_source(observation.source, release_authority(record.parent))?;
                for resource in in_use.resources() {
                    ledger.check_device(resource)?;
                }
                owners.push((record.depth, *reservation));
            }
            owners.sort_by(|left, right| right.cmp(left));
            for (_, reservation) in owners {
                if let Some(in_use) = observation.usage.get(&reservation) {
                    let finding =
                        ledger.apply_observed(reservation, in_use, observation.source, now);
                    report.findings.push(finding);
                }
            }
            Ok(report)
        })
    }

    /// The over-use flagged on an open reservation.
    pub fn over_use(&self, reservation: ReservationId) -> Option<&OverUse> {
        self.ownership.usage.over.get(&reservation)
    }

    /// Every flagged over-use, by reservation.
    pub fn over_uses(&self) -> impl Iterator<Item = &OverUse> {
        self.ownership.usage.over.values()
    }

    /// The latest under-use recorded for an open reservation.
    pub fn under_use(&self, reservation: ReservationId) -> Option<&UnderUse> {
        self.ownership.usage.under.get(&reservation)
    }

    /// Every recorded under-use, by reservation.
    pub fn under_uses(&self) -> impl Iterator<Item = &UnderUse> {
        self.ownership.usage.under.values()
    }

    /// Forgets the use of closed reservations, and clears an over-use whose reservation an
    /// authoritative reconciliation brought back within its entitlement.
    pub(super) fn settle_usage(&mut self) {
        let open = &self.open;
        let usage = &mut self.ownership.usage;
        usage
            .under
            .retain(|reservation, _| open.contains_key(reservation));
        usage.over.retain(|reservation, over| {
            let Some(record) = open.get(reservation) else {
                return false;
            };
            let reconciled_within = record.history.last().is_some_and(|change| {
                change.at >= over.observed_at
                    && matches!(change.cause, ChangeCause::Reconciled { .. })
                    && change.amounts.excess_over(&over.entitled).is_empty()
            });
            !reconciled_within
        });
    }

    fn apply_observed(
        &mut self,
        reservation: ReservationId,
        in_use: &Amounts,
        source: SourceClass,
        now: MonotonicTime,
    ) -> OwnerFinding {
        let current = self
            .open
            .get(&reservation)
            .map(|record| record.current.clone())
            .unwrap_or_default();
        let over = in_use.excess_over(&current);
        let under = current.excess_over(in_use);
        if let Some(record) = self.open.get_mut(&reservation) {
            record.record_observation(RecordedObservation {
                source,
                recorded_at: now,
                in_use: in_use.clone(),
            });
        }
        let mut grew = Vec::new();
        let mut uncounted = Amounts::new();
        if !over.is_empty() {
            uncounted = self.count_over_use(reservation, &over, source, now, &mut grew);
        }
        if let Some(flag) = self.ownership.usage.over.get_mut(&reservation) {
            let beyond = in_use.excess_over(&flag.entitled);
            if beyond.is_empty() {
                self.ownership.usage.over.remove(&reservation);
            } else {
                flag.observed_at = now;
                flag.source = source;
                flag.excess = beyond;
            }
        }
        if under.is_empty() {
            self.ownership.usage.under.remove(&reservation);
        } else {
            self.ownership.usage.under.insert(
                reservation,
                UnderUse {
                    reservation,
                    observed_at: now,
                    source,
                    unused: under.clone(),
                },
            );
        }
        OwnerFinding {
            reservation,
            over,
            uncounted,
            under,
            grew,
        }
    }

    /// Counts `over` more on `reservation`. Where its parent's room cannot hold it, the
    /// parent grows first when `source` has the parent's authority, and is flagged with
    /// the rest uncounted otherwise. Returns what was not counted; flags every reservation
    /// that grew or could not.
    fn count_over_use(
        &mut self,
        reservation: ReservationId,
        over: &Amounts,
        source: SourceClass,
        now: MonotonicTime,
        grew: &mut Vec<ReservationId>,
    ) -> Amounts {
        let Some(record) = self.open.get(&reservation) else {
            return over.clone();
        };
        let entitled = record.current.clone();
        let mut uncounted = Amounts::new();
        let parent = record
            .parent
            .and_then(|parent| self.open.get(&parent))
            .map(|parent| (parent.id, parent.current.clone(), parent.parent));
        if let Some((parent, room, grandparent)) = parent {
            let mut need = Amounts::new();
            for (resource, amount) in over.iter() {
                let free = u128::from(room.get(resource))
                    .saturating_sub(self.children_sum(parent, resource));
                need.set(
                    resource,
                    super::to_u64(u128::from(amount).saturating_sub(free)),
                );
            }
            if !need.is_empty() {
                if source.satisfies(release_authority(grandparent)) {
                    uncounted = self.count_over_use(parent, &need, source, now, grew);
                    if !need.excess_over(&uncounted).is_empty() {
                        grew.insert(0, parent);
                    }
                } else {
                    self.flag_over_use(parent, room, &need, source, now);
                    uncounted = need;
                }
            }
        }
        let counted = over.excess_over(&uncounted);
        if let Some(record) = self.open.get_mut(&reservation) {
            if !counted.is_empty() {
                let amounts = counted
                    .iter()
                    .fold(record.current.clone(), |total, (resource, amount)| {
                        total.with(resource, amount)
                    });
                record.current = amounts.clone();
                record.overrun = true;
                record.history.push(AmountChange {
                    at: now,
                    amounts,
                    cause: ChangeCause::OverUseCounted { source },
                });
            }
        }
        self.flag_over_use(reservation, entitled, over, source, now);
        uncounted
    }

    /// Flags `reservation`, which held `entitled` before this observation, as observed
    /// using `beyond` more than that. A flag already raised keeps its entitlement.
    fn flag_over_use(
        &mut self,
        reservation: ReservationId,
        entitled: Amounts,
        beyond: &Amounts,
        source: SourceClass,
        now: MonotonicTime,
    ) {
        let Some(record) = self.open.get(&reservation) else {
            return;
        };
        let current = record.current.clone();
        let flag = self
            .ownership
            .usage
            .over
            .entry(reservation)
            .or_insert_with(|| OverUse {
                reservation,
                since: now,
                observed_at: now,
                source,
                entitled,
                excess: Amounts::new(),
            });
        flag.observed_at = now;
        flag.source = source;
        flag.excess = larger(
            &flag.excess,
            &larger(&current.excess_over(&flag.entitled), beyond),
        );
    }
}
