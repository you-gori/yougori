//! Transition peaks (S03; GPU part §3.6 line 761, activation step 1: "reserve
//! steady-state plus transition peaks"; §2.7's `activation_overlap`; GPU-W02 line 1182).
//!
//! While a new generation loads, the old one still serves, so for a while a reservation
//! holds more than its steady amounts: the overlap. A transition peak is that overlap,
//! reserved on the steady reservation itself, so that whatever is carved from it during
//! the switch fits in it, as from any parent:
//!
//! - It is bounded: it holds only resources the steady reservation holds, at most one
//!   more copy of each, and lasts a window of at most [`MAX_TRANSITION_WINDOW`]. Its size
//!   is the caller's peak estimate, such as `model_memory::transitions::PeakEstimate`;
//!   the ledger does not estimate it.
//! - It is admitted against the same capacity as the steady reservation: physical
//!   capacity and the tenant's budget at host level, the parent's room for a child, and
//!   the queue's fairness claims, all at once or not at all. It never waits: when it does
//!   not fit, drain first and report a real pause (§3.6).
//! - It falls back to the steady amounts when the switch completes or rolls back
//!   ([`PeakEnd`]). Before the steady workload is created that is immediate. After, it
//!   needs the same authority as a release, a host observation at host level and the
//!   runtime's report for a child, and what remains carved from the reservation must fit
//!   its steady amounts: the old generation's release is observed first (§3.6 step 7).
//! - When its window passes, a peak whose workload was never created falls back on its
//!   own. One whose workload exists is overdue: it stays counted, because nothing
//!   observed its end, and nothing more is carved from or grown on the reservation until
//!   an authoritative end settles it.
//!
//! An authoritative reconciliation of the reservation while the peak is open replaces its
//! amounts with what is in use, the overlap included, and so ends the peak.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::ownership::OwnershipError;
use super::{release_authority, require_source, Charge, Ledger};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::ledger::{
    AmountChange, Amounts, ChangeCause, LedgerError, QueuePolicy, QueueRefusal, ReservationId,
    ReservationRequest, ReservationState,
};

/// The longest window a transition peak may ask for. A switch that needs longer is a
/// different plan: drain first and report a real pause (GPU part §3.6).
pub const MAX_TRANSITION_WINDOW: Duration = Duration::from_secs(3_600);

/// How many records of ended transition peaks the ledger keeps until they are taken;
/// older ones are dropped first and counted.
pub const MAX_PEAK_RECORDS: usize = 1_024;

/// How the switch a transition peak covered ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeakEnd {
    /// The new generation serves and the old one's release was observed.
    Completed,
    /// The new generation was abandoned and its release observed; the old one serves.
    RolledBack,
}

/// How a transition peak ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeakOutcome {
    Completed,
    RolledBack,
    /// Its window passed before its workload was created, so it fell back on its own.
    Expired,
    /// An authoritative reconciliation set the reservation to what is in use.
    Reconciled,
    /// The reservation closed with the peak.
    SteadyClosed,
}

/// A transition peak open on a steady reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionPeak {
    steady: ReservationId,
    peak: Amounts,
    began_at: MonotonicTime,
    deadline: MonotonicTime,
    overdue_since: Option<MonotonicTime>,
    /// The index of the change that added the peak in the reservation's history.
    began_change: usize,
}

impl TransitionPeak {
    /// The steady reservation the peak is on.
    pub fn steady(&self) -> ReservationId {
        self.steady
    }

    /// The amounts held beyond the steady ones.
    pub fn peak(&self) -> &Amounts {
        &self.peak
    }

    pub fn began_at(&self) -> MonotonicTime {
        self.began_at
    }

    /// When its window ends.
    pub fn deadline(&self) -> MonotonicTime {
        self.deadline
    }

    /// When it was found past its window with its workload created; `None` while it is not
    /// overdue.
    pub fn overdue_since(&self) -> Option<MonotonicTime> {
        self.overdue_since
    }
}

/// The record of a transition peak that ended. The ledger's
/// [`LedgerHistory`](crate::foundation::ledger::LedgerHistory) takes and exports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeakRecord {
    pub steady: ReservationId,
    pub peak: Amounts,
    pub began_at: MonotonicTime,
    pub deadline: MonotonicTime,
    pub ended_at: MonotonicTime,
    pub outcome: PeakOutcome,
}

/// The transition peaks of one ledger.
#[derive(Debug, Default)]
pub(super) struct Peaks {
    pub(super) open: BTreeMap<ReservationId, TransitionPeak>,
    records: Vec<PeakRecord>,
    dropped: u64,
}

impl<C: Clock> Ledger<C> {
    /// Adds a transition peak of `peak` to the open reservation `steady` for at most
    /// `window`, and returns its deadline (see the module documentation). Refused when it
    /// does not fit now, when the reservation is releasing, already holds a peak or may
    /// not grow, or when the peak is not bounded by the steady amounts and the window.
    pub fn begin_transition_peak(
        &mut self,
        steady: ReservationId,
        peak: Amounts,
        window: Duration,
    ) -> Result<MonotonicTime, LedgerError> {
        self.run(|ledger, now| {
            if window.is_zero() || window > MAX_TRANSITION_WINDOW {
                return Err(OwnershipError::PeakWindow {
                    window,
                    max: MAX_TRANSITION_WINDOW,
                }
                .into());
            }
            if peak.is_empty() {
                return Err(LedgerError::EmptyDemand);
            }
            let record = ledger.open_record(steady)?;
            if record.state == ReservationState::Releasing {
                return Err(LedgerError::ParentNotOpen { parent: steady });
            }
            if ledger.ownership.peaks.open.contains_key(&steady) {
                return Err(OwnershipError::PeakAlreadyOpen {
                    reservation: steady,
                }
                .into());
            }
            for (resource, amount) in peak.iter() {
                ledger.check_device(resource)?;
                let held = record.current.get(resource);
                if amount > held {
                    return Err(OwnershipError::PeakExceedsSteady {
                        reservation: steady,
                        resource,
                        peak: amount,
                        steady: held,
                    }
                    .into());
                }
            }
            if let Some(error) = ledger.growth_refusal(steady) {
                return Err(error);
            }
            let request = ReservationRequest {
                provenance: record.provenance.clone(),
                priority: record.priority,
                parent: record.parent,
                demand: peak.clone(),
                queue: QueuePolicy::NoWait,
            };
            if let Some(error) = ledger.fit(&request, now, &ledger.waiting_claims())? {
                return Err(LedgerError::Capacity(
                    error.with_queue(QueueRefusal::NotRequested),
                ));
            }
            let deadline = now.saturating_add(window);
            let Some(record) = ledger.open.get_mut(&steady) else {
                return Err(LedgerError::Closed {
                    reservation: steady,
                });
            };
            let amounts = peak
                .iter()
                .fold(record.current.clone(), |total, (resource, amount)| {
                    total.with(resource, amount)
                });
            record.current = amounts.clone();
            let began_change = record.history.len();
            record.history.push(AmountChange {
                at: now,
                amounts,
                cause: ChangeCause::TransitionPeakBegan,
            });
            ledger.ownership.peaks.open.insert(
                steady,
                TransitionPeak {
                    steady,
                    peak,
                    began_at: now,
                    deadline,
                    overdue_since: None,
                    began_change,
                },
            );
            ledger.count_bypasses(&[Charge::of(None, &request)], now);
            Ok(deadline)
        })
    }

    /// Ends the transition peak on `steady` and returns the amounts given back. Before the
    /// steady workload is created this needs no authority. After, `source` must have the
    /// authority of a release, and what is carved from the reservation must fit its steady
    /// amounts. An overdue peak is settled the same way.
    pub fn end_transition_peak(
        &mut self,
        steady: ReservationId,
        end: PeakEnd,
        source: SourceClass,
    ) -> Result<Amounts, LedgerError> {
        self.run(|ledger, now| {
            let record = ledger.open_record(steady)?;
            let Some(peak) = ledger.ownership.peaks.open.get(&steady) else {
                return Err(OwnershipError::NoPeak {
                    reservation: steady,
                }
                .into());
            };
            if record.state != ReservationState::Granted {
                require_source(source, release_authority(record.parent))?;
            }
            let steady_amounts = record.current.excess_over(&peak.peak);
            for resource in ledger.child_resources(steady) {
                let children = ledger.children_sum(steady, resource);
                if children > u128::from(steady_amounts.get(resource)) {
                    return Err(LedgerError::BelowChildren {
                        reservation: steady,
                        resource,
                        observed: steady_amounts.get(resource),
                        children: super::to_u64(children),
                    });
                }
            }
            let outcome = match end {
                PeakEnd::Completed => PeakOutcome::Completed,
                PeakEnd::RolledBack => PeakOutcome::RolledBack,
            };
            Ok(ledger.fall_back(steady, outcome, now))
        })
    }

    /// The transition peak open on `steady`.
    pub fn transition_peak(&self, steady: ReservationId) -> Option<&TransitionPeak> {
        self.ownership.peaks.open.get(&steady)
    }

    /// Every open transition peak, by steady reservation.
    pub fn transition_peaks(&self) -> impl Iterator<Item = &TransitionPeak> {
        self.ownership.peaks.open.values()
    }

    /// Records of transition peaks that ended and were not yet taken, oldest first; at
    /// most [`MAX_PEAK_RECORDS`].
    pub fn peak_records(&self) -> &[PeakRecord] {
        &self.ownership.peaks.records
    }

    /// Hands the records of ended transition peaks over.
    pub fn take_peak_records(&mut self) -> Vec<PeakRecord> {
        std::mem::take(&mut self.ownership.peaks.records)
    }

    /// How many records of ended transition peaks were dropped untaken.
    pub fn peak_records_dropped(&self) -> u64 {
        self.ownership.peaks.dropped
    }

    /// Ends peaks whose reservation closed or was reconciled, lets a peak past its window
    /// fall back when its workload was never created, and marks it overdue otherwise.
    pub(super) fn settle_peaks(&mut self, now: MonotonicTime) {
        let steadies: Vec<ReservationId> = self.ownership.peaks.open.keys().copied().collect();
        for steady in steadies {
            let Some(peak) = self.ownership.peaks.open.get(&steady) else {
                continue;
            };
            let Some(record) = self.open.get(&steady) else {
                self.finish_peak(steady, PeakOutcome::SteadyClosed, now);
                continue;
            };
            let reconciled = record
                .history
                .iter()
                .skip(peak.began_change.saturating_add(1))
                .any(|change| matches!(change.cause, ChangeCause::Reconciled { .. }));
            if reconciled {
                self.finish_peak(steady, PeakOutcome::Reconciled, now);
                continue;
            }
            if now <= peak.deadline || peak.overdue_since.is_some() {
                continue;
            }
            let steady_amounts = record.current.excess_over(&peak.peak);
            let fits = self.child_resources(steady).into_iter().all(|resource| {
                self.children_sum(steady, resource) <= u128::from(steady_amounts.get(resource))
            });
            if record.state == ReservationState::Granted && fits {
                self.fall_back(steady, PeakOutcome::Expired, now);
            } else if let Some(peak) = self.ownership.peaks.open.get_mut(&steady) {
                peak.overdue_since = Some(now);
            }
        }
    }

    /// Takes the peak off the steady reservation and records how it ended; returns what
    /// was given back.
    fn fall_back(
        &mut self,
        steady: ReservationId,
        outcome: PeakOutcome,
        now: MonotonicTime,
    ) -> Amounts {
        let (Some(peak), Some(record)) = (
            self.ownership.peaks.open.get(&steady),
            self.open.get_mut(&steady),
        ) else {
            return Amounts::new();
        };
        let steady_amounts = record.current.excess_over(&peak.peak);
        let returned = record.current.excess_over(&steady_amounts);
        record.current = steady_amounts.clone();
        record.history.push(AmountChange {
            at: now,
            amounts: steady_amounts,
            cause: ChangeCause::TransitionPeakEnded,
        });
        self.finish_peak(steady, outcome, now);
        returned
    }

    fn finish_peak(&mut self, steady: ReservationId, outcome: PeakOutcome, now: MonotonicTime) {
        let peaks = &mut self.ownership.peaks;
        let Some(peak) = peaks.open.remove(&steady) else {
            return;
        };
        peaks.records.push(PeakRecord {
            steady,
            peak: peak.peak,
            began_at: peak.began_at,
            deadline: peak.deadline,
            ended_at: now,
            outcome,
        });
        let excess = peaks.records.len().saturating_sub(MAX_PEAK_RECORDS);
        if excess > 0 {
            peaks.records.drain(..excess);
            peaks.dropped = peaks
                .dropped
                .saturating_add(u64::try_from(excess).unwrap_or(u64::MAX));
        }
    }
}
