//! Rung 1 over the transfer executor (GPU part §2.9, §3.5): speculative jobs no request
//! waits for yet are cancelled at a safe boundary, and their destination reservations are
//! given up.
//!
//! The executor files each new destination of a job in the ledger as
//! [`Requester::Transfer`], under the job's operation, as background work when the job is
//! speculative, and marks it in use at submission. It lists neither its jobs nor the
//! ledger reservation of each operation, so the caller records what it submits in
//! [`ExecutorWork`] and [`ExecutorSpeculation`] finds each job's reservations in the
//! ledger's own records by that provenance. A job is free to cancel only while it runs,
//! is still speculative in the prefetch scheduler (promotion reuses the same transfer and
//! makes it foreground work) and every operation it subscribes to has no other
//! subscriber: §3.5, "one cancellation cannot cancel another subscriber's work". Jobs of
//! least expected value go first (§2.9).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::steps::SpeculationSource;
use super::work::{lock, Candidate, Hold, LeasedBy, StopError, WorkSource};
use crate::foundation::coordination::SharedLedger;
use crate::foundation::ids::{Clock, OperationId};
use crate::foundation::ledger::{Priority, Requester, ReservationId, ResourceKey};
use crate::model_memory::executor::{
    AllocationKey, JobPriority, TransferExecutor, TransferRequest,
};
use crate::model_memory::math::prefetch::TransferClass;

/// What the caller submitted to one transfer executor and the executor may still know:
/// jobs not yet forgotten, and destinations whose delivered regions were not yet retired.
/// The executor does not list them, so the caller records them as it submits, forgets
/// and retires.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExecutorWork {
    jobs: BTreeMap<OperationId, RecordedJob>,
    destinations: BTreeSet<AllocationKey>,
}

#[derive(Clone, Debug, PartialEq)]
struct RecordedJob {
    extents: BTreeSet<u64>,
    /// The §2.9 expected value of a speculative job; `None` for foreground work.
    expected_value: Option<f64>,
}

impl ExecutorWork {
    /// Nothing recorded.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a job the executor admitted ([`TransferExecutor::submit`]).
    pub fn record(&mut self, request: &TransferRequest) {
        let extents = request
            .dependencies
            .iter()
            .flat_map(|dependency| dependency.extents.iter().copied())
            .collect();
        let expected_value = match &request.priority {
            JobPriority::Speculative { value } => Some(value.expected_value),
            JobPriority::Foreground => None,
        };
        self.destinations.insert(request.destination.allocation);
        self.jobs.insert(
            request.operation.clone(),
            RecordedJob {
                extents,
                expected_value,
            },
        );
    }

    /// Forgets a job the executor forgot ([`TransferExecutor::forget`]); returns whether
    /// it was recorded.
    pub fn forget(&mut self, operation: &OperationId) -> bool {
        self.jobs.remove(operation).is_some()
    }

    /// Forgets a destination whose delivered regions the executor retired
    /// ([`TransferExecutor::retire_destination`]); returns whether it was recorded.
    pub fn retire(&mut self, allocation: &AllocationKey) -> bool {
        self.destinations.remove(allocation)
    }

    /// The jobs recorded and not forgotten.
    pub fn jobs(&self) -> impl Iterator<Item = &OperationId> {
        self.jobs.keys()
    }

    /// How many jobs and unretired destinations the executor may still hold.
    pub fn outstanding(&self) -> usize {
        self.jobs.len().saturating_add(self.destinations.len())
    }

    /// Whether the executor holds nothing the caller submitted: every job forgotten and
    /// every destination retired.
    pub fn is_empty(&self) -> bool {
        self.outstanding() == 0
    }
}

/// A speculative job of the executor, named by its operation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpeculativeJob(pub OperationId);

impl fmt::Display for SpeculativeJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "speculative job {}", self.0)
    }
}

/// Rung 1's source over one transfer executor and the host's shared ledger.
pub struct ExecutorSpeculation<'a, E: Clock, L: Clock> {
    executor: &'a mut TransferExecutor<E>,
    work: &'a ExecutorWork,
    ledger: SharedLedger<L>,
}

impl<'a, E: Clock, L: Clock> ExecutorSpeculation<'a, E, L> {
    /// The speculative jobs among `work` on `executor`, whose reservations are in
    /// `ledger`, the ledger the executor reserves in.
    pub fn new(
        executor: &'a mut TransferExecutor<E>,
        work: &'a ExecutorWork,
        ledger: SharedLedger<L>,
    ) -> Self {
        Self {
            executor,
            work,
            ledger,
        }
    }

    /// The largest number of jobs subscribed to any operation of `operation`'s job.
    fn most_subscribers(&self, operation: &OperationId, extents: &BTreeSet<u64>) -> usize {
        extents
            .iter()
            .filter_map(|extent| self.executor.flight_of(operation, *extent))
            .filter_map(|flight| self.executor.subscribers(flight))
            .max()
            .unwrap_or(0)
    }
}

impl<E: Clock, L: Clock> WorkSource for ExecutorSpeculation<'_, E, L> {
    type Work = SpeculativeJob;

    fn owner(&self) -> Requester {
        Requester::Transfer
    }

    fn survey(&mut self) -> Vec<Candidate<SpeculativeJob>> {
        // Destination reservations of background transfers, by the job that filed them.
        let mut filed: BTreeMap<OperationId, Vec<ReservationId>> = BTreeMap::new();
        {
            let ledger = lock(&self.ledger);
            for record in ledger.open_reservations() {
                let provenance = record.provenance();
                let destination = !record.current().is_empty()
                    && record
                        .current()
                        .resources()
                        .all(|resource| matches!(resource, ResourceKey::Vram(_)));
                if provenance.requester == Requester::Transfer
                    && record.priority() == Priority::Background
                    && destination
                {
                    filed
                        .entry(provenance.operation.clone())
                        .or_default()
                        .push(record.id());
                }
            }
        }
        let mut candidates = Vec::new();
        for (operation, job) in &self.work.jobs {
            let Some(expected_value) = job.expected_value else {
                continue;
            };
            let running = self
                .executor
                .status(operation)
                .is_some_and(|status| status.is_running());
            let speculative = self
                .executor
                .scheduler()
                .transfer(operation)
                .is_some_and(|transfer| transfer.class() == TransferClass::Speculative);
            if !running || !speculative {
                continue;
            }
            let subscribers = self.most_subscribers(operation, &job.extents);
            let hold = if subscribers > 1 {
                Hold::Leased(LeasedBy::OtherWork {
                    holders: subscribers - 1,
                })
            } else {
                Hold::Free
            };
            candidates.push(Candidate {
                work: SpeculativeJob(operation.clone()),
                reservations: filed.remove(operation).unwrap_or_default(),
                hold,
                rank: expected_value,
            });
        }
        candidates
    }

    /// Cancels the job at a safe boundary: its operations no other job shares are
    /// reclaimed at once or once their read or copy drains, and the executor gives their
    /// reservations back through its own port, which locks the shared ledger.
    fn stop(&mut self, work: &SpeculativeJob) -> Result<(), StopError> {
        self.executor
            .cancel(&work.0)
            .map(|_| ())
            .map_err(|error| StopError::Cancel(Box::new(error)))
    }
}

impl<E: Clock, L: Clock> SpeculationSource for ExecutorSpeculation<'_, E, L> {}
