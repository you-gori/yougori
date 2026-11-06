//! Rung 2's sources (GPU part §3.5 steps 2 and 8; table line 540): idle staging of the
//! transfer executor and unused staging rings of the pinned host tier.
//!
//! The executor reserves its host ring and device staging pools once, before it starts,
//! as [`Requester::Transfer`] under its own operation, and gives them back only when it
//! closes ([`TransferExecutor::close`]), which it refuses while anything is known or in
//! flight. [`ExecutorStaging`] therefore offers that staging only while the executor
//! runs, is idle, holds no staging slot, and holds nothing the caller recorded in
//! [`ExecutorWork`]: every job forgotten and every destination retired, so its close
//! succeeds. The executor exposes neither its jobs nor its delivered regions, so that
//! last check rests on the caller's records.
//!
//! A pinned staging ring belongs to its owner's process; the pinned tier does not know
//! whether a ring is in use, so its user reports that ([`RingUse`]), and
//! [`PinnedRings`] gives up only rings reported idle, through the tier's reservation for
//! each pin.

use std::fmt;

use super::speculation::ExecutorWork;
use super::steps::ScratchSource;
use super::work::{lock, Candidate, Hold, LeasedBy, StopError, WorkSource};
use crate::foundation::coordination::SharedLedger;
use crate::foundation::ids::{Clock, OperationId};
use crate::foundation::ledger::{Requester, ReservationId, ResourceKey};
use crate::model_memory::executor::{Lifecycle, StagingPlace, TransferExecutor};
use crate::model_memory::tiers::{PinId, PinnedHostTier};

/// The staging pools of one transfer executor, named by the executor's own operation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutorStagingPools(pub OperationId);

impl fmt::Display for ExecutorStagingPools {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "staging pools of transfer executor {}", self.0)
    }
}

/// Rung 2's source over one transfer executor's staging.
pub struct ExecutorStaging<'a, E: Clock, L: Clock> {
    executor: &'a mut TransferExecutor<E>,
    operation: OperationId,
    work: &'a ExecutorWork,
    ledger: SharedLedger<L>,
}

impl<'a, E: Clock, L: Clock> ExecutorStaging<'a, E, L> {
    /// The staging of `executor`, configured with `operation`
    /// ([`ExecutorConfig::operation`](crate::model_memory::executor::ExecutorConfig)),
    /// reserved in `ledger`; `work` is what the caller submitted to it.
    pub fn new(
        executor: &'a mut TransferExecutor<E>,
        operation: OperationId,
        work: &'a ExecutorWork,
        ledger: SharedLedger<L>,
    ) -> Self {
        Self {
            executor,
            operation,
            work,
            ledger,
        }
    }

    /// What holds the staging now, given the devices it has pools on.
    fn hold(&self, places: &[StagingPlace]) -> Option<Hold> {
        match self.executor.lifecycle() {
            Lifecycle::Running => {}
            // After a fault staging may still be in use; a closed executor holds none.
            Lifecycle::Faulted { .. } => return Some(Hold::Leased(LeasedBy::InFlight)),
            Lifecycle::Closed => return None,
        }
        let slots_in_use = places.iter().any(|place| {
            self.executor
                .staging_usage(*place)
                .is_some_and(|usage| usage.in_use > 0)
        });
        Some(if !self.executor.is_idle() || slots_in_use {
            Hold::Leased(LeasedBy::InFlight)
        } else if !self.work.is_empty() {
            Hold::Leased(LeasedBy::OtherWork {
                holders: self.work.outstanding(),
            })
        } else {
            Hold::Free
        })
    }
}

impl<E: Clock, L: Clock> WorkSource for ExecutorStaging<'_, E, L> {
    type Work = ExecutorStagingPools;

    fn owner(&self) -> Requester {
        Requester::Transfer
    }

    fn survey(&mut self) -> Vec<Candidate<ExecutorStagingPools>> {
        let mut reservations: Vec<ReservationId> = Vec::new();
        let mut places = vec![StagingPlace::Host];
        {
            let ledger = lock(&self.ledger);
            for record in ledger.open_reservations() {
                let provenance = record.provenance();
                if provenance.requester != Requester::Transfer
                    || provenance.operation != self.operation
                {
                    continue;
                }
                reservations.push(record.id());
                for resource in record.current().resources() {
                    if let ResourceKey::Vram(device) = resource {
                        let place = StagingPlace::Device {
                            device: device.key(),
                        };
                        if !places.contains(&place) {
                            places.push(place);
                        }
                    }
                }
            }
        }
        let Some(hold) = self.hold(&places) else {
            return Vec::new();
        };
        if reservations.is_empty() {
            return Vec::new();
        }
        vec![Candidate {
            work: ExecutorStagingPools(self.operation.clone()),
            reservations,
            hold,
            rank: 0.0,
        }]
    }

    /// Closes the executor, which gives its staging back through its own port, which
    /// locks the shared ledger. A new executor must be started for later transfers.
    fn stop(&mut self, _work: &ExecutorStagingPools) -> Result<(), StopError> {
        self.executor
            .close()
            .map_err(|error| StopError::Close(Box::new(error)))
    }
}

impl<E: Clock, L: Clock> ScratchSource for ExecutorStaging<'_, E, L> {}

/// One staging ring of the pinned host tier, as its user reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingUse {
    pub pin: PinId,
    /// Whether transfers use the ring now or will before it is given back.
    pub in_use: bool,
}

/// One pinned staging ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinnedRing(pub PinId);

impl fmt::Display for PinnedRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pinned staging ring {:?}", self.0)
    }
}

/// Rung 2's source over the pinned host tier's staging rings.
pub struct PinnedRings<'a, L: Clock> {
    tier: &'a mut PinnedHostTier,
    rings: &'a [RingUse],
    ledger: SharedLedger<L>,
}

impl<'a, L: Clock> PinnedRings<'a, L> {
    /// The staging rings `rings` of `tier`, reserved in `ledger`.
    pub fn new(
        tier: &'a mut PinnedHostTier,
        rings: &'a [RingUse],
        ledger: SharedLedger<L>,
    ) -> Self {
        Self {
            tier,
            rings,
            ledger,
        }
    }
}

impl<L: Clock> WorkSource for PinnedRings<'_, L> {
    type Work = PinnedRing;

    fn owner(&self) -> Requester {
        Requester::ModelPlacement
    }

    fn survey(&mut self) -> Vec<Candidate<PinnedRing>> {
        self.rings
            .iter()
            .filter_map(|ring| {
                let reservation = self.tier.reservation(ring.pin).ok()?;
                Some(Candidate {
                    work: PinnedRing(ring.pin),
                    reservations: vec![reservation],
                    hold: if ring.in_use {
                        Hold::Leased(LeasedBy::InFlight)
                    } else {
                        Hold::Free
                    },
                    rank: 0.0,
                })
            })
            .collect()
    }

    /// Unpins the ring; the tier gives its reservation back through the ledger, where it
    /// is already releasing.
    fn stop(&mut self, work: &PinnedRing) -> Result<(), StopError> {
        let mut ledger = lock(&self.ledger);
        self.tier
            .unpin(work.0, &mut ledger)
            .map(|_| ())
            .map_err(|refusal| StopError::Pinned(Box::new(refusal)))
    }
}

impl<L: Clock> ScratchSource for PinnedRings<'_, L> {}
