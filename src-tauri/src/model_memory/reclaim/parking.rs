//! Rung 4's sources (GPU part §3.6, §3.9; GPU-W05: "clean-drop parking only when
//! canonical state can reconstruct exact weights"): idle models parked through the
//! placement slot or through the coordination protocol.
//!
//! [`SlotParking`] offers the placements of one [`PlacementSlot`] whose steady state is
//! reserved directly in the ledger as [`Requester::ModelPlacement`]. A placement is free
//! to park only while it serves, drains, rests materialized or is parked, no request
//! lease holds it, no activation in progress uses it as its placement or its predecessor,
//! and its artifact is verified as exactly its identity, the canonical state that rebuilds
//! its weights. Resting placements go before serving ones. Stopping one drains it if it
//! serves, parks it and reclaims it (§3.6 steps 6 and 7): its extents no other placement
//! shares are freed and its steady reservation is released through the slot's own port,
//! which confirms the release with the source the placement's configuration names. The
//! slot refuses to reclaim while a process reference or a GPU completion event still uses
//! the memory; the slot does not expose them before, so that refusal is reported as
//! work not stopped.
//!
//! [`CoordinatorParking`] offers the serving activations of models the coordinator runs
//! in VM sandboxes, whose memory it reserves as [`Requester::Coordination`] children of
//! the sandbox reservation. The coordinator accounts memory, not contents, so the caller
//! says whether canonical state can rebuild each model ([`CoordinatedModel`]). An
//! activation is free to park only while no lease may still use it, and it gives up only
//! the holdings that parking leaves for [`Coordinator::confirm_gpu_released`] to close:
//! used by no other unretired activation, not weights reserved apart from activations,
//! fully reserved and promised to no successor. An activation with a holding in a
//! drain-first handover is kept. Stopping one parks it ([`Coordinator::park`]); the
//! caller confirms the release through `confirm_gpu_released` once the runtime freed the
//! memory, never in the ledger directly, and must not reactivate a parked activation
//! whose holdings were given up.

use std::fmt;

use super::steps::ParkingSource;
use super::work::{lock, Candidate, Hold, LeasedBy, PinnedBy, StopError, WorkSource};
use crate::foundation::coordination::{
    ActivationState, Coordinator, GpuReservationState, LedgerCapacity, ModelActivations, ModelId,
    ReservationKey, SharedLedger,
};
use crate::foundation::ids::{Clock, ExecutionId, ModelActivationGeneration};
use crate::foundation::ledger::{Requester, ReservationId};
use crate::model_memory::placement::{
    LedgerReservations as PlacementReservations, PlacementKey, PlacementSlot, PlacementView,
    StateKind,
};

/// One placement of a slot, to park.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdlePlacement(pub PlacementKey);

impl fmt::Display for IdlePlacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "placement {}", self.0)
    }
}

/// Rung 4's source over one placement slot whose reservations are in the ledger.
pub struct SlotParking<'a, S: Clock, L: Clock> {
    slot: &'a mut PlacementSlot<S>,
    reservations: &'a mut PlacementReservations,
    ledger: SharedLedger<L>,
}

impl<'a, S: Clock, L: Clock> SlotParking<'a, S, L> {
    /// The placements of `slot`, whose reservations `reservations` filed in `ledger`.
    pub fn new(
        slot: &'a mut PlacementSlot<S>,
        reservations: &'a mut PlacementReservations,
        ledger: SharedLedger<L>,
    ) -> Self {
        Self {
            slot,
            reservations,
            ledger,
        }
    }

    /// What holds a placement, or `None` when it is no idle model at all.
    fn hold(&self, view: &PlacementView) -> Option<Hold> {
        match view.state.kind() {
            StateKind::Serving
            | StateKind::Draining
            | StateKind::Materialized
            | StateKind::Parked => {}
            StateKind::Absent
            | StateKind::Preparing
            | StateKind::Activating
            | StateKind::Failed => return None,
        }
        let in_transition = self.slot.activation().is_some_and(|activation| {
            activation.placement == view.key || activation.predecessor == Some(view.key)
        });
        Some(if in_transition {
            Hold::Pinned(PinnedBy::Transition)
        } else if view.leases > 0 {
            Hold::Leased(LeasedBy::Requests {
                leases: view.leases,
            })
        } else if !view.artifact.is_verified_as(&view.artifact_identity) {
            Hold::Pinned(PinnedBy::NoCanonicalState)
        } else {
            Hold::Free
        })
    }
}

impl<S: Clock, L: Clock> WorkSource for SlotParking<'_, S, L> {
    type Work = IdlePlacement;

    fn owner(&self) -> Requester {
        Requester::ModelPlacement
    }

    fn survey(&mut self) -> Vec<Candidate<IdlePlacement>> {
        let mut candidates = Vec::new();
        for key in self.slot.placement_keys() {
            let Some(view) = self.slot.placement(key) else {
                continue;
            };
            let Some(steady) = view.steady_reservation else {
                continue;
            };
            let Some(hold) = self.hold(&view) else {
                continue;
            };
            let reservations = self.reservations.ledger_reservations(steady);
            if reservations.is_empty() {
                continue;
            }
            let serving = matches!(view.state.kind(), StateKind::Serving | StateKind::Draining);
            candidates.push(Candidate {
                work: IdlePlacement(key),
                reservations,
                hold,
                rank: if serving { 1.0 } else { 0.0 },
            });
        }
        candidates
    }

    /// Drains a serving placement, parks it and reclaims it through the slot's ledger
    /// port.
    fn stop(&mut self, work: &IdlePlacement) -> Result<(), StopError> {
        let key = work.0;
        let state = self
            .slot
            .placement(key)
            .ok_or(StopError::Gone)?
            .state
            .kind();
        if state == StateKind::Serving {
            self.slot
                .begin_draining(key)
                .map_err(|error| StopError::Slot(Box::new(error)))?;
        }
        if matches!(state, StateKind::Serving | StateKind::Draining) {
            self.slot
                .park(key)
                .map_err(|error| StopError::Slot(Box::new(error)))?;
        }
        let mut ledger = lock(&self.ledger);
        let mut port = self.reservations.port(&mut ledger);
        self.slot
            .reclaim(key, &mut port)
            .map(|_| ())
            .map_err(|error| StopError::Slot(Box::new(error)))
    }
}

impl<S: Clock, L: Clock> ParkingSource for SlotParking<'_, S, L> {}

/// A model the coordinator runs, and whether canonical state can rebuild its weights
/// exactly, such as a verified artifact in local storage (§3.6; GPU-W05).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatedModel {
    pub execution: ExecutionId,
    pub model: ModelId,
    pub canonical_state: bool,
}

/// One activation of a model the coordinator runs, to park.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdleActivation {
    pub execution: ExecutionId,
    pub model: ModelId,
    pub activation: ModelActivationGeneration,
}

impl fmt::Display for IdleActivation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "activation {} of model {} under {}",
            self.activation, self.model, self.execution
        )
    }
}

/// Rung 4's source over the coordinator, whose capacity port charges the host's shared
/// ledger.
pub struct CoordinatorParking<'a, C: Clock, L: Clock> {
    coordinator: &'a mut Coordinator<C, LedgerCapacity<L, SharedLedger<L>>>,
    models: &'a [CoordinatedModel],
}

impl<'a, C: Clock, L: Clock> CoordinatorParking<'a, C, L> {
    /// The serving activations of `models` on `coordinator`.
    pub fn new(
        coordinator: &'a mut Coordinator<C, LedgerCapacity<L, SharedLedger<L>>>,
        models: &'a [CoordinatedModel],
    ) -> Self {
        Self {
            coordinator,
            models,
        }
    }

    /// Leases on the activation that may still be in use.
    fn live_leases(
        &self,
        execution: &ExecutionId,
        model: ModelId,
        activation: ModelActivationGeneration,
    ) -> usize {
        let now = self.coordinator.now();
        self.coordinator
            .leases()
            .filter(|record| {
                let lease = record.lease();
                lease.parent() == execution
                    && lease.model().is_some_and(|binding| {
                        binding.model == model && binding.generations.activation == activation
                    })
                    && record.may_be_in_use(now)
            })
            .count()
    }

    /// The ledger reservations of the holdings parking leaves to be closed. When a
    /// holding of the activation is in a drain-first handover, the activation is kept, and
    /// all its holdings' reservations are named only to tell whether it would help.
    fn closable(
        &self,
        models: &ModelActivations,
        activation: ModelActivationGeneration,
    ) -> (Vec<ReservationId>, bool) {
        let Some(entry) = models.activation(activation) else {
            return (Vec::new(), false);
        };
        let ledger_ids = |keys: &[ReservationKey]| -> Vec<ReservationId> {
            keys.iter()
                .filter_map(|key| self.coordinator.capacity().record(key))
                .map(|record| record.id())
                .collect()
        };
        let mut closable = Vec::new();
        let mut every = Vec::new();
        let mut in_transition = false;
        for id in entry.holdings() {
            let Some(holding) = models.holding(*id) else {
                continue;
            };
            let reservations = ledger_ids(holding.reservations());
            every.extend(reservations.iter().copied());
            if !holding.is_backed() || holding.promised_to().is_some() {
                in_transition = true;
                continue;
            }
            let others_use = holding.users().iter().any(|user| {
                *user != activation
                    && models
                        .activation(*user)
                        .is_some_and(|other| !other.state().is_retired())
            });
            if !holding.holds_weights()
                && holding.state() == GpuReservationState::Held
                && !others_use
            {
                closable.extend(reservations);
            }
        }
        if in_transition {
            (every, true)
        } else {
            (closable, false)
        }
    }
}

impl<C: Clock, L: Clock> WorkSource for CoordinatorParking<'_, C, L> {
    type Work = IdleActivation;

    fn owner(&self) -> Requester {
        Requester::Coordination
    }

    fn survey(&mut self) -> Vec<Candidate<IdleActivation>> {
        let mut candidates = Vec::new();
        for model in self.models {
            let Some(activations) = self
                .coordinator
                .model_activations(&model.execution, model.model)
            else {
                continue;
            };
            for activation in activations.activations() {
                if activation.state() != ActivationState::Active {
                    continue;
                }
                let generation = activation.generations().activation;
                let (reservations, in_transition) = self.closable(activations, generation);
                if reservations.is_empty() {
                    continue;
                }
                let leases = self.live_leases(&model.execution, model.model, generation);
                let hold = if in_transition {
                    Hold::Pinned(PinnedBy::Transition)
                } else if leases > 0 {
                    Hold::Leased(LeasedBy::Requests { leases })
                } else if !model.canonical_state {
                    Hold::Pinned(PinnedBy::NoCanonicalState)
                } else {
                    Hold::Free
                };
                candidates.push(Candidate {
                    work: IdleActivation {
                        execution: model.execution.clone(),
                        model: model.model,
                        activation: generation,
                    },
                    reservations,
                    hold,
                    rank: 0.0,
                });
            }
        }
        candidates
    }

    /// Parks the activation: it serves no more and its holdings wait for
    /// `confirm_gpu_released`.
    fn stop(&mut self, work: &IdleActivation) -> Result<(), StopError> {
        self.coordinator
            .park(&work.execution, work.model, work.activation)
            .map(|_| ())
            .map_err(|refusal| StopError::Model(Box::new(refusal)))
    }
}

impl<C: Clock, L: Clock> ParkingSource for CoordinatorParking<'_, C, L> {}
