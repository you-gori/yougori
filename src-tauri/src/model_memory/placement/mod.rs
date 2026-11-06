//! P04: placement lifecycle and atomic activation
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md §3.6, with S3.1 for the typed
//! generations, §2.6 for execute-while-load and GPU-W05 for context).
//!
//! A [`PlacementSlot`] holds the placements of one model slot that a parent execution
//! owns. Each placement has an explicit state ([`PlacementState`], lines 580–583) and
//! independent fields for artifact validity, process liveness and GPU residency (line
//! 585). Activation follows the seven steps of lines 589–595: reserve steady state plus
//! transition peak, allocate or acquire immutable extents, validate every rank, check
//! readiness for the declared request shape, publish the new
//! `ModelActivationGeneration` to the request router in one step, drain old-generation
//! leases, and reclaim only after process references and GPU completion events allow
//! it. Versions overlap only when the reservation fits; otherwise the old generation
//! drains first and the slot reports a real pause (line 597). A request keeps the
//! generation it was admitted with and never reads another generation's weights, an
//! adapter update is a new placement with its own adapter identity, and a multi-rank
//! activation publishes only after every rank passed (line 599). Execute-while-load
//! serves one assigned request under a preparation-generation lease and releases
//! nothing before its dependency chain is computed and its generation is published
//! (line 601).
//!
//! Model identities come from the identity layers (T07) directly: requests carry their
//! typed execution, artifact and adapter identities, and placement identities are built
//! from `PlacementSpec`. Reservations (CORE-03, T04) and leases and generations (CORE-04,
//! T09) are reached through [`PlacementPorts`]. [`CoordinatorPorts`] serves both over the
//! coordinator for a model in a VM sandbox, counting memory shared across generations
//! once and handing it over when versions cannot overlap; [`LedgerReservations`]
//! reserves directly in the ledger where no coordinator owns the model, counting the
//! steady state whole; tests use the fakes in `fakes`. Pure, synchronous code: time
//! comes from the slot's [`Clock`].
//!
//! [`Clock`]: crate::foundation::ids::Clock

mod activation;
mod barrier;
mod coordinator_port;
mod early;
mod events;
mod extents;
mod fields;
mod keys;
mod ledger_port;
mod ports;
mod reclaim;
mod router;
mod slot;
mod state;

#[cfg(test)]
pub mod fakes;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

pub use activation::{
    AbortReport, ActivationError, ActivationIdentity, ActivationRequest, ActivationStarted,
    ActivationView, ExtentProgress, PlacementChoice, ProtocolStep, PublishReport, RequestProblem,
    TransitionMode, TransitionPreference,
};
pub use barrier::{BarrierError, RankBarrier, ReadinessReport, ValidationCheck, ValidationReport};
pub use coordinator_port::{CoordinatorBinding, CoordinatorPlacement, CoordinatorPorts};
pub use early::{AssignedRequest, EarlyRefusal, EarlyResult};
pub use events::{open_placement_log, PlacementEvent, PlacementLog, Recorded};
pub use extents::{ExtentSpec, FreedExtent};
pub use fields::{
    ArtifactProblem, ArtifactValidity, GpuResidency, ProcessLiveness, RequestShape, ShapeRefusal,
    SupportedShape,
};
pub use keys::{
    CompletionEventId, Component, ExtentKey, PlacementKey, ProcessInstance, Rank, ReferenceId,
    ReservationId, SlotId, WeightPosition,
};
pub use ledger_port::{ledger_device, LedgerPlacementConfig, LedgerPort, LedgerReservations};
pub use ports::{
    CapacityRefusal, CoordinationPort, CoordinationRefusal, LeaseKind, LeaseRequest, LeaseStatus,
    PlacementPorts, Ports, PublicationRefusal, ReservationGrant, ReservationPort,
    ReservationProblem, ReservationRefusal, ReservationRequest, ResourceDemand, ResourceKind,
    RetryOutlook,
};
pub use reclaim::{GateError, ReclaimBlocked, ReclaimGate, ReferenceKind};
pub use router::{
    ActivationContent, AdmissionRequest, PauseOutcome, PauseReason, PauseRecord, RequestTicket,
    RouteRefusal, TicketError,
};
pub use slot::{
    DrainStatus, EndedLease, PlacementSlot, PlacementView, ReclaimReport, RollbackOutlook,
    SlotError, SlotSpec,
};
pub use state::{
    is_allowed, Failure, FailureReason, IllegalTransition, PlacementState, StateKind,
    TransientStage,
};
